// Package pki covers the agent's key, CSR and certificate handling, and the
// mutual-TLS policy applied to the control plane's client certificate.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// ControlPlaneCN is the common name the control plane's client certificate
// must carry. Chaining to the CA alone is not enough: an agent certificate
// signed by the same CA must never be accepted as a client.
const ControlPlaneCN = "adguard-admin"

// GenerateKey returns a fresh ECDSA P-256 key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// EncodeKey returns the PKCS#8 PEM of a key.
func EncodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseKey reads a PKCS#8 or EC PEM key.
func ParseKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block in key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if ec, ok := k.(*ecdsa.PrivateKey); ok {
			return ec, nil
		}
		return nil, errors.New("key is not ECDSA")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// CSR builds a PEM certificate request. The CA decides the SANs; the request
// only carries the public key and a name, plus the address as a hint.
func CSR(key *ecdsa.PrivateKey, commonName, address string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	if address != "" {
		if ip := net.ParseIP(address); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		} else {
			tmpl.DNSNames = []string{address}
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// ParseCert parses the first certificate in a PEM blob.
func ParseCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block in certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// Pool builds a cert pool from one or more PEM certificates.
func Pool(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("no certificates in CA PEM")
	}
	return pool, nil
}

// Holder keeps the live server certificate and lets it be swapped without a
// restart.
type Holder struct {
	cert atomic.Pointer[tls.Certificate]
}

// Load sets the certificate from PEM cert and key material.
func (h *Holder) Load(certPEM, keyPEM []byte) error {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if c.Leaf == nil {
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return err
		}
		c.Leaf = leaf
	}
	h.cert.Store(&c)
	return nil
}

// LoadFiles reads cert and key from disk.
func (h *Holder) LoadFiles(certFile, keyFile string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	return h.Load(certPEM, keyPEM)
}

// Current returns the live certificate.
func (h *Holder) Current() *tls.Certificate { return h.cert.Load() }

// NotAfter returns the expiry of the live certificate.
func (h *Holder) NotAfter() time.Time {
	c := h.cert.Load()
	if c == nil || c.Leaf == nil {
		return time.Time{}
	}
	return c.Leaf.NotAfter
}

// ServerTLSConfig returns the mTLS listener configuration: TLS 1.3 only, the
// live certificate from the holder, and a client certificate required and
// chained to the control plane CA (Go verifies the clientAuth EKU here).
func ServerTLSConfig(h *Holder, ca *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  ca,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c := h.Current()
			if c == nil {
				return nil, errors.New("no server certificate loaded")
			}
			return c, nil
		},
	}
}

// CheckClient is the second half of the policy: the verified leaf must carry
// the clientAuth EKU and the control plane's CN.
func CheckClient(r *http.Request) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return errors.New("no client certificate")
	}
	leaf := r.TLS.PeerCertificates[0]
	hasClientAuth := false
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		return errors.New("client certificate lacks the clientAuth extended key usage")
	}
	if leaf.Subject.CommonName != ControlPlaneCN {
		return fmt.Errorf("client certificate CN %q is not %q", leaf.Subject.CommonName, ControlPlaneCN)
	}
	return nil
}

// RequireControlPlane wraps a handler with CheckClient.
func RequireControlPlane(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := CheckClient(r); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// PublicKeyMatches reports whether cert was issued for key.
func PublicKeyMatches(cert *x509.Certificate, key *ecdsa.PrivateKey) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && pub.Equal(&key.PublicKey)
}
