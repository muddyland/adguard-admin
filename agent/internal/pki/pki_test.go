package pki

import (
	"crypto/x509"
	"net"
	"testing"

	"adguard-admin/agent/internal/pki/testpki"
)

func TestCSRAndKeyRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := CSR(key, "host-a", "10.0.0.11")
	if err != nil {
		t.Fatal(err)
	}
	ca := testpki.NewCA()
	certPEM := ca.SignCSR(csr, "host-a", "10.0.0.11")
	cert, err := ParseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !PublicKeyMatches(cert, key) {
		t.Fatal("issued cert does not match key")
	}
	keyPEM, _ := EncodeKey(key)
	back, err := ParseKey(keyPEM)
	if err != nil || !back.Equal(key) {
		t.Fatalf("key round trip failed: %v", err)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("10.0.0.11")) {
		t.Fatalf("SAN not carried: %v", cert.IPAddresses)
	}
	var h Holder
	if err := h.Load(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if h.NotAfter().IsZero() {
		t.Fatal("holder lost the leaf")
	}
	_ = x509.ExtKeyUsageServerAuth
}
