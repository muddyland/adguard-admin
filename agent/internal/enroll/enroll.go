// Package enroll performs the one-time certificate enrollment against the
// control plane using a provisioning token.
package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"adguard-admin/agent/internal/config"
	"adguard-admin/agent/internal/pki"
	"adguard-admin/agent/internal/sysinfo"
)

// Request is the enrollment body.
type Request struct {
	CSRPEM       string `json:"csr_pem"`
	Hostname     string `json:"hostname"`
	Address      string `json:"address"`
	Port         int    `json:"port"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agent_version"`
}

// Response is what the control plane returns.
type Response struct {
	AgentID  int64  `json:"agent_id"`
	Name     string `json:"name"`
	CertPEM  string `json:"cert_pem"`
	CAPEM    string `json:"ca_pem"`
	NotAfter string `json:"not_after"`
}

// Options drive one enrollment.
type Options struct {
	URL     string
	Token   string
	Listen  string
	Address string
	Name    string
	Version string
	HTTP    *http.Client
}

// LocalAddressFor returns the local IP used to reach host (no packets sent).
func LocalAddressFor(host string) (string, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(host, "9"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

// BuildRequest prepares the CSR and the body; the key is returned for saving.
func BuildRequest(o Options) (*Request, []byte, error) {
	if o.Listen == "" {
		o.Listen = config.DefaultListen
	}
	_, portStr, err := net.SplitHostPort(o.Listen)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %q must be host:port", o.Listen)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %q has a bad port", o.Listen)
	}
	name := o.Name
	if name == "" {
		name = sysinfo.Hostname()
	}
	key, err := pki.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	csr, err := pki.CSR(key, name, o.Address)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := pki.EncodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return &Request{
		CSRPEM: string(csr), Hostname: sysinfo.Hostname(), Address: o.Address, Port: port,
		OS: sysinfo.OS(), Arch: sysinfo.Arch(), AgentVersion: o.Version,
	}, keyPEM, nil
}

// Run enrolls and writes the identity files.
func Run(ctx context.Context, dirs config.Dirs, o Options) (*Response, error) {
	if o.URL == "" || o.Token == "" {
		return nil, errors.New("--url and --token are required")
	}
	if strings.ContainsAny(o.Token, "/ \t\n?#") {
		return nil, errors.New("token contains characters that cannot appear in a token")
	}
	base, err := url.Parse(strings.TrimRight(o.URL, "/"))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("--url must be an http(s) URL")
	}
	if base.Scheme == "http" {
		fmt.Fprintln(os.Stderr, "warning: enrolling over plain HTTP; the token and certificate are readable on the wire")
	}
	if o.Address == "" {
		if o.Address, err = LocalAddressFor(base.Hostname()); err != nil {
			return nil, fmt.Errorf("could not determine this host's address, pass --address: %w", err)
		}
	}
	if config.Exists(dirs.CertFile()) {
		return nil, fmt.Errorf("%s already exists; this host is enrolled (remove %s to re-enroll)", dirs.CertFile(), dirs.Config)
	}
	req, keyPEM, err := BuildRequest(o)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(req)
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	endpoint := base.String() + "/api/provision/" + o.Token + "/enroll"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("enroll request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		var e struct {
			Detail any `json:"detail"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Detail != nil {
			return nil, fmt.Errorf("enrollment refused (HTTP %d): %v", resp.StatusCode, e.Detail)
		}
		return nil, fmt.Errorf("enrollment refused (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("bad enrollment response: %w", err)
	}
	if _, err := pki.ParseCert([]byte(out.CertPEM)); err != nil {
		return nil, fmt.Errorf("control plane returned an unusable certificate: %w", err)
	}
	if _, err := pki.Pool([]byte(out.CAPEM)); err != nil {
		return nil, fmt.Errorf("control plane returned an unusable CA: %w", err)
	}
	if err := os.MkdirAll(dirs.Config, 0o700); err != nil {
		return nil, err
	}
	if err := config.WriteFileAtomic(dirs.KeyFile(), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := config.WriteFileAtomic(dirs.CertFile(), []byte(out.CertPEM), 0o644); err != nil {
		return nil, err
	}
	if err := config.WriteFileAtomic(dirs.CAFile(), []byte(out.CAPEM), 0o644); err != nil {
		return nil, err
	}
	name := out.Name
	if name == "" {
		name = req.Hostname
	}
	cfg := &config.Agent{Listen: o.Listen, Name: name, AgentID: out.AgentID, ControlPlaneURL: base.String(), Address: o.Address}
	if cfg.Listen == "" {
		cfg.Listen = config.DefaultListen
	}
	if err := config.Save(dirs, cfg); err != nil {
		return nil, err
	}
	return &out, nil
}
