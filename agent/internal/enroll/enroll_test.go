package enroll

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adguard-admin/agent/internal/config"
	"adguard-admin/agent/internal/pki"
	"adguard-admin/agent/internal/pki/testpki"
)

func TestBuildRequest(t *testing.T) {
	req, keyPEM, err := BuildRequest(Options{Listen: "0.0.0.0:8443", Address: "10.0.0.11", Name: "host-a", Version: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if req.Port != 8443 || req.Address != "10.0.0.11" || req.AgentVersion != "0.1.0" || req.OS != "linux" {
		t.Fatalf("%+v", req)
	}
	if !strings.Contains(req.CSRPEM, "CERTIFICATE REQUEST") {
		t.Fatal("no CSR")
	}
	key, err := pki.ParseKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ca := testpki.NewCA()
	cert, _ := pki.ParseCert(ca.SignCSR([]byte(req.CSRPEM), "host-a", "10.0.0.11"))
	if !pki.PublicKeyMatches(cert, key) {
		t.Fatal("CSR public key does not match the generated key")
	}
	raw, _ := json.Marshal(req)
	for _, field := range []string{`"csr_pem"`, `"hostname"`, `"address"`, `"port"`, `"os"`, `"arch"`, `"agent_version"`} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("body lacks %s", field)
		}
	}
}

func TestRunWritesIdentity(t *testing.T) {
	ca := testpki.NewCA()
	var gotPath string
	var gotBody Request
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		if !strings.HasSuffix(r.URL.Path, "/enroll") || r.Method != http.MethodPost {
			w.WriteHeader(404)
			return
		}
		cert := ca.SignCSR([]byte(gotBody.CSRPEM), "host-a", gotBody.Address)
		_ = json.NewEncoder(w).Encode(Response{AgentID: 42, Name: "host-a", CertPEM: string(cert), CAPEM: string(ca.PEM), NotAfter: "2027-01-01T00:00:00Z"})
	}))
	defer cp.Close()

	dirs := config.Dirs{Config: filepath.Join(t.TempDir(), "etc"), State: t.TempDir()}
	resp, err := Run(context.Background(), dirs, Options{URL: cp.URL + "/", Token: "tok123", Listen: "127.0.0.1:18443", Address: "127.0.0.1", Name: "host-a", Version: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/provision/tok123/enroll" {
		t.Fatalf("path %q", gotPath)
	}
	if resp.AgentID != 42 {
		t.Fatalf("%+v", resp)
	}
	for _, f := range []string{dirs.KeyFile(), dirs.CertFile(), dirs.CAFile(), dirs.AgentJSON()} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	st, _ := os.Stat(dirs.KeyFile())
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %o", st.Mode().Perm())
	}
	cfg, err := config.Load(dirs)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentID != 42 || cfg.Listen != "127.0.0.1:18443" || cfg.DnsdistAPIKey == "" || cfg.DnsdistConsoleKey == "" || cfg.ControlPlaneURL != cp.URL {
		t.Fatalf("%+v", cfg)
	}
	var h pki.Holder
	if err := h.LoadFiles(dirs.CertFile(), dirs.KeyFile()); err != nil {
		t.Fatal(err)
	}
	// Re-enrolling over an existing identity is refused.
	if _, err := Run(context.Background(), dirs, Options{URL: cp.URL, Token: "tok123", Address: "127.0.0.1"}); err == nil {
		t.Fatal("expected refusal")
	}
}

func TestRunRefusesServerErrors(t *testing.T) {
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(410)
		_, _ = w.Write([]byte(`{"detail":"Token expired"}`))
	}))
	defer cp.Close()
	dirs := config.Dirs{Config: filepath.Join(t.TempDir(), "etc"), State: t.TempDir()}
	_, err := Run(context.Background(), dirs, Options{URL: cp.URL, Token: "tok", Address: "127.0.0.1"})
	if err == nil || !strings.Contains(err.Error(), "Token expired") {
		t.Fatalf("expected the server's detail, got %v", err)
	}
	if _, statErr := os.Stat(dirs.KeyFile()); statErr == nil {
		t.Fatal("no files may be written on failure")
	}
}
