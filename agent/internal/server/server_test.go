package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"adguard-admin/agent/internal/config"
	"adguard-admin/agent/internal/execx"
	"adguard-admin/agent/internal/pki"
	"adguard-admin/agent/internal/pki/testpki"
	"adguard-admin/agent/internal/roles"
	"adguard-admin/agent/internal/roles/adguard"
	"adguard-admin/agent/internal/roles/dnsdist"
	"adguard-admin/agent/internal/roles/ipvsbackend"
	"adguard-admin/agent/internal/roles/keepalived"
	"adguard-admin/agent/internal/services"
)

type fixture struct {
	ca      *testpki.CA
	srv     *httptest.Server
	server  *Server
	fake    *execx.Fake
	dirs    config.Dirs
	manager *roles.Manager
	agh     *httptest.Server // mock AdGuard Home
	aghPort int
}

func newFixture(t *testing.T, handler func(name string, args []string) execx.Result) *fixture {
	t.Helper()
	root := t.TempDir()
	dirs := config.Dirs{Config: filepath.Join(root, "etc"), State: filepath.Join(root, "state")}
	for _, d := range []string{dirs.Config, dirs.Desired(), dirs.Status(), dirs.Dnsdist(), dirs.Keepalived()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ca := testpki.NewCA()
	srvKey, srvKeyPEM := testpki.KeyPEM()
	srvCert := ca.Issue(&srvKey.PublicKey, "host-a", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	_ = os.WriteFile(dirs.KeyFile(), srvKeyPEM, 0o600)
	_ = os.WriteFile(dirs.CertFile(), srvCert, 0o644)
	_ = os.WriteFile(dirs.CAFile(), ca.PEM, 0o644)
	holder := &pki.Holder{}
	if err := holder.Load(srvCert, srvKeyPEM); err != nil {
		t.Fatal(err)
	}
	fake := &execx.Fake{Handler: handler}
	host := services.Host{R: fake}
	cfg := &config.Agent{Listen: "127.0.0.1:0", Name: "host-a", AgentID: 7, Address: "127.0.0.1", DnsdistAPIKey: "apikey", DnsdistConsoleKey: "consolekey"}
	ag := adguard.New(host)
	ag.Sleep = func(time.Duration) {}
	ag.WaitTimeout = 2 * time.Second
	dd := dnsdist.New(host, dirs, cfg.DnsdistAPIKey, cfg.DnsdistConsoleKey)
	dd.Sleep = func(time.Duration) {}
	dd.WaitTimeout = time.Second
	ib := ipvsbackend.New(host)
	ib.SysctlPath = filepath.Join(root, "sysctl.conf")
	ib.ProcRoot = filepath.Join(root, "proc")
	mgr := roles.NewManager(dirs, log.New(io.Discard, "", 0), ag, dd, keepalived.NewWithDirs(host, dirs), ib)
	s := &Server{Dirs: dirs, Cfg: cfg, Host: host, Manager: mgr, Holder: holder, Logger: log.New(io.Discard, "", 0)}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.PEM)
	// Not httptest.StartTLS: it would install its own certificate and bypass
	// the holder's GetCertificate, which the renewal test relies on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, pki.ServerTLSConfig(holder, pool))
	hs := &http.Server{Handler: s.Handler(), ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = hs.Serve(tlsLn) }()
	t.Cleanup(func() { _ = hs.Close() })
	ts := &httptest.Server{URL: "https://" + ln.Addr().String()}
	return &fixture{ca: ca, srv: ts, server: s, fake: fake, dirs: dirs, manager: mgr}
}

func (f *fixture) client(t *testing.T, cn string, ekus []x509.ExtKeyUsage) *http.Client {
	t.Helper()
	key, keyPEM := testpki.KeyPEM()
	certPEM := f.ca.Issue(&key.PublicKey, cn, ekus, nil, nil)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(f.ca.PEM)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13,
	}}}
}

func (f *fixture) good(t *testing.T) *http.Client {
	return f.client(t, pki.ControlPlaneCN, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

func TestMTLSPolicy(t *testing.T) {
	f := newFixture(t, nil)
	f.fake.Programs = map[string]bool{} // no docker, no systemctl on this fake host

	// No client certificate at all: the handshake is refused.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(f.ca.PEM)
	anon := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
	if _, err := anon.Get(f.srv.URL + "/v1/info"); err == nil {
		t.Fatal("request without a client certificate must fail")
	}

	// serverAuth-only certificate (an agent's own cert) must be refused.
	agentCert := f.client(t, "other-agent", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if resp, err := agentCert.Get(f.srv.URL + "/v1/info"); err == nil && resp.StatusCode == 200 {
		t.Fatal("serverAuth certificate was accepted")
	}

	// clientAuth with the wrong CN: handshake passes, policy says 403.
	wrongCN := f.client(t, "someone-else", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	resp, err := wrongCN.Get(f.srv.URL + "/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("wrong CN: got %d, want 403", resp.StatusCode)
	}

	// The real control plane.
	resp, err = f.good(t).Get(f.srv.URL + "/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("good client: got %d", resp.StatusCode)
	}
	var info map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&info)
	if info["name"] != "host-a" || info["agent_id"] != float64(7) {
		t.Fatalf("unexpected info: %v", info)
	}
	if info["docker"] != false || info["systemd"] != false {
		t.Fatalf("expected docker/systemd false on a host without them: %v", info)
	}
	hashes := info["desired_hashes"].(map[string]any)
	if hashes["adguard"] != nil || hashes["dnsdist"] != nil || hashes["keepalived"] != nil {
		t.Fatalf("expected nil hashes before any PUT: %v", hashes)
	}
}

func TestHealthWithoutServices(t *testing.T) {
	f := newFixture(t, func(name string, args []string) execx.Result {
		return execx.Result{Err: os.ErrNotExist} // docker version fails -> no docker
	})
	f.fake.Programs = map[string]bool{} // nothing installed
	resp, err := f.good(t).Get(f.srv.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&h)
	svcs := h["services"].(map[string]any)
	for _, n := range []string{"adguard", "dnsdist", "keepalived"} {
		st := svcs[n].(map[string]any)
		if st["kind"] != "none" || st["present"] != false {
			t.Fatalf("%s: %v", n, st)
		}
	}
	if _, ok := h["load"]; !ok {
		t.Fatal("load missing")
	}
}

// aghMock imitates a fresh AdGuard Home that becomes configured after the wizard.
func aghMock(t *testing.T) (*httptest.Server, int, *[]string) {
	t.Helper()
	configured := false
	var calls []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/control/install/get_addresses":
			if configured {
				w.WriteHeader(404)
				return
			}
			w.WriteHeader(200)
		case "/control/install/configure":
			body, _ := io.ReadAll(r.Body)
			if !bytes.Contains(body, []byte(`"username":"admin"`)) {
				w.WriteHeader(400)
				return
			}
			configured = true
			w.WriteHeader(200)
		case "/control/status":
			if !configured {
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			u, p, ok := r.BasicAuth()
			if !ok || u != "admin" || p != "s3cret" {
				w.WriteHeader(403)
				return
			}
			_, _ = w.Write([]byte(`{"version":"v0.107.80","running":true}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(ts.Close)
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	return ts, port, &calls
}

func TestAdGuardPutConvergesAndProxies(t *testing.T) {
	_, port, calls := aghMock(t)
	var created bool
	f := newFixture(t, func(name string, args []string) execx.Result {
		switch {
		case name == "docker" && args[0] == "version":
			return execx.Result{Stdout: "29.0.0"}
		case name == "docker" && args[0] == "inspect":
			if created {
				return execx.Result{Stdout: `[{"Image":"sha256:abc","State":{"Running":true,"Status":"running"},"Config":{"Image":"adguard/adguardhome:latest","Labels":{"adguard-admin.spec-hash":"HASH"}}}]`}
			}
			return execx.Result{Err: os.ErrNotExist}
		case name == "docker" && args[0] == "run":
			created = true
			return execx.Result{Stdout: "cid"}
		}
		return execx.Result{}
	})
	spec := map[string]any{
		"enabled": true, "install_method": "docker", "web_bind": "127.0.0.1", "web_port": port,
		"dns_bind": []string{"0.0.0.0"}, "dns_port": 53, "admin_username": "admin", "admin_password": "s3cret",
	}
	raw, _ := json.Marshal(spec)
	req, _ := http.NewRequest(http.MethodPut, f.srv.URL+"/v1/adguard", bytes.NewReader(raw))
	resp, err := f.good(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 202 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT: %d %s", resp.StatusCode, b)
	}
	var acc struct {
		Hash string `json:"hash"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&acc)
	if len(acc.Hash) != 64 {
		t.Fatalf("bad hash %q", acc.Hash)
	}
	if _, err := os.Stat(filepath.Join(f.dirs.Desired(), "adguard.json")); err != nil {
		t.Fatal("desired spec not persisted")
	}

	// Converge synchronously (the loop is not started in tests).
	f.manager.ConvergeNow(context.Background(), "adguard")

	var runCall *execx.Call
	for i := range f.fake.Calls {
		if f.fake.Calls[i].Name == "docker" && f.fake.Calls[i].Args[0] == "run" {
			runCall = &f.fake.Calls[i]
		}
	}
	if runCall == nil {
		t.Fatalf("docker run was not called; calls: %v", f.fake.Calls)
	}
	joined := runCall.Joined()
	for _, want := range []string{"--name adguardhome", "-l adguard-admin.spec-hash=" + acc.Hash, "-p 127.0.0.1:" + itoa(port) + ":3000/tcp", "-p 0.0.0.0:53:53/udp", "adguard/adguardhome:latest"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("docker run missing %q: %s", want, joined)
		}
	}
	if !contains(*calls, "POST /control/install/configure") {
		t.Fatalf("wizard not run: %v", *calls)
	}

	resp, _ = f.good(t).Get(f.srv.URL + "/v1/adguard")
	var st map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&st)
	if st["state"] != "ready" || st["version"] != "v0.107.80" || st["applied_hash"] != acc.Hash {
		t.Fatalf("status: %v", st)
	}

	// The proxy forwards to the mock with the Authorization header intact.
	preq, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/v1/adguard/api/control/status", nil)
	preq.SetBasicAuth("admin", "s3cret")
	presp, err := f.good(t).Do(preq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(presp.Body)
	if presp.StatusCode != 200 || !strings.Contains(string(body), "v0.107.80") {
		t.Fatalf("proxy: %d %s", presp.StatusCode, body)
	}
}

func TestAdGuardRejectsBadSpec(t *testing.T) {
	f := newFixture(t, nil)
	for _, bad := range []string{
		`{"enabled":true}`,
		`{"enabled":true,"admin_username":"a","admin_password":"b","install_method":"snap"}`,
		`{"enabled":true,"admin_username":"a","admin_password":"b","web_bind":"localhost"}`,
		`{"enabled":true,"admin_username":"a","admin_password":"b","dns_port":70000}`,
	} {
		req, _ := http.NewRequest(http.MethodPut, f.srv.URL+"/v1/adguard", strings.NewReader(bad))
		resp, err := f.good(t).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 422 {
			t.Fatalf("%s: got %d", bad, resp.StatusCode)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dirs.Desired(), "adguard.json")); err == nil {
		t.Fatal("rejected spec must not be persisted")
	}
}

func TestDnsdistDrainUsesConsole(t *testing.T) {
	f := newFixture(t, func(name string, args []string) execx.Result {
		if name == "docker" && args[0] == "version" {
			return execx.Result{Stdout: "29"}
		}
		return execx.Result{}
	})
	spec := `{"enabled":true,"backends":[{"name":"dns-a","address":"10.0.0.11","port":5335}]}`
	req, _ := http.NewRequest(http.MethodPut, f.srv.URL+"/v1/dnsdist", strings.NewReader(spec))
	resp, err := f.good(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 202 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT dnsdist: %d %s", resp.StatusCode, b)
	}
	resp, _ = f.good(t).Post(f.srv.URL+"/v1/dnsdist/backends/dns-a/drain", "application/json", nil)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("drain: %d %s", resp.StatusCode, b)
	}
	var consoleCall *execx.Call
	for i := range f.fake.Calls {
		if f.fake.Calls[i].Name == "docker" && f.fake.Calls[i].Args[0] == "exec" {
			consoleCall = &f.fake.Calls[i]
		}
	}
	if consoleCall == nil {
		t.Fatalf("console not invoked: %v", f.fake.Calls)
	}
	want := []string{"exec", "dnsdist", "dnsdist", "--client=127.0.0.1:5199", "-k", "consolekey", "-e", `for _,s in ipairs(getServers()) do if s:getName()=="dns-a" then s:setDown() end end`}
	if strings.Join(consoleCall.Args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("console args:\n got %q\nwant %q", consoleCall.Args, want)
	}
	resp, _ = f.good(t).Post(f.srv.URL+"/v1/dnsdist/backends/nope/drain", "application/json", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("unknown backend: %d", resp.StatusCode)
	}
	resp, _ = f.good(t).Get(f.srv.URL + "/v1/dnsdist")
	var st map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&st)
	drained := st["drained"].([]any)
	if len(drained) != 1 || drained[0] != "dns-a" {
		t.Fatalf("drained list: %v", st)
	}
}

func TestCertRenewal(t *testing.T) {
	f := newFixture(t, nil)
	c := f.good(t)
	resp, err := c.Post(f.srv.URL+"/v1/cert/renew", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		CSR string `json:"csr_pem"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if !strings.Contains(out.CSR, "CERTIFICATE REQUEST") {
		t.Fatalf("no CSR: %q", out.CSR)
	}
	before := f.server.Holder.Current().Leaf.SerialNumber
	cert := f.ca.SignCSR([]byte(out.CSR), "host-a", "127.0.0.1")
	body, _ := json.Marshal(map[string]string{"cert_pem": string(cert), "ca_pem": string(f.ca.PEM)})
	req, _ := http.NewRequest(http.MethodPut, f.srv.URL+"/v1/cert", bytes.NewReader(body))
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT cert: %d %s", resp.StatusCode, b)
	}
	if f.server.Holder.Current().Leaf.SerialNumber.Cmp(before) == 0 {
		t.Fatal("live certificate was not swapped")
	}
	// A second PUT without a pending renewal is refused.
	req, _ = http.NewRequest(http.MethodPut, f.srv.URL+"/v1/cert", bytes.NewReader(body))
	resp, _ = c.Do(req)
	if resp.StatusCode != 409 {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}
	// The next connection uses the new certificate.
	resp, err = f.good(t).Get(f.srv.URL + "/v1/info")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("after renewal: %v %d", err, resp.StatusCode)
	}
}

func TestRestartAndLogsValidateService(t *testing.T) {
	f := newFixture(t, nil)
	resp, _ := f.good(t).Post(f.srv.URL+"/v1/services/agent/restart", "application/json", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("restarting the agent itself must be refused: %d", resp.StatusCode)
	}
	resp, _ = f.good(t).Get(f.srv.URL + "/v1/logs?service=bogus")
	if resp.StatusCode != 400 {
		t.Fatalf("bogus service: %d", resp.StatusCode)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestIPVSBackendRoleAndKeepalivedDrainRoutes(t *testing.T) {
	f := newFixture(t, func(name string, args []string) execx.Result {
		switch name {
		case "ip":
			return execx.Result{Stdout: "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"}
		case "sysctl":
			return execx.Result{}
		}
		return execx.Result{Err: os.ErrNotExist}
	})
	// Unknown role before any spec: info lists a null hash for it.
	resp, _ := f.good(t).Get(f.srv.URL + "/v1/info")
	var info map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&info)
	hashes := info["desired_hashes"].(map[string]any)
	if v, ok := hashes["ipvs_backend"]; !ok || v != nil {
		t.Fatalf("desired_hashes: %v", hashes)
	}

	req, _ := http.NewRequest(http.MethodPut, f.srv.URL+"/v1/ipvs-backend", strings.NewReader(`{"enabled":true,"vip":"10.0.0.53"}`))
	resp, err := f.good(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 202 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT ipvs-backend: %d %s", resp.StatusCode, b)
	}
	f.manager.ConvergeNow(context.Background(), "ipvs_backend")
	resp, _ = f.good(t).Get(f.srv.URL + "/v1/ipvs-backend")
	var st map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&st)
	if st["state"] != "ready" {
		t.Fatalf("status %v", st)
	}
	if !contains(callsJoined(f.fake), "ip addr add 10.0.0.53/32 dev lo") {
		t.Fatalf("loopback VIP not added: %v", callsJoined(f.fake))
	}
	resp, _ = f.good(t).Get(f.srv.URL + "/v1/info")
	_ = json.NewDecoder(resp.Body).Decode(&info)
	if !contains(anyStrings(info["roles"]), "ipvs_backend") {
		t.Fatalf("roles: %v", info["roles"])
	}

	req, _ = http.NewRequest(http.MethodPut, f.srv.URL+"/v1/ipvs-backend", strings.NewReader(`{"enabled":true,"vip":"10.0.0.53/24"}`))
	resp, _ = f.good(t).Do(req)
	if resp.StatusCode != 422 {
		t.Fatalf("bad vip accepted: %d", resp.StatusCode)
	}

	// Drains on keepalived are refused while no IPVS service is managed.
	resp, _ = f.good(t).Post(f.srv.URL+"/v1/keepalived/backends/dns-a/drain", "application/json", nil)
	if resp.StatusCode != 409 {
		t.Fatalf("drain without ipvs: %d", resp.StatusCode)
	}
}

func callsJoined(f *execx.Fake) []string {
	var out []string
	for _, c := range f.Calls {
		out = append(out, c.Joined())
	}
	return out
}

func anyStrings(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, x := range list {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
