package adguard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"adguard-admin/agent/internal/aghyaml"
	"adguard-admin/agent/internal/execx"
	"adguard-admin/agent/internal/services"
)

func quietRole(fake *execx.Fake) *Role {
	r := New(services.Host{R: fake})
	r.Sleep = func(time.Duration) {}
	r.WaitTimeout = 500 * time.Millisecond
	return r
}

func TestWaitWebAcceptsARedirectToAnUnreachablePlace(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/control/status" {
			// What an unconfigured AdGuard does; the Location is deliberately
			// a dead port so a client that followed it would see a failure.
			http.Redirect(w, r, "http://127.0.0.1:1/install.html", http.StatusFound)
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()
	r := quietRole(&execx.Fake{})
	if err := r.waitWeb(context.Background(), ts.URL); err != nil {
		t.Fatalf("a 302 is an answer; waitWeb returned %v", err)
	}
	// And the client really does not follow: the status it sees is the 302.
	status, _, err := r.do(context.Background(), http.MethodGet, ts.URL+"/control/status", nil, nil)
	if err != nil || status != http.StatusFound {
		t.Fatalf("status=%d err=%v, want 302 and no error", status, err)
	}
}

func TestWaitWebTimeoutNamesTheLastError(t *testing.T) {
	r := quietRole(&execx.Fake{})
	r.WaitTimeout = 0
	err := r.waitWeb(context.Background(), "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if !strings.Contains(err.Error(), "last error:") || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("timeout message should carry the transport error: %q", err)
	}
}

func TestResetDockerRemovesContainersAndVolumes(t *testing.T) {
	fake := &execx.Fake{Handler: func(name string, args []string) execx.Result {
		if name == "docker" && len(args) > 0 && args[0] == "version" {
			return execx.Result{Stdout: "29.0.0\n"}
		}
		return execx.Result{}
	}}
	r := quietRole(fake)
	spec := &Spec{InstallMethod: "docker"}
	if err := r.Reset(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range fake.Calls {
		if !(c.Name == "docker" && c.Args[0] == "version") {
			got = append(got, c.Joined())
		}
	}
	want := []string{
		"docker rm -f adguardhome",
		"docker rm -f adguardhome-prev",
		"docker volume rm -f adguardhome-work adguardhome-conf",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if err := r.Reset(context.Background(), nil); err == nil {
		t.Fatal("a nil spec must be refused")
	}
}

func TestResetBareStopsServiceAndDeletesState(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "AdGuardHome.yaml"), []byte("dns: {}\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(dir, "data", "querylog"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "AdGuardHome"), []byte("binary"), 0o755)
	fake := &execx.Fake{}
	r := quietRole(fake)
	r.BareDir = dir
	if err := r.Reset(context.Background(), &Spec{InstallMethod: "bare_metal"}); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"AdGuardHome.yaml", "data"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s should be gone", gone)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "AdGuardHome")); err != nil {
		t.Fatal("the binary must survive a reset")
	}
	if r.Host.HasSystemd() {
		if len(fake.Calls) == 0 || fake.Calls[0].Joined() != "systemctl stop AdGuardHome" {
			t.Fatalf("calls = %v", fake.Calls)
		}
	}
}

// ---------------------------------------------------------- host network ----

func TestRunArgsHostNetworkPublishesNothing(t *testing.T) {
	s := &Spec{Image: DefaultImage, WebBind: "127.0.0.1", WebPort: 3000, DNSBind: []string{"0.0.0.0"}, DNSPort: 53, Network: "host"}
	args := RunArgs(s, "h1")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--network host") {
		t.Fatalf("host mode must use the host network: %s", joined)
	}
	for _, a := range args {
		if a == "-p" {
			t.Fatalf("host mode must not publish ports: %s", joined)
		}
	}
	if args[len(args)-1] != DefaultImage {
		t.Fatalf("image must be last: %s", joined)
	}
}

func TestRunArgsBridgeUnchanged(t *testing.T) {
	s := &Spec{Image: DefaultImage, WebBind: "127.0.0.1", WebPort: 3000, DNSBind: []string{"0.0.0.0", "::"}, DNSPort: 5335, Network: "bridge"}
	want := "run -d --name adguardhome --restart unless-stopped -l adguard-admin.managed=true -l adguard-admin.spec-hash=h1 " +
		"-v adguardhome-work:/opt/adguardhome/work -v adguardhome-conf:/opt/adguardhome/conf " +
		"-p 127.0.0.1:3000:3000/tcp -p 0.0.0.0:5335:53/tcp -p 0.0.0.0:5335:53/udp -p :::5335:53/tcp -p :::5335:53/udp " + DefaultImage
	if got := strings.Join(RunArgs(s, "h1"), " "); got != want {
		t.Fatalf("bridge args changed:\n got %s\nwant %s", got, want)
	}
}

func TestDecodeNetwork(t *testing.T) {
	r := quietRole(&execx.Fake{})
	base := `"admin_username":"admin","admin_password":"pw"`
	spec, err := r.Decode([]byte(`{` + base + `}`))
	if err != nil || spec.(*Spec).Network != "host" {
		t.Fatalf("default network must be host: %v %v", spec, err)
	}
	spec, err = r.Decode([]byte(`{` + base + `,"network":"bridge"}`))
	if err != nil || spec.(*Spec).Network != "bridge" {
		t.Fatalf("bridge must be accepted: %v %v", spec, err)
	}
	if _, err := r.Decode([]byte(`{` + base + `,"network":"overlay"}`)); err == nil {
		t.Fatal("overlay must be rejected")
	}
}

// hostMock imitates a fresh AdGuard on the host network: the wizard and the
// configured instance share one listener here (the test sets web_port to it).
func hostMock(t *testing.T) (*httptest.Server, int, *[][]byte) {
	t.Helper()
	configured := false
	var bodies [][]byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/control/install/get_addresses":
			if configured {
				w.WriteHeader(404)
				return
			}
			w.WriteHeader(200)
		case "/control/install/configure":
			body, _ := io.ReadAll(r.Body)
			bodies = append(bodies, body)
			configured = true
			w.WriteHeader(200)
		case "/control/status":
			if !configured {
				http.Redirect(w, r, "/install.html", http.StatusFound)
				return
			}
			if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "pw" {
				w.WriteHeader(403)
				return
			}
			_, _ = w.Write([]byte(`{"version":"v0.107.80"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(ts.Close)
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	return ts, port, &bodies
}

func hostFake(confDir string) (*execx.Fake, *bool) {
	created := false
	fake := &execx.Fake{}
	fake.Handler = func(name string, args []string) execx.Result {
		if name != "docker" {
			return execx.Result{}
		}
		switch args[0] {
		case "version":
			return execx.Result{Stdout: "29.0.0\n"}
		case "inspect":
			if !created {
				return execx.Result{Err: errors.New("no such container")}
			}
			return execx.Result{Stdout: `[{"Image":"sha256:x","State":{"Running":true,"Status":"running"},"Config":{"Image":"` + DefaultImage + `","Labels":{"adguard-admin.spec-hash":"h1"}}}]`}
		case "run":
			created = true
		case "volume":
			return execx.Result{Stdout: confDir + "\n"}
		}
		return execx.Result{}
	}
	return fake, &created
}

func dockerCalls(fake *execx.Fake) []string {
	var out []string
	for _, c := range fake.Calls {
		if c.Name == "docker" && c.Args[0] != "version" && c.Args[0] != "inspect" && c.Args[0] != "volume" {
			out = append(out, c.Joined())
		}
	}
	return out
}

func TestHostNetworkConvergeRunsWizardWithRealBindsAndFixesYAML(t *testing.T) {
	ts, port, bodies := hostMock(t)
	confDir := t.TempDir()
	// What the wizard writes: one bind host; the spec wants two, so the yaml
	// must be rewritten and the container restarted.
	yamlPath := filepath.Join(confDir, "AdGuardHome.yaml")
	_ = os.WriteFile(yamlPath, []byte("http:\n  address: 127.0.0.1:"+strconv.Itoa(port)+"\ndns:\n  bind_hosts:\n    - 0.0.0.0\n  port: 53\n  upstream_dns:\n    - 1.1.1.1\n"), 0o600)
	fake, _ := hostFake(confDir)
	r := quietRole(fake)
	r.WizardBase = ts.URL
	s := &Spec{Enabled: true, InstallMethod: "docker", Image: DefaultImage, WebBind: "127.0.0.1", WebPort: port,
		DNSBind: []string{"0.0.0.0", "::"}, DNSPort: 53, AdminUsername: "admin", AdminPassword: "pw", Network: "host"}
	out, err := r.Converge(context.Background(), s, "h1", func(string, string) {})
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != "v0.107.80" || !out.Enabled {
		t.Fatalf("outcome %+v", out)
	}
	if len(*bodies) != 1 {
		t.Fatalf("wizard should run once, ran %d times", len(*bodies))
	}
	var cfg struct {
		Web struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"web"`
		DNS struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"dns"`
	}
	_ = json.Unmarshal((*bodies)[0], &cfg)
	if cfg.Web.IP != "127.0.0.1" || cfg.Web.Port != port || cfg.DNS.IP != "0.0.0.0" || cfg.DNS.Port != 53 {
		t.Fatalf("wizard body must carry the spec's binds, got %s", (*bodies)[0])
	}
	calls := dockerCalls(fake)
	want := []string{
		strings.Join(RunArgs(s, "h1"), " "),
		"docker stop adguardhome",
		"docker start adguardhome",
	}
	want[0] = "docker " + want[0]
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("docker calls:\n got %q\nwant %q", calls, want)
	}
	raw, _ := os.ReadFile(yamlPath)
	have, err := aghyaml.Read(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !sameBinds(have, aghyaml.Binds{DNSBindHosts: []string{"0.0.0.0", "::"}, DNSPort: 53, HTTPAddress: "127.0.0.1:" + strconv.Itoa(port)}) {
		t.Fatalf("yaml not rewritten: %+v", have)
	}
	if !strings.Contains(string(raw), "1.1.1.1") {
		t.Fatal("the rest of the yaml must survive the edit")
	}
}

func TestHostNetworkConvergeLeavesMatchingYAMLAlone(t *testing.T) {
	ts, port, _ := hostMock(t)
	confDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(confDir, "AdGuardHome.yaml"),
		[]byte("http:\n  address: 0.0.0.0:"+strconv.Itoa(port)+"\ndns:\n  bind_hosts:\n    - 0.0.0.0\n  port: 53\n"), 0o600)
	fake, _ := hostFake(confDir)
	r := quietRole(fake)
	r.WizardBase = ts.URL
	s := &Spec{Enabled: true, InstallMethod: "docker", Image: DefaultImage, WebBind: "0.0.0.0", WebPort: port,
		DNSBind: []string{"0.0.0.0"}, DNSPort: 53, AdminUsername: "admin", AdminPassword: "pw", Network: "host"}
	if _, err := r.Converge(context.Background(), s, "h1", func(string, string) {}); err != nil {
		t.Fatal(err)
	}
	for _, c := range dockerCalls(fake) {
		if strings.HasPrefix(c, "docker stop") || strings.HasPrefix(c, "docker start") {
			t.Fatalf("no restart expected when the binds already match: %v", dockerCalls(fake))
		}
	}
}
