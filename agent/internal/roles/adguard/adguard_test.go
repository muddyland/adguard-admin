package adguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
