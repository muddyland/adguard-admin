package ipvsbackend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adguard-admin/agent/internal/execx"
	"adguard-admin/agent/internal/roles"
	"adguard-admin/agent/internal/services"
)

const loWithout = `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
`
const loWith = loWithout + `1: lo    inet 10.0.0.53/32 scope global lo\       valid_lft forever preferred_lft forever
`

func newRole(t *testing.T, loOutput string) (*Role, *execx.Fake) {
	t.Helper()
	fake := &execx.Fake{Handler: func(name string, args []string) execx.Result {
		if name == "ip" && len(args) >= 2 && args[1] == "addr" && args[2] == "show" {
			return execx.Result{Stdout: loOutput}
		}
		return execx.Result{}
	}}
	dir := t.TempDir()
	r := New(services.Host{R: fake})
	r.SysctlPath = filepath.Join(dir, "sysctl.conf")
	r.ProcRoot = filepath.Join(dir, "proc")
	return r, fake
}

func writeProc(t *testing.T, root string, values map[string]string) {
	t.Helper()
	for k, v := range values {
		p := filepath.Join(root, "sys", strings.ReplaceAll(k, ".", "/"))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func joined(f *execx.Fake) string {
	var out []string
	for _, c := range f.Calls {
		out = append(out, c.Joined())
	}
	return strings.Join(out, "\n")
}

func TestDecode(t *testing.T) {
	r := New(services.Host{R: &execx.Fake{}})
	for _, bad := range []string{`{"vip":"10.0.0.53/24"}`, `{"vip":"host"}`, `{"vip":"127.0.0.1"}`, `{"vip":"0.0.0.0"}`, `{"enabled":true}`} {
		if _, err := r.Decode([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, err := r.Decode([]byte(`{"enabled":false,"vip":""}`)); err != nil {
		t.Fatal(err)
	}
}

func TestConvergeAddsVIPOnceAndWritesSysctls(t *testing.T) {
	r, fake := newRole(t, loWithout)
	spec, _ := r.Decode([]byte(`{"enabled":true,"vip":"10.0.0.53"}`))
	if _, err := r.Converge(context.Background(), spec, "h", func(string, string) {}); err != nil {
		t.Fatal(err)
	}
	all := joined(fake)
	for _, want := range []string{
		"ip -o addr show dev lo",
		"ip addr add 10.0.0.53/32 dev lo",
		"sysctl -w net.ipv4.conf.all.arp_ignore=1 net.ipv4.conf.all.arp_announce=2 net.ipv4.conf.lo.arp_ignore=1 net.ipv4.conf.lo.arp_announce=2",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
	raw, err := os.ReadFile(r.SysctlPath)
	if err != nil || !strings.Contains(string(raw), "net.ipv4.conf.lo.arp_announce = 2") {
		t.Fatalf("sysctl file: %v %s", err, raw)
	}

	// Already present: no second add.
	r2, fake2 := newRole(t, loWith)
	if _, err := r2.Converge(context.Background(), spec, "h", func(string, string) {}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(joined(fake2), "ip addr add") {
		t.Fatal("address added twice")
	}
}

func TestConvergeDisabledTearsDown(t *testing.T) {
	r, fake := newRole(t, loWith)
	_ = os.WriteFile(r.SysctlPath, []byte("x"), 0o644)
	spec, _ := r.Decode([]byte(`{"enabled":false,"vip":"10.0.0.53"}`))
	out, err := r.Converge(context.Background(), spec, "h", func(string, string) {})
	if err != nil || out.Enabled {
		t.Fatalf("%v %+v", err, out)
	}
	all := joined(fake)
	if !strings.Contains(all, "ip addr del 10.0.0.53/32 dev lo") || !strings.Contains(all, "arp_ignore=0") {
		t.Fatalf("teardown calls:\n%s", all)
	}
	if _, err := os.Stat(r.SysctlPath); !os.IsNotExist(err) {
		t.Fatal("sysctl file not removed")
	}
}

func TestStatusRechecksHost(t *testing.T) {
	r, _ := newRole(t, loWith)
	spec, _ := r.Decode([]byte(`{"enabled":true,"vip":"10.0.0.53"}`))
	writeProc(t, r.ProcRoot, map[string]string{
		"net.ipv4.conf.all.arp_ignore": "1", "net.ipv4.conf.all.arp_announce": "2",
		"net.ipv4.conf.lo.arp_ignore": "1", "net.ipv4.conf.lo.arp_announce": "2",
	})
	st, _ := r.Status(context.Background(), spec, roles.Common{State: "ready"})
	m := st.(map[string]any)
	if m["vip_present"] != true || m["sysctls_ok"] != true {
		t.Fatalf("status %v", m)
	}
	writeProc(t, r.ProcRoot, map[string]string{"net.ipv4.conf.lo.arp_announce": "0"})
	st, _ = r.Status(context.Background(), spec, roles.Common{State: "ready"})
	if st.(map[string]any)["sysctls_ok"] != false {
		t.Fatal("drifted sysctl not detected")
	}
	r3, _ := newRole(t, loWithout)
	st, _ = r3.Status(context.Background(), spec, roles.Common{State: "ready"})
	if st.(map[string]any)["vip_present"] != false {
		t.Fatal("missing VIP not detected")
	}
}
