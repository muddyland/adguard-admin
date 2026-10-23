package keepalived

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"adguard-admin/agent/internal/config"
	"adguard-admin/agent/internal/execx"
	"adguard-admin/agent/internal/services"
)

// The kernel's own table: hex addresses and ports, no packet counters.
const procIPVS = `IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port Forward Weight ActiveConn InActConn
UDP  C0A80237:0035 wlc
  -> C0A80233:0035      Route   1      0          12
  -> C0A80234:0035      Route   1      0          9
TCP  C0A80237:0035 wlc
  -> C0A80233:0035      Route   1      0          0
  -> C0A80234:0035      Route   0      0          0
TCP  [20010DB8000000000000000000000001]:0035 rr
  -> [20010DB8000000000000000000000002]:0035      Route   1      0          0
`

const procSpecJSON = `{"enabled":true,"vip":"192.168.2.55/24","router_id":55,"priority":150,
  "auth_pass":"8charsMx","peers":[],"src_ip":"192.168.2.53","check_dns":"",
  "ipvs":{"enabled":true,"vip":"192.168.2.55","ports":[53],"protocols":["udp","tcp"],"algo":"wlc",
          "backends":[{"name":"lan-01-1","address":"192.168.2.51","port":53,"weight":1},
                      {"name":"lan-02-2","address":"192.168.2.52","port":53,"weight":1},
                      {"name":"lan-03-3","address":"192.168.2.53","port":53,"weight":1}]}}`

func TestParseProcIPVS(t *testing.T) {
	svcs, order := parseProcIPVS(procIPVS)
	if len(order) != 3 {
		t.Fatalf("order %v", order)
	}
	if order[0] != "UDP 192.168.2.55:53" || order[1] != "TCP 192.168.2.55:53" || order[2] != "TCP [2001:db8::1]:53" {
		t.Fatalf("decoded service keys %v", order)
	}
	udp := svcs["UDP 192.168.2.55:53"]
	d := udp.Dests["192.168.2.52:53"]
	if d == nil || !d.seenWeight || d.Weight != 1 || d.ActiveConns != 0 || d.InactConns != 9 || d.InPkts != 0 {
		t.Fatalf("udp dest: %+v", d)
	}
	tcp := svcs["TCP 192.168.2.55:53"]
	if tcp.Dests["192.168.2.52:53"].Weight != 0 {
		t.Fatal("weight 0 not parsed")
	}
	if svcs["TCP [2001:db8::1]:53"].Dests["[2001:db8::2]:53"] == nil {
		t.Fatal("IPv6 destination not decoded")
	}
	if _, ok := decodeProcAddr("ZZZZ:0035"); ok {
		t.Fatal("garbage address accepted")
	}
}

func procRole(t *testing.T, fake *execx.Fake, withProc bool) (*Role, string) {
	t.Helper()
	dir := t.TempDir()
	r := NewWithDirs(services.Host{R: fake}, config.Dirs{State: dir})
	r.ProcRoot = filepath.Join(dir, "proc")
	r.ConfPath = filepath.Join(dir, "keepalived.conf")
	r.Now = func() time.Time { return time.Date(2026, 10, 23, 3, 10, 0, 0, time.UTC) }
	r.DockerEnvPath = filepath.Join(dir, "dockerenv-absent")
	if withProc {
		if err := os.MkdirAll(filepath.Join(r.ProcRoot, "net"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(r.ProcRoot, "net", "ip_vs"), []byte(procIPVS), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return r, dir
}

func systemctlHandler(active bool) func(name string, args []string) execx.Result {
	return func(name string, args []string) execx.Result {
		if name == "systemctl" && len(args) > 0 && args[0] == "show" {
			state := "inactive"
			if active {
				state = "active"
			}
			return execx.Result{Stdout: "LoadState=loaded\nActiveState=" + state + "\n"}
		}
		return execx.Result{}
	}
}

func TestDiagnosticsFromProcRootAndFakeExec(t *testing.T) {
	// Module absent, ipvsadm absent, config without virtual_server, keepalived stopped.
	fake := &execx.Fake{Programs: map[string]bool{"systemctl": true}, Handler: systemctlHandler(false)}
	r, _ := procRole(t, fake, false)
	r.mu.Lock()
	r.lastRendered = "vrrp_instance x {}\n"
	r.lastModprobe = "modprobe: FATAL: Module ip_vs not found in directory /lib/modules/6.1.0"
	r.mu.Unlock()
	d := r.diagnostics(context.Background())
	want := map[string]any{
		"ipvsadm": false, "module_loaded": false, "proc_ip_vs": false,
		"config_has_virtual_servers": false, "keepalived_running": false,
		"modprobe_error": "modprobe: FATAL: Module ip_vs not found in directory /lib/modules/6.1.0",
		"container":      "",
		"checked_at":     "2026-10-23T03:10:00Z",
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("%s = %v, want %v", k, d[k], v)
		}
	}

	// Everything present.
	fake = &execx.Fake{Programs: map[string]bool{"systemctl": true, "ipvsadm": true}, Handler: systemctlHandler(true)}
	r, _ = procRole(t, fake, true)
	r.mu.Lock()
	r.lastRendered = "virtual_server 192.168.2.55 53 {\n}\n"
	r.mu.Unlock()
	d = r.diagnostics(context.Background())
	for _, k := range []string{"ipvsadm", "module_loaded", "proc_ip_vs", "config_has_virtual_servers", "keepalived_running"} {
		if d[k] != true {
			t.Errorf("%s should be true: %v", k, d)
		}
	}
	if d["modprobe_error"] != "" {
		t.Errorf("modprobe_error should be empty, got %v", d["modprobe_error"])
	}
	// With no converge in this process, the on-disk config stands in for the rendered one.
	r2, dir := procRole(t, fake, true)
	if err := os.WriteFile(filepath.Join(dir, "keepalived.conf"), []byte("virtual_server 1.2.3.4 53 {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r2.diagnostics(context.Background())["config_has_virtual_servers"] != true {
		t.Error("on-disk config not consulted")
	}
}

func TestContainerKindFromPid1EnvironAndDockerenv(t *testing.T) {
	fake := &execx.Fake{}
	r, dir := procRole(t, fake, false)
	if err := os.MkdirAll(filepath.Join(r.ProcRoot, "1"), 0o755); err != nil {
		t.Fatal(err)
	}
	environ := "PATH=/usr/bin\x00container=lxc\x00HOME=/root\x00"
	if err := os.WriteFile(filepath.Join(r.ProcRoot, "1", "environ"), []byte(environ), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := r.containerKind(); got != "lxc" {
		t.Fatalf("container kind %q, want lxc", got)
	}
	if r.diagnostics(context.Background())["container"] != "lxc" {
		t.Fatal("diagnostics must carry the container kind")
	}
	// Proxmox-style lxc-libvirt and systemd-nspawn spellings.
	_ = os.WriteFile(filepath.Join(r.ProcRoot, "1", "environ"), []byte("container=systemd-nspawn\x00"), 0o644)
	if got := r.containerKind(); got != "systemd-nspawn" {
		t.Fatalf("got %q", got)
	}
	// No container= variable: fall back to /.dockerenv, then to "".
	_ = os.WriteFile(filepath.Join(r.ProcRoot, "1", "environ"), []byte("PATH=/usr/bin\x00"), 0o644)
	if got := r.containerKind(); got != "" {
		t.Fatalf("bare metal should be empty, got %q", got)
	}
	r.DockerEnvPath = filepath.Join(dir, "dockerenv")
	_ = os.WriteFile(r.DockerEnvPath, nil, 0o644)
	if got := r.containerKind(); got != "docker" {
		t.Fatalf("/.dockerenv should mean docker, got %q", got)
	}

	// In a container, a modprobe failure is logged with the host-node hint.
	var logged strings.Builder
	r.Logger = log.New(&logged, "", 0)
	_ = os.WriteFile(filepath.Join(r.ProcRoot, "1", "environ"), []byte("container=lxc\x00"), 0o644)
	fake.Handler = func(name string, args []string) execx.Result {
		if name == "modprobe" {
			return execx.Result{Stderr: "modprobe: ERROR: could not insert 'ip_vs': Operation not permitted\n", Err: errors.New("exit status 1")}
		}
		return execx.Result{}
	}
	r.modprobe(context.Background())
	if !strings.Contains(logged.String(), "lxc container") || !strings.Contains(logged.String(), "loaded on the container's host node") {
		t.Fatalf("log line missing the host-node hint: %q", logged.String())
	}
}

func TestModprobeErrorIsRecordedNotFatal(t *testing.T) {
	fake := &execx.Fake{Handler: func(name string, args []string) execx.Result {
		if name == "modprobe" {
			return execx.Result{Stderr: "modprobe: FATAL: Module ip_vs not found in directory /lib/modules/6.1.0\n", Err: errors.New("exit status 1")}
		}
		return execx.Result{}
	}}
	r, _ := procRole(t, fake, false)
	r.modprobe(context.Background())
	if r.diagnostics(context.Background())["modprobe_error"] != "modprobe: FATAL: Module ip_vs not found in directory /lib/modules/6.1.0" {
		t.Fatalf("modprobe error not recorded: %v", r.lastModprobe)
	}
	fake.Handler = func(string, []string) execx.Result { return execx.Result{} }
	r.modprobe(context.Background())
	if r.lastModprobe != "" {
		t.Fatal("a successful modprobe should clear the error")
	}
}

func TestIPVSStatusFallsBackToProcWhenIpvsadmFails(t *testing.T) {
	fake := &execx.Fake{Programs: map[string]bool{"systemctl": true, "ipvsadm": true}}
	fake.Handler = func(name string, args []string) execx.Result {
		if name == "ipvsadm" {
			return execx.Result{Stderr: "Can't initialize ipvs: Protocol not available\nAre you sure that IP Virtual Server is built in the kernel or as module?\n", Err: errors.New("exit status 255")}
		}
		return systemctlHandler(true)(name, args)
	}
	r, _ := procRole(t, fake, true)
	spec, err := r.Decode([]byte(procSpecJSON))
	if err != nil {
		t.Fatal(err)
	}
	st := r.ipvsStatus(context.Background(), spec.(*Spec).IPVS)
	if st["present"] != true || st["services"] != 2 {
		t.Fatalf("fallback did not read the kernel table: %v", st)
	}
	if !strings.Contains(st["message"].(string), "ipvsadm -Ln: Are you sure that IP Virtual Server is built in the kernel") {
		t.Fatalf("message should carry ipvsadm's last stderr line: %q", st["message"])
	}
	backends := st["backends"].([]any)
	b1 := backends[0].(map[string]any)
	b2 := backends[1].(map[string]any)
	b3 := backends[2].(map[string]any)
	if b1["state"] != "up" || b1["weight"] != 1 || b1["inactive_conns"] != 12.0 {
		t.Fatalf("backend 1: %v", b1)
	}
	// lan-02 has weight 0 on the TCP service -> down, and the kernel table has no packet counters.
	if b2["state"] != "down" || b2["in_pkts"] != nil || b2["in_pps"] != nil || b2["conns"] != nil {
		t.Fatalf("backend 2: %v", b2)
	}
	// lan-03 is in the spec but not in the kernel table -> down, counters null.
	if b3["state"] != "down" || b3["in_pkts"] != nil {
		t.Fatalf("backend 3: %v", b3)
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"in_pkts":null`) {
		t.Fatalf("unknown counters must serialise as null: %s", raw)
	}
	if d := st["diagnostics"].(map[string]any); d["module_loaded"] != true || d["ipvsadm"] != true {
		t.Fatalf("diagnostics: %v", d)
	}
}

func TestIPVSStatusWithoutIpvsadmOrModule(t *testing.T) {
	fake := &execx.Fake{Programs: map[string]bool{"systemctl": true}, Handler: systemctlHandler(true)}
	r, _ := procRole(t, fake, false)
	spec, _ := r.Decode([]byte(procSpecJSON))
	st := r.ipvsStatus(context.Background(), spec.(*Spec).IPVS)
	if st["present"] != false || st["services"] != 0 || st["message"] != "ipvsadm is not installed" {
		t.Fatalf("status: %v", st)
	}
	d := st["diagnostics"].(map[string]any)
	if d["ipvsadm"] != false || d["module_loaded"] != false || d["keepalived_running"] != true {
		t.Fatalf("diagnostics: %v", d)
	}
	for _, c := range fake.Calls {
		if c.Name == "ipvsadm" {
			t.Fatal("ipvsadm must not be run when LookPath says it is absent")
		}
	}
}
