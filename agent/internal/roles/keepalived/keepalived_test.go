package keepalived

import (
	"net"
	"strings"
	"testing"

	"adguard-admin/agent/internal/execx"
	"adguard-admin/agent/internal/services"
)

func TestRender(t *testing.T) {
	r := New(services.Host{R: &execx.Fake{}})
	spec, err := r.Decode([]byte(`{"enabled":true,"vip":"10.0.0.53/24","router_id":53,"priority":150,
	  "auth_pass":"8charsMx","peers":["10.0.0.12","10.0.0.13"],"src_ip":"10.0.0.11","check_dns":"127.0.0.1:53"}`))
	if err != nil {
		t.Fatal(err)
	}
	conf := Render(spec.(*Spec), "eth0")
	for _, want := range []string{
		"enable_script_security", "script_user root",
		`script "/usr/local/bin/adguard-admin-agent probe-dns 127.0.0.1:53"`, "weight -60",
		"vrrp_instance adguard_admin_53 {", "state BACKUP", "interface eth0", "virtual_router_id 53", "priority 150",
		"auth_type PASS", "auth_pass 8charsMx", "unicast_src_ip 10.0.0.11", "unicast_peer {\n    10.0.0.12\n    10.0.0.13\n  }",
		"virtual_ipaddress {\n    10.0.0.53/24\n  }", "track_script {\n    chk_dns\n  }",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("config lacks %q\n%s", want, conf)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	r := New(services.Host{R: &execx.Fake{}})
	base := `"router_id":53,"auth_pass":"pw","src_ip":"10.0.0.11"`
	for label, raw := range map[string]string{
		"no prefix":  `{"vip":"10.0.0.53",` + base + `}`,
		"loopback":   `{"vip":"127.0.0.1/8",` + base + `}`,
		"router id":  `{"vip":"10.0.0.53/24","router_id":300,"auth_pass":"pw","src_ip":"10.0.0.11"}`,
		"long auth":  `{"vip":"10.0.0.53/24","router_id":1,"auth_pass":"waytoolongpassword","src_ip":"10.0.0.11"}`,
		"auth quote": `{"vip":"10.0.0.53/24","router_id":1,"auth_pass":"a\"b","src_ip":"10.0.0.11"}`,
		"bad peer":   `{"vip":"10.0.0.53/24",` + base + `,"peers":["host"]}`,
		"bad iface":  `{"vip":"10.0.0.53/24",` + base + `,"interface":"eth0; rm"}`,
		"priority":   `{"vip":"10.0.0.53/24","router_id":1,"auth_pass":"pw","src_ip":"10.0.0.11","priority":255}`,
		"check_dns":  `{"vip":"10.0.0.53/24",` + base + `,"check_dns":"nonsense"}`,
	} {
		if _, err := r.Decode([]byte(raw)); err == nil {
			t.Errorf("%s: expected rejection", label)
		}
	}
	// Disabled needs nothing else.
	if _, err := r.Decode([]byte(`{"enabled":false}`)); err != nil {
		t.Fatal(err)
	}
}

func TestVIPOwnerAndInterface(t *testing.T) {
	r := New(services.Host{R: &execx.Fake{}})
	r.Interfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "lo"}, {Name: "eth0"}}, nil
	}
	r.Addrs = func(i net.Interface) ([]net.Addr, error) {
		if i.Name == "eth0" {
			_, a, _ := net.ParseCIDR("10.0.0.11/24")
			_, v, _ := net.ParseCIDR("10.0.0.53/24")
			a.IP = net.ParseIP("10.0.0.11")
			v.IP = net.ParseIP("10.0.0.53")
			return []net.Addr{a, v}, nil
		}
		_, lo, _ := net.ParseCIDR("127.0.0.1/8")
		lo.IP = net.ParseIP("127.0.0.1")
		return []net.Addr{lo}, nil
	}
	if !r.VIPOwner("10.0.0.53/24") {
		t.Fatal("expected VIP owner")
	}
	if r.VIPOwner("10.0.0.99/24") {
		t.Fatal("unexpected VIP owner")
	}
	iface, err := r.interfaceFor("10.0.0.11")
	if err != nil || iface != "eth0" {
		t.Fatalf("interfaceFor: %q %v", iface, err)
	}
}
