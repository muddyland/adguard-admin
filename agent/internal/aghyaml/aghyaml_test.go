package aghyaml

import (
	"strings"
	"testing"
)

const sample = `# AdGuard Home config
http:
  pprof:
    port: 6060
    enabled: false
  address: 0.0.0.0:3000
  session_ttl: 720h
users:
  - name: admin
    password: $2a$10$hash
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  anonymize_client_ip: false
  ratelimit: 20
filtering:
  protection_enabled: true
schema_version: 29
`

func TestReadAndApply(t *testing.T) {
	b, err := Read([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if b.DNSPort != 53 || b.HTTPAddress != "0.0.0.0:3000" || len(b.DNSBindHosts) != 1 || b.DNSBindHosts[0] != "0.0.0.0" {
		t.Fatalf("read: %+v", b)
	}
	out, err := Apply([]byte(sample), Binds{DNSBindHosts: []string{"127.0.0.1", "::1"}, DNSPort: 5335, HTTPAddress: "127.0.0.1:3000"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{"# AdGuard Home config", "port: 5335", "- 127.0.0.1", "- ::1", "address: 127.0.0.1:3000", "ratelimit: 20", "schema_version: 29", "password: $2a$10$hash"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	back, _ := Read(out)
	if back.DNSPort != 5335 || len(back.DNSBindHosts) != 2 || back.HTTPAddress != "127.0.0.1:3000" {
		t.Fatalf("round trip: %+v", back)
	}
}

func TestApplyCreatesMissingSections(t *testing.T) {
	out, err := Apply([]byte("schema_version: 29\n"), Binds{DNSBindHosts: []string{"0.0.0.0"}, DNSPort: 53, HTTPAddress: "0.0.0.0:3000"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Read(out)
	if b.DNSPort != 53 || b.HTTPAddress != "0.0.0.0:3000" {
		t.Fatalf("%+v\n%s", b, out)
	}
}
