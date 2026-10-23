package canon

import "testing"

func TestCanonicalMatchesPython(t *testing.T) {
	// Expected values produced by:
	//   json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
	raw := []byte(`{"name": "dns-a", "enabled": true, "port": 5335, "tags": ["b", "a"],
	  "nested": {"z": 1, "a": "ü\n\"q\" <&>\u001f"}, "empty": {}, "n": null}`)
	want := `{"empty":{},"enabled":true,"n":null,"name":"dns-a","nested":{"a":"ü\n\"q\" <&>\u001f","z":1},"port":5335,"tags":["b","a"]}`
	got, err := Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("canonical mismatch\n got %s\nwant %s", got, want)
	}
	h, _ := Hash(raw)
	if h != "9f79ca2f4de2cc349cad631197731aced371e0af2696958a9e1521a6c6f62275" {
		t.Fatalf("hash mismatch: %s", h)
	}
}

func TestHashAdGuardSpec(t *testing.T) {
	raw := []byte(`{"enabled":true,"install_method":"docker","image":"adguard/adguardhome:latest","web_bind":"127.0.0.1","web_port":3000,"dns_bind":["0.0.0.0"],"dns_port":53,"admin_username":"admin","admin_password":"s3cret"}`)
	h, err := Hash(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h != "e8ae4bcd6be3de88355200bd8c5cc91b2fd17036bf4816dff81b08699e9419e8" {
		t.Fatalf("hash mismatch: %s", h)
	}
	// Whitespace and key order must not matter.
	h2, _ := Hash([]byte(`{ "dns_port": 53, "admin_password": "s3cret", "enabled": true, "install_method": "docker", "web_port": 3000, "web_bind": "127.0.0.1", "dns_bind": [ "0.0.0.0" ], "admin_username": "admin", "image": "adguard/adguardhome:latest" }`))
	if h2 != h {
		t.Fatalf("reordered spec hashed differently: %s", h2)
	}
}

func TestRejectsTrailingGarbage(t *testing.T) {
	if _, err := Canonical([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Fatal("expected error")
	}
}
