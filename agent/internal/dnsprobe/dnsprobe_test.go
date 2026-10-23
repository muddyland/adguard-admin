package dnsprobe

import (
	"net"
	"testing"
	"time"
)

func TestQueryShape(t *testing.T) {
	q := Query(0x1234, "a.root-servers.net.")
	if len(q) != 12+2+12+5+1+4 {
		t.Fatalf("unexpected length %d", len(q))
	}
	if q[0] != 0x12 || q[1] != 0x34 || q[2] != 0x01 || q[5] != 1 {
		t.Fatalf("bad header % x", q[:6])
	}
	if string(q[13:14]) != "a" || q[12] != 1 || q[14] != 12 {
		t.Fatalf("bad qname encoding % x", q[12:])
	}
	if !Valid(append([]byte{0x12, 0x34, 0x81, 0x80}, make([]byte, 8)...), 0x1234) {
		t.Fatal("valid response rejected")
	}
	if Valid(append([]byte{0x12, 0x35, 0x81, 0x80}, make([]byte, 8)...), 0x1234) {
		t.Fatal("wrong id accepted")
	}
	if Valid(q, 0x1234) {
		t.Fatal("a query (QR=0) must not count as a response")
	}
}

func TestProbeAgainstUDPEcho(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		buf[2] |= 0x80 // flip QR, echo the rest
		_, _ = pc.WriteTo(buf[:n], addr)
	}()
	if err := Probe(pc.LocalAddr().String(), "example.com.", 2*time.Second); err != nil {
		t.Fatal(err)
	}
	// Nothing listening: must fail within the timeout.
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := dead.LocalAddr().String()
	dead.Close()
	if err := Probe(addr, "example.com.", 300*time.Millisecond); err == nil {
		t.Fatal("expected failure against a closed port")
	}
}
