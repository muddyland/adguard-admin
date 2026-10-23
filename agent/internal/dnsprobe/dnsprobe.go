// Package dnsprobe sends one hand-built DNS query over UDP and reports whether
// a valid DNS response came back. It is the keepalived track script.
package dnsprobe

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

// Query builds a standard A query for name with the given ID.
func Query(id uint16, name string) []byte {
	buf := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(buf[0:], id)
	binary.BigEndian.PutUint16(buf[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(buf[4:], 1)      // QDCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)          // root
	buf = append(buf, 0, 1, 0, 1) // QTYPE A, QCLASS IN
	return buf
}

// Valid checks that resp is a response to the query with id: QR bit set,
// matching ID, at least a header.
func Valid(resp []byte, id uint16) bool {
	if len(resp) < 12 {
		return false
	}
	if binary.BigEndian.Uint16(resp[0:]) != id {
		return false
	}
	return resp[2]&0x80 != 0
}

// Probe sends a query to addr and waits up to timeout for a valid answer.
func Probe(addr, name string, timeout time.Duration) error {
	if name == "" {
		name = "a.root-servers.net."
	}
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return err
	}
	id := binary.BigEndian.Uint16(idb[:])
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := conn.Write(Query(id, name)); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if !Valid(buf[:n], id) {
		return errors.New("not a valid DNS response")
	}
	return nil
}
