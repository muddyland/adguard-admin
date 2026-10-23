package keepalived

import (
	"encoding/hex"
	"net"
	"strconv"
	"strings"
)

// parseProcIPVS parses the kernel's own table at /proc/net/ip_vs, used when
// ipvsadm is missing or cannot talk to the kernel. The format:
//
//	IP Virtual Server version 1.2.1 (size=4096)
//	Prot LocalAddress:Port Scheduler Flags
//	  -> RemoteAddress:Port Forward Weight ActiveConn InActConn
//	UDP  C0A80237:0035 wlc
//	  -> C0A80233:0035      Route   1      0          12
//
// Addresses are hex (IPv6 inside brackets) and ports are hex. Services and
// destinations come back keyed and printed the way ipvsadm prints them, so
// the status code treats both sources alike. The kernel table carries no
// packet counters; only weight and connection counts are filled in.
func parseProcIPVS(text string) (map[string]*ipvsService, []string) {
	into := map[string]*ipvsService{}
	var order []string
	var cur *ipvsService
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if isProtoLine(fields) {
			addr, ok := decodeProcAddr(fields[1])
			if !ok {
				cur = nil
				continue
			}
			key := fields[0] + " " + addr
			svc, ok := into[key]
			if !ok {
				svc = &ipvsService{Proto: fields[0], Addr: addr, Dests: map[string]*ipvsDest{}}
				into[key] = svc
				order = append(order, key)
			}
			cur = svc
			continue
		}
		if fields[0] != "->" || cur == nil || len(fields) < 6 {
			continue
		}
		addr, ok := decodeProcAddr(fields[1])
		if !ok {
			continue
		}
		d, ok := cur.Dests[addr]
		if !ok {
			d = &ipvsDest{Addr: addr}
			cur.Dests[addr] = d
			cur.Order = append(cur.Order, addr)
		}
		// Forward Weight ActiveConn InActConn
		d.Weight = int(bigNum(fields[3]))
		d.seenWeight = true
		d.ActiveConns = bigNum(fields[4])
		d.InactConns = bigNum(fields[5])
	}
	return into, order
}

// decodeProcAddr turns C0A80237:0035 or [20010DB8...]:0035 into 192.168.2.55:53
// or [2001:db8::...]:53.
func decodeProcAddr(s string) (string, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", false
	}
	hexAddr, hexPort := s[:i], s[i+1:]
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return "", false
	}
	hexAddr = strings.TrimSuffix(strings.TrimPrefix(hexAddr, "["), "]")
	raw, err := hex.DecodeString(hexAddr)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", false
	}
	ip := net.IP(raw)
	return net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10)), true
}
