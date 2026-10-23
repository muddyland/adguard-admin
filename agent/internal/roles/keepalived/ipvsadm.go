package keepalived

import (
	"strconv"
	"strings"
)

// ipvsService is one virtual service as ipvsadm lists it.
type ipvsService struct {
	Proto string // UDP, TCP, SCTP
	Addr  string // host:port as printed
	Dests map[string]*ipvsDest
	Order []string
}

// ipvsDest is one real server inside a service, merged from the three listings.
type ipvsDest struct {
	Addr        string
	Weight      int
	ActiveConns float64
	InactConns  float64
	Conns       float64
	InPkts      float64
	InBytes     float64
	CPS         float64
	InPPS       float64
	seenWeight  bool
}

func isProtoLine(fields []string) bool {
	if len(fields) < 2 {
		return false
	}
	switch fields[0] {
	case "TCP", "UDP", "SCTP":
		return true
	}
	return false
}

// parseListing parses one `ipvsadm -Ln [--stats|--rate] --exact` output and
// merges it into services keyed by "PROTO addr:port". kind is "plain", "stats"
// or "rate" and decides which columns the dest lines carry.
func parseListing(text, kind string, into map[string]*ipvsService) []string {
	var order []string
	var cur *ipvsService
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if isProtoLine(fields) {
			key := fields[0] + " " + fields[1]
			svc, ok := into[key]
			if !ok {
				svc = &ipvsService{Proto: fields[0], Addr: fields[1], Dests: map[string]*ipvsDest{}}
				into[key] = svc
			}
			order = append(order, key)
			cur = svc
			continue
		}
		if fields[0] != "->" || cur == nil || len(fields) < 2 {
			continue
		}
		addr := fields[1]
		if addr == "RemoteAddress:Port" {
			continue
		}
		d, ok := cur.Dests[addr]
		if !ok {
			d = &ipvsDest{Addr: addr}
			cur.Dests[addr] = d
			cur.Order = append(cur.Order, addr)
		}
		nums := fields[2:]
		switch kind {
		case "plain": // Forward Weight ActiveConn InActConn
			if len(nums) >= 4 {
				d.Weight = int(bigNum(nums[1]))
				d.seenWeight = true
				d.ActiveConns = bigNum(nums[2])
				d.InactConns = bigNum(nums[3])
			}
		case "stats": // Conns InPkts OutPkts InBytes OutBytes
			if len(nums) >= 5 {
				d.Conns = bigNum(nums[0])
				d.InPkts = bigNum(nums[1])
				d.InBytes = bigNum(nums[3])
			}
		case "rate": // CPS InPPS OutPPS InBPS OutBPS
			if len(nums) >= 5 {
				d.CPS = bigNum(nums[0])
				d.InPPS = bigNum(nums[1])
			}
		}
	}
	return order
}

// bigNum parses ipvsadm's numbers, tolerating the K/M/G suffixes it prints
// without --exact.
func bigNum(s string) float64 {
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "K"):
		mult, s = 1e3, strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "M"):
		mult, s = 1e6, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "G"):
		mult, s = 1e9, strings.TrimSuffix(s, "G")
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v * mult
}
