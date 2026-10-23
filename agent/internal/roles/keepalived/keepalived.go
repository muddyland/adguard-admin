// Package keepalived renders and runs a VRRP instance for a zone's virtual IP,
// and, in IPVS mode, the kernel load balancer behind it (direct routing).
package keepalived

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"adguard-admin/agent/internal/config"
	"adguard-admin/agent/internal/execx"
	"adguard-admin/agent/internal/roles"
	"adguard-admin/agent/internal/services"
)

const (
	UnitName = "keepalived"
	ConfPath = "/etc/keepalived/keepalived.conf"
	// ProbeBinary is the agent itself, used as the VRRP track script and as the
	// MISC_CHECK health checker for IPVS real servers.
	ProbeBinary = "/usr/local/bin/adguard-admin-agent"
	// ModulesLoadPath makes ip_vs load at boot on IPVS directors.
	ModulesLoadPath = "/etc/modules-load.d/adguard-admin-ipvs.conf"
	// DirectorSysctlPath persists net.ipv4.vs.backup_only on IPVS directors.
	DirectorSysctlPath = "/etc/sysctl.d/91-adguard-admin-ipvs-director.conf"
	// backupOnlyKey makes the kernel skip IPVS while the backup sync daemon
	// runs, so a standby director delivers VIP packets to its own resolver.
	backupOnlyKey = "net.ipv4.vs.backup_only"
)

var (
	ifaceRE   = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	authRE    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,8}$`)
	nameRE    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	algos     = map[string]bool{"rr": true, "wrr": true, "lc": true, "wlc": true, "sh": true}
	protocols = map[string]bool{"udp": true, "tcp": true}
)

// IPVSBackend is one real server.
type IPVSBackend struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Weight  int    `json:"weight"`
}

// IPVSCheck is the MISC_CHECK schedule.
type IPVSCheck struct {
	IntervalS int `json:"interval_s"`
	TimeoutS  int `json:"timeout_s"`
	Retry     int `json:"retry"`
}

// IPVSSpec programs the kernel balancer behind the VIP.
type IPVSSpec struct {
	Enabled   bool          `json:"enabled"`
	VIP       string        `json:"vip"`
	Ports     []int         `json:"ports"`
	Protocols []string      `json:"protocols"`
	Algo      string        `json:"algo"`
	Backends  []IPVSBackend `json:"backends"`
	Check     IPVSCheck     `json:"check"`
}

// Spec is the desired state.
type Spec struct {
	Enabled   bool      `json:"enabled"`
	VIP       string    `json:"vip"`
	Interface string    `json:"interface"`
	RouterID  int       `json:"router_id"`
	Priority  int       `json:"priority"`
	AuthPass  string    `json:"auth_pass"`
	Peers     []string  `json:"peers"`
	SrcIP     string    `json:"src_ip"`
	CheckDNS  string    `json:"check_dns"`
	IPVS      *IPVSSpec `json:"ipvs,omitempty"`
}

// IPVSOn reports whether the kernel balancer is part of the desired state.
func (s *Spec) IPVSOn() bool { return s != nil && s.Enabled && s.IPVS != nil && s.IPVS.Enabled }

// Role implements roles.Role.
type Role struct {
	Host        services.Host
	ConfPath    string
	ModulesLoad string
	// DirectorSysctl is the sysctl.d file carrying net.ipv4.vs.backup_only.
	DirectorSysctl string
	// ProcRoot is /proc; tests point it at a directory of their own.
	ProcRoot string
	// DockerEnvPath is /.dockerenv, the fallback container marker.
	DockerEnvPath string
	Dirs          config.Dirs
	Interfaces    func() ([]net.Interface, error)
	Addrs         func(net.Interface) ([]net.Addr, error)
	Now           func() time.Time
	Logger        *log.Logger

	mu           sync.Mutex
	drained      map[string]bool
	lastRendered string // the config written by the last converge
	lastModprobe string // the last `modprobe ip_vs` failure, "" when it worked
	lastSysctl   string // the last backup_only sysctl failure, "" when it worked
}

// New builds a role with production defaults.
func New(h services.Host) *Role {
	return NewWithDirs(h, config.Dirs{})
}

// NewWithDirs builds a role that persists drains under dirs.
func NewWithDirs(h services.Host, dirs config.Dirs) *Role {
	r := &Role{
		Host: h, ConfPath: ConfPath, ModulesLoad: ModulesLoadPath, DirectorSysctl: DirectorSysctlPath,
		ProcRoot: "/proc", DockerEnvPath: "/.dockerenv", Dirs: dirs,
		Interfaces: net.Interfaces,
		Addrs:      func(i net.Interface) ([]net.Addr, error) { return i.Addrs() },
		Now:        time.Now,
		Logger:     log.Default(),
		drained:    map[string]bool{},
	}
	if dirs.State != "" {
		if raw, err := os.ReadFile(r.drainedPath()); err == nil {
			var names []string
			if json.Unmarshal(raw, &names) == nil {
				for _, n := range names {
					r.drained[n] = true
				}
			}
		}
	}
	return r
}

func (r *Role) Name() string { return "keepalived" }

func (r *Role) drainedPath() string { return filepath.Join(r.Dirs.Keepalived(), "drained.json") }

// Decode validates a spec.
func (r *Role) Decode(raw []byte) (any, error) {
	var in struct {
		Enabled   *bool    `json:"enabled"`
		VIP       string   `json:"vip"`
		Interface string   `json:"interface"`
		RouterID  int      `json:"router_id"`
		Priority  int      `json:"priority"`
		AuthPass  string   `json:"auth_pass"`
		Peers     []string `json:"peers"`
		SrcIP     string   `json:"src_ip"`
		CheckDNS  *string  `json:"check_dns"`
		IPVS      *struct {
			Enabled   *bool         `json:"enabled"`
			VIP       string        `json:"vip"`
			Ports     []int         `json:"ports"`
			Protocols []string      `json:"protocols"`
			Algo      string        `json:"algo"`
			Backends  []IPVSBackend `json:"backends"`
			Check     *IPVSCheck    `json:"check"`
		} `json:"ipvs"`
	}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&in); err != nil {
		return nil, fmt.Errorf("invalid keepalived spec: %w", err)
	}
	s := &Spec{Enabled: true, Priority: 100, CheckDNS: "127.0.0.1:53"}
	if in.Enabled != nil {
		s.Enabled = *in.Enabled
	}
	if !s.Enabled {
		return s, nil
	}
	vipIP, _, err := net.ParseCIDR(in.VIP)
	if err != nil {
		return nil, fmt.Errorf("vip %q must be an address with prefix, e.g. 10.0.0.53/24", in.VIP)
	}
	if vipIP.IsUnspecified() || vipIP.IsLoopback() || vipIP.IsMulticast() {
		return nil, errors.New("vip must be a unicast address")
	}
	s.VIP = in.VIP
	if in.Interface != "" && !ifaceRE.MatchString(in.Interface) {
		return nil, fmt.Errorf("interface %q is not a valid interface name", in.Interface)
	}
	s.Interface = in.Interface
	if in.RouterID < 1 || in.RouterID > 255 {
		return nil, errors.New("router_id must be between 1 and 255")
	}
	s.RouterID = in.RouterID
	if in.Priority != 0 {
		if in.Priority < 1 || in.Priority > 254 {
			return nil, errors.New("priority must be between 1 and 254")
		}
		s.Priority = in.Priority
	}
	if !authRE.MatchString(in.AuthPass) {
		return nil, errors.New("auth_pass must be 1 to 8 characters of [A-Za-z0-9._-]")
	}
	s.AuthPass = in.AuthPass
	for _, p := range in.Peers {
		if net.ParseIP(p) == nil {
			return nil, fmt.Errorf("peer %q is not an IP address", p)
		}
		s.Peers = append(s.Peers, p)
	}
	if net.ParseIP(in.SrcIP) == nil {
		return nil, errors.New("src_ip must be an IP address")
	}
	s.SrcIP = in.SrcIP
	if in.CheckDNS != nil {
		if *in.CheckDNS != "" {
			if _, _, err := net.SplitHostPort(*in.CheckDNS); err != nil {
				return nil, errors.New("check_dns must be host:port or empty")
			}
		}
		s.CheckDNS = *in.CheckDNS
	}
	if in.IPVS == nil {
		return s, nil
	}
	v := &IPVSSpec{Enabled: true, Ports: []int{53}, Protocols: []string{"udp", "tcp"}, Algo: "wlc",
		Check: IPVSCheck{IntervalS: 2, TimeoutS: 2, Retry: 2}}
	if in.IPVS.Enabled != nil {
		v.Enabled = *in.IPVS.Enabled
	}
	if !v.Enabled {
		s.IPVS = v
		return s, nil
	}
	ip := net.ParseIP(in.IPVS.VIP)
	if ip == nil {
		return nil, fmt.Errorf("ipvs.vip %q must be an IP address without prefix", in.IPVS.VIP)
	}
	if !ip.Equal(vipIP) {
		return nil, errors.New("ipvs.vip must be the address of the VRRP vip")
	}
	v.VIP = ip.String()
	if len(in.IPVS.Ports) > 0 {
		v.Ports = nil
		for _, p := range in.IPVS.Ports {
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("ipvs.ports: %d is not a port", p)
			}
			v.Ports = append(v.Ports, p)
		}
	}
	if len(in.IPVS.Protocols) > 0 {
		v.Protocols = nil
		for _, pr := range in.IPVS.Protocols {
			pr = strings.ToLower(pr)
			if !protocols[pr] {
				return nil, fmt.Errorf("ipvs.protocols: %q must be udp or tcp", pr)
			}
			v.Protocols = append(v.Protocols, pr)
		}
	}
	if in.IPVS.Algo != "" {
		if !algos[in.IPVS.Algo] {
			return nil, fmt.Errorf("ipvs.algo %q must be one of rr, wrr, lc, wlc, sh", in.IPVS.Algo)
		}
		v.Algo = in.IPVS.Algo
	}
	seen := map[string]bool{}
	for _, b := range in.IPVS.Backends {
		if !nameRE.MatchString(b.Name) {
			return nil, fmt.Errorf("ipvs backend name %q must match [A-Za-z0-9_.-]{1,64}", b.Name)
		}
		if seen[b.Name] {
			return nil, fmt.Errorf("ipvs backend name %q is duplicated", b.Name)
		}
		seen[b.Name] = true
		bip := net.ParseIP(b.Address)
		if bip == nil {
			return nil, fmt.Errorf("ipvs backend %q: address %q must be an IP literal", b.Name, b.Address)
		}
		if b.Port < 1 || b.Port > 65535 {
			return nil, fmt.Errorf("ipvs backend %q: port %d is not a port", b.Name, b.Port)
		}
		if b.Weight < 0 || b.Weight > 65535 {
			return nil, fmt.Errorf("ipvs backend %q: weight must be 0..65535", b.Name)
		}
		v.Backends = append(v.Backends, IPVSBackend{Name: b.Name, Address: bip.String(), Port: b.Port, Weight: b.Weight})
	}
	if in.IPVS.Check != nil {
		c := *in.IPVS.Check
		if c.IntervalS > 0 {
			v.Check.IntervalS = c.IntervalS
		}
		if c.TimeoutS > 0 {
			v.Check.TimeoutS = c.TimeoutS
		}
		if c.Retry >= 0 && in.IPVS.Check.Retry != 0 {
			v.Check.Retry = c.Retry
		}
		if c.IntervalS < 0 || c.TimeoutS < 0 || c.Retry < 0 || c.IntervalS > 3600 || c.TimeoutS > 600 || c.Retry > 100 {
			return nil, errors.New("ipvs.check values are out of range")
		}
	}
	s.IPVS = v
	return s, nil
}

// Render produces keepalived.conf.
func Render(s *Spec, iface string) string {
	var b strings.Builder
	b.WriteString("# generated by adguard-admin-agent\n")
	b.WriteString("global_defs {\n  enable_script_security\n  script_user root\n")
	if s.IPVSOn() {
		// Every director carries the same virtual_server table, so without
		// this a standby would re-schedule the packets the owner direct-routes
		// to it, and the two kernels would bounce each query between them
		// until its TTL ran out (about half of all queries timed out that
		// way). The sync daemon follows the VRRP state: the owner runs the
		// master daemon, every standby the backup daemon, and the backup
		// daemon is what net.ipv4.vs.backup_only keys on (see Converge).
		fmt.Fprintf(&b, "  lvs_sync_daemon %s adguard_admin_%d id %d\n", iface, s.RouterID, s.RouterID)
	}
	b.WriteString("}\n")
	if s.CheckDNS != "" {
		fmt.Fprintf(&b, "vrrp_script chk_dns {\n  script \"%s probe-dns %s\"\n  interval 2\n  timeout 2\n  fall 2\n  rise 2\n  weight -60\n}\n", ProbeBinary, s.CheckDNS)
	}
	fmt.Fprintf(&b, "vrrp_instance adguard_admin_%d {\n", s.RouterID)
	b.WriteString("  state BACKUP\n")
	fmt.Fprintf(&b, "  interface %s\n", iface)
	fmt.Fprintf(&b, "  virtual_router_id %d\n", s.RouterID)
	fmt.Fprintf(&b, "  priority %d\n", s.Priority)
	b.WriteString("  advert_int 1\n")
	fmt.Fprintf(&b, "  authentication {\n    auth_type PASS\n    auth_pass %s\n  }\n", s.AuthPass)
	fmt.Fprintf(&b, "  unicast_src_ip %s\n", s.SrcIP)
	if len(s.Peers) > 0 {
		b.WriteString("  unicast_peer {\n")
		for _, p := range s.Peers {
			fmt.Fprintf(&b, "    %s\n", p)
		}
		b.WriteString("  }\n")
	}
	fmt.Fprintf(&b, "  virtual_ipaddress {\n    %s\n  }\n", s.VIP)
	if s.CheckDNS != "" {
		b.WriteString("  track_script {\n    chk_dns\n  }\n")
	}
	b.WriteString("}\n")
	if s.IPVSOn() {
		renderIPVS(&b, s.IPVS)
	}
	return b.String()
}

// renderIPVS writes one virtual_server per port and protocol. Keywords follow
// keepalived.conf(5) for 2.x: lvs_sched / lvs_method (lb_algo / lb_kind are
// their older aliases). retry and delay_before_retry are checker keywords and
// go inside MISC_CHECK, whose own retry default is 0.
func renderIPVS(b *strings.Builder, v *IPVSSpec) {
	for _, port := range v.Ports {
		for _, proto := range v.Protocols {
			fmt.Fprintf(b, "virtual_server %s %d {\n", v.VIP, port)
			fmt.Fprintf(b, "  delay_loop %d\n", v.Check.IntervalS)
			fmt.Fprintf(b, "  lvs_sched %s\n", v.Algo)
			b.WriteString("  lvs_method DR\n")
			fmt.Fprintf(b, "  protocol %s\n", strings.ToUpper(proto))
			for _, be := range v.Backends {
				fmt.Fprintf(b, "  real_server %s %d {\n", be.Address, be.Port)
				fmt.Fprintf(b, "    weight %d\n", be.Weight)
				b.WriteString("    inhibit_on_failure\n")
				b.WriteString("    MISC_CHECK {\n")
				fmt.Fprintf(b, "      misc_path \"%s probe-dns %s\"\n", ProbeBinary, net.JoinHostPort(be.Address, strconv.Itoa(be.Port)))
				fmt.Fprintf(b, "      misc_timeout %d\n", v.Check.TimeoutS)
				fmt.Fprintf(b, "      retry %d\n", v.Check.Retry)
				b.WriteString("      delay_before_retry 1\n")
				b.WriteString("    }\n")
				b.WriteString("  }\n")
			}
			b.WriteString("}\n")
		}
	}
}

// interfaceFor finds the interface carrying ip.
func (r *Role) interfaceFor(ip string) (string, error) {
	want := net.ParseIP(ip)
	ifaces, err := r.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifaces {
		addrs, err := r.Addrs(i)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(want) {
				return i.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface carries %s; set the interface explicitly", ip)
}

// VIPOwner reports whether the VIP is assigned to a non-loopback interface.
// (IPVS backends hold the VIP on lo too, which does not make them the owner.)
func (r *Role) VIPOwner(vip string) bool {
	ip, _, err := net.ParseCIDR(vip)
	if err != nil {
		return false
	}
	ifaces, err := r.Interfaces()
	if err != nil {
		return false
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || i.Name == "lo" {
			continue
		}
		addrs, err := r.Addrs(i)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// Converge installs, renders and (re)starts keepalived.
func (r *Role) Converge(ctx context.Context, spec any, hash string, report roles.Reporter) (roles.Outcome, error) {
	s := spec.(*Spec)
	if !r.Host.HasSystemd() {
		return roles.Outcome{}, errors.New("keepalived needs systemd")
	}
	if !s.Enabled {
		_, _, _ = r.Host.R.Run(ctx, "systemctl", "stop", UnitName)
		r.applyDirectorSysctl(ctx, false)
		return roles.Outcome{Enabled: false}, nil
	}
	if _, err := r.Host.R.LookPath("keepalived"); err != nil {
		report("installing", "installing the keepalived package")
		if err := r.Host.InstallPackage(ctx, "keepalived"); err != nil {
			return roles.Outcome{}, err
		}
	}
	if s.IPVSOn() {
		if _, err := r.Host.R.LookPath("ipvsadm"); err != nil {
			report("installing", "installing the ipvsadm package")
			if err := r.Host.InstallPackage(ctx, "ipvsadm"); err != nil {
				return roles.Outcome{}, err
			}
		}
		if err := config.WriteFileAtomic(r.ModulesLoad, []byte("ip_vs\n"), 0o644); err != nil {
			return roles.Outcome{}, err
		}
		// Every converge, not just the first: a failure here (no module on
		// this kernel, a container) does not stop the converge, but it is the
		// first thing the diagnostics show when no service gets programmed.
		r.modprobe(ctx)
		r.applyDirectorSysctl(ctx, true)
	} else {
		r.applyDirectorSysctl(ctx, false)
	}
	iface := s.Interface
	if iface == "" {
		var err error
		if iface, err = r.interfaceFor(s.SrcIP); err != nil {
			return roles.Outcome{}, err
		}
	}
	rendered := Render(s, iface)
	r.mu.Lock()
	r.lastRendered = rendered
	r.mu.Unlock()
	current, _ := os.ReadFile(r.ConfPath)
	changed := string(current) != rendered
	if changed {
		if err := config.WriteFileAtomic(r.ConfPath, []byte(rendered), 0o600); err != nil {
			return roles.Outcome{}, err
		}
	}
	if _, _, err := r.Host.R.Run(ctx, "systemctl", "enable", "--now", UnitName); err != nil {
		return roles.Outcome{}, err
	}
	if changed {
		report("installing", "restarting keepalived")
		if _, _, err := r.Host.R.Run(ctx, "systemctl", "restart", UnitName); err != nil {
			return roles.Outcome{}, err
		}
	}
	if s.IPVSOn() {
		if err := r.reapplyDrains(ctx, s); err != nil {
			report("ready", "drains not re-applied: "+err.Error())
		}
	}
	return roles.Outcome{Version: r.version(ctx), Enabled: true}, nil
}

func (r *Role) version(ctx context.Context) string {
	out, errOut, _ := r.Host.R.Run(ctx, "keepalived", "--version")
	text := string(out) + string(errOut)
	if m := regexp.MustCompile(`v?(\d+\.\d+\.\d+)`).FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

// Status renders the status body.
func (r *Role) Status(ctx context.Context, spec any, c roles.Common) (any, error) {
	out := map[string]any{
		"state": c.State, "desired_hash": c.DesiredHash, "applied_hash": c.AppliedHash,
		"version": c.Version, "message": c.Message, "last_change": c.LastChange,
		"vip_owner": false, "interface": "",
	}
	s, ok := spec.(*Spec)
	if !ok || s == nil || !s.Enabled {
		return out, nil
	}
	out["vip_owner"] = r.VIPOwner(s.VIP)
	iface := s.Interface
	if iface == "" {
		iface, _ = r.interfaceFor(s.SrcIP)
	}
	out["interface"] = iface
	if s.IPVSOn() {
		out["ipvs"] = r.ipvsStatus(ctx, s.IPVS)
	}
	return out, nil
}

// modprobe loads ip_vs and remembers how it went for the diagnostics. Inside
// a container the call can never work: modules belong to the host kernel, so
// the log says where to load it instead.
func (r *Role) modprobe(ctx context.Context) {
	_, errOut, err := r.Host.R.Run(ctx, "modprobe", "ip_vs")
	msg := ""
	if err != nil {
		msg = execx.LastLine(string(errOut))
		if msg == "" {
			msg = err.Error()
		}
		if kind := r.containerKind(); kind != "" && r.Logger != nil {
			r.Logger.Printf("keepalived: modprobe ip_vs failed (%s); this host is a %s container, so the ip_vs module must be loaded on the container's host node (e.g. `modprobe ip_vs` there, persisted in /etc/modules-load.d)", msg, kind)
		}
	}
	r.mu.Lock()
	r.lastModprobe = msg
	r.mu.Unlock()
}

// applyDirectorSysctl sets net.ipv4.vs.backup_only=1 on IPVS directors, and
// clears it (and the sysctl.d file) everywhere else. The key only exists once
// ip_vs is loaded, so a failure here is kept for the diagnostics instead of
// failing the converge; the missing module is already reported separately.
func (r *Role) applyDirectorSysctl(ctx context.Context, director bool) {
	msg := ""
	if director {
		body := "# generated by adguard-admin-agent: IPVS director\n" +
			"# A standby director must hand VIP packets to its own resolver instead\n" +
			"# of re-scheduling the ones the VIP owner direct-routes to it.\n" +
			backupOnlyKey + " = 1\n"
		if err := config.WriteFileAtomic(r.DirectorSysctl, []byte(body), 0o644); err != nil {
			msg = err.Error()
		} else if _, errOut, err := r.Host.R.Run(ctx, "sysctl", "-w", backupOnlyKey+"=1"); err != nil {
			msg = execx.LastLine(string(errOut))
			if msg == "" {
				msg = err.Error()
			}
		}
	} else {
		if err := os.Remove(r.DirectorSysctl); err != nil && !errors.Is(err, os.ErrNotExist) {
			msg = err.Error()
		}
		if _, err := os.Stat(r.backupOnlyPath()); err == nil {
			_, _, _ = r.Host.R.Run(ctx, "sysctl", "-w", backupOnlyKey+"=0")
		}
	}
	r.mu.Lock()
	r.lastSysctl = msg
	r.mu.Unlock()
}

func (r *Role) backupOnlyPath() string {
	return filepath.Join(r.ProcRoot, "sys", "net", "ipv4", "vs", "backup_only")
}

// backupOnly reads the live sysctl.
func (r *Role) backupOnly() bool {
	raw, err := os.ReadFile(r.backupOnlyPath())
	return err == nil && strings.TrimSpace(string(raw)) == "1"
}

// syncDaemon reports which IPVS sync daemon runs in this namespace, from
// `ipvsadm -Ln --daemon` (lines like "backup sync daemon (mcast=eth0,
// syncid=53, maxlen=1472)"): "master", "backup", "both" or "none".
func (r *Role) syncDaemon(ctx context.Context) string {
	if _, err := r.Host.R.LookPath("ipvsadm"); err != nil {
		return "none"
	}
	out, _, err := r.Host.R.Run(ctx, "ipvsadm", "-Ln", "--daemon")
	if err != nil {
		return "none"
	}
	master, backup := false, false
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "master sync daemon"):
			master = true
		case strings.HasPrefix(l, "backup sync daemon"):
			backup = true
		}
	}
	switch {
	case master && backup:
		return "both"
	case master:
		return "master"
	case backup:
		return "backup"
	}
	return "none"
}

// containerKind reports the container runtime this host runs under: the
// `container=` variable in PID 1's environment (lxc, docker, podman,
// systemd-nspawn), or "docker" when only /.dockerenv exists; "" on bare metal
// and in VMs.
func (r *Role) containerKind() string {
	if raw, err := os.ReadFile(filepath.Join(r.ProcRoot, "1", "environ")); err == nil {
		for _, kv := range strings.Split(string(raw), "\x00") {
			if v, ok := strings.CutPrefix(kv, "container="); ok {
				v = strings.TrimSpace(v)
				switch {
				case v == "":
				case strings.HasPrefix(v, "lxc"):
					return "lxc"
				case v == "docker", v == "oci":
					return "docker"
				case v == "podman", v == "systemd-nspawn":
					return v
				default:
					return v
				}
			}
		}
	}
	if _, err := os.Stat(r.DockerEnvPath); err == nil {
		return "docker"
	}
	return ""
}

// readIPVS returns the kernel table from ipvsadm, or from /proc/net/ip_vs
// when ipvsadm is missing or fails. counters is false when the source
// carries no packet statistics (the /proc table).
func (r *Role) readIPVS(ctx context.Context) (services map[string]*ipvsService, order []string, counters bool, message string) {
	services = map[string]*ipvsService{}
	if _, err := r.Host.R.LookPath("ipvsadm"); err == nil {
		plain, errOut, err := r.Host.R.Run(ctx, "ipvsadm", "-Ln")
		if err == nil {
			order = parseListing(string(plain), "plain", services)
			if stats, _, err := r.Host.R.Run(ctx, "ipvsadm", "-Ln", "--stats", "--exact"); err == nil {
				parseListing(string(stats), "stats", services)
			}
			if rate, _, err := r.Host.R.Run(ctx, "ipvsadm", "-Ln", "--rate", "--exact"); err == nil {
				parseListing(string(rate), "rate", services)
			}
			return services, order, true, ""
		}
		message = execx.LastLine(string(errOut))
		if message == "" {
			message = err.Error()
		}
		message = "ipvsadm -Ln: " + message
	} else {
		message = "ipvsadm is not installed"
	}
	// Fall back to the kernel's own table.
	raw, err := os.ReadFile(filepath.Join(r.ProcRoot, "net", "ip_vs"))
	if err != nil {
		return services, nil, false, message
	}
	services, order = parseProcIPVS(string(raw))
	return services, order, false, message
}

// diagnostics answers the questions behind "no virtual server programmed".
func (r *Role) diagnostics(ctx context.Context) map[string]any {
	procPath := filepath.Join(r.ProcRoot, "net", "ip_vs")
	_, statErr := os.Stat(procPath)
	_, readErr := os.ReadFile(procPath)
	_, lookErr := r.Host.R.LookPath("ipvsadm")
	r.mu.Lock()
	rendered, modprobeErr, sysctlErr := r.lastRendered, r.lastModprobe, r.lastSysctl
	r.mu.Unlock()
	if rendered == "" {
		if current, err := os.ReadFile(r.ConfPath); err == nil {
			rendered = string(current)
		}
	}
	return map[string]any{
		"ipvsadm":                    lookErr == nil,
		"module_loaded":              statErr == nil,
		"proc_ip_vs":                 readErr == nil,
		"config_has_virtual_servers": strings.Contains(rendered, "virtual_server"),
		"keepalived_running":         r.Host.UnitState(ctx, UnitName).Active,
		"modprobe_error":             modprobeErr,
		"container":                  r.containerKind(),
		"ipvs_permission_denied":     r.ipvsPermissionDenied(ctx),
		"backup_only":                r.backupOnly(),
		"sync_daemon":                r.syncDaemon(ctx),
		"sysctl_error":               sysctlErr,
		"checked_at":                 r.Now().UTC().Format(time.RFC3339),
	}
}

// ipvsPermissionDenied reports whether keepalived's recent log shows the
// kernel refusing IPVS writes. That is what an unprivileged container looks
// like: root inside it lacks CAP_NET_ADMIN in the host's namespace, so every
// IP_VS_SO_SET_* call fails with "Permission denied (you must be root)" while
// VRRP and the health checks carry on as if nothing were wrong.
func (r *Role) ipvsPermissionDenied(ctx context.Context) bool {
	if _, err := r.Host.R.LookPath("journalctl"); err != nil {
		return false
	}
	out, _, err := r.Host.R.Run(ctx, "journalctl", "-u", UnitName, "-n", "60", "--no-pager", "-o", "cat")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "IPVS cmd") && strings.Contains(l, "Permission denied") {
			return true
		}
	}
	return false
}

// ipvsStatus reads the kernel table and sums each backend's services.
// Out-direction counters are left out: replies bypass the director in direct
// routing, so they would always read zero. Packet counters are null when the
// only source was /proc/net/ip_vs, which does not carry them.
func (r *Role) ipvsStatus(ctx context.Context, v *IPVSSpec) map[string]any {
	services, order, counters, message := r.readIPVS(ctx)
	type agg struct {
		be       IPVSBackend
		seen     int
		up       bool
		weight   int
		active   float64
		inactive float64
		conns    float64
		inPkts   float64
		inBytes  float64
		cps      float64
		inPPS    float64
	}
	aggs := map[string]*agg{}
	for _, be := range v.Backends {
		aggs[net.JoinHostPort(be.Address, strconv.Itoa(be.Port))] = &agg{be: be, up: true, weight: be.Weight}
	}
	count := 0
	for _, key := range order {
		svc := services[key]
		host, _, err := net.SplitHostPort(svc.Addr)
		if err != nil || host != v.VIP {
			continue
		}
		count++
		for addr, d := range svc.Dests {
			a, ok := aggs[addr]
			if !ok {
				continue
			}
			a.seen++
			if d.seenWeight {
				a.weight = d.Weight
				if d.Weight <= 0 {
					a.up = false
				}
			}
			a.active += d.ActiveConns
			a.inactive += d.InactConns
			a.conns += d.Conns
			a.inPkts += d.InPkts
			a.inBytes += d.InBytes
			a.cps += d.CPS
			a.inPPS += d.InPPS
		}
	}
	r.mu.Lock()
	drained := map[string]bool{}
	for k, val := range r.drained {
		drained[k] = val
	}
	r.mu.Unlock()
	num := func(x float64) any {
		if !counters {
			return nil
		}
		return x
	}
	backends := make([]any, 0, len(v.Backends))
	for _, be := range v.Backends {
		a := aggs[net.JoinHostPort(be.Address, strconv.Itoa(be.Port))]
		state := "down"
		if a.seen > 0 && a.up {
			state = "up"
		}
		backends = append(backends, map[string]any{
			"name": be.Name, "address": be.Address, "port": be.Port, "weight": a.weight,
			"state": state, "drained": drained[be.Name],
			"active_conns": a.active, "inactive_conns": a.inactive,
			"conns": num(a.conns), "in_pkts": num(a.inPkts), "in_bytes": num(a.inBytes),
			"cps": num(a.cps), "in_pps": num(a.inPPS),
		})
	}
	diag := r.diagnostics(ctx)
	// A standby whose backup sync daemon runs with backup_only set schedules
	// nothing: the kernel hands VIP packets to the local resolver. Its
	// counters are then history from its last spell as owner.
	standby := diag["sync_daemon"] == "backup" && diag["backup_only"] == true
	return map[string]any{
		"present": count > 0, "services": count, "backends": backends, "director": !standby,
		"message": message, "diagnostics": diag,
	}
}

// --------------------------------------------------------------- drains ----

func (r *Role) backend(v *IPVSSpec, name string) (IPVSBackend, bool) {
	for _, b := range v.Backends {
		if b.Name == name {
			return b, true
		}
	}
	return IPVSBackend{}, false
}

// setWeight edits one backend's weight on every programmed service.
func (r *Role) setWeight(ctx context.Context, v *IPVSSpec, be IPVSBackend, weight int) error {
	for _, port := range v.Ports {
		for _, proto := range v.Protocols {
			flag := "-u"
			if proto == "tcp" {
				flag = "-t"
			}
			args := []string{"-e", flag, net.JoinHostPort(v.VIP, strconv.Itoa(port)),
				"-r", net.JoinHostPort(be.Address, strconv.Itoa(be.Port)), "-g", "-w", strconv.Itoa(weight)}
			if _, _, err := r.Host.R.Run(ctx, "ipvsadm", args...); err != nil {
				return err
			}
		}
	}
	return nil
}

// SetDrained sets a backend's IPVS weight to 0 (drain) or back to its spec
// weight (undrain), and remembers the choice across restarts.
func (r *Role) SetDrained(ctx context.Context, spec any, name string, drain bool) error {
	s, ok := spec.(*Spec)
	if !ok || s == nil || !s.IPVSOn() {
		return errors.New("ipvs is not managed on this host")
	}
	be, ok := r.backend(s.IPVS, name)
	if !ok {
		return fmt.Errorf("no backend named %q", name)
	}
	weight := be.Weight
	if drain {
		weight = 0
	}
	if err := r.setWeight(ctx, s.IPVS, be, weight); err != nil {
		return err
	}
	r.mu.Lock()
	if drain {
		r.drained[name] = true
	} else {
		delete(r.drained, name)
	}
	names := r.drainedLocked()
	r.mu.Unlock()
	raw, _ := json.Marshal(names)
	return config.WriteFileAtomic(r.drainedPath(), raw, 0o600)
}

func (r *Role) drainedLocked() []string {
	names := make([]string, 0, len(r.drained))
	for n := range r.drained {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (r *Role) reapplyDrains(ctx context.Context, s *Spec) error {
	r.mu.Lock()
	names := r.drainedLocked()
	r.mu.Unlock()
	for _, name := range names {
		be, ok := r.backend(s.IPVS, name)
		if !ok {
			r.mu.Lock()
			delete(r.drained, name)
			r.mu.Unlock()
			continue
		}
		if err := r.setWeight(ctx, s.IPVS, be, 0); err != nil {
			return err
		}
	}
	return nil
}
