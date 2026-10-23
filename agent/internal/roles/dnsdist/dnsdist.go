// Package dnsdist renders, validates, runs and observes a dnsdist balancer.
package dnsdist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"adguard-admin/agent/internal/config"
	"adguard-admin/agent/internal/roles"
	"adguard-admin/agent/internal/services"
)

const (
	ContainerName = "dnsdist"
	UnitName      = "dnsdist"
	DefaultImage  = "powerdns/dnsdist-20:2.0.8"
	APIAddr       = "127.0.0.1:8083"
	ConsoleAddr   = "127.0.0.1:5199"
	// The rendered directory is mounted here inside the container (a directory,
	// not a file, so an atomic rename of the config is visible to the container).
	containerConfDir = "/etc/dnsdist/agent"
	bareConfPath     = "/etc/dnsdist/dnsdist.conf"
)

var (
	nameRE   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	fqdnRE   = regexp.MustCompile(`^(?:[A-Za-z0-9-]{1,63}\.)+$|^(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}\.?$`)
	policies = map[string]bool{"leastOutstanding": true, "roundrobin": true, "wrandom": true, "whashed": true, "firstAvailable": true}
)

// Backend is one downstream server.
type Backend struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Weight  int    `json:"weight"`
	Order   int    `json:"order"`
}

// Spec is the desired state.
type Spec struct {
	Enabled       bool     `json:"enabled"`
	InstallMethod string   `json:"install_method"`
	Image         string   `json:"image"`
	Listen        []string `json:"listen"`
	Policy        string   `json:"policy"`
	ECS           bool     `json:"ecs"`
	Cache         struct {
		Enabled    bool `json:"enabled"`
		MaxEntries int  `json:"max_entries"`
	} `json:"cache"`
	Healthcheck struct {
		Name        string `json:"name"`
		IntervalS   int    `json:"interval_s"`
		MaxFailures int    `json:"max_failures"`
		Rise        int    `json:"rise"`
		Mode        string `json:"mode"`
	} `json:"healthcheck"`
	ACL      []string  `json:"acl"`
	Backends []Backend `json:"backends"`
}

// Role implements roles.Role.
type Role struct {
	Host        services.Host
	Dirs        config.Dirs
	APIKey      string
	ConsoleKey  string
	HTTP        *http.Client
	WaitTimeout time.Duration
	Sleep       func(time.Duration)
	Resolve     func(host string) ([]net.IP, error)

	mu      sync.Mutex
	drained map[string]bool
}

// New builds a role with production defaults.
func New(h services.Host, dirs config.Dirs, apiKey, consoleKey string) *Role {
	r := &Role{
		Host: h, Dirs: dirs, APIKey: apiKey, ConsoleKey: consoleKey,
		HTTP:        &http.Client{Timeout: 5 * time.Second},
		WaitTimeout: 30 * time.Second,
		Sleep:       time.Sleep,
		Resolve:     net.LookupIP,
		drained:     map[string]bool{},
	}
	if raw, err := os.ReadFile(r.drainedPath()); err == nil {
		var names []string
		if json.Unmarshal(raw, &names) == nil {
			for _, n := range names {
				r.drained[n] = true
			}
		}
	}
	return r
}

func (r *Role) Name() string { return "dnsdist" }

func (r *Role) confDir() string     { return r.Dirs.Dnsdist() }
func (r *Role) confPath() string    { return filepath.Join(r.confDir(), "dnsdist.conf") }
func (r *Role) appliedPath() string { return filepath.Join(r.confDir(), "applied.json") }
func (r *Role) drainedPath() string { return filepath.Join(r.confDir(), "drained.json") }

// Decode validates and defaults a spec.
func (r *Role) Decode(raw []byte) (any, error) {
	var in struct {
		Enabled       *bool    `json:"enabled"`
		InstallMethod string   `json:"install_method"`
		Image         string   `json:"image"`
		Listen        []string `json:"listen"`
		Policy        string   `json:"policy"`
		ECS           *bool    `json:"ecs"`
		Cache         *struct {
			Enabled    bool `json:"enabled"`
			MaxEntries int  `json:"max_entries"`
		} `json:"cache"`
		Healthcheck *struct {
			Name        string `json:"name"`
			IntervalS   int    `json:"interval_s"`
			MaxFailures int    `json:"max_failures"`
			Rise        int    `json:"rise"`
			Mode        string `json:"mode"`
		} `json:"healthcheck"`
		ACL      []string  `json:"acl"`
		Backends []Backend `json:"backends"`
	}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&in); err != nil {
		return nil, fmt.Errorf("invalid dnsdist spec: %w", err)
	}
	s := &Spec{Enabled: true, InstallMethod: "docker", Image: DefaultImage, Listen: []string{"0.0.0.0:53"}, Policy: "leastOutstanding", ECS: true}
	s.Cache.MaxEntries = 100000
	s.Healthcheck.Name, s.Healthcheck.IntervalS, s.Healthcheck.MaxFailures, s.Healthcheck.Rise, s.Healthcheck.Mode = "a.root-servers.net.", 1, 3, 2, "auto"
	s.ACL = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}

	if in.Enabled != nil {
		s.Enabled = *in.Enabled
	}
	if in.InstallMethod != "" {
		s.InstallMethod = in.InstallMethod
	}
	if s.InstallMethod != "docker" && s.InstallMethod != "bare_metal" {
		return nil, errors.New("install_method must be docker or bare_metal")
	}
	if in.Image != "" {
		if strings.ContainsAny(in.Image, " \t\n\"'") || strings.HasPrefix(in.Image, "-") {
			return nil, errors.New("image reference is not valid")
		}
		s.Image = in.Image
	}
	if len(in.Listen) > 0 {
		s.Listen = nil
		for _, l := range in.Listen {
			host, port, err := net.SplitHostPort(l)
			if err != nil {
				return nil, fmt.Errorf("listen %q must be ip:port", l)
			}
			if net.ParseIP(host) == nil {
				return nil, fmt.Errorf("listen %q: host must be an IP address", l)
			}
			if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("listen %q: bad port", l)
			}
			s.Listen = append(s.Listen, l)
		}
	}
	if in.Policy != "" {
		if !policies[in.Policy] {
			return nil, fmt.Errorf("policy %q is not one of leastOutstanding, roundrobin, wrandom, whashed, firstAvailable", in.Policy)
		}
		s.Policy = in.Policy
	}
	if in.ECS != nil {
		s.ECS = *in.ECS
	}
	if in.Cache != nil {
		s.Cache.Enabled = in.Cache.Enabled
		if in.Cache.MaxEntries > 0 {
			s.Cache.MaxEntries = in.Cache.MaxEntries
		}
	}
	if in.Healthcheck != nil {
		h := in.Healthcheck
		if h.Name != "" {
			if !fqdnRE.MatchString(h.Name) || len(h.Name) > 253 {
				return nil, fmt.Errorf("healthcheck.name %q is not a domain name", h.Name)
			}
			s.Healthcheck.Name = h.Name
		}
		if h.IntervalS > 0 {
			s.Healthcheck.IntervalS = h.IntervalS
		}
		if h.MaxFailures > 0 {
			s.Healthcheck.MaxFailures = h.MaxFailures
		}
		if h.Rise > 0 {
			s.Healthcheck.Rise = h.Rise
		}
		if h.Mode != "" {
			if h.Mode != "auto" && h.Mode != "lazy" {
				return nil, errors.New("healthcheck.mode must be auto or lazy")
			}
			s.Healthcheck.Mode = h.Mode
		}
	}
	if in.ACL != nil {
		s.ACL = nil
		for _, a := range in.ACL {
			if _, _, err := net.ParseCIDR(a); err != nil {
				return nil, fmt.Errorf("acl entry %q is not a CIDR network", a)
			}
			s.ACL = append(s.ACL, a)
		}
	}
	seen := map[string]bool{}
	for _, b := range in.Backends {
		if !nameRE.MatchString(b.Name) {
			return nil, fmt.Errorf("backend name %q must match [A-Za-z0-9_.-]{1,64}", b.Name)
		}
		if seen[b.Name] {
			return nil, fmt.Errorf("duplicate backend name %q", b.Name)
		}
		seen[b.Name] = true
		if b.Address == "" || strings.ContainsAny(b.Address, " \t\n\"'[]") {
			return nil, fmt.Errorf("backend %q: address is not valid", b.Name)
		}
		if b.Port == 0 {
			b.Port = 53
		}
		if b.Port < 1 || b.Port > 65535 {
			return nil, fmt.Errorf("backend %q: bad port", b.Name)
		}
		if b.Weight <= 0 {
			b.Weight = 1
		}
		if b.Order <= 0 {
			b.Order = 1
		}
		s.Backends = append(s.Backends, b)
	}
	if s.Enabled && len(s.Backends) == 0 {
		return nil, errors.New("at least one backend is required")
	}
	return s, nil
}

// ------------------------------------------------------------ rendering ----

func luaString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\%03d`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Render produces the Lua configuration. Hostnames in backend addresses are
// resolved here because dnsdist's newServer() takes IP literals only.
func (r *Role) Render(s *Spec, hash string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "-- generated by adguard-admin-agent; hash %s\n", hash)
	for i, l := range s.Listen {
		if i == 0 {
			fmt.Fprintf(&b, "setLocal(%s)\n", luaString(l))
		} else {
			fmt.Fprintf(&b, "addLocal(%s)\n", luaString(l))
		}
	}
	acl := make([]string, 0, len(s.ACL))
	for _, a := range s.ACL {
		acl = append(acl, luaString(a))
	}
	fmt.Fprintf(&b, "setACL({%s})\n", strings.Join(acl, ", "))
	for _, be := range s.Backends {
		ip, err := r.resolveBackend(be.Address)
		if err != nil {
			return "", err
		}
		addr := net.JoinHostPort(ip, strconv.Itoa(be.Port))
		fmt.Fprintf(&b, "newServer({name=%s, address=%s, weight=%d, order=%d, useClientSubnet=%t, checkName=%s, checkInterval=%d, maxCheckFailures=%d, rise=%d, healthCheckMode=%s})\n",
			luaString(be.Name), luaString(addr), be.Weight, be.Order, s.ECS,
			luaString(s.Healthcheck.Name), s.Healthcheck.IntervalS, s.Healthcheck.MaxFailures, s.Healthcheck.Rise, luaString(s.Healthcheck.Mode))
	}
	fmt.Fprintf(&b, "setServerPolicy(%s)\n", s.Policy)
	if s.Cache.Enabled {
		fmt.Fprintf(&b, "pc = newPacketCache(%d, {maxTTL=86400, minTTL=0})\ngetPool(\"\"):setCache(pc)\n", s.Cache.MaxEntries)
	}
	fmt.Fprintf(&b, "webserver(%s)\n", luaString(APIAddr))
	fmt.Fprintf(&b, "setWebserverConfig({apiKey=%s, acl=%s})\n", luaString(r.APIKey), luaString("127.0.0.1/32,::1/128"))
	fmt.Fprintf(&b, "controlSocket(%s)\n", luaString(ConsoleAddr))
	fmt.Fprintf(&b, "setKey(%s)\n", luaString(r.ConsoleKey))
	return b.String(), nil
}

func (r *Role) resolveBackend(address string) (string, error) {
	if ip := net.ParseIP(address); ip != nil {
		return ip.String(), nil
	}
	ips, err := r.Resolve(address)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("backend address %q does not resolve: %v", address, err)
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return ips[0].String(), nil
}

// ------------------------------------------------------------- converge ----

type applied struct {
	Hash  string `json:"hash"`
	Image string `json:"image"`
}

func (r *Role) readApplied() applied {
	var a applied
	if raw, err := os.ReadFile(r.appliedPath()); err == nil {
		_ = json.Unmarshal(raw, &a)
	}
	return a
}

func (r *Role) writeApplied(a applied) error {
	raw, _ := json.Marshal(a)
	return config.WriteFileAtomic(r.appliedPath(), raw, 0o600)
}

// Status renders the status body, including live data from dnsdist's API.
func (r *Role) Status(ctx context.Context, spec any, c roles.Common) (any, error) {
	out := map[string]any{
		"state": c.State, "desired_hash": c.DesiredHash, "applied_hash": c.AppliedHash,
		"version": c.Version, "message": c.Message, "last_change": c.LastChange,
		"backends": []any{}, "frontends": []any{}, "stats": map[string]any{}, "drained": r.drainedList(),
	}
	s, ok := spec.(*Spec)
	if !ok || s == nil {
		return out, nil
	}
	out["install_method"] = s.InstallMethod
	if c.State != "ready" {
		return out, nil
	}
	live, err := r.fetchLive(ctx)
	if err != nil {
		out["message"] = "dnsdist API unreachable: " + err.Error()
		return out, nil
	}
	for k, v := range live {
		out[k] = v
	}
	return out, nil
}

func (r *Role) drainedList() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.drained))
	for n := range r.drained {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Converge brings dnsdist to the spec.
func (r *Role) Converge(ctx context.Context, spec any, hash string, report roles.Reporter) (roles.Outcome, error) {
	s := spec.(*Spec)
	if !s.Enabled {
		return r.stop(ctx, s)
	}
	lua, err := r.Render(s, hash)
	if err != nil {
		return roles.Outcome{}, err
	}
	prev := r.readApplied()
	var version string
	if s.InstallMethod == "docker" {
		version, err = r.convergeDocker(ctx, s, hash, lua, prev, report)
	} else {
		version, err = r.convergeBare(ctx, s, hash, lua, prev, report)
	}
	if err != nil {
		return roles.Outcome{}, err
	}
	if err := r.writeApplied(applied{Hash: hash, Image: s.Image}); err != nil {
		return roles.Outcome{}, err
	}
	if err := r.reapplyDrains(ctx, s); err != nil {
		report("ready", "drains not re-applied: "+err.Error())
	}
	return roles.Outcome{Version: version, Enabled: true}, nil
}

func (r *Role) stop(ctx context.Context, s *Spec) (roles.Outcome, error) {
	if s.InstallMethod == "docker" {
		if c, _ := r.Host.ContainerState(ctx, ContainerName); c.Exists && c.Running {
			if _, _, err := r.Host.R.Run(ctx, "docker", "stop", ContainerName); err != nil {
				return roles.Outcome{}, err
			}
		}
		return roles.Outcome{Enabled: false}, nil
	}
	if r.Host.HasSystemd() {
		_, _, _ = r.Host.R.Run(ctx, "systemctl", "stop", UnitName)
	}
	return roles.Outcome{Enabled: false}, nil
}

// RunArgs is the docker run argument list (exported for tests). The image
// runs as the unprivileged pdns user, which cannot bind :53 on the host
// network, so the container starts as root with only the capabilities needed
// to bind and then drop, and dnsdist itself drops to pdns after binding.
func (r *Role) RunArgs(s *Spec) []string {
	return []string{
		"run", "-d", "--name", ContainerName, "--network", "host", "--restart", "unless-stopped",
		"--user", "0:0", "--cap-drop", "ALL",
		"--cap-add", "NET_BIND_SERVICE", "--cap-add", "SETUID", "--cap-add", "SETGID",
		"--security-opt", "no-new-privileges",
		"-l", "adguard-admin.managed=true",
		"-v", r.confDir() + ":" + containerConfDir + ":ro",
		s.Image,
		"--uid", "pdns", "--gid", "pdns", "-C", containerConfDir + "/dnsdist.conf",
	}
}

func (r *Role) convergeDocker(ctx context.Context, s *Spec, hash, lua string, prev applied, report roles.Reporter) (string, error) {
	if !r.Host.HasDocker(ctx) {
		return "", errors.New("docker is not available on this host")
	}
	if err := config.WriteFileAtomic(r.confPath(), []byte(lua), 0o600); err != nil {
		return "", err
	}
	c, err := r.Host.ContainerState(ctx, ContainerName)
	if err != nil {
		return "", err
	}
	configChanged := prev.Hash != hash
	if configChanged || !c.Exists {
		report("installing", "validating the dnsdist configuration")
		if _, _, err := r.Host.R.Run(ctx, "docker", "run", "--rm", "--user", "0:0",
			"-v", r.confDir()+":"+containerConfDir+":ro", "--entrypoint", "dnsdist", s.Image,
			"--check-config", "-C", containerConfDir+"/dnsdist.conf"); err != nil {
			return "", fmt.Errorf("dnsdist rejected the configuration: %w", err)
		}
	}
	switch {
	case !c.Exists:
		report("installing", "starting the dnsdist container")
		if _, _, err := r.Host.R.Run(ctx, "docker", r.RunArgs(s)...); err != nil {
			return "", err
		}
	case c.Image != s.Image:
		report("installing", "recreating dnsdist with the new image")
		if _, _, err := r.Host.R.Run(ctx, "docker", "rm", "-f", ContainerName); err != nil {
			return "", err
		}
		if _, _, err := r.Host.R.Run(ctx, "docker", r.RunArgs(s)...); err != nil {
			return "", err
		}
	case configChanged:
		report("installing", "restarting dnsdist with the new configuration")
		if _, _, err := r.Host.R.Run(ctx, "docker", "restart", ContainerName); err != nil {
			return "", err
		}
	case !c.Running:
		if _, _, err := r.Host.R.Run(ctx, "docker", "start", ContainerName); err != nil {
			return "", err
		}
	}
	return r.waitAPI(ctx)
}

func (r *Role) convergeBare(ctx context.Context, s *Spec, hash, lua string, prev applied, report roles.Reporter) (string, error) {
	if !r.Host.HasSystemd() {
		return "", errors.New("a native dnsdist install needs systemd")
	}
	if _, err := r.Host.R.LookPath("dnsdist"); err != nil {
		report("installing", "installing the dnsdist package")
		if err := r.Host.InstallPackage(ctx, "dnsdist"); err != nil {
			return "", err
		}
	}
	// Keep a copy in the state dir too, so the agent can diff and the file the
	// service reads is written atomically.
	if err := config.WriteFileAtomic(r.confPath(), []byte(lua), 0o600); err != nil {
		return "", err
	}
	if err := config.WriteFileAtomic(bareConfPath, []byte(lua), 0o640); err != nil {
		return "", err
	}
	if _, _, err := r.Host.R.Run(ctx, "dnsdist", "--check-config", "-C", bareConfPath); err != nil {
		return "", fmt.Errorf("dnsdist rejected the configuration: %w", err)
	}
	if _, _, err := r.Host.R.Run(ctx, "systemctl", "enable", "--now", UnitName); err != nil {
		return "", err
	}
	if prev.Hash != hash {
		report("installing", "restarting dnsdist with the new configuration")
		if _, _, err := r.Host.R.Run(ctx, "systemctl", "restart", UnitName); err != nil {
			return "", err
		}
	}
	return r.waitAPI(ctx)
}

// waitAPI waits for the local REST API and returns the dnsdist version.
func (r *Role) waitAPI(ctx context.Context) (string, error) {
	deadline := time.Now().Add(r.WaitTimeout)
	for {
		top, err := r.apiGet(ctx, "/api/v1/servers/localhost")
		if err == nil {
			v, _ := top["version"].(string)
			return v, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("dnsdist API did not answer within %s: %v", r.WaitTimeout, err)
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		r.Sleep(time.Second)
	}
}

func (r *Role) apiGet(ctx context.Context, path string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+APIAddr+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", r.APIKey)
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	var out any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	switch t := out.(type) {
	case map[string]any:
		return t, nil
	case []any:
		return map[string]any{"items": t}, nil
	}
	return nil, errors.New("unexpected JSON from dnsdist")
}

func num(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	}
	return 0
}

// fetchLive maps dnsdist's API into the contract's backends/frontends/stats.
func (r *Role) fetchLive(ctx context.Context) (map[string]any, error) {
	top, err := r.apiGet(ctx, "/api/v1/servers/localhost")
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	drained := map[string]bool{}
	for k, v := range r.drained {
		drained[k] = v
	}
	r.mu.Unlock()

	backends := []any{}
	if servers, ok := top["servers"].([]any); ok {
		for _, item := range servers {
			sv, _ := item.(map[string]any)
			name, _ := sv["name"].(string)
			addr, _ := sv["address"].(string)
			state, _ := sv["state"].(string)
			pools := []any{}
			if p, ok := sv["pools"].([]any); ok {
				pools = p
			}
			backends = append(backends, map[string]any{
				"name": name, "address": addr, "state": strings.ToLower(state), "drained": drained[name],
				"qps": num(sv["qps"]), "queries": num(sv["queries"]), "responses": num(sv["responses"]),
				"drop_rate": num(sv["dropRate"]), "send_errors": num(sv["sendErrors"]),
				"latency_ms": num(sv["latency"]), "outstanding": num(sv["outstanding"]),
				"weight": num(sv["weight"]), "order": num(sv["order"]), "pools": pools,
				"health_failures": num(sv["healthCheckFailures"]),
			})
		}
	}
	frontends := []any{}
	if fs, ok := top["frontends"].([]any); ok {
		for _, item := range fs {
			fe, _ := item.(map[string]any)
			addr, _ := fe["address"].(string)
			proto := "udp"
			if t, _ := fe["tcp"].(bool); t {
				proto = "tcp"
			}
			frontends = append(frontends, map[string]any{
				"address": addr, "protocol": proto, "queries": num(fe["queries"]), "responses": num(fe["responses"]),
			})
		}
	}
	stats := map[string]any{}
	if st, err := r.apiGet(ctx, "/api/v1/servers/localhost/statistics"); err == nil {
		if items, ok := st["items"].([]any); ok {
			for _, item := range items {
				m, _ := item.(map[string]any)
				if name, ok := m["name"].(string); ok {
					stats[name] = num(m["value"])
				}
			}
		}
	}
	version, _ := top["version"].(string)
	return map[string]any{"backends": backends, "frontends": frontends, "stats": stats, "version": version}, nil
}

// --------------------------------------------------------------- drains ----

func (r *Role) console(ctx context.Context, s *Spec, lua string) error {
	args := []string{"--client=" + ConsoleAddr, "-k", r.ConsoleKey, "-e", lua}
	var err error
	if s.InstallMethod == "docker" {
		_, _, err = r.Host.R.Run(ctx, "docker", append([]string{"exec", ContainerName, "dnsdist"}, args...)...)
	} else {
		_, _, err = r.Host.R.Run(ctx, "dnsdist", args...)
	}
	return err
}

func drainLua(name, method string) string {
	return fmt.Sprintf(`for _,s in ipairs(getServers()) do if s:getName()==%s then s:%s() end end`, luaString(name), method)
}

func (r *Role) hasBackend(s *Spec, name string) bool {
	for _, b := range s.Backends {
		if b.Name == name {
			return true
		}
	}
	return false
}

// SetDrained administratively marks a backend down (drain) or returns it to
// health-checked operation (undrain), and remembers the choice.
func (r *Role) SetDrained(ctx context.Context, spec any, name string, drain bool) error {
	s, ok := spec.(*Spec)
	if !ok || s == nil {
		return errors.New("dnsdist is not managed on this host")
	}
	if !r.hasBackend(s, name) {
		return fmt.Errorf("no backend named %q", name)
	}
	method := "setAuto"
	if drain {
		method = "setDown"
	}
	if err := r.console(ctx, s, drainLua(name, method)); err != nil {
		return err
	}
	r.mu.Lock()
	if drain {
		r.drained[name] = true
	} else {
		delete(r.drained, name)
	}
	names := make([]string, 0, len(r.drained))
	for n := range r.drained {
		names = append(names, n)
	}
	sort.Strings(names)
	r.mu.Unlock()
	raw, _ := json.Marshal(names)
	return config.WriteFileAtomic(r.drainedPath(), raw, 0o600)
}

func (r *Role) reapplyDrains(ctx context.Context, s *Spec) error {
	for _, name := range r.drainedList() {
		if !r.hasBackend(s, name) {
			r.mu.Lock()
			delete(r.drained, name)
			r.mu.Unlock()
			continue
		}
		if err := r.console(ctx, s, drainLua(name, "setDown")); err != nil {
			return err
		}
	}
	return nil
}
