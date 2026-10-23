// Package adguard converges an AdGuard Home install (container or native) to
// the control plane's spec, runs its first-run wizard and reports its state.
package adguard

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
	"sort"
	"strconv"
	"strings"
	"time"

	"adguard-admin/agent/internal/aghyaml"
	"adguard-admin/agent/internal/roles"
	"adguard-admin/agent/internal/services"
)

const (
	ContainerName = "adguardhome"
	UnitName      = "AdGuardHome"
	DefaultImage  = "adguard/adguardhome:latest"
	// InstallScriptURL is AdGuard's official native installer.
	InstallScriptURL = "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh"
	labelManaged     = "adguard-admin.managed"
	labelHash        = "adguard-admin.spec-hash"
)

// Spec is the desired state for this role.
type Spec struct {
	Enabled       bool     `json:"enabled"`
	InstallMethod string   `json:"install_method"`
	Image         string   `json:"image"`
	WebBind       string   `json:"web_bind"`
	WebPort       int      `json:"web_port"`
	DNSBind       []string `json:"dns_bind"`
	DNSPort       int      `json:"dns_port"`
	AdminUsername string   `json:"admin_username"`
	AdminPassword string   `json:"admin_password"`
	// Network is the container's network mode: "host" (default) or "bridge".
	// Host networking is the default because a published port is a DNAT rule
	// in PREROUTING, which runs before IPVS's LOCAL_IN hook: on a director
	// that also runs AdGuard in a bridged container, packets to the VIP are
	// rewritten to the container before IPVS can see them, so the owner answers
	// everything itself and nothing is balanced. It also needs Docker's
	// userland proxy to reach a loopback-published port.
	Network string `json:"network"`
}

// WizardBase is where a fresh instance's first-run wizard listens on the host
// network (the wizard always binds :3000 until configured).
const WizardBase = "http://127.0.0.1:3000"

// LocalBase is the loopback URL of the web API.
func (s *Spec) LocalBase() string { return fmt.Sprintf("http://127.0.0.1:%d", s.WebPort) }

// Role implements roles.Role.
type Role struct {
	Host        services.Host
	HTTP        *http.Client
	BareDir     string        // /opt/AdGuardHome
	WaitTimeout time.Duration // how long to wait for the web API after a start
	Sleep       func(time.Duration)
	// WizardBase is where a fresh host-network container's wizard answers;
	// tests point it at a mock.
	WizardBase string
	// Fetch downloads a URL (the native installer); tests replace it.
	Fetch func(ctx context.Context, url string) ([]byte, error)
}

// New builds a role with production defaults.
func New(h services.Host) *Role {
	r := &Role{
		Host: h,
		// Never follow redirects: an unconfigured instance answers /control/status
		// with a 302 to its install page, and a configured one may redirect to
		// its login page. Either is "the server answered". Following the
		// redirect could end on an address the agent cannot reach, which made
		// a healthy container look silent.
		HTTP: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		BareDir:     "/opt/AdGuardHome",
		WaitTimeout: 90 * time.Second,
		Sleep:       time.Sleep,
		WizardBase:  WizardBase,
	}
	r.Fetch = func(ctx context.Context, url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	}
	return r
}

func (r *Role) Name() string { return "adguard" }

// Decode validates the spec and fills defaults.
func (r *Role) Decode(raw []byte) (any, error) {
	var in struct {
		Enabled       *bool    `json:"enabled"`
		InstallMethod string   `json:"install_method"`
		Image         string   `json:"image"`
		WebBind       string   `json:"web_bind"`
		WebPort       int      `json:"web_port"`
		DNSBind       []string `json:"dns_bind"`
		DNSPort       int      `json:"dns_port"`
		AdminUsername string   `json:"admin_username"`
		AdminPassword string   `json:"admin_password"`
		Network       string   `json:"network"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("invalid adguard spec: %w", err)
	}
	s := &Spec{
		Enabled: true, InstallMethod: "docker", Image: DefaultImage, WebBind: "127.0.0.1",
		WebPort: 3000, DNSBind: []string{"0.0.0.0"}, DNSPort: 53, Network: "host",
	}
	if in.Enabled != nil {
		s.Enabled = *in.Enabled
	}
	if in.Network != "" {
		if in.Network != "host" && in.Network != "bridge" {
			return nil, fmt.Errorf("network must be host or bridge")
		}
		s.Network = in.Network
	}
	if in.InstallMethod != "" {
		s.InstallMethod = in.InstallMethod
	}
	if s.InstallMethod != "docker" && s.InstallMethod != "bare_metal" {
		return nil, fmt.Errorf("install_method must be docker or bare_metal")
	}
	if in.Image != "" {
		if strings.ContainsAny(in.Image, " \t\n\"'") || strings.HasPrefix(in.Image, "-") {
			return nil, fmt.Errorf("image reference is not valid")
		}
		s.Image = in.Image
	}
	if in.WebBind != "" {
		if net.ParseIP(in.WebBind) == nil {
			return nil, fmt.Errorf("web_bind must be an IP address")
		}
		s.WebBind = in.WebBind
	}
	if in.WebPort != 0 {
		s.WebPort = in.WebPort
	}
	if in.DNSPort != 0 {
		s.DNSPort = in.DNSPort
	}
	for _, p := range []int{s.WebPort, s.DNSPort} {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d out of range", p)
		}
	}
	if len(in.DNSBind) > 0 {
		for _, b := range in.DNSBind {
			if net.ParseIP(b) == nil {
				return nil, fmt.Errorf("dns_bind entry %q is not an IP address", b)
			}
		}
		s.DNSBind = in.DNSBind
	}
	s.AdminUsername, s.AdminPassword = in.AdminUsername, in.AdminPassword
	if s.Enabled && (s.AdminUsername == "" || s.AdminPassword == "") {
		return nil, fmt.Errorf("admin_username and admin_password are required")
	}
	return s, nil
}

// Status renders the role's status body.
func (r *Role) Status(ctx context.Context, spec any, c roles.Common) (any, error) {
	out := map[string]any{
		"state": c.State, "desired_hash": c.DesiredHash, "applied_hash": c.AppliedHash,
		"version": c.Version, "message": c.Message, "last_change": c.LastChange,
	}
	if s, ok := spec.(*Spec); ok && s != nil {
		out["web_url_local"] = s.LocalBase()
		out["install_method"] = s.InstallMethod
		if s.InstallMethod == "docker" {
			out["container"] = ContainerName
		}
	}
	return out, nil
}

// Converge brings the host to the spec.
func (r *Role) Converge(ctx context.Context, spec any, hash string, report roles.Reporter) (roles.Outcome, error) {
	s := spec.(*Spec)
	if s.InstallMethod == "docker" {
		return r.convergeDocker(ctx, s, hash, report)
	}
	return r.convergeBare(ctx, s, hash, report)
}

// ---------------------------------------------------------------- docker ----

// RunArgs is the `docker run` argument list for a spec (exported for tests).
// Host networking publishes nothing: AdGuard binds the spec's addresses
// itself, exactly as a native install does, and the kernel sees the packets
// unrewritten. Bridge mode maps the ports the classic way.
func RunArgs(s *Spec, hash string) []string {
	args := []string{
		"run", "-d", "--name", ContainerName, "--restart", "unless-stopped",
		"-l", labelManaged + "=true", "-l", labelHash + "=" + hash,
		"-v", "adguardhome-work:/opt/adguardhome/work",
		"-v", "adguardhome-conf:/opt/adguardhome/conf",
	}
	if s.Network != "bridge" {
		return append(append(args, "--network", "host"), s.Image)
	}
	args = append(args, "-p", fmt.Sprintf("%s:%d:3000/tcp", s.WebBind, s.WebPort))
	for _, b := range s.DNSBind {
		args = append(args,
			"-p", fmt.Sprintf("%s:%d:53/tcp", b, s.DNSPort),
			"-p", fmt.Sprintf("%s:%d:53/udp", b, s.DNSPort),
		)
	}
	return append(args, s.Image)
}

func (r *Role) convergeDocker(ctx context.Context, s *Spec, hash string, report roles.Reporter) (roles.Outcome, error) {
	if !r.Host.HasDocker(ctx) {
		return roles.Outcome{}, errors.New("docker is not available on this host")
	}
	c, err := r.Host.ContainerState(ctx, ContainerName)
	if err != nil {
		return roles.Outcome{}, err
	}
	if !s.Enabled {
		if c.Exists && c.Running {
			if _, _, err := r.Host.R.Run(ctx, "docker", "stop", ContainerName); err != nil {
				return roles.Outcome{}, err
			}
		}
		return roles.Outcome{Enabled: false}, nil
	}
	switch {
	case !c.Exists:
		report("installing", "starting the AdGuard Home container")
		if _, _, err := r.Host.R.Run(ctx, "docker", RunArgs(s, hash)...); err != nil {
			return roles.Outcome{}, err
		}
	case c.Labels[labelHash] != hash || c.Image != s.Image:
		report("installing", "recreating the AdGuard Home container with the new settings")
		if err := r.recreate(ctx, s, hash); err != nil {
			return roles.Outcome{}, err
		}
	case !c.Running:
		if _, _, err := r.Host.R.Run(ctx, "docker", "start", ContainerName); err != nil {
			return roles.Outcome{}, err
		}
	}
	report("configuring", "waiting for AdGuard Home to answer")
	if s.Network == "bridge" {
		// The port mapping does the binding; inside the container AdGuard
		// listens on every address and the canonical ports.
		if err := r.waitWeb(ctx, s.LocalBase()); err != nil {
			return roles.Outcome{}, err
		}
		version, err := r.wizardOrVerify(ctx, s, s.LocalBase(), s.LocalBase(), configureBody(s, "0.0.0.0", 3000, "0.0.0.0", 53))
		if err != nil {
			return roles.Outcome{}, err
		}
		return roles.Outcome{Version: version, Enabled: true}, nil
	}
	return r.convergeHostNetwork(ctx, s, report)
}

// convergeHostNetwork finishes a container that shares the host's network
// namespace. A fresh instance's wizard answers on :3000; a configured one on
// the spec's web address. The wizard is told the real binds, and anything the
// wizard cannot express (several DNS bind addresses, a changed port later) is
// applied to AdGuardHome.yaml in the conf volume, as the native path does.
func (r *Role) convergeHostNetwork(ctx context.Context, s *Spec, report roles.Reporter) (roles.Outcome, error) {
	if err := r.waitWebAny(ctx, r.WizardBase, s.LocalBase()); err != nil {
		return roles.Outcome{}, err
	}
	body := configureBody(s, s.WebBind, s.WebPort, s.DNSBind[0], s.DNSPort)
	version, err := r.wizardOrVerify(ctx, s, r.WizardBase, s.LocalBase(), body)
	if err != nil {
		return roles.Outcome{}, err
	}
	yamlPath, err := r.confVolumeYAML(ctx)
	if err != nil {
		return roles.Outcome{}, err
	}
	raw, err := os.ReadFile(yamlPath)
	if err != nil {
		return roles.Outcome{}, fmt.Errorf("read %s: %w", yamlPath, err)
	}
	have, err := aghyaml.Read(raw)
	if err != nil {
		return roles.Outcome{}, fmt.Errorf("read %s: %w", yamlPath, err)
	}
	want := aghyaml.Binds{DNSBindHosts: s.DNSBind, DNSPort: s.DNSPort, HTTPAddress: net.JoinHostPort(s.WebBind, strconv.Itoa(s.WebPort))}
	if sameBinds(have, want) {
		return roles.Outcome{Version: version, Enabled: true}, nil
	}
	report("configuring", "applying listen addresses")
	if _, _, err := r.Host.R.Run(ctx, "docker", "stop", ContainerName); err != nil {
		return roles.Outcome{}, err
	}
	if err := aghyaml.ApplyFile(yamlPath, want); err != nil {
		return roles.Outcome{}, err
	}
	if _, _, err := r.Host.R.Run(ctx, "docker", "start", ContainerName); err != nil {
		return roles.Outcome{}, err
	}
	if err := r.waitWeb(ctx, s.LocalBase()); err != nil {
		return roles.Outcome{}, err
	}
	version, err = r.wizardOrVerify(ctx, s, s.LocalBase(), s.LocalBase(), body)
	if err != nil {
		return roles.Outcome{}, err
	}
	return roles.Outcome{Version: version, Enabled: true}, nil
}

// confVolumeYAML is the path of AdGuardHome.yaml inside the conf volume, as
// seen from the host.
func (r *Role) confVolumeYAML(ctx context.Context) (string, error) {
	out, _, err := r.Host.R.Run(ctx, "docker", "volume", "inspect", "-f", "{{.Mountpoint}}", "adguardhome-conf")
	if err != nil {
		return "", fmt.Errorf("locate the adguardhome-conf volume: %w", err)
	}
	mount := strings.TrimSpace(string(out))
	if mount == "" {
		return "", errors.New("the adguardhome-conf volume has no mountpoint")
	}
	return filepath.Join(mount, "AdGuardHome.yaml"), nil
}

// recreate swaps the container, keeping the old one until the new one answers.
func (r *Role) recreate(ctx context.Context, s *Spec, hash string) error {
	prev := ContainerName + "-prev"
	_, _, _ = r.Host.R.Run(ctx, "docker", "rm", "-f", prev)
	if _, _, err := r.Host.R.Run(ctx, "docker", "rename", ContainerName, prev); err != nil {
		return err
	}
	_, _, _ = r.Host.R.Run(ctx, "docker", "stop", prev)
	rollback := func(cause error) error {
		_, _, _ = r.Host.R.Run(ctx, "docker", "rm", "-f", ContainerName)
		_, _, _ = r.Host.R.Run(ctx, "docker", "rename", prev, ContainerName)
		_, _, _ = r.Host.R.Run(ctx, "docker", "start", ContainerName)
		return fmt.Errorf("recreate failed, previous container restored: %w", cause)
	}
	if _, _, err := r.Host.R.Run(ctx, "docker", RunArgs(s, hash)...); err != nil {
		return rollback(err)
	}
	if err := r.waitWeb(ctx, s.LocalBase()); err != nil {
		return rollback(err)
	}
	_, _, _ = r.Host.R.Run(ctx, "docker", "rm", "-f", prev)
	return nil
}

// Update pulls the image and recreates the container when the digest moved
// (docker), or asks AdGuard to update itself (bare metal).
func (r *Role) Update(ctx context.Context, spec any, hash string) (bool, string, error) {
	s, ok := spec.(*Spec)
	if !ok || s == nil {
		return false, "", errors.New("adguard is not managed on this host")
	}
	if s.InstallMethod == "bare_metal" {
		status, _, err := r.do(ctx, http.MethodPost, s.LocalBase()+"/control/update", s, nil)
		if err != nil && status == 0 {
			// The process restarts under us; a dropped connection means it started.
			return true, "update started", nil
		}
		if status >= 400 {
			return false, "", fmt.Errorf("AdGuard refused to update: HTTP %d", status)
		}
		return true, "update started", nil
	}
	if _, _, err := r.Host.R.Run(ctx, "docker", "pull", "-q", s.Image); err != nil {
		return false, "", err
	}
	c, err := r.Host.ContainerState(ctx, ContainerName)
	if err != nil {
		return false, "", err
	}
	latest := r.Host.ImageID(ctx, s.Image)
	if c.Exists && latest != "" && c.ImageID == latest {
		return false, "already current", nil
	}
	if !c.Exists {
		return false, "container not present; converge first", nil
	}
	if err := r.recreate(ctx, s, hash); err != nil {
		return false, "", err
	}
	return true, "container recreated from " + s.Image, nil
}

// Reset wipes the AdGuard install so the next converge runs the first-run
// wizard again with the control plane's credentials. Docker: the container,
// its previous-generation twin and both named volumes. Bare metal: the
// service is stopped and the configuration file and data directory removed.
// The caller clears the applied hash and triggers the converge.
func (r *Role) Reset(ctx context.Context, spec any) error {
	s, ok := spec.(*Spec)
	if !ok || s == nil {
		return errors.New("adguard is not managed on this host")
	}
	if s.InstallMethod == "docker" {
		if !r.Host.HasDocker(ctx) {
			return errors.New("docker is not available on this host")
		}
		for _, name := range []string{ContainerName, ContainerName + "-prev"} {
			_, _, _ = r.Host.R.Run(ctx, "docker", "rm", "-f", name)
		}
		if _, _, err := r.Host.R.Run(ctx, "docker", "volume", "rm", "-f", "adguardhome-work", "adguardhome-conf"); err != nil {
			return err
		}
		return nil
	}
	if r.Host.HasSystemd() {
		_, _, _ = r.Host.R.Run(ctx, "systemctl", "stop", UnitName)
	}
	for _, path := range []string{filepath.Join(r.BareDir, "AdGuardHome.yaml"), filepath.Join(r.BareDir, "data")} {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	return nil
}

// ------------------------------------------------------------- bare metal ----

func (r *Role) convergeBare(ctx context.Context, s *Spec, hash string, report roles.Reporter) (roles.Outcome, error) {
	if !r.Host.HasSystemd() {
		return roles.Outcome{}, errors.New("a native install needs systemd")
	}
	binary := filepath.Join(r.BareDir, "AdGuardHome")
	if _, err := os.Stat(binary); err != nil {
		if !s.Enabled {
			return roles.Outcome{Enabled: false}, nil
		}
		report("installing", "running AdGuard Home's native installer")
		if err := r.installBare(ctx); err != nil {
			return roles.Outcome{}, err
		}
	}
	if !s.Enabled {
		_, _, err := r.Host.R.Run(ctx, "systemctl", "stop", UnitName)
		return roles.Outcome{Enabled: false}, err
	}
	yamlPath := filepath.Join(r.BareDir, "AdGuardHome.yaml")
	if _, err := os.Stat(yamlPath); err != nil {
		// First run: the wizard listens on :3000 until configured.
		if _, _, err := r.Host.R.Run(ctx, "systemctl", "start", UnitName); err != nil {
			return roles.Outcome{}, err
		}
		report("configuring", "running the first-run wizard")
		if err := r.waitWeb(ctx, "http://127.0.0.1:3000"); err != nil {
			return roles.Outcome{}, err
		}
		body := configureBody(s, s.WebBind, s.WebPort, s.DNSBind[0], s.DNSPort)
		if _, err := r.wizardOrVerify(ctx, s, "http://127.0.0.1:3000", s.LocalBase(), body); err != nil {
			return roles.Outcome{}, err
		}
	}
	want := aghyaml.Binds{DNSBindHosts: s.DNSBind, DNSPort: s.DNSPort, HTTPAddress: net.JoinHostPort(s.WebBind, strconv.Itoa(s.WebPort))}
	raw, err := os.ReadFile(yamlPath)
	if err != nil {
		return roles.Outcome{}, err
	}
	have, err := aghyaml.Read(raw)
	if err != nil {
		return roles.Outcome{}, fmt.Errorf("read %s: %w", yamlPath, err)
	}
	if !sameBinds(have, want) {
		report("configuring", "applying listen addresses")
		if _, _, err := r.Host.R.Run(ctx, "systemctl", "stop", UnitName); err != nil {
			return roles.Outcome{}, err
		}
		if err := aghyaml.ApplyFile(yamlPath, want); err != nil {
			return roles.Outcome{}, err
		}
	}
	if _, _, err := r.Host.R.Run(ctx, "systemctl", "enable", "--now", UnitName); err != nil {
		return roles.Outcome{}, err
	}
	if err := r.waitWeb(ctx, s.LocalBase()); err != nil {
		return roles.Outcome{}, err
	}
	version, err := r.wizardOrVerify(ctx, s, s.LocalBase(), s.LocalBase(), configureBody(s, s.WebBind, s.WebPort, s.DNSBind[0], s.DNSPort))
	if err != nil {
		return roles.Outcome{}, err
	}
	return roles.Outcome{Version: version, Enabled: true}, nil
}

func (r *Role) installBare(ctx context.Context) error {
	script, err := r.Fetch(ctx, InstallScriptURL)
	if err != nil {
		return fmt.Errorf("download installer: %w", err)
	}
	tmp, err := os.CreateTemp("", "agh-install-*.sh")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(script); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	_, _, err = r.Host.R.Run(ctx, "sh", tmp.Name(), "-v")
	return err
}

func sameBinds(a, b aghyaml.Binds) bool {
	if a.DNSPort != b.DNSPort || a.HTTPAddress != b.HTTPAddress || len(a.DNSBindHosts) != len(b.DNSBindHosts) {
		return false
	}
	x := append([]string(nil), a.DNSBindHosts...)
	y := append([]string(nil), b.DNSBindHosts...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------ web helpers ----

func configureBody(s *Spec, webIP string, webPort int, dnsIP string, dnsPort int) []byte {
	body, _ := json.Marshal(map[string]any{
		"web":      map[string]any{"ip": webIP, "port": webPort},
		"dns":      map[string]any{"ip": dnsIP, "port": dnsPort},
		"username": s.AdminUsername,
		"password": s.AdminPassword,
	})
	return body
}

// do performs a request; status 0 means a transport error.
func (r *Role) do(ctx context.Context, method, url string, s *Spec, body []byte) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s != nil && s.AdminUsername != "" {
		req.SetBasicAuth(s.AdminUsername, s.AdminPassword)
	}
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, nil
}

// waitWeb waits until the web server at base answers anything at all. The
// timeout message carries the last transport error: without it, "did not
// answer" is indistinguishable from "answered in a way we could not read".
func (r *Role) waitWeb(ctx context.Context, base string) error {
	deadline := time.Now().Add(r.WaitTimeout)
	var lastErr error
	for {
		status, _, err := r.do(ctx, http.MethodGet, base+"/control/status", nil, nil)
		if status != 0 {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("AdGuard Home did not answer on %s within %s (last error: %v)", base, r.WaitTimeout, lastErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		r.Sleep(2 * time.Second)
	}
}

// waitWebAny waits until any of the bases answers; a fresh host-network
// container listens on the wizard port, a configured one on its web address.
func (r *Role) waitWebAny(ctx context.Context, bases ...string) error {
	deadline := time.Now().Add(r.WaitTimeout)
	var lastErr error
	for {
		for _, base := range bases {
			status, _, err := r.do(ctx, http.MethodGet, base+"/control/status", nil, nil)
			if status != 0 {
				return nil
			}
			if err != nil {
				lastErr = err
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("AdGuard Home did not answer on %s within %s (last error: %v)", strings.Join(bases, " or "), r.WaitTimeout, lastErr)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		r.Sleep(2 * time.Second)
	}
}

// wizardOrVerify configures a fresh instance or checks the credentials of an
// existing one, then returns the running version. setupBase is where the
// wizard listens, finalBase where the configured instance will answer.
func (r *Role) wizardOrVerify(ctx context.Context, s *Spec, setupBase, finalBase string, configure []byte) (string, error) {
	status, _, _ := r.do(ctx, http.MethodGet, setupBase+"/control/install/get_addresses", nil, nil)
	if status == 200 {
		st, body, err := r.do(ctx, http.MethodPost, setupBase+"/control/install/configure", nil, configure)
		if err == nil && st >= 400 {
			return "", fmt.Errorf("first-run configuration rejected: HTTP %d %s", st, strings.TrimSpace(string(body)))
		}
		// The server restarts onto its configured address; give it a moment.
		r.Sleep(3 * time.Second)
		if err := r.waitWeb(ctx, finalBase); err != nil {
			return "", err
		}
	}
	deadline := time.Now().Add(r.WaitTimeout)
	for {
		status, body, err := r.do(ctx, http.MethodGet, finalBase+"/control/status", s, nil)
		switch {
		case err == nil && status == 200:
			var st struct {
				Version string `json:"version"`
			}
			_ = json.Unmarshal(body, &st)
			return st.Version, nil
		case err == nil && (status == 401 || status == 403):
			return "", errors.New("credentials rejected; the instance was configured before this agent managed it")
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("AdGuard Home did not become ready (last HTTP %d)", status)
		}
		r.Sleep(2 * time.Second)
	}
}
