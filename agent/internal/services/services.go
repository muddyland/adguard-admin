// Package services wraps the host facilities roles share: Docker containers,
// systemd units, distro packages, logs and restarts.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"adguard-admin/agent/internal/execx"
	"adguard-admin/agent/internal/sysinfo"
)

// Known maps a service name to its container and unit.
type Known struct {
	Container string
	Unit      string
}

// Table is the fixed set of services the API accepts.
var Table = map[string]Known{
	"adguard":    {Container: "adguardhome", Unit: "AdGuardHome"},
	"dnsdist":    {Container: "dnsdist", Unit: "dnsdist"},
	"keepalived": {Container: "", Unit: "keepalived"},
	"agent":      {Container: "", Unit: "adguard-admin-agent"},
}

// Host is the facility set bound to a runner.
type Host struct {
	R execx.Runner
}

// HasDocker reports whether the docker CLI exists and a daemon answers.
func (h Host) HasDocker(ctx context.Context) bool {
	if _, err := h.R.LookPath("docker"); err != nil {
		return false
	}
	_, _, err := h.R.Run(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	return err == nil
}

// DockerRootDir returns the daemon's data root, or "".
func (h Host) DockerRootDir(ctx context.Context) string {
	out, _, err := h.R.Run(ctx, "docker", "info", "--format", "{{.DockerRootDir}}")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// HasSystemd reports whether systemctl can be used.
func (h Host) HasSystemd() bool {
	if !sysinfo.HasSystemd() {
		return false
	}
	_, err := h.R.LookPath("systemctl")
	return err == nil
}

// PackageManager returns apt, dnf, apk or "".
func (h Host) PackageManager() string {
	for _, pm := range []string{"apt-get", "dnf", "apk"} {
		if _, err := h.R.LookPath(pm); err == nil {
			if pm == "apt-get" {
				return "apt"
			}
			return pm
		}
	}
	return ""
}

// InstallPackage installs a distro package non-interactively.
func (h Host) InstallPackage(ctx context.Context, name string) error {
	switch h.PackageManager() {
	case "apt":
		if _, _, err := h.R.Run(ctx, "apt-get", "update", "-q"); err != nil {
			return err
		}
		_, _, err := h.R.Run(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-q", name)
		return err
	case "dnf":
		_, _, err := h.R.Run(ctx, "dnf", "install", "-y", "-q", name)
		return err
	case "apk":
		_, _, err := h.R.Run(ctx, "apk", "add", "--no-cache", name)
		return err
	}
	return errors.New("no supported package manager (apt-get, dnf or apk) found")
}

// Container is what the agent needs to know about a container.
type Container struct {
	Exists  bool
	Running bool
	Status  string
	Image   string            // reference the container was created from
	ImageID string            // resolved image id
	Labels  map[string]string // Config.Labels
}

// ContainerState inspects a container by name.
func (h Host) ContainerState(ctx context.Context, name string) (Container, error) {
	out, _, err := h.R.Run(ctx, "docker", "inspect", name)
	if err != nil {
		return Container{}, nil // not found is the common case
	}
	var items []struct {
		Image string `json:"Image"`
		State struct {
			Running bool   `json:"Running"`
			Status  string `json:"Status"`
		} `json:"State"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(out, &items); err != nil || len(items) == 0 {
		return Container{}, fmt.Errorf("parse docker inspect %s: %v", name, err)
	}
	it := items[0]
	return Container{
		Exists: true, Running: it.State.Running, Status: it.State.Status,
		Image: it.Config.Image, ImageID: it.Image, Labels: it.Config.Labels,
	}, nil
}

// ImageID resolves a local image reference to its id, or "".
func (h Host) ImageID(ctx context.Context, ref string) string {
	out, _, err := h.R.Run(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", ref)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Unit is a systemd unit's state.
type Unit struct {
	Exists bool
	Active bool
	Status string
}

// UnitState asks systemd about a unit.
func (h Host) UnitState(ctx context.Context, unit string) Unit {
	out, _, _ := h.R.Run(ctx, "systemctl", "show", unit+".service", "-p", "LoadState", "-p", "ActiveState")
	var u Unit
	for _, line := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "LoadState":
			u.Exists = v == "loaded"
		case "ActiveState":
			u.Status = v
			u.Active = v == "active"
		}
	}
	return u
}

// ServiceState is the health view of one service.
type ServiceState struct {
	Present bool    `json:"present"`
	Running bool    `json:"running"`
	Kind    string  `json:"kind"`
	Detail  string  `json:"detail"`
	Version *string `json:"version"`
}

// Probe finds a service as a container or a unit.
func (h Host) Probe(ctx context.Context, name string) ServiceState {
	k, ok := Table[name]
	if !ok {
		return ServiceState{Kind: "none"}
	}
	if k.Container != "" && h.HasDocker(ctx) {
		if c, _ := h.ContainerState(ctx, k.Container); c.Exists {
			return ServiceState{Present: true, Running: c.Running, Kind: "docker", Detail: c.Status}
		}
	}
	if k.Unit != "" && h.HasSystemd() {
		if u := h.UnitState(ctx, k.Unit); u.Exists {
			return ServiceState{Present: true, Running: u.Active, Kind: "systemd", Detail: u.Status}
		}
	}
	return ServiceState{Kind: "none"}
}

// Restart restarts a service wherever it lives.
func (h Host) Restart(ctx context.Context, name string) error {
	st := h.Probe(ctx, name)
	k := Table[name]
	switch st.Kind {
	case "docker":
		_, _, err := h.R.Run(ctx, "docker", "restart", k.Container)
		return err
	case "systemd":
		_, _, err := h.R.Run(ctx, "systemctl", "restart", k.Unit)
		return err
	}
	return fmt.Errorf("%s is not installed on this host", name)
}

// Logs tails a service's log.
func (h Host) Logs(ctx context.Context, name string, lines int) ([]string, error) {
	if lines <= 0 {
		lines = 200
	}
	if lines > 2000 {
		lines = 2000
	}
	st := h.Probe(ctx, name)
	k := Table[name]
	var out, errOut []byte
	var err error
	switch st.Kind {
	case "docker":
		out, errOut, err = h.R.Run(ctx, "docker", "logs", "--tail", strconv.Itoa(lines), k.Container)
		out = append(out, errOut...) // docker logs splits streams; the UI wants both
	case "systemd":
		out, _, err = h.R.Run(ctx, "journalctl", "-u", k.Unit, "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso")
	default:
		return nil, fmt.Errorf("%s is not installed on this host", name)
	}
	if err != nil {
		return nil, err
	}
	text := strings.TrimRight(string(out), "\n")
	if text == "" {
		return []string{}, nil
	}
	return strings.Split(text, "\n"), nil
}
