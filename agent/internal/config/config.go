// Package config holds the agent's on-disk identity and settings.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultConfigDir = "/etc/adguard-admin-agent"
	DefaultStateDir  = "/var/lib/adguard-admin-agent"
	DefaultListen    = "0.0.0.0:8443"
)

// Dirs are the two roots the agent writes to.
type Dirs struct {
	Config string
	State  string
}

func (d Dirs) AgentJSON() string  { return filepath.Join(d.Config, "agent.json") }
func (d Dirs) KeyFile() string    { return filepath.Join(d.Config, "agent.key") }
func (d Dirs) CertFile() string   { return filepath.Join(d.Config, "agent.crt") }
func (d Dirs) CAFile() string     { return filepath.Join(d.Config, "ca.crt") }
func (d Dirs) Desired() string    { return filepath.Join(d.State, "desired") }
func (d Dirs) Status() string     { return filepath.Join(d.State, "status") }
func (d Dirs) Dnsdist() string    { return filepath.Join(d.State, "dnsdist") }
func (d Dirs) Keepalived() string { return filepath.Join(d.State, "keepalived") }

// Agent is the content of agent.json.
type Agent struct {
	Listen            string `json:"listen"`
	Name              string `json:"name"`
	AgentID           int64  `json:"agent_id"`
	ControlPlaneURL   string `json:"control_plane_url"`
	Address           string `json:"address"`
	DnsdistAPIKey     string `json:"dnsdist_api_key"`
	DnsdistConsoleKey string `json:"dnsdist_console_key"`
	CreatedAt         string `json:"created_at"`
}

// Load reads agent.json.
func Load(d Dirs) (*Agent, error) {
	raw, err := os.ReadFile(d.AgentJSON())
	if err != nil {
		return nil, err
	}
	var a Agent
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("parse %s: %w", d.AgentJSON(), err)
	}
	if a.Listen == "" {
		a.Listen = DefaultListen
	}
	return &a, nil
}

// Save writes agent.json with mode 0600, generating the dnsdist secrets on
// first save so they exist before the dnsdist role is ever enabled.
func Save(d Dirs, a *Agent) error {
	if err := os.MkdirAll(d.Config, 0o700); err != nil {
		return err
	}
	if a.DnsdistAPIKey == "" {
		a.DnsdistAPIKey = RandomKey(32)
	}
	if a.DnsdistConsoleKey == "" {
		a.DnsdistConsoleKey = RandomKey(32) // makeKey() format: base64 of 32 bytes
	}
	if a.CreatedAt == "" {
		a.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(d.AgentJSON(), raw, 0o600)
}

// RandomKey returns n random bytes, standard base64.
func RandomKey(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// WriteFileAtomic writes via a temp file and rename so readers never see a
// partial file.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// Exists reports whether a file exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ErrNotEnrolled is returned by serve when the identity files are missing.
var ErrNotEnrolled = errors.New("agent is not enrolled: run `adguard-admin-agent enroll` first")
