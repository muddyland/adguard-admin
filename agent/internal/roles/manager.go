// Package roles holds the desired-state machinery shared by every role: a spec
// arrives over the API, is validated and persisted, and a per-role goroutine
// converges the host toward it, now and again every 30 seconds.
package roles

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"adguard-admin/agent/internal/canon"
	"adguard-admin/agent/internal/config"
)

// ConvergeInterval is how often each role re-checks the host when idle.
var ConvergeInterval = 30 * time.Second

// Reporter lets a role publish intermediate states while it works.
type Reporter func(state, message string)

// Outcome is what a successful converge reports back.
type Outcome struct {
	Version string
	Enabled bool
}

// Common is the status every role shares.
type Common struct {
	State       string `json:"state"`
	DesiredHash string `json:"desired_hash"`
	AppliedHash string `json:"applied_hash"`
	Version     string `json:"version"`
	Message     string `json:"message"`
	LastChange  string `json:"last_change"`
}

// Role is one managed service.
type Role interface {
	Name() string
	// Decode validates a raw spec and returns the typed spec with defaults.
	Decode(raw []byte) (any, error)
	// Converge brings the host to the spec. It must be idempotent.
	Converge(ctx context.Context, spec any, hash string, report Reporter) (Outcome, error)
	// Status renders the role's status body. spec may be nil (no desired state).
	Status(ctx context.Context, spec any, c Common) (any, error)
}

type entry struct {
	role        Role
	convergeMu  sync.Mutex
	wake        chan struct{}
	desiredRaw  []byte
	desiredHash string
	spec        any
	common      Common
}

// Manager owns every role's desired state and status.
type Manager struct {
	dirs    config.Dirs
	mu      sync.Mutex
	entries map[string]*entry
	logger  *log.Logger
}

// NewManager registers roles.
func NewManager(dirs config.Dirs, logger *log.Logger, rs ...Role) *Manager {
	m := &Manager{dirs: dirs, entries: map[string]*entry{}, logger: logger}
	for _, r := range rs {
		m.entries[r.Name()] = &entry{role: r, wake: make(chan struct{}, 1), common: Common{State: "absent"}}
	}
	return m
}

// Names lists registered roles in a stable order.
func (m *Manager) Names() []string {
	out := make([]string, 0, len(m.entries))
	for n := range m.entries {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Role returns a registered role.
func (m *Manager) Role(name string) (Role, bool) {
	e, ok := m.entries[name]
	if !ok {
		return nil, false
	}
	return e.role, true
}

// Load restores desired specs and last-known status from disk.
func (m *Manager) Load() error {
	for name, e := range m.entries {
		raw, err := os.ReadFile(filepath.Join(m.dirs.Desired(), name+".json"))
		if err == nil {
			spec, derr := e.role.Decode(raw)
			hash, herr := canon.Hash(raw)
			if derr == nil && herr == nil {
				e.desiredRaw, e.desiredHash, e.spec = raw, hash, spec
				e.common.DesiredHash = hash
				e.common.State = "installing"
			} else {
				m.logger.Printf("ignoring stored %s spec: %v %v", name, derr, herr)
			}
		}
		sraw, err := os.ReadFile(filepath.Join(m.dirs.Status(), name+".json"))
		if err == nil {
			var c Common
			if json.Unmarshal(sraw, &c) == nil {
				e.common.AppliedHash = c.AppliedHash
				e.common.Version = c.Version
				e.common.LastChange = c.LastChange
			}
		}
	}
	return nil
}

// Put validates and stores a new desired spec and wakes the converger.
func (m *Manager) Put(name string, raw []byte) (string, error) {
	e, ok := m.entries[name]
	if !ok {
		return "", fmt.Errorf("unknown role %q", name)
	}
	spec, err := e.role.Decode(raw)
	if err != nil {
		return "", err
	}
	hash, err := canon.Hash(raw)
	if err != nil {
		return "", err
	}
	if err := config.WriteFileAtomic(filepath.Join(m.dirs.Desired(), name+".json"), raw, 0o600); err != nil {
		return "", err
	}
	m.mu.Lock()
	e.desiredRaw, e.desiredHash, e.spec = raw, hash, spec
	e.common.DesiredHash = hash
	if e.common.AppliedHash != hash {
		e.common.State = "installing"
		e.common.Message = ""
	}
	m.mu.Unlock()
	select {
	case e.wake <- struct{}{}:
	default:
	}
	return hash, nil
}

// Spec returns the current typed spec, or nil.
func (m *Manager) Spec(name string) any {
	e, ok := m.entries[name]
	if !ok {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return e.spec
}

// Common returns the shared status of a role.
func (m *Manager) Common(name string) Common {
	e, ok := m.entries[name]
	if !ok {
		return Common{State: "absent"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return e.common
}

// DesiredHash returns the hash of the stored spec, or nil when none exists.
func (m *Manager) DesiredHash(name string) *string {
	e, ok := m.entries[name]
	if !ok {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.desiredHash == "" {
		return nil
	}
	h := e.desiredHash
	return &h
}

// Status renders a role's full status body.
func (m *Manager) Status(ctx context.Context, name string) (any, error) {
	e, ok := m.entries[name]
	if !ok {
		return nil, fmt.Errorf("unknown role %q", name)
	}
	m.mu.Lock()
	spec, c := e.spec, e.common
	m.mu.Unlock()
	return e.role.Status(ctx, spec, c)
}

// Start launches one converge goroutine per role.
func (m *Manager) Start(ctx context.Context) {
	for name, e := range m.entries {
		go m.loop(ctx, name, e)
	}
}

// ConvergeNow runs one converge pass for a role synchronously (tests, CLI).
func (m *Manager) ConvergeNow(ctx context.Context, name string) {
	if e, ok := m.entries[name]; ok {
		m.converge(ctx, name, e)
	}
}

func (m *Manager) loop(ctx context.Context, name string, e *entry) {
	m.converge(ctx, name, e)
	ticker := time.NewTicker(ConvergeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.wake:
		case <-ticker.C:
		}
		m.converge(ctx, name, e)
	}
}

func (m *Manager) converge(ctx context.Context, name string, e *entry) {
	e.convergeMu.Lock()
	defer e.convergeMu.Unlock()

	m.mu.Lock()
	spec, hash := e.spec, e.desiredHash
	m.mu.Unlock()
	if spec == nil {
		return
	}
	report := func(state, message string) {
		m.mu.Lock()
		e.common.State, e.common.Message = state, message
		m.mu.Unlock()
	}
	out, err := e.role.Converge(ctx, spec, hash, report)
	m.mu.Lock()
	if err != nil {
		e.common.State = "error"
		e.common.Message = err.Error()
		m.logger.Printf("%s: converge failed: %v", name, err)
	} else {
		if e.common.AppliedHash != hash {
			e.common.LastChange = time.Now().UTC().Format(time.RFC3339)
		}
		e.common.AppliedHash = hash
		e.common.Version = out.Version
		e.common.Message = ""
		if out.Enabled {
			e.common.State = "ready"
		} else {
			e.common.State = "stopped"
		}
	}
	c := e.common
	m.mu.Unlock()
	if raw, err := json.Marshal(c); err == nil {
		_ = config.WriteFileAtomic(filepath.Join(m.dirs.Status(), name+".json"), raw, 0o600)
	}
}
