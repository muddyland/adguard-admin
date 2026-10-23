package roles

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"adguard-admin/agent/internal/config"
)

// blockingRole converges until released, so a test can observe the lock.
type blockingRole struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingRole) Name() string                   { return "blocky" }
func (b *blockingRole) Decode(raw []byte) (any, error) { return map[string]any{"enabled": true}, nil }
func (b *blockingRole) Status(context.Context, any, Common) (any, error) {
	return map[string]any{}, nil
}
func (b *blockingRole) Converge(ctx context.Context, spec any, hash string, report Reporter) (Outcome, error) {
	close(b.entered)
	<-b.release
	return Outcome{Enabled: true, Version: "v1"}, nil
}

func TestTryLockConvergeRefusesWhileConverging(t *testing.T) {
	root := t.TempDir()
	dirs := config.Dirs{Config: filepath.Join(root, "etc"), State: filepath.Join(root, "state")}
	_ = os.MkdirAll(dirs.Desired(), 0o700)
	_ = os.MkdirAll(dirs.Status(), 0o700)
	role := &blockingRole{entered: make(chan struct{}), release: make(chan struct{})}
	m := NewManager(dirs, log.New(io.Discard, "", 0), role)
	if _, err := m.Put("blocky", []byte(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { m.ConvergeNow(context.Background(), "blocky"); close(done) }()
	<-role.entered
	if _, ok := m.TryLockConverge("blocky"); ok {
		t.Fatal("the lock must be refused while a converge is in flight")
	}
	close(role.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("converge did not finish")
	}
	if m.Common("blocky").AppliedHash == "" || m.Common("blocky").Version != "v1" {
		t.Fatalf("converge should have applied: %+v", m.Common("blocky"))
	}
	unlock, ok := m.TryLockConverge("blocky")
	if !ok {
		t.Fatal("the lock must be free after the converge")
	}
	m.ResetApplied("blocky")
	unlock()
	c := m.Common("blocky")
	if c.AppliedHash != "" || c.Version != "" || c.State != "installing" {
		t.Fatalf("reset should clear what was applied: %+v", c)
	}
	raw, err := os.ReadFile(filepath.Join(dirs.Status(), "blocky.json"))
	if err != nil || len(raw) == 0 {
		t.Fatal("reset must be persisted")
	}
	if _, ok := m.TryLockConverge("nope"); ok {
		t.Fatal("unknown roles have no lock")
	}
	m.Wake("blocky") // must not block on a full channel
	m.Wake("blocky")
}
