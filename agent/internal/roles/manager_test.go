package roles

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"adguard-admin/agent/internal/config"
)

type fakeRole struct {
	fail     bool
	converge int
}

func (f *fakeRole) Name() string { return "fake" }
func (f *fakeRole) Decode(raw []byte) (any, error) {
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if v["bad"] == true {
		return nil, errors.New("bad spec")
	}
	return v, nil
}
func (f *fakeRole) Converge(_ context.Context, spec any, hash string, report Reporter) (Outcome, error) {
	f.converge++
	report("installing", "working")
	if f.fail {
		return Outcome{}, errors.New("boom")
	}
	enabled := spec.(map[string]any)["enabled"] != false
	return Outcome{Version: "1.2.3", Enabled: enabled}, nil
}
func (f *fakeRole) Status(_ context.Context, spec any, c Common) (any, error) {
	return map[string]any{"state": c.State, "applied_hash": c.AppliedHash, "version": c.Version, "message": c.Message}, nil
}

func TestManagerLifecycle(t *testing.T) {
	dirs := config.Dirs{Config: t.TempDir(), State: t.TempDir()}
	role := &fakeRole{}
	m := NewManager(dirs, log.New(io.Discard, "", 0), role)
	ctx := context.Background()

	if _, err := m.Put("fake", []byte(`{"bad":true}`)); err == nil {
		t.Fatal("invalid spec accepted")
	}
	if m.Common("fake").State != "absent" {
		t.Fatal("state changed by a rejected spec")
	}
	hash, err := m.Put("fake", []byte(`{"enabled":true,"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if h := m.DesiredHash("fake"); h == nil || *h != hash {
		t.Fatal("desired hash not recorded")
	}
	if m.Common("fake").State != "installing" {
		t.Fatalf("state after PUT: %s", m.Common("fake").State)
	}
	m.ConvergeNow(ctx, "fake")
	c := m.Common("fake")
	if c.State != "ready" || c.AppliedHash != hash || c.Version != "1.2.3" || c.LastChange == "" {
		t.Fatalf("after converge: %+v", c)
	}
	if _, err := os.Stat(filepath.Join(dirs.Status(), "fake.json")); err != nil {
		t.Fatal("status not persisted")
	}

	// Failure flips to error with the message, keeps the applied hash.
	role.fail = true
	m.ConvergeNow(ctx, "fake")
	c = m.Common("fake")
	if c.State != "error" || c.Message != "boom" || c.AppliedHash != hash {
		t.Fatalf("after failure: %+v", c)
	}

	// Disabled spec converges to stopped.
	role.fail = false
	if _, err := m.Put("fake", []byte(`{"enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	m.ConvergeNow(ctx, "fake")
	if m.Common("fake").State != "stopped" {
		t.Fatalf("expected stopped, got %s", m.Common("fake").State)
	}

	// A fresh manager restores desired spec and applied hash from disk.
	m2 := NewManager(dirs, log.New(io.Discard, "", 0), &fakeRole{})
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	if m2.DesiredHash("fake") == nil || m2.Common("fake").AppliedHash == "" {
		t.Fatalf("not restored: %+v", m2.Common("fake"))
	}
	st, _ := m2.Status(ctx, "fake")
	if st.(map[string]any)["version"] != "1.2.3" {
		t.Fatalf("status after reload: %v", st)
	}
}
