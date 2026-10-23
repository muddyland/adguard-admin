package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func harness(t *testing.T, payload []byte) (*Updater, string, chan int) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write(payload)
	}))
	t.Cleanup(ts.Close)
	exe := filepath.Join(t.TempDir(), "adguard-admin-agent")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	exits := make(chan int, 1)
	u := &Updater{
		Version:      "0.1.0",
		Executable:   func() (string, error) { return exe, nil },
		UnderSystemd: func() bool { return true },
		Exit:         func(code int) { exits <- code },
		ExitDelay:    time.Millisecond,
		// The payload is not a real binary; stand in for `<exe>.new version`.
		Probe: func(ctx context.Context, path string) (string, error) { return "0.2.0", nil },
	}
	u.HTTP = ts.Client()
	t.Setenv("SELFUPDATE_TEST_URL", ts.URL)
	return u, exe, exits
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestApplyReplacesBinaryAndSchedulesExit(t *testing.T) {
	payload := []byte("new binary contents")
	u, exe, exits := harness(t, payload)
	resp, uerr := u.Apply(context.Background(), Request{Version: "0.2.0", URL: os.Getenv("SELFUPDATE_TEST_URL") + "/linux/amd64", SHA256: sum(payload)})
	if uerr != nil {
		t.Fatal(uerr)
	}
	if !resp.OK || resp.Version != "0.2.0" || !resp.Restarting {
		t.Fatalf("resp = %+v", resp)
	}
	got, _ := os.ReadFile(exe)
	if string(got) != string(payload) {
		t.Fatalf("binary not replaced: %q", got)
	}
	st, _ := os.Stat(exe)
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %o", st.Mode().Perm())
	}
	if _, err := os.Stat(exe + ".new"); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}
	u.ScheduleRestart()
	select {
	case code := <-exits:
		if code != 0 {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(time.Second):
		t.Fatal("exit was not scheduled")
	}
}

func TestApplyWithoutSystemdDoesNotClaimRestart(t *testing.T) {
	payload := []byte("x")
	u, _, _ := harness(t, payload)
	u.UnderSystemd = func() bool { return false }
	resp, uerr := u.Apply(context.Background(), Request{Version: "0.2.0", URL: os.Getenv("SELFUPDATE_TEST_URL") + "/b", SHA256: sum(payload)})
	if uerr != nil {
		t.Fatal(uerr)
	}
	if resp.Restarting || !strings.Contains(resp.Message, "restart the agent by hand") {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestApplyRefusesMismatchSameVersionAndBadInput(t *testing.T) {
	payload := []byte("new binary contents")
	u, exe, _ := harness(t, payload)
	base := os.Getenv("SELFUPDATE_TEST_URL")

	_, uerr := u.Apply(context.Background(), Request{Version: "0.2.0", URL: base + "/b", SHA256: strings.Repeat("0", 64)})
	if uerr == nil || uerr.Status != 409 || !strings.Contains(uerr.Error(), "checksum mismatch") {
		t.Fatalf("mismatch: %v", uerr)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old binary" {
		t.Fatal("a mismatch must not touch the binary")
	}
	if _, err := os.Stat(exe + ".new"); !os.IsNotExist(err) {
		t.Fatal("a mismatch must not leave a file")
	}

	_, uerr = u.Apply(context.Background(), Request{Version: "0.1.0", URL: base + "/b", SHA256: sum(payload)})
	if uerr == nil || uerr.Status != 409 || !strings.Contains(uerr.Error(), "already running") {
		t.Fatalf("same version: %v", uerr)
	}

	for _, bad := range []Request{
		{Version: "", URL: base + "/b", SHA256: sum(payload)},
		{Version: "0.2.0", URL: "ftp://x/y", SHA256: sum(payload)},
		{Version: "0.2.0", URL: base + "/b", SHA256: "nothex"},
	} {
		if _, uerr = u.Apply(context.Background(), bad); uerr == nil || uerr.Status != 400 {
			t.Fatalf("bad input %+v: %v", bad, uerr)
		}
	}
	_, uerr = u.Apply(context.Background(), Request{Version: "0.2.0", URL: base + "/missing", SHA256: sum(payload)})
	if uerr == nil || uerr.Status != 502 {
		t.Fatalf("missing download: %v", uerr)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old binary" {
		t.Fatal("no failure path may touch the binary")
	}
}

func TestApplyRefusesBinaryWhoseVersionDiffers(t *testing.T) {
	payload := []byte("new binary bytes")
	u, exe, _ := harness(t, payload)
	u.Probe = func(ctx context.Context, path string) (string, error) { return "0.1.0-dev", nil }
	_, uerr := u.Apply(context.Background(), Request{Version: "0.2.0", URL: os.Getenv("SELFUPDATE_TEST_URL") + "/b", SHA256: sum(payload)})
	if uerr == nil || uerr.Status != 409 || !strings.Contains(uerr.Error(), `reports version "0.1.0-dev"`) {
		t.Fatalf("expected a 409 version mismatch, got %v", uerr)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old binary" {
		t.Fatalf("binary was replaced despite the mismatch: %q", got)
	}
	if _, err := os.Stat(exe + ".new"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind: %v", err)
	}
	u.Probe = func(ctx context.Context, path string) (string, error) { return "", errors.New("exec format error") }
	_, uerr = u.Apply(context.Background(), Request{Version: "0.2.0", URL: os.Getenv("SELFUPDATE_TEST_URL") + "/b", SHA256: sum(payload)})
	if uerr == nil || uerr.Status != 409 || !strings.Contains(uerr.Error(), "does not run") {
		t.Fatalf("expected a 409 for a binary that does not run, got %v", uerr)
	}
}
