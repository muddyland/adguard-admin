// Package selfupdate replaces the running agent binary with one the control
// plane points at, then lets systemd restart the service.
//
// Integrity comes from the SHA-256 the control plane sends over mutual TLS; the
// download itself uses the same plain trust as enrollment, because the URL is
// the control plane's own. Nothing is written unless the hash matches.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// MaxSize caps the download; the agent binary is a few MiB.
const MaxSize = 64 << 20

// Request is the body of POST /v1/self-update.
type Request struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

// Response is the success body.
type Response struct {
	OK         bool   `json:"ok"`
	Version    string `json:"version"`
	Restarting bool   `json:"restarting"`
	Message    string `json:"message,omitempty"`
}

// Error carries the HTTP status the failure maps to.
type Error struct {
	Status int
	Err    error
}

func (e *Error) Error() string { return e.Err.Error() }

// Updater performs the swap. Every external touch point is a field so tests
// can run it against a temp "executable" and a stub exit.
type Updater struct {
	Version      string                 // the running version
	HTTP         *http.Client           // download client; default 120 s timeout
	Executable   func() (string, error) // default os.Executable
	UnderSystemd func() bool            // default: INVOCATION_ID is set
	Exit         func(code int)         // default os.Exit
	ExitDelay    time.Duration          // default 1 s, so the reply is flushed first
	// Probe runs a candidate binary's `version` and returns what it prints.
	// A download whose embedded version is not the one requested is refused,
	// so a control plane whose manifest disagrees with its binaries cannot
	// make every host reinstall the same build on every retry.
	Probe  func(ctx context.Context, path string) (string, error)
	Logger *log.Logger
}

func (u *Updater) defaults() {
	if u.HTTP == nil {
		u.HTTP = &http.Client{Timeout: 120 * time.Second}
	}
	if u.Executable == nil {
		u.Executable = os.Executable
	}
	if u.UnderSystemd == nil {
		u.UnderSystemd = func() bool { return os.Getenv("INVOCATION_ID") != "" }
	}
	if u.Exit == nil {
		u.Exit = os.Exit
	}
	if u.ExitDelay == 0 {
		u.ExitDelay = time.Second
	}
	if u.Probe == nil {
		u.Probe = func(ctx context.Context, path string) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, path, "version").Output()
			return strings.TrimSpace(string(out)), err
		}
	}
}

// Apply downloads, verifies and installs the new binary. It does not exit;
// call ScheduleRestart after the response has been written.
func (u *Updater) Apply(ctx context.Context, req Request) (Response, *Error) {
	u.defaults()
	req.Version = strings.TrimSpace(req.Version)
	req.SHA256 = strings.ToLower(strings.TrimSpace(req.SHA256))
	if req.Version == "" {
		return Response{}, &Error{400, errors.New("version is required")}
	}
	if len(req.SHA256) != 64 {
		return Response{}, &Error{400, errors.New("sha256 must be 64 hex characters")}
	}
	if _, err := hex.DecodeString(req.SHA256); err != nil {
		return Response{}, &Error{400, errors.New("sha256 must be hex")}
	}
	parsed, err := url.Parse(req.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return Response{}, &Error{400, errors.New("url must be an http(s) URL")}
	}
	if req.Version == u.Version {
		return Response{}, &Error{409, fmt.Errorf("already running version %s", u.Version)}
	}

	exe, err := u.Executable()
	if err != nil {
		return Response{}, &Error{500, fmt.Errorf("locate executable: %w", err)}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return Response{}, &Error{400, err}
	}
	resp, err := u.HTTP.Do(httpReq)
	if err != nil {
		return Response{}, &Error{502, fmt.Errorf("download: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Response{}, &Error{502, fmt.Errorf("download: HTTP %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxSize+1))
	if err != nil {
		return Response{}, &Error{502, fmt.Errorf("download: %w", err)}
	}
	if len(body) > MaxSize {
		return Response{}, &Error{502, fmt.Errorf("download exceeds %d bytes", MaxSize)}
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != req.SHA256 {
		return Response{}, &Error{409, fmt.Errorf("checksum mismatch: downloaded %s, expected %s", got, req.SHA256)}
	}

	tmp := exe + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return Response{}, &Error{500, fmt.Errorf("write %s: %w", tmp, err)}
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		os.Remove(tmp)
		return Response{}, &Error{500, fmt.Errorf("write %s: %w", tmp, err)}
	}
	if err := f.Chmod(0o755); err != nil { // the umask may have narrowed the create mode
		f.Close()
		os.Remove(tmp)
		return Response{}, &Error{500, err}
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return Response{}, &Error{500, err}
	}
	reported, err := u.Probe(ctx, tmp)
	if err != nil {
		os.Remove(tmp)
		return Response{}, &Error{409, fmt.Errorf("downloaded binary does not run: %w", err)}
	}
	if reported != req.Version {
		os.Remove(tmp)
		return Response{}, &Error{409, fmt.Errorf("downloaded binary reports version %q, expected %q", reported, req.Version)}
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Remove(tmp)
		return Response{}, &Error{500, fmt.Errorf("replace %s: %w", exe, err)}
	}
	out := Response{OK: true, Version: req.Version, Restarting: u.UnderSystemd()}
	if !out.Restarting {
		out.Message = "binary replaced; restart the agent by hand (not running under systemd)"
	}
	if u.Logger != nil {
		u.Logger.Printf("self-update: installed version %s at %s (restarting=%v)", req.Version, exe, out.Restarting)
	}
	return out, nil
}

// ScheduleRestart exits the process after ExitDelay so systemd's Restart=always
// brings up the new binary. Call it only after the reply has been sent.
func (u *Updater) ScheduleRestart() {
	u.defaults()
	go func() {
		time.Sleep(u.ExitDelay)
		u.Exit(0)
	}()
}
