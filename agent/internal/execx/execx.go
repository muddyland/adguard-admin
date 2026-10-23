// Package execx is the single door through which the agent runs external
// programs. Arguments are always passed as a list, never as a shell string, so
// control-plane data can never become a command.
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
)

// Debug, when set, receives the complete stderr of every failed command. The
// error returned to callers carries only the last meaningful line: a failed
// `docker run` otherwise reports dozens of lines of image-pull progress ahead
// of the one line that says why it failed.
var Debug *log.Logger

// Runner runs programs.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)
	RunInput(ctx context.Context, input []byte, name string, args ...string) (stdout, stderr []byte, err error)
	LookPath(name string) (string, error)
}

// Real executes programs on the host.
type Real struct{}

func (Real) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	return Real{}.RunInput(ctx, nil, name, args...)
}

func (Real) RunInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		full := strings.TrimSpace(errb.String())
		if Debug != nil {
			Debug.Printf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, full)
		}
		err = fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, LastLine(full))
	}
	return out.Bytes(), errb.Bytes(), err
}

// LastLine returns the last non-empty line of a program's stderr, skipping the
// "Run '... --help' for more information" hint docker appends after its error.
func LastLine(stderr string) string {
	lines := strings.Split(stderr, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		t := strings.TrimSpace(lines[i])
		if t == "" || (strings.HasPrefix(t, "Run '") && strings.Contains(t, "--help'")) {
			continue
		}
		return t
	}
	return ""
}

func (Real) LookPath(name string) (string, error) { return exec.LookPath(name) }

// Call is one recorded invocation.
type Call struct {
	Name  string
	Args  []string
	Input []byte
}

// Result is a scripted answer.
type Result struct {
	Stdout string
	Stderr string
	Err    error
}

// Fake answers from a handler and records every call.
type Fake struct {
	mu       sync.Mutex
	Calls    []Call
	Handler  func(name string, args []string) Result
	Programs map[string]bool // LookPath answers; nil means everything exists
}

func (f *Fake) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	return f.RunInput(ctx, nil, name, args...)
}

func (f *Fake) RunInput(_ context.Context, input []byte, name string, args ...string) ([]byte, []byte, error) {
	f.mu.Lock()
	f.Calls = append(f.Calls, Call{Name: name, Args: append([]string(nil), args...), Input: input})
	f.mu.Unlock()
	if f.Handler == nil {
		return nil, nil, nil
	}
	r := f.Handler(name, args)
	return []byte(r.Stdout), []byte(r.Stderr), r.Err
}

func (f *Fake) LookPath(name string) (string, error) {
	if f.Programs == nil {
		return "/usr/bin/" + name, nil
	}
	if f.Programs[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found: " + name)
}

// Joined renders a call as one line for assertions.
func (c Call) Joined() string { return strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " ")) }
