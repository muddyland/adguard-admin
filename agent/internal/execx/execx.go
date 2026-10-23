// Package execx is the single door through which the agent runs external
// programs. Arguments are always passed as a list, never as a shell string, so
// control-plane data can never become a command.
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

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
		err = fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), errb.Bytes(), err
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
