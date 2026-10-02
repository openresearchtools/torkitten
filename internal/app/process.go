// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type process struct {
	cmd      *exec.Cmd
	done     chan struct{}
	mu       sync.Mutex
	err      error
	stopping bool
}

func componentEnv() []string {
	var env []string
	for _, s := range os.Environ() {
		if !strings.HasPrefix(s, "AUTHELIA_") && !strings.HasPrefix(s, "TOR_") && !strings.HasPrefix(s, "OTEL_") && !strings.HasPrefix(s, "GODEBUG=") && !strings.HasPrefix(s, "GOTELEMETRY=") && !strings.HasPrefix(s, "DO_NOT_TRACK=") {
			env = append(env, s)
		}
	}
	env = append(env, "AUTHELIA_TELEMETRY_METRICS_ENABLED=false", "GOTELEMETRY=off", "OTEL_SDK_DISABLED=true", "DO_NOT_TRACK=1")
	return env
}
func startProcess(ctx context.Context, binary, logPath string, args ...string) (*process, error) {
	if !filepath.IsAbs(binary) {
		return nil, errors.New("component path must be absolute")
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = f
	cmd.Stderr = f
	cmd.Env = componentEnv()
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	if err = cmd.Start(); err != nil {
		f.Close()
		return nil, err
	}
	p := &process{cmd: cmd, done: make(chan struct{})}
	go func() {
		e := cmd.Wait()
		f.Close()
		p.mu.Lock()
		p.err = e
		p.mu.Unlock()
		close(p.done)
	}()
	return p, nil
}
func (p *process) stop() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.stopping = true
	p.mu.Unlock()
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}
func (p *process) alive() bool {
	if p == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}
func (p *process) reload() error {
	if !p.alive() {
		return errors.New("component is not running")
	}
	return p.cmd.Process.Signal(syscall.SIGHUP)
}
func unixHTTP(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}, Timeout: 20 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}
func waitReady(ctx context.Context, p *process, check func() error) error {
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if !p.alive() {
			return errors.New("component stopped before readiness; inspect its private log")
		}
		if check() == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("component readiness timed out")
		case <-tick.C:
		}
	}
}
func runPrivate(ctx context.Context, binary string, input []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = strings.NewReader(string(input))
	cmd.Env = componentEnv()
	var output limitedOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s command failed", filepath.Base(binary))
	}
	if output.large {
		return nil, errors.New("component response too large")
	}
	return output.data, nil
}

type limitedOutput struct {
	data  []byte
	large bool
}

func (w *limitedOutput) Write(b []byte) (int, error) {
	n := len(b)
	if len(w.data)+n <= MaxFile {
		w.data = append(w.data, b...)
	} else {
		w.large = true
	}
	return n, nil
}
