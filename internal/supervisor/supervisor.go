// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package supervisor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Name string

const (
	Tor      Name = "tor"
	Caddy    Name = "caddy"
	Authelia Name = "authelia"
)

type HealthFunc func(context.Context) error
type Spec struct {
	Name            Name
	Path            string
	Args            []string
	Env             []string
	Health, Recover HealthFunc
	Disabled        bool
}
type Status struct {
	Name        Name      `json:"name"`
	State       string    `json:"state"`
	PID         int       `json:"pid,omitempty"`
	Restarts    int       `json:"restarts"`
	Since       time.Time `json:"since"`
	LastError   string    `json:"last_error,omitempty"`
	Intentional bool      `json:"intentional_stop"`
}
type worker struct {
	spec       Spec
	desired    bool
	generation uint64
	cmd        *exec.Cmd
	status     Status
	wake       chan struct{}
}
type Supervisor struct {
	mu      sync.Mutex
	workers map[Name]*worker
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	logger  *log.Logger
}

func New(specs []Spec, logger *log.Logger) (*Supervisor, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	s := &Supervisor{workers: map[Name]*worker{}, logger: logger}
	for _, spec := range specs {
		if spec.Name != Tor && spec.Name != Caddy && spec.Name != Authelia || !filepath.IsAbs(spec.Path) || spec.Health == nil {
			return nil, errors.New("invalid component specification")
		}
		if _, exists := s.workers[spec.Name]; exists {
			return nil, errors.New("duplicate component specification")
		}
		s.workers[spec.Name] = &worker{spec: spec, desired: !spec.Disabled, wake: make(chan struct{}, 1), status: Status{Name: spec.Name, State: "pending"}}
	}
	if len(s.workers) != 3 {
		return nil, errors.New("all three components are required")
	}
	return s, nil
}
func (s *Supervisor) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx != nil {
		return errors.New("supervisor already started")
	}
	s.ctx, s.cancel = context.WithCancel(parent)
	for _, w := range s.workers {
		s.wg.Add(1)
		go s.run(w)
	}
	return nil
}
func (s *Supervisor) Shutdown() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func (s *Supervisor) Statuses() []Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Status, 0, len(s.workers))
	for _, w := range s.workers {
		result = append(result, w.status)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
func (s *Supervisor) StartComponent(name Name) error   { return s.command(name, true, false) }
func (s *Supervisor) StopComponent(name Name) error    { return s.command(name, false, true) }
func (s *Supervisor) RestartComponent(name Name) error { return s.command(name, true, true) }
func (s *Supervisor) Action(name Name, action string) error {
	switch action {
	case "start":
		return s.StartComponent(name)
	case "stop":
		return s.StopComponent(name)
	case "restart":
		return s.RestartComponent(name)
	default:
		return errors.New("invalid component action")
	}
}
func (s *Supervisor) command(name Name, desired, interrupt bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.workers[name]
	if w == nil || s.ctx == nil {
		return errors.New("unknown or inactive component")
	}
	w.desired, w.generation = desired, w.generation+1
	w.status.Intentional = !desired
	if interrupt && w.cmd != nil && w.cmd.Process != nil {
		_ = w.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
	return nil
}
func (s *Supervisor) run(w *worker) {
	defer s.wg.Done()
	failures := 0
	for {
		if !s.shouldRun(w) {
			if !s.waitWake(w, 0) {
				return
			}
			continue
		}
		generation, wait, err := s.launch(w)
		if err != nil {
			failures++
			s.failed(w, failures, "component could not start")
			if failures >= 6 || !s.waitWake(w, backoff(failures)) {
				if failures >= 6 {
					s.disableCrashLoop(w)
				}
				if s.contextDone() {
					return
				}
			}
			continue
		}
		started, healthDelay := time.Now(), 500*time.Millisecond
		exited := false
		for !exited {
			select {
			case <-s.ctx.Done():
				s.terminate(w, wait)
				return
			case <-w.wake:
				if s.generationChanged(w, generation) {
					s.terminate(w, wait)
					exited = true
				}
			case err = <-wait:
				exited = true
			case <-time.After(healthDelay):
				if s.checkHealth(w, started) {
					healthDelay = 5 * time.Second
				}
			}
		}
		s.clearProcess(w)
		if s.generationChanged(w, generation) {
			failures = 0
			continue
		}
		if time.Since(started) > 2*time.Minute {
			failures = 0
		}
		failures++
		s.failed(w, failures, "component exited")
		if failures >= 6 {
			s.disableCrashLoop(w)
			continue
		}
		if !s.waitWake(w, backoff(failures)) {
			return
		}
	}
}
func (s *Supervisor) launch(w *worker) (uint64, <-chan error, error) {
	s.mu.Lock()
	generation := w.generation
	s.mu.Unlock()
	cmd := exec.CommandContext(s.ctx, w.spec.Path, w.spec.Args...)
	cmd.Dir, cmd.Env = "/", componentEnv(os.Environ(), w.spec.Env)
	out, errOut := newLogWriter(s.logger, w.spec.Name), newLogWriter(s.logger, w.spec.Name)
	cmd.Stdout, cmd.Stderr = out, errOut
	if err := cmd.Start(); err != nil {
		return generation, nil, err
	}
	s.mu.Lock()
	w.cmd = cmd
	w.status = Status{Name: w.spec.Name, State: "starting", PID: cmd.Process.Pid, Restarts: w.status.Restarts + 1, Since: time.Now().UTC()}
	s.mu.Unlock()
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait(); out.flush(); errOut.flush() }()
	return generation, wait, nil
}
func (s *Supervisor) checkHealth(w *worker, started time.Time) bool {
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	err := w.spec.Health(ctx)
	cancel()
	s.mu.Lock()
	starting := w.status.State == "starting" && w.status.Restarts > 1
	s.mu.Unlock()
	if err == nil && starting && w.spec.Recover != nil {
		ctx, cancel = context.WithTimeout(s.ctx, 15*time.Second)
		err = w.spec.Recover(ctx)
		cancel()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if w.cmd == nil {
		return false
	}
	if err == nil {
		w.status.State, w.status.LastError = "running", ""
	} else if time.Since(started) > 45*time.Second {
		w.status.State, w.status.LastError = "unhealthy", "readiness check failed"
		_ = w.cmd.Process.Signal(syscall.SIGTERM)
	}
	return err == nil
}
func (s *Supervisor) terminate(w *worker, wait <-chan error) {
	s.mu.Lock()
	cmd := w.cmd
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-wait:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-wait
	}
	s.clearProcess(w)
}
func (s *Supervisor) shouldRun(w *worker) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !w.desired {
		w.status.State, w.status.PID, w.status.Intentional = "stopped", 0, true
	}
	return w.desired
}
func (s *Supervisor) generationChanged(w *worker, generation uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return w.generation != generation
}
func (s *Supervisor) clearProcess(w *worker) {
	s.mu.Lock()
	w.cmd, w.status.PID = nil, 0
	s.mu.Unlock()
}
func (s *Supervisor) failed(w *worker, failures int, message string) {
	s.mu.Lock()
	w.status.State, w.status.LastError, w.status.PID = "backoff", message, 0
	s.mu.Unlock()
}
func (s *Supervisor) disableCrashLoop(w *worker) {
	s.mu.Lock()
	w.desired, w.status.State, w.status.LastError = false, "crash-loop", "restart ceiling reached"
	s.mu.Unlock()
}
func (s *Supervisor) contextDone() bool { return s.ctx.Err() != nil }
func (s *Supervisor) waitWake(w *worker, delay time.Duration) bool {
	if delay == 0 {
		select {
		case <-s.ctx.Done():
			return false
		case <-w.wake:
			return true
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-s.ctx.Done():
		return false
	case <-w.wake:
		return true
	case <-timer.C:
		return true
	}
}
func backoff(failures int) time.Duration {
	d := 250 * time.Millisecond << min(failures-1, 7)
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}
func componentEnv(base, overrides []string) []string {
	blocked := []string{"OTEL_", "AUTHELIA_", "CADDY_", "TOR_"}
	result := make([]string, 0, len(base)+len(overrides)+4)
	for _, value := range base {
		keep := true
		for _, prefix := range blocked {
			if strings.HasPrefix(value, prefix) {
				keep = false
			}
		}
		if keep {
			result = append(result, value)
		}
	}
	for _, value := range overrides {
		if !strings.HasPrefix(value, "AUTHELIA_TELEMETRY_METRICS_") {
			result = append(result, value)
		}
	}
	return append(result, "OTEL_SDK_DISABLED=true", "OTEL_METRICS_EXPORTER=none", "OTEL_TRACES_EXPORTER=none", "AUTHELIA_TELEMETRY_METRICS_ENABLED=false")
}

type logWriter struct {
	mu      sync.Mutex
	logger  *log.Logger
	name    Name
	pending bytes.Buffer
}

func newLogWriter(logger *log.Logger, name Name) *logWriter {
	return &logWriter{logger: logger, name: name}
}
func (w *logWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(data)
	for _, b := range data {
		if b == '\n' || w.pending.Len() >= 8192 {
			w.emit()
		} else {
			_ = w.pending.WriteByte(b)
		}
	}
	return n, nil
}
func (w *logWriter) flush() { w.mu.Lock(); defer w.mu.Unlock(); w.emit() }
func (w *logWriter) emit() {
	if w.pending.Len() == 0 {
		return
	}
	size := w.pending.Len()
	w.pending.Reset()
	w.logger.Printf("component=%s output_redacted bytes=%d", w.name, size)
}
