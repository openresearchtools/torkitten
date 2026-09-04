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
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("TORKITTEN_HELPER_PROCESS") != "1" {
		return
	}
	if os.Getenv("TORKITTEN_HELPER_MODE") == "crash" {
		os.Exit(2)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func helperSpec(name Name, mode string) Spec {
	return Spec{Name: name, Path: os.Args[0], Args: []string{"-test.run=TestHelperProcess"}, Env: []string{"TORKITTEN_HELPER_PROCESS=1", "TORKITTEN_HELPER_MODE=" + mode}, Health: func(context.Context) error { return nil }}
}

func TestIndependentLifecycle(t *testing.T) {
	caddy := helperSpec(Caddy, "stable")
	var recovered atomic.Int32
	caddy.Recover = func(context.Context) error {
		if recovered.Add(1) == 1 {
			return errors.New("retry recovery")
		}
		return nil
	}
	s, err := New([]Spec{helperSpec(Tor, "stable"), caddy, helperSpec(Authelia, "stable")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err = s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown()
	waitStatus(t, s, Caddy, "running", 1)
	if recovered.Load() != 0 {
		t.Fatal("recovery ran on the initial start")
	}
	if err = s.StopComponent(Caddy); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, s, Caddy, "stopped", 1)
	if status := statusFor(s, Tor); status.State != "running" {
		t.Fatalf("Tor was disrupted: %+v", status)
	}
	if err = s.StartComponent(Caddy); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, s, Caddy, "running", 2)
	if recovered.Load() != 2 {
		t.Fatal("failed recovery was not retried before readiness")
	}
	if err = s.RestartComponent(Caddy); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, s, Caddy, "running", 3)
	if recovered.Load() != 3 {
		t.Fatal("recovery did not run after restart")
	}
}

func TestCrashBackoffDoesNotStopPeers(t *testing.T) {
	s, err := New([]Spec{helperSpec(Tor, "crash"), helperSpec(Caddy, "stable"), helperSpec(Authelia, "stable")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown()
	waitStatus(t, s, Tor, "backoff", 2)
	waitStatus(t, s, Authelia, "running", 1)
	if err = s.StopComponent(Tor); err != nil {
		t.Fatal(err)
	}
}

func TestForcedTelemetryEnvironmentAndRedactedLogs(t *testing.T) {
	env := componentEnv([]string{"PATH=/bin", "OTEL_SDK_DISABLED=false", "AUTHELIA_ACCESS_CONTROL_DEFAULT_POLICY=bypass", "CADDY_ADMIN=localhost:2019", "TOR_CONTROLPORT=1"}, []string{"AUTHELIA_TELEMETRY_METRICS_ENABLED=true", "AUTHELIA_SESSION_SECRET_FILE=/private/session"})
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "OTEL_SDK_DISABLED=false") || strings.Contains(joined, "METRICS_ENABLED=true") || strings.Contains(joined, "bypass") || strings.Contains(joined, "CADDY_ADMIN") || strings.Contains(joined, "TOR_CONTROLPORT") || !strings.Contains(joined, "OTEL_SDK_DISABLED=true") || !strings.Contains(joined, "METRICS_ENABLED=false") || !strings.Contains(joined, "AUTHELIA_SESSION_SECRET_FILE=/private/session") {
		t.Fatalf("environment=%q", joined)
	}
	var output bytes.Buffer
	writer := newLogWriter(log.New(&output, "", 0), Tor)
	_, _ = writer.Write([]byte("password=do-not-log\nordinary details\n"))
	writer.flush()
	if strings.Contains(output.String(), "do-not-log") || strings.Contains(output.String(), "ordinary") || !strings.Contains(output.String(), "output_redacted") {
		t.Fatalf("log output=%q", output.String())
	}
}

func TestRequiresFixedComponentSet(t *testing.T) {
	_, err := New([]Spec{helperSpec(Tor, "stable")}, log.New(io.Discard, "", 0))
	if err == nil {
		t.Fatal("incomplete component set accepted")
	}
}

func waitStatus(t *testing.T, s *Supervisor, name Name, state string, restarts int) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		status := statusFor(s, name)
		if status.State == state && status.Restarts >= restarts {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("component %s did not reach %s: %+v", name, state, statusFor(s, name))
}

func statusFor(s *Supervisor, name Name) Status {
	for _, status := range s.Statuses() {
		if status.Name == name {
			return status
		}
	}
	return Status{}
}
