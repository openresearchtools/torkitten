// Copyright 2026 The TorKitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"torkitten/internal/tunnel"
)

func TestManagedOwnership(t *testing.T) {
	a := &App{root: "/private/host-a"}
	s := Service{ID: "model", Command: "/usr/bin/sleep 120", Endpoint: Endpoint{"tcp", "127.0.0.1:8080"}}
	u := a.managedUnit(s)
	if !a.ownsUnit(u) || (&App{root: "/private/host-b"}).ownsUnit(u) {
		t.Fatal("unit ownership crosses application states")
	}
	s.Title, s.Available = "Renamed", true
	if a.managedUnit(s) != u {
		t.Fatal("display or availability change replaced launch identity")
	}
	s.Command = "/usr/bin/sleep 121"
	if a.managedUnit(s) == u {
		t.Fatal("changed command retained old launch identity")
	}
	s.Command, s.Endpoint.Address = "/usr/bin/sleep 120", "127.0.0.1:8081"
	if a.managedUnit(s) == u {
		t.Fatal("changed endpoint retained old launch identity")
	}
	for _, foreign := range []string{"dbus.service", a.managedPrefix() + "model.service", a.managedPrefix() + "bad-id-zzzzzzzzzzzzzzzz.service", a.managedPrefix() + "../../escape-1234567890abcdef.service"} {
		if a.ownsUnit(foreign) || a.stopUnit(context.Background(), foreign) == nil {
			t.Fatal("accepted unrelated unit", foreign)
		}
	}
	if a.managedAction(context.Background(), s, "restart") == nil {
		t.Fatal("accepted a non-API action")
	}
}

func TestManagedClientOnly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &App{root: "/private/client", ctx: ctx}
	if err := a.applyServices(Services{Version: 2}); err != nil {
		t.Fatal("client-only configuration attempted host management", err)
	}
	a.host.Initialized = true
	if err := a.applyServices(Services{Version: 2}); err == nil {
		t.Fatal("hosting silently accepted an unavailable manager")
	}
	a.hostError = "complete local two-factor setup"
	a.services.SSH = true
	a.relay = &tunnel.Server{}
	if err := a.applyServices(Services{Version: 2}); err == nil || !strings.Contains(err.Error(), "systemd user service control") {
		t.Fatal("pre-enrollment SSH change tried to revoke nonexistent sessions instead of reaching manager validation", err)
	}
	if a.host.Enrolled || a.hostError != "complete local two-factor setup" {
		t.Fatal("pre-enrollment service update bypassed local two-factor setup")
	}
}

func TestManagedCorrectedConfigurationClearsOnlyServiceError(t *testing.T) {
	a := &App{root: t.TempDir(), ctx: context.Background(), hostError: "service update failed; remote access closed"}
	if err := a.saveServices(Services{Version: 2}); err != nil || a.hostError != "" {
		t.Fatal("explicit corrected configuration retained stale service failure", err)
	}
	a.hostError = "authelia stopped; remote access is closed"
	if err := a.saveServices(Services{Version: 2}); err != nil || a.hostError == "" {
		t.Fatal("service edit cleared unrelated authorization failure", err)
	}
}

// Opt-in: requires the real host user manager; generated files stay outside Git.
// The >45-second assertion intentionally cannot be shortened by an environment flag.
func TestLiveManaged(t *testing.T) {
	dir := os.Getenv("TORKITTEN_MANAGED_PROOF")
	if dir == "" {
		t.Skip("set TORKITTEN_MANAGED_PROOF to a fresh external proof directory")
	}
	base := "/run/media/user/Data/TorkittenV2Build/proofs/"
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || !strings.HasPrefix(dir, base) {
		t.Fatal("proof directory must be below TorkittenV2Build/proofs")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal("proof directory must be fresh", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &App{root: dir, ctx: ctx, host: HostState{OAuthClient: "proof-epoch"}}
	var units []string
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		for _, unit := range units {
			if err := a.stopUnit(cleanup, unit); err != nil {
				t.Error("fixture unit cleanup", err)
			}
		}
	})
	var checks []string
	pass := func(name string) { checks = append(checks, name); t.Log(name) }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	fixture := filepath.Join(dir, "process.py")
	state := filepath.Join(dir, "process.json")
	must(os.WriteFile(fixture, []byte(`import json, os, sys, time
os.umask(0o077)
eof = sys.stdin.buffer.read() == b''
with open(sys.argv[1] + '.tmp', 'w') as f:
    json.dump({'pid': os.getpid(), 'ppid': os.getppid(), 'argv': sys.argv[2:], 'stdin_eof': eof, 'cgroup': open('/proc/self/cgroup').read()}, f)
os.replace(sys.argv[1] + '.tmp', sys.argv[1])
time.sleep(180)
`), 0600))
	s := Service{ID: "model", Title: "Proof", Available: true, Endpoint: Endpoint{"tcp", "127.0.0.1:49373"}, Command: fmt.Sprintf("/usr/bin/python3 %s %s '$HOME' '%%n' 'space word' ';touch nope'", fixture, state)}
	a.services = Services{Version: 2, Services: []Service{s}}
	units = append(units, a.managedUnit(s))
	type snapshot struct {
		PID    int      `json:"pid"`
		PPID   int      `json:"ppid"`
		Argv   []string `json:"argv"`
		EOF    bool     `json:"stdin_eof"`
		Cgroup string   `json:"cgroup"`
	}
	read := func(previous int) snapshot {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var value snapshot
			data, err := os.ReadFile(state)
			if err == nil && json.Unmarshal(data, &value) == nil && value.PID != 0 && value.PID != previous {
				return value
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("managed executable did not write readiness")
		return snapshot{}
	}
	request, finish := context.WithCancel(context.Background())
	started := time.Now()
	must(a.action(request, s.ID, "load", "proof-epoch"))
	finish()
	first := read(0)
	if !first.EOF || !reflect.DeepEqual(first.Argv, []string{"$HOME", "%n", "space word", ";touch nope"}) {
		t.Fatalf("argv expansion or attached stdin: %+v", first)
	}
	self, err := os.ReadFile("/proc/self/cgroup")
	must(err)
	if first.PPID == os.Getpid() || first.Cgroup == string(self) || !strings.Contains(first.Cgroup, a.managedUnit(s)) {
		t.Fatal("launched process was not assigned its independent service cgroup")
	}
	pass("literal arguments, independent cgroup and disconnected stdin")
	properties, err := manager(ctx, "/usr/bin/systemctl", "--user", "show", "--property=MemoryHigh,MemoryMax", "--", a.managedUnit(s))
	must(err)
	if !strings.Contains(string(properties), "MemoryHigh=infinity") || !strings.Contains(string(properties), "MemoryMax=infinity") {
		t.Fatal("proof host has unexpected service memory properties", string(properties))
	}
	pass("fixture has no MemoryHigh or MemoryMax limits")
	time.Sleep(time.Until(started.Add(46 * time.Second)))
	if !a.managedRunning(s) {
		t.Fatal("service stopped after its launch request ended")
	}
	pass("real process remains running after 46 seconds and request cancellation")
	cancel()
	ctx, reopenedCancel := context.WithCancel(context.Background())
	defer reopenedCancel()
	reopened := &App{root: dir, ctx: ctx, host: a.host, services: a.services}
	must(reopened.reconcileManaged(reopened.services))
	must(reopened.action(ctx, s.ID, "load", "proof-epoch"))
	pid, err := manager(ctx, "/usr/bin/systemctl", "--user", "show", "--property=MainPID", "--value", "--", reopened.managedUnit(s))
	must(err)
	if strings.TrimSpace(string(pid)) != strconv.Itoa(first.PID) {
		t.Fatal("same-state reopening or repeated Load replaced running process")
	}
	a = reopened
	pass("same-state reopening and idempotent Load retain process")
	if reopened.action(ctx, s.ID, "stop", "old-epoch") == nil || !reopened.managedRunning(s) {
		t.Fatal("stale authorization changed managed service")
	}
	pass("stale OAuth epoch cannot stop service")
	disabled := s
	disabled.Available = false
	must(a.applyServices(Services{Version: 2, Services: []Service{disabled}}))
	if !a.managedRunning(s) || a.action(ctx, s.ID, "stop", "proof-epoch") == nil {
		t.Fatal("disabling remote availability stopped process or retained remote actions")
	}
	must(a.applyServices(Services{Version: 2, Services: []Service{s}}))
	pass("availability changes preserve process and deny unavailable remote actions")
	must(reopened.action(ctx, s.ID, "reload", "proof-epoch"))
	second := read(first.PID)
	if _, err := os.Stat("/proc/" + strconv.Itoa(first.PID)); !os.IsNotExist(err) {
		t.Fatal("Reload left old process alive")
	}
	if !reopened.managedRunning(s) || second.PID == first.PID {
		t.Fatal("Reload did not relaunch")
	}
	pass("Reload terminates old process and launches configured command")
	foreign := &App{root: filepath.Join(dir, "other-host"), ctx: ctx}
	other := Service{ID: "model", Command: "/usr/bin/sleep 180", Endpoint: s.Endpoint}
	must(foreign.managedAction(ctx, other, "load"))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if err := foreign.stopUnit(cleanup, foreign.managedUnit(other)); err != nil {
			t.Error("other host fixture cleanup", err)
		}
	})
	next := s
	next.Command += " changed"
	must(reopened.reconcileManaged(Services{Version: 2, Services: []Service{next}}))
	if reopened.managedRunning(s) {
		t.Fatal("changed preset retained old process")
	}
	pass("changed preset reconciliation stops old owned launch")
	must(reopened.action(ctx, s.ID, "load", "proof-epoch"))
	third := read(second.PID)
	must(reopened.action(ctx, s.ID, "stop", "proof-epoch"))
	if reopened.managedRunning(s) {
		t.Fatal("Stop left unit running")
	}
	if _, err := os.Stat("/proc/" + strconv.Itoa(third.PID)); !os.IsNotExist(err) {
		t.Fatal("Stop left process alive")
	}
	pass("Stop terminates managed process")
	must(a.reconcileManaged(Services{Version: 2}))
	if !foreign.managedRunning(other) {
		t.Fatal("reconciliation touched another application's unit")
	}
	pass("reconciliation preserves other application's running unit")
	missing := s
	missing.ID, missing.Command = "missing", filepath.Join(dir, "missing-executable")
	units = append(units, a.managedUnit(missing))
	if a.managedAction(ctx, missing, "load") == nil || a.managedRunning(missing) {
		t.Fatal("missing executable accepted")
	}
	pass("missing executable fails at exec with no alternate launch")
	bus, runtime := os.Getenv("DBUS_SESSION_BUS_ADDRESS"), os.Getenv("XDG_RUNTIME_DIR")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(dir, "absent-bus"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "absent-runtime"))
	err = a.managedAction(ctx, s, "load")
	must(os.Setenv("DBUS_SESSION_BUS_ADDRESS", bus))
	must(os.Setenv("XDG_RUNTIME_DIR", runtime))
	if err == nil || a.managedRunning(s) {
		t.Fatal("missing user manager triggered alternate launch")
	}
	pass("unavailable user manager fails without fallback")
	result := map[string]any{"checks": checks, "seconds": time.Since(started).Seconds(), "manager": "systemd --user", "resource_properties": strings.TrimSpace(string(properties))}
	data, err := json.MarshalIndent(result, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(dir, "results.json"), append(data, '\n'), 0600))
}
