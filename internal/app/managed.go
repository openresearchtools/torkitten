// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The user manager owns the process/cgroup. TorKitten never waits on the
// application's lifetime or assigns resource limits, scheduling or restart policy.
func (a *App) managedPrefix() string {
	sum := sha256.Sum256([]byte(a.root))
	return fmt.Sprintf("torkitten-%x-", sum[:10])
}
func (a *App) managedUnit(service Service) string {
	data, _ := json.Marshal(struct {
		Command  string
		Endpoint Endpoint
	}{service.Command, service.Endpoint})
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%s%s-%x.service", a.managedPrefix(), service.ID, sum[:8])
}
func (a *App) ownsUnit(unit string) bool {
	if !strings.HasPrefix(unit, a.managedPrefix()) || !strings.HasSuffix(unit, ".service") {
		return false
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(unit, a.managedPrefix()), ".service")
	split := strings.LastIndexByte(rest, '-')
	if split < 0 || !identifier.MatchString(rest[:split]) {
		return false
	}
	digest, err := hex.DecodeString(rest[split+1:])
	return err == nil && len(digest) == 8
}
func manager(ctx context.Context, binary string, args ...string) ([]byte, error) {
	data, err := runPrivate(ctx, binary, nil, args...)
	if err != nil {
		return nil, errors.New("systemd user service control failed; check the user manager and service journal")
	}
	return data, nil
}
func unitState(ctx context.Context, unit string) (running, exists bool, err error) {
	data, err := manager(ctx, "/usr/bin/systemctl", "--user", "--no-pager", "show", "--property=LoadState,ActiveState", "--", unit)
	if err != nil {
		return false, false, err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			fields[k] = v
		}
	}
	if fields["LoadState"] == "" || fields["ActiveState"] == "" {
		return false, false, errors.New("invalid user manager status")
	}
	return fields["ActiveState"] == "active" || fields["ActiveState"] == "reloading", fields["LoadState"] != "not-found", nil
}
func (a *App) stopUnit(ctx context.Context, unit string) error {
	if !a.ownsUnit(unit) {
		return errors.New("refusing unrelated systemd unit")
	}
	_, exists, err := unitState(ctx, unit)
	if err != nil || !exists {
		return err
	}
	if _, err = manager(ctx, "/usr/bin/systemctl", "--user", "--no-ask-password", "stop", "--", unit); err != nil {
		return err
	}
	// --collect unloads a stopped transient service. Wait for the manager's GC
	// before reusing its name; no alternate launch path or repeated Start request.
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		_, exists, err = unitState(ctx, unit)
		if err != nil || !exists {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
func (a *App) managedAction(ctx context.Context, service Service, action string) error {
	if action != "load" && action != "reload" && action != "stop" {
		return errors.New("unknown service action")
	}
	argv, err := commandArgs(service.Command)
	if err != nil {
		return err
	}
	// This deadline bounds control calls only. systemd-run returns after exec;
	// the separately owned service does not inherit this context or its stdio.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	unit := a.managedUnit(service)
	running, exists, err := unitState(ctx, unit)
	if err != nil {
		return err
	}
	if action == "load" && running {
		return nil
	}
	if action == "stop" || exists {
		if err = a.stopUnit(ctx, unit); err != nil {
			return err
		}
	}
	if action == "stop" {
		return nil
	}
	args := []string{"--user", "--quiet", "--no-ask-password", "--collect", "--service-type=exec", "--expand-environment=no", "--unit", unit, "--"}
	_, err = manager(ctx, "/usr/bin/systemd-run", append(args, argv...)...)
	return err
}
func (a *App) managedRunning(service Service) bool {
	ctx, cancel := context.WithTimeout(a.ctx, 3*time.Second)
	defer cancel()
	running, _, err := unitState(ctx, a.managedUnit(service))
	return err == nil && running
}
func (a *App) reconcileManaged(next Services) error {
	// A client-only profile has no host services to reconcile and requires no
	// Linux user manager. Configuring or running host services does require it.
	if !a.host.Initialized && len(next.Services) == 0 && len(a.services.Services) == 0 && !next.SSH && !a.services.SSH {
		return nil
	}
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	defer cancel()
	data, err := manager(ctx, "/usr/bin/systemctl", "--user", "list-units", "--all", "--type=service", "--no-legend", "--plain", "--full", "--no-pager", a.managedPrefix()+"*.service")
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, service := range next.Services {
		keep[a.managedUnit(service)] = true
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		unit := fields[0]
		if a.ownsUnit(unit) && !keep[unit] {
			if err = a.stopUnit(ctx, unit); err != nil {
				return err
			}
		}
	}
	return nil
}
