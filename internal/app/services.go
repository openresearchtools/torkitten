// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"torkitten/internal/tunnel"
)

func (a *App) validateServices(next Services) error {
	if err := next.Validate(a.root); err != nil {
		return err
	}
	return next.Validate(a.run)
}
func (a *App) applyServices(next Services) error {
	if err := a.validateServices(next); err != nil {
		return err
	}
	old := map[string]Service{}
	for _, v := range a.services.Services {
		old[v.ID] = v
	}
	boundary := false
	for _, v := range next.Services {
		prior, ok := old[v.ID]
		if (v.SSH || prior.SSH) && (!ok || !reflect.DeepEqual(prior, v)) {
			boundary = true
		}
		delete(old, v.ID)
	}
	for _, v := range old {
		if v.SSH {
			boundary = true
		}
	}
	if boundary && a.host.Initialized && a.relay != nil {
		if err := a.revokeSessions(); err != nil {
			return err
		}
	}
	if a.relay != nil {
		for id := range old {
			a.relay.RemoveService(id)
		}
		for _, v := range next.Services {
			if !v.Available {
				a.relay.RemoveService(v.ID)
				continue
			}
			if err := a.relay.SetService(v.ID, tunnel.Endpoint{Network: v.Endpoint.Network, Address: v.Endpoint.Address}); err != nil {
				return err
			}
		}
	}
	a.services = next
	return nil
}
func (a *App) saveServices(next Services) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validateServices(next); err != nil {
		return err
	}
	// Persist desired configuration first. Any application error closes access;
	// there is no silently restored prior security configuration.
	if err := writeJSON(a.path("services.json"), next); err != nil {
		return err
	}
	if err := a.applyServices(next); err != nil {
		a.hostError = "service update failed; remote access closed"
		if a.relay != nil {
			a.relay.Revoke()
		}
		return err
	}
	if strings.HasPrefix(a.hostError, "services.json rejected:") {
		a.hostError = ""
	}
	b, _ := json.MarshalIndent(next, "", "  ")
	a.serviceBytes = string(append(b, '\n'))
	return nil
}
func (a *App) serviceList() []ViewService {
	a.mu.Lock()
	values := append([]Service(nil), a.services.Services...)
	a.mu.Unlock()
	var result []ViewService
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, v := range values {
		if !v.Available {
			continue
		}
		wg.Add(1)
		go func(v Service) {
			defer wg.Done()
			view := ViewService{ID: v.ID, Title: v.Title, SSH: v.SSH, Actions: []string{}}
			for action := range v.Actions {
				view.Actions = append(view.Actions, action)
			}
			sort.Strings(view.Actions)
			c, err := net.DialTimeout(v.Endpoint.Network, v.Endpoint.Address, 300*time.Millisecond)
			if err == nil {
				view.Reachable = true
				c.Close()
			}
			mu.Lock()
			result = append(result, view)
			mu.Unlock()
		}(v)
	}
	wg.Wait()
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if result == nil {
		result = []ViewService{}
	}
	return result
}
func (a *App) action(ctx context.Context, id, action, epoch string) error {
	a.mu.Lock()
	if epoch != "" && (epoch != a.host.OAuthClient || a.hostError != "") {
		a.mu.Unlock()
		return errors.New("OAuth login required")
	}
	var argv []string
	for _, v := range a.services.Services {
		if v.ID == id && (epoch == "" || v.Available) {
			argv = append([]string(nil), v.Actions[action]...)
		}
	}
	if len(argv) == 0 {
		a.mu.Unlock()
		return errors.New("service action is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	// The host preset invokes its chosen independent launcher. We add no shell,
	// resource limits, scheduling flags, restart policy, or inferred stop command.
	err := cmd.Start()
	a.mu.Unlock()
	if err == nil {
		err = cmd.Wait()
	}
	if err != nil {
		return errors.New("preset action failed")
	}
	return nil
}
func bearer(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(header, "Bearer ")
}
