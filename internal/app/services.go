// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
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
	boundary := next.SSH != a.services.SSH
	if boundary && a.host.Initialized && a.host.Enrolled && a.relay != nil {
		if err := a.revokeSessions(); err != nil {
			return err
		}
	}
	if a.relay != nil {
		for _, v := range next.Services {
			prior, ok := old[v.ID]
			if !v.Available || (ok && (prior.Endpoint != v.Endpoint || prior.Command != v.Command)) {
				a.relay.RemoveService(v.ID)
			}
			delete(old, v.ID)
		}
		for id := range old {
			a.relay.RemoveService(id)
		}
	}
	if err := a.reconcileManaged(next); err != nil {
		return err
	}
	if a.relay != nil {
		if err := a.syncHostSSH(next.SSH); err != nil {
			return err
		}
		for _, v := range next.Services {
			if !v.Available {
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
	if strings.HasPrefix(a.hostError, "services.json rejected:") || a.hostError == "service update failed; remote access closed" {
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
			view := ViewService{ID: v.ID, Title: v.Title, Running: a.managedRunning(v), Actions: []string{"load", "reload", "stop"}}
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
	if ssh := a.hostSSHView(); ssh != nil {
		result = append(result, *ssh)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if result == nil {
		result = []ViewService{}
	}
	return result
}
func (a *App) action(ctx context.Context, id, action, epoch string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if epoch != "" && (epoch != a.host.OAuthClient || a.hostError != "") {
		return errors.New("OAuth login required")
	}
	for _, service := range a.services.Services {
		if service.ID == id && (epoch == "" || service.Available) {
			return a.managedAction(ctx, service, action)
		}
	}
	return errors.New("service action is unavailable")
}
func bearer(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(header, "Bearer ")
}
