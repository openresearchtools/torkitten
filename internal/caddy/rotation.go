// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package caddy

import (
	"context"
	"errors"
	"os"
	"time"
	"torkitten/internal/authelia"
	"torkitten/internal/model"
	"torkitten/internal/state"
	"torkitten/internal/supervisor"
	torkitTor "torkitten/internal/tor"
)

type RotatedCredential struct {
	DeviceID   string `json:"device_id"`
	Name       string `json:"name"`
	Credential string `json:"credential"`
}
type IdentityRotator struct {
	Tor       torkitTor.Paths
	Renderer  Renderer
	Caddy     Applier
	Authelia  authelia.Paths
	Auth      *authelia.Client
	Processes *supervisor.Supervisor
}

func (r IdentityRotator) Apply(ctx context.Context, current model.State) (model.State, []RotatedCredential, func() error, func(), error) {
	candidate, private := state.Clone(current), make([]string, len(current.Devices))
	if r.Caddy == nil || r.Auth == nil || r.Processes == nil {
		return current, nil, nil, nil, errors.New("identity runtime unavailable")
	}
	for i := range candidate.Devices {
		public, secret, err := torkitTor.GenerateClientKey()
		if err != nil {
			return current, nil, nil, nil, err
		}
		candidate.Devices[i].PublicKey, private[i] = public, secret
	}
	stage, err := r.Tor.StageIdentity(ctx, candidate.Devices)
	if err != nil {
		return current, nil, nil, nil, err
	}
	oldID := current.ServiceID
	candidate.ServiceID = stage.ServiceID
	credentials := make([]RotatedCredential, len(candidate.Devices))
	for i, device := range candidate.Devices {
		value, credentialErr := torkitTor.Credential(candidate.ServiceID, private[i])
		if credentialErr != nil {
			_ = os.RemoveAll(stage.Root)
			return current, nil, nil, nil, credentialErr
		}
		credentials[i] = RotatedCredential{device.ID, device.Name, value}
	}
	backup, authRestarted := "", false
	rollback := func() error {
		recovery, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		_ = os.RemoveAll(stage.Root)
		var identityErr, torErr, authErr error
		if backup != "" {
			identityErr = r.Tor.RestoreIdentity(backup)
		}
		config, configErr := r.Authelia.Render(oldID)
		if configErr == nil {
			configErr = state.AtomicWrite(r.Authelia.Config, config, 0o600)
		}
		r.Auth.SetServiceID(oldID)
		if backup != "" {
			torErr = RestartComponent(recovery, r.Processes, supervisor.Tor)
		}
		if authRestarted {
			authErr = RestartComponent(recovery, r.Processes, supervisor.Authelia)
		}
		prior, priorErr := r.Renderer.Render(current)
		if priorErr == nil {
			_, priorErr = r.Caddy.Apply(recovery, prior)
		}
		return errors.Join(identityErr, configErr, torErr, authErr, priorErr)
	}
	fail := func(cause error) (model.State, []RotatedCredential, func() error, func(), error) {
		return current, nil, nil, nil, errors.Join(cause, rollback())
	}
	aliases := r.Renderer
	aliases.Aliases = []string{oldID}
	config, err := aliases.Render(candidate)
	if err == nil {
		_, err = r.Caddy.Apply(ctx, config)
	}
	if err != nil {
		return fail(err)
	}
	authConfig, err := r.Authelia.Render(candidate.ServiceID)
	if err == nil {
		err = state.AtomicWrite(r.Authelia.Config, authConfig, 0o600)
	}
	if err == nil {
		err = (authelia.Runner{Paths: r.Authelia}).Validate(ctx)
	}
	if err != nil {
		return fail(err)
	}
	if backup, err = r.Tor.ActivateIdentity(stage); err != nil {
		return fail(err)
	}
	if err = RestartComponent(ctx, r.Processes, supervisor.Tor); err != nil {
		return fail(err)
	}
	r.Auth.SetServiceID(candidate.ServiceID)
	authRestarted = true
	if err = RestartComponent(ctx, r.Processes, supervisor.Authelia); err != nil {
		return fail(err)
	}
	config, err = r.Renderer.Render(candidate)
	if err == nil {
		_, err = r.Caddy.Apply(ctx, config)
	}
	if err != nil {
		return fail(err)
	}
	return candidate, credentials, rollback, func() { _ = r.Tor.FinishIdentity(backup) }, nil
}
func RestartAuth(ctx context.Context, process *supervisor.Supervisor) error {
	return RestartComponent(ctx, process, supervisor.Authelia)
}
func RestartComponent(ctx context.Context, process *supervisor.Supervisor, name supervisor.Name) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	oldPID := 0
	for _, status := range process.Statuses() {
		if status.Name == name {
			oldPID = status.PID
		}
	}
	if err := process.RestartComponent(name); err != nil {
		return err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		for _, status := range process.Statuses() {
			if status.Name == name && status.State == "running" && status.PID != 0 && status.PID != oldPID {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
