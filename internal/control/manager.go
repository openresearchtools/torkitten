// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
	"torkitten/internal/authelia"
	"torkitten/internal/caddy"
	"torkitten/internal/localsession"
	"torkitten/internal/model"
	"torkitten/internal/state"
	"torkitten/internal/supervisor"
	torkitTor "torkitten/internal/tor"
)

type Caddy interface {
	Apply(context.Context, []byte) ([]byte, error)
	RootCA(context.Context) ([]byte, error)
}

func AuthenticateFactors(ctx context.Context, client *authelia.Client, username string, password []byte, token string) (*authelia.FactorSession, error) {
	if client == nil {
		return nil, errors.New("authentication failed")
	}
	flow, err := client.BeginFactors(ctx, username, password)
	if err != nil {
		return nil, err
	}
	if _, err = flow.Complete(ctx, token); err != nil {
		flow.Destroy()
		return nil, err
	}
	return flow, nil
}

type IdentityRuntime interface {
	Apply(context.Context, model.State) (model.State, []caddy.RotatedCredential, func() error, func(), error)
}
type Manager struct {
	store    *state.Store
	renderer caddy.Renderer
	caddy    Caddy
	tor      torkitTor.Paths
	control  torkitTor.Client
	rotation IdentityRuntime
	sessions *localsession.Manager
	process  *supervisor.Supervisor
	now      func() time.Time
}

func New(store *state.Store, renderer caddy.Renderer, caddyClient Caddy, torPaths torkitTor.Paths) *Manager {
	return &Manager{store: store, renderer: renderer, caddy: caddyClient, tor: torPaths, control: torkitTor.Client{Socket: torPaths.ControlSocket, Cookie: torPaths.CookieFile}, now: time.Now}
}
func (m *Manager) State() model.State                         { return m.store.View() }
func (m *Manager) SetIdentityRuntime(runtime IdentityRuntime) { m.rotation = runtime }
func (m *Manager) SetCredentials(s *localsession.Manager, p *supervisor.Supervisor) {
	m.sessions, m.process = s, p
}
func (m *Manager) PrepareCredentialChange() error { return m.sessions.RevokeAll() }
func (m *Manager) FinishCredentialChange(ctx context.Context) error {
	return caddy.RestartAuth(ctx, m.process)
}
func (m *Manager) RotateIdentity(ctx context.Context, confirmation string) ([]caddy.RotatedCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if !strings.EqualFold(strings.TrimSpace(confirmation), "ROTATE") || m.rotation == nil {
		return nil, errors.New("identity rotation unavailable")
	}
	var credentials []caddy.RotatedCredential
	var finish func()
	err := m.store.Transition(func(current model.State) (model.State, func() error, error) {
		if !current.Initialized || current.Pending != nil || current.Bootstrap != nil || len(current.Devices) == 0 {
			return current, nil, errors.New("identity cannot be rotated")
		}
		base := state.Clone(current)
		base.Sessions, base.Bootstrap = []model.LocalSession{}, nil
		candidate, values, rollback, commit, err := m.rotation.Apply(ctx, base)
		if err != nil {
			return current, nil, err
		}
		if err = candidate.Validate(); err != nil {
			_ = rollback()
			return current, nil, err
		}
		credentials, finish = values, commit
		return candidate, rollback, nil
	})
	if err == nil && finish != nil {
		finish()
	}
	return credentials, err
}
func (m *Manager) Initialize(ctx context.Context, session model.LocalSession) error {
	return m.caddyChange(ctx, func(candidate *model.State) error {
		if candidate.Initialized {
			return errors.New("setup is already complete")
		}
		candidate.Initialized = true
		candidate.Sessions = append(candidate.Sessions, session)
		return nil
	})
}
func (m *Manager) CreateMapping(ctx context.Context, mapping model.Mapping) error {
	return m.caddyChange(ctx, func(candidate *model.State) error {
		for _, existing := range candidate.Mappings {
			if existing.Prefix == mapping.Prefix {
				return errors.New("mapping already exists")
			}
		}
		candidate.Mappings = append(candidate.Mappings, mapping)
		sort.Slice(candidate.Mappings, func(i, j int) bool { return candidate.Mappings[i].Prefix < candidate.Mappings[j].Prefix })
		return nil
	})
}
func (m *Manager) UpdateMapping(ctx context.Context, oldPrefix string, mapping model.Mapping) error {
	return m.caddyChange(ctx, func(candidate *model.State) error {
		found := false
		for i := range candidate.Mappings {
			if candidate.Mappings[i].Prefix == oldPrefix {
				candidate.Mappings[i], found = mapping, true
			} else if candidate.Mappings[i].Prefix == mapping.Prefix {
				return errors.New("mapping already exists")
			}
		}
		if !found {
			return errors.New("mapping not found")
		}
		sort.Slice(candidate.Mappings, func(i, j int) bool { return candidate.Mappings[i].Prefix < candidate.Mappings[j].Prefix })
		return nil
	})
}
func (m *Manager) EnableMapping(ctx context.Context, prefix string, enabled bool) error {
	return m.caddyChange(ctx, func(candidate *model.State) error {
		for i := range candidate.Mappings {
			if candidate.Mappings[i].Prefix == prefix {
				candidate.Mappings[i].Enabled = enabled
				return nil
			}
		}
		return errors.New("mapping not found")
	})
}
func (m *Manager) DeleteMapping(ctx context.Context, prefix string) error {
	return m.caddyChange(ctx, func(candidate *model.State) error {
		kept := candidate.Mappings[:0]
		for _, mapping := range candidate.Mappings {
			if mapping.Prefix != prefix {
				kept = append(kept, mapping)
			}
		}
		if len(kept) == len(candidate.Mappings) {
			return errors.New("mapping not found")
		}
		candidate.Mappings = kept
		return nil
	})
}
func (m *Manager) TestMapping(ctx context.Context, mapping model.Mapping) error {
	if err := model.ValidateMapping(mapping); err != nil {
		return err
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(m.renderer.TargetHost, strconv.Itoa(mapping.Port)))
	if err != nil {
		return errors.New("upstream connection failed")
	}
	return conn.Close()
}
func (m *Manager) caddyChange(ctx context.Context, mutate func(*model.State) error) error {
	return state.ComponentChange(ctx, m.store, m.renderer.Render, m.caddy.Apply, mutate)
}
func (m *Manager) SetPublication(ctx context.Context, enabled bool) error {
	return m.store.Transition(func(current model.State) (model.State, func() error, error) {
		candidate := current
		candidate.Publication = enabled
		if err := candidate.Validate(); err != nil {
			return current, nil, err
		}
		if err := m.tor.WriteConfig(enabled); err != nil {
			return current, nil, err
		}
		if err := m.tor.Validate(ctx); err != nil {
			_ = m.tor.WriteConfig(current.Publication)
			return current, nil, err
		}
		if err := m.control.Reload(ctx); err != nil {
			_ = m.tor.WriteConfig(current.Publication)
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return current, nil, errors.Join(err, m.control.Reload(rollbackCtx))
		}
		rollback := func() error {
			if err := m.tor.WriteConfig(current.Publication); err != nil {
				return err
			}
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return m.control.Reload(rollbackCtx)
		}
		return candidate, rollback, nil
	})
}
func (m *Manager) CreateDevice(ctx context.Context, name string) (model.PendingDevice, string, error) {
	var pending model.PendingDevice
	var credential string
	err := m.store.Transition(func(current model.State) (model.State, func() error, error) {
		if !current.Initialized || current.Pending != nil || len(current.Devices) >= model.MaxDevices {
			return current, nil, errors.New("device cannot be created")
		}
		idRaw := make([]byte, 16)
		if _, err := rand.Read(idRaw); err != nil {
			return current, nil, err
		}
		public, private, err := torkitTor.GenerateClientKey()
		if err != nil {
			return current, nil, err
		}
		now := m.now().UTC()
		pending = model.PendingDevice{Device: model.Device{ID: hex.EncodeToString(idRaw), Name: name, PublicKey: public, CreatedAt: now}, PrivateKey: private, ExpiresAt: now.Add(15 * time.Minute)}
		candidate := current
		candidate.Pending = &pending
		if err = candidate.Validate(); err != nil {
			return current, nil, err
		}
		credential, err = torkitTor.Credential(current.ServiceID, private)
		if err != nil {
			return current, nil, err
		}
		if err = m.tor.WriteAuthorization(pending.ID, public); err == nil {
			err = m.control.Reload(ctx)
		}
		if err != nil {
			_ = m.tor.RemoveAuthorization(pending.ID)
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return current, nil, errors.Join(err, m.control.Reload(rollbackCtx))
		}
		rollback := func() error {
			_ = m.tor.RemoveAuthorization(pending.ID)
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return m.control.Reload(rollbackCtx)
		}
		return candidate, rollback, nil
	})
	return pending, credential, err
}
func (m *Manager) AcknowledgeDevice(id string) error {
	return m.store.Transition(func(current model.State) (model.State, func() error, error) {
		if current.Pending == nil || current.Pending.ID != id || !current.Pending.ExpiresAt.After(m.now()) {
			return current, nil, errors.New("pending device not found")
		}
		device := current.Pending.Device
		device.AcknowledgedAt = m.now().UTC()
		current.Devices = append(current.Devices, device)
		current.Pending = nil
		return current, nil, nil
	})
}
func (m *Manager) RevokeDevice(ctx context.Context, id string) error {
	return m.store.Transition(func(current model.State) (model.State, func() error, error) {
		candidate := state.Clone(current)
		var removed *model.Device
		kept := candidate.Devices[:0]
		for i := range candidate.Devices {
			if candidate.Devices[i].ID == id {
				copy := candidate.Devices[i]
				removed = &copy
			} else {
				kept = append(kept, candidate.Devices[i])
			}
		}
		candidate.Devices = kept
		if removed == nil || candidate.Publication && len(candidate.Devices) == 0 {
			return current, nil, errors.New("device cannot be revoked")
		}
		if err := candidate.Validate(); err != nil {
			return current, nil, err
		}
		if err := m.tor.RemoveAuthorization(id); err != nil {
			return current, nil, err
		}
		if err := m.control.Reload(ctx); err != nil {
			_ = m.tor.WriteAuthorization(id, removed.PublicKey)
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return current, nil, errors.Join(err, m.control.Reload(rollbackCtx))
		}
		rollback := func() error {
			if err := m.tor.WriteAuthorization(id, removed.PublicKey); err != nil {
				return err
			}
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return m.control.Reload(rollbackCtx)
		}
		return candidate, rollback, nil
	})
}
func (m *Manager) ExpirePending(ctx context.Context) error {
	pending := m.store.View().Pending
	if pending == nil || pending.ExpiresAt.After(m.now()) {
		return nil
	}
	return m.store.Transition(func(current model.State) (model.State, func() error, error) {
		if current.Pending == nil || current.Pending.ExpiresAt.After(m.now()) {
			return current, nil, nil
		}
		pending, candidate := *current.Pending, state.Clone(current)
		candidate.Pending = nil
		if err := m.tor.RemoveAuthorization(pending.ID); err != nil {
			return current, nil, err
		}
		if err := m.control.Reload(ctx); err != nil {
			_ = m.tor.WriteAuthorization(pending.ID, pending.PublicKey)
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return current, nil, errors.Join(err, m.control.Reload(rollbackCtx))
		}
		rollback := func() error {
			if err := m.tor.WriteAuthorization(pending.ID, pending.PublicKey); err != nil {
				return err
			}
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return m.control.Reload(rollbackCtx)
		}
		return candidate, rollback, nil
	})
}
func (m *Manager) ReconcileTor(ctx context.Context) error {
	return m.store.Transition(func(current model.State) (model.State, func() error, error) {
		candidate := state.Clone(current)
		if candidate.Pending != nil && !candidate.Pending.ExpiresAt.After(m.now()) {
			candidate.Pending = nil
		}
		if candidate.Bootstrap != nil && !candidate.Bootstrap.ExpiresAt.After(m.now()) {
			candidate.Bootstrap = nil
		}
		apply := func(callCtx context.Context, value model.State) error {
			if err := m.tor.Reconcile(value.Devices, value.Pending); err != nil {
				return err
			}
			return m.control.Reload(callCtx)
		}
		if err := apply(ctx, candidate); err != nil {
			_ = m.tor.Reconcile(current.Devices, current.Pending)
			return current, nil, err
		}
		rollback := func() error {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return apply(rollbackCtx, current)
		}
		return candidate, rollback, nil
	})
}
func (m *Manager) PublicCA(ctx context.Context) ([]byte, error) { return m.caddy.RootCA(ctx) }
func (m *Manager) SetBootstrap(ctx context.Context, window *model.BootstrapWindow) error {
	return m.caddyChange(ctx, func(candidate *model.State) error { candidate.Bootstrap = window; return nil })
}
func StageOwnerReset(store *state.Store) error {
	return store.Transition(func(current model.State) (model.State, func() error, error) {
		if !current.Initialized {
			return current, nil, errors.New("owner is not initialized")
		}
		current.Initialized, current.Publication = false, false
		current.Sessions, current.Tokens = []model.LocalSession{}, []model.AgentToken{}
		current.Pending, current.Bootstrap = nil, nil
		return current, nil, nil
	})
}
