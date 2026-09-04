// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"torkitten/internal/caddy"
	"torkitten/internal/model"
	"torkitten/internal/state"
	torkitTor "torkitten/internal/tor"
)

type fakeCaddy struct {
	mu      sync.Mutex
	configs [][]byte
	fail    bool
	hook    func()
}

func (f *fakeCaddy) Apply(_ context.Context, config []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configs = append(f.configs, append([]byte(nil), config...))
	if f.hook != nil {
		f.hook()
		f.hook = nil
	}
	if f.fail {
		return nil, errors.New("rejected")
	}
	return []byte(`{}`), nil
}
func (f *fakeCaddy) RootCA(context.Context) ([]byte, error) { return []byte("ca"), nil }

func controlFixture(t *testing.T) (*Manager, *state.Store, *fakeCaddy, string) {
	t.Helper()
	root := t.TempDir()
	statePath := filepath.Join(root, "state", "state.json")
	store, err := state.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Transition(func(current model.State) (model.State, func() error, error) {
		current.ServiceID = strings.Repeat("a", 56)
		return current, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	renderer := caddy.Renderer{AdminSocket: filepath.Join(root, "run", "admin.sock"), OnionTLSSocket: filepath.Join(root, "run", "tls.sock"), OnionHTTPSocket: filepath.Join(root, "run", "http.sock"), AutheliaSocket: filepath.Join(root, "run", "authelia.sock"), LauncherRoot: filepath.Join(root, "launcher"), BootstrapRoot: filepath.Join(root, "bootstrap"), StorageRoot: filepath.Join(root, "storage"), TargetHost: "host.containers.internal"}
	tp := torkitTor.Paths{Binary: "/bin/true", Config: filepath.Join(root, "etc", "torrc"), DataDir: filepath.Join(root, "tor", "data"), HiddenServiceDir: filepath.Join(root, "tor", "hs"), ControlSocket: filepath.Join(root, "run", "tor.sock"), CookieFile: filepath.Join(root, "run", "cookie"), OnionHTTPSocket: renderer.OnionHTTPSocket, OnionTLSSocket: renderer.OnionTLSSocket}
	if err = tp.Ensure(); err != nil {
		t.Fatal(err)
	}
	fc := &fakeCaddy{}
	return New(store, renderer, fc, tp), store, fc, filepath.Dir(statePath)
}

func validSession() model.LocalSession {
	now := time.Unix(1_800_000_000, 0).UTC()
	return model.LocalSession{ID: strings.Repeat("a", 32), Owner: "owner", TokenHash: strings.Repeat("A", 43), CreatedAt: now, LastUseAt: now, AuthenticatedAt: now, ExpiresAt: now.Add(time.Hour)}
}

func TestInitializeAndMappingTransactions(t *testing.T) {
	manager, store, caddyClient, _ := controlFixture(t)
	if err := manager.Initialize(context.Background(), validSession()); err != nil {
		t.Fatal(err)
	}
	mapping := model.Mapping{Prefix: "api", Port: 7777, Protocol: model.ProtocolHTTP, Enabled: true}
	if err := manager.CreateMapping(context.Background(), mapping); err != nil {
		t.Fatal(err)
	}
	if err := manager.CreateMapping(context.Background(), mapping); err == nil {
		t.Fatal("duplicate mapping accepted")
	}
	mapping.Port = 8888
	if err := manager.UpdateMapping(context.Background(), "api", mapping); err != nil {
		t.Fatal(err)
	}
	if got := store.View(); !got.Initialized || len(got.Sessions) != 1 || len(got.Mappings) != 1 || got.Mappings[0].Port != 8888 {
		t.Fatalf("state=%+v", got)
	}
	if len(caddyClient.configs) != 3 {
		t.Fatalf("loads=%d", len(caddyClient.configs))
	}
}

func TestCaddyRejectionKeepsDurableState(t *testing.T) {
	manager, store, caddyClient, _ := controlFixture(t)
	if err := manager.Initialize(context.Background(), validSession()); err != nil {
		t.Fatal(err)
	}
	caddyClient.fail = true
	err := manager.CreateMapping(context.Background(), model.Mapping{Prefix: "api", Port: 7777, Protocol: model.ProtocolHTTP})
	if err == nil || len(store.View().Mappings) != 0 || len(caddyClient.configs) != 3 {
		t.Fatalf("err=%v state=%+v loads=%d", err, store.View(), len(caddyClient.configs))
	}
	if string(caddyClient.configs[0]) != string(caddyClient.configs[2]) {
		t.Fatal("prior configuration was not retried")
	}
}

func TestPersistenceFailureReloadsPriorCaddyState(t *testing.T) {
	manager, store, caddyClient, stateDir := controlFixture(t)
	if err := manager.Initialize(context.Background(), validSession()); err != nil {
		t.Fatal(err)
	}
	caddyClient.hook = func() { _ = os.RemoveAll(stateDir) }
	err := manager.CreateMapping(context.Background(), model.Mapping{Prefix: "api", Port: 7777, Protocol: model.ProtocolHTTP})
	if err == nil || len(store.View().Mappings) != 0 {
		t.Fatalf("err=%v state=%+v", err, store.View())
	}
	if len(caddyClient.configs) != 3 || string(caddyClient.configs[0]) != string(caddyClient.configs[2]) {
		t.Fatal("prior Caddy configuration was not restored")
	}
}

func TestOwnerResetDisablesPublicationAndRevokesAuthority(t *testing.T) {
	_, store, _, _ := controlFixture(t)
	if err := store.Transition(func(current model.State) (model.State, func() error, error) {
		now := time.Now().UTC()
		current.Initialized, current.Publication = true, true
		current.Devices = []model.Device{{ID: strings.Repeat("b", 32), Name: "phone", PublicKey: strings.Repeat("a", 52), CreatedAt: now, AcknowledgedAt: now}}
		current.Sessions = []model.LocalSession{validSession()}
		current.Tokens = []model.AgentToken{{ID: strings.Repeat("c", 32), Name: "agent", TokenHash: strings.Repeat("A", 43), Scopes: []model.Scope{model.ScopeMappingsRead}, CreatedAt: now}}
		return current, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := StageOwnerReset(store); err != nil {
		t.Fatal(err)
	}
	current := store.View()
	if current.Initialized || current.Publication || len(current.Sessions) != 0 || len(current.Tokens) != 0 || len(current.Devices) != 1 {
		t.Fatalf("reset state=%+v", current)
	}
}

func TestPendingDeviceExpiresAndReloadsTor(t *testing.T) {
	manager, store, _, _ := controlFixture(t)
	if err := manager.Initialize(context.Background(), validSession()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	pending := &model.PendingDevice{Device: model.Device{ID: strings.Repeat("b", 32), Name: "phone", PublicKey: strings.Repeat("a", 52), CreatedAt: now.Add(-time.Hour)}, PrivateKey: strings.Repeat("c", 52), ExpiresAt: now.Add(-time.Minute)}
	if err := store.Transition(func(current model.State) (model.State, func() error, error) {
		current.Pending = pending
		return current, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.tor.WriteAuthorization(pending.ID, pending.PublicKey); err != nil {
		t.Fatal(err)
	}
	serveTorControl(t, manager.control.Socket, manager.control.Cookie)
	if err := manager.ExpirePending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.View().Pending != nil {
		t.Fatal("expired private credential persisted")
	}
	if _, err := os.Stat(filepath.Join(manager.tor.HiddenServiceDir, "authorized_clients", pending.ID+".auth")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("authorization remains: %v", err)
	}
}

func TestPublicationRequiresDeviceAndReloadsTor(t *testing.T) {
	manager, store, _, _ := controlFixture(t)
	if err := manager.Initialize(context.Background(), validSession()); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetPublication(context.Background(), true); err == nil {
		t.Fatal("publication without a device succeeded")
	}
	now := time.Now().UTC()
	if err := store.Transition(func(current model.State) (model.State, func() error, error) {
		current.Devices = append(current.Devices, model.Device{ID: strings.Repeat("b", 32), Name: "phone", PublicKey: strings.Repeat("a", 52), CreatedAt: now, AcknowledgedAt: now})
		return current, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	serveTorControl(t, manager.control.Socket, manager.control.Cookie)
	if err := manager.SetPublication(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	config, _ := os.ReadFile(manager.tor.Config)
	if !store.View().Publication || !strings.Contains(string(config), "DisableNetwork 0") {
		t.Fatal("publication intent not persisted or Tor remained disabled")
	}
}

type fakeRotation struct {
	rollback, finish, bounded bool
	hook                      func()
}

func (f *fakeRotation) Apply(ctx context.Context, current model.State) (model.State, []caddy.RotatedCredential, func() error, func(), error) {
	_, f.bounded = ctx.Deadline()
	current.ServiceID = strings.Repeat("b", 56)
	current.Devices[0].PublicKey = strings.Repeat("c", 52)
	if f.hook != nil {
		f.hook()
	}
	return current, []caddy.RotatedCredential{{DeviceID: current.Devices[0].ID, Name: current.Devices[0].Name, Credential: "replacement"}}, func() error { f.rollback = true; return nil }, func() { f.finish = true }, nil
}

func TestIdentityRotationCommitsAndRevokesLocalSessions(t *testing.T) {
	manager, store, _, _ := controlFixture(t)
	if err := manager.Initialize(context.Background(), validSession()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.Transition(func(s model.State) (model.State, func() error, error) {
		s.Devices = []model.Device{{ID: strings.Repeat("b", 32), Name: "phone", PublicKey: strings.Repeat("a", 52), CreatedAt: now, AcknowledgedAt: now}}
		return s, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRotation{}
	manager.SetIdentityRuntime(runtime)
	credentials, err := manager.RotateIdentity(context.Background(), "ROTATE")
	if err != nil || len(credentials) != 1 || store.View().ServiceID != strings.Repeat("b", 56) || len(store.View().Sessions) != 0 || runtime.rollback || !runtime.finish || !runtime.bounded {
		t.Fatalf("credentials=%v state=%+v runtime=%+v err=%v", credentials, store.View(), runtime, err)
	}
}

func TestIdentityRotationPersistenceFailureRollsBack(t *testing.T) {
	manager, store, _, stateDir := controlFixture(t)
	if err := manager.Initialize(context.Background(), validSession()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.Transition(func(s model.State) (model.State, func() error, error) {
		s.Devices = []model.Device{{ID: strings.Repeat("b", 32), Name: "phone", PublicKey: strings.Repeat("a", 52), CreatedAt: now, AcknowledgedAt: now}}
		return s, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRotation{hook: func() { _ = os.RemoveAll(stateDir) }}
	manager.SetIdentityRuntime(runtime)
	if _, err := manager.RotateIdentity(context.Background(), "ROTATE"); err == nil || !runtime.rollback || runtime.finish || store.View().ServiceID != strings.Repeat("a", 56) {
		t.Fatalf("state=%+v runtime=%+v err=%v", store.View(), runtime, err)
	}
}

func TestUncertainTorReloadRestoresStoppedPublication(t *testing.T) {
	manager, store, _, _ := controlFixture(t)
	if err := manager.Initialize(context.Background(), validSession()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.Transition(func(current model.State) (model.State, func() error, error) {
		current.Devices = []model.Device{{ID: strings.Repeat("b", 32), Name: "phone", PublicKey: strings.Repeat("a", 52), CreatedAt: now, AcknowledgedAt: now}}
		return current, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	serveTorReloads(t, manager.control.Socket, manager.control.Cookie, "551 uncertain", "250 OK")
	if err := manager.SetPublication(context.Background(), true); err == nil {
		t.Fatal("uncertain reload succeeded")
	}
	config, _ := os.ReadFile(manager.tor.Config)
	if store.View().Publication || !strings.Contains(string(config), "DisableNetwork 1") || !strings.Contains(string(config), "PublishHidServDescriptors 0") {
		t.Fatal("publication was not restored")
	}
}

func serveTorControl(t *testing.T, socket, cookie string) {
	serveTorReloads(t, socket, cookie, "250 OK")
}
func serveTorReloads(t *testing.T, socket, cookie string, responses ...string) {
	t.Helper()
	if err := os.WriteFile(cookie, []byte(strings.Repeat("c", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer listener.Close()
		for _, response := range responses {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			r := bufio.NewReader(conn)
			_, _ = r.ReadString('\n')
			_, _ = conn.Write([]byte("250 OK\r\n"))
			_, _ = r.ReadString('\n')
			_, _ = conn.Write([]byte(response + "\r\n"))
			conn.Close()
		}
	}()
}
