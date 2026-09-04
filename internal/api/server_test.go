// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"torkitten/internal/apitoken"
	"torkitten/internal/authelia"
	"torkitten/internal/bootstrap"
	"torkitten/internal/caddy"
	"torkitten/internal/control"
	"torkitten/internal/localsession"
	"torkitten/internal/model"
	"torkitten/internal/onboarding"
	"torkitten/internal/state"
	"torkitten/internal/supervisor"
	torkitTor "torkitten/internal/tor"
)

type apiCaddy struct{ loads int }

func (c *apiCaddy) Apply(_ context.Context, value []byte) ([]byte, error) {
	c.loads++
	return value, nil
}
func (c *apiCaddy) RootCA(context.Context) ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("certificate")}), nil
}

type setupLifecycle struct{}

func (setupLifecycle) StartAuthelia(context.Context) error { return nil }
func (setupLifecycle) StopAuthelia(context.Context) error  { return nil }

type setupFactors struct{}

func (setupFactors) Verify(context.Context, string, []byte, string) error { return nil }

func apiFixture(t *testing.T) (*Server, *state.Store, string, string) {
	t.Helper()
	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Transition(func(current model.State) (model.State, func() error, error) {
		current.ServiceID, current.Initialized = strings.Repeat("a", 56), true
		return current, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	renderer := caddy.Renderer{AdminSocket: filepath.Join(root, "admin.sock"), OnionTLSSocket: filepath.Join(root, "tls.sock"), OnionHTTPSocket: filepath.Join(root, "http.sock"), AutheliaSocket: filepath.Join(root, "authelia.sock"), LauncherRoot: filepath.Join(root, "launcher"), BootstrapRoot: filepath.Join(root, "bootstrap"), StorageRoot: filepath.Join(root, "storage"), TargetHost: "host.containers.internal"}
	tp := torkitTor.Paths{Binary: "/bin/true", Config: filepath.Join(root, "torrc"), DataDir: filepath.Join(root, "tor-data"), HiddenServiceDir: filepath.Join(root, "hs"), ControlSocket: filepath.Join(root, "tor.sock"), CookieFile: filepath.Join(root, "cookie"), OnionHTTPSocket: renderer.OnionHTTPSocket, OnionTLSSocket: renderer.OnionTLSSocket}
	manager := control.New(store, renderer, &apiCaddy{}, tp)
	sessions := localsession.New(store)
	cookie, csrf, err := sessions.Create("owner")
	if err != nil {
		t.Fatal(err)
	}
	factors, err := authelia.NewClient(renderer.AutheliaSocket, strings.Repeat("a", 56))
	if err != nil {
		t.Fatal(err)
	}
	paths := authelia.Paths{Binary: "/bin/true", Config: filepath.Join(root, "authelia.yml"), Users: filepath.Join(root, "users.yml"), Database: filepath.Join(root, "db.sqlite"), SecretsDir: filepath.Join(root, "secrets"), Socket: renderer.AutheliaSocket, QR: filepath.Join(root, "qr.png"), Notifications: filepath.Join(root, "notifications")}
	setup := bootstrap.New(paths, setupLifecycle{}, setupFactors{}, manager, sessions)
	onboard, err := onboarding.New(manager, factors, renderer.BootstrapRoot)
	if err != nil {
		t.Fatal(err)
	}
	spec := func(name supervisor.Name) supervisor.Spec {
		return supervisor.Spec{Name: name, Path: "/bin/true", Health: func(context.Context) error { return nil }}
	}
	process, err := supervisor.New([]supervisor.Spec{spec(supervisor.Tor), spec(supervisor.Caddy), spec(supervisor.Authelia)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager.SetCredentials(sessions, process)
	server, err := New(Dependencies{Control: manager, Sessions: sessions, Factors: factors, Setup: setup, Tokens: apitoken.New(store), Onboarding: onboard, Supervisor: process})
	if err != nil {
		t.Fatal(err)
	}
	return server, store, cookie, csrf
}

func TestExactHostAndSecurityHeaders(t *testing.T) {
	server, _, cookie, _ := apiFixture(t)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Host = "evil.example"
	request.AddCookie(&http.Cookie{Name: localsession.CookieName, Value: cookie})
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Host = localHost
	request.AddCookie(&http.Cookie{Name: localsession.CookieName, Value: cookie})
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "data:image/png;base64,") || !strings.Contains(response.Body.String(), "Permanent HTTPS onion site") {
		t.Fatalf("dashboard status=%d", response.Code)
	}
}

func TestPendingCredentialDownloadsAsAttachment(t *testing.T) {
	server, store, cookie, _ := apiFixture(t)
	now := time.Now().UTC()
	if err := store.Transition(func(current model.State) (model.State, func() error, error) {
		current.Pending = &model.PendingDevice{Device: model.Device{ID: strings.Repeat("b", 32), Name: "phone", PublicKey: strings.Repeat("a", 52), CreatedAt: now}, PrivateKey: strings.Repeat("c", 52), ExpiresAt: now.Add(time.Minute)}
		return current, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/devices/pending.auth_private", nil)
	request.Host = localHost
	request.AddCookie(&http.Cookie{Name: localsession.CookieName, Value: cookie})
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	want := strings.Repeat("a", 56) + ":descriptor:x25519:" + strings.Repeat("c", 52)
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Disposition"), ".auth_private") || response.Header().Get("Cache-Control") != "no-store" || strings.TrimSpace(response.Body.String()) != want {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/devices/pending.png", nil)
	request.Host = localHost
	request.AddCookie(&http.Cookie{Name: localsession.CookieName, Value: cookie})
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "image/png" || !strings.HasPrefix(response.Body.String(), "\x89PNG") {
		t.Fatalf("QR status=%d headers=%v", response.Code, response.Header())
	}
}

func TestBootstrapOpenReturnsLinkQR(t *testing.T) {
	server, store, cookie, csrf := apiFixture(t)
	now := time.Now().UTC()
	if err := store.Transition(func(current model.State) (model.State, func() error, error) {
		current.Devices = []model.Device{{ID: strings.Repeat("b", 32), Name: "phone", PublicKey: strings.Repeat("a", 52), CreatedAt: now, AcknowledgedAt: now}}
		return current, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/bootstrap/open", strings.NewReader(`{}`))
	request.Host = localHost
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", localOrigin)
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(&http.Cookie{Name: localsession.CookieName, Value: cookie})
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	var value map[string]any
	decodeErr := json.Unmarshal(response.Body.Bytes(), &value)
	qr, _ := value["qr"].(string)
	url, _ := value["url"].(string)
	if decodeErr != nil || response.Code != http.StatusOK || !strings.HasPrefix(qr, "data:image/png;base64,") || !strings.HasPrefix(url, "http://") || store.View().Bootstrap == nil {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestBrowserMutationRequiresOriginAndCSRF(t *testing.T) {
	server, store, cookie, csrf := apiFixture(t)
	body := `{"prefix":"api","port":7777,"protocol":"http"}`
	do := func(origin, token string) int {
		request := httptest.NewRequest(http.MethodPost, "/api/mappings/create", strings.NewReader(body))
		request.Host = localHost
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		request.Header.Set("X-CSRF-Token", token)
		request.AddCookie(&http.Cookie{Name: localsession.CookieName, Value: cookie})
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		return response.Code
	}
	if code := do("http://evil.example", csrf); code != http.StatusForbidden || len(store.View().Mappings) != 0 {
		t.Fatalf("cross-origin code=%d mappings=%v", code, store.View().Mappings)
	}
	if code := do(localOrigin, "wrong"); code != http.StatusForbidden || len(store.View().Mappings) != 0 {
		t.Fatalf("bad CSRF code=%d", code)
	}
	if code := do(localOrigin, csrf); code != http.StatusOK || len(store.View().Mappings) != 1 {
		t.Fatalf("valid code=%d mappings=%v", code, store.View().Mappings)
	}
}

func TestAgentScopeAndStrictJSON(t *testing.T) {
	server, store, _, _ := apiFixture(t)
	tokens := apitoken.New(store)
	value, _, err := tokens.Create("reader", []model.Scope{model.ScopeMappingsRead}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/mappings", nil)
	request.Host = localHost
	request.Header.Set("Authorization", "Bearer "+value)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("read status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/mappings/create", strings.NewReader(`{"prefix":"api","port":7777,"protocol":"http","host":"evil"}`))
	request.Host = localHost
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+value)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || len(store.View().Mappings) != 0 {
		t.Fatal("read-only token mutated mappings")
	}
}

func TestLocalCookieFlags(t *testing.T) {
	response := httptest.NewRecorder()
	setCookie(response, localsession.CookieName, "value", 60)
	cookie := response.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("cookie=%+v", cookie)
	}
}
