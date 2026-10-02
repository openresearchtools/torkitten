// Copyright 2026 The TorKitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func securityFixture(t *testing.T, authorize http.HandlerFunc) (*App, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "tks-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	a := &App{ctx: context.Background(), root: filepath.Join(dir, "state"), run: filepath.Join(dir, "run"), host: HostState{Version: 2, Enrolled: true, Onion: clientTestOnion, OAuthClient: "epoch-a"}, profiles: map[string]*Profile{}, processes: map[string]*process{}}
	for _, p := range []string{a.root, a.run} {
		if err = privateDir(p); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(dir, "launched")
	a.services = Services{Version: 2, Services: []Service{{ID: "service", Title: "Test", Available: true, Endpoint: Endpoint{Network: "tcp", Address: "127.0.0.1:12345"}, Command: "/usr/bin/touch " + marker}}}
	ln, err := net.Listen("unix", a.socket("authelia"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: authorize}
	go server.Serve(ln)
	t.Cleanup(func() { server.Close() })
	return a, marker
}
func securityActionRequest(body io.Reader) *http.Request {
	r := httptest.NewRequest("POST", "https://"+clientTestOnion+"/api/actions", body)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer authelia_at_old")
	return r
}

type securityGatedBody struct {
	started chan struct{}
	release chan struct{}
	body    io.Reader
	once    sync.Once
}

func (b *securityGatedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return b.body.Read(p)
}
func (b *securityGatedBody) Close() error { return nil }
func waitSecurity(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal(label + " timed out")
	}
}

func TestSecurityActionBodyReadBeforeAuthorization(t *testing.T) {
	entered := make(chan struct{}, 1)
	allowed := atomic.Bool{}
	allowed.Store(true)
	a, marker := securityFixture(t, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		if !allowed.Load() {
			w.WriteHeader(401)
		}
	})
	body := &securityGatedBody{started: make(chan struct{}), release: make(chan struct{}), body: strings.NewReader(`{"id":"service","action":"load"}`)}
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { a.remoteHandler(response, securityActionRequest(body)); close(done) }()
	select {
	case <-body.started:
	case <-entered:
		close(body.release)
		waitSecurity(t, done, "request")
		t.Fatal("authorized a request before its body arrived")
	case <-time.After(3 * time.Second):
		close(body.release)
		t.Fatal("body read did not start")
	}
	allowed.Store(false)
	a.mu.Lock()
	a.host.OAuthClient = "epoch-b"
	a.mu.Unlock()
	close(body.release)
	waitSecurity(t, done, "post-revocation request")
	if response.Code != 401 {
		t.Fatalf("old login accepted after body delay: %d", response.Code)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("old authorization launched a host command")
	}
}

func TestSecurityEpochCheckedAfterAuthorizationResponse(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	a, marker := securityFixture(t, func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.WriteHeader(200) })
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		a.remoteHandler(response, securityActionRequest(strings.NewReader(`{"id":"service","action":"load"}`)))
		close(done)
	}()
	waitSecurity(t, entered, "authorization request")
	a.mu.Lock()
	a.host.OAuthClient = "epoch-b"
	a.mu.Unlock()
	close(release)
	waitSecurity(t, done, "epoch-gated action")
	if response.Code == 200 {
		t.Fatal("old authorization response survived epoch rotation")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("command started after its authorization epoch ended")
	}
}

func TestSecurityAuthorizedActionAndRemoteAdminBoundary(t *testing.T) {
	a, _ := securityFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	for _, path := range []string{"/api/identity", "/api/config", "/api/revoke", "/api/identity-confirm", "/api/qr", "/api/host-action"} {
		r := httptest.NewRequest("POST", "https://"+clientTestOnion+path, strings.NewReader(`{"confirm":true,"username":"attacker"}`))
		r.Header.Set("Authorization", "Bearer authelia_at_owner")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.remoteHandler(w, r)
		if w.Code != 404 {
			t.Fatalf("remote administration route exposed: %s", path)
		}
	}
	if a.host.OAuthClient != "epoch-a" || a.host.Generation != "" {
		t.Fatal("remote request changed host identity")
	}
	r := securityActionRequest(strings.NewReader(`{"id":"service","action":"load","command":["/usr/bin/false"]}`))
	w := httptest.NewRecorder()
	a.remoteHandler(w, r)
	if w.Code != 400 {
		t.Fatal("remote command injection field accepted")
	}
}

func TestSecurityHostOriginAndPrivateSockets(t *testing.T) {
	a, _ := securityFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	for _, pair := range [][2]string{{"evil.example", "torkitten://app"}, {"app", "https://evil.example"}, {"app", ""}, {"127.0.0.1", "torkitten://app"}} {
		r := httptest.NewRequest("GET", "http://"+pair[0]+"/api/state", nil)
		r.Header.Set("Origin", pair[1])
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("invalid Host/Origin accepted")
		}
	}
	r := httptest.NewRequest("GET", "http://app/api/state", nil)
	r.Header.Set("Origin", "torkitten://app")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("trusted native origin rejected")
	}
	for _, path := range []string{a.path("admin.sock"), a.socket("authelia"), a.socket("caddy"), a.socket("remote"), a.socket("socks")} {
		s := Services{Version: 2, Services: []Service{{ID: "bad", Title: "Bad", Command: "/usr/bin/true", Endpoint: Endpoint{Network: "unix", Address: path}}}}
		if err := a.validateServices(s); err == nil {
			t.Fatal("control socket accepted as a user service")
		}
		if err := a.saveServices(s); err == nil {
			t.Fatal("private socket configuration persisted")
		}
	}
	if _, err := os.Stat(a.path("services.json")); !os.IsNotExist(err) {
		t.Fatal("invalid config wrote the service document")
	}
	valid := Services{Version: 2, Services: []Service{{ID: "app", Title: "App", Command: "/usr/bin/true", Endpoint: Endpoint{Network: "unix", Address: filepath.Join(filepath.Dir(a.root), "application.sock")}}}}
	if err := a.validateServices(valid); err != nil {
		t.Fatal("ordinary host Unix service rejected")
	}
	for _, endpoint := range []Endpoint{{"tcp", "example.com:80"}, {"tcp", "8.8.8.8:53"}, {"udp", "127.0.0.1:53"}, {"unix", "relative.sock"}} {
		valid.Services[0].Endpoint = endpoint
		if err := a.validateServices(valid); err == nil {
			t.Fatal("invalid destination accepted")
		}
	}
}

func TestSecurityComponentEnvironmentSanitized(t *testing.T) {
	t.Setenv("AUTHELIA_STORAGE_LOCAL_PATH", "/must-not-use-existing-v1.sqlite")
	t.Setenv("TOR_FAKE_SETTING", "must-not-inherit")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://must-not-contact.example")
	t.Setenv("GODEBUG", "must-not-inherit")
	t.Setenv("TORKITTEN_TEST_SENTINEL", "preserved")
	data, err := runPrivate(t.Context(), "/usr/bin/env", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "AUTHELIA_") && line != "AUTHELIA_TELEMETRY_METRICS_ENABLED=false" {
			t.Fatal("Authelia CLI inherited external configuration")
		}
		for _, prefix := range []string{"TOR_", "OTEL_EXPORTER_", "GODEBUG="} {
			if strings.HasPrefix(line, prefix) {
				t.Fatal("component inherited forbidden configuration")
			}
		}
	}
	if !strings.Contains(string(data), "TORKITTEN_TEST_SENTINEL=preserved") {
		t.Fatal("ordinary environment lost")
	}
}

func TestSecurityProfileActivationDoesNotWaitForAnotherProfileLock(t *testing.T) {
	a, p := clientFixture(t)
	p.activeOnion = p.cache.Bundle.Onion
	candidate := &Profile{app: a, id: strings.Repeat("b", 48), cache: p.cache}
	p.mu.Lock()
	done := make(chan error, 1)
	go func() { a.mu.Lock(); defer a.mu.Unlock(); done <- a.activateProfile(candidate) }()
	select {
	case err := <-done:
		p.mu.Unlock()
		if err == nil {
			t.Fatal("duplicate active onion accepted")
		}
	case <-time.After(time.Second):
		p.mu.Unlock()
		<-done
		t.Fatal("activation waited for another profile mutex while holding App.mu")
	}
}

func TestSecurityShutdownCancelsProfileRequestBeforeLocking(t *testing.T) {
	a, p := clientFixture(t)
	a.ctx, a.cancel = context.WithCancel(context.Background())
	p.cache.Token = clientValidToken()
	entered := make(chan struct{})
	p.HTTP = &http.Client{Transport: clientRoundTrip(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	ln, err := net.Listen("unix", a.path("admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	a.admin = &http.Server{Handler: a.Handler()}
	go a.admin.Serve(ln)
	t.Cleanup(func() { a.admin.Close() })
	client := unixHTTP(a.path("admin.sock"))
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		req, _ := http.NewRequest("GET", "http://app/api/services?id="+p.id, nil)
		req.Header.Set("Origin", "torkitten://app")
		res, _ := client.Do(req)
		if res != nil {
			res.Body.Close()
		}
	}()
	waitSecurity(t, entered, "blocked profile request")
	closed := make(chan struct{})
	go func() { a.Close(); close(closed) }()
	waitSecurity(t, closed, "shutdown")
	waitSecurity(t, requestDone, "cancelled local request")
}

func TestSecurityWatcherRejectsInvalidFilesAndRecovers(t *testing.T) {
	for _, kind := range []string{"fifo", "oversized", "empty"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			a := &App{ctx: ctx, root: dir, run: filepath.Join(dir, "run"), services: Services{Version: 2}, processes: map[string]*process{}}
			path := a.path("services.json")
			switch kind {
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(path, make([]byte, MaxFile+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			stopped := make(chan struct{})
			go func() { a.watchServices(); close(stopped) }()
			// This also releases a regressed os.ReadFile(FIFO), making a failure bounded.
			release := func() {
				if kind == "fifo" {
					if fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
						syscall.Close(fd)
					}
				}
			}
			defer func() { release(); cancel(); waitSecurity(t, stopped, "watcher shutdown") }()
			waitState := func(rejected bool) bool {
				found := make(chan struct{})
				go func() {
					for {
						a.mu.Lock()
						bad := strings.HasPrefix(a.hostError, "services.json rejected:")
						a.mu.Unlock()
						if bad == rejected {
							close(found)
							return
						}
						select {
						case <-ctx.Done():
							return
						case <-time.After(10 * time.Millisecond):
						}
					}
				}()
				select {
				case <-found:
					return true
				case <-time.After(3 * time.Second):
					return false
				}
			}
			if !waitState(true) {
				release()
				t.Fatal("invalid configuration blocked the watcher or was not rejected")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := writeJSON(path, Services{Version: 2, Services: []Service{}}); err != nil {
				t.Fatal(err)
			}
			if !waitState(false) {
				t.Fatal("valid replacement did not recover after rejection")
			}
		})
	}
}
