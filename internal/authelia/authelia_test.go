// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package authelia

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"torkitten/internal/state"
)

func testPaths(root string) Paths {
	return Paths{
		Binary: os.Getenv("TORKITTEN_AUTHELIA_BIN"), Config: filepath.Join(root, "etc", "configuration.yml"),
		Users: filepath.Join(root, "state", "users.yml"), Database: filepath.Join(root, "state", "db.sqlite3"),
		SecretsDir: filepath.Join(root, "state", "secrets"), Socket: filepath.Join(root, "run", "authelia.sock"),
		QR: filepath.Join(root, "run", "totp.png"), Notifications: filepath.Join(root, "state", "notifications.txt"),
	}
}

func TestRenderOwnsPolicyInAuthelia(t *testing.T) {
	p := testPaths(t.TempDir())
	if p.Binary == "" {
		p.Binary = "/usr/bin/authelia"
	}
	id := strings.Repeat("a", 56)
	data, err := p.Render(id)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"path=login", "theme: 'dark'", "authelia_url: 'https://" + id + ".onion/login'", "default_policy: 'deny'", "group:torkitten-owner", "policy: 'two_factor'", "*." + id + ".onion", "implementation: 'ForwardAuth'", "enabled: false", "password_change: { disable: false }", "regulation: { modes: ['user']", "inactivity: '87600h'", "expiration: '87600h'"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(text, "bypass") || strings.Contains(text, "inactivity: '15m'") || strings.Contains(text, "expiration: '8h'") {
		t.Fatal("unexpected bypass or short session expiry")
	}
}

func TestEnsureFilesAndOwner(t *testing.T) {
	p := testPaths(t.TempDir())
	if p.Binary == "" {
		p.Binary = "/usr/bin/authelia"
	}
	if err := p.EnsureFiles(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"session", "storage", "jwt"} {
		info, err := os.Stat(filepath.Join(p.SecretsDir, name))
		if err != nil || info.Mode().Perm() != 0o600 || info.Size() != 64 {
			t.Fatalf("secret %s: %v %v", name, info, err)
		}
	}
	digest := "$argon2id$v=19$m=65536,t=3,p=4$YWJj$ZGVm"
	if err := WriteOwner(p.Users, "owner", digest); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p.Users)
	if strings.Count(string(data), "torkitten-owner") != 1 || strings.Count(string(data), "  owner:") != 1 {
		t.Fatalf("bad users file: %s", data)
	}
}

func TestFactorClientUsesIsolatedUnixCookieJar(t *testing.T) {
	root := t.TempDir()
	socket := filepath.Join(root, "authelia.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 56)
	var logins atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") != "https" || r.Header.Get("X-Forwarded-Host") != id+".onion" {
			http.Error(w, "metadata", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/login/api/firstfactor":
			logins.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Domain: id + ".onion", Path: "/", Secure: true, HttpOnly: true})
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
		case "/login/api/user/info":
			if cookie, _ := r.Cookie("session"); cookie == nil || cookie.Value != "ok" {
				http.Error(w, "cookie", http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"status":"OK","data":{"has_totp":true}}`))
		case "/login/api/secondfactor/totp":
			if _, err := r.Cookie("session"); err != nil {
				http.Error(w, "cookie", http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"status":"OK","data":{"redirect":""}}`))
		case "/login/api/health":
			_, _ = w.Write([]byte(`{"status":"OK"}`))
		default:
			http.NotFound(w, r)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	client, err := NewClient(socket, id)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		flow, flowErr := client.BeginFactors(context.Background(), "owner", []byte("long-enough-password"))
		if flowErr != nil {
			t.Fatal(flowErr)
		}
		if _, flowErr = flow.Complete(context.Background(), "123456"); flowErr != nil {
			t.Fatal(flowErr)
		}
		flow.Destroy()
	}
	if logins.Load() != 2 {
		t.Fatal("verification reused a prior Authelia session")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = client.Healthy(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedConfigurationValidation(t *testing.T) {
	binary := os.Getenv("TORKITTEN_AUTHELIA_BIN")
	if binary == "" {
		t.Skip("set TORKITTEN_AUTHELIA_BIN for pinned integration test")
	}
	p := testPaths(t.TempDir())
	for _, dir := range []string{filepath.Dir(p.Config), filepath.Dir(p.Socket)} {
		if err := state.EnsureDir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.EnsureFiles(); err != nil {
		t.Fatal(err)
	}
	data, err := p.Render(strings.Repeat("a", 56))
	if err != nil {
		t.Fatal(err)
	}
	if err = state.AtomicWrite(p.Config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = (Runner{Paths: p}).Validate(ctx); err != nil {
		t.Fatal(err)
	}
}
