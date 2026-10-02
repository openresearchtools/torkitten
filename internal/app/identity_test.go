// Copyright 2026 The TorKitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func identityProcess(t *testing.T, a *App, name string) *process {
	t.Helper()
	marker := a.path(name + ".ready")
	p, err := startProcess(a.ctx, "/bin/sh", a.path(name+".log"), "-c", `trap '' HUP; : > "$1"; exec /bin/sleep 30`, "fixture", marker)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.stop)
	if err = waitReady(t.Context(), p, func() error { _, e := os.Stat(marker); return e }); err != nil {
		t.Fatal(err)
	}
	a.processes[name] = p
	return p
}

func TestIdentityResetClosesOldAccessBeforeGenerationFailure(t *testing.T) {
	a, _ := clientFixture(t)
	a.bin = a.path("missing-binaries")
	a.host = HostState{Version: 2, Generation: "identity-" + randomID(), Initialized: true, Enrolled: true, Owner: "oldowner", Onion: clientTestOnion, OAuthClient: "torkitten-" + randomID()}
	old := a.gen()
	if err := privateDir(old); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(filepath.Join(old, "secret"), []byte("obsolete-identity")); err != nil {
		t.Fatal(err)
	}
	services := []byte(`{"version":2,"services":[]}`)
	if err := atomicWrite(a.path("services.json"), services); err != nil {
		t.Fatal(err)
	}
	p := identityProcess(t, a, "tor")
	if _, err := a.issueIdentity(t.Context(), "short"); err == nil || !p.alive() || a.gen() != old {
		t.Fatal("invalid password changed the active identity")
	}
	if _, err := a.issueIdentity(t.Context(), "new-QR-password"); err == nil {
		t.Fatal("missing upstream binary accepted")
	}
	if p.alive() || a.host.Initialized || a.host.Enrolled || a.hostError == "" {
		t.Fatal("failed reset retained old access")
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old identity retained after reset")
	}
	var disk HostState
	if err := readJSON(a.path("host.json"), &disk); err != nil || disk.Initialized || disk.Enrolled {
		t.Fatal("failed setup did not remain closed on disk")
	}
	data, _ := os.ReadFile(a.path("services.json"))
	if !bytes.Equal(data, services) {
		t.Fatal("identity reset altered services")
	}
}

func TestIdentityRequiresUpstreamTwoFactorBeforePublication(t *testing.T) {
	a, _ := clientFixture(t)
	a.host = HostState{Version: 2, Generation: "identity-" + randomID(), Initialized: true, Owner: "owner-test", Onion: clientTestOnion, OAuthClient: "torkitten-" + randomID()}
	if err := privateDir(a.gen()); err != nil {
		t.Fatal(err)
	}
	q := []byte("encrypted-QR-PNG-fixture")
	if err := atomicWrite(a.gen("connection.png"), q); err != nil {
		t.Fatal(err)
	}
	password := []byte("generated-owner-password")
	a.pendingSetup = &pendingSetup{password: password, deadline: time.Now().Add(time.Minute)}
	a.host.Devices = []Device{{ID: randomID()}}
	oldTor := identityProcess(t, a, "tor")
	a.bin = a.path("bin")
	if err := privateDir(a.bin); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.bin, "tor"), []byte("#!/bin/sh\nexec /bin/sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(a.gen("onion")); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(a.gen("onion", "hostname"), []byte(clientTestOnion+"\n")); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", a.socket("authelia"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") != "https" || r.Host != clientTestOnion {
			t.Error("private verification lost secure virtual origin")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/login/api/firstfactor":
			var request struct {
				Username, Password string
				KeepMeLoggedIn     bool
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Username != a.host.Owner || request.Password != string(password) {
				t.Error("upstream did not receive generated owner credentials")
			}
			http.SetCookie(w, &http.Cookie{Name: "setup", Value: "private", Secure: true, HttpOnly: true, Path: "/login"})
		case "/login/api/user/info", "/login/api/secondfactor/totp":
			if cookie, e := r.Cookie("setup"); e != nil || cookie.Value != "private" {
				t.Error("secure native verification cookie missing")
			}
			if strings.HasSuffix(r.URL.Path, "totp") {
				var request struct{ Token string }
				_ = json.NewDecoder(r.Body).Decode(&request)
				if request.Token != "123456" {
					w.WriteHeader(401)
					return
				}
			}
		default:
			t.Error("setup attempted OAuth authorization/token issuance")
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"status":"OK","data":{"has_totp":true}}`))
	})}
	go server.Serve(ln)
	t.Cleanup(func() { server.Close() })
	if !strings.Contains(a.torServerConfig(), "PublishHidServDescriptors 0") {
		t.Fatal("unconfirmed identity publishes onion")
	}
	if _, err = a.ConfirmIdentity(t.Context(), "000000"); err == nil || a.host.Enrolled || a.pendingSetup == nil {
		t.Fatal("incorrect factor published identity or discarded retry")
	}
	result, err := a.ConfirmIdentity(t.Context(), "123456")
	if err != nil {
		t.Fatal(err)
	}
	if result["qr"] != base64.StdEncoding.EncodeToString(q) || len(result) != 1 || !a.host.Enrolled || a.pendingSetup != nil {
		t.Fatal("confirmed setup did not return only encrypted QR")
	}
	if oldTor.alive() || a.processes["tor"] == oldTor || !a.processes["tor"].alive() {
		t.Fatal("confirmed setup did not restart Tor to reset unpublished descriptor scheduling")
	}
	t.Cleanup(a.processes["tor"].stop)
	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("generated password retained after confirmation")
	}
	if !strings.Contains(a.torServerConfig(), "PublishHidServDescriptors 1") {
		t.Fatal("confirmed identity remained unpublished")
	}
	if _, err = a.ConfirmIdentity(context.Background(), "123456"); err == nil {
		t.Fatal("confirmation replay accepted")
	}
}

func TestIdentityExpiredSetupErasesPasswordAndStaysClosed(t *testing.T) {
	a, _ := clientFixture(t)
	password := []byte("temporary-owner-password")
	a.host.Initialized = true
	a.pendingSetup = &pendingSetup{password: password, deadline: time.Now().Add(-time.Second)}
	if _, err := a.ConfirmIdentity(t.Context(), "123456"); err == nil || a.host.Enrolled || a.pendingSetup != nil {
		t.Fatal("expired setup was not rejected and erased")
	}
	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("expired setup retained its password")
	}
}
