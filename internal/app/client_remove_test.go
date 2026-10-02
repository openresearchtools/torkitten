// Copyright 2026 The TorKitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestClientRemovalClosesBeforeRevocationAndDeletesState(t *testing.T) {
	a, p := clientFixture(t)
	identityProcess(t, a, "client-tor")
	if err := p.saveToken(clientValidToken()); err != nil {
		t.Fatal(err)
	}
	if err := a.saveProfileIndex(nil); err != nil {
		t.Fatal(err)
	}
	authPath := a.path("client-auth", p.id+".auth_private")
	if err := atomicWrite(authPath, []byte("private authorization")); err != nil {
		t.Fatal(err)
	}
	m := clientMapped(t, p)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	calls := atomic.Int64{}
	p.HTTP = &http.Client{Transport: clientRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/login/api/oidc/revocation" {
			t.Error("remove called an unexpected endpoint")
		}
		calls.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return clientReply(200, ""), nil
	})}
	done := make(chan error, 1)
	go func() { done <- a.RemoveProfile(t.Context(), p.id) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("token revocation timed out")
	}
	listener, err := net.Listen("tcp4", m.Addr().String())
	if err != nil {
		close(release)
		t.Fatal("remove waited for remote revocation before closing listener")
	}
	listener.Close()
	if _, err = p.GetToken(t.Context()); err == nil {
		close(release)
		t.Fatal("removed profile retained credentials")
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("access and refresh credentials were not both revoked")
	}
	for _, path := range []string{authPath, a.path("profiles", p.id+".age")} {
		if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("removed profile retained a private file")
		}
	}
	var index []profileEntry
	if err = readJSON(a.path("profiles", "index.json"), &index); err != nil || len(index) != 0 || len(a.PublicProfiles()) != 0 {
		t.Fatal("removed profile remains indexed")
	}
	if err = p.saveToken(clientValidToken()); err == nil {
		t.Fatal("stale profile reference recreated encrypted credentials")
	}
}

func TestClientRemovalStillErasesWhenGatewayOffline(t *testing.T) {
	a, p := clientFixture(t)
	identityProcess(t, a, "client-tor")
	if err := p.saveToken(clientValidToken()); err != nil {
		t.Fatal(err)
	}
	p.HTTP = &http.Client{Transport: clientRoundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })}
	if err := a.RemoveProfile(t.Context(), p.id); err == nil || !strings.Contains(err.Error(), "revocation could not be confirmed") {
		t.Fatal("unconfirmed revocation was not reported")
	}
	if _, err := os.Stat(a.path("profiles", p.id+".age")); !errors.Is(err, os.ErrNotExist) || len(a.PublicProfiles()) != 0 {
		t.Fatal("offline removal retained the connection")
	}
}

func TestClientSSHKeysOnlyInPrivateRuntimeFiles(t *testing.T) {
	a, p := clientFixture(t)
	p.cache.Token = clientValidToken()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyText := string(pem.EncodeToMemory(private))
	body, _ := json.Marshal(map[string]string{"user": "test-owner", "key": keyText, "host_key": string(ssh.MarshalAuthorizedKey(signer.PublicKey()))})
	p.HTTP = &http.Client{Transport: clientRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/ssh-config" || r.Header.Get("Authorization") != "Bearer "+p.cache.Token.AccessToken {
			t.Error("SSH credentials requested without OAuth")
		}
		return clientReply(200, string(body)), nil
	})}
	if err = p.configureSSH(t.Context(), 43210); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"key", "known_hosts", "config"} {
		st, e := os.Stat(filepath.Join(p.sshDirectory(), name))
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatal("SSH runtime file is not private")
		}
	}
	config, err := os.ReadFile(filepath.Join(p.sshDirectory(), "config"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"HostName 127.0.0.1", "Port 43210", "IdentitiesOnly yes", "StrictHostKeyChecking yes", "PasswordAuthentication no"} {
		if !strings.Contains(string(config), required) {
			t.Fatal("missing strict native SSH setting")
		}
	}
	status, _ := json.Marshal(a.PublicProfiles())
	if strings.Contains(string(status), keyText) || strings.Contains(string(status), "PRIVATE KEY") {
		t.Fatal("public status contains SSH key")
	}
	if err = p.clearAccess(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(p.sshDirectory()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("revocation retained native SSH credentials")
	}
}

func TestClientOwnerIsBoundToEncryptedConnection(t *testing.T) {
	a, p := clientFixture(t)
	p.HTTP = &http.Client{Transport: clientRoundTrip(func(*http.Request) (*http.Response, error) {
		t.Error("mismatched owner reached gateway")
		return nil, errors.New("denied")
	})}
	if _, err := a.LoginProfile(t.Context(), p.id, "different-owner", "password", "123456"); err == nil {
		t.Fatal("different account accepted")
	}
	p.cache.Bundle.Owner = "invalid\nowner"
	if err := p.prepare(); err == nil {
		t.Fatal("malformed owner in encrypted QR accepted")
	}
}

func TestClientCatalogueAllows64ServicesPlusManagedSSH(t *testing.T) {
	a, p := clientFixture(t)
	p.cache.Token = clientValidToken()
	services := []ViewService{{ID: "host-ssh", Title: "Host SSH", SSH: true}}
	for i := range 64 {
		services = append(services, ViewService{ID: fmt.Sprintf("service-%d", i), Title: "Service"})
	}
	p.HTTP = &http.Client{Transport: clientRoundTrip(func(*http.Request) (*http.Response, error) {
		body, _ := json.Marshal(map[string]any{"services": services})
		return clientReply(200, string(body)), nil
	})}
	if list, err := a.ProfileServices(t.Context(), p.id); err != nil || len(list) != 65 {
		t.Fatal("full catalogue with reserved SSH was rejected")
	}
	services[0].SSH = false
	if _, err := a.ProfileServices(t.Context(), p.id); err == nil {
		t.Fatal("reserved SSH identity with inconsistent capability marker accepted")
	}
}
