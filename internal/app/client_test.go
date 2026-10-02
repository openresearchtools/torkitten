// Copyright 2026 The TorKitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"torkitten/internal/oauth"
	"torkitten/internal/tunnel"
)

const clientTestOnion = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
const clientTestPassword = "profile-test-password"

type clientRoundTrip func(*http.Request) (*http.Response, error)

func (f clientRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func clientReply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}
func clientFixture(t *testing.T) (*App, *Profile) {
	t.Helper()
	dir, err := os.MkdirTemp("", "tkc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	a := &App{ctx: context.Background(), root: dir, run: dir, profiles: map[string]*Profile{}, processes: map[string]*process{}}
	for _, name := range []string{"profiles", "client-auth"} {
		if err = privateDir(a.path(name)); err != nil {
			t.Fatal(err)
		}
	}
	_, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test private CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	_, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "device"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, leaf, deviceKey.Public(), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(deviceKey)
	b := Bundle{Version: 2, ID: strings.Repeat("a", 48), Name: "Test gateway", Onion: clientTestOnion, TorPrivate: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(make([]byte, 32)), RootCA: string(rootPEM), Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})), PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), Fingerprint: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	p := &Profile{app: a, id: b.ID, name: b.Name, password: clientTestPassword, cache: encryptedProfile{Version: 2, Bundle: b}, mappings: map[string]*tunnel.Mapping{}}
	if err = p.prepare(); err != nil {
		t.Fatal(err)
	}
	a.profiles[p.id] = p
	t.Cleanup(func() { p.Close() })
	return a, p
}
func clientValidToken() oauth.Token {
	return oauth.Token{Issuer: "https://" + clientTestOnion + "/login", ClientID: "native-test", AccessToken: "authelia_at_private", RefreshToken: "authelia_rt_private", ExpiresAt: time.Now().Add(time.Hour)}
}

func TestClientEncryptedCacheAndLockedStartup(t *testing.T) {
	a, p := clientFixture(t)
	if err := p.saveToken(clientValidToken()); err != nil {
		t.Fatal(err)
	}
	if err := a.saveProfileIndex(nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(a.path("profiles", p.id+".age"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{p.cache.Bundle.PrivateKey, p.cache.Token.AccessToken, p.cache.Token.RefreshToken, clientTestPassword, p.cache.Bundle.Onion} {
		if strings.Contains(string(data), secret) {
			t.Fatal("plaintext in encrypted profile")
		}
	}
	var decoded encryptedProfile
	if err = decrypt(data, clientTestPassword, &decoded); err != nil || decoded.Token.AccessToken != p.cache.Token.AccessToken {
		t.Fatal("encrypted cache roundtrip failed")
	}
	if err = atomicWrite(a.path("client-auth", p.id+".auth_private"), []byte("stale private auth")); err != nil {
		t.Fatal(err)
	}
	another := &App{ctx: a.ctx, root: a.root, run: a.run, profiles: map[string]*Profile{}}
	if err = another.loadProfiles(); err != nil {
		t.Fatal(err)
	}
	loaded := another.profiles[p.id]
	if loaded == nil || loaded.HTTP != nil || loaded.password != "" || loaded.cache.Bundle.PrivateKey != "" {
		t.Fatal("startup unlocked a cached profile")
	}
	if _, err = os.Stat(a.path("client-auth", p.id+".auth_private")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale Tor credential survived locked startup")
	}
	if err = another.UnlockProfile(t.Context(), p.id, "incorrect password"); err == nil || loaded.HTTP != nil {
		t.Fatal("incorrect password unlocked profile")
	}
	st, _ := os.Stat(a.path("profiles", p.id+".age"))
	if st.Mode().Perm() != 0600 {
		t.Fatal("cache permissions")
	}
	public := another.PublicProfiles()
	if len(public) != 1 || !public[0].Locked || public[0].Authenticated {
		t.Fatal("locked public profile state")
	}
}

func TestClientRejectInvalidBundleAndCache(t *testing.T) {
	a, p := clientFixture(t)
	original := p.cache
	for name, change := range map[string]func(*encryptedProfile){
		"version":      func(c *encryptedProfile) { c.Bundle.Version = 1 },
		"path id":      func(c *encryptedProfile) { c.Bundle.ID = "../../escape" },
		"onion":        func(c *encryptedProfile) { c.Bundle.Onion = "example.com" },
		"tor key":      func(c *encryptedProfile) { c.Bundle.TorPrivate = "invalid" },
		"fingerprint":  func(c *encryptedProfile) { c.Bundle.Fingerprint = "invalid" },
		"root":         func(c *encryptedProfile) { c.Bundle.RootCA = c.Bundle.Certificate },
		"mismatch key": func(c *encryptedProfile) { c.Bundle.PrivateKey = "invalid" },
		"token issuer": func(c *encryptedProfile) {
			c.Token = clientValidToken()
			c.Token.Issuer = "https://other.example/login"
		},
		"token newline": func(c *encryptedProfile) { c.Token = clientValidToken(); c.Token.AccessToken += "\r\nInjected: value" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := original
			change(&copy)
			bad := &Profile{app: a, cache: copy}
			if err := bad.prepare(); err == nil {
				t.Fatal("invalid bundle accepted")
			}
		})
	}
	data, err := encrypt(original.Bundle, clientTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir(a.path("profiles"))
	if _, err = a.ImportBundle(t.Context(), data, "wrong password", ""); err == nil {
		t.Fatal("wrong-password import accepted")
	}
	after, _ := os.ReadDir(a.path("profiles"))
	if len(before) != len(after) {
		t.Fatal("invalid import modified profiles")
	}
	if err = os.WriteFile(a.path("profiles", "bad.age"), []byte("invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readPrivate(a.path("profiles", "bad.age")); err == nil {
		t.Fatal("permissive private file accepted")
	}
}

func TestClientStrictOriginAndNoFallback(t *testing.T) {
	_, p := clientFixture(t)
	if p.tls.InsecureSkipVerify || p.tls.MinVersion != tls.VersionTLS13 || p.tls.ServerName != clientTestOnion || len(p.tls.RootCAs.Subjects()) != 1 {
		t.Fatal("incorrect TLS trust boundary")
	}
	for _, uri := range []string{"http://" + clientTestOnion, "https://example.com", "https://127.0.0.1", "https://" + clientTestOnion + ":444", "https://user@" + clientTestOnion} {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", uri, nil)
		if _, err := p.HTTP.Do(req); err == nil {
			t.Fatal("unexpected origin accepted")
		}
	}
	// The only legal destination still fails at the missing private SOCKS socket.
	req, _ := http.NewRequestWithContext(t.Context(), "GET", "https://"+clientTestOnion+"/api/info", nil)
	if _, err := p.HTTP.Do(req); err == nil {
		t.Fatal("direct-network fallback")
	}
	if err := p.HTTP.CheckRedirect(req, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatal("redirect fallback")
	}
}

func TestClientRefreshSerializedAndPersisted(t *testing.T) {
	a, p := clientFixture(t)
	p.cache.Token = clientValidToken()
	p.cache.Token.ExpiresAt = time.Now().Add(-time.Second)
	calls := atomic.Int64{}
	p.HTTP = &http.Client{Transport: clientRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Path != "/login/api/oidc/token" {
			t.Fatal("unexpected request")
		}
		return clientReply(200, `{"access_token":"authelia_at_new","refresh_token":"authelia_rt_new","token_type":"Bearer","expires_in":3600}`), nil
	})}
	var group sync.WaitGroup
	for range 6 {
		group.Go(func() {
			token, err := p.GetToken(t.Context())
			if err != nil || token != "authelia_at_new" {
				t.Errorf("concurrent refresh failed: %v", err)
			}
		})
	}
	group.Wait()
	if calls.Load() != 1 {
		t.Fatal("refresh was not serialized")
	}
	data, err := readPrivate(a.path("profiles", p.id+".age"))
	if err != nil {
		t.Fatal(err)
	}
	var saved encryptedProfile
	if err = decrypt(data, clientTestPassword, &saved); err != nil || saved.Token.RefreshToken != "authelia_rt_new" {
		t.Fatal("rotated token not persisted")
	}
}

func clientMapped(t *testing.T, p *Profile) *tunnel.Mapping {
	t.Helper()
	m, err := tunnel.Map(context.Background(), tunnel.ClientConfig{OnionURL: "https://" + p.cache.Bundle.Onion, SOCKSNetwork: "unix", SOCKSAddress: p.app.socket("socks"), TLS: p.tls, Fingerprint: p.cache.Bundle.Fingerprint, AccessToken: p.GetToken}, "echo", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	p.mappings["echo"] = m
	return m
}
func TestClientUnauthorizedClosesMapsAndClearsDiskToken(t *testing.T) {
	a, p := clientFixture(t)
	p.cache.Token = clientValidToken()
	m := clientMapped(t, p)
	p.HTTP = &http.Client{Transport: clientRoundTrip(func(*http.Request) (*http.Response, error) {
		return clientReply(401, `private error never surfaced`), nil
	})}
	if _, err := a.ProfileServices(t.Context(), p.id); !errors.Is(err, oauth.ErrLoginRequired) {
		t.Fatal("401 did not require login")
	}
	if len(p.mappings) != 0 || p.cache.Token.AccessToken != "" {
		t.Fatal("401 retained access")
	}
	listener, err := net.Listen("tcp4", m.Addr().String())
	if err != nil {
		t.Fatal("mapping listener survived 401")
	}
	listener.Close()
	data, _ := readPrivate(a.path("profiles", p.id+".age"))
	var saved encryptedProfile
	if err = decrypt(data, clientTestPassword, &saved); err != nil || saved.Token.AccessToken != "" {
		t.Fatal("revoked token remained in encrypted cache")
	}
}
func TestClientCatalogueUpdatesOnlyAffectedMappings(t *testing.T) {
	a, p := clientFixture(t)
	p.cache.Token = clientValidToken()
	m := clientMapped(t, p)
	response := `{"services":[{"id":"echo","title":"Echo","ssh":false,"actions":["load"],"reachable":true}]}`
	p.HTTP = &http.Client{Transport: clientRoundTrip(func(*http.Request) (*http.Response, error) { return clientReply(200, response), nil })}
	services, err := a.ProfileServices(t.Context(), p.id)
	if err != nil || len(services) != 1 || !services[0].Mapped || services[0].Port == 0 {
		t.Fatal("unchanged service mapping lost")
	}
	if l, err := net.Listen("tcp4", m.Addr().String()); err == nil {
		l.Close()
		t.Fatal("unchanged mapping closed")
	}
	response = `{"services":[{"id":"echo","title":"Echo","ssh":false,"actions":["load"],"reachable":false}]}`
	services, err = a.ProfileServices(t.Context(), p.id)
	if err != nil || !services[0].Mapped {
		t.Fatal("transient probe failure closed an authorized mapping")
	}
	if _, err = a.MapProfile(t.Context(), p.id, "echo", false, 0); err != nil {
		t.Fatal(err)
	}
	port, err := a.MapProfile(t.Context(), p.id, "echo", true, 0)
	if err != nil || port == 0 {
		t.Fatal("stopped authorized service could not be mapped")
	}
	response = `{"services":[]}`
	if _, err = a.ProfileServices(t.Context(), p.id); err != nil || len(p.mappings) != 0 {
		t.Fatal("removed service retained mapping")
	}
	if p.cache.Token.AccessToken == "" {
		t.Fatal("ordinary service update forced logout")
	}
}
func TestClientProfileIndexTraversalRejected(t *testing.T) {
	a, _ := clientFixture(t)
	if err := writeJSON(a.path("profiles", "index.json"), []profileEntry{{ID: "../else", Name: "invalid"}}); err != nil {
		t.Fatal(err)
	}
	a.profiles = map[string]*Profile{}
	if err := a.loadProfiles(); err == nil {
		t.Fatal("unsafe profile index accepted")
	}
	if _, err := os.Stat(filepath.Join(a.root, "else.age")); err == nil {
		t.Fatal("profile path escaped")
	}
}
