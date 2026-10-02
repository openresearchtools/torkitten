// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	"torkitten/internal/oauth"
	"torkitten/internal/tunnel"
)

var profileID = regexp.MustCompile(`^[a-f0-9]{48}$`)

type encryptedProfile struct {
	Version int         `json:"version"`
	Bundle  Bundle      `json:"bundle"`
	Token   oauth.Token `json:"token"`
}
type profileEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type ProfileStatus struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Onion         string `json:"onion,omitempty"`
	Locked        bool   `json:"locked"`
	Authenticated bool   `json:"authenticated"`
	Error         string `json:"error,omitempty"`
}
type ClientService struct {
	ViewService
	Mapped bool   `json:"mapped"`
	Port   int    `json:"port"`
	Error  string `json:"error,omitempty"`
}
type Profile struct {
	mu                 sync.Mutex
	app                *App
	id, name, password string
	activeOnion        string // Assigned once on activation; protected by App.mu, never Profile.mu.
	cache              encryptedProfile
	HTTP               *http.Client
	tls                *tls.Config
	oauth              *oauth.Client
	pending            *oauth.Consent
	mappings           map[string]*tunnel.Mapping
	lastError          string
}

func validProfileName(s string) bool {
	return len(s) > 0 && len(s) <= 80 && !strings.ContainsAny(s, "\x00\r\n")
}
func (a *App) loadProfiles() error {
	entries, err := os.ReadDir(a.path("client-auth"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".auth_private") {
			if err = os.Remove(a.path("client-auth", entry.Name())); err != nil {
				return err
			}
		}
	}
	var index []profileEntry
	if err = readJSON(a.path("profiles", "index.json"), &index); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if len(index) > 64 {
		return errors.New("too many connection profiles")
	}
	for _, entry := range index {
		if !profileID.MatchString(entry.ID) || !validProfileName(entry.Name) || a.profiles[entry.ID] != nil {
			return errors.New("invalid connection profile index")
		}
		if _, err = readPrivate(a.path("profiles", entry.ID+".age")); err != nil {
			return err
		}
		a.profiles[entry.ID] = &Profile{app: a, id: entry.ID, name: entry.Name, mappings: map[string]*tunnel.Mapping{}}
	}
	return nil
}
func readPrivate(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > MaxFile {
		return nil, errors.New("unsafe private profile file")
	}
	return os.ReadFile(path)
}
func (a *App) profile(id string) (*Profile, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.profiles[id]
	if p == nil {
		return nil, errors.New("connection profile not found")
	}
	return p, nil
}
func (a *App) saveProfileIndex(extra *Profile) error {
	entries := make([]profileEntry, 0, len(a.profiles)+1)
	for _, p := range a.profiles {
		entries = append(entries, profileEntry{p.id, p.name})
	}
	if extra != nil {
		entries = append(entries, profileEntry{extra.id, extra.name})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return writeJSON(a.path("profiles", "index.json"), entries)
}
func (a *App) ImportBundle(ctx context.Context, data []byte, password, name string) (string, error) {
	if len(password) < 12 || len(password) > 256 {
		return "", errors.New("invalid file password length")
	}
	var bundle Bundle
	if err := decrypt(data, password, &bundle); err != nil {
		return "", err
	}
	if name != "" {
		bundle.Name = name
	}
	p := &Profile{app: a, id: bundle.ID, name: bundle.Name, password: password, cache: encryptedProfile{Version: 2, Bundle: bundle}, mappings: map[string]*tunnel.Mapping{}}
	if err := p.prepare(); err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(a.profiles) >= 64 || a.profiles[p.id] != nil {
		return "", errors.New("profile already imported or profile limit reached")
	}
	if err := p.saveToken(oauth.Token{}); err != nil {
		return "", err
	}
	if err := a.activateProfile(p); err != nil {
		os.Remove(a.path("profiles", p.id+".age"))
		return "", err
	}
	if err := a.saveProfileIndex(p); err != nil {
		os.Remove(a.path("profiles", p.id+".age"))
		os.Remove(a.path("client-auth", p.id+".auth_private"))
		_ = a.processes["client-tor"].reload()
		return "", err
	}
	a.profiles[p.id] = p
	return p.id, nil
}
func (a *App) activateProfile(p *Profile) error {
	for _, other := range a.profiles {
		if other == p {
			continue
		}
		if other.activeOnion == p.cache.Bundle.Onion {
			return errors.New("this onion already has an unlocked connection profile")
		}
	}
	path := a.path("client-auth", p.id+".auth_private")
	text := strings.TrimSuffix(p.cache.Bundle.Onion, ".onion") + ":descriptor:x25519:" + p.cache.Bundle.TorPrivate + "\n"
	if err := atomicWrite(path, []byte(text)); err != nil {
		return err
	}
	if err := a.processes["client-tor"].reload(); err != nil {
		os.Remove(path)
		return err
	}
	p.activeOnion = p.cache.Bundle.Onion
	return nil
}
func (a *App) UnlockProfile(ctx context.Context, id, password string) error {
	if len(password) < 12 || len(password) > 256 {
		return errors.New("invalid file password length")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.profiles[id]
	if p == nil {
		return errors.New("connection profile not found")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.HTTP != nil {
		return errors.New("profile is already unlocked")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := readPrivate(a.path("profiles", id+".age"))
	if err != nil {
		return err
	}
	var cache encryptedProfile
	if err = decrypt(data, password, &cache); err != nil {
		return err
	}
	if cache.Version != 2 || cache.Bundle.ID != id || cache.Bundle.Name != p.name {
		return errors.New("encrypted profile identity mismatch")
	}
	p.cache, p.password = cache, password
	if err = p.prepare(); err == nil {
		err = a.activateProfile(p)
	}
	if err != nil {
		p.cache = encryptedProfile{}
		p.password = ""
		p.HTTP = nil
		p.tls = nil
		return err
	}
	return nil
}

// prepare installs only the imported root and a verified device identity. The
// sole socket dial target is the application's Tor SOCKS Unix socket; the sole
// destination passed to SOCKS is this profile's onion:443 (no local DNS).
func (p *Profile) prepare() error {
	b := p.cache.Bundle
	if b.Version != 2 || !profileID.MatchString(b.ID) || !validProfileName(b.Name) || !onionName.MatchString(b.Onion) {
		return errors.New("invalid connection bundle")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b.TorPrivate)
	pin, pinErr := base64.StdEncoding.DecodeString(b.Fingerprint)
	if err != nil || len(key) != 32 || len(pin) != 32 || pinErr != nil || base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key) != b.TorPrivate {
		return errors.New("invalid Tor credential or tunnel fingerprint")
	}
	block, rest := pem.Decode([]byte(b.RootCA))
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return errors.New("invalid private root CA")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !root.IsCA || !root.BasicConstraintsValid || root.CheckSignatureFrom(root) != nil || time.Now().Before(root.NotBefore) || time.Now().After(root.NotAfter) {
		return errors.New("invalid or expired private root CA")
	}
	cert, err := tls.X509KeyPair([]byte(b.Certificate), []byte(b.PrivateKey))
	if err != nil || len(cert.Certificate) != 1 {
		return errors.New("invalid device certificate and key")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return errors.New("invalid device certificate")
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		clientAuth = clientAuth || usage == x509.ExtKeyUsageClientAuth
	}
	if leaf.IsCA || !clientAuth || time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
		return errors.New("expired or unsuitable device certificate")
	}
	token := p.cache.Token
	if token != (oauth.Token{}) && (token.Issuer != "https://"+b.Onion+"/login" || !validCredential(token.ClientID) || !validCredential(token.AccessToken) || !validCredential(token.RefreshToken) || token.ExpiresAt.IsZero() || !strings.HasPrefix(token.AccessToken, "authelia_at_") || !strings.HasPrefix(token.RefreshToken, "authelia_rt_")) {
		return errors.New("saved token does not belong to this profile")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	p.tls = &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: b.Onion, MinVersion: tls.VersionTLS13}
	socks, err := proxy.SOCKS5("unix", p.app.socket("socks"), nil, &net.Dialer{Timeout: 45 * time.Second})
	if err != nil {
		return err
	}
	contextual, ok := socks.(proxy.ContextDialer)
	if !ok {
		return errors.New("Tor SOCKS lacks cancellation")
	}
	tr := &http.Transport{TLSClientConfig: p.tls, ResponseHeaderTimeout: 45 * time.Second, TLSHandshakeTimeout: 45 * time.Second, IdleConnTimeout: 90 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != b.Onion+":443" {
			return nil, errors.New("unexpected profile destination")
		}
		return contextual.DialContext(ctx, "tcp", b.Onion+":443")
	}}
	p.HTTP = &http.Client{Transport: &profileTransport{Transport: tr, host: b.Onion}, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return nil
}

type profileTransport struct {
	*http.Transport
	host string
}

func (t *profileTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != t.host || r.URL.User != nil {
		return nil, errors.New("unexpected profile origin")
	}
	return t.Transport.RoundTrip(r)
}

func validCredential(s string) bool {
	if len(s) == 0 || len(s) > 8192 {
		return false
	}
	for _, r := range s {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func (p *Profile) saveToken(token oauth.Token) error {
	next := p.cache
	next.Token = token
	data, err := encrypt(next, p.password)
	if err != nil {
		return err
	}
	if err = atomicWrite(p.app.path("profiles", p.id+".age"), data); err != nil {
		return err
	}
	p.cache = next
	return nil
}
func (p *Profile) configureOAuth(clientID string) error {
	c, err := oauth.New(oauth.Config{Issuer: "https://" + p.cache.Bundle.Onion + "/login", Audience: "https://" + p.cache.Bundle.Onion, ClientID: clientID, HTTP: p.HTTP, Save: p.saveToken})
	if err == nil {
		p.oauth = c
	}
	return err
}
func (p *Profile) clearAccess() error {
	for id, m := range p.mappings {
		m.Close()
		delete(p.mappings, id)
	}
	if p.pending != nil {
		p.pending.Close()
		p.pending = nil
	}
	p.cache.Token = oauth.Token{}
	if p.HTTP != nil {
		return p.saveToken(oauth.Token{})
	}
	return nil
}
func (p *Profile) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.mappings {
		m.Close()
	}
	p.mappings = map[string]*tunnel.Mapping{}
	if p.pending != nil {
		p.pending.Close()
		p.pending = nil
	}
	if p.HTTP != nil {
		p.HTTP.CloseIdleConnections()
	}
	p.HTTP = nil
	p.tls = nil
	p.oauth = nil
	p.password = ""
	p.cache = encryptedProfile{}
	os.Remove(p.app.path("client-auth", p.id+".auth_private"))
}
func (p *Profile) token(ctx context.Context) (string, error) {
	if p.HTTP == nil || p.cache.Token.AccessToken == "" {
		return "", oauth.ErrLoginRequired
	}
	if !p.cache.Token.ExpiresAt.After(time.Now().Add(time.Minute)) {
		if p.oauth == nil {
			if err := p.configureOAuth(p.cache.Token.ClientID); err != nil {
				return "", err
			}
		}
		if _, err := p.oauth.Refresh(ctx, p.cache.Token); err != nil {
			if clearErr := p.clearAccess(); clearErr != nil {
				return "", clearErr
			}
			p.lastError = "OAuth login required"
			return "", err
		}
	}
	return p.cache.Token.AccessToken, nil
}
func (p *Profile) GetToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.token(ctx)
}

func (a *App) LoginProfile(ctx context.Context, id, username, password, totp string) (oauth.ConsentDetails, error) {
	p, err := a.profile(id)
	if err != nil {
		return oauth.ConsentDetails{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.HTTP == nil {
		return oauth.ConsentDetails{}, errors.New("unlock the connection profile first")
	}
	if err = p.clearAccess(); err != nil {
		return oauth.ConsentDetails{}, err
	}
	var info struct {
		Version  int    `json:"version"`
		ClientID string `json:"client_id"`
	}
	if err = p.call(ctx, "GET", "/api/info", nil, false, &info); err != nil {
		return oauth.ConsentDetails{}, err
	}
	if info.Version != 2 {
		return oauth.ConsentDetails{}, errors.New("unsupported gateway version")
	}
	if err = p.configureOAuth(info.ClientID); err != nil {
		return oauth.ConsentDetails{}, err
	}
	p.pending, err = p.oauth.Login(ctx, username, password, totp)
	if err != nil {
		return oauth.ConsentDetails{}, err
	}
	return p.pending.Details(), nil
}
func (a *App) AcceptProfile(ctx context.Context, id string, accept bool) error {
	p, err := a.profile(id)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending == nil {
		return errors.New("no pending consent")
	}
	pending := p.pending
	p.pending = nil
	if !accept {
		pending.Close()
		return nil
	}
	if _, err = pending.Accept(ctx); err != nil {
		if clearErr := p.clearAccess(); clearErr != nil {
			return clearErr
		}
		return err
	}
	p.lastError = ""
	return nil
}
func (p *Profile) call(ctx context.Context, method, path string, body any, auth bool, out any) error {
	if p.HTTP == nil {
		return errors.New("connection profile is locked")
	}
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+p.cache.Bundle.Onion+path, bytes.NewReader(data))
	if err != nil {
		return errors.New("invalid gateway request")
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		token, err := p.token(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := p.HTTP.Do(req)
	if err != nil {
		return errors.New("Tor gateway unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == 401 || response.StatusCode == 403 {
		if clearErr := p.clearAccess(); clearErr != nil {
			return clearErr
		}
		p.lastError = "OAuth login required"
		return oauth.ErrLoginRequired
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("gateway request rejected")
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, MaxFile+1))
	if err != nil || len(data) > MaxFile {
		return errors.New("invalid gateway response size")
	}
	if out != nil {
		return decode(data, out)
	}
	return nil
}
func (a *App) ProfileServices(ctx context.Context, id string) ([]ClientService, error) {
	p, err := a.profile(id)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.services(ctx)
}
func (p *Profile) services(ctx context.Context) ([]ClientService, error) {
	var result struct {
		Services []ViewService `json:"services"`
	}
	if err := p.call(ctx, "GET", "/api/services", nil, true, &result); err != nil {
		return nil, err
	}
	if len(result.Services) > 64 {
		return nil, errors.New("invalid service catalogue")
	}
	seen := map[string]bool{}
	out := make([]ClientService, 0, len(result.Services))
	for _, s := range result.Services {
		if !identifier.MatchString(s.ID) || seen[s.ID] || !validProfileName(s.Title) || len(s.Actions) > 3 {
			return nil, errors.New("invalid service catalogue")
		}
		for _, action := range s.Actions {
			if action != "load" && action != "reload" && action != "stop" {
				return nil, errors.New("invalid service action")
			}
		}
		seen[s.ID] = true
		entry := ClientService{ViewService: s}
		if m := p.mappings[s.ID]; m != nil {
			entry.Mapped = true
			entry.Port = m.Addr().(*net.TCPAddr).Port
			if m.Status() != nil {
				entry.Error = "tunnel connection failed"
			}
		}
		out = append(out, entry)
	}
	for id, m := range p.mappings {
		if !seen[id] {
			m.Close()
			delete(p.mappings, id)
		}
	}
	return out, nil
}
func (a *App) MapProfile(ctx context.Context, id, service string, enabled bool, port int) (int, error) {
	p, err := a.profile(id)
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !enabled {
		if m := p.mappings[service]; m != nil {
			m.Close()
			delete(p.mappings, service)
		}
		return 0, nil
	}
	catalogue, err := p.services(ctx)
	if err != nil {
		return 0, err
	}
	available := false
	for _, s := range catalogue {
		available = available || s.ID == service
	}
	if !available {
		return 0, errors.New("service is unavailable")
	}
	old := p.mappings[service]
	if old != nil && (port == 0 || old.Addr().(*net.TCPAddr).Port == port) {
		return old.Addr().(*net.TCPAddr).Port, nil
	}
	b := p.cache.Bundle
	m, err := tunnel.Map(p.app.ctx, tunnel.ClientConfig{OnionURL: "https://" + b.Onion, SOCKSNetwork: "unix", SOCKSAddress: p.app.socket("socks"), TLS: p.tls, Fingerprint: b.Fingerprint, AccessToken: p.GetToken}, service, port)
	if err != nil {
		return 0, err
	}
	if old != nil {
		old.Close()
	}
	p.mappings[service] = m
	return m.Addr().(*net.TCPAddr).Port, nil
}
func (a *App) ProfileAction(ctx context.Context, id, service, action string) error {
	if !identifier.MatchString(service) || (action != "load" && action != "reload" && action != "stop") {
		return errors.New("invalid service action")
	}
	p, err := a.profile(id)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.call(ctx, "POST", "/api/actions", map[string]string{"id": service, "action": action}, true, nil)
}
func (a *App) DisconnectProfile(ctx context.Context, id string) error {
	p, err := a.profile(id)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	old := p.cache.Token
	if err = p.clearAccess(); err != nil {
		return err
	}
	if old.AccessToken != "" {
		if p.oauth == nil {
			if err = p.configureOAuth(old.ClientID); err != nil {
				return err
			}
		}
		return p.oauth.Revoke(ctx, old)
	}
	return nil
}
func (a *App) PublicProfiles() []ProfileStatus {
	a.mu.Lock()
	list := make([]*Profile, 0, len(a.profiles))
	for _, p := range a.profiles {
		list = append(list, p)
	}
	a.mu.Unlock()
	out := make([]ProfileStatus, 0, len(list))
	for _, p := range list {
		p.mu.Lock()
		out = append(out, ProfileStatus{ID: p.id, Name: p.name, Onion: p.cache.Bundle.Onion, Locked: p.HTTP == nil, Authenticated: p.cache.Token.AccessToken != "", Error: p.lastError})
		p.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
