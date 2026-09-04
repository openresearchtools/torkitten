// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package authelia

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"torkitten/internal/model"
	"torkitten/internal/state"
)

const maxExchange = 64 << 10

type Paths struct{ Binary, Config, Users, Database, SecretsDir, Socket, QR, Notifications string }

func DefaultPaths() Paths {
	return Paths{
		Binary: "/usr/bin/authelia", Config: "/etc/torkitten/authelia/configuration.yml",
		Users: "/var/lib/torkitten/authelia/users.yml", Database: "/var/lib/torkitten/authelia/db.sqlite3",
		SecretsDir: "/var/lib/torkitten/authelia/secrets", Socket: "/run/torkitten/authelia.sock",
		QR: "/run/torkitten/setup-totp.png", Notifications: "/var/lib/torkitten/authelia/notifications.txt",
	}
}
func (p Paths) Render(serviceID string) ([]byte, error) {
	s := model.NewState()
	s.ServiceID = serviceID
	if !regexp.MustCompile(`^[a-z2-7]{56}$`).MatchString(serviceID) || !p.safe() {
		return nil, errors.New("invalid Authelia rendering inputs")
	}
	base := s.Host("")
	return []byte(fmt.Sprintf(`theme: 'dark'
server:
  address: 'unix://%s?umask=0077&path=login'
  disable_healthcheck: true
  endpoints:
    enable_pprof: false
    enable_expvars: false
    authz: { forward-auth: { implementation: 'ForwardAuth', authn_strategies: [{ name: 'CookieSession' }] } }
    rate_limits:
      second_factor_totp: { enable: true, buckets: [{ period: '1 minute', requests: 10 }, { period: '10 minutes', requests: 30 }] }
totp: { issuer: 'Torkitten', algorithm: 'sha1', digits: 6, period: 30, skew: 1, secret_size: 32, disable_reuse_security_policy: false }
webauthn: { disable: true }
identity_validation:
  reset_password: {}
  elevated_session: { require_second_factor: true, skip_second_factor: true }
authentication_backend:
  password_reset: { disable: true }
  password_change: { disable: false }
  file:
    path: '%s'
    watch: true
    search: { email: false, case_insensitive: false }
    password:
      algorithm: 'argon2'
      argon2: { variant: 'argon2id', iterations: 3, memory: 65536, parallelism: 4, key_length: 32, salt_length: 16 }
access_control:
  default_policy: 'deny'
  rules: [{ domain: ['%s', '*.%s'], subject: 'group:%s', policy: 'two_factor' }]
session:
  name: 'torkitten_onion'
  same_site: 'lax'
  inactivity: '87600h'
  expiration: '87600h'
  remember_me: -1
  cookies:
    - { domain: '%s', authelia_url: 'https://%s/login', default_redirection_url: 'https://%s', name: 'torkitten_onion', same_site: 'lax', inactivity: '87600h', expiration: '87600h', remember_me: -1 }
regulation: { modes: ['user'], max_retries: 3, find_time: '2m', ban_time: '5m' }
storage: { local: { path: '%s' } }
notifier: { filesystem: { filename: '%s' } }
ntp: { disable_startup_check: true }
telemetry: { metrics: { enabled: false } }
`, p.Socket, p.Users, base, base, model.OwnerGroup, base, base, base, p.Database, p.Notifications)), nil
}

var safePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

func (p Paths) safe() bool {
	for _, v := range []string{p.Binary, p.Config, p.Users, p.Database, p.SecretsDir, p.Socket, p.QR, p.Notifications} {
		if !filepath.IsAbs(v) || !safePath.MatchString(v) {
			return false
		}
	}
	return true
}
func (p Paths) Environment(base []string) []string {
	env := make([]string, 0, len(base)+4)
	for _, value := range base {
		if !strings.HasPrefix(value, "AUTHELIA_") {
			env = append(env, value)
		}
	}
	return append(env,
		"AUTHELIA_SESSION_SECRET_FILE="+filepath.Join(p.SecretsDir, "session"),
		"AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE="+filepath.Join(p.SecretsDir, "storage"),
		"AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE="+filepath.Join(p.SecretsDir, "jwt"),
		"AUTHELIA_TELEMETRY_METRICS_ENABLED=false")
}
func (p Paths) EnsureFiles() error {
	if !p.safe() {
		return errors.New("unsafe Authelia paths")
	}
	for _, dir := range []string{filepath.Dir(p.Config), filepath.Dir(p.Users), p.SecretsDir, filepath.Dir(p.Socket)} {
		if err := state.EnsureDir(dir, 0o700); err != nil {
			return err
		}
	}
	for _, name := range []string{"session", "storage", "jwt"} {
		path := filepath.Join(p.SecretsDir, name)
		if err := ensureSecret(path); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(p.Users); errors.Is(err, os.ErrNotExist) {
		return state.AtomicWrite(p.Users, []byte("users: {}\n"), 0o600)
	}
	return nil
}
func ensureSecret(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 64 {
			return errors.New("unsafe Authelia secret file")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := randomBytes(48)
	if err != nil {
		return err
	}
	return state.AtomicWrite(path, []byte(raw), 0o600)
}
func WriteOwner(path, username, digest string) error {
	if err := model.ValidateUsername(username); err != nil {
		return err
	}
	if !strings.HasPrefix(digest, "$argon2id$") || len(digest) > 512 || strings.ContainsAny(digest, "\r\n'") {
		return errors.New("invalid Authelia password digest")
	}
	body := fmt.Sprintf("users:\n  %s:\n    disabled: false\n    displayname: '%s'\n    password: '%s'\n    groups:\n      - '%s'\n", username, username, digest, model.OwnerGroup)
	return state.AtomicWrite(path, []byte(body), 0o600)
}

type Runner struct{ Paths Paths }

func (r Runner) Validate(ctx context.Context) error {
	return r.run(ctx, "config", "validate", "--config", r.Paths.Config)
}
func (r Runner) GenerateTOTP(ctx context.Context, username string) error {
	if model.ValidateUsername(username) != nil {
		return errors.New("invalid owner")
	}
	_ = os.Remove(r.Paths.QR)
	if err := r.run(ctx, "storage", "user", "totp", "generate", username, "--config", r.Paths.Config, "--path", r.Paths.QR); err != nil {
		return err
	}
	info, err := os.Lstat(r.Paths.QR)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 100 || info.Size() > 1<<20 {
		return errors.New("Authelia did not create a bounded TOTP QR")
	}
	return os.Chmod(r.Paths.QR, 0o600)
}
func (r Runner) run(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, r.Paths.Binary, args...)
	cmd.Env, cmd.Dir = r.Paths.Environment(os.Environ()), "/"
	var output boundedBuffer
	defer output.zero()
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil || output.overflow {
		return errors.New("Authelia command failed")
	}
	return nil
}

type boundedBuffer struct {
	bytes.Buffer
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxExchange {
		b.overflow = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}
func (b *boundedBuffer) zero() { zero(b.Bytes()); b.Reset() }
func zero(v []byte)            { clear(v) }
func randomBytes(n int) (string, error) {
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

type Client struct {
	socket string
	domain atomic.Value
}

func NewClient(socket, serviceID string) (*Client, error) {
	if !filepath.IsAbs(socket) || !safePath.MatchString(socket) || !regexp.MustCompile(`^[a-z2-7]{56}$`).MatchString(serviceID) {
		return nil, errors.New("invalid Authelia client configuration")
	}
	client := &Client{socket: socket}
	client.domain.Store(serviceID)
	return client, nil
}
func (c *Client) SetServiceID(serviceID string) { c.domain.Store(serviceID) }
func (c *Client) httpClient(withJar bool) *http.Client {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", c.socket)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: dial, DialTLSContext: dial}, Timeout: 15 * time.Second}
	if withJar {
		client.Jar, _ = cookiejar.New(nil)
	}
	return client
}

type FactorSession struct {
	owner  string
	client *http.Client
	parent *Client
}

func (c *Client) BeginFactors(ctx context.Context, username string, password []byte) (*FactorSession, error) {
	if model.ValidateUsername(username) != nil || len(password) < 1 || len(password) > 128 {
		return nil, errors.New("authentication failed")
	}
	httpClient := c.httpClient(true)
	var status struct{ Status string }
	if c.call(ctx, httpClient, http.MethodPost, "/api/firstfactor", map[string]any{"username": username, "password": string(password), "keepMeLoggedIn": false}, &status) != nil || status.Status != "OK" {
		return nil, errors.New("authentication failed")
	}
	var info struct {
		Status string `json:"status"`
		Data   struct {
			HasTOTP bool `json:"has_totp"`
		} `json:"data"`
	}
	if c.call(ctx, httpClient, http.MethodPost, "/api/user/info", map[string]any{}, &info) != nil || info.Status != "OK" || !info.Data.HasTOTP {
		return nil, errors.New("authentication failed")
	}
	return &FactorSession{owner: username, client: httpClient, parent: c}, nil
}
func (f *FactorSession) Complete(ctx context.Context, token string) (string, error) {
	if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(token) {
		return "", errors.New("authentication failed")
	}
	var status struct{ Status string }
	if f.parent.call(ctx, f.client, http.MethodPost, "/api/secondfactor/totp", map[string]string{"token": token}, &status) != nil || status.Status != "OK" {
		return "", errors.New("authentication failed")
	}
	return f.owner, nil
}
func (f *FactorSession) ChangePassword(ctx context.Context, oldPassword, newPassword []byte) error {
	return f.parent.call(ctx, f.client, http.MethodPost, "/api/change-password", map[string]string{"old_password": string(oldPassword), "new_password": string(newPassword)}, nil)
}
func (f *FactorSession) BeginTOTP(ctx context.Context) (string, error) {
	var response struct{ Data map[string]string }
	err := f.parent.call(ctx, f.client, http.MethodPut, "/api/secondfactor/totp/register", map[string]any{"algorithm": "SHA1", "length": 6, "period": 30}, &response)
	return response.Data["otpauth_url"], err
}
func (f *FactorSession) CompleteTOTP(ctx context.Context, token string) error {
	return f.parent.call(ctx, f.client, http.MethodPost, "/api/secondfactor/totp/register", map[string]string{"token": token}, nil)
}
func (f *FactorSession) Destroy() {
	f.owner = ""
	if f.client != nil {
		f.client.Jar = nil
		f.client.CloseIdleConnections()
	}
	f.client, f.parent = nil, nil
}
func (c *Client) Verify(ctx context.Context, username string, password []byte, token string) error {
	flow, err := c.BeginFactors(ctx, username, password)
	if err == nil {
		defer flow.Destroy()
		_, err = flow.Complete(ctx, token)
	}
	return err
}
func (c *Client) Healthy(ctx context.Context) error {
	return c.call(ctx, c.httpClient(false), http.MethodGet, "/api/health", nil, nil)
}
func (c *Client) call(ctx context.Context, client *http.Client, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	host, path := c.domain.Load().(string)+".onion", "/login"+path
	req, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Forwarded-URI", path)
	req.Header.Set("X-Forwarded-Method", method)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxExchange+1))
	if err != nil || len(data) > maxExchange || resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("Authelia rejected request")
	}
	if output != nil && json.Unmarshal(data, output) != nil {
		return errors.New("malformed Authelia response")
	}
	return nil
}
