// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"filippo.io/age"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
	"torkitten/internal/oauth"
)

func encrypt(value any, password string) ([]byte, error) {
	if len(password) < 12 || len(password) > 256 {
		return nil, errors.New("QR password must contain 12–256 characters")
	}
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	r, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return nil, err
	}
	z := gzip.NewWriter(w)
	if _, err = z.Write(b); err == nil {
		err = z.Close()
	}
	if err == nil {
		err = w.Close()
	}
	return out.Bytes(), err
}
func decrypt(data []byte, password string, value any) error {
	if len(data) > MaxFile {
		return errors.New("encrypted file too large")
	}
	id, err := age.NewScryptIdentity(password)
	if err != nil {
		return err
	}
	id.SetMaxWorkFactor(18)
	r, err := age.Decrypt(bytes.NewReader(data), id)
	if err != nil {
		return errors.New("incorrect QR password or damaged connection")
	}
	z, err := gzip.NewReader(r)
	if err != nil {
		return errors.New("invalid connection file")
	}
	defer z.Close()
	b, err := io.ReadAll(io.LimitReader(z, MaxFile+1))
	defer clear(b)
	if err != nil {
		return errors.New("invalid encrypted connection data")
	}
	return decode(b, value)
}
func qrPNG(s string) ([]byte, error) {
	if len(s) > 2900 {
		return nil, errors.New("encrypted connection exceeds QR capacity")
	}
	q, err := qr.Encode(s, qr.M, qr.Auto)
	if err != nil {
		return nil, err
	}
	q, err = barcode.Scale(q, 720, 720)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = png.Encode(&b, q)
	return b.Bytes(), err
}
func (a *App) writeAuthelia() error {
	pem, err := os.ReadFile(a.gen("oidc.key"))
	if err != nil {
		return err
	}
	var secrets map[string]string
	if err = readJSON(a.gen("secrets.json"), &secrets); err != nil {
		return err
	}
	host := a.host.Onion
	cfg := map[string]any{
		"log":    map[string]any{"level": "warn", "format": "json"},
		"server": map[string]any{"address": "unix://" + a.socket("authelia") + "?umask=0077&path=login", "disable_healthcheck": true, "endpoints": map[string]any{"enable_pprof": false, "enable_expvars": false, "authz": map[string]any{"forward-auth": map[string]any{"implementation": "ForwardAuth", "authn_strategies": []any{map[string]any{"name": "HeaderAuthorization", "schemes": []string{"Bearer"}}}}}}},
		"totp":   map[string]any{"issuer": "TorKitten", "algorithm": "sha1", "digits": 6, "period": 30, "skew": 1, "secret_size": 32}, "webauthn": map[string]any{"disable": true},
		"authentication_backend": map[string]any{"password_reset": map[string]any{"disable": true}, "file": map[string]any{"path": a.gen("users.json"), "watch": false}},
		"access_control":         map[string]any{"default_policy": "deny", "rules": []any{map[string]any{"domain": host, "subject": "group:torkitten-owner", "policy": "two_factor"}}},
		"session":                map[string]any{"secret": secrets["session"], "same_site": "lax", "inactivity": "30m", "expiration": "1h", "remember_me": -1, "cookies": []any{map[string]any{"domain": host, "authelia_url": "https://" + host + "/login", "default_redirection_url": "https://" + host + "/", "name": "torkitten_login"}}},
		"storage":                map[string]any{"encryption_key": secrets["storage"], "local": map[string]any{"path": a.gen("authelia.sqlite3")}},
		"notifier":               map[string]any{"filesystem": map[string]any{"filename": a.gen("notifications.txt")}}, "ntp": map[string]any{"disable_startup_check": true}, "telemetry": map[string]any{"metrics": map[string]any{"enabled": false}},
		"identity_providers": map[string]any{"oidc": map[string]any{"hmac_secret": secrets["hmac"], "jwks": []any{map[string]any{"key": string(pem), "algorithm": "RS256", "use": "sig"}}, "clients": []any{oauth.Registration(a.host.OAuthClient, "https://"+host)}}},
	}
	return writeJSON(a.gen("authelia.json"), cfg)
}
func (a *App) startAuthelia() error {
	p, err := startProcess(a.ctx, filepath.Join(a.bin, "authelia"), a.gen("authelia.log"), "--config", a.gen("authelia.json"))
	if err != nil {
		return err
	}
	a.processes["authelia"] = p
	return waitReady(a.ctx, p, func() error {
		r, e := unixHTTP(a.socket("authelia")).Get("http://" + a.host.Onion + "/login/api/health")
		if e != nil {
			return e
		}
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			return errors.New("Authelia not ready")
		}
		return nil
	})
}

type pendingSetup struct {
	password []byte
	deadline time.Time
	timer    *time.Timer
}

func (a *App) clearPendingSetup() {
	if a.pendingSetup != nil {
		if a.pendingSetup.timer != nil {
			a.pendingSetup.timer.Stop()
		}
		clear(a.pendingSetup.password)
		a.pendingSetup = nil
	}
}
func (a *App) stopHost() {
	a.clearPendingSetup()
	if a.relay != nil {
		a.relay.Close()
		a.relay = nil
	}
	a.stopHostSSH()
	if a.remote != nil {
		a.remote.Close()
		a.remote = nil
	}
	for _, name := range []string{"tor", "caddy", "authelia"} {
		a.processes[name].stop()
		delete(a.processes, name)
	}
	for _, name := range []string{"remote", "gateway", "authelia", "caddy"} {
		os.Remove(a.socket(name))
	}
}
func (a *App) issueIdentity(ctx context.Context, qrPassword string) (result map[string]string, err error) {
	if len(qrPassword) < 12 || len(qrPassword) > 256 {
		return nil, errors.New("QR password must contain 12–256 characters")
	}
	old := a.host.Generation
	a.stopHost()
	defer func() {
		if err != nil {
			a.hostError = "identity setup incomplete; remote access closed"
			a.stopHost()
			a.host.Initialized = false
			err = errors.Join(err, writeJSON(a.path("host.json"), a.host))
		}
	}()
	username := "owner-" + randomID()[:16]
	a.host = HostState{Version: 2, Generation: "identity-" + randomID(), Owner: username, OAuthClient: "torkitten-" + randomID(), Devices: []Device{}}
	a.hostError = "identity setup incomplete; remote access closed"
	if err := writeJSON(a.path("host.json"), a.host); err != nil {
		return nil, err
	}
	if err := privateDir(a.gen()); err != nil {
		return nil, err
	}
	// Old identity is deliberately never restored after a failed rotation.
	if old != "" {
		if err := os.RemoveAll(a.path(old)); err != nil {
			return nil, err
		}
	}
	if err := a.startServerTor(); err != nil {
		return nil, err
	}
	authelia := filepath.Join(a.bin, "authelia")
	raw, err := runPrivate(ctx, authelia, nil, "crypto", "hash", "generate", "argon2", "--random", "--random.length", "48")
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	secret := regexp.MustCompile(`(?m)^Random Password: (.+)$`).FindSubmatch(raw)
	digest := regexp.MustCompile(`(?m)^Digest: (.+)$`).FindSubmatch(raw)
	if len(secret) != 2 || len(digest) != 2 {
		return nil, errors.New("Authelia did not generate credentials")
	}
	if err = writeJSON(a.gen("users.json"), map[string]any{"users": map[string]any{username: map[string]any{"displayname": username, "password": string(digest[1]), "groups": []string{"torkitten-owner"}}}}); err != nil {
		return nil, err
	}
	if err = writeJSON(a.gen("secrets.json"), map[string]string{"session": randomID(), "storage": randomID(), "hmac": randomID()}); err != nil {
		return nil, err
	}
	if _, err = runPrivate(ctx, "/usr/bin/openssl", nil, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", a.gen("oidc.key")); err != nil {
		return nil, err
	}
	if _, err = runPrivate(ctx, "/usr/bin/ssh-keygen", nil, "-t", "ed25519", "-N", "", "-f", a.gen("tunnel.key")); err != nil {
		return nil, err
	}
	if err = a.writeAuthelia(); err != nil {
		return nil, err
	}
	for _, args := range [][]string{{"config", "validate"}, {"storage", "migrate", "up"}, {"storage", "user", "totp", "generate", username, "--path", a.gen("totp.png")}} {
		if _, err = runPrivate(ctx, authelia, nil, append(args, "--config", a.gen("authelia.json"))...); err != nil {
			return nil, err
		}
	}
	image, err := os.ReadFile(a.gen("totp.png"))
	if err != nil {
		return nil, err
	}
	os.Remove(a.gen("totp.png"))
	a.processes["tor"].stop()
	delete(a.processes, "tor")
	a.host.Initialized = true
	if err = a.startHost(); err != nil {
		a.host.Initialized = false
		a.stopHost()
		return nil, err
	}
	connection, err := a.connectionQR(ctx, qrPassword)
	if err != nil {
		return nil, err
	}
	if err = atomicWrite(a.gen("connection.png"), connection); err != nil {
		return nil, err
	}
	if err = writeJSON(a.path("host.json"), a.host); err != nil {
		a.stopHost()
		return nil, err
	}
	pending := &pendingSetup{password: append([]byte(nil), secret[1]...), deadline: time.Now().Add(10 * time.Minute)}
	a.pendingSetup = pending
	pending.timer = time.AfterFunc(10*time.Minute, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.pendingSetup == pending {
			a.clearPendingSetup()
		}
	})
	a.hostError = "confirm the authenticator code on This Host to complete setup"
	return map[string]string{"username": username, "password": string(secret[1]), "totp_qr": base64.StdEncoding.EncodeToString(image)}, nil
}

// localAutheliaTransport preserves the secure virtual origin for native cookies;
// the actual request can only reach the host's private Authelia Unix socket.
type localAutheliaTransport struct{ http.RoundTripper }

func (t localAutheliaTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme = "http"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", r.URL.Host)
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	return t.RoundTripper.RoundTrip(r)
}

// ConfirmIdentity is called under App.mu by the host-only private API.
func (a *App) ConfirmIdentity(ctx context.Context, totp string) (map[string]string, error) {
	if a.pendingSetup == nil || time.Now().After(a.pendingSetup.deadline) || !a.host.Initialized || a.host.Enrolled {
		a.clearPendingSetup()
		return nil, errors.New("setup expired or unavailable; issue a new identity")
	}
	client := unixHTTP(a.socket("authelia"))
	client.Transport = localAutheliaTransport{client.Transport}
	issuer := "https://" + a.host.Onion
	verification, err := oauth.New(oauth.Config{Issuer: issuer + "/login", Audience: issuer, ClientID: a.host.OAuthClient, HTTP: client, Save: func(oauth.Token) error { return errors.New("setup cannot issue tokens") }})
	if err != nil {
		return nil, err
	}
	if err = verification.VerifyFactors(ctx, a.host.Owner, string(a.pendingSetup.password), totp); err != nil {
		return nil, err
	}
	q, err := readPrivate(a.gen("connection.png"))
	if err != nil {
		return nil, err
	}
	a.clearPendingSetup()
	a.host.Enrolled = true
	a.hostError = ""
	if err = writeJSON(a.path("host.json"), a.host); err == nil {
		// Tor retains the next descriptor upload time while publication is off.
		// Start the confirmed service afresh rather than waiting on that timer.
		a.processes["tor"].stop()
		delete(a.processes, "tor")
		err = a.startServerTor()
	}
	if err != nil {
		a.host.Enrolled = false
		a.hostError = "setup publication failed; remote access closed"
		a.stopHost()
		return nil, errors.Join(err, writeJSON(a.path("host.json"), a.host))
	}
	a.hostError = ""
	return map[string]string{"qr": base64.StdEncoding.EncodeToString(q)}, nil
}
func (a *App) revokeSessions() error {
	if !a.host.Initialized || !a.host.Enrolled {
		return errors.New("host is not initialized")
	}
	a.hostError = "sessions revoked; authorization is restarting"
	if a.relay != nil {
		a.relay.Revoke()
	}
	a.processes["authelia"].stop()
	os.Remove(a.socket("authelia"))
	a.host.OAuthClient = "torkitten-" + randomID()
	if err := writeJSON(a.path("host.json"), a.host); err != nil {
		return err
	}
	if err := a.writeAuthelia(); err != nil {
		return err
	}
	if err := a.startAuthelia(); err != nil {
		return err
	}
	a.hostError = ""
	return nil
}
func (a *App) connectionQR(ctx context.Context, password string) ([]byte, error) {
	if !a.host.Initialized || a.host.Enrolled || len(a.host.Devices) != 0 {
		return nil, errors.New("identity unavailable or connection already issued")
	}
	name := "TorKitten " + a.host.Onion[:8]
	id := randomID()
	tmp, err := os.MkdirTemp(a.gen(), ".enroll-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	cert, key := filepath.Join(tmp, "client.pem"), filepath.Join(tmp, "client.key")
	if _, err = runPrivate(ctx, "/usr/bin/openssl", nil, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "365", "-subj", "/CN="+id, "-keyout", key, "-out", cert, "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=clientAuth"); err != nil {
		return nil, err
	}
	certBytes, err := os.ReadFile(cert)
	if err != nil {
		return nil, err
	}
	keyBytes, err := os.ReadFile(key)
	if err != nil {
		return nil, err
	}
	defer clear(keyBytes)
	torKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString
	root, err := a.caddyRoot()
	if err != nil {
		return nil, err
	}
	bundle := Bundle{Version: 2, ID: id, Name: name, Owner: a.host.Owner, Onion: a.host.Onion, TorPrivate: enc(torKey.Bytes()), RootCA: string(root), Certificate: string(certBytes), PrivateKey: string(keyBytes), Fingerprint: a.relay.Fingerprint()}
	encrypted, err := encrypt(bundle, password)
	if err != nil {
		return nil, err
	}
	q, err := qrPNG("TK2:" + base64.StdEncoding.EncodeToString(encrypted))
	if err != nil {
		return nil, err
	}
	if err = privateDir(a.gen("devices")); err != nil {
		return nil, err
	}
	if err = atomicWrite(a.gen("devices", id+".pem"), certBytes); err != nil {
		return nil, err
	}
	public := enc(torKey.PublicKey().Bytes())
	if err = atomicWrite(a.gen("onion", "authorized_clients", id+".auth"), []byte("descriptor:x25519:"+public+"\n")); err != nil {
		return nil, err
	}
	a.host.Devices = append(a.host.Devices, Device{ID: id, Name: name, TorPublic: public, Certificate: string(certBytes)})
	if err = a.reloadCaddy(); err != nil {
		a.hostError = "device configuration failed; remote access closed"
		a.relay.Revoke()
		return nil, err
	}
	if err = atomicWrite(a.gen("torrc"), []byte(a.torServerConfig())); err != nil {
		return nil, err
	}
	if err = a.processes["tor"].reload(); err != nil {
		return nil, err
	}
	return q, nil
}
