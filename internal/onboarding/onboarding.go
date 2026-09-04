// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package onboarding

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
	"torkitten/internal/authelia"
	"torkitten/internal/control"
	"torkitten/internal/model"
	"torkitten/internal/state"
	torkitTor "torkitten/internal/tor"
)

const WindowDuration = 15 * time.Minute

type Control interface {
	State() model.State
	PublicCA(context.Context) ([]byte, error)
	SetBootstrap(context.Context, *model.BootstrapWindow) error
	ExpirePending(context.Context) error
	PrepareCredentialChange() error
	FinishCredentialChange(context.Context) error
}
type Manager struct {
	control Control
	factors *authelia.Client
	root    string
	random  io.Reader
	now     func() time.Time
	mu      sync.Mutex
	totp    *totpFlow
}
type totpFlow struct {
	session *authelia.FactorSession
	expires time.Time
}

func New(control Control, factors *authelia.Client, root string) (*Manager, error) {
	if !filepath.IsAbs(root) || !regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`).MatchString(root) {
		return nil, errors.New("invalid bootstrap root")
	}
	if err := state.EnsureDir(root, 0o700); err != nil {
		return nil, err
	}
	keep := ""
	if window := control.State().Bootstrap; window != nil {
		keep = window.Token
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Name() != keep {
			if err = os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
				return nil, err
			}
		}
	}
	return &Manager{control: control, factors: factors, root: root, random: rand.Reader, now: time.Now}, nil
}
func (m *Manager) ChangePassword(ctx context.Context, username string, oldPassword, newPassword, confirmation []byte, token string) error {
	if len(newPassword) < 12 || len(newPassword) > 128 || !bytes.Equal(newPassword, confirmation) || bytes.IndexByte(newPassword, 0) >= 0 {
		return errors.New("invalid credential change")
	}
	flow, err := control.AuthenticateFactors(ctx, m.factors, username, oldPassword, token)
	if err != nil {
		return err
	}
	defer flow.Destroy()
	if err = m.control.PrepareCredentialChange(); err == nil {
		err = flow.ChangePassword(ctx, oldPassword, newPassword)
	}
	if err != nil {
		return errors.New("password change failed")
	}
	return m.control.FinishCredentialChange(ctx)
}
func (m *Manager) BeginTOTP(ctx context.Context, username string, password []byte, token string) ([]byte, error) {
	flow, err := control.AuthenticateFactors(ctx, m.factors, username, password, token)
	if err != nil {
		return nil, err
	}
	uri, err := flow.BeginTOTP(ctx)
	var image []byte
	if err == nil {
		image, err = EnrollmentQR(uri)
	}
	if err != nil {
		flow.Destroy()
		return nil, errors.New("TOTP change failed")
	}
	m.mu.Lock()
	m.clearTOTP()
	m.totp = &totpFlow{session: flow, expires: m.now().Add(10 * time.Minute)}
	m.mu.Unlock()
	return image, nil
}
func (m *Manager) CompleteTOTP(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.totp == nil || !m.totp.expires.After(m.now()) {
		m.clearTOTP()
		return errors.New("TOTP change expired")
	}
	if err := m.control.PrepareCredentialChange(); err != nil {
		return err
	}
	if err := m.totp.session.CompleteTOTP(ctx, token); err != nil {
		return errors.New("TOTP change failed")
	}
	m.clearTOTP()
	return m.control.FinishCredentialChange(ctx)
}
func (m *Manager) clearTOTP() {
	if m.totp != nil {
		m.totp.session.Destroy()
		m.totp = nil
	}
}
func (m *Manager) Open(ctx context.Context) (string, time.Time, error) {
	current := m.control.State()
	if !current.Initialized || len(current.Devices) == 0 {
		return "", time.Time{}, errors.New("onboarding requires an acknowledged device")
	}
	ca, err := m.control.PublicCA(ctx)
	certificate, _ := pem.Decode(ca)
	if err != nil || len(ca) == 0 || len(ca) > 64<<10 || certificate == nil || certificate.Type != "CERTIFICATE" {
		return "", time.Time{}, errors.New("public CA unavailable")
	}
	profile := bytes.ReplaceAll(bytes.ReplaceAll([]byte(iosProfile), []byte("CERTIFICATE_DATA"), []byte(base64.StdEncoding.EncodeToString(certificate.Bytes))), []byte("SERVICE_ID"), []byte(current.ServiceID))
	raw := make([]byte, 32)
	if _, err = io.ReadFull(m.random, raw); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	dir := filepath.Join(m.root, token)
	if err = state.EnsureDir(dir, 0o700); err != nil {
		return "", time.Time{}, err
	}
	if err = state.AtomicWrite(filepath.Join(dir, "torkitten-ios.mobileconfig"), profile, 0o600); err == nil {
		err = state.AtomicWrite(filepath.Join(dir, "torkitten-root-ca.cer"), certificate.Bytes, 0o600)
	}
	if err == nil {
		err = state.AtomicWrite(filepath.Join(dir, "index.html"), []byte(instructions), 0o600)
	}
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", time.Time{}, err
	}
	expires := m.now().UTC().Add(WindowDuration)
	window := &model.BootstrapWindow{Token: token, ExpiresAt: expires}
	if err = m.control.SetBootstrap(ctx, window); err != nil {
		_ = os.RemoveAll(dir)
		return "", time.Time{}, err
	}
	if old := current.Bootstrap; old != nil && old.Token != token {
		_ = os.RemoveAll(filepath.Join(m.root, old.Token))
	}
	return "http://" + current.Host("") + "/onboard/" + token + "/", expires, nil
}
func (m *Manager) Extend(ctx context.Context) (time.Time, error) {
	window := m.control.State().Bootstrap
	if window == nil {
		return time.Time{}, errors.New("bootstrap is not open")
	}
	window.ExpiresAt = m.now().UTC().Add(WindowDuration)
	return window.ExpiresAt, m.control.SetBootstrap(ctx, window)
}
func (m *Manager) Close(ctx context.Context) error {
	current := m.control.State()
	if current.Bootstrap == nil {
		return nil
	}
	if err := m.control.SetBootstrap(ctx, nil); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(m.root, current.Bootstrap.Token))
}
func (m *Manager) Expire(ctx context.Context) error {
	m.mu.Lock()
	if m.totp != nil && !m.totp.expires.After(m.now()) {
		m.clearTOTP()
	}
	m.mu.Unlock()
	if err := m.control.ExpirePending(ctx); err != nil {
		return err
	}
	window := m.control.State().Bootstrap
	if window != nil && !window.ExpiresAt.After(m.now()) {
		return m.Close(ctx)
	}
	return nil
}
func (m *Manager) ServePending(w http.ResponseWriter, qr bool) {
	current := m.control.State()
	if current.Pending == nil || !current.Pending.ExpiresAt.After(m.now()) {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}
	credential, err := torkitTor.Credential(current.ServiceID, current.Pending.PrivateKey)
	var data []byte
	if err == nil && qr {
		data, err = EnrollmentQR("http://" + current.Host("") + "?key=" + current.Pending.PrivateKey)
	}
	if err != nil {
		http.Error(w, "request failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if qr {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(data)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+current.ServiceID+`.auth_private"`)
	_, _ = io.WriteString(w, credential+"\n")
}
func EnrollmentQR(value string) ([]byte, error) {
	if !(len(value) <= 1024 && regexp.MustCompile(`^otpauth://totp/[^\r\n]+$`).MatchString(value)) && !regexp.MustCompile(`^(?:https://[a-z2-7]{56}\.onion/|http://[a-z2-7]{56}\.onion(?:\?key=[a-z2-7]{52}|/onboard/[A-Za-z0-9_-]{43}/))$`).MatchString(value) {
		return nil, errors.New("invalid enrollment value")
	}
	code, err := qr.Encode(value, qr.M, qr.Auto)
	if err == nil {
		code, err = barcode.Scale(code, 384, 384)
	}
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err = png.Encode(&output, code); err != nil || output.Len() > 1<<20 {
		return nil, errors.New("could not encode credential QR")
	}
	return output.Bytes(), nil
}

//go:embed instructions.html
var instructions string

//go:embed ios.mobileconfig
var iosProfile string
