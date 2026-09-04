// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package onboarding

import (
	"bytes"
	"context"
	"errors"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"image/png"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
	"torkitten/internal/authelia"
	"torkitten/internal/control"
	"torkitten/internal/model"
	torkitTor "torkitten/internal/tor"
)

type Control interface {
	State() model.State
	ExpirePending(context.Context) error
	PrepareCredentialChange() error
	FinishAuth(context.Context) error
}
type Manager struct {
	control Control
	factors *authelia.Client
	now     func() time.Time
	mu      sync.Mutex
	totp    *totpFlow
}
type totpFlow struct {
	session *authelia.FactorSession
	expires time.Time
}

func New(control Control, factors *authelia.Client) *Manager {
	return &Manager{control: control, factors: factors, now: time.Now}
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
	return m.control.FinishAuth(ctx)
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
	return m.control.FinishAuth(ctx)
}
func (m *Manager) clearTOTP() {
	if m.totp != nil {
		m.totp.session.Destroy()
		m.totp = nil
	}
}
func (m *Manager) Expire(ctx context.Context) error {
	m.mu.Lock()
	if m.totp != nil && !m.totp.expires.After(m.now()) {
		m.clearTOTP()
	}
	m.mu.Unlock()
	return m.control.ExpirePending(ctx)
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
	public := value == "https://orbot.app/download/" || value == "https://play.google.com/store/apps/details?id=org.torproject.android"
	if !(len(value) <= 1024 && regexp.MustCompile(`^otpauth://totp/[^\r\n]+$`).MatchString(value)) && !regexp.MustCompile(`^(?:https://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)?[a-z2-7]{56}\.onion/|http://[a-z2-7]{56}\.onion\?key=[a-z2-7]{52})$`).MatchString(value) && !public {
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
