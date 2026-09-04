// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package localsession

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"time"
	"torkitten/internal/model"
	"torkitten/internal/state"
)

const CookieName = "torkitten_admin"

type Manager struct {
	store    *state.Store
	random   io.Reader
	now      func() time.Time
	idle     time.Duration
	absolute time.Duration
}
type Auth struct {
	ID, Owner, CSRF string
	AuthenticatedAt time.Time
}
type Summary struct {
	ID              string    `json:"id"`
	Owner           string    `json:"owner"`
	CreatedAt       time.Time `json:"created_at"`
	LastUseAt       time.Time `json:"last_use_at"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func RandomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	defer zero(raw)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func New(store *state.Store) *Manager {
	return &Manager{store: store, random: rand.Reader, now: time.Now, idle: 30 * time.Minute, absolute: 12 * time.Hour}
}
func (m *Manager) Issue(owner string) (cookie, csrf string, record model.LocalSession, err error) {
	if err = model.ValidateUsername(owner); err != nil {
		return "", "", record, err
	}
	raw := make([]byte, 32)
	id := make([]byte, 16)
	if _, err = io.ReadFull(m.random, raw); err != nil {
		return "", "", record, err
	}
	if _, err = io.ReadFull(m.random, id); err != nil {
		zero(raw)
		return "", "", record, err
	}
	now := m.now().UTC()
	hash := sha256.Sum256(raw)
	record = model.LocalSession{ID: hex.EncodeToString(id), Owner: owner, TokenHash: base64.RawURLEncoding.EncodeToString(hash[:]), CreatedAt: now, LastUseAt: now, AuthenticatedAt: now, ExpiresAt: now.Add(m.absolute)}
	cookie = base64.RawURLEncoding.EncodeToString(raw)
	csrf = csrfFor(raw)
	zero(raw)
	return cookie, csrf, record, nil
}
func (m *Manager) Create(owner string) (cookie, csrf string, err error) {
	cookie, csrf, record, err := m.Issue(owner)
	if err != nil {
		return "", "", err
	}
	err = m.store.Transition(func(current model.State) (model.State, func() error, error) {
		current.Sessions = prune(current.Sessions, m.now(), m.idle)
		if len(current.Sessions) >= model.MaxSessions {
			current.Sessions = current.Sessions[1:]
		}
		current.Sessions = append(current.Sessions, record)
		return current, nil, nil
	})
	if err != nil {
		return "", "", err
	}
	return cookie, csrf, nil
}
func (m *Manager) Authenticate(cookie string) (Auth, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil || len(raw) != 32 {
		return Auth{}, errors.New("invalid session")
	}
	defer zero(raw)
	hash := sha256.Sum256(raw)
	now := m.now().UTC()
	var found model.LocalSession
	err = m.store.Transition(func(current model.State) (model.State, func() error, error) {
		current.Sessions = prune(current.Sessions, now, m.idle)
		for i := range current.Sessions {
			stored, decodeErr := base64.RawURLEncoding.DecodeString(current.Sessions[i].TokenHash)
			if decodeErr == nil && subtle.ConstantTimeCompare(stored, hash[:]) == 1 {
				current.Sessions[i].LastUseAt = now
				found = current.Sessions[i]
			}
			zero(stored)
		}
		return current, nil, nil
	})
	if err != nil || found.ID == "" {
		return Auth{}, errors.New("invalid session")
	}
	return Auth{ID: found.ID, Owner: found.Owner, CSRF: csrfFor(raw), AuthenticatedAt: found.AuthenticatedAt}, nil
}
func ValidateCSRF(cookie, supplied string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil || len(raw) != 32 {
		return false
	}
	defer zero(raw)
	want := csrfFor(raw)
	return subtle.ConstantTimeCompare([]byte(want), []byte(supplied)) == 1
}
func (m *Manager) Revoke(id string) error {
	return m.store.Transition(func(current model.State) (model.State, func() error, error) {
		result := current.Sessions[:0]
		for _, session := range current.Sessions {
			if session.ID != id {
				result = append(result, session)
			}
		}
		current.Sessions = result
		return current, nil, nil
	})
}
func (m *Manager) RevokeAll() error {
	return m.store.Transition(func(current model.State) (model.State, func() error, error) {
		current.Sessions = []model.LocalSession{}
		return current, nil, nil
	})
}
func (m *Manager) List() []Summary {
	current := m.store.View()
	rows := make([]Summary, 0, len(current.Sessions))
	for _, session := range current.Sessions {
		rows = append(rows, Summary{ID: session.ID, Owner: session.Owner, CreatedAt: session.CreatedAt, LastUseAt: session.LastUseAt, AuthenticatedAt: session.AuthenticatedAt, ExpiresAt: session.ExpiresAt})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CreatedAt.After(rows[j].CreatedAt) })
	return rows
}
func prune(sessions []model.LocalSession, now time.Time, idle time.Duration) []model.LocalSession {
	result := sessions[:0]
	for _, session := range sessions {
		if now.Before(session.ExpiresAt) && now.Sub(session.LastUseAt) <= idle {
			result = append(result, session)
		}
	}
	return result
}
func csrfFor(raw []byte) string {
	digest := sha256.Sum256(append([]byte("torkitten-local-csrf\x00"), raw...))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
func zero(data []byte) { clear(data) }
