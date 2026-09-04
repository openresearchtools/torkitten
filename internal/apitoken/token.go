// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package apitoken

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"torkitten/internal/model"
	"torkitten/internal/state"
)

type Manager struct {
	store  *state.Store
	mu     sync.Mutex
	random io.Reader
	now    func() time.Time
	rates  map[string]*bucket
}

type bucket struct {
	remaining float64
	updated   time.Time
}

func New(store *state.Store) *Manager {
	return &Manager{store: store, random: rand.Reader, now: time.Now, rates: map[string]*bucket{}}
}

func (m *Manager) Create(name string, scopes []model.Scope, lifetime time.Duration) (string, string, error) {
	if len(name) < 1 || len(name) > 64 || strings.TrimSpace(name) != name || lifetime < 0 || lifetime > 365*24*time.Hour {
		return "", "", errors.New("invalid token request")
	}
	if len(scopes) == 0 {
		scopes = []model.Scope{model.ScopeMappingsRead, model.ScopeMappingsWrite}
	}
	idRaw, secret := make([]byte, 16), make([]byte, 32)
	if _, err := io.ReadFull(m.random, idRaw); err != nil {
		return "", "", err
	}
	if _, err := io.ReadFull(m.random, secret); err != nil {
		return "", "", err
	}
	defer zero(secret)
	id := hex.EncodeToString(idRaw)
	token := "tk_" + id + "_" + base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256([]byte(token))
	now := m.now().UTC()
	record := model.AgentToken{ID: id, Name: name, TokenHash: base64.RawURLEncoding.EncodeToString(digest[:]), Scopes: append([]model.Scope(nil), scopes...), CreatedAt: now}
	if lifetime > 0 {
		record.ExpiresAt = now.Add(lifetime)
	}
	if err := m.store.Transition(func(current model.State) (model.State, func() error, error) {
		if len(current.Tokens) >= model.MaxTokens {
			return current, nil, errors.New("token limit reached")
		}
		current.Tokens = append(current.Tokens, record)
		return current, nil, nil
	}); err != nil {
		return "", "", err
	}
	return token, id, nil
}

func (m *Manager) Authorize(token string, required model.Scope) error {
	if len(token) != 79 || !strings.HasPrefix(token, "tk_") || token[35] != '_' {
		return errors.New("invalid API token")
	}
	id := token[3:35]
	digest := sha256.Sum256([]byte(token))
	now := m.now().UTC()
	var matched bool
	err := m.store.Transition(func(current model.State) (model.State, func() error, error) {
		for i := range current.Tokens {
			record := &current.Tokens[i]
			stored, decodeErr := base64.RawURLEncoding.DecodeString(record.TokenHash)
			valid := decodeErr == nil && subtle.ConstantTimeCompare(stored, digest[:]) == 1 && record.ID == id && (record.ExpiresAt.IsZero() || now.Before(record.ExpiresAt)) && hasScope(record.Scopes, required)
			zero(stored)
			if valid && m.allow(id, now) {
				matched = true
				record.LastUseAt = now
			}
		}
		if !matched {
			return current, nil, errors.New("token denied")
		}
		return current, nil, nil
	})
	if err != nil || !matched {
		return errors.New("invalid or rate-limited API token")
	}
	return nil
}

func (m *Manager) allow(id string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	b := m.rates[id]
	if b == nil {
		b = &bucket{remaining: 20, updated: now}
		m.rates[id] = b
	}
	b.remaining += now.Sub(b.updated).Seconds()
	if b.remaining > 20 {
		b.remaining = 20
	}
	b.updated = now
	if b.remaining < 1 {
		return false
	}
	b.remaining--
	return true
}

func (m *Manager) Revoke(id string) error {
	err := m.store.Transition(func(current model.State) (model.State, func() error, error) {
		kept := current.Tokens[:0]
		for _, token := range current.Tokens {
			if token.ID != id {
				kept = append(kept, token)
			}
		}
		current.Tokens = kept
		return current, nil, nil
	})
	m.mu.Lock()
	delete(m.rates, id)
	m.mu.Unlock()
	return err
}

func hasScope(scopes []model.Scope, required model.Scope) bool {
	for _, scope := range scopes {
		if scope == required || scope == model.ScopeMappingsWrite && required == model.ScopeMappingsRead {
			return true
		}
	}
	return false
}
func zero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
