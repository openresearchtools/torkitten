// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package apitoken

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"torkitten/internal/model"
	"torkitten/internal/state"
)

func newTestManager(t *testing.T) (*Manager, *state.Store, *time.Time) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	manager := New(store)
	manager.now = func() time.Time { return now }
	manager.random = bytes.NewReader(bytes.Repeat([]byte{3}, 1024))
	return manager, store, &now
}

func TestTokenLifecycleAndScopes(t *testing.T) {
	manager, store, _ := newTestManager(t)
	token, id, err := manager.Create("automation", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 79 || len(id) != 32 || strings.Contains(string(stateTokenHashes(store)), token) {
		t.Fatal("invalid or plaintext-persisted token")
	}
	if err = manager.Authorize(token, model.ScopeMappingsRead); err != nil {
		t.Fatal(err)
	}
	if err = manager.Authorize(token, model.ScopeMappingsWrite); err != nil {
		t.Fatal(err)
	}
	if err = manager.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if err = manager.Authorize(token, model.ScopeMappingsRead); err == nil {
		t.Fatal("revoked token authorized")
	}
}

func TestReadScopeCannotWriteAndExpiry(t *testing.T) {
	manager, _, now := newTestManager(t)
	token, _, err := manager.Create("reader", []model.Scope{model.ScopeMappingsRead}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Authorize(token, model.ScopeMappingsWrite); err == nil {
		t.Fatal("read token wrote")
	}
	*now = now.Add(2 * time.Minute)
	if err = manager.Authorize(token, model.ScopeMappingsRead); err == nil {
		t.Fatal("expired token authorized")
	}
}

func TestRateLimit(t *testing.T) {
	manager, _, _ := newTestManager(t)
	token, _, err := manager.Create("agent", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if err = manager.Authorize(token, model.ScopeMappingsRead); err != nil {
			t.Fatal(err)
		}
	}
	if err = manager.Authorize(token, model.ScopeMappingsRead); err == nil {
		t.Fatal("rate limit not enforced")
	}
}

func stateTokenHashes(store *state.Store) []byte {
	var result strings.Builder
	for _, token := range store.View().Tokens {
		result.WriteString(token.TokenHash)
	}
	return []byte(result.String())
}
