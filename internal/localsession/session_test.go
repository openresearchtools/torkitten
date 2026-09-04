// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package localsession

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"torkitten/internal/state"
)

func testManager(t *testing.T) (*Manager, *state.Store, *time.Time) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	manager := New(store)
	manager.now = func() time.Time { return now }
	manager.random = bytes.NewReader(bytes.Repeat([]byte{7}, 256))
	return manager, store, &now
}

func TestSessionLifecycleAndPersistence(t *testing.T) {
	manager, store, _ := testManager(t)
	cookie, csrf, err := manager.Create("owner")
	if err != nil {
		t.Fatal(err)
	}
	if len(cookie) != 43 || len(csrf) != 43 || strings.Contains(cookie, "=") {
		t.Fatalf("cookie=%q csrf=%q", cookie, csrf)
	}
	if strings.Contains(string(mustStateJSON(t, store)), cookie) {
		t.Fatal("plaintext token was persisted")
	}
	auth, err := manager.Authenticate(cookie)
	if err != nil || auth.Owner != "owner" || auth.CSRF != csrf {
		t.Fatalf("auth=%+v err=%v", auth, err)
	}
	if !ValidateCSRF(cookie, csrf) || ValidateCSRF(cookie, "wrong") {
		t.Fatal("CSRF validation failed")
	}
	if len(manager.List()) != 1 {
		t.Fatal("session missing from list")
	}
	if err = manager.Revoke(auth.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Authenticate(cookie); err == nil {
		t.Fatal("revoked session authenticated")
	}
}

func TestIdleAndAbsoluteExpiry(t *testing.T) {
	manager, _, now := testManager(t)
	cookie, _, err := manager.Create("owner")
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(manager.idle + time.Second)
	if _, err = manager.Authenticate(cookie); err == nil {
		t.Fatal("idle session authenticated")
	}
	if len(manager.List()) != 0 {
		t.Fatal("expired session not pruned")
	}
}

func TestIssueDoesNotPersistBeforeCommit(t *testing.T) {
	manager, store, _ := testManager(t)
	_, _, record, err := manager.Issue("owner")
	if err != nil {
		t.Fatal(err)
	}
	if record.TokenHash == "" || len(store.View().Sessions) != 0 {
		t.Fatal("Issue persisted before initialization transaction")
	}
}

func mustStateJSON(t *testing.T, store *state.Store) []byte {
	t.Helper()
	value := store.View()
	var b strings.Builder
	for _, session := range value.Sessions {
		b.WriteString(session.TokenHash)
	}
	return []byte(b.String())
}
