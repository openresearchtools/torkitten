// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"torkitten/internal/model"
)

func TestOpenAndTransition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "state.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.View(); got.Version != model.StateVersion || got.Mappings == nil {
		t.Fatalf("unexpected initial state: %+v", got)
	}
	if err = store.Transition(func(current model.State) (model.State, func() error, error) {
		current.ServiceID = strings.Repeat("a", 56)
		return current, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.View().ServiceID != strings.Repeat("a", 56) {
		t.Fatal("state did not survive reopen")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unsafe state mode: %v %v", info, err)
	}
}

func TestOpenNormalizesLegacyNullCollections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	body := `{"version":1,"mappings":null,"devices":null,"local_sessions":null,"agent_tokens":null,"bootstrap":{"token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":"2030-01-01T00:00:00Z"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got := store.View()
	if got.Mappings == nil || got.Devices == nil || got.Sessions == nil || got.Tokens == nil || got.Bootstrap != nil {
		t.Fatal("legacy state was not normalized")
	}
}

func TestReconcileAppliesWithoutMutation(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err = store.Reconcile(func(candidate model.State) error {
		called = candidate.Version == model.StateVersion
		return nil
	}); err != nil || !called {
		t.Fatalf("err=%v called=%v", err, called)
	}
	if got := store.View(); got.ServiceID != "" || got.Initialized {
		t.Fatalf("reconciliation mutated state: %+v", got)
	}
}

func TestPersistenceFailureRollsBack(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	store.write = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	applied, rolledBack := false, false
	err = store.Transition(func(current model.State) (model.State, func() error, error) {
		applied = true
		current.ServiceID = strings.Repeat("a", 56)
		return current, func() error { rolledBack = true; return nil }, nil
	})
	if err == nil || !applied || !rolledBack {
		t.Fatalf("err=%v applied=%v rolledBack=%v", err, applied, rolledBack)
	}
	if store.View().ServiceID != "" {
		t.Fatal("failed state became visible")
	}
}

func TestRejectsMalformedState(t *testing.T) {
	for name, body := range map[string]string{
		"unknown":  `{"version":1,"mappings":[],"devices":[],"local_sessions":[],"agent_tokens":[],"surprise":true}`,
		"trailing": `{"version":1,"mappings":[],"devices":[],"local_sessions":[],"agent_tokens":[]} {}`,
		"version":  `{"version":99,"mappings":[],"devices":[],"local_sessions":[],"agent_tokens":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path); err == nil {
				t.Fatal("malformed state accepted")
			}
		})
	}
}

func TestAtomicWriteReplacesAndBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "value")
	if err := AtomicWrite(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "two" {
		t.Fatalf("got %q", data)
	}
	if err := AtomicWrite(path, make([]byte, MaxBytes+1), 0o600); err == nil {
		t.Fatal("oversized write accepted")
	}
}
