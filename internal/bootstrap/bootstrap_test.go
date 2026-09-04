// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"torkitten/internal/authelia"
	"torkitten/internal/model"
	"torkitten/internal/state"
)

type fakeLifecycle struct{ starts, stops int }

func (f *fakeLifecycle) StartAuthelia(context.Context) error { f.starts++; return nil }
func (f *fakeLifecycle) StopAuthelia(context.Context) error  { f.stops++; return nil }

type fakeFactors struct{ fail bool }

func (f fakeFactors) Verify(_ context.Context, user string, pass []byte, code string) error {
	if f.fail || user != "owner" || string(pass) != "long-enough-password" || code != "123456" {
		return errors.New("no")
	}
	return nil
}

type fakeInitializer struct{ record model.LocalSession }

func (f *fakeInitializer) Initialize(_ context.Context, record model.LocalSession) error {
	f.record = record
	return nil
}

type fakeIssuer struct{ now time.Time }

func (f fakeIssuer) Issue(owner string) (string, string, model.LocalSession, error) {
	r := model.LocalSession{ID: strings.Repeat("a", 32), Owner: owner, TokenHash: strings.Repeat("A", 43), CreatedAt: f.now, LastUseAt: f.now, AuthenticatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	return "cookie", "csrf", r, nil
}

func bootstrapPaths(root string) authelia.Paths {
	return authelia.Paths{Binary: "/usr/bin/authelia", Config: filepath.Join(root, "etc", "config.yml"), Users: filepath.Join(root, "state", "users.yml"), Database: filepath.Join(root, "state", "db.sqlite3"), SecretsDir: filepath.Join(root, "state", "secrets"), Socket: filepath.Join(root, "run", "authelia.sock"), QR: filepath.Join(root, "run", "totp.png"), Notifications: filepath.Join(root, "state", "notifications")}
}

func TestSetupFlow(t *testing.T) {
	root := t.TempDir()
	paths := bootstrapPaths(root)
	for _, dir := range []string{filepath.Dir(paths.Users), filepath.Dir(paths.Config), filepath.Dir(paths.QR)} {
		if err := state.EnsureDir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	life := &fakeLifecycle{}
	init := &fakeInitializer{}
	now := time.Unix(1_800_000_000, 0).UTC()
	manager := New(paths, life, fakeFactors{}, init, fakeIssuer{now: now})
	manager.now = func() time.Time { return now }
	manager.hash = func(context.Context, authelia.Paths, []byte) (string, error) {
		return "$argon2id$v=19$m=1,t=1,p=1$YWJj$ZGVm", nil
	}
	manager.generate = func(context.Context, string) error {
		return os.WriteFile(paths.QR, []byte(strings.Repeat("x", 128)), 0o600)
	}
	password := []byte("long-enough-password")
	flow, err := manager.Begin(context.Background(), false, "owner", password, append([]byte(nil), password...))
	if err != nil {
		t.Fatal(err)
	}
	if life.stops != 1 || life.starts != 1 || len(flow) != 43 {
		t.Fatalf("lifecycle=%+v flow=%q", life, flow)
	}
	if qr, err := manager.QR(flow); err != nil || len(qr) != 128 {
		t.Fatalf("QR: %d %v", len(qr), err)
	}
	cookie, csrf, err := manager.Complete(context.Background(), flow, "123456")
	if err != nil || cookie != "cookie" || csrf != "csrf" || init.record.Owner != "owner" {
		t.Fatalf("complete: %q %q %+v %v", cookie, csrf, init.record, err)
	}
	if _, err = manager.QR(flow); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("completed setup remained open")
	}
	if _, err = os.Stat(paths.QR); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("QR was not removed")
	}
}

func TestSetupRejectsBadInputsAndExpiry(t *testing.T) {
	manager := New(bootstrapPaths(t.TempDir()), &fakeLifecycle{}, fakeFactors{}, &fakeInitializer{}, fakeIssuer{})
	if _, err := manager.Begin(context.Background(), true, "owner", []byte("long-enough-password"), []byte("long-enough-password")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := manager.Begin(context.Background(), false, "Owner", []byte("short"), []byte("other")); err == nil {
		t.Fatal("bad setup accepted")
	}
}

func TestPinnedAutheliaHashCLI(t *testing.T) {
	binary := os.Getenv("TORKITTEN_AUTHELIA_BIN")
	if binary == "" {
		t.Skip("set TORKITTEN_AUTHELIA_BIN for pinned integration test")
	}
	paths := bootstrapPaths(t.TempDir())
	paths.Binary = binary
	if err := paths.EnsureFiles(); err != nil {
		t.Fatal(err)
	}
	data, err := paths.Render(strings.Repeat("a", 56))
	if err != nil {
		t.Fatal(err)
	}
	if err = state.AtomicWrite(paths.Config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	digest, err := HashPassword(ctx, paths, []byte("integration-password-42!"))
	if err != nil || !strings.HasPrefix(digest, "$argon2id$") || strings.Contains(digest, "integration-password") {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
}
