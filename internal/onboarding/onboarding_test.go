// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package onboarding

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"image/png"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"torkitten/internal/authelia"
	"torkitten/internal/model"
)

type fakeControl struct {
	state              model.State
	fail               bool
	prepared, finished int
}

func (f *fakeControl) State() model.State { return f.state }
func (f *fakeControl) PublicCA(context.Context) ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("public certificate")}), nil
}
func (f *fakeControl) ExpirePending(context.Context) error          { return nil }
func (f *fakeControl) PrepareCredentialChange() error               { f.prepared++; return nil }
func (f *fakeControl) FinishCredentialChange(context.Context) error { f.finished++; return nil }
func (f *fakeControl) SetBootstrap(_ context.Context, window *model.BootstrapWindow) error {
	if f.fail {
		return errors.New("load failed")
	}
	f.state.Bootstrap = window
	return nil
}

func onboardingFixture(t *testing.T) (*Manager, *fakeControl, *time.Time) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	control := &fakeControl{state: model.State{Version: model.StateVersion, Initialized: true, ServiceID: strings.Repeat("a", 56), Devices: []model.Device{{ID: strings.Repeat("a", 32)}}}}
	manager, err := New(control, nil, filepath.Join(t.TempDir(), "bootstrap"))
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	manager.random = bytes.NewReader(bytes.Repeat([]byte{4}, 128))
	return manager, control, &now
}

func TestBootstrapWindowLifecycle(t *testing.T) {
	manager, control, now := onboardingFixture(t)
	url, expires, err := manager.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "http://"+strings.Repeat("a", 56)+".onion/onboard/") || !expires.Equal(now.Add(WindowDuration)) {
		t.Fatalf("url=%q expires=%v", url, expires)
	}
	token := control.state.Bootstrap.Token
	for _, name := range []string{"index.html", "torkitten-ios.mobileconfig", "torkitten-root-ca.cer"} {
		if info, statErr := os.Stat(filepath.Join(manager.root, token, name)); statErr != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("file %s: %v %#o", name, statErr, info.Mode().Perm())
		}
	}
	certificate, err := os.ReadFile(filepath.Join(manager.root, token, "torkitten-root-ca.cer"))
	if err != nil || string(certificate) != "public certificate" {
		t.Fatalf("certificate=%q err=%v", certificate, err)
	}
	profile, err := os.ReadFile(filepath.Join(manager.root, token, "torkitten-ios.mobileconfig"))
	if err != nil || bytes.Contains(profile, []byte("CERTIFICATE_DATA")) || bytes.Contains(profile, []byte("SERVICE_ID")) || !bytes.Contains(profile, []byte("cHVibGljIGNlcnRpZmljYXRl")) {
		t.Fatalf("invalid profile: %v", err)
	}
	*now = now.Add(WindowDuration + time.Second)
	if err = manager.Expire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if control.state.Bootstrap != nil {
		t.Fatal("expired bootstrap remained active")
	}
	if _, err = os.Stat(filepath.Join(manager.root, token)); !os.IsNotExist(err) {
		t.Fatal("expired bootstrap files remained")
	}
}

func TestFailedCaddyLoadRemovesFiles(t *testing.T) {
	manager, control, _ := onboardingFixture(t)
	control.fail = true
	if _, _, err := manager.Open(context.Background()); err == nil {
		t.Fatal("failed load reported success")
	}
	entries, err := os.ReadDir(manager.root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
}

func TestNativePasswordAndTOTPChanges(t *testing.T) {
	root, id := t.TempDir(), strings.Repeat("a", 56)
	socket := filepath.Join(root, "authelia.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var changed, registered atomic.Bool
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firstfactor":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Domain: id + ".onion", Path: "/", Secure: true})
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
		case "/api/user/info":
			_, _ = w.Write([]byte(`{"status":"OK","data":{"has_totp":true}}`))
		case "/api/secondfactor/totp":
			_, _ = w.Write([]byte(`{"status":"OK"}`))
		case "/api/change-password":
			changed.Store(true)
			_, _ = w.Write([]byte(`{"status":"OK"}`))
		case "/api/secondfactor/totp/register":
			if r.Method == http.MethodPut {
				_, _ = w.Write([]byte(`{"status":"OK","data":{"otpauth_url":"otpauth://totp/Torkitten:owner?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&issuer=Torkitten"}}`))
			} else {
				registered.Store(true)
				_, _ = w.Write([]byte(`{"status":"OK"}`))
			}
		default:
			http.NotFound(w, r)
		}
	})}
	go server.Serve(listener)
	t.Cleanup(func() { _ = server.Close() })
	client, err := authelia.NewClient(socket, id)
	if err != nil {
		t.Fatal(err)
	}
	control := &fakeControl{state: model.State{Version: model.StateVersion, Initialized: true, ServiceID: id}}
	manager, err := New(control, client, filepath.Join(root, "bootstrap"))
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.ChangePassword(context.Background(), "owner", []byte("old-password-value"), []byte("new-password-value"), []byte("new-password-value"), "123456"); err != nil {
		t.Fatal(err)
	}
	image, err := manager.BeginTOTP(context.Background(), "owner", []byte("new-password-value"), "123456")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = png.Decode(bytes.NewReader(image)); err != nil {
		t.Fatal(err)
	}
	if registered.Load() {
		t.Fatal("replacement TOTP committed before confirmation")
	}
	if err = manager.CompleteTOTP(context.Background(), "654321"); err != nil {
		t.Fatal(err)
	}
	if !changed.Load() || !registered.Load() || control.prepared != 2 || control.finished != 2 {
		t.Fatalf("changed=%v registered=%v prepare=%d finish=%d", changed.Load(), registered.Load(), control.prepared, control.finished)
	}
	if _, err = manager.BeginTOTP(context.Background(), "owner", []byte("new-password-value"), "123456"); err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if err = manager.Expire(context.Background()); err != nil || manager.totp != nil {
		t.Fatal("expired TOTP registration remained")
	}
}

func TestEnrollmentQR(t *testing.T) {
	values := []string{"https://" + strings.Repeat("a", 56) + ".onion/", "http://" + strings.Repeat("a", 56) + ".onion?key=" + strings.Repeat("b", 52), "http://" + strings.Repeat("a", 56) + ".onion/onboard/" + strings.Repeat("A", 43) + "/"}
	for _, value := range values {
		data, err := EnrollmentQR(value)
		if err != nil {
			t.Fatal(err)
		}
		image, err := png.Decode(bytes.NewReader(data))
		if err != nil || image.Bounds().Dx() != 384 || image.Bounds().Dy() != 384 {
			t.Fatalf("invalid QR image: %v", err)
		}
	}
	if _, err := EnrollmentQR("secret"); err == nil {
		t.Fatal("invalid enrollment value accepted")
	}
}
