// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package onboarding

import (
	"bytes"
	"context"
	"encoding/json"
	"image/png"
	"net"
	"net/http"
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
	prepared, finished int
}

func (f *fakeControl) State() model.State                  { return f.state }
func (f *fakeControl) ExpirePending(context.Context) error { return nil }
func (f *fakeControl) PrepareCredentialChange() error      { f.prepared++; return nil }
func (f *fakeControl) FinishAuth(context.Context) error    { f.finished++; return nil }

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
		case "/login/api/firstfactor":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Domain: id + ".onion", Path: "/", Secure: true})
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
		case "/login/api/user/info":
			_, _ = w.Write([]byte(`{"status":"OK","data":{"has_totp":true}}`))
		case "/login/api/secondfactor/totp":
			_, _ = w.Write([]byte(`{"status":"OK"}`))
		case "/login/api/change-password":
			changed.Store(true)
			_, _ = w.Write([]byte(`{"status":"OK"}`))
		case "/login/api/secondfactor/totp/register":
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
	manager := New(control, client)
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
	values := []string{"https://" + strings.Repeat("a", 56) + ".onion/", "https://photos." + strings.Repeat("a", 56) + ".onion/", "http://" + strings.Repeat("a", 56) + ".onion?key=" + strings.Repeat("b", 52), "https://orbot.app/download/", "https://play.google.com/store/apps/details?id=org.torproject.android"}
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
