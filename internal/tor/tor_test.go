// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package tor

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"encoding/base32"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"torkitten/internal/model"
	"torkitten/internal/state"
)

func testPaths(root string) Paths {
	return Paths{Binary: "/usr/bin/tor", Config: filepath.Join(root, "etc", "torrc"), DataDir: filepath.Join(root, "state", "data"), HiddenServiceDir: filepath.Join(root, "state", "hs"), ControlSocket: filepath.Join(root, "run", "control.sock"), CookieFile: filepath.Join(root, "run", "cookie"), OnionHTTPSocket: filepath.Join(root, "run", "http.sock"), OnionTLSSocket: filepath.Join(root, "run", "tls.sock")}
}

func TestRenderPrivacyAndPublication(t *testing.T) {
	p := testPaths(t.TempDir())
	data, err := p.Render(false)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"SocksPort 0", "DisableNetwork 1", "PublishHidServDescriptors 0", "HiddenServicePort 80 unix:", "HiddenServicePort 443 unix:", "HiddenServiceStatistics 0", "HeartbeatPeriod 0", "CookieAuthentication 1"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	on, _ := p.Render(true)
	if !strings.Contains(string(on), "DisableNetwork 0") || !strings.Contains(string(on), "PublishHidServDescriptors 1") {
		t.Fatal("publication was not enabled")
	}
}

func TestClientKeyPairAndCredential(t *testing.T) {
	public, private, err := GenerateClientKey()
	if err != nil || len(public) != 52 || len(private) != 52 {
		t.Fatalf("public=%q private length=%d err=%v", public, len(private), err)
	}
	decode := base32.StdEncoding.WithPadding(base32.NoPadding)
	privateRaw, err := decode.DecodeString(strings.ToUpper(private))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey(privateRaw)
	if err != nil || strings.ToLower(decode.EncodeToString(key.PublicKey().Bytes())) != public {
		t.Fatal("public key does not correspond to private key")
	}
	id := strings.Repeat("a", 56)
	credential, err := Credential(id, private)
	if err != nil || credential != id+":descriptor:x25519:"+private {
		t.Fatal("invalid credential formatting")
	}
}

func TestAuthorizationReconciliation(t *testing.T) {
	p := testPaths(t.TempDir())
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(p.AuthDir(), strings.Repeat("f", 32)+".auth")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	device := model.Device{ID: strings.Repeat("a", 32), PublicKey: strings.Repeat("a", 52)}
	if err := p.Reconcile([]model.Device{device}, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(p.AuthDir(), device.ID+".auth"))
	if err != nil || string(data) != "descriptor:x25519:"+device.PublicKey+"\n" {
		t.Fatalf("auth file: %q %v", data, err)
	}
	if _, err = os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale authorization remained")
	}
}

func TestCookieAuthenticatedControl(t *testing.T) {
	root := t.TempDir()
	socket, cookiePath := filepath.Join(root, "control.sock"), filepath.Join(root, "cookie")
	cookie := strings.Repeat("x", 32)
	if err := os.WriteFile(cookiePath, []byte(cookie), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		line, _ := r.ReadString('\n')
		if line != "AUTHENTICATE "+fmt.Sprintf("%x", cookie)+"\r\n" {
			done <- fmt.Errorf("authentication line %q", line)
			return
		}
		_, _ = conn.Write([]byte("250 OK\r\n"))
		line, _ = r.ReadString('\n')
		if line != "SIGNAL RELOAD\r\n" {
			done <- fmt.Errorf("command line %q", line)
			return
		}
		_, _ = conn.Write([]byte("250 OK\r\n"))
		done <- nil
	}()
	if err = (Client{Socket: socket, Cookie: cookiePath}).Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRecoverIdentityAfterInterruptedRotation(t *testing.T) {
	p := testPaths(t.TempDir())
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	oldID, newID := strings.Repeat("a", 56), strings.Repeat("b", 56)
	if err := os.WriteFile(filepath.Join(p.HiddenServiceDir, "hostname"), []byte(newID+".onion\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := p.HiddenServiceDir + ".previous"
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "hostname"), []byte(oldID+".onion\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(filepath.Dir(p.HiddenServiceDir), ".identity-stage-test")
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := p.RecoverIdentity(oldID); err != nil {
		t.Fatal(err)
	}
	if got, err := p.ServiceID(); err != nil || got != oldID {
		t.Fatalf("identity=%q err=%v", got, err)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatal("backup remained")
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatal("staged private identity remained")
	}
}

func TestPinnedTorIdentityAndReload(t *testing.T) {
	binary := os.Getenv("TORKITTEN_TOR_BIN")
	if binary == "" {
		t.Skip("set TORKITTEN_TOR_BIN for pinned integration test")
	}
	p := testPaths(t.TempDir())
	p.Binary = binary
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	public, _, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	// Either 32-byte X25519 value is syntactically accepted as an authorization key.
	if err = p.WriteAuthorization(strings.Repeat("a", 32), public); err != nil {
		t.Fatal(err)
	}
	config, _ := p.Render(false)
	if err = state.AtomicWrite(p.Config, config, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = p.Validate(ctx); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "-f", p.Config)
	cmd.Env = cleanEnvironment(os.Environ())
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if _, err = p.WaitServiceID(ctx); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = os.Stat(p.CookieFile); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err = (Client{Socket: p.ControlSocket, Cookie: p.CookieFile}).Reload(ctx); err != nil {
		t.Fatal(err)
	}
	stage, err := p.StageIdentity(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if current, _ := p.ServiceID(); stage.ServiceID == current {
		t.Fatal("staged identity did not rotate")
	}
	_ = os.RemoveAll(stage.Root)
}
