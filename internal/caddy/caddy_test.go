// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"torkitten/internal/model"
)

func testRenderer(root string) Renderer {
	return Renderer{
		AdminSocket: filepath.Join(root, "admin.sock"), OnionTLSSocket: filepath.Join(root, "tls.sock"),
		OnionHTTPSocket: filepath.Join(root, "http.sock"), AutheliaSocket: filepath.Join(root, "authelia.sock"),
		LauncherRoot: filepath.Join(root, "launcher"),
		StorageRoot:  filepath.Join(root, "storage"), TargetHost: "host.containers.internal",
	}
}

func renderState() model.State {
	s := model.NewState()
	s.ServiceID = strings.Repeat("a", 56)
	s.Initialized = true
	s.Mappings = []model.Mapping{
		{Prefix: "zeta", Port: 9000, Protocol: model.ProtocolHTTP, Enabled: false},
		{Prefix: "api", Port: 7777, Protocol: model.ProtocolH2C, Enabled: true},
	}
	return s
}

func TestRenderDeterministicAndFailClosed(t *testing.T) {
	r := testRenderer(t.TempDir())
	r.PublicRoot = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("public root")})
	first, err := r.Render(renderState())
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Render(renderState())
	if err != nil || string(first) != string(second) {
		t.Fatal("render is not deterministic")
	}
	text := string(first)
	for _, required := range []string{
		"https://:443", "https://*." + strings.Repeat("a", 56) + ".onion", "lifetime 9528h", "intermediate_lifetime 17520h", "respond \"not found\" 404", "forward_auth unix/", "uri /login/api/authz/forward-auth", "path /login /login/", "respond @apps", "/trust/torkitten-root-ca.pem",
		"request_header -Remote-User", "request_header -X-Forwarded-For", "reverse_proxy h2c://host.containers.internal:7777",
		"group:torkitten-owner", // must not occur: checked below.
	} {
		if required == "group:torkitten-owner" {
			if strings.Contains(text, required) {
				t.Fatal("Caddy renderer implemented Authelia authorization policy")
			}
			continue
		}
		if !strings.Contains(text, required) {
			t.Errorf("missing %q", required)
		}
	}
	if strings.Contains(text, "zeta."+strings.Repeat("a", 56)) {
		t.Fatal("disabled mapping was routed")
	}
	if strings.Contains(text, "sign_with_root") {
		t.Fatal("intermediate-signing trial still enables direct-root signing")
	}
	if strings.Contains(text, "/login/api/change-password") || strings.Contains(text, "/login/api/secondfactor/totp/register") || !strings.Contains(text, "method GET HEAD POST") {
		t.Fatal("uncoordinated credential mutation was exposed")
	}
}

func TestUninitializedAndHTTPDeny(t *testing.T) {
	r := testRenderer(t.TempDir())
	s := model.NewState()
	s.ServiceID = strings.Repeat("a", 56)
	data, err := r.Render(s)
	if err != nil || strings.Contains(string(data), "forward_auth") {
		t.Fatalf("uninitialized config: %v\n%s", err, data)
	}
	s.Initialized = true
	s.Bootstrap = &model.BootstrapWindow{Token: strings.Repeat("A", 43), ExpiresAt: time.Now().Add(time.Minute)}
	data, err = r.Render(s)
	if err != nil || strings.Contains(string(data), "/onboard/") || !strings.Contains(string(data), "http://:80") {
		t.Fatalf("HTTP was not denied: %v", err)
	}
}

func TestClientAdaptsThenLoads(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "caddy.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var paths []string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path+":"+r.Header.Get("Content-Type"))
		mu.Unlock()
		switch r.URL.Path {
		case "/adapt":
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"admin": map[string]any{}}})
		case "/load":
			w.WriteHeader(http.StatusOK)
		case "/config/":
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	client, err := NewClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Apply(context.Background(), []byte("example.test { respond ok }")); err != nil {
		t.Fatal(err)
	}
	if err = client.Healthy(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"/adapt:text/caddyfile", "/load:application/json", "/config/:"}
	if strings.Join(paths, "|") != strings.Join(want, "|") {
		t.Fatalf("requests %v", paths)
	}
}

func TestPinnedCaddyTLSAndForwardAuth(t *testing.T) {
	binary := os.Getenv("TORKITTEN_CADDY_BIN")
	if binary == "" {
		t.Skip("set TORKITTEN_CADDY_BIN for pinned integration test")
	}
	root := t.TempDir()
	renderer := testRenderer(root)
	renderer.TargetHost = "127.0.0.1"
	for _, dir := range []string{renderer.LauncherRoot, renderer.StorageRoot} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(renderer.LauncherRoot, "index.html"), []byte("protected launcher"), 0o600); err != nil {
		t.Fatal(err)
	}
	var authorized, spoofed, metadata atomic.Bool
	authListener, err := net.Listen("unix", renderer.AutheliaSocket)
	if err != nil {
		t.Fatal(err)
	}
	authServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Remote-User") == "attacker" {
			spoofed.Store(true)
		}
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" && r.Header.Get("X-Forwarded-Proto") == "https" {
			metadata.Store(true)
		}
		if !authorized.Load() {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Remote-User", "owner")
		w.WriteHeader(http.StatusOK)
	})}
	go authServer.Serve(authListener)
	defer authServer.Close()
	state := renderState()
	state.Mappings = nil
	state.Bootstrap = &model.BootstrapWindow{Token: strings.Repeat("A", 43), ExpiresAt: time.Now().Add(time.Minute)}
	config, err := renderer.Render(state)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "Caddyfile")
	if err = os.WriteFile(path, config, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "--config", path, "--adapter", "caddyfile")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	client, err := NewClient(renderer.AdminSocket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for client.Healthy(ctx) != nil {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	time.Sleep(500 * time.Millisecond)
	publicRoot, err := client.RootCA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(publicRoot) {
		t.Fatal("Caddy returned an unusable root certificate")
	}
	leaf := func(host string) []byte {
		raw, dialErr := (&net.Dialer{}).DialContext(ctx, "unix", renderer.OnionTLSSocket)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		conn := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: roots})
		if dialErr = conn.Handshake(); dialErr != nil {
			t.Fatal(dialErr)
		}
		chains := conn.ConnectionState().VerifiedChains
		if len(chains) == 0 || len(chains[0]) != 3 {
			t.Fatal("Caddy did not provide a verifiable leaf/intermediate/root chain")
		}
		certificate, intermediate, root := chains[0][0], chains[0][1], chains[0][2]
		if certificate.CheckSignatureFrom(intermediate) != nil || intermediate.CheckSignatureFrom(root) != nil || certificate.CheckSignatureFrom(root) == nil {
			t.Fatal("website certificate was not signed exclusively through the intermediate")
		}
		if certificate.NotAfter.Sub(certificate.NotBefore) != 397*24*time.Hour || intermediate.NotAfter.Sub(intermediate.NotBefore) != 730*24*time.Hour || certificate.NotAfter.After(intermediate.NotAfter) {
			t.Fatal("unexpected native certificate lifetimes")
		}
		_ = conn.Close()
		return certificate.Raw
	}
	baseLeaf := leaf(state.Host(""))
	if first, second := leaf(state.Host("photos")), leaf(state.Host("api")); !bytes.Equal(first, second) {
		t.Fatal("prefixed hosts did not share the wildcard leaf certificate")
	}
	request := func(path string, secure bool) (int, string, http.Header) {
		socket := renderer.OnionHTTPSocket
		if secure {
			socket = renderer.OnionTLSSocket
		}
		raw, dialErr := (&net.Dialer{}).DialContext(ctx, "unix", socket)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		var conn net.Conn = raw
		if secure {
			conn = tls.Client(raw, &tls.Config{ServerName: state.Host(""), RootCAs: roots})
		}
		if _, dialErr = io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: "+state.Host("")+"\r\nRemote-User: attacker\r\nConnection: close\r\n\r\n"); dialErr != nil {
			t.Fatal(dialErr)
		}
		response, readErr := http.ReadResponse(bufio.NewReader(conn), nil)
		if readErr != nil {
			t.Fatal(readErr)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		conn.Close()
		return response.StatusCode, string(body), response.Header
	}
	bootstrapPath := "/onboard/" + state.Bootstrap.Token + "/"
	if status, _, _ := request(bootstrapPath, false); status != http.StatusNotFound {
		t.Fatalf("unexpected HTTP onboarding route status=%d", status)
	}
	if status, _, _ := request("/", false); status != http.StatusNotFound {
		t.Fatalf("unexpected HTTP route status=%d", status)
	}
	if status, body, _ := request("/", true); status == http.StatusOK || strings.Contains(body, "protected launcher") {
		t.Fatal("authorization failure exposed launcher")
	}
	if spoofed.Load() {
		t.Fatal("caller identity reached Authelia")
	}
	if !metadata.Load() {
		t.Fatal("constructed authorization metadata missing")
	}
	authorized.Store(true)
	if status, body, _ := request("/", true); status != http.StatusOK || !strings.Contains(body, "protected launcher") {
		t.Fatalf("status=%d body=%q", status, body)
	}
	renderer.PublicRoot = publicRoot
	config, err = renderer.Render(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Apply(ctx, config); err != nil {
		t.Fatal(err)
	}
	authorized.Store(false)
	if status, _, _ := request("/trust/torkitten-root-ca.pem", true); status == http.StatusOK {
		t.Fatal("authorization failure exposed public root")
	}
	authorized.Store(true)
	if status, body, header := request("/trust/torkitten-root-ca.pem", true); status != http.StatusOK || string(publicRoot) != body || header.Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("root download status=%d type=%q", status, header.Get("Content-Type"))
	}
	if err = client.Load(ctx, []byte(`{"invalid":`)); err == nil {
		t.Fatal("invalid load succeeded")
	}
	if status, _, _ := request("/", true); status != http.StatusOK {
		t.Fatal("failed load replaced working configuration")
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	cmd = exec.Command(binary, "run", "--config", path, "--adapter", "caddyfile")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for client.Healthy(ctx) != nil {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	rootAfterRestart, err := client.RootCA(ctx)
	if err != nil || !bytes.Equal(publicRoot, rootAfterRestart) || !bytes.Equal(baseLeaf, leaf(state.Host(""))) {
		t.Fatal("Caddy restart did not retain the root and intermediate-signed leaf")
	}
}

func TestClientRejectsWarningsAndOversize(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "caddy.sock")
	listener, _ := net.Listen("unix", socket)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/adapt" {
			_, _ = w.Write([]byte(`{"warnings":[{"message":"bad"}],"result":{}}`))
			return
		}
		_, _ = w.Write(make([]byte, maxResponse+1))
	})}
	go server.Serve(listener)
	defer server.Close()
	client, _ := NewClient(socket)
	if _, err := client.Adapt(context.Background(), nil); err == nil {
		t.Fatal("warnings accepted")
	}
	if _, err := client.request(context.Background(), http.MethodGet, "/large", "", nil); err == nil {
		t.Fatal("oversized response accepted")
	}
}
