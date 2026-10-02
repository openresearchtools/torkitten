// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// TestLiveApp is opt-in: it starts real pinned Tor, Caddy and Authelia, and uses
// public Tor relays. All actions use the same private Unix API as the native UI.
// TORKITTEN_APP_PROOF must name a fresh directory below V2Build/proofs; APP_BIN
// must contain the packaged torkitten/tor/caddy/authelia binaries. Never use live state.
func TestLiveApp(t *testing.T) {
	work := os.Getenv("TORKITTEN_APP_PROOF")
	bin := os.Getenv("TORKITTEN_APP_BIN")
	if work == "" {
		t.Skip("set TORKITTEN_APP_PROOF and TORKITTEN_APP_BIN for real Tor proof")
	}
	if os.Geteuid() == 0 {
		t.Fatal("live app proof requires the unprivileged host user and its systemd user manager")
	}
	if !filepath.IsAbs(work) || filepath.Clean(work) != work || !strings.HasPrefix(work, "/run/media/user/Data/TorkittenV2Build/proofs/") || !filepath.IsAbs(bin) {
		t.Fatal("fresh private external proof path and absolute binary directory required")
	}
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal("proof directory must be fresh:", err)
	}
	for _, name := range []string{"tor", "caddy", "authelia", "torkitten", "sshd", "sshd-session", "sshd-auth"} {
		if st, err := os.Stat(filepath.Join(bin, name)); err != nil || st.Mode()&0111 == 0 {
			t.Fatalf("missing executable %s", name)
		}
	}
	hashes := map[string]string{}
	for _, name := range []string{"tor", "caddy", "authelia", "torkitten", "sshd", "sshd-session", "sshd-auth"} {
		data, err := os.ReadFile(filepath.Join(bin, name))
		if err != nil {
			t.Fatal(err)
		}
		hashes[name] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	started := time.Now()
	checks := []string{}
	success := false
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	var host, client, qrClient *App
	var hostDaemon, clientDaemon *process
	defer func() {
		if clientDaemon != nil {
			clientDaemon.stop()
		}
		if hostDaemon != nil {
			hostDaemon.stop()
		}
		if client != nil {
			client.Close()
		}
		if qrClient != nil {
			qrClient.Close()
		}
		if host != nil {
			host.Close()
		}
		// Only this fresh proof's generated credentials/state are erased. Keep a
		// sanitized result and private component logs, never onboarding or tokens.
		for _, name := range []string{"host", "client", "qr-client"} {
			root := filepath.Join(work, name)
			filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() && strings.HasSuffix(path, ".log") {
					data, _ := os.ReadFile(path)
					_ = os.WriteFile(filepath.Join(work, name+"-"+filepath.Base(filepath.Dir(path))+"-"+filepath.Base(path)), data, 0600)
				}
				return nil
			})
			os.RemoveAll(root)
		}
		os.Remove(filepath.Join(work, "ssh-client.key"))
		os.Remove(filepath.Join(work, "known_hosts"))
		result := map[string]any{"passed": success, "duration_seconds": time.Since(started).Seconds(), "upstream_sha256": hashes, "checks": checks, "scope": "real app Unix API, public Tor onion/client authorization, Caddy verified TLS/mTLS, Authelia password+TOTP+OAuth PAR/PKCE explicit consent, QR-only onboarding after local2FA, Chisel WSS/SSH, stock host SSH, systemd user command, complete identity rotation and packaged daemon restart; headless, not GTK"}
		body, _ := json.MarshalIndent(result, "", "  ")
		os.WriteFile(filepath.Join(work, "results.json"), append(body, '\n'), 0600)
	}()
	check := func(name string) { checks = append(checks, name); t.Log("PASS", name) }
	t.Log("starting isolated host/client applications")
	var err error
	host, err = Open(ctx, filepath.Join(work, "host"), bin)
	if err != nil {
		t.Fatal("host open:", err)
	}
	client, err = Open(ctx, filepath.Join(work, "client"), bin)
	if err != nil {
		t.Fatal("client open:", err)
	}
	hostAPI, clientAPI := liveAPI(t, host), liveAPI(t, client)
	password := "proof QR password " + randomID()
	var credentials struct{ Username, Password, TOTPQR string }
	var secret string
	usedCodes := map[string]string{}
	nextCode := func(secret string) string {
		for {
			code := liveTOTP(secret)
			if code != usedCodes[secret] {
				usedCodes[secret] = code
				return code
			}
			select {
			case <-ctx.Done():
				t.Fatal("fresh TOTP timed out")
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	beginIdentity := func() {
		var v map[string]string
		liveCall(t, hostAPI, "POST", "/api/identity", map[string]any{"password": password, "confirm": true}, &v, 200)
		credentials.Username, credentials.Password, credentials.TOTPQR = v["username"], v["password"], v["totp_qr"]
		if credentials.Username == "" || credentials.Password == "" || credentials.TOTPQR == "" || v["qr"] != "" {
			t.Fatal("initial setup did not restrict output to new owner credentials/TOTP")
		}
		secret = liveTOTPSecret(t, credentials.TOTPQR)
		if host.host.Enrolled || !strings.Contains(host.torServerConfig(), "PublishHidServDescriptors 0") {
			t.Fatal("unconfirmed setup published a connection")
		}
		liveCall(t, hostAPI, "POST", "/api/qr", map[string]any{}, nil, 400)
	}
	identity := func() string {
		beginIdentity()
		var confirmed map[string]string
		liveCall(t, hostAPI, "POST", "/api/identity-confirm", map[string]any{"totp": nextCode(secret)}, &confirmed, 200)
		if len(confirmed) != 1 || confirmed["qr"] == "" || !host.host.Enrolled {
			t.Fatal("local upstream 2FA did not release only the encrypted connection QR")
		}
		var shown map[string]string
		liveCall(t, hostAPI, "POST", "/api/qr", map[string]any{}, &shown, 200)
		if shown["qr"] != confirmed["qr"] {
			t.Fatal("show QR reissued connection credentials")
		}
		return confirmed["qr"]
	}
	beginIdentity()
	hostRootBeforeSetup := host.root
	host.Close()
	hostAPI.CloseIdleConnections()
	host, err = Open(ctx, hostRootBeforeSetup, bin)
	if err != nil {
		t.Fatal("restart unconfirmed host", err)
	}
	hostAPI = liveAPI(t, host)
	liveCall(t, hostAPI, "POST", "/api/identity-confirm", map[string]any{"totp": nextCode(secret)}, nil, 400)
	liveCall(t, hostAPI, "POST", "/api/qr", map[string]any{}, nil, 400)
	if host.host.Enrolled {
		t.Fatal("unconfirmed restart enabled remote access")
	}
	check("unconfirmed host restart remains closed and does not retain setup password")
	connectionQR := identity()
	check("fresh identity requires actual local Authelia 2FA before encrypted QR publication")
	rawTCP := liveEcho(t, "tcp", work)
	rawUnix := liveEcho(t, "unix", work)
	marker := filepath.Join(work, "explicit-action.marker")
	services := Services{Version: 2, SSH: true, Services: []Service{
		{ID: "tcp", Title: "Opaque TCP", Available: true, Endpoint: rawTCP, Command: "/usr/bin/touch " + marker},
		{ID: "unix", Title: "Opaque Unix", Available: true, Endpoint: rawUnix, Command: "/usr/bin/sleep 1800"},
	}}
	liveCall(t, hostAPI, "POST", "/api/config", map[string]any{"services": services}, nil, 200)
	image, err := base64.StdEncoding.DecodeString(connectionQR)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := decodeQR(image)
	if err != nil || !bytes.HasPrefix(encrypted, []byte("age-encryption.org/v1")) {
		t.Fatal("connection QR did not contain an age ciphertext")
	}
	if bytes.Contains(encrypted, []byte(".onion")) || bytes.Contains(encrypted, []byte("PRIVATE KEY")) {
		t.Fatal("connection QR contains plaintext credentials")
	}
	var recognition map[string]any
	liveCall(t, clientAPI, "POST", "/api/scan-qr", map[string]any{"data": connectionQR}, &recognition, 200)
	if len(recognition) != 1 || recognition["found"] != true {
		t.Fatal("scanner exposed more than recognition status")
	}
	liveCall(t, clientAPI, "POST", "/api/import", map[string]any{"data": base64.StdEncoding.EncodeToString(encrypted), "password": password}, nil, 404)
	liveCall(t, clientAPI, "POST", "/api/import-qr", map[string]any{"data": connectionQR, "password": "incorrect password"}, nil, 400)
	var imported map[string]string
	liveCall(t, clientAPI, "POST", "/api/import-qr", map[string]any{"data": connectionQR, "password": password}, &imported, 200)
	id := imported["id"]
	if id == "" || client.profiles[id].cache.Bundle.Owner != credentials.Username {
		t.Fatal("QR did not bind the generated owner")
	}
	check("QR-only import rejects wrong password; scanner returns no credential bytes")
	qrClient, err = Open(ctx, filepath.Join(work, "qr-client"), bin)
	if err != nil {
		t.Fatal("second QR client open", err)
	}
	var qrImported map[string]string
	liveCall(t, liveAPI(t, qrClient), "POST", "/api/import-qr", map[string]any{"data": connectionQR, "password": password}, &qrImported, 200)
	if qrImported["id"] != id {
		t.Fatal("same owner QR changed connection identity on another client")
	}
	qrClient.Close()
	check("one encrypted owner QR imports independently on another client")
	livePrivateTLS(t, host, client.profiles[id])
	livePrivateListeners(t, host)
	livePrivateListeners(t, client)
	check("private gateway verifies TLS and device mTLS before Tor publication readiness")
	liveOnionReady(t, ctx, client, id)
	livePrivateListeners(t, host)
	livePrivateListeners(t, client)
	check("real authorized onion reachable through strict Tor TLS/mTLS")
	check("actual upstream components expose only private Unix listeners")
	liveNoCertificate(t, client.profiles[id])
	check("actual gateway TLS rejects a connection without its device certificate")
	liveRemoteDenied(t, client.profiles[id], "")
	check("gateway rejects application requests without OAuth bearer")
	liveCall(t, clientAPI, "GET", "/api/services?id="+id, nil, nil, 400)
	login := func(profile string) {
		var consent struct {
			Gateway string   `json:"gateway"`
			Scopes  []string `json:"scopes"`
		}
		liveCall(t, clientAPI, "POST", "/api/login", map[string]any{"id": profile, "password": credentials.Password, "totp": nextCode(secret)}, &consent, 200)
		if !strings.HasPrefix(consent.Gateway, "https://") || len(consent.Scopes) != 2 {
			t.Fatal("explicit consent details absent")
		}
		liveCall(t, clientAPI, "GET", "/api/services?id="+profile, nil, nil, 400)
		liveCall(t, clientAPI, "POST", "/api/consent", map[string]any{"id": profile, "accept": true}, nil, 200)
	}
	login(id)
	check("real password+TOTP, PAR, PKCE and explicit OAuth consent")
	var listing struct {
		Services []ViewService `json:"services"`
	}
	liveCall(t, clientAPI, "GET", "/api/services?id="+id, nil, &listing, 200)
	if len(listing.Services) != 3 {
		t.Fatalf("service count %d", len(listing.Services))
	}
	mapService := func(service string, port int) int {
		var out map[string]int
		liveCall(t, clientAPI, "POST", "/api/map", map[string]any{"id": id, "service": service, "enabled": true, "port": port}, &out, 200)
		if out["port"] <= 0 {
			t.Fatal("assigned port absent")
		}
		return out["port"]
	}
	tcpPort := mapService("tcp", 0)
	unixPort := mapService("unix", 0)
	if l, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort)); e == nil {
		l.Close()
		t.Fatal("Auto listener not held")
	}
	payload := make([]byte, 128<<10)
	rand.Read(payload)
	var wg sync.WaitGroup
	for _, port := range []int{tcpPort, tcpPort, unixPort} {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			got, e := liveExchange(port, payload)
			if e != nil || !bytes.Equal(got, payload) {
				t.Errorf("opaque native stream failed: got %d, error %v", len(got), e)
			}
		}(port)
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	check("concurrent byte-identical TCP and Unix streams on native Auto ports")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	manualPort := l.Addr().(*net.TCPAddr).Port
	l.Close()
	sshPort := mapService("host-ssh", manualPort)
	if sshPort != manualPort {
		t.Fatal("manual SSH port changed")
	}
	sshCtx, sshCancel := context.WithTimeout(ctx, 45*time.Second)
	command := exec.CommandContext(sshCtx, "/usr/bin/ssh", "-F", filepath.Join(client.profiles[id].sshDirectory(), "config"), "torkitten", "/usr/bin/cat")
	command.Stdin = bytes.NewReader(payload)
	out, err := command.Output()
	sshCancel()
	if err != nil || !bytes.Equal(out, payload) {
		t.Fatal("actual packaged OpenSSH through managed native config failed", err)
	}
	oldSSHHostKey, err := os.ReadFile(host.gen("ssh.host.pub"))
	if err != nil {
		t.Fatal(err)
	}
	oldSSHLoginKey, e := os.ReadFile(host.gen("ssh.login.pub"))
	if e != nil {
		t.Fatal(e)
	}
	check("actual bundled OpenSSH host exec and binary stdin/stdout through managed manual port")
	liveCall(t, clientAPI, "POST", "/api/action", map[string]any{"id": id, "service": "tcp", "action": "load"}, nil, 200)
	actionDeadline := time.Now().Add(10 * time.Second)
	for {
		if _, e := os.Stat(marker); e == nil {
			break
		}
		if time.Now().After(actionDeadline) {
			t.Fatal("host command not executed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	check("remote Load executes the exact host command through systemd user service")
	held := liveOpenEcho(t, tcpPort)
	services.Services[0].Available = false
	liveCall(t, hostAPI, "POST", "/api/config", map[string]any{"services": services}, nil, 200)
	liveClosed(t, held)
	liveCall(t, clientAPI, "GET", "/api/services?id="+id, nil, &listing, 200)
	if len(listing.Services) != 2 {
		t.Fatal("unavailable service still listed")
	}
	check("availability disable closes its existing streams without unrelated logout")
	services.Services[0].Available = true
	liveCall(t, hostAPI, "POST", "/api/config", map[string]any{"services": services}, nil, 200)
	held = liveOpenEcho(t, unixPort)
	oldCredentials := client.profiles[id].cache.Token
	oldOAuth := client.profiles[id].oauth
	oldToken := oldCredentials.AccessToken
	liveCall(t, hostAPI, "POST", "/api/revoke", map[string]any{}, nil, 200)
	liveClosed(t, held)
	liveRemoteDenied(t, client.profiles[id], oldToken)
	if _, err = oldOAuth.Refresh(ctx, oldCredentials); err == nil {
		t.Fatal("revoked OAuth registration accepted old refresh token")
	}
	liveCall(t, clientAPI, "GET", "/api/services?id="+id, nil, nil, 400)
	liveCall(t, clientAPI, "POST", "/api/login", map[string]any{"id": id, "username": credentials.Username, "password": credentials.Password, "totp": ""}, nil, 400)
	login(id)
	check("global revoke closes carriers, rejects old tokens and requires fresh 2FA consent")
	unixPort = mapService("unix", 0)
	held = liveOpenEcho(t, unixPort)
	services.SSH = false
	liveCall(t, hostAPI, "POST", "/api/config", map[string]any{"services": services}, nil, 200)
	liveClosed(t, held)
	liveCall(t, clientAPI, "GET", "/api/services?id="+id, nil, nil, 400)
	check("host SSH capability change revokes active and future old-session access")
	oldProfile := client.profiles[id]
	oldHTTP := oldProfile.HTTP
	oldBundle := oldProfile.cache.Bundle
	oldOnion := oldBundle.Onion
	oldOwner, oldPassword, oldTOTP := credentials.Username, credentials.Password, secret
	connectionQR = identity()
	if credentials.Username == oldOwner || credentials.Password == oldPassword || secret == oldTOTP {
		t.Fatal("identity reset reused owner credentials or TOTP")
	}
	if !bytes.Equal(mustJSON(services), mustJSON(host.services)) {
		t.Fatal("identity reset changed host services")
	}
	rejectCtx, rejectCancel := context.WithTimeout(ctx, 10*time.Second)
	request, _ := http.NewRequestWithContext(rejectCtx, "GET", "https://"+oldOnion+"/api/info", nil)
	response, oldErr := oldHTTP.Do(request)
	if response != nil {
		response.Body.Close()
	}
	rejectCancel()
	if oldErr == nil {
		t.Fatal("old identity remained reachable")
	}
	check("identity rotation invalidates old onion, credentials and trust while preserving service configurations")
	services.SSH = true
	liveCall(t, hostAPI, "POST", "/api/config", map[string]any{"services": services}, nil, 200)
	newSSHHostKey, e := os.ReadFile(host.gen("ssh.host.pub"))
	newSSHLoginKey, loginErr := os.ReadFile(host.gen("ssh.login.pub"))
	if e != nil || loginErr != nil || bytes.Equal(newSSHHostKey, oldSSHHostKey) || bytes.Equal(newSSHLoginKey, oldSSHLoginKey) {
		t.Fatal("identity reset reused SSH host key")
	}
	liveCall(t, clientAPI, "POST", "/api/import-qr", map[string]any{"data": connectionQR, "password": password, "name": "new identity"}, &imported, 200)
	id = imported["id"]
	if len(client.PublicProfiles()) != 2 {
		t.Fatal("distinct onion profiles were not retained independently")
	}
	newBundle := client.profiles[id].cache.Bundle
	if newBundle.Onion == oldBundle.Onion || newBundle.RootCA == oldBundle.RootCA || newBundle.Fingerprint == oldBundle.Fingerprint || newBundle.TorPrivate == oldBundle.TorPrivate || newBundle.Certificate == oldBundle.Certificate || newBundle.PrivateKey == oldBundle.PrivateKey || newBundle.Owner == oldBundle.Owner {
		t.Fatal("identity rotation retained old trust or credentials")
	}
	livePrivateTLS(t, host, client.profiles[id])
	liveOnionReady(t, ctx, client, id)
	livePrivateListeners(t, host)
	livePrivateListeners(t, client)
	login(id)
	unixPort = mapService("unix", 0)
	out, err = liveExchange(unixPort, payload)
	if err != nil || !bytes.Equal(out, payload) {
		t.Fatal("new identity stream failed", err)
	}
	check("new identity requires new onboarding and fresh OAuth, then carries original service")
	check("multiple distinct-onion profiles retained independently")
	var beforeRestart struct {
		Host     HostState `json:"host"`
		Services Services  `json:"services"`
	}
	liveCall(t, hostAPI, "GET", "/api/state", nil, &beforeRestart, 200)
	hostRoot, clientRoot := host.root, client.root
	oldHostRun, oldClientRun := host.run, client.run
	held = liveOpenEcho(t, unixPort)
	client.Close()
	liveClosed(t, held)
	host.Close()
	hostAPI.CloseIdleConnections()
	clientAPI.CloseIdleConnections()
	t.Log("restarting packaged host and client daemon processes on persisted state")
	hostDaemon = liveDaemon(t, ctx, bin, hostRoot, filepath.Join(work, "host-restarted.log"))
	clientDaemon = liveDaemon(t, ctx, bin, clientRoot, filepath.Join(work, "client-restarted.log"))
	hostAPI, clientAPI = liveAPI(t, &App{root: hostRoot}), liveAPI(t, &App{root: clientRoot})
	var afterRestart struct {
		Host     HostState       `json:"host"`
		Services Services        `json:"services"`
		Profiles []ProfileStatus `json:"profiles"`
	}
	liveCall(t, hostAPI, "GET", "/api/state", nil, &afterRestart, 200)
	if !afterRestart.Host.Initialized || !afterRestart.Host.Enrolled || afterRestart.Host.Generation != beforeRestart.Host.Generation || afterRestart.Host.Onion != beforeRestart.Host.Onion || afterRestart.Host.OAuthClient != beforeRestart.Host.OAuthClient {
		t.Fatal("host identity or OAuth registration changed on restart")
	}
	beforeServices, _ := json.Marshal(beforeRestart.Services)
	afterServices, _ := json.Marshal(afterRestart.Services)
	if !bytes.Equal(beforeServices, afterServices) {
		t.Fatal("host services changed on restart")
	}
	for _, state := range []struct{ root, oldRun string }{{hostRoot, oldHostRun}, {clientRoot, oldClientRun}} {
		torrc, err := os.ReadFile(filepath.Join(state.root, "client-torrc"))
		if err != nil {
			t.Fatal(err)
		}
		var socket string
		for _, line := range strings.Split(string(torrc), "\n") {
			if strings.HasPrefix(line, "SocksPort unix:") {
				socket = strings.TrimPrefix(line, "SocksPort unix:")
			}
		}
		if socket == "" || filepath.Dir(socket) == state.oldRun {
			t.Fatal("restart did not replace its private runtime sockets")
		}
		st, err := os.Stat(socket)
		if err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm()&0077 != 0 {
			t.Fatal("restarted Tor socket is not private")
		}
		if _, err := os.Stat(state.oldRun); !os.IsNotExist(err) {
			t.Fatal("old runtime directory survived clean shutdown")
		}
	}
	check("packaged daemon restart preserves host identity/services and recreates private sockets")
	liveCall(t, clientAPI, "GET", "/api/state", nil, &afterRestart, 200)
	if len(afterRestart.Profiles) != 2 {
		t.Fatal("imported profiles were lost on restart")
	}
	for _, profile := range afterRestart.Profiles {
		if !profile.Locked || profile.Authenticated {
			t.Fatal("profile unlocked itself after restart")
		}
	}
	liveCall(t, clientAPI, "GET", "/api/services?id="+id, nil, nil, 400)
	liveCall(t, clientAPI, "POST", "/api/unlock", map[string]any{"id": id, "password": "wrong file password"}, nil, 400)
	liveCall(t, clientAPI, "POST", "/api/unlock", map[string]any{"id": id, "password": password}, nil, 200)
	check("restarted client keeps profiles encrypted and locked until correct password unlock")
	// This is readiness polling only, not replay of an application request. A
	// revoked/expired token is not silently replaced or treated as readiness.
	deadline := time.Now().Add(8 * time.Minute)
	for {
		req, _ := http.NewRequest("GET", "http://app/api/services?id="+id, nil)
		req.Header.Set("Origin", "torkitten://app")
		response, err := clientAPI.Do(req)
		if err != nil {
			t.Fatal("restart service probe failed", err)
		}
		data, _ := io.ReadAll(io.LimitReader(response.Body, MaxFile+1))
		response.Body.Close()
		if response.StatusCode == 200 {
			break
		}
		var problem struct {
			Error string `json:"error"`
		}
		json.Unmarshal(data, &problem)
		if problem.Error != "Tor gateway unavailable" || time.Now().After(deadline) {
			t.Fatalf("persisted token after same-registration restart: status %d (%s)", response.StatusCode, problem.Error)
		}
		time.Sleep(time.Second)
	}
	unixPort = mapService("unix", 0)
	out, err = liveExchange(unixPort, payload)
	if err != nil || !bytes.Equal(out, payload) {
		t.Fatal("native transfer after packaged daemon restart failed", err)
	}
	check("same-registration persisted OAuth remains valid after upstream restart and native transfer resumes after remapping")
	held = liveOpenEcho(t, unixPort)
	liveCall(t, clientAPI, "POST", "/api/remove", map[string]any{"id": id}, nil, 200)
	liveClosed(t, held)
	liveCall(t, clientAPI, "GET", "/api/state", nil, &afterRestart, 200)
	if len(afterRestart.Profiles) != 1 || afterRestart.Profiles[0].ID == id {
		t.Fatal("removed connection remains in client state")
	}
	for _, path := range []string{filepath.Join(clientRoot, "profiles", id+".age"), filepath.Join(clientRoot, "client-auth", id+".auth_private")} {
		if _, e := os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("connection removal retained credentials")
		}
	}
	check("Remove connection closes active stream, revokes tokens and erases private profile/auth state")
	success = true
}

func mustJSON(value any) []byte { b, _ := json.Marshal(value); return b }

func liveAPI(t *testing.T, a *App) *http.Client {
	t.Helper()
	c := &http.Client{Timeout: 3 * time.Minute, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", a.path("admin.sock"))
	}}}
	t.Cleanup(c.CloseIdleConnections)
	return c
}
func liveCall(t *testing.T, c *http.Client, method, path string, input, output any, want int) {
	t.Helper()
	var body []byte
	if input != nil {
		body, _ = json.Marshal(input)
	}
	req, err := http.NewRequest(method, "http://app"+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "torkitten://app")
	req.Header.Set("Content-Type", "application/json")
	response, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s transport error: %v", method, strings.Split(path, "?")[0], err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxFile+1))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		var problem struct {
			Error string `json:"error"`
		}
		json.Unmarshal(data, &problem)
		t.Fatalf("%s %s: status %d want %d (%s)", method, strings.Split(path, "?")[0], response.StatusCode, want, problem.Error)
	}
	if output != nil && json.Unmarshal(data, output) != nil {
		t.Fatal("invalid API response")
	}
}
func liveTOTPSecret(t *testing.T, encoded string) string {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	im, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	bitmap, err := gozxing.NewBinaryBitmapFromImage(im)
	if err != nil {
		t.Fatal(err)
	}
	qr, err := qrcode.NewQRCodeReader().Decode(bitmap, nil)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(qr.GetText())
	if err != nil || uri.Scheme != "otpauth" || uri.Query().Get("secret") == "" {
		t.Fatal("invalid Authelia TOTP QR")
	}
	return uri.Query().Get("secret")
}
func liveTOTP(secret string) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}
func liveOnionReady(t *testing.T, ctx context.Context, a *App, id string) {
	t.Helper()
	t.Log("waiting for authorized onion publication/bootstrap")
	p := a.profiles[id]
	deadline := time.Now().Add(8 * time.Minute)
	lastStatus, lastError := 0, ""
	for time.Now().Before(deadline) {
		checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		req, _ := http.NewRequestWithContext(checkCtx, "GET", "https://"+p.cache.Bundle.Onion+"/api/info", nil)
		r, err := p.HTTP.Do(req)
		if r != nil {
			lastStatus = r.StatusCode
			r.Body.Close()
		}
		if err != nil {
			lastError = strings.ReplaceAll(err.Error(), p.cache.Bundle.Onion, "[onion]")
		}
		cancel()
		if err == nil && r.StatusCode == 200 {
			return
		}
		if ctx.Err() != nil {
			break
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("authorized onion did not become ready: status %d, error %s", lastStatus, lastError)
}

// This diagnostic isolates certificate verification from public Tor readiness;
// the actual product and every service/OAuth exchange below still use Tor only.
func livePrivateTLS(t *testing.T, host *App, profile *Profile) {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: profile.tls.Clone(), DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", host.socket("gateway"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := client.Get("https://" + profile.cache.Bundle.Onion + "/api/info")
	if err != nil {
		t.Fatal("private TLS/mTLS verification failed:", strings.ReplaceAll(err.Error(), profile.cache.Bundle.Onion, "[onion]"))
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatal("private TLS/mTLS info endpoint rejected:", r.StatusCode)
	}
}
func liveEcho(t *testing.T, network, work string) Endpoint {
	t.Helper()
	address := "127.0.0.1:0"
	if network == "unix" {
		address = filepath.Join(work, "echo.sock")
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); listener.Close() })
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				io.Copy(c, c)
			}()
		}
	}()
	return Endpoint{Network: network, Address: listener.Addr().String()}
}
func liveExchange(port int, body []byte) ([]byte, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Minute))
	if _, err = c.Write(body); err != nil {
		return nil, err
	}
	c.(*net.TCPConn).CloseWrite()
	return io.ReadAll(c)
}
func liveOpenEcho(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(time.Minute))
	c.Write([]byte("held"))
	var got [4]byte
	if _, err = io.ReadFull(c, got[:]); err != nil || string(got[:]) != "held" {
		t.Fatal("opening persistent stream", err)
	}
	return c
}
func liveClosed(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var b [1]byte
	n, err := c.Read(b[:])
	if n != 0 || err == nil {
		t.Fatal("revoked stream still open")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("revoked stream did not close")
	}
}

func liveRemoteDenied(t *testing.T, p *Profile, token string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "https://"+p.cache.Bundle.Onion+"/api/services", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := p.HTTP.Do(req)
	if err != nil {
		t.Fatal("authorization denial was not observable over the working gateway", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 401 && response.StatusCode != 403 {
		t.Fatalf("gateway accepted unauthenticated/revoked token: %d", response.StatusCode)
	}
}

func liveNoCertificate(t *testing.T, p *Profile) {
	t.Helper()
	base := p.HTTP.Transport.(*profileTransport).Transport.Clone()
	base.TLSClientConfig = base.TLSClientConfig.Clone()
	base.TLSClientConfig.Certificates = nil
	base.TLSClientConfig.GetClientCertificate = nil
	client := &http.Client{Transport: base, Timeout: 20 * time.Second}
	defer client.CloseIdleConnections()
	response, err := client.Get("https://" + p.cache.Bundle.Onion + "/api/info")
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("actual gateway accepted missing device mTLS certificate")
	}
}

func liveDaemon(t *testing.T, ctx context.Context, bin, root, log string) *process {
	t.Helper()
	p, err := startProcess(ctx, filepath.Join(bin, "torkitten"), log, "daemon", "--state", root, "--bin-dir", bin)
	if err != nil {
		t.Fatal("start packaged daemon", err)
	}
	if err = waitReady(ctx, p, func() error {
		c, err := net.DialTimeout("unix", filepath.Join(root, "admin.sock"), time.Second)
		if c != nil {
			c.Close()
		}
		return err
	}); err != nil {
		p.stop()
		t.Fatal("packaged daemon readiness", err)
	}
	return p
}
