// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"torkitten/internal/tunnel"
)

func quote(s string) string { return strconv.Quote(s) }
func torCommon(dir string) string {
	return "DataDirectory " + quote(dir) + "\nClientOnly 1\nRunAsDaemon 0\nSafeLogging 1\nAvoidDiskWrites 1\nHeartbeatPeriod 0\nHiddenServiceStatistics 0\nMetricsPort 0\nLog notice stdout\n"
}
func (a *App) torServerConfig() string {
	publish := 0
	if len(a.host.Devices) > 0 {
		publish = 1
	}
	return torCommon(a.gen("tor")) + fmt.Sprintf("SocksPort 0\nPublishHidServDescriptors %d\nHiddenServiceDir %s\nHiddenServiceVersion 3\nHiddenServiceAllowUnknownPorts 0\nHiddenServicePort 443 unix:%s\n", publish, quote(a.gen("onion")), a.socket("gateway"))
}
func (a *App) startServerTor() error {
	for _, d := range []string{"tor", "onion", "onion/authorized_clients"} {
		if err := privateDir(a.gen(d)); err != nil {
			return err
		}
	}
	if err := atomicWrite(a.gen("torrc"), []byte(a.torServerConfig())); err != nil {
		return err
	}
	p, err := startProcess(a.ctx, filepath.Join(a.bin, "tor"), a.gen("tor.log"), "-f", a.gen("torrc"))
	if err != nil {
		return err
	}
	a.processes["tor"] = p
	return waitReady(a.ctx, p, func() error {
		b, err := os.ReadFile(a.gen("onion", "hostname"))
		if err != nil {
			return err
		}
		host := strings.TrimSpace(string(b))
		if !onionName.MatchString(host) {
			return errors.New("invalid Tor onion identity")
		}
		if a.host.Onion != "" && a.host.Onion != host {
			return errors.New("Tor identity changed unexpectedly")
		}
		a.host.Onion = host
		return nil
	})
}
func (a *App) startHost() error {
	if !generationName.MatchString(a.host.Generation) {
		return errors.New("invalid identity generation")
	}
	if err := a.startServerTor(); err != nil {
		return err
	}
	if err := a.writeAuthelia(); err != nil {
		return err
	}
	if err := a.startAuthelia(); err != nil {
		return err
	}
	key, err := os.ReadFile(a.gen("tunnel.key"))
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey(key)
	clear(key)
	if err != nil {
		return err
	}
	a.relay, err = tunnel.NewServer(signer, a.authorizeBearer)
	if err != nil {
		return err
	}
	if err = a.applyServices(a.services); err != nil {
		return err
	}
	ln, err := net.Listen("unix", a.socket("remote"))
	if err != nil {
		return err
	}
	a.remote = &http.Server{Handler: http.HandlerFunc(a.remoteHandler), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	go a.remote.Serve(ln)
	if err = a.writeCaddy(); err != nil {
		return err
	}
	p, err := startProcess(a.ctx, filepath.Join(a.bin, "caddy"), a.gen("caddy.log"), "run", "--config", a.gen("caddy.json"))
	if err != nil {
		return err
	}
	a.processes["caddy"] = p
	if err = waitReady(a.ctx, p, func() error { _, e := a.caddyRoot(); return e }); err != nil {
		return err
	}
	a.hostError = ""
	return nil
}
func (a *App) writeCaddy() error {
	var trusted []string
	for _, d := range a.host.Devices {
		trusted = append(trusted, a.gen("devices", d.ID+".pem"))
	}
	// With no enrolled devices the gateway has no application routes. Its CA can
	// still be initialized through Caddy's private administration socket.
	gateway := "respond 403"
	if len(trusted) > 0 {
		gateway = fmt.Sprintf(`@login path /login /login/*
handle @login {
 reverse_proxy unix/%s {
  header_up X-Forwarded-Proto https
  header_up X-Forwarded-Host {http.request.host}
 }
}
@info path /api/info
handle @info {
 reverse_proxy unix/%s
}
handle {
 route {
  request_header -Remote-User
  request_header -Remote-Groups
  forward_auth unix/%s {
   uri /login/api/authz/forward-auth
   header_up X-Forwarded-For 127.0.0.1
   header_up X-Forwarded-Host {http.request.host}
   header_up X-Forwarded-Proto https
  }
  reverse_proxy unix/%s {
   stream_close_delay 24h
  }
 }
}`, a.socket("authelia"), a.socket("remote"), a.socket("authelia"), a.socket("remote"))
	}
	text := fmt.Sprintf(`{
 admin unix/%s
 persist_config off
 skip_install_trust
 auto_https disable_redirects
 storage file_system {
  root %s
 }
}
https://%s {
 bind unix/%s
 tls internal
 %s
}
`, a.socket("caddy"), quote(a.gen("caddy-storage")), a.host.Onion, a.socket("gateway"), gateway)
	if err := atomicWrite(a.gen("Caddyfile"), []byte(text)); err != nil {
		return err
	}
	b, err := runPrivate(a.ctx, filepath.Join(a.bin, "caddy"), nil, "adapt", "--adapter", "caddyfile", "--config", a.gen("Caddyfile"))
	if err != nil {
		return err
	}
	var c map[string]any
	if err = json.Unmarshal(b, &c); err != nil {
		return err
	}
	if len(trusted) > 0 {
		apps := c["apps"].(map[string]any)
		servers := apps["http"].(map[string]any)["servers"].(map[string]any)
		for _, raw := range servers {
			srv := raw.(map[string]any)
			srv["protocols"] = []string{"h1"}
			srv["tls_connection_policies"] = []any{map[string]any{"client_authentication": map[string]any{"mode": "require_and_verify", "ca": map[string]any{"provider": "file", "pem_files": trusted}, "verifiers": []any{map[string]any{"verifier": "leaf", "leaf_certs_loaders": []any{map[string]any{"loader": "file", "files": trusted}}}}}}}
		}
	}
	return writeJSON(a.gen("caddy.json"), c)
}
func (a *App) caddyRoot() ([]byte, error) {
	r, err := unixHTTP(a.socket("caddy")).Get("http://localhost/pki/ca/local")
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	var data struct {
		Root string `json:"root_certificate"`
	}
	if r.StatusCode != 200 || json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&data) != nil || data.Root == "" {
		return nil, errors.New("Caddy root CA unavailable")
	}
	return []byte(data.Root), nil
}
func (a *App) reloadCaddy() error {
	if err := a.writeCaddy(); err != nil {
		return err
	}
	data, err := os.ReadFile(a.gen("caddy.json"))
	if err != nil {
		return err
	}
	r, err := unixHTTP(a.socket("caddy")).Post("http://localhost/load", "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return errors.New("Caddy rejected configuration")
	}
	return nil
}
func (a *App) authorizeBearer(ctx context.Context, token string) error {
	// This endpoint is also private; Caddy is not the only enforcement point.
	a.mu.Lock()
	host, bad := a.host.Onion, a.hostError != ""
	a.mu.Unlock()
	if bad || !strings.HasPrefix(token, "authelia_at_") || strings.ContainsAny(token, "\r\n") {
		return errors.New("OAuth login required")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+host+"/login/api/authz/forward-auth", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Forwarded-Method", "GET")
	req.Header.Set("X-Forwarded-Uri", "/tunnel")
	r, err := unixHTTP(a.socket("authelia")).Do(req)
	if err != nil {
		return errors.New("authorization unavailable")
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return errors.New("OAuth login required")
	}
	return nil
}
