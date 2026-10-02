// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package oauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"golang.org/x/net/html"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLiveAuthelia is opt-in: tools/proof-oauth.py creates isolated, real pinned
// Authelia/Caddy fixtures. This local TLS proof does not claim to exercise Tor.
func TestLiveAuthelia(t *testing.T) {
	path := os.Getenv("TORKITTEN_OAUTH_PROOF")
	if path == "" {
		t.Skip("isolated real-component proof only")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read private proof configuration")
	}
	var cfg struct{ Issuer, ClientID, Audience, Address, CA, Certificate, Key, Username, Password, TOTP, EpochControl string }
	if json.Unmarshal(raw, &cfg) != nil {
		t.Fatal("proof configuration")
	}
	roots := x509.NewCertPool()
	root, _ := os.ReadFile(cfg.CA)
	if !roots.AppendCertsFromPEM(root) {
		t.Fatal("proof CA")
	}
	cert, err := tls.LoadX509KeyPair(cfg.Certificate, cfg.Key)
	if err != nil {
		t.Fatal("proof client certificate")
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != strings.TrimPrefix(cfg.Audience, "https://")+":443" {
			t.Fatal("unexpected outbound destination")
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", cfg.Address)
	}
	transport := &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	var authBody []byte
	h := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		res, e := transport.RoundTrip(r)
		if e == nil && r.URL.Path == "/login/api/oidc/authorization" && res.StatusCode == 200 {
			authBody, _ = io.ReadAll(io.LimitReader(res.Body, maxBody+1))
			res.Body.Close()
			res.Body = io.NopCloser(bytes.NewReader(authBody))
		}
		return res, e
	}), Timeout: 20 * time.Second}
	saved := 0
	c, err := New(Config{Issuer: cfg.Issuer, ClientID: cfg.ClientID, Audience: cfg.Audience, HTTP: h, Save: func(Token) error { saved++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	check := func(token string, allowed bool) {
		t.Helper()
		for _, path := range []string{"/tunnel/id", "/api/services", "/api/actions"} {
			req, _ := http.NewRequest("GET", cfg.Audience+path, nil)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			res, err := h.Do(req)
			if err != nil {
				t.Fatal("proof gateway unavailable")
			}
			defer res.Body.Close()
			io.Copy(io.Discard, res.Body)
			if (res.StatusCode == 200) != allowed {
				t.Fatalf("gateway authorization mismatch for %s: status %d", path, res.StatusCode)
			}
		}
	}
	check("", false)
	consent, err := c.Login(t.Context(), cfg.Username, cfg.Password, cfg.TOTP)
	if err != nil {
		t.Fatal(err)
	}
	if saved != 0 {
		t.Fatal("token before explicit consent")
	}
	d := consent.Details()
	if d.ClientID != cfg.ClientID || len(d.Audience) != 1 || d.Audience[0] != cfg.Audience {
		t.Fatal("consent mismatch")
	}
	token, err := consent.Accept(t.Context())
	if err != nil {
		z := html.NewTokenizer(bytes.NewReader(authBody))
		for z.Next() != html.ErrorToken {
			tk := z.Token()
			if tk.Data == "input" {
				for _, a := range tk.Attr {
					if a.Key == "name" {
						t.Log("form input", a.Val)
					}
				}
			}
		}
		t.Fatal(err)
	}
	check(token.AccessToken, true)
	rotated, err := c.Refresh(t.Context(), token)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RefreshToken == token.RefreshToken {
		t.Fatal("refresh token did not rotate")
	}
	check(rotated.AccessToken, true)
	if cfg.EpochControl != "" {
		if err := os.WriteFile(filepath.Join(cfg.EpochControl, "rotate.ready"), []byte("ready"), 0600); err != nil {
			t.Fatal("epoch signal")
		}
		deadline := time.Now().Add(50 * time.Second)
		for {
			if _, err := os.Stat(filepath.Join(cfg.EpochControl, "rotate.done")); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("epoch restart timeout")
			}
			time.Sleep(100 * time.Millisecond)
		}
		check(rotated.AccessToken, false)
		if _, err = c.Refresh(t.Context(), rotated); err == nil {
			t.Fatal("old registration refresh survived epoch")
		}
		// The previous login jar is retained here only to verify the real memory session was lost.
		_, _, stateBody, err := consent.request(t.Context(), http.MethodGet, cfg.Issuer+"/api/state", nil)
		var state struct {
			Data struct {
				Level int `json:"authentication_level"`
			} `json:"data"`
		}
		if err != nil || json.Unmarshal(stateBody, &state) != nil || state.Data.Level != 0 {
			t.Fatal("old browser session survived restart")
		}
		if saved != 2 {
			t.Fatal("unexpected credential persistence count")
		}
		t.Log("client-registration rotation denied old access+refresh tokens and memory-session restart requires fresh factors")
		return
	}
	if err = c.Revoke(t.Context(), rotated); err != nil {
		t.Fatal(err)
	}
	check(rotated.AccessToken, false)
	if _, err = c.Refresh(t.Context(), rotated); err == nil {
		t.Fatal("revoked refresh token accepted")
	}
	if saved != 2 {
		t.Fatal("unexpected credential persistence count")
	}
	t.Log("real password+TOTP, PAR/S256, explicit consent, form_post, bearer authorization, refresh rotation and revocation passed")
}
