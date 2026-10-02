// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testIssuer = "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/login"
const testFlow = "e9940201-2613-4adb-933c-f17c172a48e7"

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func reply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}
func testConfig(rt roundTrip) Config {
	return Config{Issuer: testIssuer, ClientID: "native", Audience: strings.TrimSuffix(testIssuer, "/login"), HTTP: &http.Client{Transport: rt}, Save: func(Token) error { return nil }}
}
func form(callback, state, issuer string) string {
	return `<html><script>ignored()</script><form method="post" action="` + html.EscapeString(callback) + `"><input type="hidden" name="code" value="test_code"/><input type="hidden" name="state" value="` + html.EscapeString(state) + `"/><input type="hidden" name="iss" value="` + html.EscapeString(issuer) + `"/></form></html>`
}

func TestNativeLoginConsentRefresh(t *testing.T) {
	var state, pkce string
	var saved int
	calls := map[string]int{}
	var scopes = []string{"offline_access", "authelia.bearer.authz"}
	cfg := testConfig(func(r *http.Request) (*http.Response, error) {
		calls[r.URL.Path]++
		switch r.URL.Path {
		case "/login/api/firstfactor":
			var v map[string]any
			json.NewDecoder(r.Body).Decode(&v)
			if v["password"] != "private-password" {
				t.Fatal("missing password")
			}
			out := reply(200, `{"status":"OK"}`)
			out.Header.Set("Set-Cookie", "session=private; Secure; HttpOnly; Path=/login")
			return out, nil
		case "/login/api/user/info", "/login/api/secondfactor/totp":
			if c, _ := r.Cookie("session"); c == nil || c.Value != "private" {
				t.Fatal("private cookie missing")
			}
			return reply(200, `{"status":"OK","data":{"has_totp":true}}`), nil
		case "/login/api/oidc/pushed-authorization-request":
			r.ParseForm()
			state = r.Form.Get("state")
			pkce = r.Form.Get("code_challenge")
			if r.Form.Get("scope") != scope || r.Form.Get("redirect_uri") != CallbackURI || r.Form.Get("response_mode") != "form_post" || r.Form.Get("code_challenge_method") != "S256" || r.Form.Get("audience") != strings.TrimSuffix(testIssuer, "/login") {
				t.Fatal("wrong PAR")
			}
			if r.Header.Get("Cookie") != "" {
				t.Fatal("portal cookie escaped into token client")
			}
			return reply(201, `{"request_uri":"urn:ietf:params:oauth:request_uri:example","expires_in":90}`), nil
		case "/login/api/oidc/authorization":
			if r.URL.Query().Get("consent_id") == "" {
				out := reply(303, "")
				out.Header.Set("Location", testIssuer+"/consent/openid/decision?flow=openid_connect&flow_id="+testFlow)
				return out, nil
			}
			out := reply(200, form(CallbackURI, state, testIssuer))
			out.Header.Set("Content-Type", "text/html; charset=utf-8")
			return out, nil
		case "/login/api/oidc/consent":
			if r.Method == "GET" {
				raw, _ := json.Marshal(map[string]any{"status": "OK", "data": map[string]any{"client_id": "native", "scopes": scopes, "audience": []string{strings.TrimSuffix(testIssuer, "/login")}, "resource": []string{strings.TrimSuffix(testIssuer, "/login")}}})
				return reply(200, string(raw)), nil
			}
			return reply(200, `{"status":"OK","data":{"redirect_uri":"`+testIssuer+`/api/oidc/authorization?consent_id=`+testFlow+`"}}`), nil
		case "/login/api/oidc/token":
			r.ParseForm()
			if r.Form.Get("grant_type") == "authorization_code" && challenge(r.Form.Get("code_verifier")) != pkce {
				t.Fatal("PKCE mismatch")
			}
			if r.Header.Get("Cookie") != "" {
				t.Fatal("cookies on token exchange")
			}
			return reply(200, `{"access_token":"authelia_at_access","refresh_token":"authelia_rt_refresh","token_type":"Bearer","expires_in":300,"scope":"`+scope+`"}`), nil
		case "/login/api/oidc/revocation":
			return reply(200, ""), nil
		}
		t.Fatalf("unexpected request %s", r.URL.Path)
		return nil, nil
	})
	cfg.Save = func(token Token) error {
		saved++
		if token.ClientID != "native" {
			t.Fatal("token identity")
		}
		return nil
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	consent, err := c.Login(t.Context(), "owner", "private-password", "123456")
	if err != nil {
		t.Fatal(err)
	}
	if calls["/login/api/oidc/token"] != 0 || calls["/login/api/oidc/consent"] != 1 {
		t.Fatal("token or consent before explicit acceptance")
	}
	d := consent.Details()
	d.Scopes[0] = "tampered"
	if consent.Details().Scopes[0] == "tampered" {
		t.Fatal("mutable consent details")
	}
	token, err := consent.Accept(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = consent.Accept(t.Context()); !errors.Is(err, ErrLoginRequired) {
		t.Fatal("consent replay")
	}
	if _, err = c.Refresh(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	if err = c.Revoke(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	if saved != 2 || calls["/login/api/oidc/revocation"] != 2 {
		t.Fatal("rotation/revocation missing")
	}
	scopes = append(scopes, "openid")
	if _, err = c.Login(t.Context(), "owner", "private-password", "123456"); err == nil {
		t.Fatal("accepted extra consent scope")
	}
}

func TestFormRejectsSubstitution(t *testing.T) {
	valid := form(CallbackURI, "state", testIssuer)
	if code, err := decodeForm([]byte(valid), CallbackURI, "state", testIssuer); err != nil || code != "test_code" {
		t.Fatal("valid form rejected")
	}
	for name, input := range map[string]string{
		"wrong state":    strings.Replace(valid, `value="state"`, `value="other"`, 1),
		"wrong issuer":   strings.Replace(valid, html.EscapeString(testIssuer), "https://evil.example", 1),
		"wrong action":   strings.Replace(valid, CallbackURI, "http://127.0.0.1/else", 1),
		"missing issuer": strings.Replace(valid, `<input type="hidden" name="iss" value="`+html.EscapeString(testIssuer)+`"/>`, "", 1),
		"extra scope":    strings.Replace(valid, "</form>", `<input type="hidden" name="scope" value="authelia.bearer.authz offline_access openid"/></form>`, 1),
		"wrong method":   strings.Replace(valid, `method="post"`, `method="get"`, 1),
		"duplicate":      strings.Replace(valid, "</form>", `<input type="hidden" name="state" value="state"/></form>`, 1),
		"second form":    valid + `<form method="post" action="` + CallbackURI + `"></form>`,
		"external input": valid + `<input type="hidden" name="other" value="x"/>`,
		"override":       strings.Replace(valid, `name="code"`, `name="code" formaction="https://evil.example"`, 1),
		"missing code":   strings.Replace(valid, `value="test_code"`, `value=""`, 1),
		"oversize":       strings.Repeat("x", maxBody+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeForm([]byte(input), CallbackURI, "state", testIssuer); err == nil {
				t.Fatalf("accepted malformed form: %s", input)
			}
		})
	}
}

func TestRejectConfigurationAndTokenLeak(t *testing.T) {
	calls := 0
	cfg := testConfig(func(r *http.Request) (*http.Response, error) {
		calls++
		out := reply(302, "")
		out.Header.Set("Location", "https://evil.example/token")
		return out, nil
	})
	for _, issuer := range []string{"http://" + strings.TrimPrefix(testIssuer, "https://"), testIssuer + "/", testIssuer + "?secret=x", "https://example.com/login"} {
		bad := cfg
		bad.Issuer = issuer
		if _, err := New(bad); err == nil {
			t.Fatal("invalid issuer")
		}
	}
	bad := cfg
	bad.HTTP = &http.Client{}
	if _, err := New(bad); err == nil {
		t.Fatal("default direct transport")
	}
	c, _ := New(cfg)
	token := Token{Issuer: testIssuer, ClientID: "native", AccessToken: "authelia_at_a", RefreshToken: "authelia_rt_secret"}
	if _, err := c.Refresh(t.Context(), token); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("redirect accepted or secret exposed")
	}
	if calls != 1 {
		t.Fatal("redirect followed")
	}
	token.ClientID = "old-client"
	if _, err := c.Refresh(t.Context(), token); !errors.Is(err, ErrLoginRequired) || calls != 1 {
		t.Fatal("cross-registration token used")
	}
}

func TestPersistenceFailureAndInvalidGrant(t *testing.T) {
	cfg := testConfig(func(r *http.Request) (*http.Response, error) {
		return reply(200, `{"access_token":"authelia_at_a","refresh_token":"authelia_rt_b","token_type":"Bearer","expires_in":300}`), nil
	})
	cfg.Save = func(Token) error { return errors.New("private path and credential") }
	c, _ := New(cfg)
	token, err := c.exchange(t.Context(), url.Values{})
	if err == nil || token.AccessToken != "" || strings.Contains(err.Error(), "private path") {
		t.Fatal("persistence failure exposed token/error")
	}
	cfg.Save = func(Token) error { return nil }
	cfg.HTTP.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return reply(400, `{"error":"invalid_grant","error_description":"secret"}`), nil
	})
	c, _ = New(cfg)
	if _, err = c.exchange(t.Context(), url.Values{}); !errors.Is(err, ErrLoginRequired) {
		t.Fatal("stale token should require login")
	}
}

func TestConsentClosedOrExpired(t *testing.T) {
	for _, expire := range []bool{false, true} {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		if !expire {
			ctx, cancel = context.WithCancel(context.Background())
		}
		p := &Consent{ctx: ctx, cancel: cancel}
		if !expire {
			p.Close()
		}
		if _, err := p.Accept(t.Context()); !errors.Is(err, ErrLoginRequired) {
			t.Fatal("closed consent accepted")
		}
		cancel()
	}
}
