// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var flowID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ConsentDetails is safe to display in the trusted application UI. The user
// must explicitly accept this exact gateway and scopes before Accept is called.
type ConsentDetails struct {
	Gateway   string   `json:"gateway"`
	ClientID  string   `json:"client_id"`
	Scopes    []string `json:"scopes"`
	Audience  []string `json:"audience"`
	Resources []string `json:"resources"`
}

type Consent struct {
	client                *Client
	http                  http.Client
	details               ConsentDetails
	state, verifier, flow string
	ctx                   context.Context
	cancel                context.CancelFunc
	mu                    sync.Mutex
	used                  bool
}

// Login delegates password and TOTP verification to the documented portal APIs
// of pinned Authelia. Cookies stay in this short-lived native jar. No credentials
// or remote HTML are passed to a WebView, and no token is issued before Accept.
func (c *Client) authenticate(ctx context.Context, username, password, totp string) (*Consent, error) {
	if username == "" || len(username) > 256 || password == "" || len(password) > 4096 || len(totp) != 6 {
		return nil, ErrLoginRequired
	}
	for _, r := range totp {
		if r < '0' || r > '9' {
			return nil, ErrLoginRequired
		}
	}
	p := &Consent{client: c, http: c.http}
	p.http.Jar, _ = cookiejar.New(nil)
	p.ctx, p.cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	success := false
	defer func() {
		if !success {
			p.Close()
		}
	}()
	requestCtx, cancel := p.requestContext(ctx)
	defer cancel()
	if err := p.json(requestCtx, http.MethodPost, "/api/firstfactor", map[string]any{
		"username": username, "password": password, "keepMeLoggedIn": false}, nil); err != nil {
		return nil, err
	}
	var info struct {
		HasTOTP bool `json:"has_totp"`
	}
	if err := p.json(requestCtx, http.MethodPost, "/api/user/info", map[string]any{}, &info); err != nil || !info.HasTOTP {
		return nil, ErrLoginRequired
	}
	if err := p.json(requestCtx, http.MethodPost, "/api/secondfactor/totp", map[string]string{"token": totp}, nil); err != nil {
		return nil, err
	}
	success = true
	return p, nil
}

// VerifyFactors confirms setup using the same upstream verification as Login,
// without requesting OAuth authorization or issuing credentials.
func (c *Client) VerifyFactors(ctx context.Context, username, password, totp string) error {
	p, err := c.authenticate(ctx, username, password, totp)
	if p != nil {
		p.Close()
	}
	return err
}

func (c *Client) Login(ctx context.Context, username, password, totp string) (*Consent, error) {
	p, err := c.authenticate(ctx, username, password, totp)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			p.Close()
		}
	}()
	requestCtx, cancel := p.requestContext(ctx)
	defer cancel()
	if p.state, err = randomValue(); err != nil {
		return nil, err
	}
	if p.verifier, err = randomValue(); err != nil {
		return nil, err
	}
	var par struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int64  `json:"expires_in"`
	}
	if err = c.post(requestCtx, "pushed-authorization-request", url.Values{
		"response_type": {"code"}, "response_mode": {"form_post"}, "redirect_uri": {CallbackURI},
		"scope": {scope}, "audience": {c.config.Audience}, "resource": {c.config.Audience}, "state": {p.state},
		"code_challenge": {challenge(p.verifier)}, "code_challenge_method": {"S256"}, "prompt": {"consent"},
	}, &par); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(par.RequestURI, "urn:ietf:params:oauth:request_uri:") || !safeValue(par.RequestURI) || par.ExpiresIn <= 0 {
		return nil, errors.New("invalid pushed authorization response")
	}
	// The flow cannot outlive the pushed request, even if the user leaves consent open.
	deadline := time.Now().Add(time.Duration(min(par.ExpiresIn, 300)) * time.Second)
	nextCtx, nextCancel := context.WithDeadline(p.ctx, deadline)
	previousCancel := p.cancel
	p.ctx, p.cancel = nextCtx, func() { nextCancel(); previousCancel() }
	query := url.Values{"client_id": {c.config.ClientID}, "request_uri": {par.RequestURI}}
	status, headers, _, err := p.request(requestCtx, http.MethodGet, c.config.Issuer+"/api/oidc/authorization?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	location, err := p.location(headers.Get("Location"), "/consent/openid/decision")
	if err != nil || status != http.StatusSeeOther || location.Query().Get("flow") != "openid_connect" || !flowID.MatchString(location.Query().Get("flow_id")) {
		return nil, errors.New("unexpected OAuth consent redirect")
	}
	p.flow = location.Query().Get("flow_id")
	var requested struct {
		ClientID        string   `json:"client_id"`
		Scopes          []string `json:"scopes"`
		Audience        []string `json:"audience"`
		Resource        []string `json:"resource"`
		Claims          []string `json:"claims"`
		EssentialClaims []string `json:"essential_claims"`
		RequireLogin    bool     `json:"require_login"`
	}
	if err = p.json(requestCtx, http.MethodGet, "/api/oidc/consent?flow_id="+p.flow, nil, &requested); err != nil {
		return nil, err
	}
	if requested.ClientID != c.config.ClientID || !exactScopes(requested.Scopes) || len(requested.Audience) != 1 || requested.Audience[0] != c.config.Audience || requested.RequireLogin || len(requested.Resource) != 1 || requested.Resource[0] != c.config.Audience || len(requested.Claims)+len(requested.EssentialClaims) != 0 {
		return nil, errors.New("OAuth consent does not match the requested gateway")
	}
	p.details = ConsentDetails{Gateway: c.origin, ClientID: c.config.ClientID, Scopes: strings.Fields(scope), Audience: []string{c.config.Audience}, Resources: []string{c.config.Audience}}
	success = true
	return p, nil
}

func (p *Consent) Details() ConsentDetails {
	d := p.details
	d.Scopes = append([]string(nil), d.Scopes...)
	d.Audience = append([]string(nil), d.Audience...)
	d.Resources = append([]string(nil), d.Resources...)
	return d
}

// Accept must be called only after a separate, explicit user consent action.
// It is one-use even on failure; retries require a fresh Login.
func (p *Consent) Accept(ctx context.Context) (Token, error) {
	p.mu.Lock()
	if p.used || p.ctx.Err() != nil {
		p.mu.Unlock()
		return Token{}, ErrLoginRequired
	}
	p.used = true
	p.mu.Unlock()
	defer p.Close()
	ctx, cancel := p.requestContext(ctx)
	defer cancel()
	var response struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := p.json(ctx, http.MethodPost, "/api/oidc/consent", map[string]any{
		"flow_id": p.flow, "client_id": p.client.config.ClientID, "consent": true, "pre_configure": false, "claims": []string{},
	}, &response); err != nil {
		return Token{}, err
	}
	location, err := p.location(response.RedirectURI, "/api/oidc/authorization")
	if err != nil || location.Query().Get("consent_id") != p.flow {
		return Token{}, errors.New("unexpected OAuth authorization redirect")
	}
	status, headers, body, err := p.request(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return Token{}, err
	}
	if status != http.StatusOK || !strings.HasPrefix(headers.Get("Content-Type"), "text/html") {
		return Token{}, errors.New("unexpected OAuth authorization response")
	}
	code, err := decodeForm(body, CallbackURI, p.state, p.client.config.Issuer)
	if err != nil {
		return Token{}, err
	}
	return p.client.exchange(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {CallbackURI}, "code_verifier": {p.verifier}})
}

func (p *Consent) Close() { p.mu.Lock(); p.used = true; p.mu.Unlock(); p.cancel() }

func (p *Consent) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, _ := p.ctx.Deadline()
	child, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(p.ctx, cancel)
	return child, func() { stop(); cancel() }
}

func (p *Consent) location(raw, path string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || "https://"+u.Host != p.client.origin || u.User != nil || u.Fragment != "" || u.RawPath != "" || u.Path != "/login"+path {
		return nil, errors.New("unexpected OAuth redirect destination")
	}
	return u, nil
}

func (p *Consent) json(ctx context.Context, method, path string, input, output any) error {
	var encoded []byte
	var err error
	if input != nil {
		encoded, err = json.Marshal(input)
		if err != nil {
			return errors.New("invalid login request")
		}
	}
	status, _, body, err := p.request(ctx, method, p.client.config.Issuer+path, encoded)
	if err != nil {
		return err
	}
	var envelope struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &envelope) != nil || envelope.Status != "OK" {
		return ErrLoginRequired
	}
	if output != nil && json.Unmarshal(envelope.Data, output) != nil {
		return errors.New("invalid login response")
	}
	return nil
}

func (p *Consent) request(ctx context.Context, method, uri string, body []byte) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, uri, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, errors.New("invalid login request")
	}
	req.Header.Set("Accept", "application/json, text/html")
	req.Header.Set("Origin", p.client.origin)
	req.Header.Set("Referer", p.client.config.Issuer+"/")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := p.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, nil, ctx.Err()
		}
		return 0, nil, nil, errors.New("login endpoint unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || len(data) > maxBody {
		return 0, nil, nil, errors.New("invalid login response size")
	}
	return response.StatusCode, response.Header, data, nil
}
