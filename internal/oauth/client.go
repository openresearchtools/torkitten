// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

// Package oauth implements the native public-client flow for pinned Authelia.
// The caller owns Tor, verified TLS/mTLS, the trusted login UI, and encrypted
// profile persistence. This package never creates an outbound transport.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const CallbackURI = "http://127.0.0.1/oauth/callback"
const scope = "authelia.bearer.authz offline_access"
const maxBody = 64 << 10

var ErrLoginRequired = errors.New("OAuth login required")
var onionHost = regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)

// Token belongs only to its issuer/client registration. Never expose it to a
// browser bridge or log. Save must atomically encrypt it in the private profile.
type Token struct {
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type Config struct {
	Issuer, ClientID, Audience string
	HTTP                       *http.Client
	Save                       func(Token) error
}

type Client struct {
	config Config
	http   http.Client
	origin string
}

func New(config Config) (*Client, error) {
	u, err := url.Parse(config.Issuer)
	if err != nil || u.Scheme != "https" || !onionHost.MatchString(u.Host) || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Path != "/login" || u.RawPath != "" {
		return nil, errors.New("OAuth issuer must be the profile's HTTPS onion login URL")
	}
	audience, err := url.Parse(config.Audience)
	if err != nil || audience.Scheme != "https" || audience.Host != u.Host || audience.User != nil ||
		audience.Fragment != "" || audience.RawQuery != "" || audience.RawPath != "" {
		return nil, errors.New("OAuth audience must be an exact URL on the profile's onion")
	}
	if !safeValue(config.ClientID) || config.HTTP == nil || config.HTTP.Transport == nil || config.Save == nil {
		return nil, errors.New("OAuth requires a client id, explicit secure transport and private token persistence")
	}
	c := &Client{config: config, http: *config.HTTP, origin: "https://" + u.Host}
	c.http.Jar = nil // Each native login gets a separate, temporary cookie jar.
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if c.http.Timeout == 0 || c.http.Timeout > 45*time.Second {
		c.http.Timeout = 45 * time.Second
	}
	return c, nil
}

func (c *Client) post(ctx context.Context, endpoint string, values url.Values, output any) error {
	values.Set("client_id", c.config.ClientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.Issuer+"/api/oidc/"+endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return errors.New("invalid OAuth request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("OAuth endpoint unavailable")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return errors.New("invalid OAuth response size")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var denied struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &denied)
		switch denied.Error {
		case "invalid_grant", "invalid_client", "unauthorized_client", "access_denied":
			return ErrLoginRequired
		}
		return errors.New("OAuth request rejected")
	}
	if output != nil && json.Unmarshal(body, output) != nil {
		return errors.New("invalid OAuth response")
	}
	return nil
}

func (c *Client) exchange(ctx context.Context, values url.Values) (Token, error) {
	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := c.post(ctx, "token", values, &response); err != nil {
		return Token{}, err
	}
	if !strings.EqualFold(response.TokenType, "Bearer") || !safeValue(response.AccessToken) || !safeValue(response.RefreshToken) ||
		!strings.HasPrefix(response.AccessToken, "authelia_at_") || !strings.HasPrefix(response.RefreshToken, "authelia_rt_") ||
		response.ExpiresIn <= 0 || response.ExpiresIn > int64((365*24*time.Hour)/time.Second) {
		return Token{}, errors.New("invalid OAuth token response")
	}
	if response.Scope != "" {
		granted := strings.Fields(response.Scope)
		if !exactScopes(granted) {
			return Token{}, errors.New("required OAuth scopes were not granted")
		}
	}
	token := Token{Issuer: c.config.Issuer, ClientID: c.config.ClientID, AccessToken: response.AccessToken,
		RefreshToken: response.RefreshToken, ExpiresAt: time.Now().Add(time.Duration(response.ExpiresIn) * time.Second)}
	if err := c.config.Save(token); err != nil {
		return Token{}, errors.New("could not persist OAuth credentials")
	}
	return token, nil
}

// Refresh rotates credentials. Callers must serialize refreshes per profile;
// a failed rotation is never retried automatically with an old refresh token.
func (c *Client) Refresh(ctx context.Context, token Token) (Token, error) {
	if !c.owns(token) {
		return Token{}, ErrLoginRequired
	}
	return c.exchange(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token.RefreshToken}})
}

// Revoke invalidates both credentials through Authelia's supported endpoint.
// The caller separately closes live carriers and deletes the saved token.
func (c *Client) Revoke(ctx context.Context, token Token) error {
	if !c.owns(token) {
		return ErrLoginRequired
	}
	for _, value := range []struct{ token, hint string }{{token.AccessToken, "access_token"}, {token.RefreshToken, "refresh_token"}} {
		if err := c.post(ctx, "revocation", url.Values{"token": {value.token}, "token_type_hint": {value.hint}}, nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) owns(t Token) bool {
	return t.Issuer == c.config.Issuer && t.ClientID == c.config.ClientID && safeValue(t.AccessToken) && safeValue(t.RefreshToken)
}

func safeValue(s string) bool {
	if len(s) == 0 || len(s) > 8192 {
		return false
	}
	for _, r := range s {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func randomValue() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.New("OAuth entropy unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
