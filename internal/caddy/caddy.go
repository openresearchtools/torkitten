// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package caddy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"torkitten/internal/model"
)

const maxResponse = 2 << 20

type Renderer struct {
	AdminSocket     string
	OnionTLSSocket  string
	OnionHTTPSocket string
	AutheliaSocket  string
	LauncherRoot    string
	StorageRoot     string
	TargetHost      string
	Aliases         []string
	PublicRoot      []byte
}

func DefaultRenderer() Renderer {
	return Renderer{
		AdminSocket: "/run/torkitten/caddy-admin.sock", OnionTLSSocket: "/run/torkitten/caddy-https.sock",
		OnionHTTPSocket: "/run/torkitten/caddy-http.sock", AutheliaSocket: "/run/torkitten/authelia.sock",
		LauncherRoot: "/usr/share/torkitten/launcher",
		StorageRoot:  "/var/lib/torkitten/caddy/storage", TargetHost: "127.0.0.1",
	}
}

var safePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
var safeHost = regexp.MustCompile(`^[a-z0-9.-]+$`)
var untrustedHeaders = []string{"Remote-User", "Remote-Groups", "Remote-Email", "Remote-Name", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-URI", "X-Forwarded-Method"}

func (r Renderer) Render(s model.State) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	for _, path := range []string{r.AdminSocket, r.OnionTLSSocket, r.OnionHTTPSocket, r.AutheliaSocket, r.LauncherRoot, r.StorageRoot} {
		if !filepath.IsAbs(path) || !safePath.MatchString(path) {
			return nil, errors.New("unsafe internal Caddy path")
		}
	}
	if !safeHost.MatchString(r.TargetHost) {
		return nil, errors.New("unsafe fixed upstream host")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "{\n\tadmin unix/%s\n\tpersist_config off\n\tstorage file_system {\n\t\troot %s\n\t}\n\tpki {\n\t\tca local {\n\t\t\tname \"Torkitten Local CA\"\n\t\t}\n\t}\n\tcert_issuer internal {\n\t\tlifetime 9528h\n\t\tsign_with_root\n\t}\n\tskip_install_trust\n\tauto_https disable_redirects\n}\n\n", r.AdminSocket, r.StorageRoot)
	if s.ServiceID == "" || !s.Initialized {
		fmt.Fprintf(&b, "https://:443 {\n\tbind unix/%s\n\trespond \"not found\" 404\n}\n\nhttp://:80 {\n\tbind unix/%s\n\trespond \"not found\" 404\n}\n", r.OnionTLSSocket, r.OnionHTTPSocket)
		return []byte(b.String()), nil
	}
	mappings := append([]model.Mapping(nil), s.Mappings...)
	sort.Slice(mappings, func(i, j int) bool { return mappings[i].Prefix < mappings[j].Prefix })
	ids := []string{s.ServiceID}
	for _, id := range r.Aliases {
		if !regexp.MustCompile(`^[a-z2-7]{56}$`).MatchString(id) || id == s.ServiceID {
			return nil, errors.New("invalid Caddy identity alias")
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		alias := s
		alias.ServiceID = id
		fmt.Fprintf(&b, "https://%s, https://*.%s, ", alias.Host(""), alias.Host(""))
	}
	b.WriteString("https://:443 {\n")
	fmt.Fprintf(&b, "\tbind unix/%s\n\ttls {\n\t\tprotocols tls1.2 tls1.3\n\t}\n", r.OnionTLSSocket)
	r.renderPortal(&b, hosts(ids, ""))
	fmt.Fprintf(&b, "\t@launcher host %s\n\thandle @launcher {\n", strings.Join(hosts(ids, ""), " "))
	r.renderProtectedPrefix(&b)
	b.WriteString("\t\t@apps path /apps.json\n\t\theader @apps Content-Type application/json\n")
	fmt.Fprintf(&b, "\t\trespond @apps `%s` 200\n", launcherJSON(s, mappings))
	if len(r.PublicRoot) != 0 {
		b.WriteString("\t\t@root_ca path /trust/torkitten-root-ca.pem\n\t\theader @root_ca Content-Type application/x-pem-file\n\t\theader @root_ca Content-Disposition `attachment; filename=torkitten-root-ca.pem`\n")
		fmt.Fprintf(&b, "\t\trespond @root_ca `%s` 200\n", r.PublicRoot)
	}
	fmt.Fprintf(&b, "\t\theader {\n\t\t\tCache-Control no-store\n\t\t\tContent-Security-Policy \"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'\"\n\t\t\tReferrer-Policy no-referrer\n\t\t\tX-Content-Type-Options nosniff\n\t\t}\n\t\troot * %s\n\t\tfile_server\n\t}\n", r.LauncherRoot)
	for _, mapping := range mappings {
		if !mapping.Enabled {
			continue
		}
		host := strings.Join(hosts(ids, mapping.Prefix), " ")
		fmt.Fprintf(&b, "\t@map_%s host %s\n\thandle @map_%s {\n", mapping.Prefix, host, mapping.Prefix)
		r.renderProtectedPrefix(&b)
		fmt.Fprintf(&b, "\t\treverse_proxy %s://%s:%d\n\t}\n", mapping.Protocol, r.TargetHost, mapping.Port)
	}
	b.WriteString("\trespond \"not found\" 404\n}\n\n")
	fmt.Fprintf(&b, "http://:80 {\n\tbind unix/%s\n\trespond \"not found\" 404\n}\n", r.OnionHTTPSocket)
	return []byte(b.String()), nil
}
func hosts(ids []string, prefix string) []string {
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = (model.State{ServiceID: id}).Host(prefix)
	}
	return result
}
func launcherJSON(s model.State, mappings []model.Mapping) string {
	apps := make([]map[string]string, 0, len(mappings))
	for _, mapping := range mappings {
		if mapping.Enabled {
			apps = append(apps, map[string]string{"name": mapping.Prefix, "url": "https://" + s.Host(mapping.Prefix) + "/"})
		}
	}
	data, _ := json.Marshal(map[string]any{"apps": apps})
	return string(data)
}
func (r Renderer) renderPortal(b *strings.Builder, hosts []string) {
	b.WriteString("\t@portal {\n")
	fmt.Fprintf(b, "\t\thost %s\n", strings.Join(hosts, " "))
	b.WriteString("\t\tpath /login /login/ /login/favicon.ico /login/manifest.json /login/robots.txt /login/static/* /login/locales /login/locales/* /login/api/state /login/api/configuration /login/api/configuration/password-policy /login/api/checks/safe-redirection /login/api/firstfactor /login/api/logout /login/api/user/info /login/api/secondfactor/totp\n\t\tmethod GET HEAD POST\n\t}\n\thandle @portal {\n\t\troute {\n")
	for _, h := range untrustedHeaders {
		fmt.Fprintf(b, "\t\t\trequest_header -%s\n", h)
	}
	fmt.Fprintf(b, "\t\t\treverse_proxy unix/%s {\n\t\t\t\theader_up X-Forwarded-For 127.0.0.1\n\t\t\t\theader_up X-Forwarded-Host {http.request.host}\n\t\t\t\theader_up X-Forwarded-Proto https\n\t\t\t}\n\t\t}\n\t}\n", r.AutheliaSocket)
}
func (r Renderer) renderProtectedPrefix(b *strings.Builder) {
	b.WriteString("\t\troute {\n")
	for _, h := range untrustedHeaders {
		fmt.Fprintf(b, "\t\t\trequest_header -%s\n", h)
	}
	fmt.Fprintf(b, "\t\t\tforward_auth unix/%s {\n\t\t\t\turi /login/api/authz/forward-auth\n\t\t\t\theader_up X-Forwarded-For 127.0.0.1\n\t\t\t\theader_up X-Forwarded-Host {http.request.host}\n\t\t\t\theader_up X-Forwarded-Proto https\n\t\t\t\tcopy_headers Remote-User Remote-Groups Remote-Email Remote-Name\n\t\t\t}\n\t\t}\n", r.AutheliaSocket)
}

type Applier interface {
	Apply(context.Context, []byte) ([]byte, error)
}

type Client struct {
	http *http.Client
}

func NewClient(socket string) (*Client, error) {
	if !filepath.IsAbs(socket) || !safePath.MatchString(socket) {
		return nil, errors.New("invalid Caddy socket")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &Client{http: &http.Client{Transport: transport, Timeout: 15 * time.Second}}, nil
}
func (c *Client) Apply(ctx context.Context, caddyfile []byte) ([]byte, error) {
	config, err := c.Adapt(ctx, caddyfile)
	if err != nil {
		return nil, err
	}
	if err = c.Load(ctx, config); err != nil {
		return nil, err
	}
	return config, nil
}
func (c *Client) Adapt(ctx context.Context, caddyfile []byte) ([]byte, error) {
	body, err := c.request(ctx, http.MethodPost, "/adapt", "text/caddyfile", caddyfile)
	if err != nil {
		return nil, fmt.Errorf("adapt Caddy configuration: %w", err)
	}
	var response struct {
		Warnings []json.RawMessage `json:"warnings"`
		Result   json.RawMessage   `json:"result"`
	}
	if err = json.Unmarshal(body, &response); err != nil || len(response.Result) == 0 {
		return nil, errors.New("Caddy returned malformed adaptation")
	}
	if len(response.Warnings) != 0 {
		return nil, errors.New("Caddy adaptation returned warnings")
	}
	var valid any
	if json.Unmarshal(response.Result, &valid) != nil {
		return nil, errors.New("Caddy adaptation result is not JSON")
	}
	return append([]byte(nil), response.Result...), nil
}
func (c *Client) Load(ctx context.Context, config []byte) error {
	_, err := c.request(ctx, http.MethodPost, "/load", "application/json", config)
	if err != nil {
		return fmt.Errorf("load Caddy configuration: %w", err)
	}
	return nil
}
func (c *Client) RootCA(ctx context.Context) ([]byte, error) {
	body, err := c.request(ctx, http.MethodGet, "/pki/ca/local", "", nil)
	if err != nil {
		return nil, err
	}
	var response struct {
		Root string `json:"root_certificate"`
	}
	if json.Unmarshal(body, &response) != nil || len(response.Root) > 64<<10 {
		return nil, errors.New("invalid Caddy PKI response")
	}
	block, rest := pem.Decode([]byte(response.Root))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("Caddy did not return one public root certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		return nil, errors.New("Caddy root is not a CA certificate")
	}
	return []byte(response.Root), nil
}
func (c *Client) Healthy(ctx context.Context) error {
	_, err := c.request(ctx, http.MethodGet, "/config/", "", nil)
	return err
}
func (c *Client) request(ctx context.Context, method, path, contentType string, data []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://caddy"+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(body) > maxResponse {
		return nil, errors.New("invalid Caddy response body")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("Caddy returned HTTP %d", resp.StatusCode)
	}
	return body, nil
}
