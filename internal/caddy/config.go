package caddy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"torkitten/internal/model"
)

type RenderOptions struct {
	Listen            string
	AdminSocket       string
	AutheliaUpstream  string
	HostLoopback      string
	CertificateIssuer string
}

func (options RenderOptions) validate() error {
	if options.Listen == "" {
		return errors.New("Caddy listener is required")
	}
	if !strings.HasPrefix(options.AdminSocket, "/") {
		return errors.New("Caddy administration socket must be absolute")
	}
	if _, _, err := net.SplitHostPort(options.AutheliaUpstream); err != nil {
		return fmt.Errorf("invalid Authelia upstream: %w", err)
	}
	ip := net.ParseIP(options.HostLoopback)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("application upstream address must be a numeric loopback address")
	}
	if options.CertificateIssuer == "" {
		return errors.New("certificate issuer is required")
	}
	return nil
}

func Render(state model.State, forbiddenPorts map[uint16]struct{}, options RenderOptions) ([]byte, error) {
	if err := state.Validate(forbiddenPorts); err != nil {
		return nil, err
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	baseDomain, err := model.BaseDomain(state.ServiceID)
	if err != nil {
		return nil, err
	}

	mappings := append([]model.Mapping(nil), state.Mappings...)
	sort.Slice(mappings, func(left, right int) bool {
		return mappings[left].Prefix < mappings[right].Prefix
	})

	authDomain := "auth." + baseDomain
	hosts := []string{baseDomain, authDomain}
	routes := []any{
		hostRoute(authDomain, []any{reverseProxy(options.AutheliaUpstream, model.SchemeHTTP)}),
		hostRoute(baseDomain, []any{reverseProxy(options.AutheliaUpstream, model.SchemeHTTP)}),
	}
	for _, mapping := range mappings {
		if !mapping.Enable {
			continue
		}
		host := mapping.Prefix + "." + baseDomain
		hosts = append(hosts, host)
		target := net.JoinHostPort(options.HostLoopback, fmt.Sprintf("%d", mapping.Port))
		routes = append(routes, hostRoute(host, []any{
			sanitizeForwardingHeaders(),
			forwardAuthorization(options.AutheliaUpstream),
			reverseProxy(target, mapping.Scheme),
		}))
	}
	routes = append(routes, map[string]any{
		"handle": []any{map[string]any{
			"handler":     "static_response",
			"status_code": 404,
			"body":        "Not found\n",
		}},
		"terminal": true,
	})

	document := map[string]any{
		"admin": map[string]any{
			"listen": fmt.Sprintf("unix/%s|0600", options.AdminSocket),
			"config": map[string]any{"persist": false},
		},
		"apps": map[string]any{
			"pki": map[string]any{
				"certificate_authorities": map[string]any{
					options.CertificateIssuer: map[string]any{
						"name": "Torkitten Private Certificate Authority",
					},
				},
			},
			"tls": map[string]any{
				"automation": map[string]any{
					"policies": []any{map[string]any{
						"subjects": hosts,
						"issuers": []any{map[string]any{
							"module": "internal",
							"ca":     options.CertificateIssuer,
						}},
					}},
				},
			},
			"http": map[string]any{
				"servers": map[string]any{
					"onion": map[string]any{
						"listen":                  []string{options.Listen},
						"routes":                  routes,
						"tls_connection_policies": []any{map[string]any{}},
						"strict_sni_host":         true,
						"automatic_https":         map[string]any{"disable": true},
						"protocols":               []string{"h1", "h2"},
						"read_header_timeout":     "30s",
						"idle_timeout":            "5m",
						"max_header_bytes":        1_048_576,
					},
				},
			},
		},
	}

	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Caddy configuration: %w", err)
	}
	return append(encoded, '\n'), nil
}

func hostRoute(host string, handlers []any) map[string]any {
	return map[string]any{
		"match":    []any{map[string]any{"host": []string{host}}},
		"handle":   handlers,
		"terminal": true,
	}
}

func sanitizeForwardingHeaders() map[string]any {
	return map[string]any{
		"handler": "headers",
		"request": map[string]any{
			"delete": []string{
				"Forwarded",
				"X-Forwarded-*",
				"X-Real-IP",
				"X-Authelia-*",
				"Remote-User",
				"Remote-Groups",
				"Remote-Email",
				"Remote-Name",
			},
		},
	}
}

func forwardAuthorization(upstream string) map[string]any {
	return map[string]any{
		"handler": "reverse_proxy",
		"upstreams": []any{map[string]any{
			"dial": upstream,
		}},
		"rewrite": map[string]any{
			"method": "GET",
			"uri":    "/api/authz/forward-auth",
		},
		"headers": map[string]any{
			"request": map[string]any{
				"set": map[string][]string{
					"X-Forwarded-Method": {"{http.request.method}"},
					"X-Forwarded-Proto":  {"https"},
					"X-Forwarded-Host":   {"{http.request.host}"},
					"X-Forwarded-Uri":    {"{http.request.uri}"},
				},
			},
		},
		"handle_response": []any{map[string]any{
			"match": map[string]any{"status_code": []int{2}},
			"routes": []any{map[string]any{
				"handle": []any{map[string]any{"handler": "vars"}},
			}},
		}},
	}
}

func reverseProxy(upstream string, scheme model.Scheme) map[string]any {
	handler := map[string]any{
		"handler":            "reverse_proxy",
		"upstreams":          []any{map[string]any{"dial": upstream}},
		"stream_close_delay": "5m",
	}
	switch scheme {
	case model.SchemeHTTPS:
		handler["transport"] = map[string]any{
			"protocol": "http",
			"tls":      map[string]any{},
		}
	case model.SchemeH2C:
		handler["transport"] = map[string]any{
			"protocol": "http",
			"versions": []string{"h2c"},
		}
	}
	return handler
}

func Compact(value []byte) ([]byte, error) {
	var output bytes.Buffer
	if err := json.Compact(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
