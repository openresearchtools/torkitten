// Package mobile exposes only the trusted local UI API to native app shells.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"torkitten/internal/app"
)

type Core struct {
	app    *app.App
	cancel context.CancelFunc
}

func Open(stateDir, binDir string) (*Core, error) {
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Open(ctx, stateDir, binDir)
	if err != nil {
		cancel()
		return nil, err
	}
	return &Core{app: a, cancel: cancel}, nil
}

// Request is available only to bundled app content, never a service WebView.
func (c *Core) Request(method, path, body string) (string, error) {
	u, err := url.ParseRequestURI(path)
	if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || u.Host != "" || u.Scheme != "" || len(body) > 2*1024*1024 {
		return "", errors.New("invalid private UI request")
	}
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		return "", errors.New("unsupported method")
	}
	r, err := http.NewRequest(method, "http://app"+path, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	r.Header.Set("Origin", "torkitten://app")
	r.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	c.app.Handler().ServeHTTP(response, r)
	if response.Body.Len() > 2*1024*1024 {
		return "", errors.New("private response exceeds limit")
	}
	result, err := json.Marshal(struct {
		Status int    `json:"status"`
		Type   string `json:"type"`
		Body   []byte `json:"body"`
	}{response.Code, response.Header().Get("Content-Type"), response.Body.Bytes()})
	return string(result), err
}

func (c *Core) Close() error { c.cancel(); return c.app.Close() }
