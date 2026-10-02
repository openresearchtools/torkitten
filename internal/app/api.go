// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"strings"
	"torkitten/internal/ui"
)

func respond(w http.ResponseWriter, value any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		value = map[string]string{"error": err.Error()}
	}
	if value == nil {
		value = map[string]bool{"ok": true}
	}
	_ = json.NewEncoder(w).Encode(value)
}
func input(r *http.Request, dst any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("JSON content type required")
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, MaxFile+1))
	if err != nil {
		return err
	}
	return decode(b, dst)
}
func (a *App) Handler() http.Handler {
	assets := ui.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'none'")
		if r.Host != "app" || r.URL.RawQuery != "" && r.URL.Path != "/api/services" {
			http.Error(w, "forbidden", 403)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("Origin") != "torkitten://app" {
				http.Error(w, "forbidden", 403)
				return
			}
			a.localAPI(w, r)
			return
		}
		if r.Method != "GET" || r.URL.Path != "/" && r.URL.Path != "/app.js" && r.URL.Path != "/app.css" {
			http.NotFound(w, r)
			return
		}
		assets.ServeHTTP(w, r)
	})
}
func (a *App) localAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && r.URL.Path == "/api/state" {
		a.mu.Lock()
		host := a.host
		host.Devices = nil
		services := a.services
		problem := a.hostError
		a.mu.Unlock()
		respond(w, map[string]any{"host": host, "services": services, "error": problem, "profiles": a.PublicProfiles()}, nil)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/services" {
		list, err := a.ProfileServices(r.Context(), r.URL.Query().Get("id"))
		respond(w, map[string]any{"services": list}, err)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		ID       string    `json:"id"`
		Name     string    `json:"name"`
		Username string    `json:"username"`
		Password string    `json:"password"`
		TOTP     string    `json:"totp"`
		Data     string    `json:"data"`
		Service  string    `json:"service"`
		Action   string    `json:"action"`
		Enabled  bool      `json:"enabled"`
		Port     int       `json:"port"`
		Accept   bool      `json:"accept"`
		Confirm  bool      `json:"confirm"`
		Services *Services `json:"services"`
	}
	if err := input(r, &req); err != nil {
		respond(w, nil, err)
		return
	}
	var result any
	var err error
	switch r.URL.Path {
	case "/api/identity":
		if !req.Confirm {
			err = errors.New("identity replacement requires confirmation")
			break
		}
		a.mu.Lock()
		result, err = a.issueIdentity(r.Context(), req.Username)
		a.mu.Unlock()
	case "/api/revoke":
		a.mu.Lock()
		err = a.revokeSessions()
		a.mu.Unlock()
	case "/api/enroll":
		a.mu.Lock()
		result, err = a.enroll(r.Context(), req.Name, req.Password)
		a.mu.Unlock()
	case "/api/config":
		if req.Services == nil {
			err = errors.New("services document required")
		} else {
			err = a.saveServices(*req.Services)
		}
	case "/api/host-action":
		err = a.action(r.Context(), req.Service, req.Action, "")
	case "/api/scan-qr":
		var data []byte
		data, err = base64.StdEncoding.DecodeString(req.Data)
		if err == nil {
			data, err = decodeQR(data)
		}
		if errors.Is(err, ErrQRNotFound) {
			result, err = map[string]bool{"found": false}, nil
		} else if err == nil {
			result = map[string]any{"found": true, "data": base64.StdEncoding.EncodeToString(data)}
		}
	case "/api/import", "/api/import-qr":
		var data []byte
		data, err = base64.StdEncoding.DecodeString(req.Data)
		if err == nil && r.URL.Path == "/api/import-qr" {
			data, err = decodeQR(data)
		}
		if err == nil {
			var id string
			id, err = a.ImportBundle(r.Context(), data, req.Password, req.Name)
			result = map[string]string{"id": id}
		}
	case "/api/unlock":
		err = a.UnlockProfile(r.Context(), req.ID, req.Password)
	case "/api/login":
		result, err = a.LoginProfile(r.Context(), req.ID, req.Username, req.Password, req.TOTP)
	case "/api/consent":
		err = a.AcceptProfile(r.Context(), req.ID, req.Accept)
	case "/api/map":
		var port int
		port, err = a.MapProfile(r.Context(), req.ID, req.Service, req.Enabled, req.Port)
		result = map[string]int{"port": port}
	case "/api/action":
		err = a.ProfileAction(r.Context(), req.ID, req.Service, req.Action)
	case "/api/disconnect":
		err = a.DisconnectProfile(r.Context(), req.ID)
	default:
		http.NotFound(w, r)
		return
	}
	respond(w, result, err)
}

var ErrQRNotFound = errors.New("no TorKitten encrypted QR found")

func decodeQR(data []byte) ([]byte, error) {
	if len(data) > MaxFile {
		return nil, errors.New("QR image too large")
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 4096 || cfg.Height > 4096 {
		return nil, errors.New("invalid or oversized QR image")
	}
	im, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(im)
	if err != nil {
		return nil, err
	}
	q, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		var unreadable gozxing.ReaderException
		if errors.As(err, &unreadable) {
			return nil, ErrQRNotFound
		}
		return nil, err
	}
	s := q.GetText()
	if !strings.HasPrefix(s, "TK2:") {
		return nil, ErrQRNotFound
	}
	bundle, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "TK2:"))
	if err != nil || !bytes.HasPrefix(bundle, []byte("age-encryption.org/v1\n")) {
		return nil, errors.New("invalid TorKitten encrypted QR payload")
	}
	return bundle, nil
}
func (a *App) remoteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == "GET" && r.URL.Path == "/api/info" {
		a.mu.Lock()
		result := map[string]any{"version": 2, "client_id": a.host.OAuthClient}
		a.mu.Unlock()
		respond(w, result, nil)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/tunnel/") {
		a.mu.Lock()
		relay := a.relay
		a.mu.Unlock()
		if relay == nil {
			http.Error(w, "unavailable", 503)
			return
		}
		relay.ServeHTTP(w, r)
		return
	}
	var req struct {
		ID     string `json:"id"`
		Action string `json:"action"`
	}
	if r.Method == "POST" && r.URL.Path == "/api/actions" {
		if err := input(r, &req); err != nil {
			respond(w, nil, err)
			return
		}
	}
	a.mu.Lock()
	epoch := a.host.OAuthClient
	a.mu.Unlock()
	if err := a.authorizeBearer(r.Context(), bearer(r.Header.Get("Authorization"))); err != nil {
		http.Error(w, "OAuth login required", 401)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/services":
		respond(w, map[string]any{"services": a.serviceList()}, nil)
	case r.Method == "POST" && r.URL.Path == "/api/actions":
		respond(w, nil, a.action(r.Context(), req.ID, req.Action, epoch))
	default:
		http.NotFound(w, r)
	}
}
