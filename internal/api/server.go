// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
	"torkitten/internal/apitoken"
	"torkitten/internal/authelia"
	"torkitten/internal/bootstrap"
	"torkitten/internal/control"
	"torkitten/internal/localsession"
	"torkitten/internal/model"
	"torkitten/internal/onboarding"
	"torkitten/internal/supervisor"
)

const localHost, localOrigin, failText = "localhost:12755", "http://localhost:12755", "request failed"

//go:embed templates/*.html assets/*
var files embed.FS

type Server struct {
	control                 *control.Manager
	sessions                *localsession.Manager
	login                   *localsession.Login
	setup                   *bootstrap.Manager
	tokens                  *apitoken.Manager
	onboard                 *onboarding.Manager
	process                 *supervisor.Supervisor
	template                *template.Template
	assets                  http.Handler
	secret                  []byte
	sem                     chan struct{}
	mu                      sync.Mutex
	minute                  int64
	general, authentication int
}
type Dependencies struct {
	Control    *control.Manager
	Sessions   *localsession.Manager
	Factors    *authelia.Client
	Setup      *bootstrap.Manager
	Tokens     *apitoken.Manager
	Onboarding *onboarding.Manager
	Supervisor *supervisor.Supervisor
}
type page struct{ CSRF, Error, OnionQR, AppleQR, AndroidQR string }
type input struct {
	Prefix        string         `json:"prefix"`
	OldPrefix     string         `json:"old_prefix"`
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Action        string         `json:"action"`
	Confirmation  string         `json:"confirmation"`
	Port          int            `json:"port"`
	LifetimeHours int            `json:"lifetime_hours"`
	Protocol      model.Protocol `json:"protocol"`
	Enabled       bool           `json:"enabled"`
	Scopes        []model.Scope  `json:"scopes"`
	Username      string         `json:"username"`
	Password      string         `json:"password"`
	NewPassword   string         `json:"new_password"`
	TOTP          string         `json:"totp"`
}

func New(deps Dependencies) (*Server, error) {
	if deps.Control == nil || deps.Sessions == nil || deps.Factors == nil || deps.Setup == nil || deps.Tokens == nil || deps.Onboarding == nil || deps.Supervisor == nil {
		return nil, errors.New("incomplete API dependencies")
	}
	tmpl, err := template.ParseFS(files, "templates/*.html")
	if err != nil {
		return nil, err
	}
	assets, _ := fs.Sub(files, "assets")
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return nil, err
	}
	return &Server{control: deps.Control, sessions: deps.Sessions, login: localsession.NewLogin(deps.Factors), setup: deps.Setup, tokens: deps.Tokens, onboard: deps.Onboarding, process: deps.Supervisor, template: tmpl, assets: http.StripPrefix("/assets/", http.FileServer(http.FS(assets))), secret: secret, sem: make(chan struct{}, 32)}, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Host != localHost || r.URL.Host != "" || r.URL.Scheme != "" {
		http.NotFound(w, r)
		return
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	if !s.allow(r.URL.Path) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	switch path := r.URL.Path; {
	case strings.HasPrefix(path, "/assets/"):
		s.asset(w, r)
	case strings.HasPrefix(path, "/setup"):
		s.setupRoute(w, r)
	case strings.HasPrefix(path, "/login"):
		s.loginRoute(w, r)
	case path == "/":
		s.dashboard(w, r)
	case path == "/logout":
		s.logout(w, r)
	case strings.HasPrefix(path, "/api/"):
		s.apiRoute(w, r)
	default:
		http.NotFound(w, r)
	}
}
func (s *Server) setupRoute(w http.ResponseWriter, r *http.Request) {
	if s.control.State().Initialized {
		http.NotFound(w, r)
		return
	}
	csrf := s.preauth(w, r)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/setup":
		s.render(w, "setup.html", page{CSRF: csrf})
	case r.Method == http.MethodPost && r.URL.Path == "/setup/password":
		if !s.validForm(r, csrf) {
			s.deny(w)
			return
		}
		password, confirmation := []byte(r.FormValue("password")), []byte(r.FormValue("confirmation"))
		defer wipe(password)
		defer wipe(confirmation)
		id, err := s.setup.Begin(r.Context(), false, r.FormValue("username"), password, confirmation)
		if err != nil {
			s.render(w, "setup.html", page{CSRF: csrf, Error: "Setup could not continue."})
			return
		}
		setCookie(w, "torkitten_setup", id, 600)
		http.Redirect(w, r, "/setup/totp", http.StatusSeeOther)
	case r.Method == http.MethodGet && r.URL.Path == "/setup/totp":
		s.render(w, "setup_totp.html", page{CSRF: csrf})
	case r.Method == http.MethodGet && r.URL.Path == "/setup/qr":
		s.setupQR(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/setup/totp":
		if !s.validForm(r, csrf) {
			s.deny(w)
			return
		}
		flow, err := r.Cookie("torkitten_setup")
		if err != nil {
			s.deny(w)
			return
		}
		cookie, _, err := s.setup.Complete(r.Context(), flow.Value, r.FormValue("totp"))
		if err != nil {
			s.render(w, "setup_totp.html", page{CSRF: csrf, Error: "Authentication failed."})
			return
		}
		setCookie(w, localsession.CookieName, cookie, 12*60*60)
		clearCookie(w, "torkitten_setup")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}
func (s *Server) setupQR(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("torkitten_setup")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data, err := s.setup.QR(cookie.Value)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writePNG(w, data)
}
func (s *Server) loginRoute(w http.ResponseWriter, r *http.Request) {
	if !s.control.State().Initialized {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	csrf := s.preauth(w, r)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/login":
		s.render(w, "login.html", page{CSRF: csrf})
	case r.Method == http.MethodPost && r.URL.Path == "/login/password":
		if !s.validForm(r, csrf) {
			s.deny(w)
			return
		}
		password := []byte(r.FormValue("password"))
		defer wipe(password)
		id, err := s.login.Begin(r.Context(), r.FormValue("username"), password)
		if err != nil {
			s.render(w, "login.html", page{CSRF: csrf, Error: "Authentication failed."})
			return
		}
		setCookie(w, "torkitten_login", id, 300)
		http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
	case r.Method == http.MethodGet && r.URL.Path == "/login/totp":
		s.render(w, "login_totp.html", page{CSRF: csrf})
	case r.Method == http.MethodPost && r.URL.Path == "/login/totp":
		s.finishLogin(w, r, csrf)
	default:
		http.NotFound(w, r)
	}
}
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, csrf string) {
	if !s.validForm(r, csrf) {
		s.deny(w)
		return
	}
	cookie, err := r.Cookie("torkitten_login")
	if err != nil {
		s.deny(w)
		return
	}
	owner, err := s.login.Complete(r.Context(), cookie.Value, r.FormValue("totp"))
	if err != nil {
		s.render(w, "login_totp.html", page{CSRF: csrf, Error: "Authentication failed. Start over."})
		return
	}
	token, _, err := s.sessions.Create(owner)
	if err != nil {
		s.fail(w)
		return
	}
	setCookie(w, localsession.CookieName, token, 12*60*60)
	clearCookie(w, "torkitten_login")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if !s.control.State().Initialized {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	_, auth, ok := s.browserAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, "dashboard.html", page{CSRF: auth.CSRF, OnionQR: qr64("https://" + s.control.State().Host("") + "/"), AppleQR: qr64("https://orbot.app/download/"), AndroidQR: qr64("https://play.google.com/store/apps/details?id=org.torproject.android")})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	cookie, auth, ok := s.browserAuth(r)
	if r.Method != http.MethodPost || !ok || !s.validMutation(r, cookie, auth.CSRF) {
		s.deny(w)
		return
	}
	_ = s.sessions.Revoke(auth.ID)
	clearCookie(w, localsession.CookieName)
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) apiRoute(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/mappings" || strings.HasPrefix(r.URL.Path, "/api/mappings/") {
		s.mappingRoute(w, r)
		return
	}
	cookie, auth, ok := s.browserAuth(r)
	if !ok {
		s.deny(w)
		return
	}
	if r.Method == http.MethodGet {
		s.sensitiveRead(w, r)
		return
	}
	if r.Method != http.MethodPost || !s.validMutation(r, cookie, auth.CSRF) {
		s.deny(w)
		return
	}
	var in input
	if !s.decode(w, r, &in) {
		return
	}
	s.sensitiveAction(w, r, in)
}
func (s *Server) mappingRoute(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/mappings" && r.Method == http.MethodGet {
		if !s.mappingAuth(r, model.ScopeMappingsRead) {
			s.deny(w)
			return
		}
		current := s.control.State()
		s.json(w, map[string]any{"mappings": current.Mappings, "publication_enabled": current.Publication, "onion": current.Host("")})
		return
	}
	if r.Method != http.MethodPost || !jsonType(r) || !s.mappingWriteAuth(r) {
		s.deny(w)
		return
	}
	var in input
	if !s.decode(w, r, &in) {
		return
	}
	mapping := model.Mapping{Prefix: in.Prefix, Port: in.Port, Protocol: in.Protocol, Enabled: true}
	var err error
	switch r.URL.Path {
	case "/api/mappings/create":
		err = s.control.CreateMapping(r.Context(), mapping)
	case "/api/mappings/update":
		mapping.Enabled = in.Enabled
		err = s.control.UpdateMapping(r.Context(), in.OldPrefix, mapping)
	case "/api/mappings/enable":
		err = s.control.EnableMapping(r.Context(), in.Prefix, in.Enabled)
	case "/api/mappings/delete":
		if validConfirmation(in.Confirmation, "DELETE") {
			err = s.control.DeleteMapping(r.Context(), in.ID)
		} else {
			err = errors.New("confirmation required")
		}
	case "/api/mappings/test":
		err = s.control.TestMapping(r.Context(), mapping)
	default:
		http.NotFound(w, r)
		return
	}
	s.result(w, err)
}
func (s *Server) sensitiveRead(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/state":
		s.stateJSON(w)
	case "/api/devices/pending.auth_private":
		s.onboard.ServePending(w, false)
	case "/api/devices/pending.png":
		s.onboard.ServePending(w, true)
	case "/api/application.png":
		s.applicationQR(w, r)
	default:
		http.NotFound(w, r)
	}
}
func (s *Server) sensitiveAction(w http.ResponseWriter, r *http.Request, in input) {
	var err error
	switch r.URL.Path {
	case "/api/devices/create":
		pending, credential, createErr := s.control.CreateDevice(r.Context(), in.Name)
		if createErr == nil {
			s.json(w, map[string]any{"id": pending.ID, "name": pending.Name, "credential": credential, "expires_at": pending.ExpiresAt})
			return
		}
		err = createErr
	case "/api/devices/acknowledge":
		err = s.control.AcknowledgeDevice(in.ID)
	case "/api/devices/revoke":
		if validConfirmation(in.Confirmation, "REVOKE") {
			err = s.control.RevokeDevice(r.Context(), in.ID)
		} else {
			err = errors.New("confirmation required")
		}
	case "/api/publication":
		expected := "STOP"
		if in.Enabled {
			expected = "START"
		}
		if validConfirmation(in.Confirmation, expected) {
			err = s.control.SetPublication(r.Context(), in.Enabled)
		} else {
			err = errors.New("confirmation required")
		}
	case "/api/components":
		if in.Action != "start" && !validConfirmation(in.Confirmation, strings.ToUpper(in.Action)) {
			err = errors.New("confirmation required")
		} else {
			err = s.process.Action(supervisor.Name(in.Name), in.Action)
		}
	case "/api/sessions/revoke":
		if validConfirmation(in.Confirmation, "REVOKE") {
			err = s.sessions.Revoke(in.ID)
		} else {
			err = errors.New("confirmation required")
		}
	case "/api/identity/rotate":
		credentials, rotateErr := s.control.RotateIdentity(r.Context(), in.Confirmation)
		if rotateErr == nil {
			s.json(w, map[string]any{"onion": s.control.State().Host(""), "credentials": credentials})
			return
		}
		err = rotateErr
	case "/api/owner/password":
		oldPassword, newPassword, confirmation := []byte(in.Password), []byte(in.NewPassword), []byte(in.Confirmation)
		defer wipe(oldPassword)
		defer wipe(newPassword)
		defer wipe(confirmation)
		err = s.onboard.ChangePassword(r.Context(), in.Username, oldPassword, newPassword, confirmation, in.TOTP)
		if err == nil {
			clearCookie(w, localsession.CookieName)
		}
	case "/api/owner/totp/begin":
		password := []byte(in.Password)
		defer wipe(password)
		image, beginErr := s.onboard.BeginTOTP(r.Context(), in.Username, password, in.TOTP)
		if beginErr == nil {
			s.json(w, map[string]string{"qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(image)})
			return
		}
		err = beginErr
	case "/api/owner/totp/complete":
		err = s.onboard.CompleteTOTP(r.Context(), in.TOTP)
		if err == nil {
			clearCookie(w, localsession.CookieName)
		}
	case "/api/tokens/create":
		if in.LifetimeHours < 0 || in.LifetimeHours > 8760 {
			err = errors.New("invalid token lifetime")
			break
		}
		token, id, createErr := s.tokens.Create(in.Name, in.Scopes, time.Duration(in.LifetimeHours)*time.Hour)
		if createErr == nil {
			s.json(w, map[string]string{"id": id, "token": token})
			return
		}
		err = createErr
	case "/api/tokens/revoke":
		if validConfirmation(in.Confirmation, "REVOKE") {
			err = s.tokens.Revoke(in.ID)
		} else {
			err = errors.New("confirmation required")
		}
	default:
		http.NotFound(w, r)
		return
	}
	s.result(w, err)
}
func (s *Server) applicationQR(w http.ResponseWriter, r *http.Request) {
	prefix, current, found := r.URL.Query().Get("prefix"), s.control.State(), false
	for _, mapping := range current.Mappings {
		found = found || mapping.Prefix == prefix
	}
	image, err := onboarding.EnrollmentQR("https://" + current.Host(prefix) + "/")
	if !found || err != nil {
		http.NotFound(w, r)
		return
	}
	writePNG(w, image)
}
func (s *Server) stateJSON(w http.ResponseWriter) {
	current := s.control.State()
	var pending any
	if current.Pending != nil {
		pending = map[string]any{"id": current.Pending.ID, "name": current.Pending.Name, "expires_at": current.Pending.ExpiresAt}
	}
	tokens := make([]map[string]any, 0, len(current.Tokens))
	for _, token := range current.Tokens {
		tokens = append(tokens, map[string]any{"id": token.ID, "name": token.Name, "scopes": token.Scopes, "created_at": token.CreatedAt, "last_use_at": token.LastUseAt, "expires_at": token.ExpiresAt})
	}
	s.json(w, map[string]any{"onion": current.Host(""), "publication_enabled": current.Publication, "mappings": current.Mappings, "devices": current.Devices, "pending_device": pending, "sessions": s.sessions.List(), "tokens": tokens, "components": s.process.Statuses()})
}
func (s *Server) browserAuth(r *http.Request) (string, localsession.Auth, bool) {
	cookie, err := r.Cookie(localsession.CookieName)
	if err != nil {
		return "", localsession.Auth{}, false
	}
	auth, err := s.sessions.Authenticate(cookie.Value)
	return cookie.Value, auth, err == nil
}
func (s *Server) mappingAuth(r *http.Request, scope model.Scope) bool {
	if token := bearerToken(r); token != "" {
		return s.tokens.Authorize(token, scope) == nil
	}
	_, _, ok := s.browserAuth(r)
	return ok
}
func (s *Server) mappingWriteAuth(r *http.Request) bool {
	if token := bearerToken(r); token != "" {
		return s.tokens.Authorize(token, model.ScopeMappingsWrite) == nil
	}
	cookie, auth, ok := s.browserAuth(r)
	return ok && s.validMutation(r, cookie, auth.CSRF)
}
func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if strings.HasPrefix(value, "Bearer ") && len(value) < 256 {
		return strings.TrimPrefix(value, "Bearer ")
	}
	return ""
}
func (s *Server) preauth(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie("torkitten_flow")
	if err != nil || len(cookie.Value) != 43 {
		value, _ := localsession.RandomToken()
		setCookie(w, "torkitten_flow", value, 900)
		return s.flowCSRF(value)
	}
	return s.flowCSRF(cookie.Value)
}
func (s *Server) flowCSRF(value string) string {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (s *Server) validForm(r *http.Request, csrf string) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && media == "application/x-www-form-urlencoded" && r.Header.Get("Origin") == localOrigin && r.ParseForm() == nil && subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(csrf)) == 1
}
func (s *Server) validMutation(r *http.Request, cookie, csrf string) bool {
	return r.Header.Get("Origin") == localOrigin && jsonType(r) && localsession.ValidateCSRF(cookie, csrf) && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf)) == 1
}
func validConfirmation(a, b string) bool { return strings.EqualFold(strings.TrimSpace(a), b) }
func qr64(value string) string {
	image, _ := onboarding.EnrollmentQR(value)
	return base64.StdEncoding.EncodeToString(image)
}
func writePNG(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(data)
}
func jsonType(r *http.Request) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && media == "application/json"
}
func (s *Server) decode(w http.ResponseWriter, r *http.Request, out any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	return true
}
func (s *Server) allow(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	minute := time.Now().Unix() / 60
	if s.minute != minute {
		s.minute, s.general, s.authentication = minute, 0, 0
	}
	if strings.HasPrefix(path, "/login") || strings.HasPrefix(path, "/setup") {
		s.authentication++
		return s.authentication <= 30
	}
	s.general++
	return s.general <= 240
}
func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.assets.ServeHTTP(w, r)
}
func (s *Server) render(w http.ResponseWriter, name string, data page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if s.template.ExecuteTemplate(w, name, data) != nil {
		s.fail(w)
	}
}
func (s *Server) json(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}
func (s *Server) result(w http.ResponseWriter, err error) {
	if err != nil {
		http.Error(w, "request failed", http.StatusBadRequest)
		return
	}
	s.json(w, map[string]bool{"ok": true})
}
func (s *Server) deny(w http.ResponseWriter) { http.Error(w, "denied", http.StatusForbidden) }
func (s *Server) fail(w http.ResponseWriter) { http.Error(w, failText, 500) }
func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}
func setCookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: age, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}
func clearCookie(w http.ResponseWriter, name string) { setCookie(w, name, "", -1) }
func wipe(data []byte)                               { clear(data) }
