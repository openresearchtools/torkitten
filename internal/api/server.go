package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"torkitten/internal/model"
)

const maxRequestBytes = 2048

type MappingManager interface {
	State() model.State
	Put(context.Context, model.Mapping) (model.State, error)
	Delete(context.Context, string) (model.State, error)
}

type Server struct {
	manager        MappingManager
	tokenHash      [sha256.Size]byte
	allowedHosts   map[string]struct{}
	allowedOrigins map[string]struct{}
	forbiddenPorts map[uint16]struct{}
	mutationLimit  *tokenBucket
}

type Options struct {
	BearerToken    string
	AllowedHosts   []string
	AllowedOrigins []string
	ForbiddenPorts []uint16
}

func NewServer(manager MappingManager, options Options) (*Server, error) {
	if manager == nil {
		return nil, errors.New("mapping manager is required")
	}
	if len(options.BearerToken) < 32 {
		return nil, errors.New("API bearer token must contain at least 32 characters")
	}
	server := &Server{
		manager:        manager,
		tokenHash:      sha256.Sum256([]byte(options.BearerToken)),
		allowedHosts:   make(map[string]struct{}, len(options.AllowedHosts)),
		allowedOrigins: make(map[string]struct{}, len(options.AllowedOrigins)),
		forbiddenPorts: make(map[uint16]struct{}, len(options.ForbiddenPorts)),
		mutationLimit:  newTokenBucket(10, 20),
	}
	for _, host := range options.AllowedHosts {
		server.allowedHosts[host] = struct{}{}
	}
	for _, origin := range options.AllowedOrigins {
		server.allowedOrigins[origin] = struct{}{}
	}
	for _, port := range options.ForbiddenPorts {
		server.forbiddenPorts[port] = struct{}{}
	}
	return server, nil
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.health)
	mux.HandleFunc("GET /api/v1/state", server.authorize(server.getState))
	mux.HandleFunc("POST /api/v1/mappings", server.authorize(server.rateLimit(server.putMapping)))
	mux.HandleFunc("DELETE /api/v1/mappings/{prefix}", server.authorize(server.rateLimit(server.deleteMapping)))
	return securityHeaders(mux)
}

func (server *Server) health(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(response, "{\"status\":\"ok\"}\n")
}

func (server *Server) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if _, allowed := server.allowedHosts[request.Host]; !allowed {
			writeError(response, http.StatusBadRequest, "invalid_host", "request host is not allowed")
			return
		}
		if origin := request.Header.Get("Origin"); origin != "" {
			if _, allowed := server.allowedOrigins[origin]; !allowed {
				writeError(response, http.StatusForbidden, "invalid_origin", "request origin is not allowed")
				return
			}
		}
		provided, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
		if !ok || provided == "" {
			writeError(response, http.StatusUnauthorized, "unauthorized", "valid bearer authorization is required")
			return
		}
		providedHash := sha256.Sum256([]byte(provided))
		if subtle.ConstantTimeCompare(providedHash[:], server.tokenHash[:]) != 1 {
			writeError(response, http.StatusUnauthorized, "unauthorized", "valid bearer authorization is required")
			return
		}
		next(response, request)
	}
}

func (server *Server) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if !server.mutationLimit.allow(time.Now()) {
			response.Header().Set("Retry-After", "1")
			writeError(response, http.StatusTooManyRequests, "rate_limited", "too many mapping changes")
			return
		}
		next(response, request)
	}
}

func (server *Server) getState(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, server.manager.State())
}

func (server *Server) putMapping(response http.ResponseWriter, request *http.Request) {
	if mediaType := request.Header.Get("Content-Type"); mediaType != "application/json" {
		writeError(response, http.StatusUnsupportedMediaType, "invalid_content_type", "Content-Type must be application/json")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var input struct {
		Prefix string       `json:"prefix"`
		Port   uint16       `json:"port"`
		Scheme model.Scheme `json:"scheme"`
	}
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_json", "request must be one strict JSON object")
		return
	}
	if err := requireEOF(decoder); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_json", "request must contain exactly one JSON object")
		return
	}
	if input.Scheme == "" {
		input.Scheme = model.SchemeHTTP
	}
	mapping := model.Mapping{Prefix: input.Prefix, Port: input.Port, Scheme: input.Scheme, Enable: true}
	if err := mapping.Validate(server.forbiddenPorts); err != nil {
		writeError(response, http.StatusUnprocessableEntity, "invalid_mapping", err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	state, err := server.manager.Put(ctx, mapping)
	if err != nil {
		writeError(response, http.StatusBadGateway, "apply_failed", err.Error())
		return
	}
	writeJSON(response, http.StatusOK, state)
}

func (server *Server) deleteMapping(response http.ResponseWriter, request *http.Request) {
	prefix := request.PathValue("prefix")
	if err := model.ValidatePrefix(prefix); err != nil {
		writeError(response, http.StatusUnprocessableEntity, "invalid_prefix", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	state, err := server.manager.Delete(ctx, prefix)
	if err != nil {
		writeError(response, http.StatusBadGateway, "apply_failed", err.Error())
		return
	}
	writeJSON(response, http.StatusOK, state)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(response, request)
	})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, code, message string) {
	writeJSON(response, status, map[string]string{"error": code, "message": message})
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("decode trailer: %w", err)
	}
	return nil
}

type tokenBucket struct {
	mutex  sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{rate: rate, burst: burst, tokens: burst}
}

func (bucket *tokenBucket) allow(now time.Time) bool {
	bucket.mutex.Lock()
	defer bucket.mutex.Unlock()
	if bucket.last.IsZero() {
		bucket.last = now
	}
	elapsed := now.Sub(bucket.last).Seconds()
	bucket.tokens += elapsed * bucket.rate
	if bucket.tokens > bucket.burst {
		bucket.tokens = bucket.burst
	}
	bucket.last = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}
