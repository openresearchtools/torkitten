package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"torkitten/internal/model"
)

const (
	testServiceID = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"
	testToken     = "0123456789abcdefghijklmnopqrstuvwxyzABCDEF"
)

type fakeManager struct {
	state model.State
	puts  []model.Mapping
}

func (manager *fakeManager) State() model.State { return manager.state.Clone() }

func (manager *fakeManager) Put(_ context.Context, mapping model.Mapping) (model.State, error) {
	manager.puts = append(manager.puts, mapping)
	manager.state.Mappings = append(manager.state.Mappings, mapping)
	return manager.state.Clone(), nil
}

func (manager *fakeManager) Delete(_ context.Context, prefix string) (model.State, error) {
	filtered := manager.state.Mappings[:0]
	for _, mapping := range manager.state.Mappings {
		if mapping.Prefix != prefix {
			filtered = append(filtered, mapping)
		}
	}
	manager.state.Mappings = filtered
	return manager.state.Clone(), nil
}

func testServer(t *testing.T) (*fakeManager, http.Handler) {
	t.Helper()
	manager := &fakeManager{state: model.NewState(testServiceID)}
	server, err := NewServer(manager, Options{
		BearerToken:    testToken,
		AllowedHosts:   []string{"localhost:12755"},
		AllowedOrigins: []string{"http://localhost:12755"},
		ForbiddenPorts: []uint16{12755},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager, server.Handler()
}

func TestMutationRequiresAuthorization(t *testing.T) {
	t.Parallel()

	_, handler := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "http://localhost:12755/api/v1/mappings", strings.NewReader(`{"prefix":"api","port":7777}`))
	request.Host = "localhost:12755"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

func TestMutationRejectsForeignOrigin(t *testing.T) {
	t.Parallel()

	_, handler := testServer(t)
	request := authorizedRequest(http.MethodPost, "/api/v1/mappings", `{"prefix":"api","port":7777}`)
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestPutMappingUsesStrictTypedInput(t *testing.T) {
	t.Parallel()

	manager, handler := testServer(t)
	request := authorizedRequest(http.MethodPost, "/api/v1/mappings", `{"prefix":"api","port":7777,"scheme":"http"}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(manager.puts) != 1 || manager.puts[0].Prefix != "api" || manager.puts[0].Port != 7777 {
		t.Fatalf("mapping not applied: %#v", manager.puts)
	}
}

func TestPutMappingRejectsURLAndControlPort(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"unknown URL":  `{"prefix":"api","port":7777,"url":"http://attacker"}`,
		"control port": `{"prefix":"api","port":12755}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, handler := testServer(t)
			request := authorizedRequest(http.MethodPost, "/api/v1/mappings", body)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code < 400 {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func authorizedRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, "http://localhost:12755"+path, strings.NewReader(body))
	request.Host = "localhost:12755"
	request.Header.Set("Authorization", "Bearer "+testToken)
	request.Header.Set("Content-Type", "application/json")
	return request
}
