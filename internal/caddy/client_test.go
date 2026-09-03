package caddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientLoadsJSON(t *testing.T) {
	t.Parallel()

	var contentType string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		contentType = request.Header.Get("Content-Type")
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, time.Second)
	if err := client.Load(context.Background(), []byte(`{"apps":{}}`)); err != nil {
		t.Fatal(err)
	}
	if contentType != "application/json" {
		t.Fatalf("Content-Type = %q", contentType)
	}
}

func TestClientRejectsCaddyError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Error(response, "invalid route", http.StatusBadRequest)
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, time.Second)
	if err := client.Load(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("Caddy error response was accepted")
	}
}
