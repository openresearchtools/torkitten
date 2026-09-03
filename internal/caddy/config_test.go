package caddy

import (
	"encoding/json"
	"strings"
	"testing"

	"torkitten/internal/model"
)

const testServiceID = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"

func testOptions() RenderOptions {
	return RenderOptions{
		Listen:            "127.0.0.1:8443",
		AdminSocket:       "/run/torkitten/caddy-admin.sock",
		AutheliaUpstream:  "127.0.0.1:9091",
		HostLoopback:      "127.0.0.1",
		CertificateIssuer: "torkitten",
	}
}

func TestRenderContainsForwardAuthBeforeTrustedUpstream(t *testing.T) {
	t.Parallel()

	state := model.NewState(testServiceID)
	state.Mappings = []model.Mapping{{Prefix: "wiki", Port: 7777, Scheme: model.SchemeHTTP, Enable: true}}
	document, err := Render(state, map[uint16]struct{}{12755: {}}, testOptions())
	if err != nil {
		t.Fatal(err)
	}

	text := string(document)
	authPosition := strings.Index(text, "/api/authz/forward-auth")
	upstreamPosition := strings.Index(text, "127.0.0.1:7777")
	if authPosition < 0 || upstreamPosition < 0 || authPosition > upstreamPosition {
		t.Fatalf("forward authorization must precede the application proxy:\n%s", text)
	}
	if !strings.Contains(text, `"wiki.`+testServiceID+`.onion"`) {
		t.Fatalf("generated exact application hostname is absent:\n%s", text)
	}
	if strings.Contains(text, `"metrics"`) || strings.Contains(text, `"tracing"`) {
		t.Fatalf("generated configuration enabled telemetry:\n%s", text)
	}

	var parsed map[string]any
	if err := json.Unmarshal(document, &parsed); err != nil {
		t.Fatalf("generated configuration is not JSON: %v", err)
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	t.Parallel()

	left := model.NewState(testServiceID)
	left.Mappings = []model.Mapping{
		{Prefix: "wiki", Port: 8888, Scheme: model.SchemeHTTP, Enable: true},
		{Prefix: "api", Port: 7777, Scheme: model.SchemeHTTP, Enable: true},
	}
	right := left.Clone()
	right.Mappings[0], right.Mappings[1] = right.Mappings[1], right.Mappings[0]

	one, err := Render(left, nil, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	two, err := Render(right, nil, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if string(one) != string(two) {
		t.Fatal("equivalent mapping sets produced different Caddy configurations")
	}
}
