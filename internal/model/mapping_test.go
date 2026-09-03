package model

import "testing"

const testServiceID = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"

func TestValidatePrefix(t *testing.T) {
	t.Parallel()

	valid := []string{"a", "api7", "my-app", "a1-b2"}
	for _, prefix := range valid {
		if err := ValidatePrefix(prefix); err != nil {
			t.Errorf("ValidatePrefix(%q) returned %v", prefix, err)
		}
	}

	invalid := []string{"", "Auth", "auth", "-api", "api-", "api.example", "api/path", "api%2e", "café", "*"}
	for _, prefix := range invalid {
		if err := ValidatePrefix(prefix); err == nil {
			t.Errorf("ValidatePrefix(%q) unexpectedly succeeded", prefix)
		}
	}
}

func TestStateRejectsDuplicateAndControlPort(t *testing.T) {
	t.Parallel()

	state := NewState(testServiceID)
	state.Mappings = []Mapping{
		{Prefix: "api", Port: 7777, Scheme: SchemeHTTP, Enable: true},
		{Prefix: "api", Port: 8888, Scheme: SchemeHTTP, Enable: true},
	}
	if err := state.Validate(nil); err == nil {
		t.Fatal("duplicate prefix was accepted")
	}

	state.Mappings = []Mapping{{Prefix: "api", Port: 12755, Scheme: SchemeHTTP, Enable: true}}
	if err := state.Validate(map[uint16]struct{}{12755: {}}); err == nil {
		t.Fatal("control-plane port was accepted")
	}
}

func TestBaseDomain(t *testing.T) {
	t.Parallel()

	domain, err := BaseDomain(testServiceID)
	if err != nil {
		t.Fatal(err)
	}
	if want := testServiceID + ".onion"; domain != want {
		t.Fatalf("BaseDomain() = %q, want %q", domain, want)
	}
}
