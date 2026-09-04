// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"strings"
	"testing"
	"time"
)

func TestValidatePrefix(t *testing.T) {
	valid := []string{"a", "api", "a-b", strings.Repeat("a", 63)}
	for _, value := range valid {
		if err := ValidatePrefix(value); err != nil {
			t.Errorf("ValidatePrefix(%q): %v", value, err)
		}
	}
	invalid := []string{"", "Auth", "-api", "api-", "a.b", "a_b", " api", "auth", "www", strings.Repeat("a", 64), "møøse"}
	for _, value := range invalid {
		if err := ValidatePrefix(value); err == nil {
			t.Errorf("ValidatePrefix(%q) succeeded", value)
		}
	}
}

func TestValidateMapping(t *testing.T) {
	good := Mapping{Prefix: "api", Port: 7777, Protocol: ProtocolHTTP, Enabled: true}
	if err := ValidateMapping(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Mapping{
		{Prefix: "auth", Port: 1, Protocol: ProtocolHTTP},
		{Prefix: "api", Port: 0, Protocol: ProtocolHTTP},
		{Prefix: "api", Port: 65536, Protocol: ProtocolHTTP},
		{Prefix: "api", Port: 12755, Protocol: ProtocolHTTP},
		{Prefix: "api", Port: 80, Protocol: "ftp"},
	} {
		if err := ValidateMapping(bad); err == nil {
			t.Errorf("ValidateMapping(%+v) succeeded", bad)
		}
	}
}

func TestStateValidation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	s := NewState()
	s.ServiceID = strings.Repeat("a", 56)
	s.Initialized = true
	s.Mappings = []Mapping{{Prefix: "api", Port: 7777, Protocol: ProtocolHTTP}}
	s.Devices = []Device{{ID: strings.Repeat("a", 32), Name: "phone", PublicKey: strings.Repeat("a", 52), CreatedAt: now, AcknowledgedAt: now}}
	s.Publication = true
	s.Sessions = []LocalSession{{ID: strings.Repeat("b", 32), Owner: "owner", TokenHash: strings.Repeat("A", 43), CreatedAt: now, LastUseAt: now, AuthenticatedAt: now, ExpiresAt: now.Add(time.Hour)}}
	s.Tokens = []AgentToken{{ID: strings.Repeat("c", 32), Name: "agent", TokenHash: strings.Repeat("B", 43), Scopes: []Scope{ScopeMappingsRead}, CreatedAt: now}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*State){
		"version":       func(x *State) { x.Version++ },
		"service id":    func(x *State) { x.ServiceID = "bad" },
		"duplicate map": func(x *State) { x.Mappings = append(x.Mappings, x.Mappings[0]) },
		"no device":     func(x *State) { x.Devices = nil },
		"bad scope":     func(x *State) { x.Tokens[0].Scopes = []Scope{"root"} },
	}
	for name, mutate := range cases {
		x := s
		x.Mappings = append([]Mapping(nil), s.Mappings...)
		x.Devices = append([]Device(nil), s.Devices...)
		x.Tokens = append([]AgentToken(nil), s.Tokens...)
		x.Tokens[0].Scopes = append([]Scope(nil), s.Tokens[0].Scopes...)
		mutate(&x)
		if err := x.Validate(); err == nil {
			t.Errorf("%s mutation validated", name)
		}
	}
}

func TestPublicationRequiresInitializationAndDevice(t *testing.T) {
	s := NewState()
	s.Publication = true
	if err := s.Validate(); err == nil {
		t.Fatal("unsafe publication state validated")
	}
}
