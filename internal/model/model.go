// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	StateVersion = 1
	OwnerGroup   = "torkitten-owner"
	MaxMappings  = 128
	MaxDevices   = 64
	MaxSessions  = 64
	MaxTokens    = 64
)

type Protocol string

const (
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTPS Protocol = "https"
	ProtocolH2C   Protocol = "h2c"
)

type Mapping struct {
	Prefix   string   `json:"prefix"`
	Port     int      `json:"port"`
	Protocol Protocol `json:"protocol"`
	Enabled  bool     `json:"enabled"`
}

type Device struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	PublicKey      string    `json:"public_key"`
	CreatedAt      time.Time `json:"created_at"`
	AcknowledgedAt time.Time `json:"acknowledged_at"`
}

type PendingDevice struct {
	Device
	PrivateKey string    `json:"private_key"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type LocalSession struct {
	ID              string    `json:"id"`
	Owner           string    `json:"owner"`
	TokenHash       string    `json:"token_hash"`
	CreatedAt       time.Time `json:"created_at"`
	LastUseAt       time.Time `json:"last_use_at"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type Scope string

const (
	ScopeMappingsRead  Scope = "mappings:read"
	ScopeMappingsWrite Scope = "mappings:write"
)

type AgentToken struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TokenHash string    `json:"token_hash"`
	Scopes    []Scope   `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	LastUseAt time.Time `json:"last_use_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type BootstrapWindow struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type State struct {
	Version     int              `json:"version"`
	Initialized bool             `json:"initialized"`
	ServiceID   string           `json:"service_id,omitempty"`
	Publication bool             `json:"publication_enabled"`
	Mappings    []Mapping        `json:"mappings"`
	Devices     []Device         `json:"devices"`
	Pending     *PendingDevice   `json:"pending_device,omitempty"`
	Sessions    []LocalSession   `json:"local_sessions"`
	Tokens      []AgentToken     `json:"agent_tokens"`
	Bootstrap   *BootstrapWindow `json:"bootstrap,omitempty"`
}

var (
	prefixRE    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	serviceIDRE = regexp.MustCompile(`^[a-z2-7]{56}$`)
	idRE        = regexp.MustCompile(`^[a-f0-9]{32}$`)
	keyRE       = regexp.MustCompile(`^[a-z2-7]{52}$`)
	usernameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	reserved    = map[string]bool{"admin": true, "auth": true, "bootstrap": true, "ca": true, "control": true, "health": true, "localhost": true, "metrics": true, "onboarding": true, "setup": true, "www": true}
)

func NewState() State {
	return State{Version: StateVersion, Mappings: []Mapping{}, Devices: []Device{}, Sessions: []LocalSession{}, Tokens: []AgentToken{}}
}

func ValidatePrefix(v string) error {
	if !prefixRE.MatchString(v) || reserved[v] {
		return errors.New("prefix must be a non-reserved lowercase RFC-style label")
	}
	return nil
}

func ValidateUsername(v string) error {
	if !usernameRE.MatchString(v) {
		return errors.New("username must be 1-32 lowercase ASCII letters, digits, underscores, or interior hyphens")
	}
	return nil
}

func ValidateMapping(m Mapping) error {
	if err := ValidatePrefix(m.Prefix); err != nil {
		return err
	}
	if m.Port < 1 || m.Port > 65535 || m.Port == 12755 {
		return errors.New("port must be 1-65535 and not a Torkitten control port")
	}
	if m.Protocol != ProtocolHTTP && m.Protocol != ProtocolHTTPS && m.Protocol != ProtocolH2C {
		return errors.New("protocol must be http, https, or h2c")
	}
	return nil
}

func (s State) Host(prefix string) string {
	if prefix == "" {
		return s.ServiceID + ".onion"
	}
	return prefix + "." + s.ServiceID + ".onion"
}

func (s State) Validate() error {
	if s.Version != StateVersion {
		return fmt.Errorf("unsupported state version %d", s.Version)
	}
	if s.ServiceID != "" && !serviceIDRE.MatchString(s.ServiceID) {
		return errors.New("service_id must be a lowercase 56-character v3 onion service id")
	}
	if s.Initialized && s.ServiceID == "" {
		return errors.New("initialized state requires an onion service id")
	}
	if len(s.Mappings) > MaxMappings || len(s.Devices) > MaxDevices || len(s.Sessions) > MaxSessions || len(s.Tokens) > MaxTokens {
		return errors.New("state collection limit exceeded")
	}
	seen := map[string]bool{}
	for i := range s.Mappings {
		if err := ValidateMapping(s.Mappings[i]); err != nil {
			return fmt.Errorf("mapping %d: %w", i, err)
		}
		if seen[s.Mappings[i].Prefix] {
			return fmt.Errorf("duplicate mapping prefix %q", s.Mappings[i].Prefix)
		}
		seen[s.Mappings[i].Prefix] = true
	}
	if err := validateDevices(s, seen); err != nil {
		return err
	}
	for _, session := range s.Sessions {
		if !idRE.MatchString(session.ID) || !validHash(session.TokenHash) || session.Owner == "" || session.CreatedAt.IsZero() || session.LastUseAt.Before(session.CreatedAt) || !session.ExpiresAt.After(session.CreatedAt) {
			return errors.New("invalid local session record")
		}
		if seen["session:"+session.ID] {
			return errors.New("duplicate local session id")
		}
		seen["session:"+session.ID] = true
	}
	for _, token := range s.Tokens {
		if !idRE.MatchString(token.ID) || !validName(token.Name) || !validHash(token.TokenHash) || len(token.Scopes) == 0 {
			return errors.New("invalid agent token record")
		}
		for _, scope := range token.Scopes {
			if scope != ScopeMappingsRead && scope != ScopeMappingsWrite {
				return errors.New("invalid agent token scope")
			}
		}
		if seen["token:"+token.ID] {
			return errors.New("duplicate agent token id")
		}
		seen["token:"+token.ID] = true
	}
	if s.Bootstrap != nil && (!validHash(s.Bootstrap.Token) || s.Bootstrap.ExpiresAt.IsZero()) {
		return errors.New("invalid bootstrap window")
	}
	if s.Publication && (!s.Initialized || len(s.Devices) == 0) {
		return errors.New("publication requires initialized state and an acknowledged device")
	}
	return nil
}

func validateDevices(s State, seen map[string]bool) error {
	for _, d := range s.Devices {
		if !idRE.MatchString(d.ID) || !validName(d.Name) || !keyRE.MatchString(d.PublicKey) || d.CreatedAt.IsZero() || d.AcknowledgedAt.IsZero() || seen["device:"+d.ID] {
			return errors.New("invalid or duplicate acknowledged device")
		}
		seen["device:"+d.ID] = true
	}
	if s.Pending != nil {
		d := s.Pending
		if !idRE.MatchString(d.ID) || !validName(d.Name) || !keyRE.MatchString(d.PublicKey) || !keyRE.MatchString(d.PrivateKey) || d.CreatedAt.IsZero() || !d.ExpiresAt.After(d.CreatedAt) || seen["device:"+d.ID] {
			return errors.New("invalid pending device")
		}
	}
	return nil
}

func validHash(v string) bool { return len(v) == 43 && !strings.ContainsAny(v, "+/=") }
func validName(v string) bool { return len(v) >= 1 && len(v) <= 64 && strings.TrimSpace(v) == v }
