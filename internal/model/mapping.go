package model

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const StateVersion = 1

var reservedPrefixes = map[string]struct{}{
	"admin":     {},
	"auth":      {},
	"bootstrap": {},
	"ca":        {},
	"control":   {},
	"health":    {},
	"localhost": {},
	"metrics":   {},
}

type Scheme string

const (
	SchemeHTTP  Scheme = "http"
	SchemeHTTPS Scheme = "https"
	SchemeH2C   Scheme = "h2c"
)

type Mapping struct {
	Prefix string `json:"prefix"`
	Port   uint16 `json:"port"`
	Scheme Scheme `json:"scheme"`
	Enable bool   `json:"enabled"`
}

type State struct {
	Version   int       `json:"version"`
	ServiceID string    `json:"service_id"`
	Mappings  []Mapping `json:"mappings"`
}

func NewState(serviceID string) State {
	return State{Version: StateVersion, ServiceID: serviceID, Mappings: []Mapping{}}
}

func ValidateServiceID(value string) error {
	if len(value) != 56 {
		return fmt.Errorf("service id must contain exactly 56 characters")
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '2' || character > '7') {
			return errors.New("service id must use lowercase v3 onion base32 characters")
		}
	}
	return nil
}

func BaseDomain(serviceID string) (string, error) {
	if err := ValidateServiceID(serviceID); err != nil {
		return "", err
	}
	return serviceID + ".onion", nil
}

func ValidatePrefix(value string) error {
	if len(value) == 0 || len(value) > 63 {
		return errors.New("prefix must contain between 1 and 63 characters")
	}
	if value != strings.ToLower(value) {
		return errors.New("prefix must already be canonical lowercase ASCII")
	}
	if value[0] == '-' || value[len(value)-1] == '-' {
		return errors.New("prefix cannot start or end with a hyphen")
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return errors.New("prefix may contain only lowercase ASCII letters, digits, and interior hyphens")
		}
	}
	if _, reserved := reservedPrefixes[value]; reserved {
		return fmt.Errorf("prefix %q is reserved", value)
	}
	return nil
}

func (mapping Mapping) Validate(forbiddenPorts map[uint16]struct{}) error {
	if err := ValidatePrefix(mapping.Prefix); err != nil {
		return fmt.Errorf("invalid prefix: %w", err)
	}
	if mapping.Port == 0 {
		return errors.New("port must be between 1 and 65535")
	}
	if _, forbidden := forbiddenPorts[mapping.Port]; forbidden {
		return fmt.Errorf("port %d belongs to the Torkitten control plane", mapping.Port)
	}
	switch mapping.Scheme {
	case SchemeHTTP, SchemeHTTPS, SchemeH2C:
	default:
		return errors.New("scheme must be one of http, https, or h2c")
	}
	return nil
}

func (state State) Validate(forbiddenPorts map[uint16]struct{}) error {
	if state.Version != StateVersion {
		return fmt.Errorf("unsupported state version %d", state.Version)
	}
	if err := ValidateServiceID(state.ServiceID); err != nil {
		return fmt.Errorf("invalid service id: %w", err)
	}
	seen := make(map[string]struct{}, len(state.Mappings))
	for _, mapping := range state.Mappings {
		if err := mapping.Validate(forbiddenPorts); err != nil {
			return fmt.Errorf("mapping %q: %w", mapping.Prefix, err)
		}
		if _, duplicate := seen[mapping.Prefix]; duplicate {
			return fmt.Errorf("duplicate prefix %q", mapping.Prefix)
		}
		seen[mapping.Prefix] = struct{}{}
	}
	return nil
}

func (state State) Clone() State {
	clone := state
	clone.Mappings = append([]Mapping(nil), state.Mappings...)
	return clone
}

func (state *State) Sort() {
	sort.Slice(state.Mappings, func(left, right int) bool {
		return state.Mappings[left].Prefix < state.Mappings[right].Prefix
	})
}

func (state State) Mapping(prefix string) (Mapping, bool) {
	for _, mapping := range state.Mappings {
		if mapping.Prefix == prefix {
			return mapping, true
		}
	}
	return Mapping{}, false
}
