// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"io"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// decodeForm consumes the standard OAuth form_post response as data. It never
// renders HTML, executes scripts, follows links, or posts to its form action.
func decodeForm(body []byte, callback, state, issuer string) (string, error) {
	invalid := errors.New("invalid OAuth form-post response")
	if len(body) > maxBody {
		return "", invalid
	}
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	values := url.Values{}
	forms, inside := 0, false
	for {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			if tokenizer.Err() != io.EOF {
				return "", invalid
			}
			break
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken && kind != html.EndTagToken {
			continue
		}
		token := tokenizer.Token()
		if kind == html.EndTagToken {
			if token.Data == "form" {
				if !inside {
					return "", invalid
				}
				inside = false
			}
			continue
		}
		if token.Data != "form" && token.Data != "input" {
			continue
		}
		attributes := map[string]string{}
		for _, a := range token.Attr {
			if _, ok := attributes[a.Key]; ok || a.Namespace != "" {
				return "", invalid
			}
			attributes[a.Key] = a.Val
		}
		if token.Data == "form" {
			forms++
			if forms != 1 || inside || kind == html.SelfClosingTagToken || len(attributes) != 2 || !strings.EqualFold(attributes["method"], "post") || attributes["action"] != callback {
				return "", invalid
			}
			inside = true
			continue
		}
		name := attributes["name"]
		if !inside || len(attributes) != 3 || attributes["type"] != "hidden" || len(values[name]) != 0 {
			return "", invalid
		}
		switch name {
		case "code", "state", "iss", "scope", "error", "error_description", "error_uri":
		default:
			return "", invalid
		}
		values.Set(name, attributes["value"])
	}
	if forms != 1 || inside || subtle.ConstantTimeCompare([]byte(values.Get("state")), []byte(state)) != 1 {
		return "", invalid
	}
	if values.Get("iss") != issuer {
		return "", invalid
	}
	if supplied, ok := values["scope"]; ok && !exactScopes(strings.Fields(supplied[0])) {
		return "", invalid
	}
	if values.Get("error") != "" {
		return "", ErrLoginRequired
	}
	if !safeValue(values.Get("code")) {
		return "", invalid
	}
	return values.Get("code"), nil
}

func exactScopes(scopes []string) bool {
	return len(scopes) == 2 && contains(scopes, "authelia.bearer.authz") && contains(scopes, "offline_access")
}
