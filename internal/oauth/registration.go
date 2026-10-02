// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package oauth

// Registration returns the pinned Authelia public-client configuration. The
// caller validates its profile/client identity and inserts this into oidc.clients.
// Each session epoch has a new ClientID; the old registration must be removed.
func Registration(clientID, audience string) map[string]any {
	return map[string]any{
		"client_id": clientID, "client_name": "TorKitten native client", "public": true,
		"authorization_policy": "two_factor", "consent_mode": "explicit",
		"redirect_uris": []string{CallbackURI}, "scopes": []string{"authelia.bearer.authz", "offline_access"},
		"audience": []string{audience}, "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "response_modes": []string{"form_post"},
		"token_endpoint_auth_method": "none", "require_pushed_authorization_requests": true,
		"require_pkce": true, "pkce_challenge_method": "S256",
	}
}
