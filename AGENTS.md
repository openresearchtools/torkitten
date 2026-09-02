# Torkitten Agent Guide

## Product

Torkitten is a persistent, self-hosted onion gateway for existing local web applications. It gives selected loopback services a private `.onion` entry point with Tor client authorization, HTTPS, a shared strong login, and a small native administration interface. It is intended to remain available after the desktop UI closes or crashes.

The primary platform is Ubuntu/Linux installed from a normal `.deb`. Runtime components execute as dedicated non-root users. The package supplies systemd units and AppArmor profiles; systemd owns service lifecycle and cgroups. Torkitten processes communicate through narrowly permissioned Unix sockets.

## Request path

```text
Phone browser
  -> Orbot/Tor client authorization
  -> Tor network
  -> application-owned C Tor service
  -> per-route Caddy Unix listener
  -> Caddy HTTPS and forward authentication
  -> approved numeric loopback service (127.0.0.1 or ::1)
                         |
                         -> Rust authentication Unix socket
```

C Tor provides the persistent v3 onion identity, restricted-discovery client keys, and virtual-port-to-Unix-socket mappings. Caddy remains the HTTP reverse proxy: it terminates TLS, authenticates every request before dialing an upstream, sanitizes forwarding headers, and carries normal HTTP, WebSockets, SSE, streaming responses, and uploads.

Dedicated onion virtual ports are the compatibility-first route mode:

```text
http://name.onion:80/<temporary-certificate-path> -> temporary certificate bootstrap
https://name.onion:443/*   -> Torkitten login and route portal
https://name.onion:8443/* -> Caddy -> http://127.0.0.1:3000/*
https://name.onion:8444/* -> Caddy -> http://127.0.0.1:5000/*
```

The complete request path is preserved, so applications continue to own `/`, `/assets`, `/api`, and `/ws`. Different ports are different browser origins, while a hostname-wide secure session cookie supplies one login across them. Torkitten does not publish applications under path prefixes. A separate onion identity is the strongest optional isolation mode.

## Rust workspace

- `torkitten-core`: configuration, validated route models, IPC types, and shared errors.
- `torkittend`: Tokio coordination daemon for state, health, reloads, enrollment, and the persistent emergency-disable latch.
- `torkitten-tor`: C Tor control protocol, supplied persistent Ed25519 onion identity, client authorization, and virtual-port mappings.
- `torkitten-proxy`: deterministic restricted Caddy configuration and atomic reloads.
- `torkitten-auth`: Axum authentication service using `webauthn-rs`, Argon2id, TOTP, recovery codes, CSRF/origin validation, and revocable sessions.
- `torkitten-vault`: versioned authenticated encryption for secret material. SQLite stores routes, public metadata, credential records, and hashed session tokens.
- `torkitten-web`: Askama-rendered login, enrollment, and route portal with embedded CSS and minimal JavaScript for WebAuthn.
- `torkittenctl`: local administration through the protected admin Unix socket.
- `torkitten-ui`: GTK4/libadwaita client using the same local administration API.
- `packaging/`: `.deb`, systemd units, AppArmor policy, container image, SBOM, and reproducible dependency manifests.

Crates are library boundaries, not separate services. The steady-state native installation has three long-running processes: `torkittend`, C Tor, and Caddy. The GTK client is optional and the CLI is short-lived.

## Security model

Remote access combines three independent controls: a Tor client key, private-CA HTTPS, and web authentication. Passkeys with user verification are primary; Argon2id password plus TOTP and recovery codes provide a portable fallback. Sessions are opaque, hashed server-side, revocable, and long-lived with safe rotation. Cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, host-wide, and scoped to `/`.

Every published route passes Caddy forward authentication. Auth-service failure denies access. Torkitten-owned state-changing endpoints validate CSRF tokens and allowed origins. Route targets are normalized explicit loopback addresses or approved Unix sockets. Caddy listens on Unix sockets and receives only the network access needed to connect to approved loopback services; Tor alone receives general outbound networking.

The local administration API uses a mode-restricted Unix socket and peer credentials. Adding routes or shares, creating API credentials, rotating identities, changing authentication, and enrolling clients are local administration actions. The remote emergency action writes a persistent disabled latch, stops publication cleanly, and requires local re-enablement.

The TLS hierarchy uses a private root, an onion-name-constrained intermediate, and renewable leaf certificates for the exact onion hostname. Runtime storage holds only the material needed for normal operation; encrypted recovery material supports identity recovery and rotation. Enrollment produces QR codes for the onion address and Tor client credential.

Certificate bootstrap is a separate temporary HTTP listener mapped from onion virtual port 80. Initial onboarding opens it for 15 minutes; afterward it can be reopened only through the local GTK client or `torkittenctl`, and it closes automatically. It bypasses web login because no password, session, or second factor may cross HTTP; Tor client authorization is its authentication boundary. A generated enrollment path accepts only `GET` and `HEAD` for the public CA certificate/profile and static instructions. Every other path returns 404. It never serves private keys or administration functions, and Secure session cookies never travel over it.

Logs contain bounded operational metadata with credentials, authorization headers, cookies, request bodies, uploads, chat content, and secret keys redacted.

## Runtime and packaging

Native units run as separate `torkitten`, `torkitten-tor`, and `torkitten-caddy` users with `NoNewPrivileges`, an empty capability set, filesystem restrictions, syscall filtering, and component-specific networking. Torkitten does not create user namespaces or manipulate cgroups. Unit relationships provide ordered startup, restart backoff, clean group shutdown, and singleton operation. Configuration updates are validated and atomic, retaining the last working configuration on failure.

The optional OCI image is headless and designed for an explicit Podman/Docker deployment with mounted state and credentials.

## Implementation order

1. Prove C Tor supplied-key persistence, iOS/Orbot client authorization, virtual ports, Caddy Unix ingress, private-CA trust, WebAuthn, and representative WebSocket/SSE/upload applications.
2. Implement core models, IPC, daemon state, Tor control, and deterministic Caddy routing.
3. Implement vault, SQLite schema, authentication, sessions, portal, and enrollment.
4. Add CLI, GTK administration, certificate/QR workflows, and emergency shutdown.
5. Package and verify crash recovery, fail-closed behavior, origin isolation, upgrades, backup recovery, and security boundaries.

Keep changes aligned with this architecture, prefer small auditable components, validate all trust-boundary inputs, and accompany security-sensitive behavior with integration tests.

Vendored standalone dependencies remain pristine under `third-party/`, with exact upstream identities in adjacent manifests. Build recipes and all generated files remain outside those source trees. Use Ubuntu 24.04 as the binary baseline, keep local Podman state and outputs on the Data drive, and give each independently reusable component its own version-derived CI cache and artifact. Complete features in small independently revertible commits and push each commit to `origin`.
