# Torkitten Agent Guide

## Product

Torkitten is a persistent, self-hosted onion gateway for existing local web applications. It gives selected loopback services private `.onion` entry points with Tor client authorization, HTTPS, a shared strong login, and a permanent machine-local administration interface. It is intended to remain available after the desktop UI closes or crashes.

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

## Web surfaces and product interface

Keep five concepts distinct throughout the implementation:

1. **Local Admin Control Plane:** the permanent privileged administration interface available only on the machine running Torkitten. It never appears through an onion route.
2. **Remote Login Portal:** the permanent authenticated HTTPS site on onion virtual port 443. Guests see only their permitted applications and account/session controls.
3. **Certificate Bootstrap:** the temporary HTTP endpoint on onion virtual port 80. It serves only public certificate installation material at a generated path.
4. **Device Enrollment:** a repeatable per-site and per-device workflow initiated by an administrator. Any number of guests and devices may be enrolled.
5. **Application Share:** one independently controlled mapping from a dedicated onion virtual port to an approved loopback port or Unix socket.

The local administration interface is one responsive web application rendered from Rust. Its main screen follows the familiar container-manager layout, but the primary rows are onion sites. Each site row displays its name, shortened onion address, health, publication state, whole-site on/off toggle, and actions. Expanding a site reveals indented application mappings. Each mapping shows its name, local target, onion virtual port, health, open/copy controls, and its own sharing toggle.

The dashboard includes all of the following:

- Create, rename, back up, restore, rotate, enable, and disable onion sites.
- Generate a site by displaying continuously generated candidate onion addresses until the user stops the generator. The CLI selects after three seconds by default. Each candidate is already cryptographically secure; elapsed time chooses a candidate rather than increasing key strength. Discarded private keys are zeroized.
- Add, edit, test, enable, disable, and remove mappings without affecting other mappings or sites.
- Assign guests or access groups to individual shares.
- Issue, display, copy, and revoke Tor client credentials for each device.
- Manage remote guest accounts, passkeys, password/TOTP fallback, recovery codes, and active sessions.
- Display certificate state, renew leaf certificates, open certificate bootstrap for 15 minutes, extend it, or close it immediately.
- Start, stop, and restart managed C Tor and Caddy processes; stop all publication with a persistent emergency-disabled latch.
- Configure whether enabled sites resume publication at boot and inspect bounded redacted health and error logs.

“Connect another device” opens a browser-window-relative responsive wizard with separate iOS, Android, Linux, macOS, and Windows paths:

1. Show official Orbot links and store QR codes on mobile, or Tor Browser links on desktop.
2. Generate a distinct Tor client-authorization credential for that device. Show an Orbot-compatible QR, copyable onion address and credential, and precise desktop import instructions.
3. Open certificate bootstrap for 15 minutes. Show the generated certificate URL as copyable text and QR, a visible countdown, and illustrated platform-specific certificate installation steps.
4. Create or select the guest and show a short-lived enrollment link/QR for establishing that device's passkey or password/TOTP authentication. Passwords and permanent sessions are never encoded in QR images.
5. Show the final HTTPS onion portal as a clickable link, copyable text, and QR code.

Administrators can cancel, retry, revoke, or create another enrollment at any time. Existing guests subsequently use their normal login; enrollment is not required on every visit.

## Native desktop and container presentation

There is one administration UI implementation and one administration API. HTML templates, CSS, small purpose-written browser scripts, platform illustrations, and QR generation are compiled into the Rust application. There is no Node or separate frontend runtime.

The normal Linux `.deb` is one package containing `torkittend`, the bundled C Tor and Caddy binaries, `torkittenctl`, and `torkitten-desktop`. `torkitten-desktop` is a real native Wry/WebKitGTK application window. It renders the embedded administration UI directly and reaches the daemon through the protected administration Unix socket. The desktop-menu entry opens this application window; it does not open an external browser. Closing the window does not stop the daemon or published sites.

The OCI image uses the exact same administration pages, assets, handlers, API, accounts, and persistent state, without starting the desktop executable. Podman/Docker publishes the dashboard explicitly to host loopback, for example `127.0.0.1:12755:12755`, and the user opens it in the host browser. The dashboard is permanent: first launch creates persistent administrator credentials and ordinary use never requires `docker exec`, `podman exec`, or an expiring administration URL. The supplied container configuration mounts durable state and never publishes the dashboard on all host interfaces.

For containerized applications, the preferred deployment shares a Podman pod or network namespace with Torkitten so approved targets remain loopback. Publishing native host-loopback applications from a container requires an explicit opt-in host-network deployment. The bundled Tor instance remains application-scoped in every mode and never provides system-wide SOCKS, DNS, transparent proxy, VPN, firewall, or routing changes.

## Rust workspace

- `torkitten-core`: configuration, validated route models, IPC types, and shared errors.
- `torkittend`: Tokio coordination daemon for state, health, reloads, enrollment, and the persistent emergency-disable latch.
- `torkitten-tor`: C Tor control protocol, supplied persistent Ed25519 onion identity, client authorization, and virtual-port mappings.
- `torkitten-proxy`: deterministic restricted Caddy configuration and atomic reloads.
- `torkitten-auth`: Axum authentication service using `webauthn-rs`, Argon2id, TOTP, recovery codes, CSRF/origin validation, and revocable sessions.
- `torkitten-vault`: versioned authenticated encryption for secret material. SQLite stores routes, public metadata, credential records, and hashed session tokens.
- `torkitten-web`: Askama-rendered onion login, guest enrollment, certificate bootstrap, and route portal with embedded CSS and minimal JavaScript for WebAuthn.
- `torkitten-admin-web`: the shared machine-local administration pages, dashboard handlers, device-enrollment wizard, platform guidance, and QR assets.
- `torkittenctl`: local administration through the protected admin Unix socket.
- `torkitten-desktop`: the thin Rust Wry/WebKitGTK native window that hosts `torkitten-admin-web` and uses the protected local administration API.
- `packaging/`: the single `.deb`, desktop entry, systemd units, AppArmor policy, container image, Compose/Podman examples, SBOM, and reproducible dependency manifests.

Crates are library boundaries, not separate services. The steady-state native installation has three long-running processes: `torkittend`, C Tor, and Caddy. The desktop window and CLI are short-lived clients of the daemon.

## Security model

Remote access combines three independent controls: a Tor client key, private-CA HTTPS, and web authentication. Passkeys with user verification are primary; Argon2id password plus TOTP and recovery codes provide a portable fallback. Sessions are opaque, hashed server-side, revocable, and long-lived with safe rotation. Cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, host-wide, and scoped to `/`.

Every published route passes Caddy forward authentication. Auth-service failure denies access. Torkitten-owned state-changing endpoints validate CSRF tokens and allowed origins. Route targets are normalized explicit loopback addresses or approved Unix sockets. Caddy listens on Unix sockets and receives only the network access needed to connect to approved loopback services; Tor alone receives general outbound networking.

The local administration API uses a mode-restricted Unix socket and peer credentials. Native desktop administration stays on this local boundary. Container browser administration uses the same API through an authenticated HTTP adapter published only to host loopback. Adding routes or shares, creating API credentials, rotating identities, changing authentication, and enrolling clients are local administration actions. The remote emergency action writes a persistent disabled latch, stops publication cleanly, and requires local re-enablement.

The TLS hierarchy uses a private root, an onion-name-constrained intermediate, and renewable leaf certificates for the exact onion hostname. Runtime storage holds only the material needed for normal operation; encrypted recovery material supports identity recovery and rotation. Enrollment produces QR codes for the onion address and Tor client credential.

Certificate bootstrap is a separate temporary HTTP listener mapped from onion virtual port 80. Initial onboarding opens it for 15 minutes; afterward it can be reopened through the local administration dashboard or `torkittenctl`, and it closes automatically. It bypasses web login because no password, session, or second factor may cross HTTP; Tor client authorization is its authentication boundary. A generated enrollment path accepts only `GET` and `HEAD` for the public CA certificate/profile and static instructions. Every other path returns 404. It never serves private keys or administration functions, and Secure session cookies never travel over it.

Logs contain bounded operational metadata with credentials, authorization headers, cookies, request bodies, uploads, chat content, and secret keys redacted.

## Runtime and packaging

Native units run as separate `torkitten`, `torkitten-tor`, and `torkitten-caddy` users with `NoNewPrivileges`, an empty capability set, filesystem restrictions, syscall filtering, and component-specific networking. Torkitten does not create user namespaces or manipulate cgroups. Unit relationships provide ordered startup, restart backoff, clean group shutdown, and singleton operation. Configuration updates are validated and atomic, retaining the last working configuration on failure.

The OCI image is headless only in the sense that it does not create a native window. It serves the same permanent administration UI through the configured host-loopback port and uses mounted persistent state and credentials.

## Implementation order

1. Prove C Tor supplied-key persistence, iOS/Orbot client authorization, virtual ports, Caddy Unix ingress, private-CA trust, WebAuthn, and representative WebSocket/SSE/upload applications.
2. Implement core models, IPC, daemon state, Tor control, and deterministic Caddy routing.
3. Implement vault, SQLite schema, authentication, sessions, portal, and enrollment.
4. Add CLI, shared administration web UI, Wry native desktop window, container HTTP adapter, certificate/QR workflows, and emergency shutdown.
5. Package and verify crash recovery, fail-closed behavior, origin isolation, upgrades, backup recovery, and security boundaries.

Keep changes aligned with this architecture, prefer small auditable components, validate all trust-boundary inputs, and accompany security-sensitive behavior with integration tests.

Vendored standalone dependencies remain pristine under `third-party/`, with exact upstream identities in adjacent manifests. Build recipes and all generated files remain outside those source trees. Use Ubuntu 24.04 as the binary baseline, keep local Podman state and outputs on the Data drive, and give each independently reusable component its own version-derived CI cache and artifact. Complete features in small independently revertible commits and push each commit to `origin`.
