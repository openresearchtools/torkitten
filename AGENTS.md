# Torkitten Agent Guide

## Product contract

Torkitten is a persistent self-hosted gateway that publishes approved local web applications as private onion sites. A user manages multiple sites from one machine-local dashboard. Every site owns a persistent v3 onion identity, guest/device access, HTTPS certificates, publication state, and any number of independently toggleable application mappings.

Ubuntu/Linux is delivered as one normal `.deb`. It includes the daemon, CLI, native desktop application, bundled C Tor, bundled Caddy, and all web assets. Podman/Docker uses the same daemon, administration UI, API, state model, and gateway behavior in one OCI image. Closing the desktop window or browser never stops published sites.

## Fixed security boundaries

These are separate surfaces. Never merge their listeners, credentials, permissions, or routes.

1. **Local Admin Control Plane** is the permanent privileged dashboard. It creates sites, mappings, users, credentials, and certificates and controls processes. It is never published through Tor.
2. **Remote Login Portal** is each site's permanent HTTPS onion service on virtual port 443. Guests can log in, view permitted shares, and manage their own sessions. It has no gateway-administration operations.
3. **Certificate Bootstrap** is each site's temporary HTTP onion service on virtual port 80. It serves only public CA/profile files and static installation instructions at an unguessable generated path.
4. **Device Enrollment** is a repeatable administrator-initiated workflow for one site, guest, and device. Each device gets a distinct Tor client key. Administrators may create unlimited enrollments.
5. **Application Share** is one independently toggleable mapping from a dedicated HTTPS onion virtual port to an approved loopback port or Unix socket. The upstream receives the complete original path.

## Local administration dashboard

The dashboard resembles a container manager, with onion sites replacing containers. A site row shows its name, shortened onion address, health, publication status, whole-site toggle, and actions. Expanding it reveals indented mappings. Each mapping shows its name, approved local target, onion virtual port, health, open/copy controls, access assignment, and its own sharing toggle.

The dashboard must provide:

- Generate, name, rename, back up, restore, rotate, enable, disable, and remove sites.
- Add, edit, test, enable, disable, and remove mappings without disturbing other mappings or sites.
- Assign guests or access groups to each share.
- Connect another device; issue, display, copy, and revoke its Tor authorization credential.
- Manage guest accounts, passkeys, password plus TOTP fallback, recovery codes, and active sessions.
- Inspect and renew certificates; open certificate bootstrap for 15 minutes, extend it, or close it now.
- Start, stop, and restart managed Tor and Caddy processes; stop all publication using a persistent emergency-disabled latch.
- Choose whether enabled sites resume publication after boot.
- Show bounded health and error logs with secrets and user content redacted.

Stopping one mapping leaves its site and sibling mappings running. Stopping a site removes only that site's onion publication. “Stop all publication” terminates Tor/Caddy publication while leaving the small administration daemon available so local administration can restart it.

### Site generator

“Generate site” continuously creates and displays candidate onion addresses until the user presses Stop. The chosen Ed25519 identity is encrypted and persisted. Discarded candidates are zeroized. The CLI performs the same operation for three seconds by default. Every candidate already has full cryptographic entropy; elapsed time selects a different address rather than increasing key strength.

### Connect another device

The responsive wizard stays inside the administration window and has distinct iOS, Android, Linux, macOS, and Windows instructions:

1. Show official Orbot links and App Store/Play Store QR codes for mobile, or official Tor Browser links for desktop.
2. Generate a unique Tor client-authorization credential for the device. Show an Orbot-compatible QR, copyable onion address and credential, and precise Tor Browser import instructions.
3. Open that site's certificate bootstrap for 15 minutes. Show the generated download URL as text and QR, a countdown, close/extend controls, and illustrated certificate-installation steps for the selected platform.
4. Create or select the guest. Show a short-lived enrollment link/QR for creating that device's passkey or password/TOTP login. Never encode a password or permanent session in a QR code.
5. Show the final `https://name.onion/` portal as a clickable link, copyable text, and QR code.

The administrator can cancel, retry, revoke, or create another enrollment at any time. Existing guests subsequently use normal login and do not repeat enrollment.

## Native desktop and container UI

There is one administration UI implementation. `torkitten-admin-web` contains the Rust handlers, Askama templates, embedded CSS, small purpose-written scripts, QR generation, and platform illustrations. It has no Node runtime or separate frontend server.

The single Linux `.deb` installs a real `torkitten-desktop` application using Rust Wry with the system WebKitGTK engine. It is not libadwaita, Electron, or an external browser. Wry displays the shared administration UI in a native window. The desktop process reaches `torkittend` through the mode-restricted administration Unix socket and establishes its local session using Unix peer credentials. The desktop launcher starts this window; it does not start or own Tor/Caddy.

The OCI image does not start a graphical window. It serves the exact same administration router and assets on a configured container listener. Supplied Podman/Docker configuration publishes it only as host loopback, for example `127.0.0.1:12755:12755`. The host browser opens `http://localhost:12755`. First use creates persistent administrator credentials; later access uses normal long-lived revocable login. Ordinary access never requires `docker exec`, `podman exec`, or an expiring administrator URL. Durable state is mounted into the container.

For containerized upstream applications, prefer a shared Podman pod or network namespace so approved services remain reachable on loopback. Reaching native host-loopback applications from a container is an explicit opt-in host-network deployment. Container packaging never silently broadens target validation.

## Onion routing

One application-owned C Tor process may host multiple configured hidden-service directories. It owns all site identities and client-authorization files and maps each site's virtual ports to site-and-port-specific Unix sockets. It exposes no SOCKS, HTTP tunnel, DNS, transparent proxy, NAT, relay, VPN, firewall, or system-routing facility.

One managed Caddy process listens only on those Unix sockets. It terminates private-CA TLS, authenticates every request before dialing an upstream, sanitizes forwarding headers, and carries HTTP, WebSockets, SSE, streaming responses, and uploads.

```text
Remote browser
  -> Orbot/Tor client authorization
  -> Tor network
  -> bundled C Tor hidden service
  -> site-and-port Caddy Unix listener
  -> Caddy TLS and fail-closed forward authentication
  -> approved 127.0.0.1, ::1, or Unix-socket application
```

For every site:

```text
http://name.onion:80/<generated-path> -> temporary certificate bootstrap
https://name.onion:443/*              -> guest login and permitted-share portal
https://name.onion:8443/*             -> approved local application, full path preserved
https://name.onion:8444/*             -> another approved application, full path preserved
```

Application shares use dedicated virtual ports, not path prefixes. This preserves `/`, `/assets`, `/api`, `/ws`, redirects, WebSockets, and application-relative URLs. Ports are unique within a site and may be reused by a different site. Browser origins differ by port; a secure hostname-wide cookie supplies one login across ports belonging to the same site.

## Authentication, TLS, and secrets

Remote access requires three independent controls: the site's Tor client key, private-CA HTTPS, and guest web authentication. Passkeys with user verification are primary. Argon2id password plus TOTP and recovery codes is the portable fallback. Sessions are opaque, hashed server-side, revocable, and long-lived with rotation. Remote cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, host-wide, and scoped to `/`.

Every share uses Caddy forward authentication. Auth-service failure denies access. State-changing Torkitten endpoints enforce CSRF and exact origin checks. Guest permissions are site/share scoped. Remote guests cannot create mappings, rotate identities, issue credentials, change authentication policy, or start processes. The remote emergency action can only persistently stop publication; re-enabling is local-only.

The private TLS hierarchy has a root CA, constrained intermediate, and renewable leaf certificates for exact onion hostnames. Runtime storage contains only necessary keys; recovery material is encrypted. SQLite stores sites, mappings, public metadata, credential records, permissions, and hashed sessions. Secret material uses versioned authenticated encryption.

Certificate bootstrap opens initially or on local request for 15 minutes and then closes automatically. Tor client authorization is its access boundary. Only `GET` and `HEAD` to the generated path may return the public CA certificate, mobile profile, and static instructions; all other paths return 404. It never serves private keys, passwords, login forms, sessions, or administration, and secure cookies never travel over HTTP.

## Rust workspace

- `torkitten-core`: validated multi-site models, mapping and enrollment types, IPC, and shared errors.
- `torkittend`: Tokio daemon coordinating state, health, atomic reloads, child processes, enrollment, and emergency state.
- `torkitten-tor`: C Tor configuration/control, persistent site identities, client authorization, and per-site virtual-port mappings.
- `torkitten-proxy`: deterministic restricted Caddy configuration and atomic reloads.
- `torkitten-auth`: administrator/guest authentication, authorization, CSRF/origin enforcement, and revocable sessions.
- `torkitten-vault`: encrypted secrets and SQLite persistence for the complete multi-site model.
- `torkitten-web`: onion-facing guest portal and certificate-bootstrap pages.
- `torkitten-admin-web`: shared local dashboard and device-enrollment UI.
- `torkitten-desktop`: thin Wry native host for the shared dashboard.
- `torkittenctl`: local CLI over the protected administration Unix socket.
- `packaging/`: one `.deb`, desktop entry, systemd/AppArmor files, OCI image, Podman/Docker examples, SBOM, and reproducible manifests.

These crates are code boundaries, not separate services. Native steady state has three long-running processes: `torkittend`, bundled C Tor, and bundled Caddy. The desktop window and CLI are short-lived daemon clients.

## Runtime and packaging

Native units use dedicated non-root `torkitten`, `torkitten-tor`, and `torkitten-caddy` users, narrowly shared groups/directories, `NoNewPrivileges`, empty capabilities, filesystem restrictions, syscall filtering, and component-specific networking. Torkitten does not create namespaces or manipulate cgroups. Systemd owns ordering, restart backoff, singleton operation, and clean shutdown. Updates are validated and atomic; failure retains the last working configuration.

The OCI image runs the same daemon, Tor, and Caddy under a normal container supervisor with mounted state. Its Tor remains scoped to Torkitten. Provided container configuration binds administration only to host loopback and uses an explicit restart policy.

## Development and verification

Vendored Tor and Caddy remain pristine under `third-party/`; adjacent manifests pin exact upstream tags, commits, trees, licenses, and versions. Generated files and builds never enter the repository. Ubuntu 24.04 is the binary baseline. Local Podman storage, caches, work, and artifacts stay under `/run/media/user/Data/TorkittenBuild`. Each reusable standalone component has an independent version-derived CI cache and artifact.

Refactor existing single-site foundations before adding more features: multi-site core types, site-scoped SQLite keys, site-aware Tor configuration, and site-scoped IPC must land together coherently. Then implement Caddy, authentication/TLS, web surfaces, daemon/CLI, desktop/container presentation, and packaging.

Test real bundled Tor and Caddy rather than mocks alone. Cover allowed and forbidden requests, client authorization, certificate installation, login, WebSockets/SSE/uploads, crash recovery, fail-closed behavior, origin separation, upgrades, and backups. Verify native and container builds on Ubuntu 24.04, Ubuntu 26.04, and Debian 13 test machines. Keep features in small independently revertible commits and push every commit to `origin`.
