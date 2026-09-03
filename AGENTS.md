# Torkitten Agent Guide

Read this file completely before changing the repository. It is the canonical product and implementation contract. Preserve every requirement below across compaction; do not shorten it, replace it with a summary, or invent additional user-interface structure.

## Product

Torkitten is a persistent, self-hosted onion gateway for existing local web applications. One installation manages multiple independent onion sites. Each site has its own persistent v3 onion identity and contains any number of localhost reverse-proxy mappings.

The product must keep working when its administration window closes or crashes. It must recover managed processes after failures and preserve identities, certificates, users, mappings, and settings across machine or container restarts.

The primary native package is one normal Ubuntu/Linux `.deb`. That single package contains the Rust daemon, CLI, actual desktop application, administration UI, bundled C Tor, bundled Caddy, desktop launcher, systemd units, AppArmor policy, and required assets. There are not separate desktop and web editions.

The OCI build runs the same gateway, administration UI, API, state model, and assets in Podman or Docker. Native and container installations must behave as the same product.

## Exact local administration UI

The administration UI is machine-side only. It is never published through Tor and is never part of a guest onion site.

Its main dashboard visually follows Podman Desktop or Docker Desktop, except that the top-level objects are onion sites rather than containers.

A visible **Generate site** button opens a responsive generator window. The generator continuously creates and displays candidate onion addresses until the user presses Stop. The selected identity becomes the new persistent site. Closing or cancelling stores nothing. The equivalent CLI operation automatically runs the generator for three seconds before selecting a site.

Every site is one visually distinct expandable row or card containing:

- Its chosen name and full copyable onion address.
- A whole-site on/off toggle.
- Current running, stopped, starting, or failed state.
- A **Connect from another device** button.
- Controls to replace/rotate the site with a newly generated onion identity.
- Controls to restart or stop that site's publication.
- Its application mappings visibly indented underneath it.

Each indented mapping represents one reverse proxy from an onion virtual port to an approved localhost port or Unix socket. It shows the local target and onion port, and has its own on/off toggle. Turning off a mapping leaves its site and sibling mappings running. Turning off a site disables every mapping belonging to that site without affecting other sites.

Local administration provides the operations explicitly required for running the gateway:

- Generate, name, rename, rotate/reissue, enable, disable, and remove onion sites.
- Add, edit, test, enable, disable, and remove localhost port mappings.
- Reopen the temporary port-80 certificate download for a selected site and close it early.
- Create and revoke guest/device access.
- Assign each guest access to selected mappings.
- Create and revoke API credentials for non-browser clients when that support is enabled.
- Configure remote password, TOTP, passkey, recovery-code, and session policy.
- Start, stop, and restart the managed C Tor and Caddy processes.
- Stop all publication while leaving the administration daemon available.
- Configure whether enabled sites automatically resume after boot.
- Show useful component errors without showing secrets or proxied user content.

All controls must have visible pending, success, and failure states. A toggle changes visually only after the daemon has validated and committed the change. Failures retain the last working configuration.

### Connect from another device

This button may be used repeatedly for any number of guests and devices. It opens a professional responsive window inside the administration application. The content adapts to the available window width and offers separate iOS, Android, Linux, macOS, and Windows paths.

The wizard contains these steps in this order:

1. **Install Tor access software.**
   - iOS and Android show Orbot instructions, clickable official App Store/Play Store links, and QR codes for those store pages.
   - Linux, macOS, and Windows show clickable official Tor Browser downloads and installation guidance.

2. **Install this device's Tor client authorization.**
   - Generate a distinct client key for this device.
   - Show the onion address and authorization credential as copyable text.
   - Show Orbot-compatible QR codes for the onion site and authorization key.
   - Show exact copy/paste or import instructions for Tor Browser on desktop.
   - Never reuse one device's key for another device.

3. **Install Torkitten's public certificate.**
   - Open the selected site's temporary port-80 certificate endpoint for 15 minutes.
   - Display the remaining time and controls to close or extend the window.
   - Show the generated certificate-download onion URL as clickable text, copyable text, and a QR code.
   - Provide separate illustrated, image-by-image certificate installation instructions for iOS, Android, Linux, macOS, and Windows.
   - Every referenced download or settings location is clickable where the platform permits.

4. **Enroll the guest login.**
   - Create a new guest or select an existing guest.
   - Display a short-lived enrollment link and QR used to create that device's passkey or password-plus-TOTP access.
   - Do not encode a password, permanent session, recovery code, private certificate key, or reusable administrator credential in a QR code.

5. **Open the protected site.**
   - Display the main `https://name.onion/` address as a clickable link, copyable text, and QR code.
   - The link opens the site's permanent safe login portal.
   - Existing guests use normal login afterward; they do not repeat enrollment on every visit.

The administrator can cancel, retry, revoke, or create another enrollment at any time.

## Native desktop and container presentation

There is exactly one administration frontend. Rust/Axum supplies its HTTP handlers, Askama renders its pages, and its CSS, small browser scripts, images, and QR generation are bundled with the application. Runtime does not require Node, npm, Electron, or a separate frontend server.

### Native Linux

The one `.deb` installs `torkitten-desktop`, a real desktop window implemented in Rust with Wry and the system WebKitGTK engine. It does not use libadwaita and does not open the user's ordinary browser.

The persistent daemon serves the local administration application on a loopback-only listener. The Wry window displays that exact application. Privileged changes are executed by the daemon and share the same validation path used by the CLI. The protected Unix administration socket remains the CLI/local-process control boundary.

The desktop launcher opens the Wry window. Closing that window leaves `torkittend`, Tor, Caddy, and every enabled site running. Reopening it returns to the same permanent dashboard and persistent administrator account; normal use never relies on an expiring administration URL.

### Podman and Docker

The OCI image does not create a graphical window. It serves the identical administration pages, assets, handlers, account system, and API from the same Rust code.

The supplied Podman/Docker configuration maps the administration service only to host loopback, for example:

```text
127.0.0.1:12755 -> container administration listener
```

The user opens `http://localhost:12755` in the host browser. First use creates persistent administrator credentials through that page. Later visits use normal long-lived revocable sessions. Routine access never requires `docker exec`, `podman exec`, or a one-time administration URL.

Container state is a mounted persistent directory. Replacing or restarting the container preserves all identities, certificates, mappings, users, credentials, and settings.

For containerized upstream applications, the preferred configuration places Torkitten and the applications in the same Podman pod or shared network namespace so each approved application remains reachable through a distinct loopback port. Accessing applications bound to the native host's loopback requires an explicit host-network deployment. The supplied configurations document both modes and never silently broaden network access.

No onion virtual port is published through the container engine. C Tor reaches internal Unix listeners. Only the machine-local administration listener is mapped to host loopback.

## Non-overlapping security surfaces

Keep these five concepts separate in code, listeners, credentials, routing, and UI:

1. **Local Admin Control Plane**
   - Permanent and privileged.
   - Native Wry window or container host-loopback browser.
   - Creates sites, mappings, users, credentials, and certificates and controls processes.
   - Never reachable through an onion address.

2. **Remote Login Portal**
   - Permanent HTTPS onion virtual port 443 for each site.
   - Provides guest login, permitted mapping links, logout, and the guest's own session controls.
   - Contains no site generation, mapping configuration, identity rotation, certificate-authority management, device-key issuance, process control, autostart, or local settings.

3. **Certificate Bootstrap**
   - Temporary HTTP onion virtual port 80 for a selected site.
   - Open for 15 minutes during onboarding or whenever local administration reopens it.
   - Protected by that site's Tor client authorization, not by an HTTP login form.
   - Uses a generated unguessable path.
   - Accepts only `GET` and `HEAD` for the public CA certificate/profile and static installation instructions.
   - Every other path returns 404.
   - Never serves passwords, sessions, TOTP secrets, recovery codes, private keys, administration, or application content.

4. **Device Enrollment**
   - Created repeatedly from local administration.
   - Scoped to one site, one guest, and one device.
   - Produces a distinct revocable Tor client key and a short-lived guest-login enrollment.
   - Is not an administrator-login mechanism.

5. **Application Mapping**
   - One independently toggleable HTTPS onion virtual port.
   - Proxies to one approved numeric loopback address/port or approved absolute Unix socket.
   - Preserves the complete original path and application behavior.
   - Requires authorization on every request.

## Onion routing and application compatibility

One bundled application-owned C Tor process manages all enabled sites as separate hidden-service directories. Every site's identity persists across restarts. Disabling a site removes only its hidden-service configuration; rotating a site deliberately produces a different address.

C Tor maps each site and virtual port to a site-specific Unix listener. It exposes no SOCKS port, HTTP tunnel port, DNS port, transparent proxy, NAT port, relay port, VPN, firewall modification, system proxy, or system-wide routing. Installing or running Torkitten must never route unrelated machine or phone traffic through Tor.

One bundled Caddy process provides HTTP reverse proxying. It listens on site-and-port-specific Unix sockets, terminates TLS, authenticates requests before contacting an upstream, sanitizes forwarding headers, and supports ordinary HTTP, WebSockets, server-sent events, streaming uploads/downloads, redirects, and long-running responses.

The request path is:

```text
Remote browser
  -> Orbot/Tor Browser with site client key
  -> Tor network
  -> bundled C Tor hidden service
  -> site-and-port Caddy Unix listener
  -> private-CA TLS and fail-closed authentication
  -> approved localhost or Unix-socket application
```

Each site uses dedicated virtual ports:

```text
http://name.onion:80/<generated-path> -> temporary certificate download
https://name.onion:443/*              -> permanent guest login and mapping portal
https://name.onion:8443/*             -> http://127.0.0.1:3000/*
https://name.onion:8444/*             -> http://127.0.0.1:5000/*
```

Do not publish applications beneath prefixes such as `/webui/`. Dedicated ports preserve `/`, `/assets`, `/api`, `/ws`, relative URLs, and application-owned redirects without modifying upstream applications. Virtual ports are unique within a site but may be reused by another site.

Different ports are different browser origins. A secure hostname-wide session cookie provides one login across ports belonging to the same onion hostname. An unauthenticated mapping request goes to that site's port-443 login and returns only to a validated port/path after authentication. Caddy checks authorization again on every proxied request. A guessed mapping URL cannot bypass login.

A local upstream may use HTTP because its loopback hop never leaves the machine/network namespace; Caddy makes the remote side real HTTPS. No reverse proxy or Caddy administration listener may bind a public host interface.

## Remote authentication and emergency stop

Remote access combines three independent controls:

1. The site's Tor client-authorization key.
2. Private-CA HTTPS for the exact onion hostname.
3. Torkitten guest authentication.

Passkeys with user verification are primary. Argon2id password plus TOTP and recovery codes is the portable fallback. Sessions are opaque, stored only as server-side hashes, revocable, safely rotated, and deliberately long-lived so a user is not forced through 2FA multiple times per day. Remote cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, host-wide, and scoped to `/`.

Guests receive access only to selected application mappings. Every Caddy mapping uses fail-closed forward authentication. If the authentication service is unavailable or uncertain, access is denied.

The permanent remote portal may include an emergency-stop button for an explicitly authorized owner. It requires confirmation and fresh authentication, writes a persistent disabled latch, and stops all publication. Nothing remote can clear that latch or restart publication; local administration is required.

## TLS and certificates

Torkitten creates its own private TLS hierarchy without an external cloud login or public certificate service:

- A private root CA.
- An onion-name-constrained intermediate.
- Renewable leaf certificates for exact onion hostnames.

The public root/profile is what the device downloads during temporary port-80 bootstrap. The onboarding wizard must explain and illustrate platform trust installation without requiring the phone to connect physically to a computer or enroll in MDM.

Private CA, intermediate, leaf, onion identity, Tor client, TOTP, recovery, API, and session material are never exposed by the certificate endpoint. Runtime holds only material needed for operation; encrypted recovery material supports backup and rotation.

## Processes, privilege, and failure recovery

Native steady state has three long-running processes:

1. `torkittend`
2. Bundled C Tor
3. Bundled Caddy

Rust crates are library boundaries, not additional daemons. The desktop application and CLI are short-lived clients.

Native services run as dedicated non-root `torkitten`, `torkitten-tor`, and `torkitten-caddy` users with narrowly shared groups/directories and Unix sockets. Systemd owns process lifecycle and cgroups. Torkitten itself does not create user namespaces, manipulate cgroups, or require the application to run as root.

Systemd units use `NoNewPrivileges`, an empty capability set, restricted filesystems, syscall filtering, component-specific networking, ordered startup, restart backoff, singleton operation, and clean shutdown. Caddy receives only the loopback connectivity required for approved upstreams. Tor alone receives general outbound networking.

Configuration changes are validated before use and applied atomically. Failed Tor/Caddy validation or reload retains the last working configuration. Repeated child crashes back off rather than creating process storms. The persistent disabled latch survives daemon and machine restarts.

## Storage

One SQLite database stores the multi-site model: sites, site-scoped mappings, guests, devices, permissions, public certificate metadata, settings, and hashed sessions. Ports and mapping identifiers are scoped by site rather than globally.

The daemon is the only database writer. Desktop, container HTTP handlers, CLI, Tor, and Caddy send validated commands to the daemon instead of writing SQLite independently. SQLite uses WAL mode, foreign keys, bounded busy timeouts, strict schema constraints, and atomic migrations.

Secret values use versioned authenticated encryption. Container operation cannot assume access to a host desktop or kernel keyring, so encrypted file-backed state with strict permissions must work independently. Logs are bounded and redact credentials, authorization headers, cookies, request bodies, uploads, proxied content, chat content, passwords, TOTP seeds, recovery codes, and private keys.

## Rust workspace

- `torkitten-core`: validated multi-site, mapping, enrollment, IPC, and shared error types.
- `torkittend`: Tokio daemon coordinating state, health, enrollment, atomic reloads, child processes, and the emergency latch.
- `torkitten-tor`: C Tor configuration/control, persistent site identities, client authorization, and site-scoped virtual-port mappings.
- `torkitten-proxy`: deterministic restricted Caddy configuration, validation, and atomic reloads.
- `torkitten-auth`: administrator/guest authentication, share authorization, origin/CSRF enforcement, and revocable sessions.
- `torkitten-vault`: encrypted secret storage and SQLite persistence.
- `torkitten-web`: onion-facing guest portal and certificate-bootstrap pages.
- `torkitten-admin-web`: the single shared local administration interface and device wizard.
- `torkitten-desktop`: thin Wry native window hosting the shared administration UI.
- `torkittenctl`: local administration over the protected Unix socket.
- `packaging/`: one `.deb`, desktop entry, systemd/AppArmor files, OCI image, Podman/Docker configurations, SBOM, and reproducible manifests.

## Vendored components and builds

C Tor and Caddy source are stored pristine under `third-party/` at exact official release commits. Adjacent manifests record upstream release, tag object, commit, tree, license, and import date. Normal development does not patch their source.

Ubuntu 24.04 is the binary baseline. GitHub Actions builds Tor and Caddy concurrently on separate Ubuntu 24.04 runners. Each component has its own upstream-version/source-tree/build-recipe-derived cache and artifact. A later application/package workflow downloads and verifies those artifacts and builds only Torkitten when the third-party inputs have not changed. Build metadata preserves upstream version, flags, toolchain, license, and binary digest.

Local builds use Podman. Podman graph storage, caches, temporary work, and every generated binary/package remain under `/run/media/user/Data/TorkittenBuild` or another explicitly external build root. The repository must remain free of build products whether or not Git would ignore them.

## Verification and delivery

Refactor the existing single-site foundation before layering more features: core types, SQLite keys, Tor configuration, and IPC must all become site-scoped coherently.

Test real bundled Tor and Caddy rather than relying only on mocks. Test HTTP, WebSockets, SSE, uploads, full-path preservation, fail-closed authentication, forbidden admin access, Tor client authorization, temporary certificate bootstrap, guest login, long sessions, emergency shutdown, atomic reload failure, crash recovery, identity persistence, backup/restore, and container restart persistence.

Build and install the resulting `.deb` in the disposable Ubuntu 24.04, Ubuntu 26.04, and Debian 13 libvirt guests. Test the native Wry application and complete browser/device-style onboarding. Test the OCI image with the supplied Podman and Docker configurations.

Keep independently revertible functionality in small commits. Commit and push every completed feature to `origin`. Never commit VM credentials, generated keys, local state, caches, packages, or build output.
