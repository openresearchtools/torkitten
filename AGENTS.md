# Torkitten Agent Contract

Read this entire file before changing the repository. This is the authoritative
product contract and supersedes the removed Rust, native-desktop, multi-site,
guest, group, and per-mapping-permission designs.

## Product

Torkitten is one rootless OCI container which publishes trusted web applications
already listening on the immediate host loopback through one persistent v3 onion
identity. A second independent onion identity is a second Torkitten container.

The container contains one Go Torkitten control plane, C Tor, Caddy, and
Authelia. There is no native package or desktop application. The local control
panel is opened in the host browser through a port published only on
`127.0.0.1`.

## Trust model

- Deliberately mapped host applications are trusted.
- Remote clients and the outside world are untrusted.
- Do not introduce hostile-application isolation, an OIDC broker, per-prefix
  sessions, a cookie firewall, or a custom Caddy authentication module unless
  the user explicitly changes the threat model.
- Authelia is the sole store and verifier for the owner's username, password,
  and TOTP. Torkitten never stores a second password hash or TOTP seed.
- Authelia owns onion sessions and onion authorization decisions. Caddy asks
  Authelia to authorize every protected onion request and contacts a mapped
  application only after an explicit successful authorization response.
- Stock Authelia does not protect the HTTP `localhost` administration origin.
  For local login, Torkitten delegates factor verification to Authelia over a
  private internal HTTPS connection and, only after success, creates its own
  localhost-only administration session. Torkitten does not verify passwords or
  TOTP itself.
- Tor client authorization, private-CA HTTPS, and Authelia authentication are
  independent layers. Failure or uncertainty denies access.

## Address and routing model

One container has one persistent base address:

```text
<56-character-service-id>.onion
```

Applications use hostname prefixes on that identity:

```text
<service-id>.onion            -> protected service launcher
auth.<service-id>.onion       -> Authelia login portal
api.<service-id>.onion        -> protected host loopback port 7777
chat.<service-id>.onion       -> protected host loopback port 8888
every unknown hostname        -> deny without contacting an upstream
```

Tor exposes only virtual ports 80 and 443. Caddy terminates HTTPS and selects the
application using the exact `Host` value. Paths, queries, request bodies,
responses, redirects, WebSockets, SSE, and application cookies pass through
without application-specific rewriting.

One Authelia cookie scoped to the base onion domain provides one login across
all prefixes. Adding a prefix does not create an Authelia Application, user,
group, role, provider, or separate login.

The hostname relationship does not itself enforce authentication. Generated
Caddy configuration must place an internal Authelia authorization subrequest in
front of the base launcher and every configured application host. Only an
explicit successful authorization response can continue to the protected
handler or reverse proxy. A denial, timeout, malformed response, unavailable
Authelia service, or any uncertainty returns a denial and never contacts the
application. Browser redirects to `auth.<service-id>.onion` exist only for login
user experience; a client which ignores redirects gains no access.

The `auth` host exposes only the Authelia portal and endpoints needed to perform
login and cannot be placed behind its own forward-authorization check. The
temporary port-80 public-CA bootstrap is the only other narrowly defined bypass.
Caddy rejects all unknown hosts before proxy selection, removes caller-supplied
identity and forwarding headers, constructs the authorization metadata itself,
and trusts identity headers only from its private Authelia upstream.

## Authoritative control plane

The Go Torkitten daemon is the only product-state authority and the only writer
of Torkitten state. The browser, CLI, and agents call narrow typed Torkitten
endpoints; they never receive Caddy administration access, Tor control access,
arbitrary configuration submission, filesystem paths, or shell execution.

Torkitten uses supported component boundaries:

- authenticated Tor ControlPort or deterministic Tor configuration for onion
  lifecycle;
- Caddy's JSON administration API for validated atomic hot loads;
- Authelia's documented forward-authorization endpoint at
  `/api/authz/forward-auth`;
- Authelia's documented `/api/firstfactor`, `/api/user/info`, and
  `/api/secondfactor/totp` endpoints for delegated local factor verification;
- documented Authelia configuration and CLI only where Authelia has no
  administration API.

No shell is used. Executed component paths and arguments are fixed by the
container image. Secrets never appear in command arguments or logs.

## Mapping API

The mapping API accepts only a canonical hostname prefix, a numeric port, and a
small protocol enum. It never accepts a URL, IP address, hostname, command,
Caddy fragment, arbitrary headers, or path.

The prefix is a lowercase RFC-style label of 1 through 63 ASCII letters, digits,
or interior hyphens. Leading/trailing hyphens, dots, whitespace, Unicode,
encoding, wildcard syntax, reserved names, and duplicates are rejected. The
full onion hostname is constructed internally.

The target port is a JSON integer from 1 through 65535. The destination address
is not supplied by the caller: it is the fixed host-loopback path established by
the container network. Torkitten control-plane ports are always rejected.
Mapping-write credentials are publication authority and must be scoped,
revocable, rate limited, and stored only as hashes.

For each mutation Torkitten serializes writers, validates a complete candidate,
renders deterministic Caddy JSON, asks Caddy to load it, and persists state only
after success. A failed load retains or restores the last working state.

## Container networking

The supported Podman deployment is rootless and does not use host networking,
privileged mode, capabilities, kernel modules, a Docker socket, or a host helper.
Pasta host-loopback forwarding is enabled once when the container starts. Caddy
can then connect outbound to newly created host-loopback ports without changing
the container's published ports or restarting it.

Only the local administration listener is published by the container engine,
and it is bound to host `127.0.0.1`. Onion virtual ports are internal Tor-to-Caddy
connections and are never published by Podman or Docker.

## Administration and onboarding

There is one compact responsive local control panel implemented by the Go
service. It is the only place users manage Torkitten mappings, identity,
publication, onboarding, and API credentials. Authelia's own administration
concepts are not exposed as product objects.

First-run setup creates one owner in Authelia. The user enters one username, one
password, and enrolls one TOTP secret. Local administration and onion access
both validate against that exact Authelia record; no credentials are mirrored
into Torkitten. The two browser contexts have separate sessions because
`http://localhost:12755` and `.onion` are different origins.

The administration console exists only at `http://localhost:12755`. It is never
published through Tor. The container engine binds it to host `127.0.0.1`; the Go
service rejects every other Host and Origin. Authelia never receives the local
browser request and never treats HTTP localhost as one of its protected cookie
domains. Torkitten relays only the submitted login factors to Authelia's private
HTTPS endpoint, keeps the temporary Authelia verification cookie internal, and
issues a separate opaque local session after both factors succeed.

Local session cookies are host-only, `HttpOnly`, `SameSite=Strict`, scoped to
`/`, rotated after login, and backed by server-side token hashes with idle and
absolute expiry. They cannot honestly be represented as providing HTTPS
transport security. Exact Host/Origin checks, CSRF tokens, bounded bodies,
login rate limits, and the loopback-only listener are mandatory. Host-local
malware and other principals able to defeat the host's loopback boundary are
outside the container's security boundary.

No guests, user groups, roles, or per-application grants are part of this
product.

Onboarding can be reopened for every new device. It provides the public onion
address, a Tor client-authorization credential, the public CA certificate, and
normal Authelia login instructions. It never reveals the onion service private
key, CA private key, internal component secrets, or an authenticated session.

## Storage

All state is ordinary files below `/var/lib/torkitten` in the normal rootless
container writable layer. Torkitten does not require or create a named volume,
bind mount, host keyring, host daemon, or special secret mount. Stop/start and a
host reboot retain the writable layer of the same container. Removing that
container removes its writable layer and therefore removes its Torkitten state;
the product must state this plainly and never claim otherwise.

Do not invent a storage driver, require a host keyring, add a host daemon, or
require a special secret mount. Use strict permissions, atomic replacement,
bounded files, explicit schemas, and redacted logs. Encryption whose key is
stored beside its ciphertext is not represented as protection against theft of
the complete container state.

## Source and delivery

- First-party implementation is Go. There is no Rust workspace.
- Keep upstream Tor and Caddy snapshots pristine under `third-party/`.
- Pin Authelia and every container base by version or digest.
- Build and test through rootless Podman with generated artifacts outside the
  repository.
- Unit-test validation, deterministic configuration, persistence, API
  authorization, and rollback behavior.
- Integration-test real Caddy and Authelia, including unauthenticated denial,
  authenticated access, new mapping hot load without container restart, full
  path behavior, WebSockets, SSE, uploads, component failure, and restart
  persistence.
- Do not claim `.onion` cookie or private-CA browser compatibility until it has
  passed the pinned Authelia plus every advertised client combination: desktop
  Tor Browser, iOS Safari/WebKit routed through Orbot, and each supported Android
  browser routed through Orbot.
- Keep commits independently revertible. Never commit generated identities,
  credentials, state, binaries, packages, caches, or build output.

## Implementation size budget

The completed first-party runtime must remain below 5,000 physical lines of
production Go under `cmd/` and `internal/`. The count includes commands,
handlers, validation, persistence, component configuration, PKI, supervision,
and component clients. It excludes `*_test.go`, HTML templates, CSS, static
browser assets, and pristine third-party source. Generated Go or moving logic
into JavaScript, shell, templates, or generated files to evade the limit is
forbidden.

CI enforces the equivalent of:

```sh
find cmd internal -type f -name '*.go' ! -name '*_test.go' -print0 \
  | sort -z \
  | xargs -0 wc -l
```

The implementation allocation is:

| Area | Maximum lines | Responsibility |
| --- | ---: | --- |
| `cmd/torkitten`, `cmd/torkittenctl` | 180 | Wiring, signals, and thin CLI |
| `internal/model` | 220 | State types and strict input validation |
| `internal/state` | 280 | Versioned atomic file persistence |
| `internal/bootstrap` | 360 | First owner and direct TOTP setup |
| `internal/authelia` | 340 | Config, factor client, and fixed CLI calls |
| `internal/localsession` | 240 | Opaque localhost sessions and CSRF |
| `internal/tor` | 400 | Onion identity and client authorization |
| `internal/pki` | 300 | Private CA and onion certificates |
| `internal/caddy` | 400 | Deterministic JSON and atomic hot load |
| `internal/control` | 380 | Serialized mutations and rollback |
| `internal/supervisor` | 380 | Independent child lifecycle and health |
| `internal/api` | 600 | Local UI/API handlers and middleware |
| `internal/onboarding` | 260 | Device and certificate onboarding |
| `internal/apitoken` | 160 | Agent tokens, scopes, and bounded rates |
| **Target total** | **4,500** | **500 lines remain below the hard limit** |

These packages compile into one Go `torkitten` process. The container also
contains the three pinned child binaries: C Tor, Caddy, and Authelia.

## Runtime topology

```text
Host browser
  -> host 127.0.0.1:12755 only
  -> Torkitten HTTP administration listener
  -> Torkitten local session validation

Local login verification only
  -> Torkitten typed Authelia client
  -> private internal HTTPS
  -> Authelia first-factor and TOTP endpoints

Remote browser (desktop Tor Browser, or a mobile browser routed through Orbot)
  -> Tor client authorization
  -> one persistent v3 onion service
  -> Caddy private listener and private-CA HTTPS
  -> Authelia forward authorization
  -> exact approved host-loopback application port

Agent or CLI
  -> host-loopback control endpoint
  -> scoped Torkitten API token
  -> the same control manager used by the web UI
```

The local browser never connects to Authelia directly. Authelia never issues a
cookie for `localhost`. Torkitten's internal client uses its own short-lived
cookie jar solely to complete the documented Authelia factor exchange, destroys
that jar immediately afterward, and never forwards its cookie to the browser.

The Torkitten administration backend, Caddy administration endpoint, Tor
control endpoint, and Authelia backend are not published on a host interface.
The only published host port is the Torkitten administration listener bound to
`127.0.0.1`. Caddy is the only onion HTTP entry point. On protected onion
routes it strips caller-supplied identity headers before copying only the
documented successful Authelia response headers.

Rootless Podman pasta provides the fixed outbound path from the container to
the immediate host loopback. Adding a mapping changes Caddy configuration; it
does not change published container ports and does not restart the container.

## First-run owner bootstrap and later login

The setup page is available only while durable state is `uninitialized` and
only through `http://localhost:12755`. Application onion routes remain disabled
until setup completes.

First run is a persisted state machine:

1. The local setup page asks for the one owner's username, password, and
   password confirmation. It does not ask for TOTP on the same screen.
2. Torkitten strictly validates the username and password, creates the
   Authelia-compatible Argon2id PHC hash, and atomically creates Authelia's
   one-user file database. Plaintext exists only in bounded process memory for
   the active setup exchange; it is never persisted or logged.
3. Torkitten starts or reloads the pinned Authelia configuration and waits for
   its private HTTPS readiness endpoint.
4. Torkitten executes the fixed binary and argument shape without a shell:

   ```text
   authelia storage user totp generate <validated-owner>
     --config /etc/torkitten/authelia/configuration.yml
     --path /run/torkitten/setup-totp.png
   ```

5. The next setup screen serves that QR only to the active local setup flow
   with mode `0600`, `Cache-Control: no-store`, a strict CSP, and no referrer.
6. The user scans the QR and submits one current TOTP code.
7. Torkitten uses a private, isolated cookie jar to call Authelia's documented
   first-factor endpoint with the still-bounded setup credentials, then its
   user-info and TOTP endpoints. Authelia performs both validations.
8. After both factors succeed, Torkitten creates the first localhost session,
   atomically marks state `initialized`, destroys the temporary cookie jar and
   plaintext credentials, and removes the QR.
9. Setup handlers then return 404 permanently unless the container state is
   deliberately destroyed and recreated.

If Torkitten restarts before setup finishes, no password is recovered from
disk; the user repeats the incomplete setup flow. Partial files are rolled back
or reconciled before another attempt.

Later localhost login uses two sequential screens: username/password, then
TOTP. Torkitten again delegates verification to the private Authelia endpoints
and creates a fresh local session only after both succeed. The local session
record contains the owner identifier, token hash, creation time, last-use time,
authentication time, and expiry; it contains no password, password hash, or
TOTP seed.

The onion login uses Authelia's normal portal and Authelia session. Password
changes and TOTP rotations update the single Authelia account and revoke all
local and onion sessions. There is no synchronization of two credential stores
because only Authelia stores credentials.

## Onion identity, prefixed hosts, and devices

One container has one persistent Ed25519 v3 onion-service identity and one base
address. All prefixes and devices use that identity:

```text
auth.<service-id>.onion
api.<service-id>.onion
chat.<service-id>.onion
```

An authorized device receives an independent X25519 client-authorization
keypair. This does not create another onion service, container, or copy of the
application traffic.

Device creation is transactional:

1. Generate a fresh X25519 pair from the operating system CSPRNG.
2. Write the public key to a staged Tor authorization file.
3. Validate the complete candidate Tor configuration.
4. Reload or restart Tor using the operation supported by the pinned release.
5. Display the private client credential as text, downloadable data, and QR to
   the authenticated local owner.
6. Retain the private half only for the bounded pending-enrollment window.
7. After acknowledged import, erase the private half and persist only the
   device name, identifier, timestamps, and public key.

Interrupted pending enrollment is reconciled without leaving enabled
publication with zero authorized clients. The last authorized device cannot be
revoked while publication remains enabled. A lost acknowledged private key is
not recoverable; revoke its public key and generate another pair for the same
onion address.

Onion rotation stages a fresh Tor identity, hostname-dependent certificates,
client credentials, Authelia cookie configuration, and Caddy configuration.
The previous complete generation remains active until all candidate components
validate. Committing rotation deliberately invalidates the former address and
browser sessions. Any failure restores the complete previous generation.

## PKI and certificate onboarding

Torkitten uses Go's standard cryptographic and X.509 packages to create one
persistent private root CA and the certificates required by Caddy. Private keys
never cross an HTTP or agent API response.

The rootless container never installs a certificate, Tor credential, browser
setting, DNS entry, native helper, or any other file on the host or a client
device. It can only offer the public root certificate and Tor client credential
for deliberate user download/import, with platform-specific instructions and
QR codes. Private-CA HTTPS is unsupported on a device whose policy forbids the
user from installing or trusting the public root; the product must not claim a
zero-install workaround.

Orbot is a Tor transport for other applications, not the browser that owns web
state. On mobile, cookie-domain behavior, redirects, TLS trust, WebAuthn, and
storage are implemented by the actual browser routed through Orbot. Testing
Orbot alone proves none of those browser behaviors. The supported-client matrix
must name and test complete pairs, including iOS Safari/WebKit through Orbot and
the explicitly supported Android browsers through Orbot. Desktop Tor Browser
remains a separate supported client, not a substitute for the mobile matrix.

For a remote device the local onboarding flow opens a 15-minute onion port-80
bootstrap containing only:

- `GET` or `HEAD` of one unguessable public-CA path;
- static platform installation instructions; and
- no password, TOTP, session, client private key, application, or control API.

Tor client authorization protects access before HTTP is reached. Closing or
expiring the window removes that Caddy route without changing application
mappings. The user manually installs the public CA, then opens the permanent
HTTPS onion login.

## Mapping and Caddy transaction

The mapping API accepts only:

```json
{"prefix":"api","port":7777,"protocol":"http"}
```

It rejects arbitrary URLs, hosts, IP addresses, paths, commands, headers,
configuration fragments, Unicode, reserved prefixes, control-plane ports, and
duplicate prefixes. The host-loopback address is selected from fixed runtime
configuration and cannot be supplied by a caller.

Every create, edit, enable, disable, or removal uses one serialized path:

1. Validate the request and credential scope.
2. Clone current state and apply the mutation to a candidate.
3. Render complete deterministic Caddy JSON from the candidate.
4. Load it through Caddy's private administration endpoint.
5. Persist the candidate only after Caddy confirms success.
6. If persistence fails, reload the previous known-good Caddy JSON.

Caddy uses a complete `/load` rather than partial edits. Unknown hosts fail
closed. Every known application host runs forward authorization before reverse
proxying. It preserves the original path, query, method, body, response,
redirects, WebSockets, SSE, uploads, downloads, and application cookies.

## Control API

Browser and agent handlers are thin adapters over the same typed control
manager. Browser JavaScript owns no product state or component logic. The
bounded API can:

- read component health, publication state, mappings, devices, sessions, and
  onboarding state;
- create, edit, test, enable, disable, and remove a mapping;
- start, stop, and restart publication or an individual child component;
- create, acknowledge, and revoke a Tor-authorized device;
- open, extend, and close certificate bootstrap;
- rotate the onion identity with explicit confirmation;
- change the single owner password or regenerate TOTP;
- list and revoke local and onion sessions when supported by the pinned
  Authelia interfaces; and
- create and revoke scoped agent API tokens.

Agent tokens are random high-entropy bearer values shown once. Only a
constant-time-comparable hash is persisted. Default agent scope permits mapping
inspection and mutation but not identity rotation, owner changes, device
issuance, CA access, session administration, or process control. Request bodies,
concurrency, and rates are bounded.

Every browser mutation requires a valid local session, exact Host and Origin,
a CSRF token, the correct method and content type, and bounded input.
Destructive actions require explicit confirmation. Login and TOTP failures are
generic and rate limited. No authentication or session material enters URLs,
logs, templates, analytics, or referrers.

## Supervision and recovery

The Go process is PID 1 and reaps children. It starts C Tor, Caddy, and Authelia
without a shell, using fixed image paths and fixed argument shapes. Each child
has independent readiness checks, exponential restart backoff, a crash-loop
ceiling, and bounded redacted logs.

Failure behavior is explicit:

- Authelia unavailable: onion requests fail closed and new local logins fail;
  an already-valid local Torkitten session can still reach component recovery
  controls.
- Caddy unavailable: local administration stays available and Tor has no
  working application destination.
- Tor unavailable: local administration stays available and remote publication
  is unavailable.
- An upstream application unavailable: only that mapping reports failure.
- Torkitten restart: reconstruct component configuration from durable state and
  preserve identity, CA, owner, TOTP, mappings, local sessions, and acknowledged
  devices in the same container writable layer.
- Persistent publication stop: survive process and container restarts until the
  authenticated local owner clears it.

Complete owner lockout cannot be reset through an unauthenticated browser route.
Recovery authority belongs to the rootless user who owns the container and its
writable layer, through one narrow offline `torkittenctl owner reset` command.
This command stages one replacement Authelia owner/TOTP enrollment and revokes
all sessions; it is not a routine login path.

## State layout and secret boundaries

State uses `/var/lib/torkitten` with directory mode `0700`, secret files mode
`0600`, atomic replacement, fsync before rename, bounded sizes, and explicit
schema versions:

```text
/var/lib/torkitten/state.json             model and local-session/API-token hashes
/var/lib/torkitten/tor/hidden-service/    persistent onion identity and public auth entries
/var/lib/torkitten/pki/                   private root and TLS keys/certificates
/var/lib/torkitten/authelia/users.yml     one username and password hash
/var/lib/torkitten/authelia/db.sqlite3    Authelia TOTP/WebAuthn/authentication state
/var/lib/torkitten/authelia/secrets/      Authelia session and storage-encryption keys
/var/lib/torkitten/caddy/last-good.json   derived non-authoritative routes
/run/torkitten/                           private sockets and temporary enrollment files
```

Authelia alone owns the password hash, encrypted TOTP secret, future WebAuthn
credentials, onion login regulation, and onion sessions. Torkitten owns local
session hashes, the Tor identity, private CA, component bootstrap keys,
device-public-key records, and agent-token hashes. Plaintext login factors live
only for the bounded request/exchange that uses them.

This layout is inside the normal writable layer of the existing container. No
named volume or bind mount is created or required. The same container retains
it across stop/start and host reboot. `podman rm` destroys it. Export/import or
container replacement persistence is not claimed until a separately approved
mechanism exists.

## Blocking protocol proofs

Before dependent implementation is accepted, automated and live tests against
the pinned component versions must prove:

1. Current C Tor and Tor Browser route approved prefixes of one v3 onion
   identity to one service while preserving the complete Host value.
2. Pinned Authelia and every advertised client combination accept one cookie
   scoped to the base onion hostname and send it to all approved prefixes. The
   required matrix includes desktop Tor Browser, iOS Safari/WebKit routed
   through Orbot, and each supported Android browser routed through Orbot.
3. Supported Windows, macOS, Linux, iOS, and Android combinations can manually
   import the public CA and Tor client credential, resolve prefixed onion hosts,
   complete redirects, and reopen an authenticated session. Unsupported or
   locked-down combinations are identified honestly.
4. The pinned Authelia factor endpoints validate the one owner through private
   internal HTTPS while the local browser remains on HTTP localhost.
5. Local sessions survive a Torkitten restart, revoke correctly, never contain
   credentials, reject cross-origin/CSRF/DNS-rebinding attempts, and cannot be
   used on onion routes.
6. The pinned Authelia CLI generates and persists TOTP plus a QR without a
   secret in process arguments or logs.
7. Rootless Podman pasta reaches a host-loopback port created after container
   start without publishing that port or restarting the container.
8. Caddy forward authorization fails closed and a failed JSON `/load` retains
   the previous working configuration.
9. Stop/start and host reboot retain the ordinary writable layer, and removal
   destroys it exactly as documented.

Failure of a proof blocks the dependent feature and requires an explicit
architecture decision. It is never papered over by undocumented component
behavior or a weakened browser policy.

## Implementation milestones

1. **Foundation:** enforce the line budget, complete strict schemas and atomic
   persistence, and retain existing validation/Caddy/control tests.
2. **Runtime:** build one entrypoint supervising pinned Caddy, Authelia, and C
   Tor with private control endpoints.
3. **Owner bootstrap:** implement the one-account state machine, Authelia user,
   direct TOTP generation, delegated factor proof, and local session creation.
4. **Onion and PKI:** persist one identity, require a Tor client key before
   publication, issue certificates, and prove prefixed hosts in Tor Browser.
5. **Protected mappings:** implement deterministic Caddy configuration, generic
   Authelia 2FA, hot loads, rollback, and live host-loopback upstream tests.
6. **Onboarding:** implement repeated device creation/revocation, public CA
   delivery, bounded port-80 bootstrap, and credential exports.
7. **Sensitive controls:** add publication control, onion rotation, owner
   password/TOTP rotation, session revocation, and agent credentials.
8. **UI binding:** connect the responsive server-rendered interface to the typed
   API with pending, success, and failure states; authoritative logic stays Go.
9. **Release verification:** exercise real HTTP, WebSockets, SSE, uploads,
   redirects, fail-closed authentication, crashes, concurrent mutations,
   revocation, rotation, and same-container restart persistence in rootless
   Podman and the supported Docker environment.

Each milestone is split into independently revertible commits. A milestone is
not complete until unit tests, real-component integration tests, line-count
checks, secret-redaction checks, and live browser/container evidence pass.
