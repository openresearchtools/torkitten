# Torkitten Agent Contract

Read this entire file before changing the repository. This is the authoritative
product contract and supersedes the removed Rust, native-desktop, multi-site,
guest, user-managed-group, and per-mapping-permission designs.

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
  TOTP, and membership in one fixed internal group named `torkitten-owner`.
  Torkitten never stores a second password hash, TOTP seed, or authorization
  list.
- Authelia owns onion sessions and onion authorization decisions. Its generated
  access-control policy defaults to deny and requires `two_factor` plus the
  `group:torkitten-owner` subject for the base onion domain and all of its
  subdomains. Torkitten does not evaluate group membership or implement an
  onion access-control engine.
- Caddy asks Authelia to authorize every protected onion request and contacts a
  mapped application only after an explicit successful authorization response.
- Stock Authelia does not protect the HTTP `localhost` administration origin.
  For local login, Torkitten delegates factor verification to Authelia over its
  private Unix-domain HTTP socket and, only after success, creates its own
  localhost-only administration session. Torkitten does not verify passwords or
  TOTP itself.
- Tor client authorization, Caddy-managed private-CA HTTPS, and Authelia
  authentication are independent layers. Failure or uncertainty denies access.

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

Tor exposes only virtual ports 80 and 443 and maps them to private Caddy Unix
listeners. Caddy's native PKI and internal issuer terminate HTTPS, and Caddy
selects the application using the exact `Host` value. Caddy's stock reverse
proxy preserves paths, queries, request bodies, responses, redirects,
WebSockets, SSE, and application cookies without application-specific
rewriting.

One Authelia cookie scoped to the base onion domain provides one login across
all prefixes. The owner is the sole member of the fixed `torkitten-owner`
group. Authelia's domain rule covers both the base hostname and its wildcard
subdomains, so adding a prefix does not create or modify an Authelia
Application, user, group, role, provider, policy, or login. Applications are
not group members; users are group members and domain rules select the
protected applications.

The hostname relationship and wildcard policy do not themselves intercept
traffic or enforce HTTPS. Caddy terminates HTTPS and must invoke Authelia's
stock forward-authorization endpoint for every protected route. Generated
Caddy configuration must place an internal Authelia authorization subrequest in
front of the base launcher and every configured application host. Only an
explicit successful authorization response can continue to the protected
handler or reverse proxy. A denial, timeout, malformed response, unavailable
Authelia service, or any uncertainty returns a denial and never contacts the
application. Browser redirects to `auth.<service-id>.onion` exist only for login
user experience; a client which ignores redirects gains no access.

The `auth` host exposes only the Authelia portal and endpoints needed to perform
login and cannot be placed behind its own forward-authorization check. Caddy's
stock static handlers serve the protected launcher and the temporary port-80
public-CA bootstrap; the bootstrap is the only other narrowly defined bypass.
Caddy rejects all unknown hosts before proxy selection, removes caller-supplied
identity and forwarding headers, constructs the authorization metadata itself,
and trusts identity headers only from Authelia's private Unix-socket upstream.

## Authoritative control plane

The Go Torkitten daemon is the authority and only writer for Torkitten's typed
product model: mappings, publication intent, device records, local-session
hashes, and agent-token hashes. Each pinned component owns and writes its native
security state: Tor owns its hidden-service identity, Caddy owns its PKI, and
Authelia owns credentials, group membership, factors, bans, and onion sessions.
The browser, CLI, and agents call narrow typed Torkitten endpoints; they never
receive Caddy administration access, Tor control access, arbitrary configuration
submission, filesystem paths, or shell execution.

Torkitten uses supported component boundaries:

- Tor's `HiddenServiceDir` for generated persistent identity and service-side
  client authorization, plus a private `ControlSocket` protected by Tor cookie
  authentication for lifecycle operations;
- Caddy's private Unix-socket JSON administration API for validated atomic hot
  loads, native PKI/internal issuance, and public-root retrieval;
- Authelia's documented Unix-socket listener and forward-authorization endpoint
  at `/api/authz/forward-auth`;
- Authelia's documented `/api/firstfactor`, `/api/user/info`, and
  `/api/secondfactor/totp` endpoints for delegated local factor verification;
- documented Authelia configuration, regulation, endpoint rate limits, portal,
  and CLI only where Authelia has no administration API.

First-party code validates product inputs, renders bounded component
configuration, calls typed supported interfaces, and coordinates transactions.
It does not reimplement Caddy proxying, static serving, HTTPS, PKI, or load
validation; Tor identity or service authorization; or Authelia credential
verification, access policy, regulation, factor limits, or onion sessions.

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
after success. Caddy's atomic `/load` retains its running configuration when it
rejects a candidate. If Torkitten persistence fails after a successful load,
Torkitten re-renders and reloads the prior durable state.

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

First-run setup creates one owner in Authelia as the sole member of the fixed
`torkitten-owner` group. The user enters one username, one password, and enrolls
one TOTP secret. Local administration and onion access both validate against
that exact Authelia record; no credentials are mirrored into Torkitten. The two
browser contexts have separate sessions because `http://localhost:12755` and
`.onion` are different origins.

The administration console exists only at `http://localhost:12755`. It is never
published through Tor. The container engine binds it to host `127.0.0.1`; the Go
service rejects every other Host and Origin. Authelia never receives the local
browser request and never treats HTTP localhost as one of its protected cookie
domains. Torkitten relays only the submitted login factors over Authelia's
private Unix socket, keeps the temporary Authelia verification cookie internal,
and issues a separate opaque local session after both factors succeed.

Local session cookies are host-only, `HttpOnly`, `SameSite=Strict`, scoped to
`/`, rotated after login, and backed by server-side token hashes with idle and
absolute expiry. They cannot honestly be represented as providing HTTPS
transport security. Exact Host/Origin checks, CSRF tokens, bounded bodies,
coarse request and concurrency limits, and the loopback-only listener are
mandatory. Authelia's own regulation and factor-endpoint rate limits protect
credential verification; Torkitten does not implement a second credential
ban engine. Host-local malware and other principals able to defeat the host's
loopback boundary are outside the container's security boundary.

No guests, additional users, user-managed groups, roles, or per-application
grants are part of this product. The one fixed internal Authelia owner group
exists only to express the uniform built-in Authelia policy for every mapped
application; it is not a product object or a configurable permission system.

Onboarding can be reopened for every new device. It provides the public onion
address, a Tor client-authorization credential, and the public root certificate
retrieved from Caddy's private PKI administration endpoint, plus normal Authelia
login instructions. It never reveals the onion service private key, Caddy CA
private key, internal component secrets, or an authenticated session.

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
- Keep upstream Tor, Caddy, and Authelia snapshots pristine under
  `third-party/` and pin every imported tag, tag object, commit, and tree.
- Pin every container and build-tool base by version and digest.
- Build Tor, Caddy, and Authelia as three independent, version-keyed artifacts
  on separate Ubuntu 24.04 Actions runners. Build-tool reporting and update
  checks are disabled. Runtime Authelia metrics and Caddy OpenTelemetry are
  forcibly disabled by the supervisor, not merely omitted from configuration;
  no Tor metrics listener is configured, and Tor statistics plus heartbeat
  logging are explicitly disabled in its generated configuration.
- Build and test through rootless Podman with generated artifacts outside the
  repository.
- Unit-test validation, deterministic configuration, persistence, API
  authorization, and rollback behavior.
- Integration-test real Caddy and Authelia, including unauthenticated denial,
  authenticated access, new mapping hot load without container restart, full
  path behavior, WebSockets, SSE, uploads, component failure, stated restart
  persistence, and documented onion-session loss.
- Do not claim `.onion` cookie or private-CA browser compatibility until it has
  passed the pinned Authelia plus every advertised client combination: desktop
  Tor Browser, iOS Safari/WebKit routed through Orbot, and each supported Android
  browser routed through Orbot.
- Keep commits independently revertible. Never commit generated identities,
  credentials, state, binaries, packages, caches, or build output.

## Implementation size budget

The completed first-party runtime must remain below 5,000 physical lines of
production Go under `cmd/` and `internal/`. The count includes commands,
handlers, validation, persistence, component and PKI configuration, supervision,
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
| `internal/authelia` | 340 | Config, Unix-socket factor client, and fixed CLI calls |
| `internal/localsession` | 240 | Opaque localhost sessions and CSRF |
| `internal/tor` | 400 | HiddenServiceDir, client authorization, and ControlSocket |
| `internal/caddy` | 400 | Deterministic JSON, native PKI, and atomic hot load |
| `internal/control` | 380 | Serialized mutations and rollback |
| `internal/supervisor` | 380 | Independent child lifecycle and health |
| `internal/api` | 600 | Local UI/API handlers and middleware |
| `internal/onboarding` | 260 | Device and Caddy-CA onboarding |
| `internal/apitoken` | 160 | Agent tokens, scopes, and bounded rates |
| **Target total** | **4,200** | **800 lines remain below the hard limit** |

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
  -> private Authelia Unix socket
  -> Authelia first-factor and TOTP endpoints

Remote browser (desktop Tor Browser, or a mobile browser routed through Orbot)
  -> Tor client authorization
  -> one Tor-generated persistent v3 onion service
  -> private Caddy Unix listener and Caddy-managed private-CA HTTPS
  -> Authelia forward authorization over its private Unix socket
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

The Caddy administration endpoint, Tor control endpoint, Authelia backend, and
Tor-to-Caddy listeners are private Unix sockets below `/run/torkitten`; they are
not published on a host interface. The only published host port is the
Torkitten administration listener bound to `127.0.0.1`. Caddy is the only onion
HTTP entry point. On protected onion
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
   one-user file database with that user as the sole member of the fixed
   `torkitten-owner` group. Plaintext exists only in bounded process memory for
   the active setup exchange; it is never persisted or logged.
3. Torkitten starts or reloads the pinned Authelia configuration and waits for
   its readiness endpoint over the private Unix socket.
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
TOTP. Torkitten again delegates verification through the private Authelia Unix
socket and creates a fresh local session only after both succeed. The local
session record contains the owner identifier, token hash, creation time,
last-use time,
authentication time, and expiry; it contains no password, password hash, or
TOTP seed.

The onion login and supported routine credential management use Authelia's
normal portal and interfaces. After a successful password or TOTP change,
Torkitten revokes every local session; Authelia owns onion-session invalidation,
and Torkitten restarts Authelia to clear its memory sessions when no documented
revocation interface exists. There is no synchronization of two credential
stores because only Authelia stores credentials.

## Onion identity, prefixed hosts, and devices

Tor generates and owns one persistent Ed25519 v3 onion-service identity in its
`HiddenServiceDir`; Torkitten records only the resulting public base address.
All prefixes and devices use that identity:

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

Onion rotation asks Tor to generate a fresh identity in a staged
`HiddenServiceDir`, stages client credentials and Authelia cookie configuration,
and loads candidate Caddy configuration that uses Caddy's persistent CA to
issue the new hostname certificates. The previous complete generation remains
active until all candidate components validate. Committing rotation deliberately
invalidates the former address and browser sessions. Any failure restores the
complete previous generation. Torkitten never generates or parses an onion
identity private key.

## Caddy PKI and certificate onboarding

Caddy's stock PKI app owns one persistent private root CA, its intermediate, and
all onion leaf certificates. The generated Caddy JSON selects the native
internal issuer, fixes Caddy's file storage below `/var/lib/torkitten/caddy`,
sets `install_trust` to false, and disables Caddy configuration persistence.
Caddy issues and renews certificates; Torkitten does not implement an X.509
authority or read any Caddy private key. Torkitten reconstructs Caddy
configuration from its durable typed state after every restart.

Torkitten retrieves the public root through Caddy's private documented PKI
administration endpoint and exposes only those bounded public bytes through its
onboarding API. The Caddy administration endpoint itself is never exposed.

The rootless container never installs a certificate, Tor credential, browser
setting, DNS entry, native helper, or any other file on the host or a client
device. It can only offer Caddy's public root certificate and a Tor client
credential for deliberate user download/import, with platform-specific
instructions and QR codes. Private-CA HTTPS is unsupported on a device whose
policy forbids the user from installing or trusting the public root; the product
must not claim a
zero-install workaround.

Orbot is a Tor transport for other applications, not the browser that owns web
state. On mobile, cookie-domain behavior, redirects, TLS trust, WebAuthn, and
storage are implemented by the actual browser routed through Orbot. Testing
Orbot alone proves none of those browser behaviors. The supported-client matrix
must name and test complete pairs, including iOS Safari/WebKit through Orbot and
the explicitly supported Android browsers through Orbot. Desktop Tor Browser
remains a separate supported client, not a substitute for the mobile matrix.

For a remote device the local onboarding flow enables Caddy's stock static
handlers for a 15-minute onion port-80 bootstrap containing only:

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
4. Load it through Caddy's private Unix-socket administration endpoint; Caddy
   validates and provisions the complete candidate and retains the running
   configuration if it rejects the load.
5. Persist the candidate only after Caddy confirms success.
6. If persistence fails, re-render and reload the prior durable state.

Caddy uses a complete `/load` rather than partial edits. Torkitten does not
maintain a separate last-good Caddy file or duplicate Caddy's proxy validation.
Unknown hosts fail closed. Every known application host runs forward
authorization before reverse proxying. It preserves the original path, query,
method, body, response, redirects, WebSockets, SSE, uploads, downloads, and
application cookies.

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
- coordinate supported Authelia-owned password or TOTP operations and revoke
  local sessions after success;
- list and revoke local sessions, and invoke onion-session operations only when
  a documented pinned Authelia interface supports them; and
- create and revoke scoped agent API tokens.

Agent tokens are random high-entropy bearer values shown once. Only a
constant-time-comparable hash is persisted. Default agent scope permits mapping
inspection and mutation but not identity rotation, owner changes, device
issuance, CA access, session administration, or process control. Request bodies,
concurrency, and rates are bounded.

Every browser mutation requires a valid local session, exact Host and Origin,
a CSRF token, the correct method and content type, and bounded input.
Destructive actions require explicit confirmation. Login and TOTP failures are
generic; Authelia applies its regulation and factor-endpoint rate limits. No
authentication or session material enters URLs, logs, templates, analytics, or
referrers. Torkitten never reads or modifies Authelia's database to emulate a
missing credential or onion-session API.

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
  preserve Tor's identity, Caddy's CA, the Authelia owner and TOTP, mappings,
  local sessions, and acknowledged devices in the same container writable
  layer.
- Authelia uses its stock memory session provider because this one-container
  product does not add Redis. Restarting Authelia or the container therefore
  destroys onion sessions and requires onion clients to authenticate again;
  Torkitten does not implement a replacement Authelia session store.
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
/var/lib/torkitten/tor/hidden-service/    Tor-owned onion identity and public auth entries
/var/lib/torkitten/caddy/storage/         Caddy-owned private CA and issued certificates
/var/lib/torkitten/authelia/users.yml     owner hash and fixed group membership
/var/lib/torkitten/authelia/db.sqlite3    Authelia TOTP/WebAuthn/authentication state
/var/lib/torkitten/authelia/secrets/      Authelia session and storage-encryption keys
/run/torkitten/                           private sockets and temporary enrollment files
```

Authelia alone owns the password hash, fixed owner-group membership, encrypted
TOTP secret, future WebAuthn credentials, onion login regulation, and onion
sessions. Tor alone owns the onion identity private key. Caddy alone owns the CA
and TLS private keys. Torkitten owns local-session hashes, component bootstrap
secrets, device-public-key records, bounded pending client private keys, and
agent-token hashes. Plaintext login factors live only for the bounded
request/exchange that uses them.

This layout is inside the normal writable layer of the existing container. No
named volume or bind mount is created or required. The same container retains
it across stop/start and host reboot. `podman rm` destroys it. Export/import or
container replacement persistence is not claimed until a separately approved
mechanism exists.

## Blocking protocol proofs

Before dependent implementation is accepted, automated and live tests against
the pinned component versions must prove:

1. Current C Tor generates and persists one v3 identity in `HiddenServiceDir`,
   maps virtual ports to Caddy's Unix listeners, reloads authorized-client files
   through its cookie-authenticated `ControlSocket`, and current Tor Browser
   reaches approved prefixes while preserving the complete Host value.
2. Pinned Authelia authorizes the sole owner through its fixed internal group
   and every advertised client combination accepts one cookie scoped to the
   base onion hostname and sends it to all approved prefixes. The required
   matrix includes desktop Tor Browser, iOS Safari/WebKit routed through Orbot,
   and each supported Android browser routed through Orbot.
3. Supported Windows, macOS, Linux, iOS, and Android combinations can manually
   import Caddy's public CA and a Tor client credential, resolve prefixed onion
   hosts, complete redirects, and reopen an authenticated session. Unsupported
   or locked-down combinations are identified honestly.
4. The pinned Authelia factor endpoints validate the one owner through its
   private Unix socket while the local browser remains on HTTP localhost.
5. Local sessions survive a Torkitten restart, revoke correctly, never contain
   credentials, reject cross-origin/CSRF/DNS-rebinding attempts, and cannot be
   used on onion routes.
6. The pinned Authelia CLI generates and persists TOTP plus a QR without a
   secret in process arguments or logs.
7. Rootless Podman pasta reaches a host-loopback port created after container
   start without publishing that port or restarting the container.
8. Caddy's native PKI persists its private CA, returns only public certificates
   through the private PKI API, and issues valid onion certificates; its forward
   authorization fails closed, and a failed JSON `/load` retains the previous
   working configuration.
9. Stop/start and host reboot retain the ordinary writable layer and all stated
   component state, Authelia/container restart destroys onion sessions as
   documented, and container removal destroys the writable layer.

Failure of a proof blocks the dependent feature and requires an explicit
architecture decision. It is never papered over by undocumented component
behavior or a weakened browser policy.

## Implementation milestones

1. **Foundation:** enforce the line budget and implement strict schemas, atomic
   persistence, validation, Caddy rendering, and control transaction tests.
2. **Runtime:** build one entrypoint supervising pinned Caddy, Authelia, and C
   Tor with private Unix endpoints.
3. **Owner bootstrap:** implement the one-account state machine, Authelia user
   and fixed owner-group membership, direct TOTP generation, delegated factor
   proof, and local session creation.
4. **Onion and PKI:** use Tor's persistent generated identity and Caddy's native
   PKI, require a Tor client key before publication, and prove prefixed hosts in
   Tor Browser.
5. **Protected mappings:** configure stock Caddy reverse proxy and forward auth,
   the fixed-group Authelia 2FA policy, hot loads, persistence rollback, and live
   host-loopback upstream tests.
6. **Onboarding:** implement repeated device creation/revocation, Caddy public-CA
   delivery, a bounded Caddy-served port-80 bootstrap, and credential exports.
7. **Sensitive controls:** add publication control and onion rotation,
   coordinate Authelia-owned password/TOTP operations, revoke local sessions,
   use only supported Authelia onion-session operations, and add agent
   credentials.
8. **UI binding:** connect the responsive server-rendered interface to the typed
   API with pending, success, and failure states; authoritative logic stays Go.
9. **Release verification:** exercise real HTTP, WebSockets, SSE, uploads,
   redirects, fail-closed authentication, crashes, concurrent mutations,
   revocation, rotation, stated same-container persistence, and documented
   onion-session loss in rootless Podman and the supported Docker environment.

Each milestone is split into independently revertible commits. A milestone is
not complete until unit tests, real-component integration tests, line-count
checks, secret-redaction checks, and live browser/container evidence pass.
