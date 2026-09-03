# Torkitten Minimal Implementation Plan

This plan implements the product contract in `AGENTS.md` as one Go executable
that orchestrates pinned C Tor, Caddy, and Authelia through their supported
interfaces.

## Hard size boundary

The completed first-party runtime must remain below **5,000 physical lines of
production Go** under `cmd/` and `internal/`.

The count includes commands, handlers, validation, persistence, configuration
rendering, PKI, process supervision, and component clients. It excludes
`*_test.go`, HTML templates, CSS, static browser assets, and pristine vendored
third-party source. Generated Go and moving orchestration logic into JavaScript,
shell, or generated files to evade the limit are forbidden.

CI enforces the limit with the equivalent of:

```sh
find cmd internal -type f -name '*.go' ! -name '*_test.go' -print0 \
  | sort -z \
  | xargs -0 wc -l
```

The current foundation is 1,249 production Go lines. The target allocation is
4,420 lines, leaving 580 lines of contingency:

| Area | Maximum lines | Responsibility |
| --- | ---: | --- |
| `cmd/torkitten`, `cmd/torkittenctl` | 180 | Wiring, signals, and thin CLI |
| `internal/model` | 220 | State types and input validation |
| `internal/state` | 280 | Versioned atomic persistence |
| `internal/bootstrap` | 380 | First owner and direct TOTP setup |
| `internal/authelia` | 320 | Deterministic config and fixed CLI calls |
| `internal/tor` | 420 | Onion identity and client authorization |
| `internal/pki` | 320 | Private CA and exact/wildcard leaf certificates |
| `internal/caddy` | 420 | Deterministic JSON and atomic hot load |
| `internal/control` | 400 | Serialized mutations and rollback |
| `internal/supervisor` | 400 | Independent child lifecycle and health |
| `internal/api` | 620 | Local UI/API handlers and middleware |
| `internal/onboarding` | 280 | Device and certificate onboarding |
| `internal/apitoken` | 180 | Agent tokens, scopes, and bounded rate limits |
| **Target total** | **4,420** | **580 lines remain below the hard limit** |

These source units compile into one Go `torkitten` process. The runtime container
contains that process plus the three pinned child binaries: C Tor, Caddy, and
Authelia.

## Runtime topology

```text
Host browser
  -> host 127.0.0.1:12755 only
  -> Caddy local frontend
  -> Authelia forward authorization
  -> Torkitten private Unix HTTP socket

Remote browser
  -> Tor client authorization
  -> one persistent v3 onion service
  -> Caddy private Unix HTTP/TLS listeners
  -> Authelia forward authorization
  -> exact approved host-loopback application port

Agent or CLI
  -> host-loopback control endpoint
  -> scoped Torkitten API token
  -> the same control manager used by the web UI
```

The Torkitten backend, Caddy administration endpoint, Tor control endpoint, and
Authelia backend are never published on a host interface. Caddy is the only
HTTP entry point. It removes caller-supplied identity headers before adding
headers returned by Authelia.

The container engine publishes only the local Caddy administration frontend to
host loopback. Rootless Podman pasta supplies the fixed outbound path to host
loopback. Adding a mapping changes Caddy configuration; it never changes the
container's published ports and never restarts the container.

## One owner and direct TOTP bootstrap

First-run setup creates one owner in Authelia. That same username, password,
and TOTP protect both the localhost administration panel and onion access.
There are two browser sessions because `localhost` and `.onion` are different
origins, but there is only one account and one credential set.

The only unauthenticated administration state is the initial setup route while
the durable state is `uninitialized`. It is available solely through the
host-loopback listener. All onion application routes remain unavailable.

First run is a persisted state machine:

1. The local setup page asks for a username, password, and password
   confirmation for the shared local-administration and onion owner.
2. Torkitten validates the username and password and creates an
   Authelia-compatible Argon2id PHC hash in memory. It never persists or logs
   the plaintext and never passes it in a process argument.
3. Torkitten atomically creates Authelia's one-user YAML database. Torkitten's
   own state records only the non-secret username and setup phase.
4. Torkitten starts or reloads the pinned Authelia configuration and waits for
   readiness.
5. Torkitten directly executes the fixed binary and argument shape:

   ```text
   authelia storage user totp generate <validated-owner>
     --config /etc/torkitten/authelia/configuration.yml
     --path /run/torkitten/setup-totp.png
   ```

   No shell is involved. The username is strictly validated and the fixed
   configuration supplies the SQLite location and storage-encryption-key file.
   No secret appears in arguments.
6. The setup page serves the generated QR only to the active local setup flow,
   with `Cache-Control: no-store`, a strict CSP, and no referrer. The file is
   mode `0600` and is removed after completion, cancellation, expiry, or
   regeneration.
7. The owner scans the QR and continues through the real local Authelia portal.
   Authelia—not Torkitten—validates the username, password, and TOTP.
8. A setup-completion endpoint is behind an Authelia `two_factor` policy. A
   successful forward-authorization result for the configured owner proves the
   enrollment works and atomically changes state to `initialized`.
9. Initial setup handlers then return 404 permanently. The resulting Authelia
   owner immediately serves both local administration and onion login. Their
   browser sessions remain separate because the origins differ.

Torkitten performs password hashing only to provision Authelia's supported file
backend. It never validates a password or TOTP, creates an authentication
session, or decides whether a browser is authenticated.

Authelia uses a generic `two_factor` rule for the local administration origin
and all valid application prefixes. Adding a mapping does not create an
Authelia application, role, group, provider, or user and does not require an
Authelia reload.

## Onion identity, prefixed hosts, and devices

One container has one Ed25519 v3 onion-service identity and therefore one base
address. All application prefixes and all devices use that same identity:

```text
auth.<service-id>.onion
api.<service-id>.onion
chat.<service-id>.onion
```

An authorized device has an independent X25519 client-authorization keypair.
The keypair does not create another onion identity, service, container, or copy
of application traffic.

Device creation is transactional:

1. Generate a fresh X25519 pair using Go's cryptographic randomness.
2. Write the public key to a staged Tor `.auth` file.
3. Validate the complete candidate Tor configuration.
4. Restart or reload Tor using the operation supported by the pinned release.
5. Display the client private credential as text, file, and QR to the local
   authenticated owner.
6. Retain the private half only for the bounded pending-enrollment window.
7. After the owner acknowledges import, erase the private half. Persist only
   the device name, identifier, timestamps, and public key.

If a pending enrollment is interrupted, its unusable public entry is removed
or replaced during recovery without ever leaving the service with zero
authorized public keys while publication is enabled. The last authorized
device cannot be revoked while publication remains enabled.

Adding another device later generates another pair for the same onion address.
Losing a device private key means revoking that public key and issuing a new
pair; Torkitten cannot recover or redisplay an acknowledged private key.

An onion rotation stages a fresh Tor identity, new hostname-dependent
certificates, new client credentials, Authelia cookie configuration, and Caddy
configuration. The old working generation is retained until every candidate
component validates. Committing rotation invalidates the old address and its
browser sessions deliberately. Failure restores the complete previous
generation.

## PKI and certificate onboarding

Torkitten uses Go's standard cryptographic and X.509 packages to create one
persistent private root CA and the certificates required by Caddy. Private keys
never cross an HTTP or agent API response.

The local onboarding page can always provide the public root certificate. For a
remote device it may open a 15-minute port-80 onion bootstrap containing only:

- `GET` or `HEAD` of one unguessable public-CA path;
- static platform installation instructions; and
- no password, TOTP, session, client private key, application, or control API.

Tor client authorization protects the service before HTTP is reached. Closing
or expiring the bootstrap removes the Caddy route without changing application
mappings.

## Mapping and Caddy transaction

The mapping API accepts only:

```json
{"prefix":"api","port":7777,"protocol":"http"}
```

It rejects arbitrary URLs, hosts, IP addresses, paths, commands, headers,
configuration fragments, Unicode, reserved prefixes, control-plane ports, and
duplicate prefixes. The host-loopback destination is selected internally from
a fixed runtime mode; it is never caller-controlled.

Every create, edit, enable, disable, or removal follows one serialized path:

1. Validate the request and authorization scope.
2. Clone current state and apply the requested change to the candidate.
3. Render the complete deterministic Caddy JSON from the candidate.
4. Load it through Caddy's private administration socket.
5. Persist the candidate only after Caddy confirms success.
6. If persistence fails, reload the previous known-good Caddy JSON.

Caddy's full `/load` operation is used instead of a sequence of partial edits,
so concurrent operations cannot leave half-applied routing. Unknown hosts fail
closed. Every known application host runs forward authorization before reverse
proxying. Caddy preserves the original path, query, method, body, response,
redirects, WebSockets, SSE, uploads, downloads, and application cookies.

## Control API

Browser handlers and agent endpoints are thin adapters over the same typed
control manager. Browser JavaScript owns no product state or component logic.

The bounded API surface is:

- Read component health, publication state, mappings, devices, and onboarding
  status.
- Create, edit, test, enable, disable, and remove a mapping.
- Start, stop, and restart publication or an individual child component.
- Create, acknowledge, and revoke a Tor-authorized device.
- Open, extend, and close certificate bootstrap.
- Rotate the onion identity with explicit confirmation.
- Change the owner password or regenerate TOTP from an authenticated local
  session.
- Create and revoke scoped agent API tokens.

Agent tokens are random high-entropy bearer values shown once. Only a
constant-time-comparable hash is persisted. The default agent scope permits
mapping inspection and mutation but not identity rotation, owner changes,
device issuance, CA access, or process control. Request bodies, concurrency,
and rates are bounded.

Browser mutations require an exact allowed origin, CSRF token, Authelia
forward authorization, the configured owner identity, and appropriate method
and content type. Destructive actions additionally require explicit human
confirmation. The product does not claim that this is a fresh per-action second
factor; stock Authelia forward authorization proves the current session's
authentication level.

## Supervision and recovery

The Go process is PID 1 and reaps children. It starts C Tor, Caddy, and Authelia
without a shell using fixed image paths and fixed argument shapes. Each child
has independent readiness checks, exponential restart backoff, a crash-loop
ceiling, and redacted bounded logs.

Failure behavior is explicit:

- Authelia unavailable: Caddy denies protected requests.
- Caddy unavailable: Tor has no working application destination.
- Tor unavailable: local administration stays available and remote publication
  is unavailable.
- An upstream application unavailable: only that mapping reports failure.
- Torkitten restart: reconstruct component configuration from durable
  authoritative state and preserve identity, CA, owner, TOTP, mappings, and
  acknowledged devices.
- Persistent publication stop: survive process and container restarts until the
  local owner clears it.

Normal owner password and TOTP changes require an authenticated local 2FA
session. Complete owner lockout cannot be solved by the same lost factor; the
rootless container/volume owner is the separate recovery authority and uses a
narrow offline `torkittenctl owner reset` operation. This is emergency recovery,
not routine administration and not an unauthenticated web route.

## Persistence and secret boundary

State lives under `/var/lib/torkitten` with directory mode `0700`, secret files
mode `0600`, atomic replacement, fsync before rename, bounded sizes, and explicit
schema versions.

```text
/var/lib/torkitten/state.json             Torkitten model, no plaintext credentials
/var/lib/torkitten/tor/hidden-service/    Tor-owned persistent identity and public auth entries
/var/lib/torkitten/pki/                   Root and TLS keys/certificates
/var/lib/torkitten/authelia/users.yml     One username and password hash
/var/lib/torkitten/authelia/db.sqlite3    Authelia TOTP/WebAuthn/auth state
/var/lib/torkitten/authelia/secrets/      Session and storage-encryption keys
/var/lib/torkitten/caddy/last-good.json   Derived, non-authoritative route configuration
/run/torkitten/                           Unix sockets and bounded temporary enrollment material
```

Authelia owns the password hash, encrypted TOTP secret, future WebAuthn
credentials, login regulation, and sessions. Torkitten owns the Tor identity,
private CA, component bootstrap keys, device-public-key records, and hashes of
agent API tokens.

## Blocking protocol proofs

Before completing product code, automated and live tests against pinned
versions must prove these assumptions rather than infer them:

1. Current C Tor and Tor Browser route approved prefixes of one v3 onion
   identity to the same service while preserving the complete `Host` value.
2. Tor Browser accepts the private-CA certificates after installing the public
   root.
3. The pinned browser and Authelia accept one base-domain cookie across the
   approved onion prefixes.
4. The local HTTPS origin supports a separate Authelia session for the same
   owner.
5. The pinned Authelia CLI generates and persists TOTP plus a QR without a
   secret in process arguments or logs.
6. Rootless Podman pasta lets Caddy reach a host-loopback port created after the
   container started, without adding a published port or restarting anything.
7. Caddy forward authorization fails closed and its JSON `/load` retains the
   previous configuration on failure.

Failure of a proof blocks the dependent feature and requires an explicit
architecture decision. It must not be hidden by a browser workaround, insecure
bypass, or undocumented component behavior.

## Implementation milestones

1. **Foundation:** enforce the line budget, finish strict state schemas and
   atomic persistence, and retain the existing validation/Caddy/control tests.
2. **Runtime:** produce the single entrypoint and independently supervised
   pinned Caddy, Authelia, and C Tor processes with private control endpoints.
3. **Owner bootstrap:** implement the first-run state machine, one Authelia file
   user, direct TOTP generation, QR lifecycle, and real 2FA completion proof.
4. **Private onion and PKI:** persist one identity, require at least one Tor
   client key before publication, issue certificates, and verify prefixed hosts
   in real Tor Browser.
5. **Protected mappings:** implement full deterministic Caddy configuration,
   generic Authelia 2FA enforcement, live mapping hot loads, rollback, and
   host-loopback upstream tests.
6. **Onboarding:** add repeated device creation/revocation, public CA delivery,
   bounded port-80 bootstrap, and platform-neutral credential exports.
7. **Sensitive controls:** add publication stop/start, onion rotation, owner
   password/TOTP rotation, and scoped agent credentials.
8. **UI binding:** connect the compact server-rendered interface to the typed
   API with pending/success/failure states; keep all authoritative behavior in
   Go.
9. **Release verification:** exercise real HTTP, WebSockets, SSE, uploads,
   redirects, fail-closed auth, crashes, concurrent mutations, device
   revocation, identity rotation, and persistence across replacement/restart in
   rootless Podman and the supported Docker environment.

Each milestone is split into independently revertible commits. A milestone is
not complete until its unit tests, real-component integration tests, line-count
check, secret-redaction checks, and live browser/container evidence pass.
