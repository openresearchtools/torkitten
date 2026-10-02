# TorKitten v2 design and verification

The `torkitten-v2` branch implements a Linux native app with host and client
modes, encrypted onboarding, a portable bundled web UI, OAuth authorization and
transparent native localhost mappings. Android reuses the client core and UI;
its package/device validation is still outstanding. Build and runtime details
are in [native builds](native-builds-v2.md); usage is in the [README](../README.md).

## Small ownership boundaries

| Responsibility | Implementation |
| --- | --- |
| Onion identity, client authorization, Tor routing | Pinned C Tor |
| Private-CA HTTPS, device mTLS, routes, forward authorization | Pinned Caddy |
| Account, password, TOTP, OAuth validity, refresh and revocation | Pinned Authelia |
| SSH-encrypted WebSocket carrier | Pristine Chisel wire components and Go SSH |
| File encryption | Pristine age scrypt recipient |
| QR reading/writing | Pristine gozxing and barcode |
| Service lifecycle and launch options | User launch command; upstream systemd user units |
| Local model, configuration, component coordination, UI bridge | Small Go/GTK wrapper |

Replaced v1 runtime packages are removed. There is no second transport, custom
password verifier, OAuth broker, replacement token store on the server, or
resource-policy manager. The complete production Go implementation, including
mobile, must stay below 5,000 physical lines. Tests and pristine dependencies
are excluded; moving product logic to JavaScript to evade the limit is forbidden.

## Transport

```text
service client -> held 127.0.0.1 listener -> one carrier per native connection
 -> Chisel SSH inside WSS -> Tor SOCKS Unix socket -> onion:443
 -> Caddy TLS/mTLS + Authelia bearer authorization
 -> private tunnel socket -> fixed TCP loopback or Unix stream endpoint
```

Stock Chisel cannot directly dial a raw Unix destination, return a held Auto
listener to the app, or reject every UDP request through its destination ACL.
The small adapter uses its pristine WebSocket connection, wire configuration,
fingerprint and copy components plus Go SSH. It adds exact service-ID
selection, Unix dialing, held local listeners and explicit protocol rejection.
It does not patch vendor sources or invent a new wire protocol. A stock-Chisel
interoperability test gates this boundary.

Each accepted native TCP connection gets a separate WSS/SSH carrier. It is not
a fixed pool of four shared connections. Parallel native connections therefore
do not share Chisel's ordered TCP carrier, though Tor circuits and network
capacity still affect all traffic. No automatic replay or stream resumption is
promised after a transport failure. Tor uses an explicit empty defaults file;
metrics are unconfigured because `MetricsPort 0` opens an ephemeral listener. HTTP/SSE/WebSocket/SSH payloads remain opaque.

Only configured stream targets can be selected. The wire target is a service ID,
not a caller-supplied address. UDP, SOCKS, reverse forwarding and multiple or
arbitrary destination channels are rejected. Removal, endpoint replacement and
revocation close active carriers, including handshakes. Authorization begun
before revocation cannot establish a carrier afterward.

## OAuth and credentials

Authelia's public client uses pushed authorization requests, authorization code,
PKCE S256, explicit consent, `form_post`, refresh tokens and the scopes
`authelia.bearer.authz offline_access`. The bearer resource is the gateway URL.
The device grant is not used because Authelia does not permit the required
bearer authorization scope with that grant.

The native form delegates password and TOTP verification to Authelia's supported
factor endpoints through strict Tor/TLS/mTLS. Its short-lived cookie jar exists
only during login/consent. It never authorizes a tunnel. The bounded OAuth form
response is parsed, never executed, with exact callback, state and issuer checks.
No HTTP callback listener or insecure WebKit certificate exception is needed.

Caddy's protected routes use Authelia's Bearer-only authorization strategy. The
private control/tunnel backend independently checks authorization. Tokens stay
inside the native client and its age-encrypted profile, never in application
payloads, JavaScript, URLs or command arguments. Each newly accepted native
connection obtains a current token; refresh is serialized per profile.

Manual revocation rotates the public OAuth client ID, removes the previous
registration and restarts this host's dedicated Authelia instance. The SQLite
store remains intact. This denies old access/refresh tokens and clears login
cookies, while preserving Tor/device identity. The app also closes live carriers.
The mTLS-protected `/api/info` returns only the current client ID/version so a
client can perform a fresh 2FA login. Ordinary catalogue changes do not rotate
OAuth registration; changes to SSH service boundaries do.

## Host and UI boundary

GTK loads only bundled HTML/CSS/JS at `torkitten://app`. A fixed Unix-socket
bridge supplies exact Host/Origin values; external pages cannot obtain it.
Host setup has no onion route. The remote API exposes only version/client-ID
metadata, the authorized catalogue, fixed lifecycle actions, session-authorized host SSH credentials and tunnel upgrades.

There is one agent-editable `services.json` containing names, availability,
one host SSH switch, explicit stream endpoints and one direct launch command
per service. Local UI and file edits use the same validation. The app never
chooses resource limits or expands shell expressions. Systemd owns independent
service units; Stop stops the unit and Reload stops then starts it.

Live QR scanning uses the native camera permission and portable video/canvas
UI. Frames go only to the local Go QR decoder through the private bridge; they
are never sent to Tor or the remote server. Scanning returns only a found flag; the local UI submits the same captured
image with the password for import. Capture stops when the scan closes or the app is
hidden. Android camera permission/build behavior still needs device validation.

An encrypted device export contains device credentials and public server trust,
never server identity or CA private keys. Imported profiles are locked after
restart. Identity replacement immediately closes and removes the previous generation,
retains service settings and requires host-local password/TOTP setup before
remote publication and new QR onboarding. Successful confirmation starts the
server Tor process afresh with publication enabled; it preserves that identity’s
keys and directory cache. This avoids carrying an unpublished descriptor’s
later upload timer across a config reload. A single owner is generated; there
is no additional account management UI. An incomplete replacement stays closed; it never
restores an old identity as a fallback. Missing prerequisites and component
failure deny remote access. There is no alternate network or authentication path.

## Verification

`tools/test-local.sh` uses a pinned rootless Podman builder and external caches.
It checks formatting, vet, security/concurrency unit tests, source integrity and
size. Transport tests exercise binary TCP/Unix, HTTP uploads, SSE, application
WebSockets, a nested native SSH session, half-close, independent carriers,
strict TLS/mTLS/fingerprint/Bearer, held Auto ports and protocol denials.

The opt-in OAuth proof runs actual Caddy and Authelia, including password/TOTP,
PAR, PKCE, consent, refresh rotation, revocation and client-registration changes:

```sh
python3 tools/proof-oauth.py --help
```

The full-app proof starts separate app instances and uses only their private
Unix UI API for identity, enrollment, login, mapping and control. It requires
source-built upstream binaries, host `ssh`, `ssh-keygen`, `openssl` and a working systemd user manager, and live
Tor connectivity. Run with fresh external paths and the pinned build environment:

```sh
TORKITTEN_APP_PROOF=/run/media/user/Data/TorkittenV2Build/proofs/app-new \
TORKITTEN_APP_BIN=/run/media/user/Data/TorkittenV2Build/artifacts/app/bin \
  go test -count=1 -timeout 35m -run TestLiveApp ./internal/app
```

It covers QR image import, wrong-password rejection, actual Tor,
missing-device-certificate and Bearer denial, explicit OAuth login/consent,
concurrent TCP/Unix/native SSH, lifecycle actions, service removal, global/SSH
revocation, new 2FA, identity replacement and actual packaged host/client daemon restarts
with persisted identity and encrypted profiles. It erases generated proof identity
state on exit and retains sanitized results plus private component logs.

Native bridge, bundled UI and Android build scope are recorded in
[native builds](native-builds-v2.md). Linux evidence must not be described as an
Android or iOS compatibility result. Historical Tor benchmark samples measure
their stated circuits/workloads and do not establish a bandwidth guarantee.
