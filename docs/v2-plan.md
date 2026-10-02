# TorKitten v2 implementation plan

Status: branch foundation and upstream refresh; the native v2 application is
not implemented yet. Repository: `openresearchtools/torkitten`, branch
`torkitten-v2`, checkout `/run/media/user/Data/Repositories/torkitten`.

## Product

One native Linux application can act as a server, a client, or both. Its small
GTK/WebKit interface has host setup, a live service list, and saved connections
to additional TorKitten servers. It does not add a general proxy/VPN product,
standalone cloud-provider connections, or a resource-management dashboard.

The server shares owner-selected TCP or Unix **stream** endpoints. The client
maps them onto `127.0.0.1` ports so existing SSH, API and browser clients use
their ordinary protocols. SSH, HTTP, SSE, application WebSockets, uploads and
downloads remain opaque payloads inside the authenticated tunnel. No OAuth
headers, cookie rewriting or application-specific transformations are inserted
into those payloads. Unix FD passing, peer credentials, datagrams and UDP are
not representable by this byte-stream contract and are rejected.

The UI shows the service list and status dynamically while connected. There is
no separate service-configuration import after login. File/QR import is only
the initial connection setup. Mapping controls show the actual local port and
allow a chosen port or an automatically allocated one, held by its listener.

Keep the two views plain and limited to these controls:

- **Client:** saved TorKitten connection, Authelia login, live service rows with
  a local-mapping checkbox, chosen port or Auto, assigned port, and
  Load / Reload / Stop buttons.
- **Host admin:** encrypted configuration download or QR, Issue new identity,
  Revoke sessions, and service rows with name, launch command, TCP address:port
  or Unix socket, Available checkbox, and the same lifecycle buttons. SSH can
  be enabled only here. This view is accessible only over the private admin
  socket, never through an onion route.

One versioned `services.json` file holds all service entries; the admin UI and
agents edit that same model. Do not add dashboards or resource settings. An
endpoint may be derived from an explicit supported command flag only when it
is unambiguous. Otherwise require its port/socket field; do not scan, guess, or
silently substitute a destination.

## Keep the implementation small

| Responsibility | Owner |
| --- | --- |
| Onion identity, client authorization, Tor routing | C Tor |
| Private-CA HTTPS, mTLS, exact routes, forward authorization | Caddy |
| Account, password, 2FA, browser session validity | Authelia |
| Byte-stream forwarding | Pinned GOST fixed forwarding, pending remaining protocol proofs |
| Process lifecycle and launch options | User's presets and their upstream launcher |
| File encryption | Established age implementation |
| Host keys and SSH authentication | OpenSSH |
| Local UI, preset storage, config rendering, component coordination | Small Go/GTK wrapper |

Do not implement a transport protocol, OAuth broker, replacement session store,
certificate framework, workflow engine, or service supervisor. Keep the
existing 5,000-line first-party Go ceiling. Native bindings must also remain
thin. Remove obsolete v1 code as v2 replaces it; do not use language changes or
generated code to evade the size constraint.

Tor, Caddy and Authelia remain pristine source snapshots with exact release,
tag, commit and tree records. Additional selected upstreams follow the same
policy. Use stable releases, exact build pins and licenses, not moving branches.
GOST supplies stock fixed forwarding over WebSocket with an explicitly
configured Tor hop. The source-built binary passes the bounded TCP/Unix,
TLS-verification and failed-proxy checks in `gost-proof-v2.md`. This does not
prove the complete Tor/Caddy/Authelia/native-client chain. The remaining proofs
below still gate deployment. If one fails, stop and resolve the design; do not
install a second transport or quietly introduce a custom broker.

This is a feature-fit choice, not a claim that GOST is more secure than Chisel.
Chisel supports HTTPS/WebSocket tunnels through a SOCKS proxy and can carry
native SSH. Its current target implementation forwards TCP/UDP, so raw Unix
stream targets would require another adapter. GOST directly supports both required
endpoint types. Chisel is an independent upstream with a Fedora-maintained
package; Fedora packaging does not mean Fedora develops the tunnel protocol.

## Connections and private controls

```text
ordinary client -> client 127.0.0.1 port -> native tunnel connector
  -> local Tor proxy -> onion service :443 -> Caddy HTTPS + device mTLS
  -> Authelia authorization at tunnel establishment -> fixed upstream tunnel
  -> configured server TCP or Unix stream endpoint

host setup UI / host CLI -> private Unix admin socket -> preset/config editing
authenticated client UI -> Caddy + Authelia -> service list and allowed actions
```

Caddy can already proxy HTTP and HTTP WebSockets to a Unix socket. A Unix socket
is an endpoint type, not a protocol: that capability does not turn arbitrary
SSH or other raw-stream traffic into WebSocket frames. GOST supplies that
conversion for the uniform native-port tunnel. Caddy forwards its WebSocket
envelope; it does not convert each inner service protocol. The native client
creates local listeners; a second client
Caddy is unnecessary. Only the authenticated gateway is onion-published.
Component administration and host setup sockets have no remote route or service
mapping. Remote lifecycle calls contain only an existing service ID and an
allowed action, never a shell string, destination, path or replacement config.

Use a separate login web context, first-party control UI context, and service
view context. Arbitrary service pages have no native credential or host-control
bridge. Host setup over Unix sockets can use a narrowly typed native bridge;
WebKit is not assumed to support `http+unix` URLs directly.

The tunnel connector has one explicit Tor route. Missing Tor, failed proxy
negotiation, failed TLS verification, missing/expired authentication, unknown
service IDs and invalid configuration fail closed. No direct connection,
alternative proxy, plaintext route or automatic transport substitution exists.
Reconnect may establish a new authenticated connection on the same approved
path; it never replays service commands or resumes a broken byte stream.

## Host-owned launch presets

A preset contains an ID, display name, availability, endpoint, and explicit
lifecycle command argument arrays. Agents can author entries in the single
versioned `services.json` file. The command box edits the launch command; it
does not expose component configuration or remote arbitrary execution. A preset may call
an existing systemd unit, Podman command, or user's launch script. The wrapper
does not translate or override llama.cpp flags, CPU affinity, memory settings,
GPU selection, container configuration or scheduling choices.

Example shape, with a user-provided `llama.service`:

```json
{
  "version": 1,
  "services": [{
    "id": "llama",
    "title": "Llama server",
    "available": true,
    "endpoint": {"network": "tcp", "address": "127.0.0.1:8080"},
    "actions": {
      "load": ["/usr/bin/systemctl", "--user", "start", "llama.service"],
      "reload": ["/usr/bin/systemctl", "--user", "restart", "llama.service"],
      "stop": ["/usr/bin/systemctl", "--user", "stop", "llama.service"]
    }
  }]
}
```

Unix endpoints use `{"network":"unix","address":"/absolute/service.sock"}`.
Launch argument arrays can invoke the user's existing launcher/config directly.
The launcher owns the service independently of the GTK window. Presets provide
the actions their launch mechanism actually supports. Here the owner explicitly
defines Reload to restart the unit; an omitted action is unavailable and never
silently replaced. Commands run without
an implicit shell, with bounded/redacted output and explicit exit status.

Only host setup can add/edit/delete presets and set SSH availability. Remote
users can load, reload or stop already approved presets. Their view
does not expose the host command editor or secrets. Endpoint/command correctness
and independent lifecycle are tested against the chosen preset, not guessed
by the wrapper.

## Initial connection and login

1. Host setup creates a device connection bundle: schema version, onion
   address, that device's Tor **client authorization** credential, public Caddy
   trust anchor, and unique device mTLS credential. The Tor service identity
   private key and all CA/server private keys stay on the server.
2. Encrypt the bundle with the established age passphrase format using the
   owner's chosen file password. Import asks for that password. A QR carries
   the same encrypted bootstrap data, subject to an explicit payload limit;
   oversized payloads are rejected for QR export and remain file-exportable.
   Neither QR nor file carries a plaintext password or authenticated session.
3. The native client installs trust and credentials only inside that connection
   profile, then reaches the login portal through Tor with verified HTTPS.
   Invalid password, bundle, certificate, address or unsupported format fails;
   no compatibility guessing or TLS exception is allowed.
4. Authelia performs login and 2FA. Its HttpOnly cookie stays in the isolated
   login context. Native code can obtain the cookie via the supported native
   cookie API for authenticated gateway requests; page JavaScript, logs and
   process arguments never receive it.
5. The client UI displays live services and permitted actions. Native tunnel
   connections carry the Authelia session credential only to the trusted
   gateway. Service applications never receive it. Each saved TorKitten server
   has separate trust, cookies, device credentials and mappings.

Authelia supports OIDC, but an OAuth token does not inherently include service
configuration or track TorKitten's configuration changes. The minimal design
uses Authelia's existing session token (the cookie); no OIDC broker or token
distribution layer is needed for native localhost services.

Use supported upstream certificate tools for device provisioning and Caddy's
stock mTLS leaf verifier/allowlist; do not write an online device CA service.
The source-built Caddy passes 32 local device-admission/reconnection checks with
OpenSSL-generated self-signed client leaves, `require_and_verify`, an explicit
trust pool, and the exact-leaf allowlist. It disables session tickets with mTLS.
See `caddy-mtls-proof-v2.md`; GTK/GOST integration and profile trust packaging
remain unproved.

**Issue new identity** is a complete host-authorized replacement: close remote
access and active tunnels, let Tor create a new onion identity, replace Caddy
TLS trust and device mTLS credentials, and initialize replacement Authelia
credentials and 2FA enrollment through its supported interfaces. Export only
the new encrypted connection bundle. Old profiles and sessions stop working;
clients must import the replacement and log in again. This is distinct from
ordinary session revocation. A failed replacement remains closed; it does not
silently reactivate the old identity. Private server keys never enter the file
or QR.

## SSH boundary and revocation

The host explicitly enables a configured SSH endpoint. The client's native SSH
tools then use its mapped localhost port and the expected SSH host identity.
SSH credentials are per device. Prefer generating the private client key with
OpenSSH on that client and provisioning only its public key through the
host-authorized setup. No server SSH host private key is distributed. The
selected host SSH configuration owns the account, permissions and key paths;
TorKitten does not create an account-management subsystem.

Enabling SSH grants the rights of that configured account/container. If it is
the same host UID that owns the admin socket, it can reach that socket locally;
the host preset must choose the intended account/container boundary.

Routine service-list, name and status changes update the UI without logout.
Removing/disabling a service closes its active streams on the server, including
connections held by an uncooperative client. SSH boundary changes
and the explicit **Revoke sessions** action require fresh Authelia 2FA:

1. Stop remote acceptance and close the active tunnel connections. Close client
   mappings on disconnect; cached service lists do not authorize access.
2. Restart the dedicated Authelia memory-session instance, destroying its
   sessions through its supported lifecycle. Apply changed SSH/device policy.
3. Start the verified gateway configuration. Existing cookies cannot authorize
   new connections; users must log in again. If any step fails, remote access
   stays disabled. Never restore a weaker or guessed configuration.

Stopping the tunnel endpoint, rather than merely changing a cookie, terminates
active SSH/SSE/WebSocket access. A global revoke can restart the dedicated
tunnel/Caddy processes to avoid custom per-connection session machinery. TLS
resumption must not preserve revoked device access. All affected component
state, including Authelia session loss on restart, is explicit in the UI.

Ordinary cookie expiry is checked by Authelia for new requests/upgrades; an
already-open tunnel is not magically reauthorized per inner packet. The
explicit revoke operation closes it. Do not claim otherwise.

## Proofs before application implementation

Current transport evidence includes real SSH command execution and SFTP, but
GOST's pinned copy helper imposes a ten-second read deadline after one direction
reaches EOF. The immediate-response half-close test passes; indefinite
half-close transparency is not established. Arbitrary-service support remains
blocked on resolving that limitation. Do not hide it with retries, patch the
pristine snapshot, or claim all byte-stream semantics are preserved.

1. **Upstreams:** verify pristine latest stable snapshots, signatures/provenance,
   pinned builds, and existing regression checks. See `upstream-refresh-v2.md`.
2. **One transport:** prove fixed TCP and Unix forwarding, binary transparency,
   SSH/SFTP, SSE, nested WebSockets, concurrent connections and half-close.
   Break the Tor proxy and credentials and verify there is no direct dial or
   client DNS bypass. No upstream target is contacted before authorization.
3. **GTK login:** prove actual WebKit network-process private-CA trust, mTLS,
   onion cookies, native cookie access, redirects and logout. Package a private
   trust environment if supported. There is no verified public WebKit6
   per-session CA-database setter; global TLS-ignore and per-certificate error
   exceptions are not acceptable substitutes. Failure leaves the feature
   unsupported, not downgraded.
4. **Presets and controls:** prove a real user-supplied llama/ComfyUI/SSH preset
   launches independently, reports status, and supports only declared actions.
   Prove remote routes cannot edit presets or reach component/admin sockets.
5. **Revocation:** while SSH and streaming connections are active, revoke
   sessions or disable SSH. Connections terminate and old cookies cannot
   reconnect. Still-approved devices may perform fresh 2FA; separately revoked
   device credentials must fail, including through TLS session resumption.
6. **Client UX:** encrypted file and bounded QR import, multiple isolated
   connections, live service list, explicit/automatic local ports, and exact
   error states. Exported bundles and persistent client secret stores are
   encrypted. Upstream-required runtime credential files are private with
   restrictive permissions. No secrets enter UI bridges, process arguments
   or logs.

Implement these in that order as small independently reviewable changes.
Do not claim a secure native release until the real pinned components pass the
proofs; unit tests alone do not establish browser or Tor compatibility.

## Source references

- [Tor client authorization](https://community.torproject.org/onion-services/advanced/client-auth/)
- [Caddy TLS and client certificate verifiers](https://caddyserver.com/docs/caddyfile/directives/tls)
- [Authelia proxy authorization](https://www.authelia.com/reference/guides/proxy-authorization/)
- [Authelia session storage](https://www.authelia.com/overview/authorization/statelessness/)
- [GOST fixed server forwarding](https://gost.run/en/tutorials/port-forwarding/#server-side-forwarding)
- [GOST Unix transport](https://gost.run/en/tutorials/unix/)
- [Chisel transport and packaging](https://github.com/jpillora/chisel)
- [Chisel target dialing](https://github.com/jpillora/chisel/blob/master/share/tunnel/tunnel_out_ssh.go)
- [age implementation](https://github.com/FiloSottile/age)
- [WebKit NetworkSession API](https://github.com/WebKit/WebKit/blob/main/Source/WebKit/UIProcess/API/glib/WebKitNetworkSession.h.in)
