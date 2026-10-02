# TorKitten v2

A small native app for sharing selected localhost TCP or Unix stream services
through an authenticated Tor tunnel. The same app hosts services and connects
to additional TorKitten servers. Existing SSH, HTTP API and browser clients use
ordinary `127.0.0.1` ports on the client machine.

This branch replaces the v1 container UI. The Linux app uses GTK4/WebKitGTK;
its HTML/CSS/JavaScript and Go client core are shared with a thin Android shell.
The Android packaging and device proof are not complete; see
[native builds](docs/native-builds-v2.md).

## Connection path

```text
ordinary application -> client 127.0.0.1:chosen-or-auto-port
 -> independent Chisel WSS/SSH carrier -> local Tor SOCKS Unix socket
 -> authenticated onion:443 -> Caddy TLS + device mTLS
 -> Authelia OAuth bearer authorization -> private tunnel backend
 -> host-configured TCP loopback or Unix stream service
```

Every accepted native TCP connection gets its own carrier. Services do not all
share one multiplexed connection. Caddy forwards the outer WebSocket; it does
not parse or rewrite the inner application traffic. SSH, HTTP, uploads, SSE and
application WebSockets use the same byte-stream transport. Tor still determines
latency and throughput; a broken connection is reported, not replayed.

Only the protected gateway is mapped to an onion virtual port. Host services
and administration sockets are not additional onion listeners. Device Tor
client authorization, pinned private-CA TLS, device mTLS, Authelia OAuth and the
Chisel server fingerprint are all required. The intermachine tunnel has no
direct-network, unencrypted or alternate-transport path; cookies cannot authorize it.

## Build and launch

Builds, caches and test state default to
`/run/media/user/Data/TorkittenV2Build`, outside the checkout. Requirements are
rootless Podman, Bash and normal core utilities. Exact source trees and build
pins are checked before building.

```sh
./tools/build-app.sh
./tools/test-local.sh
./tools/run-local.sh --state /run/media/user/Data/TorkittenV2Build/app-state
```

The bundle is under `artifacts/app` in that build directory. Linux runtime
packages and an explicit direct launch command are documented in
[native builds](docs/native-builds-v2.md). Closing the window leaves the Linux
daemon running. Run it again to reopen the same private administration socket.
The daemon must be started again after a reboot; imported connections begin
locked and require their QR password. Local mappings are selected again.

Tor, Caddy, Authelia, Chisel, OpenSSH, age and the QR reader are pristine vendored sources.
The [upstream refresh record](docs/upstream-refresh-v2.md) and
`third-party/*.upstream.toml` contain authoritative versions and tree hashes.
No generated identities, credentials, binaries or runtime state belong in Git.
The existing v1 runtime store is independent and is not migrated or modified.

TorKitten's own code is Apache-2.0. Dependencies retain their respective
licenses. [Third-party notices](THIRD-PARTY-NOTICES.txt) accompany each bundle,
including frontend attributions, LGPL terms for system libraries, and the
corresponding source archives for MPL-2.0 modules. The bundle's `metadata/`
inventories identify exact dependency versions and notice/source checksums.

## Host setup

1. Open **This host → New identity** and choose a QR password (12–256 characters).
2. Save the generated single-owner Authelia username/password. Scan the
   authenticator QR, then enter a valid 2FA code **on this host** to enable remote
   access. Setup expires after ten minutes; unfinished setup stays closed.
3. Add a service name, one launch command and its explicit loopback address or
   Unix socket. Enable **Available** and save. Use Load/Reload/Stop to control it.
4. Optionally enable the separate **Allow SSH to this host** switch and save.
5. Display **Connection QR** for another device’s camera, or save its PNG image.
   The receiving device needs the QR password and Authelia login.

The password-encrypted QR contains the onion address, Tor client authorization
key, public server CA, device certificate/private key, tunnel fingerprint and
owner name. It never contains the host’s onion identity or CA private keys.
Import is exclusively by QR camera scan or QR image; there is no separate
connection-file import. The host keeps the encrypted QR for sharing again.

**New identity** immediately closes all remote connections. It replaces the
onion address, Tor/device keys, TLS/mTLS trust, Chisel identity, SSH credentials,
Authelia username/password/TOTP and OAuth registration/signing state. Service
settings remain. Every client must import the new QR and log in again after
local 2FA setup. **Revoke sessions** closes live tunnels and requires fresh 2FA
while preserving the current identity, QR and service settings.

## Client use

Under **Connections → Add connection**, scan the desktop QR with a camera or
select its saved PNG/JPEG image. Enter its QR password. The app automatically
opens the branded Authelia login, then OAuth consent. Selecting an existing
connection opens any required unlock/login step; Remove erases its local
profile and attempts server token revocation.

The service list updates while connected. Toggle **Route locally**, choose a
port or leave **Auto**, and use the displayed localhost address with an ordinary
client. For example, a mapped Llama HTTP service can be used with:

```sh
curl http://127.0.0.1:43127/v1/models
```

When host SSH is enabled, its separate row maps the bundled stock OpenSSH server.
The native client fetches per-identity SSH credentials through its authenticated
OAuth session and shows
an `ssh -F … torkitten` command. This uses the current host OS user and supports
native commands, terminals and SFTP. It does not install a system SSH daemon or
open a public host port. Private key/config files are mode `0600` and removed
when access closes.

All traffic between machines uses verified HTTPS/WSS with mTLS inside Tor.
Caddy forwards the encrypted carrier; native local payloads stay unchanged:
HTTP APIs remain HTTP on client localhost, SSH remains SSH. Host components
communicate over private Unix sockets, where some use HTTP without TLS.

Access and refresh tokens are stored only inside the password-encrypted local
profile. They are never supplied to service clients or browser JavaScript.
Authelia checks tokens when a carrier opens; token expiry does not interrupt an
already authorized long stream. Explicit revocation, SSH-boundary changes and
identity replacement close active carriers. Removing or disabling an ordinary
service closes that service without logging out the whole connection.

The app tunnels the chosen connection, not the entire machine. A web UI's
external URLs retain the browser's normal network behavior. Other local
processes can use ports you choose to map on `127.0.0.1`.

## One services file

The host UI and agents edit the same private `services.json`:

```json
{
  "version": 2,
  "ssh": false,
  "services": [
    {
      "id": "llama",
      "title": "Llama server",
      "available": true,
      "endpoint": {"network": "tcp", "address": "127.0.0.1:5090"},
      "command": "/opt/llama/bin/llama-server -m '/models/my model.gguf' --port 5090"
    }
  ]
}
```

Use your foreground service executable or launcher script. TorKitten asks the
host’s systemd user manager to own it in a separate transient service. Load
starts it; Stop stops the owned unit; Reload stops and starts it. Unchanged
units survive wrapper restarts. Removing or changing a launch configuration
stops the previous owned unit. This process separation does not guarantee
survival of machine-wide OOM or an ancestor-cgroup kill.

The command supports quoted literal arguments with an absolute executable;
there is no shell expansion. No CPU, memory, swap, scheduling or restart policy
is added. Configure such choices in your command/preset. Endpoints are explicit;
the app does not scan or guess ports. A Unix endpoint uses
`{"network":"unix","address":"/absolute/path/service.sock"}`.

The file must remain mode `0600`. Valid edits are loaded automatically; an
invalid desired configuration closes remote access until corrected. Remote
controls can request only an existing service ID and Load/Reload/Stop, never
commands, addresses or host setup. Unix descriptor passing and datagrams, UDP,
SOCKS endpoints, reverse forwarding and arbitrary destinations are rejected.

## Verification and design

See [v2 design](docs/v2-plan.md) for the protocol boundaries and reproducible
proof commands, and [native builds](docs/native-builds-v2.md) for platform scope.
Production Go, including the mobile adapter, stays below 5,000 physical lines;
`tools/check.sh` enforces the limit, formatting, vet and tests; build scripts verify vendor integrity.
Historical v1 investigation documents describe that older product and are not
v2 compatibility claims.
