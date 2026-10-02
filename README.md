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
Chisel server fingerprint are all required. There is no direct-network,
unencrypted, cookie-authenticated or alternate-transport path.

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
locked and require their file password. Local mappings are selected again.

Tor, Caddy, Authelia, Chisel, age and the QR reader are pristine vendored sources.
The [upstream refresh record](docs/upstream-refresh-v2.md) and
`third-party/*.upstream.toml` contain authoritative versions and tree hashes.
No generated identities, credentials, binaries or runtime state belong in Git.
The existing v1 runtime store is independent and is not migrated or modified.

## Host setup

1. Open **This host → Issue new identity**. Save the generated Authelia password
   and scan its TOTP enrollment QR. They are shown once.
2. Add services, their names and explicit TCP loopback addresses or Unix sockets.
   Enable **Available** for services to share. Mark SSH capability only here.
3. Choose **Share connection**, name the device, and choose a file password of
   at least 12 characters. Download the age-encrypted file or display the QR for the other device to scan.
4. Transfer the encrypted file or scan the desktop QR, and share its password
   through your chosen channel.
   Provide the Authelia login separately. Each device should receive a fresh export.

An export contains the onion address, that device's Tor authorization key,
public server CA, device certificate/private key and tunnel fingerprint. It
never contains the host's onion identity key or Caddy CA private keys. The host
retains only device public material. QR is the same encrypted content and is
available only when the bundle fits QR capacity.

**Issue new identity** replaces the onion identity, TLS trust, device access and
Authelia credentials together. Old connections close and new onboarding is
required. **Revoke sessions** closes live tunnels, revokes the current OAuth
client registration, clears Authelia's login sessions and requires fresh 2FA.
It preserves the onion address and existing device files.

## Client use

Under **Connections → Add connection**, use **Scan desktop QR with camera**
or select a saved QR image or encrypted file. The QR carries that same complete
encrypted bundle; no separate file is needed. Enter
its file password, then
complete Authelia password/TOTP login and explicit OAuth consent. The service
list updates while connected. Toggle **Route locally**, choose a port or leave
it on **Auto**, and use the displayed address with a normal client:

```sh
curl http://127.0.0.1:43127/v1/models
ssh -p 43128 user@127.0.0.1
```

Those example ports belong to different mapped services. Ordinary SSH still
uses the target SSH server's host-key verification and user authentication.
The tunnel's OAuth login does not replace the SSH account or distribute its
private login key. TLS on the outer tunnel does not change a local service's
HTTP/SSH protocol.

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
  "services": [
    {
      "id": "llama",
      "title": "Llama server",
      "available": true,
      "ssh": false,
      "endpoint": {"network": "tcp", "address": "127.0.0.1:5090"},
      "actions": {
        "load": ["/usr/bin/systemctl", "--user", "start", "my-llama.service"],
        "reload": ["/usr/bin/systemctl", "--user", "restart", "my-llama.service"],
        "stop": ["/usr/bin/systemctl", "--user", "stop", "my-llama.service"]
      }
    }
  ]
}
```

Use your existing service unit, Podman command or launcher script. These are
explicit lifecycle commands that hand off to an independent launcher, not
foreground model-server commands. Each control action waits up to 45 seconds
for its launcher command; this is not a lifetime limit on the independently
launched service. No shell is inserted, and no CPU, memory, swap, scheduling or
restart settings are invented. Omit actions you do not need. Endpoints are
explicit; the wrapper does not scan or guess ports. A Unix endpoint uses
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
