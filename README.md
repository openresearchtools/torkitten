# Torkitten

Torkitten publishes deliberately selected applications from the immediate host
loopback through one persistent v3 onion identity. It runs as one rootless OCI
container containing a small Go control plane, C Tor, Caddy, and Authelia.

Each application gets a hostname prefix on the same identity:

```text
<service-id>.onion        protected application launcher
<service-id>.onion/login  Authelia portal
api.<service-id>.onion    a mapped host-loopback application
```

Tor provides onion identity and client authorization, Caddy provides private-CA
HTTPS and reverse proxying, and Authelia provides the sole owner account, TOTP,
onion sessions, and two-factor authorization. The administration console is
available only at `http://localhost:12755`.

> **Development preview / client blocker:** the pinned-component and local
> container paths are tested, but no remote browser is currently advertised as
> supported. Tor Browser 15.0.21 rejects the private CA with its default
> `security.nocertdb=true` policy. A technical test succeeded only after applying
> Tor Project's development-only root-CA procedure, which explicitly reduces or
> disables privacy protections. Torkitten does not ask users to weaken Tor
> Browser this way. The mobile browser/Orbot matrix remains untested.

## Security model

Mapped host applications are trusted. Remote clients are untrusted. Every
protected request must pass Tor client authorization, Caddy-managed TLS, and
Authelia forward authorization before Caddy contacts an application. Unknown
hosts fail closed.

The browser and agents never receive component administration access, arbitrary
proxy configuration, filesystem paths, or shell execution. Mapping input is
limited to a lowercase hostname prefix, a numeric port, and `http`, `https`, or
`h2c`. The destination is always the immediate host loopback.

Local administration uses a separate host-only session because Authelia does not
protect HTTP `localhost`. Torkitten sends factors to Authelia over a private Unix
socket; it does not verify or store another password hash or TOTP secret.

Host-local malware and users able to defeat the host loopback boundary are
outside this security boundary.

## Build

Requirements:

- rootless Podman with pasta networking;
- Bash and normal core utilities; and
- an external build directory with enough space for three upstream builds.

The default external directory is `/run/media/user/Data/TorkittenBuild`. Choose
another location with `TORKITTEN_BUILD_ROOT`; it must not be inside this
repository.

```sh
export TORKITTEN_BUILD_ROOT=/absolute/path/to/TorkittenBuild
./tools/build-local.sh all
./tools/build-runtime.sh
```

The scripts verify the pristine pinned source trees, build Tor, Caddy, and
Authelia independently, run the Go checks, and produce
`localhost/torkitten:dev`. Current pins are Tor 0.4.9.11, Caddy 2.11.4, Authelia
4.39.20, Ubuntu 24.04 build/runtime bases, and Go 1.26.3. Manifests under
`third-party/*.upstream.toml` are authoritative.

Artifacts and Podman storage remain outside the repository. Do not copy build
outputs, credentials, or runtime state into Git.

## Run and set up

```sh
./tools/run-local.sh
```

Open <http://localhost:12755>. The responsive console has four views: Dashboard,
Applications, Remote Devices, and Runtime. On first run:

1. enter one owner username and password;
2. scan the TOTP QR code and submit a current code;
3. add an authorized device and import the one-time Tor client credential;
4. acknowledge the credential only after import; and
5. start publication.

The only host-published socket is `127.0.0.1:12755`. Onion HTTP/HTTPS listeners,
Tor control, Caddy administration, and Authelia remain private Unix sockets.
Rootless pasta lets Caddy reach host-loopback ports created after the container
starts; adding a mapping does not publish another container port or restart it.
Stopping publication disables Tor networking immediately and remains disabled
across restarts until the owner starts publication again.

Use the repository wrapper for lifecycle and inspection commands because the
development scripts keep Podman storage under the external build directory:

```sh
./tools/container.sh logs -f torkitten
./tools/container.sh stop torkitten
./tools/container.sh start torkitten
```

`tools/run-local.sh` refuses to replace an existing named container. This is
intentional.

## Mappings and onboarding

A mapping such as `api` + `7777` + `http` publishes the host service listening
on `127.0.0.1:7777` as `api.<service-id>.onion`. Caddy preserves methods, paths,
queries, request bodies, responses, redirects, WebSockets, SSE, downloads,
uploads, and application cookies without application-specific rewriting.

Every device gets an independent Tor client-authorization credential. Its
private half is offered as text, an `.auth_private` download, and an
Orbot-compatible iOS/macOS QR code only during the bounded enrollment window;
Android and desktop Tor import the file. It is erased after acknowledgement. A lost credential cannot be recovered; revoke it and
create another. Publication cannot remain enabled with zero acknowledged
devices.

Remote HTTPS uses Caddy's persistent private CA. Caddy manages one 397-day
base-host leaf and one 397-day wildcard leaf shared by every application prefix,
so adding a mapping does not create another prefix-specific certificate. Caddy
renews them through its native internal issuer. After authentication, the base
onion launcher lists every enabled application and explains the initial private-
certificate warning. Installing the CA is optional: the launcher offers the
public PEM certificate and generates an Apple `.mobileconfig` containing only
that public root. It never exports a private key. Apple still requires deliberate
profile installation and trust approval. Permanent links and applications use
HTTPS; onion HTTP has no application, login, or certificate route.

Users must deliberately import the Tor credential and, if desired, the public
CA. Devices whose normal policy forbids private CA installation may have to use
a permitted manual warning exception; clients which permit neither are
unsupported.
In particular, current Tor Browser disables its local certificate database by
default. Tor Project documents a root-CA workaround as development-only and
warns that it reduces or disables privacy protections; Torkitten therefore does
not support or recommend that workaround:
<https://onionservices.torproject.org/apps/web/onionspray/guides/root-ca/>.

The local console can transactionally rotate the onion identity after pending
device enrollment is closed. Rotation stages a new
Tor-owned identity, new key for every acknowledged device, Caddy certificates,
and the new Authelia cookie domain before committing. It revokes all local and
onion sessions and returns replacement client credentials once; save and import
every credential before leaving the result page.

Owner password and TOTP replacement also run only from the authenticated local
console. Authelia verifies the current password and TOTP, performs the native
password or staged TOTP update, and remains the sole credential store. A
successful change revokes all localhost sessions and restarts Authelia to clear
its memory-backed onion sessions. The prior TOTP remains active until a code
from the replacement enrollment is accepted.

## Local mapping API

The Applications view can enable one-time CLI and agent access with mapping
read/write scope. It exposes only copy-token and copy-agent-prompt actions.
Tokens are shown once, rate limited, revocable, and persisted only as hashes.
For example:

```sh
curl -H "Authorization: Bearer $TORKITTEN_TOKEN" \
  http://localhost:12755/api/mappings
curl -H "Authorization: Bearer $TORKITTEN_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"prefix":"api","port":7777,"protocol":"http"}' \
  http://localhost:12755/api/mappings/create
```

The API is still reachable only through the host-loopback publication. Default
agent authority cannot rotate identity, issue devices, retrieve the CA,
administer sessions, change the owner, or control processes.

## State and deletion warning

All durable state lives in `/var/lib/torkitten` in the existing container's
ordinary writable layer. It includes the Tor identity, Caddy CA, Authelia owner
and factors, mappings, acknowledged devices, and hashed local/API sessions.
Stopping and starting the same container, including across a host reboot,
retains this state.

**Removing the container permanently removes its Torkitten identity and state.**
There is no named volume, bind mount, host keyring, or automatic migration in
this preview. Do not run `podman rm`, `tools/container.sh rm`, or recreate the
container unless erasure is intended.

Authelia intentionally uses its memory session provider. Routine remote idle
and absolute expiry are set to ten years, effectively disabling Torkitten's
short session timeout; a browser may still impose its own cookie lifetime.
Restarting Authelia or the container preserves credentials but destroys onion
sessions, so remote clients must authenticate again. Torkitten localhost
sessions persist until expiry or revocation.

## Owner lockout recovery

Recovery belongs to the rootless user who owns the stopped container. It is not
an unauthenticated browser route. Stop the container, stage a reset, restart it,
and repeat first-run owner/TOTP enrollment:

```sh
./tools/container.sh stop torkitten
./tools/owner-reset.sh
./tools/container.sh start torkitten
```

The reset disables publication and revokes localhost sessions and agent tokens.
It retains the onion identity, Caddy CA, mappings, and device records. Do not
interrupt it or run it against a running container.

## Verification

Run formatting, vet, race tests, schema checks, and Go line budgets with:

```sh
./tools/test-local.sh
```

Verify the pristine pinned upstream trees separately with:

```sh
./tools/verify-vendor.sh
```

Pinned integration tests are opt-in and require the corresponding external
binary paths. The build scripts place those binaries under
`$TORKITTEN_BUILD_ROOT/artifacts/third-party/`.

Torkitten is licensed under Apache-2.0. Runtime images include the Torkitten,
Go, barcode, Tor, Caddy, and Authelia license texts under
`/usr/share/doc/torkitten`.

The project does not claim supported-client compatibility. Live Tor Browser
15.0.21 testing proved client authorization, private-CA TLS, Authelia TOTP, the
cross-prefix cookie, and a mapped request only in Tor Project's explicitly
privacy-reduced development configuration; the default browser correctly
rejected the private CA. Mobile browsers through Orbot remain untested.
Container success, direct Unix-socket tests, BrowserOS, and a modified Tor
Browser are not substitutes for a supported-client matrix.
