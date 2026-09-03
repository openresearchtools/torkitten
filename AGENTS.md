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
- Authelia owns passwords, second factors, sessions, and authorization
  decisions. Torkitten must not implement replacements for those mechanisms.
- Caddy asks Authelia to authorize every protected request and contacts a mapped
  application only after an explicit successful authorization response.
- Tor client authorization, private-CA HTTPS, and Authelia authentication are
  independent layers. Failure or uncertainty denies access.

## Address and routing model

One container has one persistent base address:

```text
<56-character-service-id>.onion
```

Applications use hostname prefixes on that identity:

```text
auth.<service-id>.onion       -> Authelia
api.<service-id>.onion        -> host loopback port 7777
chat.<service-id>.onion       -> host loopback port 8888
```

Tor exposes only virtual ports 80 and 443. Caddy terminates HTTPS and selects the
application using the exact `Host` value. Paths, queries, request bodies,
responses, redirects, WebSockets, SSE, and application cookies pass through
without application-specific rewriting.

One Authelia cookie scoped to the base onion domain provides one login across
all prefixes. Adding a prefix does not create an Authelia Application, user,
group, role, provider, or separate login.

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

First-run setup creates one owner in Authelia. That same username, password,
and TOTP protect both the local administration panel and onion access. The two
browser contexts have separate sessions only because `localhost` and `.onion`
are different origins; they are not separate accounts or separately managed
credentials. No guests, user groups, roles, or per-application grants are part
of this product.

Onboarding can be reopened for every new device. It provides the public onion
address, a Tor client-authorization credential, the public CA certificate, and
normal Authelia login instructions. It never reveals the onion service private
key, CA private key, internal component secrets, or an authenticated session.

## Storage

All state is ordinary files below `/var/lib/torkitten` in the normal container
writable layer. A standard bind mount or named volume is optional and preserves
state when the container is replaced. Stop/start and host reboot retain the
writable layer of the same container; removing the container without a volume
removes its state.

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
  passed the pinned Authelia and real Tor Browser tests.
- Keep commits independently revertible. Never commit generated identities,
  credentials, state, binaries, packages, caches, or build output.
