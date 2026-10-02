# TorKitten v2 agent contract

This branch implements the native TorKitten v2 app. The user's instructions in
this session supersede earlier v1 container/browser constraints. Read the
[README](README.md), [design](docs/v2-plan.md) and
[platform scope](docs/native-builds-v2.md) before changing a boundary.

## Product and scope

- One small native app has host and client modes and independent connection
  profiles for additional TorKitten servers. GTK embeds portable HTML/CSS/JS;
  Android reuses the client core and assets. Claim only tested platform support.
- Keep the UI to the requested controls: client mapping checkbox, chosen/Auto
  port and assigned port, Load/Reload/Stop; host name, lifecycle command,
  endpoint, availability, SSH capability, the same actions, encrypted file/QR,
  Issue new identity and Revoke sessions. No additional dashboards.
- One agent-editable `services.json` is the host model. Lifecycle commands are
  explicit argument arrays for the user's independent launcher. Preserve them;
  do not add CPU, memory, swap, task-limit, container, scheduling or restart
  policy. Do not insert a shell or guess a command, stop action or endpoint.
- Map configured TCP loopback and Unix stream endpoints onto client loopback
  ports without altering payloads. Ordinary SSH retains its native host-key
  and account authentication. Do not pretend OAuth replaces that authentication.
- Remote requests can select an existing service and allowed action. They
  cannot supply destination addresses, launch commands, host configuration,
  or SSH capability. Host setup exists only on the private Unix UI API.

## Security boundaries

- Tor owns onion identity and client authorization; Caddy owns private-CA TLS,
  mTLS and forward authorization; Authelia alone owns password, TOTP, OAuth and
  authorization decisions. No password verifier, OAuth broker, replacement
  server token store, Caddy auth module or custom transport protocol.
- Use pristine Chisel wire components with a thin TCP/Unix endpoint adapter.
  Each accepted native TCP connection gets its own WSS/SSH carrier. Enforce
  exact server-selected destinations. Reject UDP, SOCKS, reverse, arbitrary
  destinations and extra channels. Verify the server fingerprint.
- Caddy requires device mTLS and Authelia Bearer-only authorization for protected
  routes. The private backend independently checks bearer authorization.
  Native login uses supported Authelia factor endpoints, PAR, PKCE S256,
  authorization code, explicit consent and refresh. Its temporary login cookie
  never authorizes a tunnel. No tokens reach JavaScript or service payloads.
- Ordinary list/status changes do not log out users. Removal or availability
  changes close affected service streams. Reachability is display information,
  never permission to close an otherwise authorized active stream.
- SSH-boundary changes and explicit revocation close active carriers and require
  fresh 2FA. Authorization started before revocation cannot open a carrier or
  dispatch a lifecycle action afterward. Preserve these concurrency checks.
- Issue new identity replaces Tor identity, TLS/mTLS and Authelia credentials
  together. Old access closes and new onboarding is required. Never restore
  an old identity as a recovery fallback.
- Export age-password-encrypted device credentials and public server trust,
  never server onion identity or CA private keys. Persist client tokens only
  inside encrypted profiles. Imported profiles start locked after restart.
- GTK loads only the bundled trusted origin through a fixed private Unix bridge.
  External content never receives the bridge or native credentials. Host setup,
  Caddy, Authelia, Tor and backend control sockets cannot be shared as services.
- No direct-network fallback, HTTP downgrade, TLS-error bypass, cookie fallback,
  unauthenticated mode, alternate transport or automatic request replay.
  Missing prerequisites and uncertain authorization fail closed.
- Mapped applications are trusted; host-local malware is outside this boundary.
  Mapping a web UI is not a machine-wide VPN and does not reroute its external
  browser URLs. Do not claim otherwise.

## Implementation and source integrity

- Keep production Go under `cmd/`, `internal/` and `mobile/` at or below 5,000
  physical lines. Tests and pristine dependencies are excluded. Do not evade
  the limit through generated files or moving product logic into another
  language. Native shells and static UI must remain small too.
- Keep upstream snapshots pristine under `third-party/` and pin release/tag,
  commit and tree. Pin build-tool/container versions and digests. Integration
  changes belong outside vendor trees; no fabricated build metadata.
- Use upstream release APIs/configuration and the host's normal independent
  launcher. Do not implement another service supervisor or PKI framework.
- Use private directories, `0600` state, strict bounded schemas, atomic writes
  and fsync. Do not put secrets in argv, URLs, logs or test evidence. Disable
  component reporting and metrics explicitly; isolate component environment.
- Build and test in rootless Podman. All generated outputs, caches, proof state
  and binaries go under `/run/media/user/Data/TorkittenV2Build`, outside Git.
  Never disturb `/run/media/user/Data/TorkittenBuild` or existing v1 containers.
- Keep commits independently revertible. Never commit generated identities,
  credentials, binaries, packages, caches or runtime state.

## Verification

- Run formatting, static UI/shell checks, vet, race tests, size and vendor checks
  appropriate to the change. Security boundaries need meaningful adversarial
  and concurrency tests, not tests that merely mirror an implementation.
- Test real pinned Caddy/Authelia OAuth, missing/invalid mTLS and bearer denial,
  actual Tor authorization, native TCP/Unix/SSH, uploads, SSE, WebSockets,
  half-close, independent carriers, revocation and identity replacement.
- The opt-in full app proof uses the actual private Unix UI API and erases its
  generated credential state. GTK must also be exercised through the actual
  native bridge; a headless backend proof is not a UI proof.
- Android support requires a compiled/signed package with packaged native Tor
  and device validation. Shared source or Linux evidence does not prove it.
- If a required proof fails, fix the boundary or report the limitation. Do not
  hide it with fallback code, relaxed certificate checks or fabricated success.
