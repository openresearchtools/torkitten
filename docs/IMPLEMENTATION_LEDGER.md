# Torkitten implementation ledger

Last updated: 2026-09-03

`AGENTS.md` is the canonical product and implementation contract. This ledger
does not replace, shorten, or reinterpret it. It records implementation status,
user-reported defects, decisions, and the evidence required before work may be
called complete.

## Working method

- Keep exactly one active implementation milestone.
- Give every distinct report a stable ID. Repeated reports add observations or
  evidence to the existing ID instead of creating duplicate work.
- Capture new non-critical reports without abandoning the active milestone.
- An immediate safety failure or explicit live-environment request may pre-empt
  the active milestone; record both the interruption and resumption point.
- Never mark an item complete from code inspection alone. Completion requires
  the relevant source paths, automated test results, live-runtime evidence where
  applicable, and the implementing commit SHA.
- Conversation compaction can discard verbatim chat messages. This file is the
  durable issue and decision record; it must be updated when a new distinct
  defect or requirement is identified.

## Evidence fields

Every completed item must record:

1. Source: exact files or modules implementing the behavior.
2. Automated: exact commands and passing tests.
3. Live: exact VM/container and observable result, when runtime behavior is
   involved.
4. Delivery: commit SHA pushed to `origin`.

No blank evidence field may be inferred as passing.

## Active milestone

### M1 — Authentication recovery, separation, and durable native sessions

Status: IN PROGRESS

Scope:

- OS-authorized local administrator reset over the protected Unix socket.
- Container administrator reset through the bundled CLI and internal Unix
  socket, without PAM or a kernel-keyring dependency.
- Local-admin-only guest authentication reset followed by fresh enrollment.
- Removal of guest-facing recovery-code generation, login, UI, and API paths.
- Staged password-then-TOTP fallback login.
- Platform passkeys as the default, with an explicit hardware-security-key path.
- A persistent, permission-restricted WebKit profile for the native Wry window.
- Explicit local administrator identity/username.
- Setup/login transitions that immediately reach the server-selected permanent
  page rather than leaving a stale setup screen.

Current verified partial evidence:

- Exact M1 package `torkitten_0.1.0_amd64.deb`, SHA-256
  `6610767d849f3ce90dd9e0425eed2251d4757738a5a24f1eb598158002504eea`,
  was built from pushed commit `622eee0` and installed successfully in all three
  running guests without restarting or reconfiguring a VM or display.
- The installed Tor and Caddy bytes in all three guests exactly match the
  downloaded Actions artifacts: Tor SHA-256
  `40e0faa9ab28b56b692758c53cf05b63b018457d55a268fdb042fb450b1a3e85`
  and Caddy SHA-256
  `8b3a71c29f07d3b7e4cee1bee3d778dbf5150525304051e42ea4d78aea1c8551`.
- Ubuntu 24.04 accepted an administrator username/password reset through
  `torkittenctl` and the protected daemon socket. The current Wry dashboard was
  opened visibly and authenticated. Closing Wry left the daemon, Tor, and Caddy
  active; reopening without credentials restored the authenticated dashboard.
  Its persistent profile was mode `0700`. Accessibility exposed `Generate
  site` and `Sign out`, and did not expose the removed recovery-code policy.
- Debian 13 accepted the protected administrator reset and displayed the
  authenticated current dashboard with exactly one Wry process.
- Ubuntu 26.04 installed and opened exactly one current Wry window at the
  username/password login. Its daemon is active with zero restarts; Tor and
  Caddy are intentionally stopped because this guest has no persisted site.
  QEMU keyboard injection did not reach the inactive Wayland window and GNOME
  denied remote focus activation, so authenticated dashboard/reopen evidence is
  still pending for this guest. No persistent input workaround was installed.
- The complete workspace test run passes 144 tests; its seven ignored
  real-binary tests were then run separately and all seven passed against the
  downloaded GitHub Actions Tor and Caddy artifacts.
- Workspace Clippy passes for all targets with warnings denied. Formatting and
  diff checks pass.

Required before M1 completion:

- Complete authenticated dashboard and reopen evidence on Ubuntu 26.04 without
  changing the user's VM/display configuration.
- Exercise live guest reset/fresh enrollment, staged password then TOTP, and
  the separate platform-passkey/hardware-key choices.

## Defect and requirement register

### AUTH-001 — Passkey UI selects a hardware security key as the primary path

Status: IMPLEMENTED; LIVE EVIDENCE PENDING (M1)

Required behavior: default to the platform authenticator/device-unlock passkey;
offer an external hardware security key only as an explicit secondary choice.

Source and automated evidence: separate platform and hardware-key controls are
implemented in `torkitten-web`; rendering/browser-option tests pass. Live
authenticator evidence is pending.

### AUTH-002 — Password and TOTP are requested in one login step

Status: IMPLEMENTED; LIVE EVIDENCE PENDING (M1)

Required behavior: stage the portable fallback as password first and TOTP only
after the password stage succeeds. Preserve generic failure behavior that does
not disclose account or factor state.

Source and automated evidence: the remote IPC and daemon implement a bounded,
one-use, 120-second password challenge before TOTP. Remote-web protocol and
daemon tests pass. Live portal evidence is pending.

### AUTH-003 — Guest recovery codes appear in guest UI/API

Status: IMPLEMENTED; LIVE EVIDENCE PENDING (M1)

Decision: guest recovery codes are not a guest-facing recovery mechanism.
Recovery is performed by local administration resetting that guest's auth state
and issuing a fresh enrollment. Legacy stored data must migrate safely without
remaining usable for login.

Source and automated evidence: the remote recovery command, HTTP handling,
template, and UI are removed; the policy is forced off; local guest-login reset
preserves devices and permissions; migration/reset/protocol tests pass. Legacy
encrypted recovery storage remains unusable and is scheduled for physical
schema/code removal during the M2 boundary refactor. Live reset and fresh
enrollment evidence is pending.

### AUTH-004 — Local administrator has only a password and no username

Status: IMPLEMENTED; LIVE EVIDENCE PENDING (M1)

Required behavior: setup and login expose an explicit stable administrator
identity/username. Existing installations need a deterministic migration.

Source and automated evidence: a validated administrator username now crosses
setup, login, protected reset, CLI, daemon, and vault migration. Existing state
migrates to username `admin`; unit and HTTP boundary tests pass. Exact-package
upgrade/reset/login passed live on Ubuntu 24.04 and Debian 13; Ubuntu 26.04
authenticated-login evidence remains pending.

### AUTH-005 — Forgotten administrator password can strand an installation

Status: IMPLEMENTED; LIVE EVIDENCE PENDING (M1)

Decision:

- Native: an OS-authorized operator invokes the CLI, which talks to the protected
  Unix administration socket; the reset revokes every administrator session.
- Container: control of the Podman/Docker container is the recovery authority;
  the operator invokes the bundled CLI inside the container over the internal
  Unix socket. The socket is never published or broadly mounted.
- Routine administration remains the persistent browser/Wry flow; container
  exec is an exceptional recovery operation only.

Source and automated evidence: native/container reset accepts the replacement
username on the command line and password only on stdin, atomically changes both
credentials, and revokes all administrator sessions. A fresh authenticated
administrator can also change credentials in the local UI; a stale session is
rejected. Exact M1 package reset/login evidence passed on Ubuntu 24.04 and Debian
13. Ubuntu 26.04 authenticated-login and container recovery evidence remain
pending.

### AUTH-006 — Native Wry window forgets its session after closing

Status: IMPLEMENTED; LIVE EVIDENCE PENDING (M1)

Required behavior: use a persistent WebKit data directory beneath the user's XDG
data directory, reject unsafe/symlinked profile paths, and enforce mode `0700`.
Closing the window must leave services running; reopening must restore a valid,
unrevoked session.

Source and automated evidence: Wry uses a persistent WebContext rooted under the
XDG data directory; unsafe paths are rejected and both directories are enforced
as mode `0700`. Four desktop tests and strict Clippy pass. Exact M1 package live
close/service-survival/reopen/session-restoration evidence passed on Ubuntu
24.04. The other environments remain pending.

### AUTH-007 — Setup page remains stale after administrator creation

Status: IMPLEMENTED; LIVE EVIDENCE PENDING (M1)

Required behavior: successful setup and login immediately navigate to `/`; the
server decides whether the permanent dashboard or login page is appropriate.

Source and automated evidence: setup/login success immediately replaces the
location with `/`, allowing the server to select the dashboard/login state.
Admin HTTP tests pass. Live evidence is pending.

### PROCESS-001 — High-rate interruptions and parallel-agent control

Status: ACTIVE CONSTRAINT

- Conversation compaction does not preserve every old message verbatim; this
  ledger preserves the actionable defect, decision, status, and evidence.
- Repeated reports attach to one defect ID rather than multiplying duplicate
  tickets.
- This harness permits at most four concurrent agents, not hundreds. The root
  agent can inspect status, message, interrupt, and review their shared changes.
- Agents never receive copied OAuth credentials or bypass platform controls.
- No worker result is accepted without root diff review and integrated tests.

### SEC-001 — A browser that ignores redirects might access a mapped service

Status: COMPLETE

Decision: redirects are navigation only, never the authorization boundary.
Caddy performs fail-closed forward authentication on every proxied request.

Source: mapping return validation and proxy/auth integration implemented through
commit `c7b19ca`.

Automated: real-artifact integration tests passed using the downloaded Tor and
Caddy binaries.

Live: Ubuntu 24.04 raw OpenSSL request without following redirects returned 303;
the upstream service was not reached.

Delivery: `c7b19ca` pushed to `origin`.

### SEC-002 — Claimed massive malware/concurrency attack and overload behavior

Status: OPEN

Current observation: during the reported event, Ubuntu 24.04 showed all three
services active, zero service restarts, low memory use, and no RX/TX traffic in a
one-second `enp1s0` sample. This does not prove overload resistance.

Required behavior/evidence: bounded load and connection tests, rate/size limits,
resource ceilings, fail-closed behavior under auth-service pressure, redacted
logs, and emergency-stop verification. Do not assist in operating malware.

### BOUNDARY-001 — Security surfaces must not cross code/listener/credential/UI boundaries

Status: OPEN AUDIT

Required separation:

1. Local Admin Control Plane
2. Remote Login Portal
3. Certificate Bootstrap
4. Device Enrollment
5. Application Mapping

Tor/Caddy process control and CLI socket access must remain local-control-plane
capabilities. The onion portal must never expose administration capabilities.

Evidence: full route, listener, credential, and negative-access audit pending.

### CODE-001 — Oversized monolithic Rust modules obscure boundaries

Status: OPEN (planned M2)

Exact observed sizes on 2026-09-03:

- `crates/torkittend/src/lib.rs`: 4,115 lines
- `crates/torkitten-web/src/lib.rs`: 1,896 lines
- `crates/torkitten-admin-web/src/lib.rs`: 1,594 lines
- `crates/torkitten-vault/src/store.rs`: 2,966 lines
- `crates/torkitten-tor/src/instance.rs`: 1,363 lines

Required behavior: split local-admin protocol, remote-auth protocol, runtime and
lifecycle, persistence concerns, and Tor instance/configuration into cohesive
`.rs` modules without weakening the crate boundaries specified by `AGENTS.md`.

Evidence: pending. A failed extraction attempt made no source change and is not
implementation evidence.

### UI-001 — Dashboard is oversized and does not look like a professional desktop control panel

Status: OPEN (planned M3)

Required behavior: compact responsive Podman/Docker-Desktop-style information
density with onion sites as top-level rows/cards and visibly indented mappings.

Evidence: screenshot and live interaction evidence pending.

### UI-002 — Sidebar/tab state does not follow the displayed section

Status: OPEN (planned M3)

Observed defects: active navigation is hard-coded and navigation disappears
entirely below 900 px.

Required behavior: current section controls active state; responsive navigation
remains usable at narrow widths and in sidecar-sized windows.

Evidence: pending.

### UI-003 — Mutations wait 350 ms and reload the full page

Status: OPEN (planned M3)

Required behavior: show immediate pending state, visually commit a toggle only
after daemon validation/commit, update only affected UI state where practical,
and retain the last working state on failure.

Evidence: pending.

### DESKTOP-001 — More than one administration window can be launched

Status: OPEN; CONFIRMED LIVE

Required behavior: make the native desktop application single-instance or focus
the existing administration window when launched again.

Evidence: Ubuntu 24.04 allowed an existing pre-upgrade Wry process and a newly
launched current process to coexist. Accessibility exposed both applications;
the stale process still held the old recovery-code control in memory while the
current process did not. The exact stale PID was closed and one authenticated
current window was left open. Implementation and regression evidence are
pending.

### VM-001 — Testing must preserve the user's live graphical VM workflow

Status: ACTIVE CONSTRAINT

Rules:

- Use only the already-running visible libvirt guests.
- Never restart, reconfigure, detach, or move virt-manager or its display
  windows.
- Do not use VirtioFS.
- Transfer files through QEMU guest-agent file APIs or a temporary host HTTP
  endpoint.
- VM package mutation is allowed.
- Open and interact with the native UI visibly in the guest when GUI behavior is
  under test.

### BUILD-001 — Builds and third-party artifacts must stay outside the repository

Status: ACTIVE CONSTRAINT

Build with Podman. Keep all generated build products under
`/run/media/user/Data/TorkittenBuild` (or another explicitly approved external
root). Use the already-downloaded GitHub Actions artifacts:

- Tor: `/run/media/user/Data/TorkittenBuild/github-actions/33698089587/third-party-tor-tor-0.4.9.11-a77de259ff32/usr/bin/tor`
- Caddy: `/run/media/user/Data/TorkittenBuild/github-actions/33698089587/third-party-caddy-v2.11.4-89190a02601c/usr/bin/caddy`

Never commit artifacts, VM credentials, generated keys, local state, caches, or
packages.

## Delivery milestones after M1

1. M2 — Module-boundary refactor and security-surface audit.
2. M3 — Professional compact UI, responsive navigation, and transactional
   partial updates.
3. M4 — Load/overload hardening and security verification.
4. M5 — Exact final `.deb` and OCI builds, complete native/container behavior,
   and the full cross-VM/product verification matrix from `AGENTS.md`.

## Exact final-package VM matrix

All rows are PENDING for the final tree/package even when partial exploratory
evidence exists.

| Environment | Install/upgrade | Visible Wry UI | Reopen session | Onboarding | Real Tor/Caddy E2E | Persistence/restart |
|---|---|---|---|---|---|---|
| Ubuntu 24.04 (`gnozzard-test-ubuntu2404`) | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Ubuntu 26.04 (`gnozzard-test-ubuntu2604`) | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Debian 13 (`gnozzard-test-debian13`) | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| Podman OCI | PENDING | N/A (host browser) | PENDING | PENDING | PENDING | PENDING |
| Docker OCI | PENDING | N/A (host browser) | PENDING | PENDING | PENDING | PENDING |

## Delivery evidence log

Append entries here; never rewrite history to make a partial test appear final.

- 2026-09-03 — `c7b19ca`: authenticated mapping return handling, real-artifact
  integration tests, and Ubuntu 24.04 no-follow fail-closed observation.
- 2026-09-03 — Partial/uncommitted M1 live check: installed an intermediate
  package on Ubuntu 24.04, reset the local administrator through the protected
  socket, and visibly opened the authenticated dashboard. This is explicitly
  not final M1 or final-package evidence.
- 2026-09-03 — `622eee0`: exact M1 package SHA-256
  `6610767d849f3ce90dd9e0425eed2251d4757738a5a24f1eb598158002504eea`
  installed in Ubuntu 24.04, Ubuntu 26.04, and Debian 13. Installed Tor/Caddy
  hashes matched the downloaded Actions artifacts in every guest. Ubuntu 24.04
  passed protected reset, authenticated native dashboard, window-close service
  survival, and credential-free session reopen. Debian 13 passed protected reset
  and authenticated native dashboard. Ubuntu 26.04 opened the current native
  login UI but authenticated GUI/reopen evidence remains pending because its VM
  keyboard injection did not reach the inactive Wayland window and GNOME denied
  remote focus activation.
