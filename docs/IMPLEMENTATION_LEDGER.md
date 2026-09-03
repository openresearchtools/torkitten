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

- Ubuntu 24.04 accepted an administrator reset through `torkittenctl` and the
  protected daemon socket; the native Wry dashboard was then opened visibly and
  authenticated using guest key events.
- The package used for that partial test does not include every uncommitted M1
  change and therefore is not final M1 evidence.
- Targeted core/vault/daemon/CLI tests passed before the latest admin-web and
  desktop changes. They must be rerun against the final M1 tree.

Required before M1 completion:

- Finish every scoped code path, including remote-web removal of recovery and
  the administrator username migration.
- Add focused vault migration/reset and CLI parsing tests.
- Run formatting, checks, tests, and clippy through the repository's Podman
  workflow.
- Build the exact package from the completed tree using the downloaded Actions
  Tor and Caddy artifacts.
- Install and exercise that exact package in all three existing visible VMs.
- Commit and push; record the SHA and evidence below.

## Defect and requirement register

### AUTH-001 — Passkey UI selects a hardware security key as the primary path

Status: OPEN (M1)

Required behavior: default to the platform authenticator/device-unlock passkey;
offer an external hardware security key only as an explicit secondary choice.

Evidence: pending.

### AUTH-002 — Password and TOTP are requested in one login step

Status: OPEN (M1)

Required behavior: stage the portable fallback as password first and TOTP only
after the password stage succeeds. Preserve generic failure behavior that does
not disclose account or factor state.

Evidence: pending.

### AUTH-003 — Guest recovery codes appear in guest UI/API

Status: IN PROGRESS (M1)

Decision: guest recovery codes are not a guest-facing recovery mechanism.
Recovery is performed by local administration resetting that guest's auth state
and issuing a fresh enrollment. Legacy stored data must migrate safely without
remaining usable for login.

Partial source: core policy, daemon commands, vault migration/reset logic, and
admin policy input have uncommitted changes. Remote portal/template paths still
need removal.

Evidence: pending.

### AUTH-004 — Local administrator has only a password and no username

Status: OPEN (M1)

Required behavior: setup and login expose an explicit stable administrator
identity/username. Existing installations need a deterministic migration.

Evidence: pending.

### AUTH-005 — Forgotten administrator password can strand an installation

Status: IN PROGRESS (M1)

Decision:

- Native: an OS-authorized operator invokes the CLI, which talks to the protected
  Unix administration socket; the reset revokes every administrator session.
- Container: control of the Podman/Docker container is the recovery authority;
  the operator invokes the bundled CLI inside the container over the internal
  Unix socket. The socket is never published or broadly mounted.
- Routine administration remains the persistent browser/Wry flow; container
  exec is an exceptional recovery operation only.

Partial live evidence: successful Ubuntu 24.04 reset and visible login. All-VM
and final-package evidence is pending.

### AUTH-006 — Native Wry window forgets its session after closing

Status: IN PROGRESS (M1)

Required behavior: use a persistent WebKit data directory beneath the user's XDG
data directory, reject unsafe/symlinked profile paths, and enforce mode `0700`.
Closing the window must leave services running; reopening must restore a valid,
unrevoked session.

Partial source: uncommitted `torkitten-desktop` WebContext/profile changes.

Evidence: compile/test and final-package live reopen test pending.

### AUTH-007 — Setup page remains stale after administrator creation

Status: IN PROGRESS (M1)

Required behavior: successful setup and login immediately navigate to `/`; the
server decides whether the permanent dashboard or login page is appropriate.

Partial source: uncommitted admin script change.

Evidence: automated and live tests pending.

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

Status: OPEN

Required behavior: make the native desktop application single-instance or focus
the existing administration window when launched again.

Evidence: pending.

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
