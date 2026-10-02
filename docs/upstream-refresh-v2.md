# V2 upstream refresh

Checked official stable release channels on 2026-10-02. The source snapshots
remain complete upstream Git trees; no Torkitten patch is applied inside them.

| Component | Release | Commit | Signature checked locally |
| --- | --- | --- | --- |
| [Tor](https://forum.torproject.org/t/security-release-0-4-9-13/22178) | `tor-0.4.9.13` | `3c575400909efe6599d88e61e7daf0012655ca44` | OpenPGP signed tag, David Goulet |
| [Caddy](https://github.com/caddyserver/caddy/releases/tag/v2.11.6) | `v2.11.6` | `ac834b5dc70a17dca296f47c78c64587d6631cbb` | SSH signed tag, Francis Lavoie |
| [Authelia](https://github.com/authelia/authelia/releases/tag/v4.39.28) | `v4.39.28` | `8da42b2348b0351c6284a2940a9c5eec3d4cd3fd` | Lightweight tag pointing to GitHub OpenPGP signed commit |
| [Chisel](https://github.com/jpillora/chisel/releases/tag/v1.12.0) | `v1.12.0` | `fe4f4fe7e6a849b4aa6d1b8ee47037e16033f42a` | Unsigned annotated tag and commit |
| [age](https://github.com/FiloSottile/age/releases/tag/v1.3.2) | `v1.3.2` | `b74dce4cdbe35b5e5f66c06d9612b72f89028758` | Unsigned lightweight tag and commit |
| [gozxing](https://github.com/makiuchi-d/gozxing/tree/v0.1.1) | `v0.1.1` | `3d941b5e72ac36566873214086fb204e7d76333c` | Unsigned lightweight tag and commit; latest stable tag, no GitHub releases |
| [OpenSSH](https://www.openssh.org/releasenotes.html#10.5p1) | `V_10_5_P1` (10.5p1) | `b3f7344209832eea8ece447d871ea748767c444b` | Damien Miller SSH-signed tag; additional official release tarball OpenPGP signature |

Adjacent `third-party/*.upstream.toml` manifests record tag objects, commits,
trees, signing fingerprints, and release URLs. `tools/verify-vendor.sh` passed
for all seven imported trees, including Git file modes. Tor's signing fingerprint
was checked against the [official signer list](https://support.torproject.org/little-t-tor/getting-started/verifying/);
its WKD copy was stale, so the current public key was retrieved from the keyserver
linked on that page before successful verification. Caddy's signer key came
from GitHub's `users/francislavoie/ssh_signing_keys` API; Authelia's commit key
came from `https://github.com/web-flow.gpg`. Chisel, age and gozxing were checked
against their official repository tags and release channels. No signature claim
is made for unsigned objects. OpenSSH’s tag was verified using the official
maintainer’s GitHub signing keys (`SHA256:JDubEpIXO0CfnM+iagFQce4MiJJDqTvgbBR80SuRwTQ`);
the additional release tarball signature matched the official release key
`7168B983815A5EEF59A4ADFD2A3F414E736060BA`. Evidence is under
`proofs/sshd-001`. The bundled source is the exact tagged Git tree, not a patched
release archive. The root Go module consumes these pristine source
snapshots through local replacements. GOST was evaluated and then removed from
the selected vendor/build set; it is not an alternate runtime transport.

## Build compatibility

The Ubuntu 24.04 baseline is retained. Authelia now requires Go 1.27.0, declares
the Go 1.27.1 toolchain, and requires pnpm 12. Its Node minimum is 22.22.0.
Caddy requires Go 1.26.0. The first-party module now selects Go 1.27.0 and builds
with the pinned Go 1.27.1 compiler. Native development packages are GTK4,
WebKitGTK 6.0 and libsoup3 from the Ubuntu 24.04 baseline.

The builder pins:

- [Go 1.27.1](https://go.dev/dl/), `golang:1.27.1-bookworm`, OCI index
  `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`.
- [Node 24.21.0](https://nodejs.org/dist/index.json), maintained LTS,
  `node:24.21.0-bookworm-slim`, OCI index
  `sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6`.
- [pnpm 12.8.1](https://github.com/pnpm/pnpm/releases/tag/v12.8.1), exact npm
  package version installed with lifecycle scripts disabled.

Image digests were obtained from Docker Hub's official `library/golang` and
`library/node` manifests. `GOTOOLCHAIN=local` prevents automatic replacement of
the pinned Go toolchain. Authelia's build timestamp comes from the signed
commit's `2026-09-17T11:45:43Z` committer timestamp in its manifest. A missing
timestamp is an error; a Git mirror and fabricated default date are unnecessary.
The vendor updater prints this timestamp from the imported commit for future
manifest updates.

All branch shell helpers default to `/run/media/user/Data/TorkittenV2Build`,
with a Podman store isolated from the original `/run/media/user/Data/TorkittenBuild`
store. `TORKITTEN_BUILD_ROOT` remains an explicit override for CI and other
external build directories; it must never point at the live v1 store during v2
work. The native bundle selects each upstream binary by its complete source and
recipe build key. The obsolete v1 runtime image and owner-reset helpers are removed.

## Validation

Completed on Linux x86_64 as an unprivileged user:

- Upstream signature checks, pristine tree and mode verification, shell syntax,
  and first-party diff whitespace checks.
- `tools/build-app.sh` rebuilt Tor 0.4.9.13, Caddy v2.11.6, Authelia
  v4.39.28-torkitten, Chisel v1.12.0 and age v1.3.2, then compiled the native
  shell and complete Linux app bundle. Gozxing is compiled into the app as a
  library. The final builder includes GTK development packages, `openssl` and
  `openssh-client`: `localhost/torkitten-builder:ubuntu-24.04-f89d522915df35ca`.
- `tools/test-local.sh` passed Go formatting, current UI JavaScript and shell
  syntax, `go vet`, race-enabled tests and the 5,000-line production Go limit
  including `mobile/` (4,179 production lines in this revision).
- The native shell compiled with warnings as errors. Real host WebKit passed
  Unix GET/JSON POST, HTTP status preservation, fixed Host/Origin and external
  HTTP canary denial. Host versions: GTK 4.22.4, WebKitGTK 2.52.6, libsoup 3.6.6.
- The complete app rendered in GTK against fresh isolated state. A test-only
  harness exercised QR-image dialog open/cancel/reset, the separate SSH switch,
  the host tab, and adding, editing and saving a single-command service through
  the real private API. Its screenshots were visually checked. The harness is
  not part of the production binary. A separate eight-check GTK flow proof in
  `proofs/ui-flow-001` used mocked API responses for setup/login/consent,
  automatic unlock/login, Auto-port display and the dedicated SSH row; it
  proves UI transitions, not real authentication or tunnel traffic.
- CI now assembles a Linux bundle from verified exact-key upstream artifacts
  and archives it as a tar file to preserve executable permissions. That CI
  workflow is checked locally but has not been dispatched on GitHub.
- Distribution notice collection reads the three Go executables' embedded
  module graphs, verifies exact source checksums and includes the matching Go
  standard-library notices. The final bundle contains 364 notices for 230
  source identities in `licenses/go-modules/`, with provenance and file hashes
  in `metadata/go-notices.json`. Two offline collections produced identical
  metadata; all eight executable hashes remained unchanged.

Artifacts and logs stay outside the repository below
`/run/media/user/Data/TorkittenV2Build`. Final logs are
`logs/build-owner-qr.log` and `logs/check-owner-qr.log`. Native bridge evidence is
`proofs/native-ui-repro-002/result.json`; real UI evidence and PNGs are under
`proofs/ui-app-002`. Earlier v1 test logs are historical, not proof of the new app.
Android SDK/NDK are absent; its AAR and Java shell remain unbuilt and unverified.
No APK or Android compatibility is claimed. See [native builds](native-builds-v2.md).

The final race-enabled real Tor app proof passed all 23 checks in
`proofs/app-owner-e2e-003/results.json` (876.920 seconds of measured work).
It used the actual private app API for local 2FA setup, encrypted QR-only
onboarding, Caddy TLS/mTLS denial, Authelia PAR/PKCE/consent, byte-identical
TCP/Unix streams, stock host SSH, systemd service launch, selective availability,
global/SSH revocation, complete identity replacement, separate profiles,
packaged host/client restarts, encrypted profile unlock, persisted OAuth and
native remapping. Remove closed an active stream and erased profile/Tor-auth
state. All generated proof identities were removed. The tested application
SHA256 is `cd671a15325c0a683b6dc4f4e1d8462154fd7a7bebc00768af870a7b7176ae27`.

The proof also verifies TLS/mTLS directly over the private gateway socket and
checks actual kernel listeners for every component. Tor starts with an empty
defaults file and without a MetricsPort directive; pinned Tor treats port zero
as an ephemeral listener. After local 2FA confirmation, server Tor is restarted
with publication enabled so the unpublished descriptor's delayed upload timer
cannot carry over. Cold bootstrap and post-restart onion rendezvous took minutes
in the live test. Readiness polling exists only in the proof; production does
not replay failed application requests or use an alternate network route.

Camera permission evidence is `proofs/camera-native-001`; the actual portable
UI’s synthetic video-to-local-decoder path, recognition-only response, retained
captured image and success/cancel cleanup passed in `proofs/scanner-ui-004`. Tests did not open a
physical camera. Device optical scanning and Android operation remain unverified.

## Managed host SSH and QR export

The additional pristine OpenSSH 10.5p1 source build completed on the same pinned
Ubuntu builder (`logs/build-openssh.log`). The latest Linux bundle includes
`sshd`, `sshd-session` and `sshd-auth`, all selected by the exact source/recipe
build key and accompanied by individual binary hashes. The wrapper supplies
the documented `SshdSessionPath` and `SshdAuthPath`; there is no older-binary or
host-daemon fallback. CI verifies all three hashes.

`proofs/sshd-001/result.log` records a race-enabled test executed as the real
unprivileged host user: ordinary OpenSSH command execution, interactive PTY, exact-byte SFTP
upload/download, denial of root/other usernames, password-only and unmatched-key
authentication, active-session closure when disabled, and host/login key changes
on identity rotation. The daemon receives each connection through its stock
inetd mode from a private Unix listener. No host global SSH service was installed
or changed. `logs/build-ssh-app.log` records the complete assembled app.

`proofs/native-png-001/run/result.json` records an exact-byte 10,276-byte encrypted
connection QR download through the actual GTK/WebKit callback. The test alone
substitutes the interactive save destination. Wrong names, wrong MIME type and
oversized Blobs are denied; the native HTTP canary still receives no requests.
The Android equivalent now accepts only bounded PNG data and remains unbuilt.

## Managed service presets

`proofs/managed-service-002/results.json` passed twelve real systemd-user
checks: literal launch arguments, independent cgroup ownership, process life
beyond a cancelled request, wrapper reopening, idempotent Load, Reload/Stop,
changed-command reconciliation, stale authorization denial, preservation of
other applications' units and failure without an executable or user manager.
The wrapper applies no resource limits or restart policy. Separate cgroup
ownership is not a promise of survival during a machine-wide OOM.

## Distribution notice completion

`THIRD-PARTY-NOTICES.txt` now accompanies the repository and Linux bundle. It
identifies the separately supplied, dynamically linked LGPL system libraries,
preserves modification/relinking rights, and points to the included unmodified
LGPL-2.1 text. MPL-2.0 modules have both explicit upstream source links and their
exact Go-module source archives in `sources/go-modules/`, with SHA256 hashes in
`metadata/go-notices.json`.

The app packaging step installs Authelia's unchanged frozen frontend lockfile
with scripts disabled and uses pnpm's production-license inventory. It copies
the actual texts for 60 production packages and three runtime-helper sources
(Vite, Rolldown and Tailwind), including the two packages whose full MIT text
appears in README.md. The inventory is `metadata/authelia-web-notices.json`.

`proofs/license-notices-001/results.json` records 364 Go notice files, 66 frontend
notice files, valid source archives for all three MPL modules, matching pinned
frontend lockfile, and exact LGPL/notice copies. The rootless Podman app build
completed; all eight executable hashes are unchanged from the 23-check Tor
proof. Packaging syntax and whitespace checks passed. This change adds
distribution materials and does not change runtime behavior or authentication.
