# V2 upstream refresh

Checked official stable release channels on 2026-10-02. The source snapshots
remain complete upstream Git trees; no Torkitten patch is applied inside them.

| Component | Release | Commit | Signature checked locally |
| --- | --- | --- | --- |
| [Tor](https://forum.torproject.org/t/security-release-0-4-9-13/22178) | `tor-0.4.9.13` | `3c575400909efe6599d88e61e7daf0012655ca44` | OpenPGP signed tag, David Goulet |
| [Caddy](https://github.com/caddyserver/caddy/releases/tag/v2.11.6) | `v2.11.6` | `ac834b5dc70a17dca296f47c78c64587d6631cbb` | SSH signed tag, Francis Lavoie |
| [Authelia](https://github.com/authelia/authelia/releases/tag/v4.39.28) | `v4.39.28` | `8da42b2348b0351c6284a2940a9c5eec3d4cd3fd` | Lightweight tag pointing to GitHub OpenPGP signed commit |
| [GOST](https://github.com/go-gost/gost/releases/tag/v3.3.0) | `v3.3.0` | `cb76f63754768c7b5d68895a0d51635b0141b80f` | Upstream tag and commit are unsigned; no signature verification claimed |

Adjacent `third-party/*.upstream.toml` manifests record tag objects, commits,
trees, signing fingerprints, and release URLs. `tools/verify-vendor.sh` passed
for all four imported trees, including Git file modes. Tor's signing fingerprint
was checked against the [official signer list](https://support.torproject.org/little-t-tor/getting-started/verifying/);
its WKD copy was stale, so the current public key was retrieved from the keyserver
linked on that page before successful verification. Caddy's signer key came
from GitHub's `users/francislavoie/ssh_signing_keys` API; Authelia's commit key
came from `https://github.com/web-flow.gpg`. GOST's official stable release and
annotated tag object were checked through GitHub's API and the official Git
repository; its unmodified `go.mod`/`go.sum` pin `go-gost/core` 0.6.1 and
`go-gost/x` 0.16.0 with their transitive dependencies.

## Build compatibility

The Ubuntu 24.04 baseline is retained. Authelia now requires Go 1.27.0, declares
the Go 1.27.1 toolchain, and requires pnpm 12. Its Node minimum is 22.22.0.
Caddy requires Go 1.26.0 and GOST requires Go 1.26.3. The first-party `go.mod`
does not need a version bump.

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
including the retained v1 runtime wrappers. Their default Podman store is
isolated from the original `/run/media/user/Data/TorkittenBuild` store.
`TORKITTEN_BUILD_ROOT` remains an explicit override for CI and other external
build directories; it must never point at the live v1 store during v2 work.
The retained runtime builder selects each bundle by its complete source and
recipe build key, so older cached recipes cannot be consumed accidentally.

## Validation

Completed on Linux x86_64 as an unprivileged user:

- Upstream signature checks, pristine tree verification, shell syntax, and
  first-party diff whitespace checks.
- `TORKITTEN_BUILD_ROOT=/run/media/user/Data/TorkittenV2Build tools/build-local.sh all`:
  the pinned Ubuntu builder and all three component binaries built successfully
  in rootless Podman. Version checks reported Tor 0.4.9.13, Caddy v2.11.6, and
  Authelia v4.39.28-torkitten. Artifact metadata confirms Go 1.27.1, Node 24.21.0,
  pnpm 12.8.1, source trees, and binary SHA-256 digests.
- `TORKITTEN_BUILD_ROOT=/run/media/user/Data/TorkittenV2Build tools/test-local.sh`:
  formatting, JavaScript syntax, `go vet`, race-enabled Go tests, and existing
  line-budget checks passed (4,071 production Go lines).
- `TORKITTEN_BUILD_ROOT=/run/media/user/Data/TorkittenV2Build tools/build-local.sh gost`:
  GOST built successfully from the pristine snapshot in rootless Podman and
  reported `gost v3.3.0 (go1.27.1 linux/amd64)`. Its bundle records the source
  tree, compiler, flags, and binary digest. The Actions build matrix and bundle
  consumption check now include all four components.

Build artifacts and logs remain outside the repository below
`/run/media/user/Data/TorkittenV2Build`; logs are `build-all.log`, `build-gost.log`,
and `test-local.log`. This source refresh does not establish V2 tunnel,
authentication, or native-client compatibility.
