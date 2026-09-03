# Building Torkitten

## Baseline and inputs

Release binaries are built on Ubuntu 24.04. Compatibility packages will be tested on Ubuntu 24.04, Ubuntu 26.04, and Debian 13 before release.

Tor and Caddy are pristine upstream source snapshots stored in `third-party/`. Their adjacent `*.upstream.toml` files record the upstream release tag, tag object, commit, tree, license, and import date. `tools/verify-vendor.sh` proves the Git-tracked subtree matches the recorded tree before any build. Update one component at a time with `tools/update-vendor.sh`, review the upstream release and signature, then commit its source and manifest together.

## Local Podman builds

Run one component or both:

```sh
./tools/build-local.sh tor
./tools/build-local.sh caddy
./tools/build-local.sh all
```

The default build root is `/run/media/user/Data/TorkittenBuild`. Override it with `TORKITTEN_BUILD_ROOT`, but it must remain outside the repository. The checkout is mounted read-only; Podman graph storage, module caches, temporary work, and finished artifacts all stay under the external build root. No build output belongs in the repository.

Each output directory names the Ubuntu baseline, architecture, upstream release, source tree, and recipe digest. `BUILD-METADATA` records the complete source identity, release flags, toolchain, license location, and binary SHA-256. Repeating an unchanged build reuses its completed output.

Real-binary integration tests accept `TORKITTEN_TOR_BINARY` and
`TORKITTEN_CADDY_BINARY`. Paths under the external build root are visible as
`/work` inside the test container. For example, a verified GitHub Actions Tor
bundle can be exercised without rebuilding it:

```sh
TORKITTEN_TOR_BINARY=/work/github-actions/<run>/<tor-artifact>/usr/bin/tor \
  ./tools/cargo-local.sh test -p torkitten-tor -- --ignored
```

## GitHub Actions

`.github/workflows/third-party.yml` builds Tor and Caddy concurrently on separate Ubuntu 24.04 runners. Each component has an independent version-and-recipe-derived cache. A cache hit is uploaded directly as a fresh run artifact; a miss builds from the vendored source and then populates that cache. The final job downloads both artifacts exactly as later Torkitten packaging jobs will.

The `workflow_dispatch` option `rebuild_third_party` bypasses cache restoration and produces fresh artifacts for that run. GitHub caches are immutable; changing a component version, source identity, build recipe, shared builder, or cache generation creates the replacement cache naturally.

Keep future standalone, non-file-linked binaries on the same model: pinned source, independent recipe, independent cache, reusable run artifact. Test installable packages in disposable libvirt guests rather than copying build products into this checkout.
