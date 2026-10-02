# Vendored upstream sources

`tor/`, `caddy/`, `authelia/`, and `gost/` are complete, normal Git-tracked snapshots. They are not
submodules, so GitHub builds never depend on GitLab or another source host.
Each adjacent `*.upstream.toml` records the release tag, tag object, commit,
and Git tree imported from the official repository.

GOST supplies the v2 fixed stream-forwarding transport. Its full release snapshot
and upstream Go dependency lockfiles remain intact; Torkitten's transport
configuration belongs outside this directory. An unsigned upstream tag is
recorded as unsigned in its manifest.

Keep these directories byte-for-byte and mode-for-mode identical to their
recorded upstream trees. Torkitten integration, configuration, patches, and
build recipes belong outside `third-party/`. If an unavoidable upstream patch
is needed, record it as a separate patch applied only in the external build
workspace.

Verify the snapshots with:

```bash
tools/verify-vendor.sh
```

To update a component, first confirm the intended stable release through the
upstream project's official release channel, then run:

```bash
tools/update-vendor.sh tor tor-X.Y.Z
tools/update-vendor.sh caddy vX.Y.Z
tools/update-vendor.sh authelia vX.Y.Z
tools/update-vendor.sh gost vX.Y.Z
```

The updater uses `TORKITTEN_BUILD_ROOT` (default
`/run/media/user/Data/TorkittenV2Build`) for its upstream mirror and staging
area. Review the upstream tag signature and release announcement, copy the
printed object IDs and `committed_at` timestamp into the component's manifest,
stage the source with `git add -f`, and run the verifier. Commit each component
update separately.
