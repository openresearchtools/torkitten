#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
build_root=${TORKITTEN_BUILD_ROOT:-/run/media/user/Data/TorkittenBuild}
tor_binary=${TORKITTEN_TOR_ARTIFACT:-}
caddy_binary=${TORKITTEN_CADDY_ARTIFACT:-}

if [[ -z $tor_binary ]]; then
    tor_binary=$(find "$build_root/github-actions" -type f \
        -path '*/third-party-tor-tor-0.4.9.11-*/usr/bin/tor' \
        -perm -u+x -print -quit 2>/dev/null || true)
fi
if [[ -z $caddy_binary ]]; then
    caddy_binary=$(find "$build_root/github-actions" -type f \
        -path '*/third-party-caddy-v2.11.4-*/usr/bin/caddy' \
        -perm -u+x -print -quit 2>/dev/null || true)
fi
if [[ -z $tor_binary || -z $caddy_binary ]]; then
    echo "download the Tor and Caddy Actions artifacts or set their artifact paths" >&2
    exit 1
fi

repo_real=$(realpath "$repo_root")
build_real=$(realpath "$build_root")
tor_real=$(realpath "$tor_binary")
caddy_real=$(realpath "$caddy_binary")
tor_artifact_root=$(realpath "$(dirname "$tor_real")/../..")
caddy_artifact_root=$(realpath "$(dirname "$caddy_real")/../..")
case "$build_real/" in
    "$repo_real/"*)
        echo "TORKITTEN_BUILD_ROOT must be outside the repository" >&2
        exit 1
        ;;
esac
for component in "$tor_real" "$caddy_real"; do
    if [[ ! -x $component ]]; then
        echo "required Actions artifact is not executable: $component" >&2
        exit 1
    fi
done

mkdir -p "$build_real/podman/storage" "$build_real/podman/runroot" \
    "$build_real/podman/tmp" "$build_real/cache/cargo" "$build_real/target" \
    "$build_real/package" "$build_real/artifacts"

containerfile="$repo_real/tools/build/Rust.Containerfile"
image_key=$(sha256sum "$containerfile" | cut -c 1-16)
image="localhost/torkitten-rust:ubuntu-24.04-$image_key"
podman_args=(
    --root "$build_real/podman/storage"
    --runroot "$build_real/podman/runroot"
    --tmpdir "$build_real/podman/tmp"
)
if ! podman "${podman_args[@]}" image exists "$image"; then
    podman "${podman_args[@]}" build --file "$containerfile" --tag "$image" \
        "$repo_real/tools/build"
fi

podman "${podman_args[@]}" run --rm --userns=host \
    --volume "$repo_real:/src:ro" \
    --volume "$build_real:/work:rw" \
    --volume "$tor_real:/inputs/tor:ro" \
    --volume "$caddy_real:/inputs/caddy:ro" \
    --volume "$tor_artifact_root:/inputs/tor-root:ro" \
    --volume "$caddy_artifact_root:/inputs/caddy-root:ro" \
    --env CARGO_HOME=/work/cache/cargo \
    --env CARGO_TARGET_DIR=/work/target \
    --env CARGO_INCREMENTAL=0 \
    --workdir /src \
    "$image" /src/tools/package-deb-inner.sh
