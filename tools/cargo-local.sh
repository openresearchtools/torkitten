#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
build_root=${TORKITTEN_BUILD_ROOT:-/run/media/user/Data/TorkittenBuild}
mkdir -p "$build_root/podman/storage" "$build_root/podman/runroot" \
    "$build_root/podman/tmp" "$build_root/cache/cargo" "$build_root/target"

repo_real=$(realpath "$repo_root")
build_real=$(realpath "$build_root")
case "$build_real/" in
    "$repo_real/"*)
        echo "TORKITTEN_BUILD_ROOT must be outside the repository" >&2
        exit 1
        ;;
esac

command -v podman >/dev/null || {
    echo "Podman is required" >&2
    exit 1
}

if (($# == 0)); then
    set -- test
fi

podman_args=(
    --root "$build_real/podman/storage"
    --runroot "$build_real/podman/runroot"
    --tmpdir "$build_real/podman/tmp"
)
containerfile="$repo_real/tools/build/Rust.Containerfile"
image_key=$(sha256sum "$containerfile" | cut -c 1-16)
image="localhost/torkitten-rust:ubuntu-24.04-$image_key"

if ! podman "${podman_args[@]}" image exists "$image"; then
    podman "${podman_args[@]}" build \
        --file "$containerfile" \
        --tag "$image" \
        "$repo_real/tools/build"
fi

podman "${podman_args[@]}" run --rm \
    --userns=host \
    --volume "$repo_real:/src:ro" \
    --volume "$build_real:/work:rw" \
    --env CARGO_HOME=/work/cache/cargo \
    --env CARGO_TARGET_DIR=/work/target \
    --env CARGO_INCREMENTAL=0 \
    --workdir /src \
    "$image" \
    cargo "$@"
