#!/usr/bin/env bash
# Copyright 2026 The Torkitten Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
build_root=${TORKITTEN_BUILD_ROOT:-/run/media/user/Data/TorkittenBuild}
mkdir -p "$build_root/podman/storage" "$build_root/podman/runroot" \
    "$build_root/podman/tmp" "$build_root/cache/go-build" "$build_root/cache/go-mod"
repo_real=$(realpath "$repo_root")
build_real=$(realpath "$build_root")
case "$build_real/" in "$repo_real/"*) echo "build root must be outside the repository" >&2; exit 1;; esac

key=$(sha256sum "$repo_real/tools/build/Containerfile" | cut -c 1-16)
image="localhost/torkitten-builder:ubuntu-24.04-$key"
args=(--root "$build_real/podman/storage" --runroot "$build_real/podman/runroot" --tmpdir "$build_real/podman/tmp")
podman "${args[@]}" image exists "$image" || {
    podman "${args[@]}" build -f "$repo_real/tools/build/Containerfile" -t "$image" "$repo_real/tools/build"
}
podman "${args[@]}" run --rm --userns=host \
    -v "$repo_real:/src:ro" -v "$build_real:/work:rw" \
    -e GOCACHE=/work/cache/go-build -e GOMODCACHE=/work/cache/go-mod \
    -e GOTELEMETRY=off -e GOFLAGS=-mod=readonly -w /src "$image" ./tools/check.sh
