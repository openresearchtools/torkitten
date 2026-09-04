#!/usr/bin/env bash
# Copyright 2026 The Torkitten Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
build_root=${TORKITTEN_BUILD_ROOT:-/run/media/user/Data/TorkittenBuild}
name=${TORKITTEN_CONTAINER:-torkitten}
case "$(realpath "$build_root")/" in "$(realpath "$repo_root")/"*) echo "build root must be outside the repository" >&2; exit 1;; esac
podman_args=(--root "$build_root/podman/storage" --runroot "$build_root/podman/runroot" --tmpdir "$build_root/podman/tmp")
podman "${podman_args[@]}" container exists "$name" || { echo "container $name does not exist" >&2; exit 1; }
[[ $(podman "${podman_args[@]}" inspect --format '{{.State.Running}}' "$name") == false ]] || { echo "stop container $name first" >&2; exit 1; }
podman unshare bash -s -- "$build_root" "$name" <<'RESET'
set -euo pipefail
build_root=$1
name=$2
args=(--root "$build_root/podman/storage" --runroot "$build_root/podman/runroot" --tmpdir "$build_root/podman/tmp")
root=$(podman "${args[@]}" mount "$name")
trap 'podman "${args[@]}" unmount "$name" >/dev/null' EXIT
chroot --userspec=1000:1000 "$root" /usr/bin/torkittenctl owner reset RESET
RESET
