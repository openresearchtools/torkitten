#!/usr/bin/env bash
# Copyright 2026 The Torkitten Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
build_root=${TORKITTEN_BUILD_ROOT:-/run/media/user/Data/TorkittenBuild}
image=${TORKITTEN_IMAGE:-localhost/torkitten:dev}
name=${TORKITTEN_CONTAINER:-torkitten}
podman_args=(--root "$build_root/podman/storage" --runroot "$build_root/podman/runroot" --tmpdir "$build_root/podman/tmp")
if podman "${podman_args[@]}" container exists "$name"; then
    echo "container $name already exists; start it to retain its writable-layer state, or remove it deliberately to erase that state" >&2
    exit 1
fi
podman "${podman_args[@]}" run --detach --name "$name" --cap-drop all --security-opt no-new-privileges --network pasta:-T,auto --publish 127.0.0.1:12755:12755 "$image"
printf 'Torkitten is starting at http://localhost:12755\nRemoving container %s will erase its Torkitten identity and state.\n' "$name"
