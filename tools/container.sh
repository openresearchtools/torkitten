#!/usr/bin/env bash
# Copyright 2026 The Torkitten Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

build_root=${TORKITTEN_BUILD_ROOT:-/run/media/user/Data/TorkittenBuild}
exec podman --root "$build_root/podman/storage" \
    --runroot "$build_root/podman/runroot" \
    --tmpdir "$build_root/podman/tmp" "$@"
