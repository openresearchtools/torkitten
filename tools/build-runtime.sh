#!/usr/bin/env bash
# Copyright 2026 The Torkitten Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
build_root=${TORKITTEN_BUILD_ROOT:-/run/media/user/Data/TorkittenV2Build}
# shellcheck source=build/common.sh
source "$repo_root/tools/build/common.sh"
image=${TORKITTEN_IMAGE:-localhost/torkitten:dev}
mkdir -p "$build_root/runtime" "$build_root/podman/storage" "$build_root/podman/runroot" "$build_root/podman/tmp"
case "$(realpath "$build_root")/" in "$(realpath "$repo_root")/"*) echo "build root must be outside the repository" >&2; exit 1;; esac
"$repo_root/tools/verify-vendor.sh"
"$repo_root/tools/test-local.sh"
context=$(mktemp -d "$build_root/runtime/context.XXXXXX")
trap 'rm -rf "$context"' EXIT
mkdir -p "$context/src" "$context/artifacts"
cp "$repo_root/Containerfile" "$repo_root/LICENSE" "$context/"
cp -a "$repo_root/licenses" "$context/"
cp "$repo_root/go.mod" "$repo_root/go.sum" "$context/src/"
cp -a "$repo_root/cmd" "$repo_root/internal" "$context/src/"
cp -a "$repo_root/runtime" "$context/"
for component in tor caddy authelia; do
    artifact_dir="$build_real/artifacts/third-party/$component/$(component_build_key "$component")"
    if [[ ! -f "$artifact_dir/.complete" ]]; then
        echo "current pinned $component artifact is required; run tools/build-local.sh $component" >&2
        exit 1
    fi
    cp -a "$artifact_dir" "$context/artifacts/$component"
done
podman_args=(--root "$build_root/podman/storage" --runroot "$build_root/podman/runroot" --tmpdir "$build_root/podman/tmp")
podman "${podman_args[@]}" build --file "$context/Containerfile" --tag "$image" "$context"
printf 'built %s\n' "$image"
