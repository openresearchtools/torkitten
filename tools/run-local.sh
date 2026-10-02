#!/usr/bin/env bash
# Copyright 2026 The Torkitten Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
build_root=${TORKITTEN_BUILD_ROOT:-/run/media/user/Data/TorkittenV2Build}
bin_dir=$(realpath "$build_root/artifacts/app/bin")
for executable in torkitten torkitten-native tor caddy authelia sshd sshd-session sshd-auth; do
    test -x "$bin_dir/$executable" || { echo "Missing $executable; run tools/build-app.sh" >&2; exit 1; }
done
for prerequisite in /usr/bin/openssl /usr/bin/ssh-keygen; do
    test -x "$prerequisite" || { echo "Install host packages openssl and openssh-client ($prerequisite required)" >&2; exit 1; }
done
exec "$bin_dir/torkitten" --bin-dir "$bin_dir" "$@"
