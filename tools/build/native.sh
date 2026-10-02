#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$script_dir/common.sh"
mkdir -p "$build_real/artifacts/native/bin"
cc -std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra -Werror \
    "$source_real/native/linux/main.c" \
    -o "$build_real/artifacts/native/bin/torkitten-native" \
    $(pkg-config --cflags --libs webkitgtk-6.0 libsoup-3.0)
printf 'Native launcher: %s\n' "$build_real/artifacts/native/bin/torkitten-native"
