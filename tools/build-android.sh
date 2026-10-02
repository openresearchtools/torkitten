#!/usr/bin/env bash
# Builds the Go AAR and compiles the thin Java shell; does not sign an APK.
set -euo pipefail
repo_root=$(git rev-parse --show-toplevel)
build_root=${TORKITTEN_BUILD_ROOT:-/run/media/user/Data/TorkittenV2Build}
: "${ANDROID_HOME:?Set ANDROID_HOME to the installed Android SDK (platform android-36 required)}"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to Android NDK 30.0.16248370}"
test -s "$ANDROID_HOME/platforms/android-36/android.jar"
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*30\.0\.16248370$' "$ANDROID_NDK_HOME/source.properties"
source "$repo_root/tools/build/common.sh"
"$repo_root/tools/verify-vendor.sh"
mkdir -p "$build_real/podman/storage" "$build_real/podman/runroot" "$build_real/podman/tmp" "$build_real/android"
args=(--root "$build_real/podman/storage" --runroot "$build_real/podman/runroot" --tmpdir "$build_real/podman/tmp")
key=$(sha256sum "$repo_root/native/android/Containerfile" | cut -c1-16)
image="localhost/torkitten-android-builder:$key"
if ! podman "${args[@]}" image exists "$image"; then
    podman "${args[@]}" build -f "$repo_root/native/android/Containerfile" -t "$image" "$repo_root/native/android"
fi
podman "${args[@]}" run --rm --userns=host \
    -v "$source_real:/src:ro" -v "$build_real:/work:rw" \
    -v "$(realpath "$ANDROID_HOME"):/android-sdk:ro" -v "$(realpath "$ANDROID_NDK_HOME"):/android-ndk:ro" \
    -e ANDROID_HOME=/android-sdk -e ANDROID_NDK_HOME=/android-ndk \
    -e GOMODCACHE=/work/cache/go-mod -e GOCACHE=/work/cache/go-build \
    "$image" /src/tools/build/android.sh
