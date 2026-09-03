#!/usr/bin/env bash
set -euo pipefail

version=0.1.0
architecture=amd64
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

context="$build_real/oci/context"
archive="$build_real/artifacts/torkitten_${version}_${architecture}.oci.tar"
case "$context" in
    "$build_real/oci/context") ;;
    *)
        echo "unsafe OCI staging path" >&2
        exit 1
        ;;
esac

./tools/cargo-local.sh build --locked --release \
    --bin torkittend --bin torkittenctl

rm -rf -- "$context"
install -d "$context/bin" "$context/licenses/torkitten" \
    "$context/licenses/tor" "$context/licenses/caddy" \
    "$build_real/artifacts"
install -m 0755 "$build_real/target/release/torkittend" "$context/bin/torkittend"
install -m 0755 "$build_real/target/release/torkittenctl" "$context/bin/torkittenctl"
install -m 0755 "$tor_real" "$context/bin/tor"
install -m 0755 "$caddy_real" "$context/bin/caddy"
install -m 0644 "$repo_real/LICENSE" "$context/licenses/torkitten/LICENSE"
install -m 0644 "$tor_artifact_root/BUILD-METADATA" \
    "$context/licenses/tor/BUILD-METADATA"
install -m 0644 \
    "$tor_artifact_root/usr/share/doc/torkitten/third-party/tor/LICENSE" \
    "$context/licenses/tor/LICENSE"
install -m 0644 "$caddy_artifact_root/BUILD-METADATA" \
    "$context/licenses/caddy/BUILD-METADATA"
install -m 0644 \
    "$caddy_artifact_root/usr/share/doc/torkitten/third-party/caddy/LICENSE" \
    "$context/licenses/caddy/LICENSE"

containerfile="$repo_real/packaging/oci/Containerfile"
containerfile_key=$(sha256sum "$repo_real/tools/build/Rust.Containerfile" | cut -c 1-16)
builder_image="localhost/torkitten-rust:ubuntu-24.04-$containerfile_key"
podman_args=(
    --root "$build_real/podman/storage"
    --runroot "$build_real/podman/runroot"
    --tmpdir "$build_real/podman/tmp"
)
if ! podman "${podman_args[@]}" image exists "$builder_image"; then
    podman "${podman_args[@]}" build \
        --file "$repo_real/tools/build/Rust.Containerfile" \
        --tag "$builder_image" \
        "$repo_real/tools/build"
fi

revision=$(git rev-parse HEAD)
source_date_epoch=$(git log -1 --format=%ct)
image="localhost/torkitten:$version"
podman "${podman_args[@]}" build \
    --file "$containerfile" \
    --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
    --build-arg "TORKITTEN_REVISION=$revision" \
    --tag "$image" \
    "$context"
podman "${podman_args[@]}" image inspect "$image" \
    --format '{{.Id}} {{.Config.User}} {{json .Config.Entrypoint}} {{json .Config.Cmd}}'
rm -f -- "$archive"
podman "${podman_args[@]}" save --format oci-archive --output "$archive" "$image"
sha256sum "$archive"
