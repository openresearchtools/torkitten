#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=common.sh
source "$script_dir/common.sh"

if prepare_component_build caddy; then
    :
else
    status=$?
    [[ $status -eq 10 ]] && exit 0
    exit "$status"
fi

release=$(lock_value caddy release)
tree=$(lock_value caddy tree)
commit=$(lock_value caddy commit)
tag_object=$(lock_value caddy tag_object)
recipe_hash=$(component_recipe_hash caddy)
work_dir=$COMPONENT_WORK_DIR
stage_dir=$COMPONENT_STAGE_DIR
artifact_dir=$COMPONENT_ARTIFACT_DIR

mkdir -p "$stage_dir/usr/bin"
cp -a "$source_real/third-party/caddy" "$work_dir/source"
(
    cd "$work_dir/source"
    CGO_ENABLED=0 \
    GOCACHE="$build_real/cache/go-build" \
    GOMODCACHE="$build_real/cache/go-mod" \
    go build \
        -buildvcs=false \
        -mod=readonly \
        -trimpath \
        -ldflags="-s -w -X github.com/caddyserver/caddy/v2.CustomVersion=$release" \
        -o "$stage_dir/usr/bin/caddy" \
        ./cmd/caddy
)

license_path=usr/share/doc/torkitten/third-party/caddy/LICENSE
mkdir -p "$stage_dir/$(dirname "$license_path")"
cp "$source_real/third-party/caddy/LICENSE" "$stage_dir/$license_path"
{
    printf 'component=caddy\n'
    printf 'baseline=ubuntu-24.04\n'
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'release=%s\n' "$release"
    printf 'source_tag_object=%s\n' "$tag_object"
    printf 'source_commit=%s\n' "$commit"
    printf 'source_tree=%s\n' "$tree"
    printf 'recipe_sha256=%s\n' "$recipe_hash"
    printf 'build_key=%s\n' "$COMPONENT_BUILD_KEY"
    printf 'cgo_enabled=0\n'
    printf 'go_build_flags=-buildvcs=false -mod=readonly -trimpath\n'
    printf 'go_ldflags=-s -w -X github.com/caddyserver/caddy/v2.CustomVersion=%s\n' "$release"
    printf 'go_version=%s\n' "$(go version)"
    printf 'license=%s\n' "$license_path"
    printf 'binary_sha256=%s\n' "$(sha256sum "$stage_dir/usr/bin/caddy" | cut -d ' ' -f 1)"
} > "$stage_dir/BUILD-METADATA"

"$stage_dir/usr/bin/caddy" version
publish_component_build "$stage_dir" "$artifact_dir"
