#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=common.sh
source "$script_dir/common.sh"

if prepare_component_build age; then
    :
else
    status=$?
    [[ $status -eq 10 ]] && exit 0
    exit "$status"
fi

release=$(lock_value age release)
tree=$(lock_value age tree)
commit=$(lock_value age commit)
tag_object=$(lock_value age tag_object)
recipe_hash=$(component_recipe_hash age)
work_dir=$COMPONENT_WORK_DIR
stage_dir=$COMPONENT_STAGE_DIR
artifact_dir=$COMPONENT_ARTIFACT_DIR

mkdir -p "$stage_dir/usr/bin"
cp -a "$source_real/third-party/age" "$work_dir/source"
(
    cd "$work_dir/source"
    CGO_ENABLED=0 \
    GOTELEMETRY=off \
    GOCACHE="$build_real/cache/go-build" \
    GOMODCACHE="$build_real/cache/go-mod" \
    go build \
        -buildvcs=false \
        -mod=readonly \
        -trimpath \
        -ldflags="-s -w -X main.Version=$release" \
        -o "$stage_dir/usr/bin/age" \
        ./cmd/age
)

license_path=usr/share/doc/torkitten/third-party/age/LICENSE
mkdir -p "$stage_dir/$(dirname "$license_path")"
cp "$source_real/third-party/age/LICENSE" "$stage_dir/$license_path"
{
    printf 'component=age\n'
    printf 'baseline=ubuntu-24.04\n'
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'release=%s\n' "$release"
    printf 'source_tag_object=%s\n' "$tag_object"
    printf 'source_commit=%s\n' "$commit"
    printf 'source_tree=%s\n' "$tree"
    printf 'recipe_sha256=%s\n' "$recipe_hash"
    printf 'build_key=%s\n' "$COMPONENT_BUILD_KEY"
    printf 'cgo_enabled=0\n'
    printf 'go_telemetry=off\n'
    printf 'go_build_flags=-buildvcs=false -mod=readonly -trimpath\n'
    printf 'go_ldflags=-s -w -X main.Version=%s\n' "$release"
    printf 'go_version=%s\n' "$(go version)"
    printf 'license=%s\n' "$license_path"
    printf 'binary_sha256=%s\n' "$(sha256sum "$stage_dir/usr/bin/age" | cut -d ' ' -f 1)"
} > "$stage_dir/BUILD-METADATA"

"$stage_dir/usr/bin/age" --version
publish_component_build "$stage_dir" "$artifact_dir"
