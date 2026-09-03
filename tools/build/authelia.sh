#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=common.sh
source "$script_dir/common.sh"

if prepare_component_build authelia; then
    :
else
    status=$?
    [[ $status -eq 10 ]] && exit 0
    exit "$status"
fi

release=$(lock_value authelia release)
tree=$(lock_value authelia tree)
commit=$(lock_value authelia commit)
tag_object=$(lock_value authelia tag_object)
recipe_hash=$(component_recipe_hash authelia)
work_dir=$COMPONENT_WORK_DIR
stage_dir=$COMPONENT_STAGE_DIR
artifact_dir=$COMPONENT_ARTIFACT_DIR

mkdir -p "$stage_dir/usr/bin"
cp -a "$source_real/third-party/authelia" "$work_dir/source"

(
    cd "$work_dir/source/web"
    pnpm install \
        --frozen-lockfile \
        --ignore-scripts \
        --store-dir "$build_real/cache/pnpm"
    pnpm build
)

rm -rf -- "$work_dir/source/internal/server/public_html/api"
cp -a "$work_dir/source/api" "$work_dir/source/internal/server/public_html/api"

build_date=$(git --git-dir="$build_real/vendor/mirrors/authelia.git" \
    log -1 --format=%cD "$commit" 2>/dev/null || printf 'Tue, 26 May 2026 10:09:21 +0000')
ldflags="-linkmode=external -s -w"
ldflags+=" -X github.com/authelia/authelia/v4/internal/utils.BuildBranch=release"
ldflags+=" -X github.com/authelia/authelia/v4/internal/utils.BuildTag=$release"
ldflags+=" -X github.com/authelia/authelia/v4/internal/utils.BuildCommit=$commit"
ldflags+=" -X 'github.com/authelia/authelia/v4/internal/utils.BuildDate=$build_date'"
ldflags+=" -X 'github.com/authelia/authelia/v4/internal/utils.BuildState=tagged clean'"
ldflags+=" -X github.com/authelia/authelia/v4/internal/utils.BuildExtra=torkitten"
ldflags+=" -X github.com/authelia/authelia/v4/internal/utils.BuildNumber=0"
(
    cd "$work_dir/source"
    CGO_ENABLED=1 \
    CGO_CFLAGS="-O2 -pipe -fno-plt -fstack-protector-strong" \
    CGO_CPPFLAGS="-D_FORTIFY_SOURCE=3" \
    CGO_LDFLAGS="-Wl,-O1,-sort-common,-as-needed,-z,relro,-z,now" \
    GOCACHE="$build_real/cache/go-build" \
    GOMODCACHE="$build_real/cache/go-mod" \
    GOTELEMETRY=off \
    go build \
        -buildmode=pie \
        -buildvcs=false \
        -mod=readonly \
        -trimpath \
        -ldflags="$ldflags" \
        -o "$stage_dir/usr/bin/authelia" \
        ./cmd/authelia
)

license_path=usr/share/doc/torkitten/third-party/authelia/LICENSE
mkdir -p "$stage_dir/$(dirname "$license_path")"
cp "$source_real/third-party/authelia/LICENSE" "$stage_dir/$license_path"
cp "$source_real/third-party/authelia/config.template.yml" \
    "$stage_dir/usr/share/doc/torkitten/third-party/authelia/configuration.template.yml"
{
    printf 'component=authelia\n'
    printf 'baseline=ubuntu-24.04\n'
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'release=%s\n' "$release"
    printf 'source_tag_object=%s\n' "$tag_object"
    printf 'source_commit=%s\n' "$commit"
    printf 'source_tree=%s\n' "$tree"
    printf 'recipe_sha256=%s\n' "$recipe_hash"
    printf 'build_key=%s\n' "$COMPONENT_BUILD_KEY"
    printf 'cgo_enabled=1\n'
    printf 'go_telemetry=off\n'
    printf 'runtime_metrics=forced_off_by_torkitten_supervisor\n'
    printf 'frontend_lockfile=web/pnpm-lock.yaml\n'
    printf 'go_build_flags=-buildmode=pie -buildvcs=false -mod=readonly -trimpath\n'
    printf 'go_version=%s\n' "$(go version)"
    printf 'node_version=%s\n' "$(node --version)"
    printf 'pnpm_version=%s\n' "$(pnpm --version)"
    printf 'license=%s\n' "$license_path"
    printf 'binary_sha256=%s\n' "$(sha256sum "$stage_dir/usr/bin/authelia" | cut -d ' ' -f 1)"
} > "$stage_dir/BUILD-METADATA"

AUTHELIA_TELEMETRY_METRICS_ENABLED=false \
    "$stage_dir/usr/bin/authelia" --version
publish_component_build "$stage_dir" "$artifact_dir"
