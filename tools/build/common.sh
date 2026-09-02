#!/usr/bin/env bash

build_script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source_root=${TORKITTEN_SOURCE_ROOT:-$(cd "$build_script_dir/../.." && pwd -P)}
build_root=${TORKITTEN_BUILD_ROOT:-/run/media/user/Data/TorkittenBuild}
jobs=${TORKITTEN_BUILD_JOBS:-$(nproc)}

mkdir -p "$build_root/artifacts/third-party" "$build_root/cache/go-build" \
    "$build_root/cache/go-mod" "$build_root/work"

source_real=$(realpath "$source_root")
build_real=$(realpath "$build_root")
case "$build_real/" in
    "$source_real/"*)
        echo "TORKITTEN_BUILD_ROOT must be outside the repository" >&2
        exit 1
        ;;
esac

lock_value() {
    local component=$1
    local field=$2
    sed -n "s/^${field} = \"\(.*\)\"$/\1/p" \
        "$source_real/third-party/${component}.upstream.toml"
}

component_recipe_hash() {
    local component=$1
    (
        cd "$source_real"
        sha256sum \
            "third-party/${component}.upstream.toml" \
            tools/build/Containerfile \
            tools/build/common.sh \
            "tools/build/${component}.sh"
    ) | sha256sum | cut -d ' ' -f 1
}

component_build_key() {
    local component=$1
    local release tree recipe_hash
    release=$(lock_value "$component" release)
    tree=$(lock_value "$component" tree)
    recipe_hash=$(component_recipe_hash "$component")
    printf 'ubuntu-24.04-%s-%s-%s-%s\n' \
        "$(uname -m)" "$release" "${tree:0:12}" "${recipe_hash:0:16}"
}

prepare_component_build() {
    local component=$1
    local build_key artifact_dir
    build_key=$(component_build_key "$component")
    artifact_dir="$build_real/artifacts/third-party/$component/$build_key"

    if [[ -f "$artifact_dir/.complete" ]]; then
        echo "Reusing $artifact_dir"
        return 10
    fi
    if [[ -e "$artifact_dir" ]]; then
        echo "Incomplete artifact directory exists: $artifact_dir" >&2
        exit 1
    fi

    COMPONENT_BUILD_KEY=$build_key
    COMPONENT_ARTIFACT_DIR=$artifact_dir
    COMPONENT_WORK_DIR=$(mktemp -d "$build_real/work/${component}.XXXXXX")
    COMPONENT_STAGE_DIR="$COMPONENT_WORK_DIR/stage"
}

publish_component_build() {
    local stage_dir=$1
    local artifact_dir=$2
    touch "$stage_dir/.complete"
    mkdir -p "$(dirname "$artifact_dir")"
    mv "$stage_dir" "$artifact_dir"
    echo "Built $artifact_dir"
}
