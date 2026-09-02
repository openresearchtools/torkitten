#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=common.sh
source "$script_dir/common.sh"

if prepare_component_build tor; then
    :
else
    status=$?
    [[ $status -eq 10 ]] && exit 0
    exit "$status"
fi

release=$(lock_value tor release)
tree=$(lock_value tor tree)
commit=$(lock_value tor commit)
tag_object=$(lock_value tor tag_object)
recipe_hash=$(component_recipe_hash tor)
work_dir=$COMPONENT_WORK_DIR
stage_dir=$COMPONENT_STAGE_DIR
artifact_dir=$COMPONENT_ARTIFACT_DIR

mkdir -p "$stage_dir/usr"
cp -a "$source_real/third-party/tor" "$work_dir/source"
(
    cd "$work_dir/source"
    ./autogen.sh
)
mkdir "$work_dir/build"
(
    cd "$work_dir/build"
    CFLAGS="-O2 -pipe" \
    LDFLAGS="-Wl,-O1 -Wl,--as-needed" \
    "$work_dir/source/configure" \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --disable-asciidoc \
        --disable-html-manual \
        --disable-manpage \
        --enable-gcc-hardening \
        --enable-linker-hardening \
        --enable-seccomp \
        --enable-systemd
    make -j "$jobs"
    make DESTDIR="$stage_dir" install-strip
)

license_path=usr/share/doc/torkitten/third-party/tor/LICENSE
mkdir -p "$stage_dir/$(dirname "$license_path")"
cp "$source_real/third-party/tor/LICENSE" "$stage_dir/$license_path"
{
    printf 'component=tor\n'
    printf 'baseline=ubuntu-24.04\n'
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'release=%s\n' "$release"
    printf 'source_tag_object=%s\n' "$tag_object"
    printf 'source_commit=%s\n' "$commit"
    printf 'source_tree=%s\n' "$tree"
    printf 'recipe_sha256=%s\n' "$recipe_hash"
    printf 'build_key=%s\n' "$COMPONENT_BUILD_KEY"
    printf 'cflags=-O2 -pipe\n'
    printf 'ldflags=-Wl,-O1 -Wl,--as-needed\n'
    printf 'configure_flags=--prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-asciidoc --disable-html-manual --disable-manpage --enable-gcc-hardening --enable-linker-hardening --enable-seccomp --enable-systemd\n'
    printf 'cc_version=%s\n' "$(cc --version | head -n 1)"
    printf 'license=%s\n' "$license_path"
    printf 'binary_sha256=%s\n' "$(sha256sum "$stage_dir/usr/bin/tor" | cut -d ' ' -f 1)"
} > "$stage_dir/BUILD-METADATA"

"$stage_dir/usr/bin/tor" --version
publish_component_build "$stage_dir" "$artifact_dir"
