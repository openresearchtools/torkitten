#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$script_dir/common.sh"
if prepare_component_build openssh; then :; else status=$?; [[ $status -eq 10 ]] && exit 0; exit "$status"; fi
work_dir=$COMPONENT_WORK_DIR
stage_dir=$COMPONENT_STAGE_DIR
cp -a "$source_real/third-party/openssh" "$work_dir/source"
(
    cd "$work_dir/source"
    ./configure --prefix=/usr --sysconfdir=/etc/ssh --libexecdir=/usr/bin --without-pam
    make -j "$jobs" sshd sshd-session sshd-auth
)
mkdir -p "$stage_dir/usr/bin" "$stage_dir/usr/share/doc/torkitten/third-party/openssh"
for name in sshd sshd-session sshd-auth; do install -m 0755 "$work_dir/source/$name" "$stage_dir/usr/bin/$name"; done
cp "$source_real/third-party/openssh/LICENCE" "$stage_dir/usr/share/doc/torkitten/third-party/openssh/LICENSE"
{
    printf 'component=openssh\nbaseline=ubuntu-24.04\narchitecture=%s\n' "$(uname -m)"
    printf 'release=%s\nsource_tag_object=%s\nsource_commit=%s\nsource_tree=%s\n' "$(lock_value openssh release)" "$(lock_value openssh tag_object)" "$(lock_value openssh commit)" "$(lock_value openssh tree)"
    printf 'recipe_sha256=%s\nbuild_key=%s\n' "$(component_recipe_hash openssh)" "$COMPONENT_BUILD_KEY"
    printf 'configure_flags=--prefix=/usr --sysconfdir=/etc/ssh --libexecdir=/usr/bin --without-pam\n'
    printf 'license=usr/share/doc/torkitten/third-party/openssh/LICENSE\n'
    printf 'binary_sha256=%s\n' "$(sha256sum "$stage_dir/usr/bin/sshd" | cut -d ' ' -f 1)"
    for name in sshd-session sshd-auth; do printf '%s_sha256=%s\n' "$name" "$(sha256sum "$stage_dir/usr/bin/$name" | cut -d ' ' -f 1)"; done
} > "$stage_dir/BUILD-METADATA"
"$stage_dir/usr/bin/sshd" -V
publish_component_build "$stage_dir" "$COMPONENT_ARTIFACT_DIR"
