#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <tor|caddy|authelia|chisel|age|gozxing|openssh> <release-tag>" >&2
    exit 2
fi

component=$1
release=$2

case "$component" in
    tor)
        upstream=https://gitlab.torproject.org/tpo/core/tor.git
        ;;
    caddy)
        upstream=https://github.com/caddyserver/caddy.git
        ;;
    authelia)
        upstream=https://github.com/authelia/authelia.git
        ;;
    chisel)
        upstream=https://github.com/jpillora/chisel.git
        ;;
    age)
        upstream=https://github.com/FiloSottile/age.git
        ;;
    openssh)
        upstream=https://github.com/openssh/openssh-portable.git
        ;;
    gozxing)
        upstream=https://github.com/makiuchi-d/gozxing.git
        ;;
    *)
        echo "unknown component: $component" >&2
        exit 2
        ;;
esac

repo_root=$(git rev-parse --show-toplevel)
build_root=${TORKITTEN_BUILD_ROOT:-/run/media/user/Data/TorkittenV2Build}
mkdir -p "$build_root/vendor/mirrors" "$build_root/vendor/staging"

repo_real=$(realpath "$repo_root")
build_real=$(realpath "$build_root")
case "$build_real/" in
    "$repo_real/"*)
        echo "TORKITTEN_BUILD_ROOT must be outside the repository" >&2
        exit 1
        ;;
esac

mirror="$build_real/vendor/mirrors/$component.git"
if [[ -d "$mirror" ]]; then
    git --git-dir="$mirror" remote set-url origin "$upstream"
    git --git-dir="$mirror" fetch --no-tags --prune origin \
        "+refs/tags/$release:refs/tags/$release"
else
    git init --bare "$mirror"
    git --git-dir="$mirror" remote add origin "$upstream"
    git --git-dir="$mirror" fetch --no-tags --filter=blob:none origin \
        "+refs/tags/$release:refs/tags/$release"
fi

tag_object=$(git --git-dir="$mirror" rev-parse "refs/tags/$release")
commit=$(git --git-dir="$mirror" rev-parse "$release^{commit}")
committed_at=$(git --git-dir="$mirror" log -1 --format=%cI "$commit")
tree=$(git --git-dir="$mirror" rev-parse "$release^{tree}")
stage=$(mktemp -d "$build_real/vendor/staging/$component.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT

git --git-dir="$mirror" archive "$commit" | tar -xf - -C "$stage"

destination="$repo_real/third-party/$component"
if [[ "$destination" != "$repo_real/third-party/$component" ]]; then
    echo "invalid vendor destination" >&2
    exit 1
fi
mkdir -p "$destination"
rsync --archive --delete "$stage/" "$destination/"

cat <<EOF
Imported $component $release. Review the release and update:

release = "$release"
upstream = "$upstream"
tag_object = "$tag_object"
commit = "$commit"
committed_at = "$committed_at"
tree = "$tree"

Then run:
  git add -f -- third-party/$component third-party/$component.upstream.toml
  tools/verify-vendor.sh
EOF
