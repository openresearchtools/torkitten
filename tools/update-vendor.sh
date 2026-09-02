#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <tor|caddy> <release-tag>" >&2
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
    *)
        echo "unknown component: $component" >&2
        exit 2
        ;;
esac

repo_root=$(git rev-parse --show-toplevel)
build_root=${TORKITTEN_BUILD_ROOT:-/run/media/user/Data/TorkittenBuild}
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
    git --git-dir="$mirror" fetch --prune origin "+refs/tags/$release:refs/tags/$release"
else
    git clone --mirror --filter=blob:none "$upstream" "$mirror"
fi

tag_object=$(git --git-dir="$mirror" rev-parse "refs/tags/$release")
commit=$(git --git-dir="$mirror" rev-parse "$release^{commit}")
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
tree = "$tree"

Then run:
  git add -f -- third-party/$component third-party/$component.upstream.toml
  tools/verify-vendor.sh
EOF
