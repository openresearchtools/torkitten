#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$script_dir/common.sh"
stage=$(mktemp -d "$build_real/work/app.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/bin" "$stage/licenses" "$stage/metadata" "$stage/docs"
for component in tor caddy authelia; do
    artifact="$build_real/artifacts/third-party/$component/$(component_build_key "$component")"
    test -f "$artifact/.complete" || { echo "Build $component first with tools/build-local.sh all" >&2; exit 1; }
    cp "$artifact/usr/bin/$component" "$stage/bin/"
    cp "$artifact/BUILD-METADATA" "$stage/metadata/$component"
    cp "$source_real/third-party/$component/LICENSE" "$stage/licenses/$component"
done
for component in chisel age gozxing; do cp "$source_real/third-party/$component/LICENSE" "$stage/licenses/$component"; done
cp "$source_real/LICENSE" "$stage/licenses/torkitten"
cp "$source_real/README.md" "$stage/README.md"
for document in native-builds-v2 v2-plan upstream-refresh-v2; do cp "$source_real/docs/$document.md" "$stage/docs/"; done
cp -a "$source_real/licenses" "$stage/licenses/go-dependencies"
"$script_dir/native.sh"
cp "$build_real/artifacts/native/bin/torkitten-native" "$stage/bin/"
(
    cd "$source_real"
    CGO_ENABLED=0 GOCACHE="$build_real/cache/go-build" GOMODCACHE="$build_real/cache/go-mod" \
        go build -mod=readonly -buildvcs=false -trimpath -o "$stage/bin/torkitten" ./cmd/torkitten
)
(cd "$stage"; sha256sum bin/* > SHA256SUMS)
artifact="$build_real/artifacts/app"
if [[ -e "$artifact" ]]; then mv "$artifact" "$stage.previous"; fi
mv "$stage" "$artifact"
rm -rf -- "$stage.previous"
trap - EXIT
printf 'Linux bundle: %s\n' "$artifact"
