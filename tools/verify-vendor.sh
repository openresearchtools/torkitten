#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

index_tree=$(git write-tree)

for component in tor caddy; do
    source_path="third-party/$component"
    manifest="third-party/$component.upstream.toml"
    expected_tree=$(sed -n 's/^tree = "\([0-9a-f]\{40\}\)"$/\1/p' "$manifest")

    if [[ -z "$expected_tree" ]]; then
        echo "missing tree in $manifest" >&2
        exit 1
    fi

    actual_tree=$(git rev-parse "$index_tree:$source_path")
    if [[ "$actual_tree" != "$expected_tree" ]]; then
        echo "$component tree mismatch: expected $expected_tree, staged $actual_tree" >&2
        exit 1
    fi

    if ! git diff --quiet -- "$source_path"; then
        echo "$component has unstaged changes" >&2
        exit 1
    fi

    if [[ -n $(git ls-files --others -- "$source_path") ]] ||
       [[ -n $(git ls-files --others --ignored --exclude-standard -- "$source_path") ]]; then
        echo "$component contains untracked files" >&2
        exit 1
    fi

    echo "$component: $actual_tree"
done

