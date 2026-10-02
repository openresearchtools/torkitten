#!/usr/bin/env bash
set -euo pipefail
repo_root=$(git rev-parse --show-toplevel)
"$repo_root/tools/build-local.sh" all
"$repo_root/tools/build-local.sh" app
