#!/usr/bin/env bash
# Copyright 2026 The Torkitten Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
unformatted=$(find cmd internal mobile -type f -name '*.go' -print0 | xargs -0 -r gofmt -l)
if [[ -n "$unformatted" ]]; then
    printf 'gofmt required:\n%s\n' "$unformatted" >&2
    exit 1
fi
for script in tools/*.sh tools/build/*.sh; do bash -n "$script"; done
node --check internal/ui/assets/app.js
go vet ./...
go test -race ./...
total=$(find cmd internal mobile -type f -name '*.go' ! -name '*_test.go' -print0 | xargs -0 -r cat | wc -l)
(( total <= 5000 )) || { echo "production Go: $total/5000 lines" >&2; exit 1; }
printf '%-38s %4d/5000\n' 'total production Go (including mobile)' "$total"
