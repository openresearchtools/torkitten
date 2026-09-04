#!/usr/bin/env bash
# Copyright 2026 The Torkitten Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

unformatted=$({ find cmd internal -type f -name '*.go' -print0 2>/dev/null || true; } | xargs -0 -r gofmt -l)
if [[ -n "$unformatted" ]]; then
    printf 'gofmt required:\n%s\n' "$unformatted" >&2
    exit 1
fi

node --check internal/api/assets/app.js
go vet ./...
go test -race ./...

check_budget() {
    local area=$1 limit=$2 count
    count=$({ find $area -type f -name '*.go' ! -name '*_test.go' -print0 2>/dev/null || true; } |
        xargs -0 -r cat | wc -l)
    if (( count > limit )); then
        echo "$area: $count/$limit lines" >&2
        exit 1
    fi
    printf '%-38s %4d/%d\n' "$area" "$count" "$limit"
}

check_budget 'cmd/torkitten cmd/torkittenctl' 180
check_budget internal/model 220
check_budget internal/state 280
check_budget internal/bootstrap 360
check_budget internal/authelia 340
check_budget internal/localsession 240
check_budget internal/tor 400
check_budget internal/caddy 400
check_budget internal/control 380
check_budget internal/supervisor 380
check_budget internal/api 600
check_budget internal/onboarding 260
check_budget internal/apitoken 160

total=$({ find cmd internal -type f -name '*.go' ! -name '*_test.go' -print0 2>/dev/null || true; } |
    xargs -0 -r cat | wc -l)
(( total <= 5000 )) || { echo "production Go: $total/5000 lines" >&2; exit 1; }
printf '%-38s %4d/5000\n' 'total production Go' "$total"
