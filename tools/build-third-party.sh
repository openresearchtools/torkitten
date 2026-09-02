#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
requested_component=${1:-all}

case "$requested_component" in
    tor)
        exec "$script_dir/build/tor.sh"
        ;;
    caddy)
        exec "$script_dir/build/caddy.sh"
        ;;
    all)
        "$script_dir/build/tor.sh"
        exec "$script_dir/build/caddy.sh"
        ;;
    *)
        echo "usage: $0 [tor|caddy|all]" >&2
        exit 2
        ;;
esac
