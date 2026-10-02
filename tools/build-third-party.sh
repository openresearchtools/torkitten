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
    authelia)
        exec "$script_dir/build/authelia.sh"
        ;;
    chisel)
        exec "$script_dir/build/chisel.sh"
        ;;
    age)
        exec "$script_dir/build/age.sh"
        ;;
    openssh)
        exec "$script_dir/build/openssh.sh"
        ;;
    native)
        exec "$script_dir/build/native.sh"
        ;;
    app)
        exec "$script_dir/build/app.sh"
        ;;
    all)
        "$script_dir/build/tor.sh"
        "$script_dir/build/caddy.sh"
        "$script_dir/build/authelia.sh"
        "$script_dir/build/chisel.sh"
        "$script_dir/build/age.sh"
        "$script_dir/build/openssh.sh"
        exec "$script_dir/build/native.sh"
        ;;
    *)
        echo "usage: $0 [tor|caddy|authelia|chisel|age|openssh|native|app|all]" >&2
        exit 2
        ;;
esac
