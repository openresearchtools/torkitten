#!/usr/bin/env bash
set -euo pipefail

version=0.1.0
architecture=amd64
package_root="/work/package/torkitten_${version}_${architecture}"
output="/work/artifacts/torkitten_${version}_${architecture}.deb"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}

case "$package_root" in
    /work/package/torkitten_*) ;;
    *)
        echo "unsafe package staging path" >&2
        exit 1
        ;;
esac

rm -rf -- "$package_root"
install -d \
    "$package_root/DEBIAN" \
    "$package_root/etc/apparmor.d" \
    "$package_root/etc/polkit-1/rules.d" \
    "$package_root/lib/systemd/system" \
    "$package_root/usr/bin" \
    "$package_root/usr/lib/torkitten" \
    "$package_root/usr/share/applications" \
    "$package_root/usr/share/doc/torkitten/third-party/tor" \
    "$package_root/usr/share/doc/torkitten/third-party/caddy" \
    "$package_root/usr/share/icons/hicolor/scalable/apps" \
    /work/artifacts

cargo build --locked --release --bins

install -m 0755 /work/target/release/torkittend "$package_root/usr/bin/torkittend"
install -m 0755 /work/target/release/torkittenctl "$package_root/usr/bin/torkittenctl"
install -m 0755 /work/target/release/torkitten-desktop "$package_root/usr/bin/torkitten-desktop"
install -m 0755 /inputs/tor "$package_root/usr/lib/torkitten/tor"
install -m 0755 /inputs/caddy "$package_root/usr/lib/torkitten/caddy"
install -m 0644 LICENSE "$package_root/usr/share/doc/torkitten/copyright"
install -m 0644 /inputs/tor-root/BUILD-METADATA \
    "$package_root/usr/share/doc/torkitten/third-party/tor/BUILD-METADATA"
install -m 0644 /inputs/tor-root/usr/share/doc/torkitten/third-party/tor/LICENSE \
    "$package_root/usr/share/doc/torkitten/third-party/tor/LICENSE"
install -m 0644 /inputs/caddy-root/BUILD-METADATA \
    "$package_root/usr/share/doc/torkitten/third-party/caddy/BUILD-METADATA"
install -m 0644 /inputs/caddy-root/usr/share/doc/torkitten/third-party/caddy/LICENSE \
    "$package_root/usr/share/doc/torkitten/third-party/caddy/LICENSE"

install -m 0644 packaging/debian/torkitten.desktop \
    "$package_root/usr/share/applications/torkitten.desktop"
install -m 0644 packaging/debian/torkitten.svg \
    "$package_root/usr/share/icons/hicolor/scalable/apps/torkitten.svg"
install -m 0644 packaging/debian/torkittend.service \
    "$package_root/lib/systemd/system/torkittend.service"
install -m 0644 packaging/debian/torkitten-tor.service \
    "$package_root/lib/systemd/system/torkitten-tor.service"
install -m 0644 packaging/debian/torkitten-caddy.service \
    "$package_root/lib/systemd/system/torkitten-caddy.service"
install -m 0644 packaging/debian/60-torkitten.rules \
    "$package_root/etc/polkit-1/rules.d/60-torkitten.rules"
install -m 0644 packaging/debian/torkitten.apparmor \
    "$package_root/etc/apparmor.d/torkitten"
install -m 0755 packaging/debian/postinst "$package_root/DEBIAN/postinst"
install -m 0755 packaging/debian/prerm "$package_root/DEBIAN/prerm"
install -m 0755 packaging/debian/postrm "$package_root/DEBIAN/postrm"

install -m 0644 packaging/debian/control "$package_root/DEBIAN/control"

find "$package_root" -exec touch -h --date="@$SOURCE_DATE_EPOCH" {} +
dpkg-deb --root-owner-group --build "$package_root" "$output"
dpkg-deb --info "$output"
sha256sum "$output"
