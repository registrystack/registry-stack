#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <runtime-root> <package-dir>" >&2
    exit 2
fi

runtime_root=$1
package_dir=$2
version=2.41-12+deb13u4

architecture=$(dpkg --print-architecture)
case "$architecture" in
    amd64)
        archive="libc6_${version}_amd64.deb"
        checksum=967aa62605721081c3eb2a17650611a792aa802d76a6511d1840242623d204c9
        ;;
    arm64)
        archive="libc6_${version}_arm64.deb"
        checksum=8784eda966b189c777a384dac5ce009e8fc9b52d006926c5a013e7fa8aa688cc
        ;;
    *)
        echo "unsupported runtime architecture: $architecture" >&2
        exit 1
        ;;
esac

temporary=$(mktemp -d)
cleanup() {
    rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM

archive="${package_dir}/${archive}"
test -f "$archive" && test ! -L "$archive"
test "$(dpkg-deb --field "$archive" Package)" = libc6
test "$(dpkg-deb --field "$archive" Version)" = "$version"
test "$(dpkg-deb --field "$archive" Architecture)" = "$architecture"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --strict
mkdir -p "$runtime_root/var/lib/dpkg/status.d"
dpkg-deb --control "$archive" "$temporary/control"
test -f "$temporary/control/md5sums"
dpkg-deb --extract "$archive" "$runtime_root"
install -m 0644 \
    "$temporary/control/md5sums" \
    "$runtime_root/var/lib/dpkg/status.d/libc6.md5sums"
dpkg-deb --field "$archive" >"$runtime_root/var/lib/dpkg/status.d/libc6"
