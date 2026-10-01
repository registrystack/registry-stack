#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <runtime-root> <package-dir>" >&2
    exit 2
fi

runtime_root=$1
package_dir=$2

architecture=$(dpkg --print-architecture)
case "$architecture" in
    amd64 | arm64) ;;
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

# Install one fixed Debian package into the runtime root and record it under
# status.d, so image scanners report the overlaid version rather than the one
# the Distroless base carries.
# Arguments: package name, exact version, amd64 SHA-256, arm64 SHA-256.
install_package() {
    package=$1
    version=$2
    case "$architecture" in
        amd64) checksum=$3 ;;
        arm64) checksum=$4 ;;
    esac

    archive="${package_dir}/${package}_${version}_${architecture}.deb"
    test -f "$archive" && test ! -L "$archive"
    test "$(dpkg-deb --field "$archive" Package)" = "$package"
    test "$(dpkg-deb --field "$archive" Version)" = "$version"
    test "$(dpkg-deb --field "$archive" Architecture)" = "$architecture"
    printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --strict
    mkdir -p "$runtime_root/var/lib/dpkg/status.d"
    dpkg-deb --control "$archive" "$temporary/$package"
    test -f "$temporary/$package/md5sums"
    dpkg-deb --extract "$archive" "$runtime_root"
    install -m 0644 \
        "$temporary/$package/md5sums" \
        "$runtime_root/var/lib/dpkg/status.d/${package}.md5sums"
    dpkg-deb --field "$archive" >"$runtime_root/var/lib/dpkg/status.d/${package}"
}

install_package libc6 2.41-12+deb13u4 \
    967aa62605721081c3eb2a17650611a792aa802d76a6511d1840242623d204c9 \
    8784eda966b189c777a384dac5ce009e8fc9b52d006926c5a013e7fa8aa688cc
install_package libssl3t64 3.5.7-1~deb13u3 \
    ff16bc048bcd7d1b256094450b79c77947d8e76fe2a24bd99b91021d591fa074 \
    d0681293a160392186c6ef85a165e40603d1628a099936137d24d391bd591f97
