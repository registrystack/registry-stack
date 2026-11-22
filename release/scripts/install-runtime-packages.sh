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

	# Debian package file names leave out the version's epoch, which the
	# Version field checked below keeps.
	archive="${package_dir}/${package}_${version#*:}_${architecture}.deb"
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

install_package libc6 2.41-12+deb13u5 \
	b59b0625cd1a791375d40dab23a4d5d3d0641e3d0a773501becdc3725b7f99cf \
	0966fc3da1a26cc57647c68b5736f791b6e7eb498173a7993f63b6c89b4ed4f5
install_package libssl3t64 3.5.7-1~deb13u3 \
	ff16bc048bcd7d1b256094450b79c77947d8e76fe2a24bd99b91021d591fa074 \
	d0681293a160392186c6ef85a165e40603d1628a099936137d24d391bd591f97
install_package zlib1g 1:1.3.dfsg+really1.3.1-1+deb13u1 \
	8c27c342230503b73dfde629642c3b352e87b554e06d60cf58772f236a305ceb \
	0e41b3d7ad8ad7fcd36dd4d61ca91a70018478fc4af652e044f4be770784ddff
