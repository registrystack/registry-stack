#!/usr/bin/env bash
set -euo pipefail

repo="registrystack/registry-stack"
binaries=(breg bregctl)
# Publication packaging replaces this empty value with the asset's canonical tag.
default_version=""
script_name="${BASH_SOURCE[0]:-}"
script_name="${script_name##*/}"
filename_version=""
if [[ "$script_name" =~ ^breg-(v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))-install\.sh$ ]]; then
	filename_version="${BASH_REMATCH[1]}"
fi
if [ -n "$default_version" ] &&
	[ -n "$filename_version" ] &&
	[ "$default_version" != "$filename_version" ]; then
	echo "Refusing an installer whose embedded release does not match its filename." >&2
	exit 1
fi
default_version="${default_version:-$filename_version}"
version="${BREG_VERSION:-$default_version}"
if [ -n "$default_version" ] &&
	[ -n "${BREG_VERSION:-}" ] &&
	[ "$BREG_VERSION" != "$default_version" ]; then
	echo "Refusing a release override that does not match the released installer asset." >&2
	exit 1
fi
install_dir="${BREG_INSTALL_DIR:-$HOME/.local/bin}"
asset_dir="${BREG_ASSET_DIR:-}"

usage() {
	cat <<EOF
Install the Base Registry Engine runtime and bregctl adopter tooling.

Quick install:
  curl -fsSL https://github.com/${repo}/releases/latest/download/breg-install.sh | bash

The installer verifies both downloaded release assets against the release's
SHA256SUMS before anything reaches the install directory, and installs both
binaries together or not at all. It does not verify release authenticity. For
a higher-assurance installation, follow the release verification guide for the
pinned tag, then rerun with BREG_ASSET_DIR set to the verified
directory:
  https://github.com/${repo}/blob/<version>/release/VERIFY.md

Environment:
  BREG_VERSION      Base Registry Engine tag to install. A published installer
                    embeds its tag and refuses a different override.
  BREG_INSTALL_DIR  Install directory. Defaults to ~/.local/bin.
  BREG_ASSET_DIR    Read already-downloaded release assets from this directory
                    instead of downloading them.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
	usage
	exit 0
fi

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "breg installer needs '$1'." >&2
		exit 1
	fi
}

if [ -z "$version" ]; then
	echo "No Base Registry Engine tag is pinned for this installer copy." >&2
	echo "Set BREG_VERSION to a pinned vMAJOR.MINOR.PATCH tag, or run a" >&2
	echo "published breg-<tag>-install.sh asset." >&2
	exit 1
fi
if [[ ! "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
	echo "Refusing a non-canonical Base Registry Engine tag." >&2
	echo "Use vMAJOR.MINOR.PATCH." >&2
	exit 1
fi

need uname
if [ -z "$asset_dir" ]; then
	need curl
fi

os="$(uname -s)"
arch="$(uname -m)"

case "$os/$arch" in
Linux/x86_64 | Linux/amd64)
	os_label="linux"
	arch_label="amd64"
	;;
Linux/arm64 | Linux/aarch64)
	os_label="linux"
	arch_label="arm64"
	;;
Darwin/arm64 | Darwin/aarch64)
	os_label="macos"
	arch_label="arm64"
	;;
*)
	printf 'No prebuilt Base Registry Engine asset is published for %s/%s.\n' "$os" "$arch" >&2
	printf 'Supported platforms: Linux amd64, Linux arm64, and macOS arm64.\n' >&2
	printf 'Check the published assets at https://github.com/%s/releases/tag/%s\n' \
		"$repo" "$version" >&2
	exit 1
	;;
esac

base_url="https://github.com/${repo}/releases/download/${version}"
verify_url="https://github.com/${repo}/blob/${version}/release/VERIFY.md"
tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t breg)"

cleanup() {
	rm -rf "$tmpdir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

download() {
	local src="$1"
	local dest="$2"
	if [ -n "$asset_dir" ]; then
		local name="${src##*/}"
		if [ ! -f "$asset_dir/$name" ]; then
			return 1
		fi
		cp "$asset_dir/$name" "$dest"
	else
		curl -fsSL "$src" -o "$dest" 2>/dev/null
	fi
}

if [ -n "$asset_dir" ]; then
	printf 'Installing verified local Base Registry Engine %s assets for %s/%s...\n' \
		"$version" "$os_label" "$arch_label"
else
	printf 'Downloading Base Registry Engine %s for %s/%s...\n' \
		"$version" "$os_label" "$arch_label"
fi

for binary in "${binaries[@]}"; do
	asset="${binary}-${version}-${os_label}-${arch_label}"
	if ! download "$base_url/$asset" "$tmpdir/$asset"; then
		printf 'Could not read the published %s %s binary for %s/%s.\n' \
			"$binary" "$version" "$os_label" "$arch_label" >&2
		printf 'Check the published assets at https://github.com/%s/releases/tag/%s\n' \
			"$repo" "$version" >&2
		exit 1
	fi
done
if ! download "$base_url/SHA256SUMS" "$tmpdir/SHA256SUMS"; then
	echo "Could not download SHA256SUMS for checksum verification." >&2
	exit 1
fi

sha256_file() {
	local path="$1"
	local result
	if command -v shasum >/dev/null 2>&1; then
		result="$(shasum -a 256 "$path")"
	elif command -v sha256sum >/dev/null 2>&1; then
		result="$(sha256sum "$path")"
	else
		echo "breg installer needs 'shasum' or 'sha256sum' for checksum verification." >&2
		exit 1
	fi
	printf '%s\n' "${result%% *}"
}

verify_asset() {
	local name="$1"
	local expected_hash actual_hash
	expected_hash="$(awk -v asset="$name" '$2 == asset {print $1}' "$tmpdir/SHA256SUMS")"
	if [ -z "$expected_hash" ]; then
		echo "SHA256SUMS has no entry for $name" >&2
		exit 1
	fi
	actual_hash="$(sha256_file "$tmpdir/$name")"
	if [ "$actual_hash" != "$expected_hash" ]; then
		echo "Checksum verification failed for $name" >&2
		echo "Expected: $expected_hash" >&2
		echo "Actual:   $actual_hash" >&2
		exit 1
	fi
}

for binary in "${binaries[@]}"; do
	verify_asset "${binary}-${version}-${os_label}-${arch_label}"
done
printf 'Integrity checks passed: %s binaries matched SHA256SUMS.\n' "${#binaries[@]}"
cat <<EOF
Authenticity check not performed by this installer.
For a higher-assurance installation, follow the tag-frozen release verification
guide first, then rerun this installer with BREG_ASSET_DIR set to
that verified directory:
  $verify_url

EOF

mkdir -p "$install_dir"
stage_dir="$(mktemp -d "$install_dir/.breg-install.XXXXXX")"
install_started=0
install_complete=0
rollback_install() {
	set +e
	if [ "$install_started" -eq 1 ] && [ "$install_complete" -eq 0 ]; then
		local binary
		for binary in "${binaries[@]}"; do
			if [ -f "$tmpdir/${binary}.previous" ]; then
				cp -p "$tmpdir/${binary}.previous" "$install_dir/$binary"
			else
				rm -f "$install_dir/$binary"
			fi
		done
	fi
	rm -rf "$stage_dir"
}
trap 'rollback_install; cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for binary in "${binaries[@]}"; do
	cp "$tmpdir/${binary}-${version}-${os_label}-${arch_label}" "$stage_dir/$binary"
	chmod 0755 "$stage_dir/$binary"
	if [ -e "$install_dir/$binary" ]; then
		cp -p "$install_dir/$binary" "$tmpdir/${binary}.previous"
	fi
done

# Replace both binaries only after each one is staged and verified, so an
# interrupted update never leaves a mixed-version Base Registry Engine toolset.
install_started=1
for binary in "${binaries[@]}"; do
	mv -f "$stage_dir/$binary" "$install_dir/$binary"
done
install_complete=1

for binary in "${binaries[@]}"; do
	printf '%s installed to %s\n' "$binary" "$install_dir/$binary"
done
cat <<EOF

Try it:
  bregctl init --help
  bregctl check --help
  breg --help

EOF

case ":$PATH:" in
*":$install_dir:"*) ;;
*) echo "Add $install_dir to PATH to run Base Registry Engine from any shell." >&2 ;;
esac
