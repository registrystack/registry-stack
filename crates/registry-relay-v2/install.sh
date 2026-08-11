#!/usr/bin/env bash
set -euo pipefail

repo="registrystack/registry-stack"
# Publication packaging replaces this empty value with the asset's canonical tag.
default_version=""
script_name="${BASH_SOURCE[0]:-}"
script_name="${script_name##*/}"
filename_version=""
if [[ "$script_name" =~ ^relay-(v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))-install\.sh$ ]]; then
	filename_version="${BASH_REMATCH[1]}"
fi
if [ -n "$default_version" ] &&
	[ -n "$filename_version" ] &&
	[ "$default_version" != "$filename_version" ]; then
	echo "Refusing an installer whose embedded release does not match its filename." >&2
	exit 1
fi
default_version="${default_version:-$filename_version}"
version="${RELAY_VERSION:-$default_version}"
if [ -n "$default_version" ] &&
	[ -n "${RELAY_VERSION:-}" ] &&
	[ "$RELAY_VERSION" != "$default_version" ]; then
	echo "Refusing a release override that does not match the released installer asset." >&2
	exit 1
fi
install_dir="${RELAY_INSTALL_DIR:-$HOME/.local/bin}"
asset_dir="${RELAY_ASSET_DIR:-}"

usage() {
	cat <<EOF
Install the Registry Stack Relay runtime.

Published binary platform: Linux amd64.

Quick install:
  curl -fsSL https://github.com/${repo}/releases/latest/download/relay-install.sh | bash

The installer verifies the downloaded Relay binary against the release's
SHA256SUMS before anything reaches the install directory. It does not verify
release authenticity. For a higher-assurance installation, follow the release
verification guide for the pinned tag, then rerun with RELAY_ASSET_DIR set to
the verified directory:
  https://github.com/${repo}/blob/<version>/release/VERIFY.md

Environment:
  RELAY_VERSION      Relay tag to install. A published installer embeds its
                     tag and refuses a different override.
  RELAY_INSTALL_DIR  Install directory. Defaults to ~/.local/bin.
  RELAY_ASSET_DIR    Read already-downloaded release assets from this directory
                     instead of downloading them.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
	usage
	exit 0
fi

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "relay installer needs '$1'." >&2
		exit 1
	fi
}

if [ -z "$version" ]; then
	echo "No Relay tag is pinned for this installer copy." >&2
	echo "Set RELAY_VERSION to a pinned vMAJOR.MINOR.PATCH tag, or run a" >&2
	echo "published relay-<tag>-install.sh asset." >&2
	exit 1
fi
if [[ ! "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
	echo "Refusing a non-canonical Relay tag." >&2
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
*)
	printf 'No prebuilt Relay asset is published for %s/%s.\n' "$os" "$arch" >&2
	printf 'Supported platform: Linux amd64.\n' >&2
	printf 'Check the published assets at https://github.com/%s/releases/tag/%s\n' \
		"$repo" "$version" >&2
	exit 1
	;;
esac

asset="relay-${version}-${os_label}-${arch_label}"
base_url="https://github.com/${repo}/releases/download/${version}"
verify_url="https://github.com/${repo}/blob/${version}/release/VERIFY.md"
tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t relay)"

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
	printf 'Installing verified local Relay %s asset for %s/%s...\n' \
		"$version" "$os_label" "$arch_label"
else
	printf 'Downloading Relay %s for %s/%s...\n' \
		"$version" "$os_label" "$arch_label"
fi

if ! download "$base_url/$asset" "$tmpdir/$asset"; then
	printf 'Could not read the published Relay %s binary for %s/%s.\n' \
		"$version" "$os_label" "$arch_label" >&2
	printf 'Check the published assets at https://github.com/%s/releases/tag/%s\n' \
		"$repo" "$version" >&2
	exit 1
fi
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
		echo "relay installer needs 'shasum' or 'sha256sum' for checksum verification." >&2
		exit 1
	fi
	printf '%s\n' "${result%% *}"
}

expected_hash="$(awk -v expected_asset="$asset" '$2 == expected_asset {print $1}' "$tmpdir/SHA256SUMS")"
if [ -z "$expected_hash" ]; then
	echo "SHA256SUMS has no entry for $asset" >&2
	exit 1
fi
actual_hash="$(sha256_file "$tmpdir/$asset")"
if [ "$actual_hash" != "$expected_hash" ]; then
	echo "Checksum verification failed for $asset" >&2
	echo "Expected: $expected_hash" >&2
	echo "Actual:   $actual_hash" >&2
	exit 1
fi

printf 'Integrity check passed: %s matched SHA256SUMS.\n' "$asset"
cat <<EOF
Authenticity check not performed by this installer.
For a higher-assurance installation, follow the tag-frozen release verification
guide first, then rerun this installer with RELAY_ASSET_DIR set to that verified
directory:
  $verify_url

EOF

mkdir -p "$install_dir"
stage_dir="$(mktemp -d "$install_dir/.relay-install.XXXXXX")"
trap 'rm -rf "$stage_dir"; cleanup' EXIT
cp "$tmpdir/$asset" "$stage_dir/relay"
chmod 0755 "$stage_dir/relay"
mv -f "$stage_dir/relay" "$install_dir/relay"
rm -rf "$stage_dir"

printf 'relay installed to %s\n' "$install_dir/relay"
cat <<EOF

Try it:
  relay --help
  relay healthcheck --help

EOF

case ":$PATH:" in
*":$install_dir:"*) ;;
*) echo "Add $install_dir to PATH to run Relay from any shell." >&2 ;;
esac
