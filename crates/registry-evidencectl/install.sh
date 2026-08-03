#!/usr/bin/env bash
set -euo pipefail

repo="registrystack/registry-stack"
binaries=(evidence evidencectl mint)
# Release packaging replaces this empty value with the asset's canonical tag.
default_version=""
script_name="${BASH_SOURCE[0]:-}"
script_name="${script_name##*/}"
filename_version=""
if [[ "$script_name" =~ ^evidencectl-(v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))-install\.sh$ ]]; then
	filename_version="${BASH_REMATCH[1]}"
fi
if [ -n "$default_version" ] &&
	[ -n "$filename_version" ] &&
	[ "$default_version" != "$filename_version" ]; then
	echo "Refusing an installer whose embedded release does not match its filename." >&2
	exit 1
fi
default_version="${default_version:-$filename_version}"
version="${EVIDENCECTL_VERSION:-$default_version}"
if [ -n "$default_version" ] &&
	[ -n "${EVIDENCECTL_VERSION:-}" ] &&
	[ "$EVIDENCECTL_VERSION" != "$default_version" ]; then
	echo "Refusing a release override that does not match the released installer asset." >&2
	exit 1
fi
install_dir="${EVIDENCECTL_INSTALL_DIR:-$HOME/.local/bin}"
asset_dir="${EVIDENCECTL_ASSET_DIR:-}"

usage() {
	cat <<EOF
Install the Evidence toolset: the evidence runtime, the evidencectl adopter
tooling, and the mint token issuer.

The installer verifies every downloaded release asset against the release's
SHA256SUMS before anything reaches the install directory, and installs the
three binaries together or not at all. It does not verify release
authenticity. For a higher-assurance installation, follow the release
verification guide for the pinned tag, then rerun with EVIDENCECTL_ASSET_DIR
set to the verified directory:
  https://github.com/${repo}/blob/<version>/release/VERIFY.md

Environment:
  EVIDENCECTL_VERSION      Release tag to install. A released installer
                           embeds its tag and refuses a different override.
  EVIDENCECTL_INSTALL_DIR  Install directory. Defaults to ~/.local/bin.
  EVIDENCECTL_ASSET_DIR    Read already-downloaded release assets from this
                           directory instead of downloading them.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
	usage
	exit 0
fi

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "evidencectl installer needs '$1'." >&2
		exit 1
	fi
}

if [ -z "$version" ]; then
	echo "No release is pinned for this installer copy." >&2
	echo "Evidence binaries ship with releases that include them; set" >&2
	echo "EVIDENCECTL_VERSION to a pinned vMAJOR.MINOR.PATCH tag or run the" >&2
	echo "versioned evidencectl-<tag>-install.sh asset from a release." >&2
	exit 1
fi
if [[ ! "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
	echo "Refusing non-canonical release tag '$version'." >&2
	echo "Set EVIDENCECTL_VERSION to a pinned vMAJOR.MINOR.PATCH tag." >&2
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
	printf 'No prebuilt Evidence toolset asset is published for %s/%s.\n' "$os" "$arch" >&2
	printf 'Supported platforms: Linux amd64, Linux arm64, and macOS arm64.\n' >&2
	printf 'Check the published assets at https://github.com/%s/releases/tag/%s\n' "$repo" "$version" >&2
	exit 1
	;;
esac

base_url="https://github.com/${repo}/releases/download/${version}"
verify_url="https://github.com/${repo}/blob/${version}/release/VERIFY.md"
tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t evidencectl)"

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
	printf 'Installing verified local Evidence toolset %s assets for %s/%s...\n' \
		"$version" "$os_label" "$arch_label"
else
	printf 'Downloading the Evidence toolset %s for %s/%s...\n' \
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
		echo "evidencectl installer needs 'shasum' or 'sha256sum' for checksum verification." >&2
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
For a higher-assurance installation, follow the tag-frozen release
verification guide first, then rerun this installer with
EVIDENCECTL_ASSET_DIR set to that verified directory:
  $verify_url

EOF

mkdir -p "$install_dir"
stage_dir="$(mktemp -d "$install_dir/.evidencectl-install.XXXXXX")"
install_started=0
install_complete=0
# The saved copy under $tmpdir is itself the record that a binary was already
# installed, so rollback needs no parallel bookkeeping. Stock macOS bash is 3.2
# and has no associative array to keep that bookkeeping in.
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

# Replace the three binaries only after every one of them is staged and
# verified, so an interrupted update never leaves a mixed-version toolset.
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
  evidencectl keygen --help
  evidencectl new --help
  evidencectl fixtures --help

EOF

case ":$PATH:" in
*":$install_dir:"*) ;;
*)
	echo "Add $install_dir to PATH to run the Evidence toolset from any shell." >&2
	;;
esac
