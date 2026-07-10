#!/usr/bin/env bash
set -euo pipefail

repo="registrystack/registry-stack"
default_version="v0.8.4"
version="${REGISTRYCTL_VERSION:-$default_version}"
install_dir="${REGISTRYCTL_INSTALL_DIR:-$HOME/.local/bin}"
verify_url="https://github.com/${repo}/blob/main/release/VERIFY.md"

usage() {
	cat <<EOF
Install registryctl.

The installer verifies the downloaded binary against SHA256SUMS only. It does
not verify release authenticity. Evidence availability varies by release, and
v0.8.0 is unsigned. Follow the canonical release verification guide:
  $verify_url

Environment:
  REGISTRYCTL_VERSION      Pinned release tag to install. Defaults to v0.8.4.
  REGISTRYCTL_INSTALL_DIR  Install directory. Defaults to ~/.local/bin.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
	usage
	exit 0
fi

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "registryctl installer needs '$1'." >&2
		exit 1
	fi
}

need grep

if ! printf '%s\n' "$version" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
	echo "Refusing non-canonical registryctl release tag." >&2
	echo "Set REGISTRYCTL_VERSION to a pinned vMAJOR.MINOR.PATCH tag such as $default_version." >&2
	exit 1
fi

need curl
need uname

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
Linux) os_label="linux" ;;
Darwin) os_label="macos" ;;
*)
	echo "Unsupported OS: $os" >&2
	exit 1
	;;
esac

case "$arch" in
x86_64 | amd64) arch_label="amd64" ;;
arm64 | aarch64) arch_label="arm64" ;;
*)
	echo "Unsupported architecture: $arch" >&2
	exit 1
	;;
esac

source_hint() {
	echo "Install registryctl from source instead:" >&2
	echo "  cargo install --git https://github.com/${repo} --tag ${version} registryctl --locked" >&2
}

asset="registryctl-${version}-${os_label}-${arch_label}"
base_url="https://github.com/${repo}/releases/download/${version}"
tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t registryctl)"

cleanup() {
	rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

download() {
	local src="$1"
	local dest="$2"
	curl -fsSL "$src" -o "$dest" 2>/dev/null
}

echo "Downloading registryctl ${version} for ${os_label}/${arch_label}..."
if ! download "$base_url/$asset" "$tmpdir/$asset"; then
	printf 'No registryctl %s binary published for %s/%s (HTTP 404 or download error).\n' "$version" "$os_label" "$arch_label" >&2
	printf 'Check the published assets at https://github.com/%s/releases/tag/%s\n' "$repo" "$version" >&2
	source_hint
	exit 1
fi

if ! download "$base_url/SHA256SUMS" "$tmpdir/SHA256SUMS"; then
	echo "Could not download SHA256SUMS for checksum verification." >&2
	exit 1
fi

expected_hash="$(awk -v asset="$asset" '$2 == asset {print $1}' "$tmpdir/SHA256SUMS")"
if [ -z "$expected_hash" ]; then
	echo "SHA256SUMS has no entry for $asset" >&2
	exit 1
fi

if command -v shasum >/dev/null 2>&1; then
	actual_hash="$(shasum -a 256 "$tmpdir/$asset")"
elif command -v sha256sum >/dev/null 2>&1; then
	actual_hash="$(sha256sum "$tmpdir/$asset")"
else
	echo "registryctl installer needs 'shasum' or 'sha256sum' for checksum verification." >&2
	exit 1
fi
actual_hash="${actual_hash%% *}"

if [ "$actual_hash" != "$expected_hash" ]; then
	echo "Checksum verification failed for $asset" >&2
	echo "Expected: $expected_hash" >&2
	echo "Actual:   $actual_hash" >&2
	exit 1
fi

cat <<EOF
Integrity check passed: $asset matched SHA256SUMS.
Authenticity check not performed by this installer.
Evidence availability varies by release, and v0.8.0 is unsigned.
Follow the canonical release verification guide to check available evidence:
  $verify_url

EOF

mkdir -p "$install_dir"
cp "$tmpdir/$asset" "$install_dir/registryctl"
chmod 0755 "$install_dir/registryctl"

cat <<EOF
registryctl installed to $install_dir/registryctl

Try it:
  registryctl init relay my-first-api --sample benefits
  cd my-first-api
  registryctl start

EOF

case ":$PATH:" in
*":$install_dir:"*) ;;
*)
	echo "Add $install_dir to PATH to run registryctl from any shell." >&2
	;;
esac
