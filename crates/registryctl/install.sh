#!/usr/bin/env bash
set -euo pipefail

repo="registrystack/registry-stack"
default_version="v0.12.2"
version="${REGISTRYCTL_VERSION:-$default_version}"
install_dir="${REGISTRYCTL_INSTALL_DIR:-$HOME/.local/bin}"
verify_url="https://github.com/${repo}/blob/main/release/VERIFY.md"

usage() {
	cat <<EOF
Install registryctl.

The installer verifies downloaded release assets against SHA256SUMS only.
Releases before v0.9.0 install the binary. Releases v0.9.0 and later install
the binary and matching release image lock. The installer does not verify
release authenticity. Evidence availability varies by release, and v0.8.0 is
unsigned. Follow the canonical release verification guide:
  $verify_url

Environment:
  REGISTRYCTL_VERSION      Pinned release tag to install. Defaults to v0.12.2.
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

if [[ ! "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
	echo "Refusing non-canonical registryctl release tag." >&2
	echo "Set REGISTRYCTL_VERSION to a pinned vMAJOR.MINOR.PATCH tag such as $default_version." >&2
	exit 1
fi

version_numbers="${version#v}"
version_major="${version_numbers%%.*}"
version_remainder="${version_numbers#*.}"
version_minor="${version_remainder%%.*}"
requires_image_lock=0
if ((version_major > 0 || version_minor >= 9)); then
	requires_image_lock=1
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
	if ((requires_image_lock)); then
		echo "Project generation also requires the checksum-verified ${version} image lock beside the installed binary." >&2
	fi
}

asset="registryctl-${version}-${os_label}-${arch_label}"
lock_asset="registryctl-${version}-image-lock.json"
base_url="https://github.com/${repo}/releases/download/${version}"
tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t registryctl)"

cleanup() {
	rm -rf "$tmpdir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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

if ((requires_image_lock)); then
	if ! download "$base_url/$lock_asset" "$tmpdir/$lock_asset"; then
		printf 'Could not download the matching registryctl image lock %s.\n' "$lock_asset" >&2
		printf 'The installer will not install a v0.9.0+ binary without its release image lock.\n' >&2
		exit 1
	fi
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
		echo "registryctl installer needs 'shasum' or 'sha256sum' for checksum verification." >&2
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

verify_asset "$asset"
if ((requires_image_lock)); then
	verify_asset "$lock_asset"
fi

if ((requires_image_lock)); then
	printf 'Integrity checks passed: %s and %s matched SHA256SUMS.\n' "$asset" "$lock_asset"
else
	printf 'Integrity check passed: %s matched SHA256SUMS.\n' "$asset"
fi
cat <<EOF
Authenticity check not performed by this installer.
Evidence availability varies by release, and v0.8.0 is unsigned.
Follow the canonical release verification guide to check available evidence:
  $verify_url

EOF

mkdir -p "$install_dir"
stage_dir="$(mktemp -d "$install_dir/.registryctl-install.XXXXXX")"
staged_binary="$stage_dir/registryctl"
staged_lock="$stage_dir/$lock_asset"
binary_path="$install_dir/registryctl"
lock_path="$install_dir/$lock_asset"
had_binary=0
had_lock=0
install_started=0
install_complete=0
rollback_install() {
	set +e
	if [ "$install_started" -eq 1 ] && [ "$install_complete" -eq 0 ]; then
		if [ "$had_binary" -eq 1 ]; then
			cp -p "$tmpdir/registryctl.previous" "$binary_path"
		else
			rm -f "$binary_path"
		fi
		if ((requires_image_lock)); then
			if [ "$had_lock" -eq 1 ]; then
				cp -p "$tmpdir/image-lock.previous" "$lock_path"
			else
				rm -f "$lock_path"
			fi
		fi
	fi
	rm -rf "$stage_dir"
}
trap 'rollback_install; cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cp "$tmpdir/$asset" "$staged_binary"
chmod 0755 "$staged_binary"
if ((requires_image_lock)); then
	cp "$tmpdir/$lock_asset" "$staged_lock"
	chmod 0644 "$staged_lock"
fi

if [ -e "$binary_path" ]; then
	cp -p "$binary_path" "$tmpdir/registryctl.previous"
	had_binary=1
fi
if ((requires_image_lock)) && [ -e "$lock_path" ]; then
	cp -p "$lock_path" "$tmpdir/image-lock.previous"
	had_lock=1
fi

# Install a required lock first so an interrupted update never exposes a new
# binary without the exact release evidence it needs for project generation.
install_started=1
if ((requires_image_lock)); then
	mv -f "$staged_lock" "$lock_path"
fi
mv -f "$staged_binary" "$binary_path"
install_complete=1

printf 'registryctl installed to %s\n' "$binary_path"
if ((requires_image_lock)); then
	printf 'release image lock installed to %s\n' "$lock_path"
fi
cat <<EOF

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
