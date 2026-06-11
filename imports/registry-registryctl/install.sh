#!/usr/bin/env bash
set -euo pipefail

repo="jeremi/registry-registryctl"
default_version="v0.1.0"
version="${REGISTRYCTL_VERSION:-$default_version}"
install_dir="${REGISTRYCTL_INSTALL_DIR:-$HOME/.local/bin}"

usage() {
	cat <<'EOF'
Install registryctl.

Environment:
  REGISTRYCTL_VERSION      Pinned release tag to install. Defaults to v0.1.0.
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

need curl
need tar
need uname

case "$version" in
latest | snapshot)
	echo "Refusing floating registryctl release tag: $version" >&2
	echo "Set REGISTRYCTL_VERSION to a pinned release tag such as $default_version." >&2
	exit 1
	;;
esac

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
x86_64 | amd64) arch_label="x86_64" ;;
arm64 | aarch64) arch_label="aarch64" ;;
*)
	echo "Unsupported architecture: $arch" >&2
	exit 1
	;;
esac

if [ "$os_label" = "macos" ] && [ "$arch_label" = "x86_64" ]; then
	echo "registryctl does not publish a macOS x86_64 binary yet." >&2
	echo "On Intel macOS, install from source for now: cargo install --git https://github.com/${repo} --tag ${version}" >&2
	exit 1
fi

asset="registryctl-${os_label}-${arch_label}.tar.gz"
url="https://github.com/${repo}/releases/download/${version}/${asset}"
tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t registryctl)"

cleanup() {
	rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

echo "Downloading registryctl ${version} for ${os_label}/${arch_label}..."
curl -fsSL "$url" -o "$tmpdir/$asset"
curl -fsSL "$url.sha256" -o "$tmpdir/$asset.sha256"

if command -v shasum >/dev/null 2>&1; then
	(
		cd "$tmpdir"
		shasum -a 256 -c "$asset.sha256"
	)
elif command -v sha256sum >/dev/null 2>&1; then
	(
		cd "$tmpdir"
		sha256sum -c "$asset.sha256"
	)
else
	echo "registryctl installer needs 'shasum' or 'sha256sum' for checksum verification." >&2
	exit 1
fi

mkdir -p "$install_dir"
tar -xzf "$tmpdir/$asset" -C "$tmpdir"
cp "$tmpdir/registryctl" "$install_dir/registryctl"
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
