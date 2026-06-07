#!/bin/sh
set -eu

repo="jeremi/registry-registryctl"
version="${REGISTRYCTL_VERSION:-snapshot}"
install_dir="${REGISTRYCTL_INSTALL_DIR:-$HOME/.local/bin}"

usage() {
  cat <<'EOF'
Install registryctl.

Environment:
  REGISTRYCTL_VERSION      Release tag to install. Defaults to snapshot.
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
  echo "On Intel macOS, install from source for now: cargo install --git https://github.com/${repo} --branch main" >&2
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

if command -v shasum >/dev/null 2>&1; then
  curl -fsSL "$url.sha256" -o "$tmpdir/$asset.sha256"
  (
    cd "$tmpdir"
    shasum -a 256 -c "$asset.sha256"
  )
elif command -v sha256sum >/dev/null 2>&1; then
  curl -fsSL "$url.sha256" -o "$tmpdir/$asset.sha256"
  (
    cd "$tmpdir"
    sha256sum -c "$asset.sha256"
  )
else
  echo "Warning: neither shasum nor sha256sum is available; skipping checksum verification." >&2
fi

mkdir -p "$install_dir"
tar -xzf "$tmpdir/$asset" -C "$tmpdir"
cp "$tmpdir/registryctl" "$install_dir/registryctl"
chmod 0755 "$install_dir/registryctl"

cat <<EOF
registryctl installed to $install_dir/registryctl

Try it:
  registryctl init spreadsheet-api my-first-api --sample benefits
  cd my-first-api
  registryctl start

EOF

case ":$PATH:" in
  *":$install_dir:"*) ;;
  *)
    echo "Add $install_dir to PATH to run registryctl from any shell." >&2
    ;;
esac
