#!/usr/bin/env bash
set -euo pipefail

# Build every Registry Stack command from this checkout and link it into an
# install directory, so unreleased changes are testable as plain commands.
# The published product installers only install tagged release assets; this
# script covers the gap for local working-tree builds.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

profile="release"
install_dir="${REGISTRY_INSTALL_DIR:-$HOME/.local/bin}"

usage() {
	cat <<'EOF'
Build every Registry Stack binary from this checkout and link it as plain
commands, for testing unreleased versions.

Usage:
  scripts/install-local.sh [--profile <profile>] [--install-dir <dir>]

The commands are absolute symlinks into the cargo target directory, so a
rebuild plus a rerun of this script refreshes every command at once.

Options:
  --profile <profile>     Cargo profile to build with. Default: release.
                          The dev profile lands in target/debug; a custom
                          profile such as ci lands in target/<profile>.
  --install-dir <dir>     Directory to link the commands into.
                          Default: $HOME/.local/bin, or $REGISTRY_INSTALL_DIR
                          when set.

Installed commands:
  breg bregctl casework caseworkctl discovery discoveryctl evidence
  evidence-oid4vci evidencectl registry-manifest relay relayctl
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	--profile | --install-dir)
		if [ "$#" -lt 2 ]; then
			printf '%s needs a value.\n' "$1" >&2
			exit 2
		fi
		if [ "$1" = "--profile" ]; then
			profile="$2"
		else
			install_dir="$2"
		fi
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		printf 'unknown argument: %s\n' "$1" >&2
		printf 'usage: scripts/install-local.sh [--profile <profile>] [--install-dir <dir>]\n' >&2
		exit 2
		;;
	esac
done

case "$profile" in
dev) target_subdir="debug" ;;
*) target_subdir="$profile" ;;
esac
bin_dir="$repo_root/target/$target_subdir"

binaries=(
	breg
	bregctl
	casework
	caseworkctl
	discovery
	discoveryctl
	evidence
	evidence-oid4vci
	evidencectl
	registry-manifest
	relay
	relayctl
)

cd "$repo_root"

# The invocation grouping follows release/scripts/build-release-binaries.sh.
# bregctl and relayctl enable authoring-only tooling features on their server
# libraries, and one cargo invocation unifies features across everything it
# builds, so the breg and relay servers build apart from them to keep the
# production feature set.
cargo build --locked --profile "$profile" \
	-p registry-manifest-cli \
	-p registry-evidence \
	-p registry-evidencectl \
	-p registry-evidence-oid4vci \
	-p registry-discovery \
	-p registry-discoveryctl \
	-p registry-casework \
	-p registry-caseworkctl

cargo build --locked --profile "$profile" \
	-p registry-breg --bin breg --features runtime

cargo build --locked --profile "$profile" \
	-p registry-relay-v2 --bin relay --no-default-features

cargo build --locked --profile "$profile" \
	-p registry-bregctl \
	-p registry-relayctl

for binary in "${binaries[@]}"; do
	if [ ! -x "$bin_dir/$binary" ]; then
		printf 'The %s profile build produced no executable %s at %s.\n' \
			"$profile" "$binary" "$bin_dir/$binary" >&2
		exit 1
	fi
done

mkdir -p "$install_dir"
for binary in "${binaries[@]}"; do
	dest="$install_dir/$binary"
	if [ -e "$dest" ] && [ ! -L "$dest" ]; then
		printf 'Replacing %s, which was a file rather than a symlink.\n' "$dest"
	fi
	ln -sfn "$bin_dir/$binary" "$dest"
	printf '%s -> %s\n' "$dest" "$bin_dir/$binary"
done

case ":$PATH:" in
*":$install_dir:"*) ;;
*) printf 'Add %s to PATH to run these commands from any shell.\n' "$install_dir" >&2 ;;
esac
