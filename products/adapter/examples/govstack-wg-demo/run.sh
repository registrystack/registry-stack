#!/usr/bin/env bash
set -euo pipefail

script_path="${BASH_SOURCE[0]}"
if [[ "$script_path" != /* ]]; then
	script_path="$PWD/$script_path"
fi
script_dir="${script_path%/*}"
repo_root="$script_dir/../../../.."
target_dir="${CARGO_TARGET_DIR:-}"
state_dir="${WG_DEMO_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/registry-adapter/govstack-wg-demo}"
controller="$script_dir/control.mjs"

usage() {
	printf 'Usage: %s {start|status|test|stop} [controller options]\n' "${0##*/}" >&2
}

if (($# == 0)); then
	usage
	exit 2
fi

command_name=$1
shift

case "$command_name" in
start | status | test | stop) ;;
*)
	usage
	exit 2
	;;
esac

if [[ -z "$target_dir" ]]; then
	printf 'Set CARGO_TARGET_DIR to an existing Cargo target directory outside the checkout.\n' >&2
	exit 2
fi

if [[ ! -d "$target_dir" ]]; then
	printf 'Cargo target directory does not exist: %s\n' "$target_dir" >&2
	exit 1
fi

if [[ ! -f "$controller" ]]; then
	printf 'Demo controller does not exist: %s\n' "$controller" >&2
	exit 1
fi

if ! command -v node >/dev/null 2>&1; then
	printf 'Node.js is required to run the demo controller.\n' >&2
	exit 1
fi

# shellcheck disable=SC1091
source "$repo_root/scripts/cargo-runtime-library-path.sh"

if [[ "$command_name" == start ]]; then
	export TMPDIR="${TMPDIR:-/private/tmp}"
	export CARGO_TARGET_DIR="$target_dir"
	export CARGO_INCREMENTAL=0
	export CARGO_PROFILE_DEV_DEBUG=0
	export CARGO_PROFILE_TEST_DEBUG=0
	export CARGO_BUILD_JOBS=6
	export PATH="$HOME/.cargo/bin:$PATH"
	registry_cargo_build "$repo_root" \
		--manifest-path "$repo_root/Cargo.toml" \
		-p registry-breg \
		-p registry-bregctl \
		-p registry-adapter \
		-p registry-adapterctl \
		--features registry-breg/runtime,registry-adapter/postgres-test \
		--locked
fi

exec node "$controller" "$command_name" \
	--state "$state_dir" \
	--target "$target_dir" \
	--repo "$repo_root" \
	"$@"
