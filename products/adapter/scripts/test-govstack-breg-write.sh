#!/usr/bin/env bash
set -euo pipefail

# Run the fixed GovStack Write journey through real Adapter and BReg
# processes. The Rust harness owns a fresh bregctl project and isolated
# Adapter schema, then stops the BReg development services without deleting
# their retained database volume.

: "${CARGO_TARGET_DIR:?Set CARGO_TARGET_DIR to the worktree Cargo target.}"
: "${ADAPTER_TEST_DATABASE_URL:?Set ADAPTER_TEST_DATABASE_URL to the maintained PostgreSQL test server.}"

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)

# shellcheck source=scripts/cargo-runtime-library-path.sh
source "$repo_root/scripts/cargo-runtime-library-path.sh"

if ! command -v docker >/dev/null 2>&1; then
	printf '%s\n' 'docker is required for the owned bregctl development fixture.' >&2
	exit 2
fi

if [[ "$#" -ne 0 ]]; then
	printf 'Usage: %s\n' "${BASH_SOURCE[0]}" >&2
	exit 2
fi

breg_bin=${BREG_BIN:-"$CARGO_TARGET_DIR/debug/breg"}
bregctl_bin=${BREGCTL_BIN:-"$CARGO_TARGET_DIR/debug/bregctl"}
docker_bin=$(command -v docker)
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0

printf '%s\n' 'Building the native BReg fixture binaries.' >&2
PATH="$HOME/.cargo/bin:$PATH" registry_cargo_build "$repo_root" \
	--manifest-path "$repo_root/Cargo.toml" --target-dir "$CARGO_TARGET_DIR" --locked \
	-p registry-bregctl -p registry-breg --features registry-breg/runtime --jobs 6

for binary in "$breg_bin" "$bregctl_bin" "$docker_bin"; do
	if [[ "$binary" != /* || ! -x "$binary" ]]; then
		printf 'The native journey requires an absolute executable path: %s\n' "$binary" >&2
		exit 2
	fi
done

printf '%s\n' 'Running the real BReg-backed GovStack Write journey.' >&2
BREG_TEST_BREG_BINARY="$breg_bin" \
	BREG_TEST_BREGCTL_BINARY="$bregctl_bin" \
	BREG_TEST_DOCKER_BINARY="$docker_bin" \
	PATH="$HOME/.cargo/bin:$PATH" cargo test --manifest-path "$repo_root/Cargo.toml" --locked \
	-p registry-adapter --features postgres-test --test govstack_breg_write --jobs 6 \
	real_breg_and_adapter_preserve_write_receipts_conditions_and_exact_recovery -- \
	--test-threads=1
