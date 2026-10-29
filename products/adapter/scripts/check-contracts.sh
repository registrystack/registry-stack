#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$repo_root"

# The verification floor from products/adapter/DELIVERY-PLAN.md: format
# over the workspace, then clippy and tests over the adapter crates. Every
# cargo invocation pins the shared target directory and cargo's PATH so
# concurrent streams serialize on one build tree.
CARGO_TARGET_DIR=/Volumes/CodexWorktrees/target/live-adapter PATH="$HOME/.cargo/bin:$PATH" cargo fmt --check
CARGO_TARGET_DIR=/Volumes/CodexWorktrees/target/live-adapter PATH="$HOME/.cargo/bin:$PATH" cargo clippy -p registry-adapter -p registry-adapter-core -p registry-adapterctl --all-targets -- -D warnings
CARGO_TARGET_DIR=/Volumes/CodexWorktrees/target/live-adapter PATH="$HOME/.cargo/bin:$PATH" cargo test -p registry-adapter -p registry-adapter-core -p registry-adapterctl --locked

printf 'Adapter product contracts passed\n'
