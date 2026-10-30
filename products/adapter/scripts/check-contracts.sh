#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$repo_root"

# The verification floor from products/adapter/DELIVERY-PLAN.md: format
# over the workspace, then clippy and tests over the adapter crates. Cargo
# runs in the caller's environment: an exported CARGO_TARGET_DIR is
# honored, and cargo's own default (target/ in this repository) is used
# otherwise; PATH keeps cargo reachable when it is not on the caller's
# PATH.
PATH="$HOME/.cargo/bin:$PATH" cargo fmt --check
PATH="$HOME/.cargo/bin:$PATH" cargo clippy -p registry-adapter -p registry-adapter-core -p registry-adapterctl --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test -p registry-adapter -p registry-adapter-core -p registry-adapterctl --locked

# The generated schemas are held to their generator (CFG-SCHEMA-2), and the
# five adapter formats are held to the configuration-format convention
# (CFG-SCHEMA-1) with the platform lint that CI also runs.
PATH="$HOME/.cargo/bin:$PATH" cargo run --locked -p registry-adapterctl -- schemas --check --output-dir products/adapter/schemas
uv run --no-project --with PyYAML==6.0.2 python products/platform/scripts/check-config-conventions.py

printf 'Adapter product contracts passed\n'
