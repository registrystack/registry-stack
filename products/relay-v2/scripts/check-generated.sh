#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PRODUCT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if find "$PRODUCT_DIR/acceptance" -type f \( -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.db' \) -print -quit | grep -q .; then
  echo "relay-v2 generated check: generated SQLite database is tracked" >&2
  exit 1
fi

cd "$REPO_ROOT"
production_tree="$(cargo tree --locked -p registry-relay-v2 --no-default-features -e normal,features)"
if rg -q 'registry-platform-sqlite feature "fixture"|tempfile' <<<"$production_tree"; then
  echo "relay-v2 generated check: production Relay dependency graph includes fixture tooling" >&2
  exit 1
fi
CARGO_INCREMENTAL=0 \
CARGO_PROFILE_DEV_DEBUG=0 \
CARGO_PROFILE_TEST_DEBUG=0 \
  cargo build --locked -p registry-relayctl

python3 "$SCRIPT_DIR/test_adopter_workflow.py" \
  --relayctl "$REPO_ROOT/target/debug/relayctl" "$@"
