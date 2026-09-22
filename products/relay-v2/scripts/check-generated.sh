#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PRODUCT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
. "$REPO_ROOT/scripts/cargo-runtime-library-path.sh"

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
if [[ -z ${RELAYCTL_BIN:-} ]]; then
  RELAYCTL_BIN="$REPO_ROOT/target/debug/relayctl"
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
    registry_cargo_build "$REPO_ROOT" --locked -p registry-relayctl
elif [[ ! -x "$RELAYCTL_BIN" ]]; then
  echo "RELAYCTL_BIN is not executable: $RELAYCTL_BIN" >&2
  exit 2
fi

python3 "$SCRIPT_DIR/test_adopter_workflow.py" \
  --relayctl "$RELAYCTL_BIN" "$@"
