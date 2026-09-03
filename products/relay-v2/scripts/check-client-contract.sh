#!/usr/bin/env bash
set -euo pipefail

# The Relay client intentionally owns no served route. Its independently
# versioned wire inventory is the client-facing contract, and it must stay
# testable without a running Relay process or acceptance fixture.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

cargo test --locked -p registry-relay-http-contract
cargo test --locked -p registry-record
cargo test --locked -p registry-relay-client

echo "Relay client contract passed"
