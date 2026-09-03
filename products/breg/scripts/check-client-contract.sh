#!/usr/bin/env bash
set -euo pipefail

# BReg client behavior is product-owned. The neutral record decoder is tested
# beside it because both BReg and Relay rely on its strict JSON boundary.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

cargo test --locked -p registry-record
cargo test --locked -p registry-breg-client
cargo test --locked -p registry-stack-client

echo "BReg client contract passed"
