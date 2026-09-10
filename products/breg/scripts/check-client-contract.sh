#!/usr/bin/env bash
set -euo pipefail

# BReg client behavior is product-owned. The neutral record decoder is tested
# beside it because both BReg and Relay rely on its strict JSON boundary.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

python3 products/breg/scripts/check_client_capabilities.py
python3 -m unittest products/breg/scripts/test_check_client_capabilities.py
cargo test --locked -p registry-record
cargo test --locked -p registry-breg-client
cargo test --locked -p registry-stack-client
cargo test --locked -p registry-breg --test problem_code_catalogues

echo "BReg client contract passed"
