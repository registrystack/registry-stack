#!/usr/bin/env bash
set -euo pipefail

# Server client behavior is product-owned. The neutral record decoder is tested
# beside it because both Server and Relay rely on its strict JSON boundary.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

cargo test --locked -p registry-record
cargo test --locked -p registry-server-client
cargo test --locked -p registry-stack-client

echo "Server client contract passed"
