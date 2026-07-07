#!/usr/bin/env bash
set -euo pipefail

product_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stack_root="$(cd "${product_root}/../.." && pwd)"

fail() {
  echo "registry-notary CI preflight failed: $*" >&2
  exit 2
}

run() {
  echo "==> registry-notary: $*"
  "$@"
}

command -v cargo >/dev/null 2>&1 || fail "cargo is required"

cd "${stack_root}"
run cargo metadata --locked --format-version 1 >/dev/null
run cargo check --locked -p registry-notary-server -p registry-notary --all-targets
