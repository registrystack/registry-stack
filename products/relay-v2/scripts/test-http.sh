#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

cd "${REPO_ROOT}"
CARGO_INCREMENTAL=0 \
CARGO_PROFILE_DEV_DEBUG=0 \
CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked -p registry-relay-v2 --features tooling --test acceptance_http

CARGO_INCREMENTAL=0 \
CARGO_PROFILE_DEV_DEBUG=0 \
CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked -p registry-relay-v2 --test multi_resource_isolation

CARGO_INCREMENTAL=0 \
CARGO_PROFILE_DEV_DEBUG=0 \
CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked -p registry-relay-v2 --test sdmx_http

if [[ "${RELAY_V2_SDMX_CONFORMANCE:-0}" == "1" ]]; then
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
    cargo test --locked -p registry-relay-v2 --test sdmx_http \
      generated_sdmx_outputs_validate_against_digest_locked_official_schemas \
      -- --exact --ignored
fi
