#!/usr/bin/env bash
set -euo pipefail

# The runtime and client own these real-router journeys. Keeping the entry
# point product-owned makes CI and an adopter invoke the same acceptance gate.
repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$repository"

CARGO_BUILD_RUSTC_WRAPPER= CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked -p registry-discovery --test http_journey
CARGO_BUILD_RUSTC_WRAPPER= CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked -p registry-discovery-client --test native_journey
