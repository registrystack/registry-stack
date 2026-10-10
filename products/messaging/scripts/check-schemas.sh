#!/usr/bin/env bash
set -euo pipefail

# Every committed Messaging schema and the OpenAPI document are reproduced by
# their generators, never hand-edited. The drift tests compile only under the
# schema feature, which a default-feature test run leaves off, so this script
# is the gate that runs them. It needs no database.
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$repo_root"

export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
cargo test --locked --quiet -p registry-messaging --features schema --lib schema::tests
