#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$repo_root"
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
schema_dir=$(mktemp -d)
trap 'rm -rf "$schema_dir"' EXIT
cargo run --locked --quiet -p registry-coordinator --features schema --example project-schema -- --output "$schema_dir/project"
cargo run --locked --quiet -p registry-coordinator --features schema --example runtime-schema -- --output "$schema_dir/runtime"
cargo run --locked --quiet -p registry-coordinator --features schema --example scenario-schema -- --output "$schema_dir/scenarios"
diff -u products/coordinator/generated/project/project.schema.json "$schema_dir/project/project.schema.json"
diff -u products/coordinator/generated/runtime/runtime.schema.json "$schema_dir/runtime/runtime.schema.json"
diff -u products/coordinator/generated/scenarios/scenarios.schema.json "$schema_dir/scenarios/scenarios.schema.json"
# The OpenAPI document is reproduced by the command the README documents.
cargo run --locked --quiet -p registry-coordinator --bin coordinatorctl -- openapi >"$schema_dir/coordinator.openapi.json"
diff -u products/coordinator/generated/openapi/coordinator.openapi.json "$schema_dir/coordinator.openapi.json"
