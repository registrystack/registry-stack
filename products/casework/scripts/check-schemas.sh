#!/bin/sh
set -eu
# Derive every maintained contract from the owning Rust DTOs and compiler.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$repo_root"
python3 products/casework/scripts/generate_openapi.py --check
python3 products/casework/scripts/generate_cli_schemas.py --check
cargo test --locked --offline -j2 -p registry-casework-core --features schema --lib schema::tests
cargo test --locked --offline -j2 -p registry-casework --features schema --lib schema::tests
cargo test --locked --offline -j2 -p registry-caseworkctl --features schema --lib schema::tests
cargo test --locked --offline -j2 -p registry-caseworkctl --features schema --lib report::typed_report_tests
