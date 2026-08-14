#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd "$script_dir/../../.." && pwd)
oracle_project="$repository_root/products/discovery/standards-oracle"
cd "$repository_root"
export UV_PROJECT_ENVIRONMENT="${UV_PROJECT_ENVIRONMENT:-$repository_root/target/discovery-standards-oracle-venv}"
PYTHONDONTWRITEBYTECODE=1 python3 "$script_dir/validate_contract_artifacts.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$script_dir/validate_profile_rdf.py" --check
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest "$script_dir/test_contract_artifacts.py"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest "$script_dir/test_profile_rdf.py"
command -v uv >/dev/null || {
  echo "uv is required to install the locked Discovery standards-oracle environment" >&2
  exit 1
}
# Dependency installation may use the package index. The oracle execution that
# follows is locked, no-sync, offline, and additionally denies socket connects.
uv sync --project "$oracle_project" --locked
uv run --project "$oracle_project" --locked --offline --no-sync \
  python -m unittest "$script_dir/test_standards_oracle.py"
CARGO_BUILD_RUSTC_WRAPPER= CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked --manifest-path "$repository_root/Cargo.toml" --quiet \
    -p registry-discovery --example openapi -- --check
CARGO_BUILD_RUSTC_WRAPPER= CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked --manifest-path "$repository_root/Cargo.toml" \
    -p registry-discoveryctl --test schema_contract
