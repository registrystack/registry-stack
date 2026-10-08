#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
committed_root="$repository_root/products/evidence/generated"
temporary_root=$(mktemp -d)
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM
generated_root="$temporary_root/generated"

if [ ! -d "$committed_root" ]; then
  echo "Evidence generated contract directory is missing: $committed_root" >&2
  exit 1
fi

cd "$repository_root"
python3 products/evidence/scripts/generate-package-sums.py
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked --quiet -p registry-evidence --test security_contract_traceability
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked --quiet -p registry-evidence --example evidence-contracts -- \
  --output "$generated_root"
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked --quiet -p registry-evidence-oid4vci -- openapi \
  --output "$generated_root/registry-evidence-oid4vci.openapi.json"
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked --quiet -p registry-evidence-oid4vci --features schema \
  --example runtime-schema -- --output "$generated_root/oid4vci-runtime"
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked --quiet -p registry-evidence-client --features schema \
  --example client-schema -- --output "$generated_root"
# The code list JSON Schema, products/evidence/generated/codelist/codelist.schema.json,
# is derived from the reader types in crates/registry-evidence/src/codelist.rs.
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked --quiet -p registry-evidence --features schema --example codelist-schema -- \
  --output "$generated_root/codelist"
# The fixture JSON Schema, products/evidence/generated/fixture/fixture.schema.json,
# states what crates/registry-evidence/src/fixture.rs reads.
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked --quiet -p registry-evidence --features schema --example fixture-schema -- \
  --output "$generated_root/fixture"

if ! diff -ru "$committed_root" "$generated_root"; then
  echo 'Evidence generated contracts differ from the committed artifacts.' >&2
  echo 'Regenerate into a separate directory and review the complete contract diff.' >&2
  exit 1
fi

echo 'Evidence generated contracts reproduce exactly.'
