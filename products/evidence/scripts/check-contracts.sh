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
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked --quiet -p registry-evidence --test security_contract_traceability
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked --quiet -p registry-evidence --example evidence-contracts -- \
  --output "$generated_root"
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked --quiet -p registry-evidence-oid4vci -- openapi \
  --output "$generated_root/registry-evidence-oid4vci.openapi.json"

if ! diff -ru "$committed_root" "$generated_root"; then
  echo 'Evidence generated contracts differ from the committed artifacts.' >&2
  echo 'Regenerate into a separate directory and review the complete contract diff.' >&2
  exit 1
fi

echo 'Evidence generated contracts reproduce exactly.'
