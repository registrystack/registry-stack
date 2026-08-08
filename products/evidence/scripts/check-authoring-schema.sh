#!/bin/sh
set -eu

# The authoring-form JSON Schemas an editor reads are generated from the Rust
# types adopter tooling reads, and committed beside `evidencectl` because
# `evidencectl` embeds them. They are tooling, not part of the frozen Evidence
# Version 1 contract set, which is why this gate is separate from
# `check-contracts.sh`: the two directories carry different promises, and one
# script covering both would blur a boundary worth keeping legible.

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
committed_root="$repository_root/crates/registry-evidencectl/schemas/authoring"
temporary_root=$(mktemp -d)
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM
generated_root="$temporary_root/authoring"

if [ ! -d "$committed_root" ]; then
  echo "Evidence authoring schema directory is missing: $committed_root" >&2
  exit 1
fi

cd "$repository_root"
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked --quiet -p registry-evidence-authoring --features schema \
  --test authoring_schema
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked --quiet -p registry-evidence-authoring --features schema \
  --example authoring-schema -- --output "$generated_root"

if ! diff -ru "$committed_root" "$generated_root"; then
  echo 'Evidence authoring schemas differ from the committed artifacts.' >&2
  echo 'Regenerate them, then review the complete diff:' >&2
  echo '  cargo run -p registry-evidence-authoring --features schema --example authoring-schema -- --output crates/registry-evidencectl/schemas/authoring' >&2
  exit 1
fi

echo 'Evidence authoring schemas reproduce exactly.'
