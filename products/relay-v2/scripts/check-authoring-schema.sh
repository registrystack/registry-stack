#!/bin/sh
set -eu

# Relay V2 editor schemas are generated from the strict contract types the
# compiler reads and committed beside relayctl because relayctl embeds them.

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
committed_root="$repository_root/crates/registry-relayctl/schemas/authoring"
temporary_root=$(mktemp -d)
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM
generated_root="$temporary_root/authoring"

if [ ! -d "$committed_root" ]; then
  echo "Relay V2 authoring schema directory is missing: $committed_root" >&2
  exit 1
fi

cd "$repository_root"
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked --quiet -p registry-relay-v2 --features schema schema::tests
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked --quiet -p registry-relay-v2 --features schema \
  --test authoring_schema
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo run --locked --quiet -p registry-relay-v2 --features schema \
  --example authoring-schema -- --output "$generated_root"

if ! diff -ru "$committed_root" "$generated_root"; then
  echo 'Relay V2 authoring schemas differ from the committed artifacts.' >&2
  echo 'Regenerate them, then review the complete diff:' >&2
  echo '  cargo run -p registry-relay-v2 --features schema --example authoring-schema -- --output crates/registry-relayctl/schemas/authoring' >&2
  exit 1
fi

echo 'Relay V2 authoring schemas reproduce exactly.'
