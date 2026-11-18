#!/usr/bin/env bash
set -euo pipefail

# Holds the committed development plan and scenario schemas under
# products/platform/generated/dev to what the registry-rstack-dev reader types
# generate, and checks each format's committed example against its schema.

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
baseline="$repository_root/products/platform/generated/dev"
temporary_root=""

cleanup() {
  case "$temporary_root" in
    "$repository_root"/.rstack-dev-schemas.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    "") ;;
    *)
      printf '%s\n' 'development schema temporary directory did not match its validated location' >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

temporary_root=$(mktemp -d "$repository_root/.rstack-dev-schemas.XXXXXX")
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0

candidate="$temporary_root/dev"
cargo run --manifest-path "$repository_root/Cargo.toml" --locked \
  -p registry-rstack-dev --features schema --example dev-schema -- \
  --output "$candidate"

if ! diff -ru "$baseline" "$candidate"; then
  cat >&2 <<'MESSAGE'
The development plan and scenario schemas differ from the committed artifacts.
Regenerate them, then review the complete diff:
  cargo run -p registry-rstack-dev --features schema --example dev-schema -- --output products/platform/generated/dev
MESSAGE
  exit 1
fi

cargo test --manifest-path "$repository_root/Cargo.toml" --locked \
  -p registry-rstack-dev --features schema --test dev_schema
