#!/usr/bin/env bash
set -euo pipefail

# Holds the committed tool-file schemas under products/breg/generated/tools to
# what the bregctl reader types generate, and checks each format's committed
# example against its schema.

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
baseline="$repository_root/products/breg/generated/tools"
temporary_root=""

cleanup() {
  case "$temporary_root" in
    "$repository_root"/.breg-tool-schemas.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    "") ;;
    *)
      printf '%s\n' 'tool-schema temporary directory did not match its validated location' >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

temporary_root=$(mktemp -d "$repository_root/.breg-tool-schemas.XXXXXX")
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

candidate="$temporary_root/tools"
cargo run --manifest-path "$repository_root/Cargo.toml" --locked \
  -p registry-bregctl --features schema --example tool-schema -- \
  --output "$candidate"

if ! diff -ru "$baseline" "$candidate"; then
  cat >&2 <<'MESSAGE'
The bregctl tool-file schemas differ from the committed artifacts.
Regenerate them, then review the complete diff:
  cargo run -p registry-bregctl --features schema --example tool-schema -- --output products/breg/generated/tools
MESSAGE
  exit 1
fi

cargo test --manifest-path "$repository_root/Cargo.toml" --locked \
  -p registry-bregctl --features schema --test tool_schema
