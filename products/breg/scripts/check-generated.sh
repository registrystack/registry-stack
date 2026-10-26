#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
authoring_baseline="$repository_root/products/breg/generated/authoring"
runtime_baseline="$repository_root/products/breg/generated/runtime"
temporary_root=""

cleanup() {
  case "$temporary_root" in
    "$repository_root"/.breg-generated.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    "") ;;
    *)
      printf '%s\n' 'generated-artifact temporary directory did not match its validated location' >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

temporary_root=$(mktemp -d "$repository_root/.breg-generated.XXXXXX")
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0

authoring_candidate="$temporary_root/authoring"
runtime_candidate="$temporary_root/runtime"
mkdir "$authoring_candidate"
mkdir "$runtime_candidate"
(
  cd "$temporary_root"
  cargo run --manifest-path "$repository_root/Cargo.toml" --locked \
    -p registry-breg --features schema --example authoring-schema -- \
    --output "$authoring_candidate"
  cargo run --manifest-path "$repository_root/Cargo.toml" --locked \
    -p registry-breg --features runtime,schema --example runtime-schema -- \
    --output "$runtime_candidate"
  cargo run --manifest-path "$repository_root/Cargo.toml" --locked \
    -p registry-breg --example example-artifacts -- --output "$temporary_root/facility"
  cargo run --manifest-path "$repository_root/Cargo.toml" --locked \
    -p registry-breg --example example-artifacts -- --output "$temporary_root/minimal" --project minimal
  cargo run --manifest-path "$repository_root/Cargo.toml" --locked \
    -p registry-breg --example proposal-event-schema -- \
    --output "$temporary_root/proposal-lifecycle.schema.json"
)

if ! diff -ru "$authoring_baseline" "$authoring_candidate"; then
  printf '%s\n' 'Base Registry Engine authoring schema differs from the committed artifact.' >&2
  printf '%s\n' 'Regenerate it, then review the complete diff:' >&2
  printf '%s\n' '  cargo run -p registry-breg --features schema --example authoring-schema -- --output products/breg/generated/authoring' >&2
  exit 1
fi

if ! diff -ru "$runtime_baseline" "$runtime_candidate"; then
  printf '%s\n' 'Base Registry Engine runtime schema differs from the committed artifact.' >&2
  printf '%s\n' 'Regenerate it, then review the complete diff:' >&2
  printf '%s\n' '  cargo run -p registry-breg --features runtime,schema --example runtime-schema -- --output products/breg/generated/runtime' >&2
  exit 1
fi

if ! cmp "$repository_root/products/breg/generated/event-schemas/proposal-lifecycle.schema.json" \
  "$temporary_root/proposal-lifecycle.schema.json"; then
  printf '%s\n' 'Base Registry Engine Proposal event schema differs from the canonical packaged bytes.' >&2
  exit 1
fi

python3 "$script_dir/compare-generated-tree.py" \
  "$repository_root/products/breg/generated/facility" "$temporary_root/facility"
python3 "$script_dir/compare-generated-tree.py" \
  "$repository_root/products/breg/generated/minimal" "$temporary_root/minimal"
