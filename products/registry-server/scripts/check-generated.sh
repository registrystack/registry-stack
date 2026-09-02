#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
fixtures=(
  acceptance/asset-site-placement
  acceptance/business-establishments
  acceptance/asset-site-placement-change-requests
  acceptance/publicschema-household-change-requests
  acceptance/person-name-change-rhai
  fixtures/asset-registration-actions
  fixtures/household-contact-actions
)
authoring_baseline="$repository_root/products/registry-server/generated/authoring"
runtime_baseline="$repository_root/products/registry-server/generated/runtime"
temporary_root=""

cleanup() {
  case "$temporary_root" in
    "$repository_root"/.registry-server-generated.*)
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

temporary_root=$(mktemp -d "$repository_root/.registry-server-generated.XXXXXX")
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

authoring_candidate="$temporary_root/authoring"
runtime_candidate="$temporary_root/runtime"
mkdir "$authoring_candidate"
mkdir "$runtime_candidate"
(
  cd "$temporary_root"
  cargo run --manifest-path "$repository_root/Cargo.toml" --locked --quiet \
    -p registry-server --features schema --example authoring-schema -- \
    --output "$authoring_candidate"
  cargo run --manifest-path "$repository_root/Cargo.toml" --locked --quiet \
    -p registry-server --features runtime,schema --example runtime-schema -- \
    --output "$runtime_candidate"
  for fixture_path in "${fixtures[@]}"; do
    fixture_name=${fixture_path##*/}
    candidate="$temporary_root/$fixture_name"
    mkdir "$candidate"
    fixture="$repository_root/products/registry-server/$fixture_path"
    selectors=(openapi schemas manifest metadata sql)
    if [[ "$fixture_path" == fixtures/* ]]; then
      selectors+=(actions)
    fi
    for selector in "${selectors[@]}"; do
      selector_candidate="$temporary_root/selector-$fixture_name-$selector"
      selector_output="./selector-$fixture_name-$selector"
      cargo run --manifest-path "$repository_root/Cargo.toml" --locked -p registry-serverctl -- \
        generate "$selector" "$fixture" --output "$selector_output"
      cp -R "$selector_candidate/." "$candidate"
    done
  done
)

if ! diff -ru "$authoring_baseline" "$authoring_candidate"; then
  printf '%s\n' 'Registry Server authoring schema differs from the committed artifact.' >&2
  printf '%s\n' 'Regenerate it, then review the complete diff:' >&2
  printf '%s\n' '  cargo run -p registry-server --features schema --example authoring-schema -- --output products/registry-server/generated/authoring' >&2
  exit 1
fi

if ! diff -ru "$runtime_baseline" "$runtime_candidate"; then
  printf '%s\n' 'Registry Server runtime schema differs from the committed artifact.' >&2
  printf '%s\n' 'Regenerate it, then review the complete diff:' >&2
  printf '%s\n' '  cargo run -p registry-server --features runtime,schema --example runtime-schema -- --output products/registry-server/generated/runtime' >&2
  exit 1
fi

for fixture_path in "${fixtures[@]}"; do
  fixture_name=${fixture_path##*/}
  python3 "$script_dir/compare-generated-tree.py" \
    "$repository_root/products/registry-server/generated/$fixture_name" \
    "$temporary_root/$fixture_name"
done
