#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
fixture="$repository_root/products/registry-server/acceptance/asset-site-placement"
baseline="$repository_root/products/registry-server/generated/asset-site-placement"
authoring_baseline="$repository_root/products/registry-server/generated/authoring"
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

candidate="$temporary_root/generated"
mkdir "$candidate"
authoring_candidate="$temporary_root/authoring"
mkdir "$authoring_candidate"
(
  cd "$temporary_root"
  cargo run --manifest-path "$repository_root/Cargo.toml" --locked --quiet \
    -p registry-server --features schema --example authoring-schema -- \
    --output "$authoring_candidate"
  for selector in openapi schemas manifest metadata sql; do
    cargo run --manifest-path "$repository_root/Cargo.toml" --locked -p registry-serverctl -- \
      generate "$selector" "$fixture" --output "./$selector"
    cp -R "./$selector/." "$candidate"
  done
)

if ! diff -ru "$authoring_baseline" "$authoring_candidate"; then
  printf '%s\n' 'Registry Server authoring schema differs from the committed artifact.' >&2
  printf '%s\n' 'Regenerate it, then review the complete diff:' >&2
  printf '%s\n' '  cargo run -p registry-server --features schema --example authoring-schema -- --output products/registry-server/generated/authoring' >&2
  exit 1
fi

python3 "$script_dir/compare-generated-tree.py" "$baseline" "$candidate"
