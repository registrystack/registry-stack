#!/usr/bin/env sh
set -eu

image="${1:-registry-relay:local}"
platform_dir="${REGISTRY_PLATFORM_DIR:-../registry-platform}"
cel_mapping_dir="${CEL_MAPPING_DIR:-../cel-mapping}"

if [ ! -f "$platform_dir/Cargo.toml" ] || [ ! -d "$platform_dir/crates" ]; then
  echo "registry-platform checkout not found at $platform_dir" >&2
  echo "Set REGISTRY_PLATFORM_DIR or clone registry-platform next to registry-relay." >&2
  exit 1
fi

if [ ! -f "$cel_mapping_dir/Cargo.toml" ] || [ ! -d "$cel_mapping_dir/crates" ]; then
  echo "cel-mapping checkout not found at $cel_mapping_dir" >&2
  echo "Set CEL_MAPPING_DIR or clone cel-mapping next to registry-relay." >&2
  exit 1
fi

docker buildx build \
  --load \
  --build-context "registry-platform=$platform_dir" \
  --build-context "cel-mapping=$cel_mapping_dir" \
  -t "$image" \
  .
