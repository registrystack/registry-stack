#!/usr/bin/env sh
set -eu

image="${1:-registry-relay:local}"
platform_dir="${REGISTRY_PLATFORM_DIR:-../registry-platform}"
manifest_dir="${REGISTRY_MANIFEST_DIR:-../registry-manifest}"
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

if [ ! -f "$manifest_dir/Cargo.toml" ] || [ ! -d "$manifest_dir/crates" ]; then
  echo "registry-manifest checkout not found at $manifest_dir" >&2
  echo "Set REGISTRY_MANIFEST_DIR or clone registry-manifest next to registry-relay." >&2
  exit 1
fi

set -- docker buildx build \
  --load \
  --build-context "registry-platform=$platform_dir" \
  --build-context "registry-manifest=$manifest_dir" \
  --build-context "cel-mapping=$cel_mapping_dir" \
  -t "$image"

if [ -n "${REGISTRY_RELAY_FEATURES:-}" ]; then
  set -- "$@" --build-arg "REGISTRY_RELAY_FEATURES=$REGISTRY_RELAY_FEATURES"
fi

exec "$@" .
