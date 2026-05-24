#!/usr/bin/env sh
set -eu

image="${1:-registry-relay:local}"
platform_dir="${REGISTRY_PLATFORM_DIR:-../registry-platform}"

if [ ! -f "$platform_dir/Cargo.toml" ] || [ ! -d "$platform_dir/crates" ]; then
  echo "registry-platform checkout not found at $platform_dir" >&2
  echo "Set REGISTRY_PLATFORM_DIR or clone registry-platform next to registry-relay." >&2
  exit 1
fi

docker buildx build \
  --load \
  --build-context "registry-platform=$platform_dir" \
  -t "$image" \
  .
