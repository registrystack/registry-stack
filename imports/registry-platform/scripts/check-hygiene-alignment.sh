#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
platform="${2:-${REGISTRY_PLATFORM_DIR:-../registry-platform}}"

for file in clippy.toml rustfmt.toml deny.toml; do
  cmp -s "$root/$file" "$platform/templates/$file" || {
    echo "$file differs from registry-platform/templates/$file" >&2
    exit 1
  }
done
