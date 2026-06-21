#!/usr/bin/env sh
set -eu

image="${1:-registry-relay:local}"
platform_dir="${REGISTRY_PLATFORM_DIR:-../registry-platform}"
manifest_dir="${REGISTRY_MANIFEST_DIR:-../registry-manifest}"
manifest_ref="${REGISTRY_MANIFEST_REF:-141efade265f453e15c967770286bafc5c3a3956}"
# CEL_MAPPING_DIR is the deprecated name for CROSSWALK_DIR; remove the fallback
# once operators have migrated.
if [ -z "${CROSSWALK_DIR:-}" ] && [ -n "${CEL_MAPPING_DIR:-}" ]; then
  echo "warning: CEL_MAPPING_DIR is deprecated, please use CROSSWALK_DIR instead" >&2
fi
crosswalk_dir="${CROSSWALK_DIR:-${CEL_MAPPING_DIR:-../crosswalk}}"

verify_pinned_git_context() {
  name="$1"
  dir="$2"
  expected_ref="$3"

  if [ -n "${REGISTRY_RELAY_ALLOW_UNPINNED_LOCAL_CONTEXTS:-}" ]; then
    echo "warning: skipping pinned $name context check for local development" >&2
    return
  fi

  if [ "$(expr "$expected_ref" : '[0-9a-f][0-9a-f]*$')" -ne 40 ]; then
    echo "$name expected ref must be a 40-character lowercase commit SHA, got $expected_ref" >&2
    exit 1
  fi

  if ! git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "$name context at $dir is not a git checkout" >&2
    exit 1
  fi

  actual_ref="$(git -C "$dir" rev-parse HEAD)"
  if [ "$actual_ref" != "$expected_ref" ]; then
    echo "$name context at $dir is $actual_ref, expected $expected_ref" >&2
    echo "Set ${name}_REF to the reviewed commit or set REGISTRY_RELAY_ALLOW_UNPINNED_LOCAL_CONTEXTS=1 for local-only development builds." >&2
    exit 1
  fi

  if [ -n "$(git -C "$dir" status --porcelain)" ]; then
    echo "$name context at $dir has uncommitted changes" >&2
    echo "Commit, stash, or set REGISTRY_RELAY_ALLOW_UNPINNED_LOCAL_CONTEXTS=1 for local-only development builds." >&2
    exit 1
  fi
}

if [ ! -f "$platform_dir/Cargo.toml" ] || [ ! -d "$platform_dir/crates" ]; then
  echo "registry-platform checkout not found at $platform_dir" >&2
  echo "Set REGISTRY_PLATFORM_DIR or clone registry-platform next to registry-relay." >&2
  exit 1
fi

if [ ! -f "$crosswalk_dir/Cargo.toml" ] || [ ! -d "$crosswalk_dir/crates" ]; then
  echo "crosswalk checkout not found at $crosswalk_dir" >&2
  echo "Set CROSSWALK_DIR or clone crosswalk next to registry-relay." >&2
  exit 1
fi

if [ ! -f "$manifest_dir/Cargo.toml" ] || [ ! -d "$manifest_dir/crates" ]; then
  echo "registry-manifest checkout not found at $manifest_dir" >&2
  echo "Set REGISTRY_MANIFEST_DIR or clone registry-manifest next to registry-relay." >&2
  exit 1
fi
verify_pinned_git_context "REGISTRY_MANIFEST" "$manifest_dir" "$manifest_ref"

set -- docker buildx build \
  --load \
  --build-context "registry-platform=$platform_dir" \
  --build-context "registry-manifest=$manifest_dir" \
  --build-context "crosswalk=$crosswalk_dir" \
  -t "$image"

if [ -n "${REGISTRY_RELAY_FEATURES:-}" ]; then
  set -- "$@" --build-arg "REGISTRY_RELAY_FEATURES=$REGISTRY_RELAY_FEATURES"
fi

exec "$@" .
