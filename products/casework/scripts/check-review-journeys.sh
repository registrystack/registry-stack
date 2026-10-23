#!/bin/sh
set -eu

# Build and execute the smallest maintained packaged-service journey for J1/J5.
# The lifecycle integration test creates a temporary authored project, starts
# the candidate service and CLI, runs explicit apply/doctor/readiness checks,
# and retains pending and terminal work across process restarts.
#
# It also loads the exact unified Rust, Node and Python Casework facades against the
# candidate product-native bindings and real HTTP service. The unified release
# artifacts normally bundle seven native products. This journey builds the
# Casework bindings and the real BReg Python authentication provider, with
# inert sibling namespaces. It avoids duplicating the full release assembly gate. This proves the
# Casework facade/native/HTTP boundary, but does not claim installed tarball or
# wheel proof; release package assembly remains separately gated.

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
. "$repo_root/scripts/cargo-runtime-library-path.sh"

case "$(uname -s):$(uname -m)" in
  Darwin:arm64)
    node_platform=darwin-arm64
    python_library_extension=dylib
    ;;
  Linux:x86_64)
    node_platform=linux-x64-gnu
    python_library_extension=so
    ;;
  Linux:aarch64)
    node_platform=linux-arm64-gnu
    python_library_extension=so
    ;;
  *)
    echo "the Registry Stack native clients do not support $(uname -s) $(uname -m)" >&2
    exit 2
    ;;
esac

for command in cargo docker node npm python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "check-review-journeys requires $command" >&2
    exit 2
  fi
done
if ! docker info >/dev/null 2>&1; then
  echo "check-review-journeys requires a running Docker daemon" >&2
  exit 2
fi

cd "$repo_root"

# Cargo builds under CARGO_TARGET_DIR, CARGO_BUILD_TARGET_DIR or the workspace
# `target` directory, so ask it where rather than assuming the last.
target_directory=$(
  cargo metadata --format-version 1 --no-deps |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
) || {
  echo "cargo metadata did not report the Cargo target directory" >&2
  exit 2
}

if [ -z "${CASEWORK_BIN:-}" ] || [ -z "${CASEWORKCTL_BIN:-}" ]; then
  registry_cargo_build "$repo_root" --locked -p registry-casework -p registry-caseworkctl
fi
CASEWORK_BIN=${CASEWORK_BIN:-"$target_directory/debug/casework"}
CASEWORKCTL_BIN=${CASEWORKCTL_BIN:-"$target_directory/debug/caseworkctl"}
export CASEWORK_BIN CASEWORKCTL_BIN
for binary in "$CASEWORK_BIN" "$CASEWORKCTL_BIN"; do
  if [ ! -x "$binary" ]; then
    echo "candidate Casework binary is not executable: $binary" >&2
    exit 2
  fi
done

(
  cd crates/registry-casework-client-node
  npm ci --ignore-scripts
  npm run build:debug
)

cargo build --locked -p registry-casework-client-py -p registry-breg-client-py --lib \
  --features registry-casework-client-py/extension-module,registry-breg-client-py/extension-module

CASEWORK_NODE_FACADE_ROOT="$repo_root/crates/registry-stack-client-node"
CASEWORK_NODE_NATIVE="$repo_root/crates/registry-casework-client-node/casework-client.$node_platform.node"
CASEWORK_PYTHON_FACADE_ROOT="$repo_root/crates/registry-stack-client-py/python/registry_client"
CASEWORK_PYTHON_PRODUCT_ROOT="$repo_root/crates/registry-casework-client-py/python/registry_casework_client"
CASEWORK_PYTHON_NATIVE="$target_directory/debug/libregistry_casework_client.$python_library_extension"
CASEWORK_PYTHON_BREG_PRODUCT_ROOT="$repo_root/crates/registry-breg-client-py/python/registry_breg_client"
CASEWORK_PYTHON_BREG_NATIVE="$target_directory/debug/libregistry_breg_client.$python_library_extension"
export CASEWORK_NODE_FACADE_ROOT CASEWORK_NODE_NATIVE
export CASEWORK_PYTHON_FACADE_ROOT CASEWORK_PYTHON_PRODUCT_ROOT CASEWORK_PYTHON_NATIVE
export CASEWORK_PYTHON_BREG_PRODUCT_ROOT CASEWORK_PYTHON_BREG_NATIVE

for artifact in "$CASEWORK_NODE_NATIVE" "$CASEWORK_PYTHON_NATIVE" "$CASEWORK_PYTHON_BREG_NATIVE"; do
  if [ ! -f "$artifact" ]; then
    echo "candidate native binding was not built: $artifact" >&2
    exit 1
  fi
done

cargo test --locked -p registry-caseworkctl --test dev_lifecycle -- \
  --ignored --test-threads=1

echo "Casework candidate service, operator lifecycle, and Rust/Node/Python Casework facade journeys passed."
