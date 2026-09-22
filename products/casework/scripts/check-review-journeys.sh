#!/bin/sh
set -eu

# Build and execute the smallest maintained packaged-service journey for J1/J5.
# The lifecycle integration test creates a temporary authored project, starts
# the candidate service and CLI, runs explicit migrate/doctor/readiness checks,
# and retains pending and terminal work across process restarts.
#
# It also loads the exact unified Node and Python Casework facades against the
# candidate product-native bindings and real HTTP service. The unified release
# artifacts normally bundle five native products. Building all five here would
# duplicate the release assembly gate, so the test supplies inert sibling
# namespaces and only the candidate Casework native artifact. This proves the
# Casework facade/native/HTTP boundary, but does not claim installed tarball or
# wheel proof; release package assembly remains separately gated.

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
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

if [ -z "${CASEWORK_BIN:-}" ] || [ -z "${CASEWORKCTL_BIN:-}" ]; then
  registry_cargo_build "$repo_root" --locked -p registry-casework -p registry-caseworkctl
fi
CASEWORK_BIN=${CASEWORK_BIN:-"$repo_root/target/debug/casework"}
CASEWORKCTL_BIN=${CASEWORKCTL_BIN:-"$repo_root/target/debug/caseworkctl"}
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

cargo build --locked -p registry-casework-client-py --lib \
  --features registry-casework-client-py/extension-module

CASEWORK_NODE_FACADE_ROOT="$repo_root/crates/registry-stack-client-node"
CASEWORK_NODE_NATIVE="$repo_root/crates/registry-casework-client-node/casework-client.$node_platform.node"
CASEWORK_PYTHON_FACADE_ROOT="$repo_root/crates/registry-stack-client-py/python/registry_client"
CASEWORK_PYTHON_PRODUCT_ROOT="$repo_root/crates/registry-casework-client-py/python/registry_casework_client"
CASEWORK_PYTHON_NATIVE="$repo_root/target/debug/libregistry_casework_client.$python_library_extension"
export CASEWORK_NODE_FACADE_ROOT CASEWORK_NODE_NATIVE
export CASEWORK_PYTHON_FACADE_ROOT CASEWORK_PYTHON_PRODUCT_ROOT CASEWORK_PYTHON_NATIVE

for artifact in "$CASEWORK_NODE_NATIVE" "$CASEWORK_PYTHON_NATIVE"; do
  if [ ! -f "$artifact" ]; then
    echo "candidate native binding was not built: $artifact" >&2
    exit 1
  fi
done

cargo test --locked -p registry-caseworkctl --test dev_lifecycle -- \
  --ignored --test-threads=1

echo "Casework candidate service, operator lifecycle, and Node/Python Casework facade journeys passed."
