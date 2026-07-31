#!/usr/bin/env bash
set -euo pipefail

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0

cargo test --locked \
  -p registryctl \
  --test deployment_seams \
  python_release_lock_runtime_renders_compose_conformance \
  -- \
  --exact
