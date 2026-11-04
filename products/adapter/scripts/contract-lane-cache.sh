#!/usr/bin/env bash
set -euo pipefail

# CI owns one cold target for this feature matrix. Release completed Adapter
# executables between lanes so their feature variants cannot fill the runner.
# Local callers retain their cache unless they explicitly opt in.
clear_completed_adapter_lane() {
  if [[ "${ADAPTER_CONTRACTS_CLEAN_BETWEEN_LANES:-0}" != "1" ]]; then
    return 0
  fi
  : "${CARGO_TARGET_DIR:?Set CARGO_TARGET_DIR to the lane-owned Cargo target.}"
  PATH="$HOME/.cargo/bin:$PATH" cargo clean --target-dir "$CARGO_TARGET_DIR" \
    -p registry-adapter -p registry-adapter-core -p registry-adapter-engine \
    -p registry-adapterctl -p registry-adapter-job -p registry-adapter-connectors
}
