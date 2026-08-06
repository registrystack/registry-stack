#!/usr/bin/env bash
set -euo pipefail

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$script_directory/wallet-verifier-harness.sh" \
  mosip/vc-verifier \
  https://github.com/mosip/vc-verifier.git \
  v1.9.0 \
  cd5a1d79aa511922a787c7def797e50b2fb13c30 \
  INJI_SD_JWT_VERIFY \
  "$@"
