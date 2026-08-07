#!/usr/bin/env bash
set -euo pipefail

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$script_directory/wallet-verifier-harness.sh" \
  walt-id/waltid-identity \
  https://github.com/walt-id/waltid-identity.git \
  v0.23.0 \
  ba72e32fb5aea2affc1315dfa8471c4ea0384ef6 \
  WALTID_SD_JWT_VERIFY \
  "$@"
