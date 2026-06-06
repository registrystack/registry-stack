#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

if [[ -z "${REGISTRY_NOTARY_ROTATED_ISSUER_JWK:-}" || -z "${REGISTRY_NOTARY_ISSUER_PUBLIC_JWK:-}" ]]; then
  echo "missing Lab 2 issuer rotation material; run just generate first" >&2
  exit 1
fi

cargo run --quiet --manifest-path tools/lab2-governed-config/Cargo.toml
