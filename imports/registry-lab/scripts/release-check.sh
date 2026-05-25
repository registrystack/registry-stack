#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"

export REGISTRY_RELAY_SOURCE_DIR="${REGISTRY_RELAY_SOURCE_DIR:-"${demo_dir}/vendor/registry-relay"}"
export REGISTRY_WITNESS_SOURCE_DIR="${REGISTRY_WITNESS_SOURCE_DIR:-"${demo_dir}/vendor/registry-witness"}"
export REGISTRY_OPENFN_WITNESS_SOURCE_DIR="${REGISTRY_OPENFN_WITNESS_SOURCE_DIR:-"${demo_dir}/../registry-witness"}"
export REGISTRY_PLATFORM_SOURCE_DIR="${REGISTRY_PLATFORM_SOURCE_DIR:-"${demo_dir}/vendor/registry-platform"}"
export REGISTRY_RELAY_PLATFORM_SOURCE_DIR="${REGISTRY_RELAY_PLATFORM_SOURCE_DIR:-"${REGISTRY_PLATFORM_SOURCE_DIR}"}"
export REGISTRY_WITNESS_PLATFORM_SOURCE_DIR="${REGISTRY_WITNESS_PLATFORM_SOURCE_DIR:-"${REGISTRY_PLATFORM_SOURCE_DIR}"}"

cleanup() {
  docker compose -f "${demo_dir}/compose.yaml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "${demo_dir}"

scripts/check-service-first-deps.sh all
uv run scripts/generate-fixtures.py
scripts/generate-demo-secrets.py --print-summary >/dev/null
scripts/publish-static-metadata.sh
docker compose -f compose.yaml build
docker compose -f compose.yaml up -d
scripts/smoke.sh
docker compose -f compose.yaml --profile client run --rm demo-client

if [[ "${REGISTRY_LAB_CHECK_RELAY_POSTGRES:-1}" == "1" ]]; then
  scripts/check-relay-postgres.sh
fi

if [[ "${REGISTRY_LAB_CHECK_RELAY_ZITADEL:-1}" == "1" ]]; then
  scripts/check-relay-zitadel.sh
fi

if [[ "${REGISTRY_LAB_CHECK_OIDC_RELAY:-1}" == "1" ]]; then
  scripts/smoke-oidc-relay.sh
fi

if [[ "${REGISTRY_LAB_CHECK_OPENFN:-1}" == "1" ]]; then
  scripts/smoke-openfn.sh
fi

if [[ "${REGISTRY_LAB_RUN_LIVE_STORIES:-1}" == "1" ]]; then
  scripts/demo-live-stories.sh
fi

echo "release check OK"
