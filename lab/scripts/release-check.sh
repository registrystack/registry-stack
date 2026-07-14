#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"

export REGISTRY_STACK_SOURCE_DIR="${REGISTRY_STACK_SOURCE_DIR:-"${demo_dir}/.."}"
export REGISTRY_RELAY_SOURCE_DIR="${REGISTRY_RELAY_SOURCE_DIR:-"${REGISTRY_STACK_SOURCE_DIR}/crates/registry-relay"}"
export REGISTRY_NOTARY_SOURCE_DIR="${REGISTRY_NOTARY_SOURCE_DIR:-"${REGISTRY_STACK_SOURCE_DIR}"}"
export REGISTRY_PLATFORM_SOURCE_DIR="${REGISTRY_PLATFORM_SOURCE_DIR:-"${REGISTRY_STACK_SOURCE_DIR}"}"
export REGISTRY_MANIFEST_REPO="${REGISTRY_MANIFEST_REPO:-"${REGISTRY_STACK_SOURCE_DIR}"}"
export CROSSWALK_SOURCE_DIR="${CROSSWALK_SOURCE_DIR:-"${demo_dir}/vendor/crosswalk"}"
export REGISTRY_RELAY_PLATFORM_SOURCE_DIR="${REGISTRY_RELAY_PLATFORM_SOURCE_DIR:-"${REGISTRY_PLATFORM_SOURCE_DIR}"}"
export REGISTRY_NOTARY_PLATFORM_SOURCE_DIR="${REGISTRY_NOTARY_PLATFORM_SOURCE_DIR:-"${REGISTRY_PLATFORM_SOURCE_DIR}"}"

cleanup() {
  docker compose -f "${demo_dir}/compose.yaml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "${demo_dir}"

scripts/check-release-source-model.sh monorepo
scripts/check-service-first-deps.sh manifest
scripts/check-project-topologies.sh
uv run scripts/generate-fixtures.py
scripts/generate-demo-secrets.py --print-summary >/dev/null
scripts/ensure-postgres-ssl.sh
scripts/publish-static-metadata.sh
docker compose -f compose.yaml build
docker compose -f compose.yaml up -d
scripts/smoke.sh

if [[ "${REGISTRY_LAB_CHECK_RELAY_POSTGRES:-1}" == "1" ]]; then
  scripts/check-relay-postgres.sh
fi

if [[ "${REGISTRY_LAB_CHECK_RELAY_ZITADEL:-1}" == "1" ]]; then
  scripts/check-relay-zitadel.sh
fi

if [[ "${REGISTRY_LAB_CHECK_OIDC_RELAY:-1}" == "1" ]]; then
  scripts/smoke-oidc-relay.sh
fi

echo "release check OK"
