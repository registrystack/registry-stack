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
export REGISTRY_OPENFN_NOTARY_SOURCE_DIR="${REGISTRY_OPENFN_NOTARY_SOURCE_DIR:-"${REGISTRY_NOTARY_SOURCE_DIR}"}"
export REGISTRY_RELAY_PLATFORM_SOURCE_DIR="${REGISTRY_RELAY_PLATFORM_SOURCE_DIR:-"${REGISTRY_PLATFORM_SOURCE_DIR}"}"
export REGISTRY_NOTARY_PLATFORM_SOURCE_DIR="${REGISTRY_NOTARY_PLATFORM_SOURCE_DIR:-"${REGISTRY_PLATFORM_SOURCE_DIR}"}"

cleanup() {
  docker compose -f "${demo_dir}/compose.yaml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

has_opencrvs_dci_credentials() {
  [[ -f "${demo_dir}/.env.local" ]] && return 0
  [[ -n "${OPENCRVS_DCI_CLIENT_ID:-}" && -n "${OPENCRVS_DCI_CLIENT_SECRET:-}" ]]
}

run_opencrvs_dci_check() {
  local mode="${REGISTRY_LAB_CHECK_OPENCRVS_DCI:-auto}"
  case "${mode}" in
    1|true|yes)
      scripts/smoke-opencrvs-dci.sh
      ;;
    0|false|no)
      echo "skipping OpenCRVS DCI smoke: disabled by REGISTRY_LAB_CHECK_OPENCRVS_DCI=${mode}"
      ;;
    auto|"")
      if has_opencrvs_dci_credentials; then
        scripts/smoke-opencrvs-dci.sh
      else
        echo "skipping OpenCRVS DCI smoke: provide lab/.env.local or OPENCRVS_DCI_CLIENT_ID/OPENCRVS_DCI_CLIENT_SECRET to enable it"
      fi
      ;;
    *)
      echo "REGISTRY_LAB_CHECK_OPENCRVS_DCI must be 1, 0, or auto, got ${mode}" >&2
      exit 2
      ;;
  esac
}

cd "${demo_dir}"

scripts/check-release-source-model.sh monorepo
scripts/check-service-first-deps.sh manifest
scripts/check-evidence-gateway-fixtures.py
uv run scripts/generate-fixtures.py
scripts/generate-demo-secrets.py --print-summary >/dev/null
scripts/ensure-postgres-ssl.sh
scripts/publish-static-metadata.sh
docker compose -f compose.yaml build
docker compose -f compose.yaml up -d
scripts/smoke.sh
scripts/smoke-federation.sh
scripts/smoke-notary-client.py
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

run_opencrvs_dci_check

echo "release check OK"
