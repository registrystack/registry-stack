#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
source_mode="${REGISTRY_LAB_RELEASE_SOURCE_MODE:-vendor}"

case "${source_mode}" in
  vendor)
    export REGISTRY_RELAY_SOURCE_DIR="${demo_dir}/vendor/registry-relay"
    export REGISTRY_NOTARY_SOURCE_DIR="${demo_dir}/vendor/registry-notary"
    export REGISTRY_PLATFORM_SOURCE_DIR="${demo_dir}/vendor/registry-platform"
    export REGISTRY_MANIFEST_REPO="${demo_dir}/vendor/registry-manifest"
    export CEL_MAPPING_SOURCE_DIR="${demo_dir}/vendor/cel-mapping"
    export REGISTRY_OPENFN_NOTARY_SOURCE_DIR="${REGISTRY_NOTARY_SOURCE_DIR}"
    export REGISTRY_RELAY_PLATFORM_SOURCE_DIR="${REGISTRY_PLATFORM_SOURCE_DIR}"
    export REGISTRY_NOTARY_PLATFORM_SOURCE_DIR="${REGISTRY_PLATFORM_SOURCE_DIR}"
    if [[ "${REGISTRY_LAB_CHECK_ATLAS:-0}" == "1" || "${REGISTRY_LAB_RUN_LIVE_STORIES:-0}" == "1" ]]; then
      export REGISTRY_ATLAS_SOURCE_DIR="${demo_dir}/vendor/registry-atlas"
    fi
    ;;
  source)
    export REGISTRY_RELAY_SOURCE_DIR="${REGISTRY_RELAY_SOURCE_DIR:-"${demo_dir}/../registry-relay"}"
    export REGISTRY_NOTARY_SOURCE_DIR="${REGISTRY_NOTARY_SOURCE_DIR:-"${demo_dir}/../registry-notary"}"
    export REGISTRY_PLATFORM_SOURCE_DIR="${REGISTRY_PLATFORM_SOURCE_DIR:-"${demo_dir}/../registry-platform"}"
    export REGISTRY_MANIFEST_REPO="${REGISTRY_MANIFEST_REPO:-"${demo_dir}/vendor/registry-manifest"}"
    export CEL_MAPPING_SOURCE_DIR="${CEL_MAPPING_SOURCE_DIR:-"${demo_dir}/vendor/cel-mapping"}"
    export REGISTRY_OPENFN_NOTARY_SOURCE_DIR="${REGISTRY_OPENFN_NOTARY_SOURCE_DIR:-"${REGISTRY_NOTARY_SOURCE_DIR}"}"
    export REGISTRY_RELAY_PLATFORM_SOURCE_DIR="${REGISTRY_RELAY_PLATFORM_SOURCE_DIR:-"${REGISTRY_PLATFORM_SOURCE_DIR}"}"
    export REGISTRY_NOTARY_PLATFORM_SOURCE_DIR="${REGISTRY_NOTARY_PLATFORM_SOURCE_DIR:-"${REGISTRY_PLATFORM_SOURCE_DIR}"}"
    ;;
  *)
    echo "REGISTRY_LAB_RELEASE_SOURCE_MODE must be vendor or source, got ${source_mode}" >&2
    exit 2
    ;;
esac

export REGISTRY_LAB_RELEASE_SOURCE_MODE="${source_mode}"
export REGISTRY_LAB_CHECK_ATLAS="${REGISTRY_LAB_CHECK_ATLAS:-0}"

cleanup() {
  docker compose -f "${demo_dir}/compose.yaml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "${demo_dir}"

scripts/check-release-source-model.sh "${source_mode}"
scripts/check-service-first-deps.sh manifest
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

if [[ "${REGISTRY_LAB_RUN_LIVE_STORIES:-0}" == "1" ]]; then
  scripts/demo-live-stories.sh
fi

echo "release check OK"
