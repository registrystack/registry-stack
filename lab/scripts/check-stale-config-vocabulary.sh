#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

if ! command -v rg >/dev/null 2>&1; then
  printf 'Error: ripgrep (rg) is required but not installed.\n' >&2
  exit 1
fi

failures=0

check_absent() {
  local pattern="$1"
  shift
  local -a paths=("$@")
  if rg -n \
    --glob '!output/**' \
    --glob '!vendor/**' \
    --glob '!CHANGELOG.md' \
    --glob '!scripts/check-stale-config-vocabulary.sh' \
    --glob '!scripts/check-project-topologies.sh' \
    --glob '!scripts/test_validate_hosted_deploy.py' \
    --glob '!scripts/validate-public-api-workspace.py' \
    --glob '!scripts/test_validate_public_api_workspace.py' \
    "${pattern}" "${paths[@]}"; then
    failures=$((failures + 1))
  fi
}

check_absent 'registry\.validation\.report\.v1' config scripts docs README.md justfile
check_absent 'allowed_typ:' config scripts docs README.md
check_absent '^[[:space:]]+leeway_seconds:' config scripts docs README.md
check_absent 'connector:[[:space:]]*openfn_sidecar' config docs README.md
check_absent 'bulk_mode:[[:space:]]*openfn_sidecar_batch' config docs README.md
check_absent 'allowed_wallet_origins' config docs README.md
check_absent '^[[:space:]]+max_entries:' config/notary config/coolify/notary
check_absent 'connector:[[:space:]]*(registry_data_api|dci|source_adapter_sidecar)' .
check_absent 'source_adapter_sidecar|source-adapter-sidecar' .
check_absent 'openfn|OPENFN' .
check_absent '(opencrvs-dci|fhir-health|dhis2-health)-notary' .
check_absent 'REGISTRY_OPENFN_NOTARY_SOURCE_DIR|FHIR_SIDECAR|OPENCRVS_DCI_' .
check_absent 'country-dir|country workspace|country authoring' projects docs README.md justfile scripts
check_absent 'connector_type|Source connector type' scripts/lab_homepage_explorer scripts/lab_homepage_static
check_absent 'kind:[[:space:]]*registry-notary' config/relay config/coolify/relay config/static-metadata
check_absent '(civil|social-protection|shared-eligibility|agriculture)-notary' \
  config/lab-homepage/public-demo-credentials.json \
  scripts/lab_homepage_explorer \
  scripts/lab_homepage_static/claims-explorer.js \
  scripts/hosted-smoke.py

if [[ "${failures}" -ne 0 ]]; then
  printf 'stale config vocabulary check failed with %s violation set(s)\n' "${failures}" >&2
  exit 1
fi

printf 'stale config vocabulary check passed\n'
