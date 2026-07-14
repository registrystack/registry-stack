#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lab_root="$(cd "${script_dir}/.." && pwd)"
compose_file="${lab_root}/compose.yaml"
output_dir="${lab_root}/output"
correlation_id="${DEMO_CORRELATION_ID:-registry-lab-smoke-001}"

if [[ ! -f "${lab_root}/.env" ]]; then
  printf 'missing .env; run scripts/generate-demo-secrets.py first\n' >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
. "${lab_root}/.env"
set +a

fail() {
  printf 'FAILED: %s\n' "$1" >&2
  exit 1
}

wait_http() {
  local name="$1"
  local url="$2"
  local header_name="$3"
  local header_value="$4"
  local deadline="${SMOKE_WAIT_SECONDS:-90}"
  local start
  start="$(date +%s)"
  while (( $(date +%s) - start < deadline )); do
    if {
      printf 'silent\nshow-error\nfail\nurl = "%s"\n' "${url}"
      [[ -z "${header_name}" ]] || printf 'header = "%s: %s"\n' "${header_name}" "${header_value}"
    } | curl --config - --output /dev/null 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  docker compose -f "${compose_file}" ps >&2 || true
  docker compose -f "${compose_file}" logs --no-color --tail 80 >&2 || true
  fail "${name} did not become ready"
}

get_json() {
  local url="$1"
  local header_name="$2"
  local header_value="$3"
  local output="$4"
  {
    printf 'silent\nshow-error\nfail\nurl = "%s"\noutput = "%s"\n' "${url}" "${output}"
    printf 'header = "Accept: application/json"\n'
    printf 'header = "x-request-id: %s"\n' "${correlation_id}"
    [[ -z "${header_name}" ]] || printf 'header = "%s: %s"\n' "${header_name}" "${header_value}"
  } | curl --config -
}

get_status() {
  local url="$1"
  local token="$2"
  local output="$3"
  {
    printf 'silent\nshow-error\nurl = "%s"\noutput = "%s"\nwrite-out = "%%{http_code}"\n' "${url}" "${output}"
    printf 'header = "Accept: application/json"\n'
    printf 'header = "Authorization: Bearer %s"\n' "${token}"
    printf 'header = "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo"\n'
    printf 'header = "x-request-id: %s"\n' "${correlation_id}"
  } | curl --config -
}

post_notary_evaluation() {
  local output="$1"
  local request
  request="$(mktemp)"
  trap 'rm -f "${request}"' RETURN
  jq -n '{
    target: {
      type: "Person",
      identifiers: [{scheme: "application_reference", value: "SYNTHETIC-APPLICATION-001"}]
    },
    claims: ["applicant-declaration"],
    disclosure: "predicate",
    format: "application/vnd.registry-notary.claim-result+json"
  }' >"${request}"
  {
    printf 'silent\nshow-error\nfail\nrequest = "POST"\n'
    printf 'url = "http://127.0.0.1:4321/v1/evaluations"\n'
    printf 'output = "%s"\n' "${output}"
    printf 'header = "Accept: application/json"\n'
    printf 'header = "Content-Type: application/json"\n'
    printf 'header = "Data-Purpose: application-processing"\n'
    printf 'header = "x-api-key: %s"\n' "${SELF_ATTESTED_EVIDENCE_CLIENT_TOKEN}"
    printf 'header = "x-request-id: %s"\n' "${correlation_id}"
    printf 'data-binary = "@%s"\n' "${request}"
  } | curl --config -
}

mkdir -p "${output_dir}"

wait_http "civil Relay" "http://127.0.0.1:4311/healthz" "Authorization" "Bearer ${CIVIL_METADATA_CLIENT_RAW}"
wait_http "social Relay" "http://127.0.0.1:4312/healthz" "Authorization" "Bearer ${SOCIAL_METADATA_CLIENT_RAW}"
wait_http "health Relay" "http://127.0.0.1:4313/healthz" "Authorization" "Bearer ${HEALTH_METADATA_CLIENT_RAW}"
wait_http "self-attested Notary" "http://127.0.0.1:4321/.well-known/evidence-service" "x-api-key" "${SELF_ATTESTED_EVIDENCE_CLIENT_TOKEN}"
wait_http "static metadata" "http://127.0.0.1:4331/.well-known/api-catalog" "" ""

get_json "http://127.0.0.1:4311/ready" "Authorization" "Bearer ${CIVIL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-civil-relay-ready.json"
get_json "http://127.0.0.1:4312/ready" "Authorization" "Bearer ${SOCIAL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-social-relay-ready.json"
get_json "http://127.0.0.1:4313/ready" "Authorization" "Bearer ${HEALTH_METADATA_CLIENT_RAW}" "${output_dir}/smoke-health-relay-ready.json"
get_json "http://127.0.0.1:4321/.well-known/evidence-service" "x-api-key" "${SELF_ATTESTED_EVIDENCE_CLIENT_TOKEN}" "${output_dir}/smoke-self-attested-discovery.json"
get_json "http://127.0.0.1:4331/.well-known/api-catalog" "" "" "${output_dir}/smoke-static-api-catalog.json"

denial_status="$(get_status "http://127.0.0.1:4312/v1/datasets/social_protection_registry/entities/household/records?limit=1" "${SOCIAL_EVIDENCE_ONLY_RAW}" "${output_dir}/smoke-relay-scope-denial.json")"
[[ "${denial_status}" == "403" ]] || fail "Relay evidence-only row access expected 403, got ${denial_status}"

success_status="$(get_status "http://127.0.0.1:4312/v1/datasets/social_protection_registry/entities/household/records?limit=1" "${SOCIAL_ROW_READER_RAW}" "${output_dir}/smoke-relay-row-read.json")"
[[ "${success_status}" == "200" ]] || fail "Relay row reader expected 200, got ${success_status}"

post_notary_evaluation "${output_dir}/smoke-self-attested-evaluation.json"
jq -e '
  (.results // .claim_results) as $results
  | ($results | type == "array")
  and any($results[]; (.claim // .claim_id) == "applicant-declaration" and (.satisfied // .value) == true)
' "${output_dir}/smoke-self-attested-evaluation.json" >/dev/null ||
  fail "source-free Notary did not return the applicant declaration"

log_output="$(docker compose -f "${compose_file}" logs --no-color)"
for secret_name in \
  REGISTRY_RELAY_AUDIT_HASH_SECRET \
  REGISTRY_NOTARY_AUDIT_HASH_SECRET \
  REGISTRY_NOTARY_ISSUER_JWK \
  SELF_ATTESTED_EVIDENCE_CLIENT_TOKEN \
  CIVIL_METADATA_CLIENT_RAW \
  SOCIAL_METADATA_CLIENT_RAW \
  HEALTH_METADATA_CLIENT_RAW; do
  secret_value="${!secret_name:-}"
  if [[ -n "${secret_value}" && "${log_output}" == *"${secret_value}"* ]]; then
    fail "container logs exposed a configured secret"
  fi
done

printf 'Lab smoke passed: Relay-only access controls and source-free Notary-only evidence.\n'
