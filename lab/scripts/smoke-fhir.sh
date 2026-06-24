#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
output_dir="${FHIR_SMOKE_OUTPUT_DIR:-${demo_dir}/output/fhir-smoke}"
correlation_id="${DEMO_CORRELATION_ID:-fhir-health-demo-correlation-001}"

notary_url="${FHIR_HEALTH_NOTARY_URL:-http://127.0.0.1:${FHIR_HEALTH_NOTARY_PORT:-4362}}"
sidecar_url="${FHIR_SOURCE_ADAPTER_URL:-http://127.0.0.1:${FHIR_SOURCE_ADAPTER_PORT:-4360}}"
fixture_url="${FHIR_FIXTURE_SERVER_URL:-http://127.0.0.1:${FHIR_FIXTURE_SERVER_PORT:-4361}}"
purpose="${FHIR_DATA_PURPOSE:-https://demo.example.gov/purpose/fhir-health-navigation}"

if [[ -f "${demo_dir}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${demo_dir}/.env"
  set +a
else
  echo "missing .env; run scripts/generate-demo-secrets.py first" >&2
  exit 1
fi

: "${FHIR_EVIDENCE_CLIENT_BEARER:?missing FHIR_EVIDENCE_CLIENT_BEARER; rerun scripts/generate-demo-secrets.py}"
: "${FHIR_SIDECAR_TOKEN_RAW:?missing FHIR_SIDECAR_TOKEN_RAW; rerun scripts/generate-demo-secrets.py}"

fail() {
  echo "FAILED: $1" >&2
  exit 1
}

wait_http() {
  local name="$1"
  local url="$2"
  local token="${3:-}"
  local deadline="${SMOKE_WAIT_SECONDS:-120}"
  local start
  start="$(date +%s)"
  local status="000"
  while (( $(date +%s) - start < deadline )); do
    local args=(-sS -o /dev/null -w "%{http_code}" -H "Accept: */*" -H "x-request-id: ${correlation_id}")
    if [[ -n "${token}" ]]; then
      args+=(-H "Authorization: Bearer ${token}")
    fi
    status="$(curl "${args[@]}" "${url}" 2>/dev/null || true)"
    if [[ "${status}" =~ ^2[0-9][0-9]$ ]]; then
      return 0
    fi
    sleep 1
  done
  fail "${name} did not become ready within ${deadline}s, last status ${status}"
}

post_evaluation() {
  local name="$1"
  local output="$2"
  local payload="$3"
  echo "check: ${name}"
  curl -fsS \
    -X POST \
    -H "Authorization: Bearer ${FHIR_EVIDENCE_CLIENT_BEARER}" \
    -H "Content-Type: application/json" \
    -H "Data-Purpose: ${purpose}" \
    -H "x-request-id: ${correlation_id}" \
    -o "${output}" \
    "${notary_url}/v1/evaluations" \
    --data "${payload}"
}

assert_all_satisfied() {
  local path="$1"
  python3 - "$path" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    body = json.load(f)
results = body.get("claim_results") or body.get("results") or []
if not results:
    raise SystemExit("no claim results in evaluation response")
bad = [item for item in results if item.get("satisfied") is not True]
if bad:
    raise SystemExit(f"unsatisfied claims: {bad}")
PY
}

mkdir -p "${output_dir}"

docker compose -f "${compose_file}" --profile fhir up -d \
  fhir-fixture-server \
  fhir-source-adapter-sidecar \
  fhir-health-notary

wait_http "FHIR fixture server" "${fixture_url}/ready"
wait_http "FHIR source adapter sidecar" "${sidecar_url}/ready"
wait_http "FHIR health notary discovery" "${notary_url}/.well-known/evidence-service" "${FHIR_EVIDENCE_CLIENT_BEARER}"

person_output="${output_dir}/person-workflow-evaluation.json"
provider_output="${output_dir}/provider-affiliation-evaluation.json"
facility_output="${output_dir}/facility-service-evaluation.json"

post_evaluation "person eligibility and care-navigation claims" "${person_output}" '{
  "requester": { "type": "Person", "id": "guardian-1" },
  "target": { "type": "Person", "id": "person-123" },
  "relationship": { "type": "guardian" },
  "claims": [
    "patient-record-exists",
    "age-over-18",
    "not-recorded-deceased",
    "coverage-active",
    "coverage-eligibility-confirmed",
    "enrolled-in-program",
    "encounter-completed",
    "referral-active",
    "appointment-booked",
    "lab-result-available",
    "vaccination-recorded",
    "prior-authorization-approved",
    "source-trace-available",
    "requester-guardian-confirmed"
  ],
  "purpose": "'"${purpose}"'"
}'
assert_all_satisfied "${person_output}"

post_evaluation "provider affiliation claim" "${provider_output}" '{
  "target": { "type": "Person", "id": "provider-123" },
  "claims": ["provider-affiliated-with-facility"],
  "purpose": "'"${purpose}"'"
}'
assert_all_satisfied "${provider_output}"

post_evaluation "facility service claim" "${facility_output}" '{
  "target": { "type": "Organization", "id": "facility-1" },
  "claims": ["facility-offers-service"],
  "purpose": "'"${purpose}"'"
}'
assert_all_satisfied "${facility_output}"

echo "FHIR smoke passed; artifacts written to ${output_dir}"
