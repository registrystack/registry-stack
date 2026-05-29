#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
output_dir="${demo_dir}/output"
correlation_id="${DEMO_CORRELATION_ID:-decentralized-demo-correlation-001}"

if [[ -f "${demo_dir}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${demo_dir}/.env"
  set +a
else
  echo "missing .env; run ${script_dir}/generate-demo-secrets.py first" >&2
  exit 1
fi

fail() {
  echo "FAILED: $1" >&2
  exit 1
}

check() {
  local name="$1"
  shift
  echo "check: ${name}"
  "$@" || fail "${name}"
}

curl_json() {
  local method="$1"
  local url="$2"
  local token="${3:-}"
  local out="$4"
  shift 4
  local args=(-fsS -X "${method}" -H "Accept: */*" -H "x-request-id: ${correlation_id}")
  if [[ -n "${token}" ]]; then
    args+=(-H "Authorization: Bearer ${token}")
  fi
  args+=("$@" -o "${out}" "${url}")
  curl "${args[@]}"
}

curl_status() {
  local method="$1"
  local url="$2"
  local token="${3:-}"
  shift 3
  local args=(-sS -o /tmp/decentralized-smoke-response.json -w "%{http_code}" -X "${method}" -H "Accept: */*" -H "x-request-id: ${correlation_id}")
  if [[ -n "${token}" ]]; then
    args+=(-H "Authorization: Bearer ${token}")
  fi
  args+=("$@" "${url}")
  curl "${args[@]}"
}

json_has_key() {
  python - "$1" "$2" <<'PY'
import json
import sys
path, key = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    body = json.load(fh)
value = body
for part in key.split("."):
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break
if value in (None, [], {}):
    raise SystemExit(1)
PY
}

json_path_equals() {
  python - "$1" "$2" "$3" <<'PY'
import json
import sys
path, key, expected = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as fh:
    body = json.load(fh)
try:
    expected_value = json.loads(expected)
except json.JSONDecodeError:
    expected_value = expected
value = body
for part in key.split("."):
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break
if value != expected_value:
    raise SystemExit(1)
PY
}

mkdir -p "${output_dir}"

check "civil relay health" curl_json GET http://127.0.0.1:4311/health "${CIVIL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-civil-health.json"
check "social relay health" curl_json GET http://127.0.0.1:4312/health "${SOCIAL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-social-health.json"
check "health relay health" curl_json GET http://127.0.0.1:4313/health "${HEALTH_METADATA_CLIENT_RAW}" "${output_dir}/smoke-health-health.json"

check "civil relay ready" curl_json GET http://127.0.0.1:4311/ready "${CIVIL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-civil-ready.json"
check "social relay ready" curl_json GET http://127.0.0.1:4312/ready "${SOCIAL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-social-ready.json"
check "health relay ready" curl_json GET http://127.0.0.1:4313/ready "${HEALTH_METADATA_CLIENT_RAW}" "${output_dir}/smoke-health-ready.json"

check "civil evidence discovery" curl_json GET http://127.0.0.1:4321/.well-known/evidence-service "${CIVIL_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-civil-evidence-discovery.json"
check "social evidence discovery" curl_json GET http://127.0.0.1:4322/.well-known/evidence-service "${SOCIAL_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-social-evidence-discovery.json"
check "shared evidence discovery" curl_json GET http://127.0.0.1:4323/.well-known/evidence-service "${SHARED_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-shared-evidence-discovery.json"

check "civil relay OpenAPI" curl_json GET http://127.0.0.1:4311/openapi.json "${CIVIL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-civil-openapi.json"
check "social relay OpenAPI" curl_json GET http://127.0.0.1:4312/openapi.json "${SOCIAL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-social-openapi.json"
check "health relay OpenAPI" curl_json GET http://127.0.0.1:4313/openapi.json "${HEALTH_METADATA_CLIENT_RAW}" "${output_dir}/smoke-health-openapi.json"

check "civil Evidence Server OpenAPI" curl_json GET http://127.0.0.1:4321/openapi.json "${CIVIL_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-civil-evidence-openapi.json"
check "social Evidence Server OpenAPI" curl_json GET http://127.0.0.1:4322/openapi.json "${SOCIAL_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-social-evidence-openapi.json"
check "shared Evidence Server OpenAPI" curl_json GET http://127.0.0.1:4323/openapi.json "${SHARED_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-shared-evidence-openapi.json"

check "civil relay evidence offerings" curl_json GET http://127.0.0.1:4311/metadata/evidence-offerings "${CIVIL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-civil-offerings.json"
check "social relay evidence offerings" curl_json GET http://127.0.0.1:4312/metadata/evidence-offerings "${SOCIAL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-social-offerings.json"
check "health relay evidence offerings" curl_json GET http://127.0.0.1:4313/metadata/evidence-offerings "${HEALTH_METADATA_CLIENT_RAW}" "${output_dir}/smoke-health-offerings.json"
check "static evidence offerings" curl_json GET http://127.0.0.1:4331/metadata/evidence-offerings.json "" "${output_dir}/smoke-static-offerings.json"
check "static policy metadata" curl_json GET http://127.0.0.1:4331/metadata/policies.jsonld "" "${output_dir}/smoke-static-policies.json"

status="$(curl_status GET http://127.0.0.1:4312/datasets/social_protection_registry/household?limit=1 "${SOCIAL_EVIDENCE_ONLY_RAW}" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo")"
[[ "${status}" == "403" ]] || fail "row denial with evidence-only credential expected 403, got ${status}"
cp /tmp/decentralized-smoke-response.json "${output_dir}/smoke-row-denial.json"
check "row denial stable error code" json_path_equals "${output_dir}/smoke-row-denial.json" code auth.scope_denied

check "positive row read" curl_json GET "http://127.0.0.1:4312/datasets/social_protection_registry/household?limit=1" "${SOCIAL_ROW_READER_RAW}" "${output_dir}/smoke-positive-row-read.json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo"
check "positive aggregate consultation" curl_json GET "http://127.0.0.1:4312/datasets/social_protection_registry/household/aggregates/households_by_eligibility_band" "${SOCIAL_AGGREGATE_READER_RAW}" "${output_dir}/smoke-positive-aggregate.json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo"

aggregate_status="$(curl_status GET http://127.0.0.1:4312/datasets/social_protection_registry/household/aggregates/households_by_eligibility_band "${SOCIAL_ROW_READER_RAW}" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo")"
[[ "${aggregate_status}" == "403" ]] || fail "aggregate denial with row-reader credential expected 403, got ${aggregate_status}"
cp /tmp/decentralized-smoke-response.json "${output_dir}/smoke-aggregate-denial.json"
check "aggregate denial stable error code" json_path_equals "${output_dir}/smoke-aggregate-denial.json" code auth.scope_denied

check "civil evidence evaluation" curl_json POST http://127.0.0.1:4321/claims/evaluate "${CIVIL_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-civil-evaluation.json" -H "Content-Type: application/json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo" --data '{"subject":{"id":"NID-1001","id_type":"national_id"},"claims":["person-is-alive"],"disclosure":"predicate","format":"application/vnd.registry-notary.claim-result+json"}'
check "civil evidence evaluation results" json_has_key "${output_dir}/smoke-civil-evaluation.json" results

check "health evidence evaluation" curl_json POST http://127.0.0.1:4323/claims/evaluate "${SHARED_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-health-evaluation.json" -H "Content-Type: application/json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo" --data '{"subject":{"id":"NID-1001","id_type":"national_id"},"claims":["health-service-available"],"disclosure":"predicate","format":"application/vnd.registry-notary.claim-result+json"}'
check "health evidence evaluation results" json_has_key "${output_dir}/smoke-health-evaluation.json" results

check "shared evidence evaluation" curl_json POST http://127.0.0.1:4323/claims/evaluate "${SHARED_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-shared-evaluation.json" -H "Content-Type: application/json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo" --data '{"subject":{"id":"NID-1001","id_type":"national_id"},"claims":["eligible-for-combined-support"],"disclosure":"predicate","format":"application/vnd.registry-notary.claim-result+json"}'
check "shared evidence source count" python - "${output_dir}/smoke-shared-evaluation.json" <<'PY'
import json
import sys
body = json.load(open(sys.argv[1], encoding="utf-8"))
results = body.get("results") or body.get("claim_results") or []
if not results:
    raise SystemExit(1)
source_count = results[0].get("provenance", {}).get("source_count", 0)
if source_count < 2:
    raise SystemExit(1)
PY

missing_status="$(curl_status POST http://127.0.0.1:4323/claims/evaluate "${SHARED_EVIDENCE_CLIENT_BEARER}" -H "Content-Type: application/json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo" --data '{"subject":{"id":"NID-9999","id_type":"national_id"},"claims":["eligible-for-combined-support"],"disclosure":"predicate","format":"application/vnd.registry-notary.claim-result+json"}')"
[[ "${missing_status}" =~ ^(200|404|422)$ ]] || fail "missing-subject evaluation expected stable 200/404/422, got ${missing_status}"
cp /tmp/decentralized-smoke-response.json "${output_dir}/smoke-missing-subject.json"

check "credential-bound evaluation" curl_json POST http://127.0.0.1:4321/claims/evaluate "${CIVIL_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-credential-evaluation.json" -H "Content-Type: application/json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo" -H "Accept: application/dc+sd-jwt" --data '{"subject":{"id":"NID-1001","id_type":"national_id"},"claims":["person-is-alive"],"disclosure":"predicate","format":"application/dc+sd-jwt"}'

check "full demo flow" env DEMO_OUTPUT_DIR="${output_dir}" DEMO_CORRELATION_ID="${correlation_id}" "${script_dir}/demo-flow.py"
grep -R "${correlation_id}" "${output_dir}" >/dev/null || fail "correlation ID artifact"
decision_artifact="$(find "${output_dir}" -maxdepth 1 -name '*household-benefit-decision.json' -print -quit)"
[[ -n "${decision_artifact}" ]] || fail "household benefit decision artifact"
check "household decision has no Relay write-back" json_path_equals "${decision_artifact}" boundary.relay_write_back false

log_file="/tmp/decentralized-smoke-service-logs.txt"
docker compose -f "${compose_file}" logs --no-color civil-registry-relay social-protection-registry-relay health-registry-relay civil-evidence-server social-protection-evidence-server shared-eligibility-evidence-server > "${log_file}"
grep '"error_code":"auth.scope_denied"' "${log_file}" >/dev/null || fail "Relay denied audit event"
grep '"decision":"evaluate"' "${log_file}" >/dev/null || fail "Evidence Server evaluation audit event"
grep '"status_code":200' "${log_file}" >/dev/null || fail "Relay positive audit event"

echo "smoke OK"
