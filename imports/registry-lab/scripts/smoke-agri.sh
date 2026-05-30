#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
output_dir="${AGRI_SMOKE_OUTPUT_DIR:-${demo_dir}/output/agri-smoke}"
correlation_id="${DEMO_CORRELATION_ID:-nagdi-agri-demo-correlation-001}"

relay_url="${AGRI_RELAY_URL:-http://127.0.0.1:4341}"
notary_url="${AGRI_WITNESS_URL:-http://127.0.0.1:4342}"
static_url="${AGRI_STATIC_METADATA_URL:-http://127.0.0.1:4343}"
purpose="${AGRI_DATA_PURPOSE:-https://demo.example.gov/purpose/nagdi/climate-smart-input-support}"
market_purpose="${AGRI_MARKET_DATA_PURPOSE:-https://demo.example.gov/purpose/nagdi/agricultural-market-sizing}"
livestock_purpose="${AGRI_LIVESTOCK_DATA_PURPOSE:-https://demo.example.gov/purpose/nagdi/livestock-movement-permit-review}"
claim="${AGRI_INPUT_VOUCHER_CLAIM:-eligible-for-climate-smart-input-voucher}"
manual_review_claim="${AGRI_INPUT_VOUCHER_REASON_CLAIM:-voucher-eligibility-reason-code}"
livestock_claim="${AGRI_LIVESTOCK_MOVEMENT_CLAIM:-eligible-for-livestock-movement-permit}"
livestock_reason_claim="${AGRI_LIVESTOCK_MOVEMENT_REASON_CLAIM:-livestock-movement-reason-code}"
dataset="${AGRI_FARMER_DATASET:-agri_registry}"
entity="${AGRI_FARMER_ENTITY:-farmer}"
aggregate_path="${AGRI_MARKET_SIZING_PATH:-/v1/datasets/agri_registry/aggregates/voucher_opportunities_by_district_crop_risk_input}"
suppressed_aggregate_path="${AGRI_SUPPRESSED_AGGREGATE_PATH:-/v1/datasets/agri_registry/aggregates/voucher_opportunities_by_district_crop_risk_input}"
suppressed_aggregate_filter="${AGRI_SUPPRESSED_AGGREGATE_FILTER_DISTRICT:-D-WEST}"
livestock_aggregate_path="${AGRI_LIVESTOCK_AGGREGATE_PATH:-/v1/datasets/agri_registry/aggregates/livestock_herds_by_species_district}"
claim_result_format="application/vnd.registry-notary.claim-result+json"

if [[ -f "${demo_dir}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${demo_dir}/.env"
  set +a
else
  echo "missing .env; run just agri-generate first" >&2
  exit 1
fi

fail() {
  echo "FAILED: $1" >&2
  exit 1
}

require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || fail "missing required AGRI token env var: ${name}"
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
  local out="$4"
  shift 4
  local args=(-sS -o "${out}" -w "%{http_code}" -X "${method}" -H "Accept: */*" -H "x-request-id: ${correlation_id}")
  if [[ -n "${token}" ]]; then
    args+=(-H "Authorization: Bearer ${token}")
  fi
  args+=("$@" "${url}")
  curl "${args[@]}"
}

wait_http() {
  local name="$1"
  local url="$2"
  local token="${3:-}"
  local deadline="${SMOKE_WAIT_SECONDS:-90}"
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

json_path_equals() {
  python3 - "$1" "$2" "$3" <<'PY'
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
    value = value.get(part) if isinstance(value, dict) else None
if value != expected_value:
    raise SystemExit(f"{key} expected {expected_value!r}, got {value!r}")
PY
}

json_has_key() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

path, key = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    value = json.load(fh)
for part in key.split("."):
    value = value.get(part) if isinstance(value, dict) else None
if value in (None, [], {}):
    raise SystemExit(f"{key} missing or empty")
PY
}

assert_claim_outcome() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

path, claim, expected = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as fh:
    body = json.load(fh)
results = body.get("results") or body.get("claim_results") or []
if not results:
    raise SystemExit("evaluation has no results")
matched = next(
    (item for item in results if item.get("claim") == claim or item.get("claim_id") == claim),
    results[0],
)
matched_claim = matched.get("claim") or matched.get("claim_id")
if matched_claim not in (None, claim):
    raise SystemExit(f"claim {claim!r} not found in results")
outcome = None
for key in ("value", "satisfied", "outcome", "decision", "verified", "result", "status"):
    if key in matched:
        outcome = matched[key]
        break
if expected == "eligible":
    allowed = {True, "true", "eligible", "pass", "passed", "satisfied", "approved"}
elif expected == "not_eligible":
    allowed = {False, "false", "not_eligible", "denied", "failed", "unsatisfied", "ineligible"}
else:
    allowed = {"manual_review", "review_required", "needs_review"}
if outcome not in allowed:
    raise SystemExit(f"{claim} expected {expected}, got {outcome!r}: {matched}")
PY
}

assert_claim_value() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

path, claim, expected = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as fh:
    body = json.load(fh)
results = body.get("results") or body.get("claim_results") or []
if not results:
    raise SystemExit("evaluation has no results")
matched = next(
    (item for item in results if item.get("claim") == claim or item.get("claim_id") == claim),
    results[0],
)
matched_claim = matched.get("claim") or matched.get("claim_id")
if matched_claim not in (None, claim):
    raise SystemExit(f"claim {claim!r} not found in results")
for key in ("value", "satisfied", "outcome", "result", "decision", "status"):
    if key in matched:
        value = matched[key]
        break
else:
    value = None
if value != expected:
    raise SystemExit(f"{claim} expected value {expected!r}, got {value!r}: {matched}")
PY
}

assert_aggregate_suppression() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    body = json.load(fh)
disclosure = body.get("disclosure_control") if isinstance(body, dict) else None
suppressed = disclosure.get("suppressed_rows") if isinstance(disclosure, dict) else None
if not isinstance(suppressed, int) or suppressed <= 0:
    raise SystemExit(f"expected disclosure_control.suppressed_rows > 0, got {suppressed!r}: {body}")
PY
}

assert_aggregate_empty_rows() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    body = json.load(fh)
rows = body.get("data") if isinstance(body, dict) else None
if rows != []:
    raise SystemExit(f"expected filtered aggregate to publish no rows, got {rows!r}")
PY
}

assert_livestock_aggregate() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    body = json.load(fh)
rows = body.get("data") if isinstance(body, dict) else None
if not isinstance(rows, list) or not rows:
    raise SystemExit(f"expected livestock aggregate to publish at least one row, got {rows!r}")
disclosure = body.get("disclosure_control") if isinstance(body, dict) else None
suppressed = disclosure.get("suppressed_rows") if isinstance(disclosure, dict) else None
if not isinstance(suppressed, int) or suppressed <= 0:
    raise SystemExit(f"expected livestock aggregate suppressed_rows > 0, got {suppressed!r}")
for row in rows:
    for forbidden in ("herd_id", "farmer_id", "animal_id", "tag_id", "livestock_holding_id"):
        if forbidden in row:
            raise SystemExit(f"livestock aggregate leaked row identifier {forbidden}: {row!r}")
PY
}

assert_agri_policy_controls() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    body = json.load(fh)
graph = body.get("@graph") or []
controls = next((item for item in graph if item.get("@id") == "#policy-nagdi-agriculture-governance-controls"), None)
if not controls:
    raise SystemExit("missing NAgDI agricultural governance controls")
expected = {
    "registry_manifest:minimumCellCount": 5,
    "registry_manifest:geographyFloor": "district",
    "registry_manifest:onwardSharingAllowed": False,
    "registry_manifest:automatedDecisionAllowed": False,
    "registry_manifest:auditRequired": True,
}
for key, value in expected.items():
    if controls.get(key) != value:
        raise SystemExit(f"{key} expected {value!r}, got {controls.get(key)!r}")
required_purposes = {
    "https://demo.example.gov/purpose/nagdi/climate-smart-input-support",
    "https://demo.example.gov/purpose/nagdi/livestock-movement-permit-review",
    "https://demo.example.gov/purpose/nagdi/agricultural-market-sizing",
}
if not required_purposes.issubset(set(controls.get("registry_manifest:allowedPurposes") or [])):
    raise SystemExit("agricultural governance controls missing required purposes")
PY
}

assert_minimized_row_artifact() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    body = json.load(fh)
if body.get("minimized") is not True:
    raise SystemExit("row artifact is not marked minimized")
for row in body.get("data") or []:
    for field in ("national_id", "given_name", "family_name"):
        if row.get(field) != "[redacted]":
            raise SystemExit(f"{field} was not redacted in row artifact: {row!r}")
PY
}

assert_denied_status() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    body = json.load(fh)
if body.get("status") not in {400, 403, 422}:
    raise SystemExit(f"expected denial status 400/403/422, got {body.get('status')!r}")
PY
}

assert_denial_code() {
  local path="$1"
  local expected_code="${2:-auth.scope_denied}"
  json_path_equals "${path}" code "${expected_code}"
}

assert_agri_discovery_only() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    body = json.load(fh)
urls = body.get("discovery_urls") or []
bad = [url for url in urls if "agri-" not in url and "nagdi-agriculture" not in url]
if bad:
    raise SystemExit(f"non-agricultural discovery URLs leaked into agri story: {bad!r}")
if not any("nagdi-agriculture-notary" in url for url in urls):
    raise SystemExit("agriculture Notary discovery URL missing")
if not any("agri-registry-relay" in url for url in urls):
    raise SystemExit("agriculture Relay aggregate URL missing")
PY
}

assert_scenario_summary() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    body = json.load(fh)
expected_farmers = {
    "FARMER-1001": ("eligible", None),
    "FARMER-1002": ("not_eligible", "parcel.status:not_active"),
    "FARMER-1003": ("not_eligible", "voucher.redemption:already_redeemed"),
    "FARMER-1004": ("not_eligible", "farmer.registration_status:not_active"),
    "FARMER-1005": ("not_eligible", "data_quality:manual_review_required"),
}
for subject, (observed, reason) in expected_farmers.items():
    got = body["golden_subjects"][subject]
    if got.get("observed") != observed or got.get("reason_code") != reason:
        raise SystemExit(f"{subject} summary mismatch: {got!r}")
expected_herds = {
    "HERD-2001": ("eligible", None),
    "HERD-2002": ("not_eligible", "livestock.vaccination:expired"),
    "HERD-2003": ("not_eligible", "quarantine.origin:active"),
}
for subject, (observed, reason) in expected_herds.items():
    got = body["livestock_subjects"][subject]
    if got.get("observed") != observed or got.get("reason_code") != reason:
        raise SystemExit(f"{subject} summary mismatch: {got!r}")
market = body.get("market_sizing") or {}
if market.get("filtered_rows_seen") != 0 or not isinstance(market.get("filtered_suppressed_rows"), int) or market["filtered_suppressed_rows"] <= 0:
    raise SystemExit(f"market sizing filtered suppression mismatch: {market!r}")
livestock = body.get("livestock_planning") or {}
if not isinstance(livestock.get("aggregate_rows_seen"), int) or livestock["aggregate_rows_seen"] <= 0:
    raise SystemExit(f"livestock planning aggregate missing publishable rows: {livestock!r}")
if not isinstance(livestock.get("suppressed_rows"), int) or livestock["suppressed_rows"] <= 0:
    raise SystemExit(f"livestock planning aggregate missing suppression proof: {livestock!r}")
if livestock.get("row_export_allowed") is not False or livestock.get("contains_individual_animal_rows") is not False:
    raise SystemExit(f"livestock planning aggregate boundary mismatch: {livestock!r}")
if not body.get("credential_issuance", {}).get("credential_present"):
    raise SystemExit("credential issuance not represented in scenario summary")
if len(body.get("source_workbooks") or []) != 7:
    raise SystemExit("scenario summary should list the seven agricultural workbooks")
PY
}

for name in \
  AGRI_METADATA_CLIENT_RAW \
  AGRI_EVIDENCE_ONLY_RAW \
  AGRI_ROW_READER_RAW \
  AGRI_AGGREGATE_READER_RAW \
  AGRI_EVIDENCE_CLIENT_BEARER
do
  require_env "${name}"
done

rm -rf "${output_dir}"
mkdir -p "${output_dir}"

wait_http "agricultural relay health" "${relay_url}/healthz" "${AGRI_METADATA_CLIENT_RAW}"
wait_http "agricultural relay ready" "${relay_url}/ready" "${AGRI_METADATA_CLIENT_RAW}"
wait_http "agriculture Notary discovery" "${notary_url}/.well-known/evidence-service" "${AGRI_EVIDENCE_CLIENT_BEARER}"
wait_http "agricultural static metadata publisher" "${static_url}/.well-known/api-catalog" ""

check "agricultural relay health" curl_json GET "${relay_url}/healthz" "${AGRI_METADATA_CLIENT_RAW}" "${output_dir}/agri-relay-health.json"
check "agricultural relay ready" curl_json GET "${relay_url}/ready" "${AGRI_METADATA_CLIENT_RAW}" "${output_dir}/agri-relay-ready.json"
check "agricultural relay OpenAPI" curl_json GET "${relay_url}/openapi.json" "${AGRI_METADATA_CLIENT_RAW}" "${output_dir}/agri-relay-openapi.json"
check "agricultural datasets" curl_json GET "${relay_url}/v1/datasets" "${AGRI_METADATA_CLIENT_RAW}" "${output_dir}/agri-datasets.json"
check "agricultural evidence offerings" curl_json GET "${relay_url}/metadata/evidence-offerings" "${AGRI_METADATA_CLIENT_RAW}" "${output_dir}/agri-relay-evidence-offerings.json"

check "agriculture Notary discovery" curl_json GET "${notary_url}/.well-known/evidence-service" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-notary-discovery.json"
check "agriculture Notary OpenAPI" curl_json GET "${notary_url}/openapi.json" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-notary-openapi.json"
check "agriculture Notary claims" curl_json GET "${notary_url}/v1/claims" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-notary-claims.json"

check "agricultural static api catalog" curl_json GET "${static_url}/.well-known/api-catalog" "" "${output_dir}/agri-static-api-catalog.json"
check "agricultural static metadata index" curl_json GET "${static_url}/metadata/index.json" "" "${output_dir}/agri-static-metadata-index.json"
check "agricultural static evidence offerings" curl_json GET "${static_url}/metadata/evidence-offerings.json" "" "${output_dir}/agri-static-evidence-offerings.json"
check "agricultural static policies" curl_json GET "${static_url}/metadata/policies.jsonld" "" "${output_dir}/agri-static-policies.json"
check "static metadata names climate-smart service" json_has_key "${output_dir}/agri-static-evidence-offerings.json" evidence_offerings
check "static policy governance controls" assert_agri_policy_controls "${output_dir}/agri-static-policies.json"

row_denial_status="$(curl_status GET "${relay_url}/v1/datasets/${dataset}/entities/${entity}/records?limit=1" "${AGRI_EVIDENCE_ONLY_RAW}" "${output_dir}/agri-row-denial-evidence-only.json" -H "Data-Purpose: ${purpose}")"
[[ "${row_denial_status}" == "403" ]] || fail "evidence-only credential row denial expected 403, got ${row_denial_status}"
check "evidence-only row denial code" assert_denial_code "${output_dir}/agri-row-denial-evidence-only.json"

aggregate_only_row_status="$(curl_status GET "${relay_url}/v1/datasets/${dataset}/entities/${entity}/records?limit=1" "${AGRI_AGGREGATE_READER_RAW}" "${output_dir}/agri-row-denial-aggregate-only.json" -H "Data-Purpose: ${purpose}")"
[[ "${aggregate_only_row_status}" == "403" ]] || fail "aggregate-only credential row denial expected 403, got ${aggregate_only_row_status}"
check "aggregate-only row denial code" assert_denial_code "${output_dir}/agri-row-denial-aggregate-only.json"

for protected_entity in parcel voucher_entitlement voucher_redemption livestock_holding herd movement_permit; do
  entity_denial_status="$(curl_status GET "${relay_url}/v1/datasets/${dataset}/entities/${protected_entity}/records?limit=1" "${AGRI_AGGREGATE_READER_RAW}" "${output_dir}/agri-row-denial-aggregate-only-${protected_entity}.json" -H "Data-Purpose: ${purpose}")"
  [[ "${entity_denial_status}" == "403" ]] || fail "aggregate-only credential ${protected_entity} row denial expected 403, got ${entity_denial_status}"
  check "aggregate-only ${protected_entity} row denial code" assert_denial_code "${output_dir}/agri-row-denial-aggregate-only-${protected_entity}.json"
done

missing_purpose_status="$(curl_status GET "${relay_url}/v1/datasets/${dataset}/entities/${entity}/records?limit=1" "${AGRI_ROW_READER_RAW}" "${output_dir}/agri-row-denial-missing-purpose.json")"
[[ "${missing_purpose_status}" =~ ^(400|403|422)$ ]] || fail "missing Data-Purpose denial expected 400/403/422, got ${missing_purpose_status}"

check "positive farmer row read" curl_json GET "${relay_url}/v1/datasets/${dataset}/entities/${entity}/records?limit=1" "${AGRI_ROW_READER_RAW}" "${output_dir}/agri-positive-row-read.json" -H "Data-Purpose: ${purpose}"

aggregate_denial_status="$(curl_status GET "${relay_url}${aggregate_path}" "${AGRI_ROW_READER_RAW}" "${output_dir}/agri-aggregate-denial-row-reader.json" -H "Data-Purpose: ${market_purpose}")"
[[ "${aggregate_denial_status}" == "403" ]] || fail "row-reader aggregate denial expected 403, got ${aggregate_denial_status}"
check "row-reader aggregate denial code" assert_denial_code "${output_dir}/agri-aggregate-denial-row-reader.json"

check "positive agricultural aggregate" curl_json GET "${relay_url}${aggregate_path}" "${AGRI_AGGREGATE_READER_RAW}" "${output_dir}/agri-positive-aggregate.json" -H "Data-Purpose: ${market_purpose}"
check "agricultural aggregate proves suppression" assert_aggregate_suppression "${output_dir}/agri-positive-aggregate.json"

check "positive livestock herd aggregate" curl_json GET "${relay_url}${livestock_aggregate_path}" "${AGRI_AGGREGATE_READER_RAW}" "${output_dir}/agri-positive-livestock-aggregate.json" -H "Data-Purpose: ${livestock_purpose}"
check "livestock herd aggregate proves planning boundary" assert_livestock_aggregate "${output_dir}/agri-positive-livestock-aggregate.json"

suppressed_status="$(curl_status POST "${relay_url}${suppressed_aggregate_path%/}/query" "${AGRI_AGGREGATE_READER_RAW}" "${output_dir}/agri-suppressed-aggregate.json" -H "Content-Type: application/json" -H "Data-Purpose: ${market_purpose}" --data "{\"filters\":{\"district_code\":\"${suppressed_aggregate_filter}\"}}")"
[[ "${suppressed_status}" == "200" ]] || fail "suppressed aggregate expected 200 with suppressed_groups, got ${suppressed_status}"
check "filtered agricultural aggregate proves suppression" assert_aggregate_suppression "${output_dir}/agri-suppressed-aggregate.json"
check "filtered agricultural aggregate publishes no rows" assert_aggregate_empty_rows "${output_dir}/agri-suppressed-aggregate.json"

check "eligible voucher evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-farmer-1001.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"FARMER-1001\",\"id_type\":\"farmer_id\"},\"claims\":[\"${claim}\"],\"disclosure\":\"predicate\",\"format\":\"${claim_result_format}\"}"
check "FARMER-1001 is eligible" assert_claim_outcome "${output_dir}/agri-evaluation-farmer-1001.json" "${claim}" eligible

check "denied voucher evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-farmer-1002.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"FARMER-1002\",\"id_type\":\"farmer_id\"},\"claims\":[\"${claim}\"],\"disclosure\":\"predicate\",\"format\":\"${claim_result_format}\"}"
check "FARMER-1002 is not eligible" assert_claim_outcome "${output_dir}/agri-evaluation-farmer-1002.json" "${claim}" not_eligible
check "FARMER-1002 reason evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-farmer-1002-reason.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"FARMER-1002\",\"id_type\":\"farmer_id\"},\"claims\":[\"${manual_review_claim}\"],\"disclosure\":\"value\",\"format\":\"${claim_result_format}\"}"
check "FARMER-1002 inactive parcel reason" assert_claim_value "${output_dir}/agri-evaluation-farmer-1002-reason.json" "${manual_review_claim}" "parcel.status:not_active"

check "already-redeemed farmer evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-farmer-1003.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"FARMER-1003\",\"id_type\":\"farmer_id\"},\"claims\":[\"${claim}\"],\"disclosure\":\"predicate\",\"format\":\"${claim_result_format}\"}"
check "FARMER-1003 is not eligible" assert_claim_outcome "${output_dir}/agri-evaluation-farmer-1003.json" "${claim}" not_eligible
check "FARMER-1003 reason evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-farmer-1003-reason.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"FARMER-1003\",\"id_type\":\"farmer_id\"},\"claims\":[\"${manual_review_claim}\"],\"disclosure\":\"value\",\"format\":\"${claim_result_format}\"}"
check "FARMER-1003 redeemed voucher reason" assert_claim_value "${output_dir}/agri-evaluation-farmer-1003-reason.json" "${manual_review_claim}" "voucher.redemption:already_redeemed"

check "stale registration farmer evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-farmer-1004.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"FARMER-1004\",\"id_type\":\"farmer_id\"},\"claims\":[\"${claim}\"],\"disclosure\":\"predicate\",\"format\":\"${claim_result_format}\"}"
check "FARMER-1004 is not eligible" assert_claim_outcome "${output_dir}/agri-evaluation-farmer-1004.json" "${claim}" not_eligible
check "FARMER-1004 reason evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-farmer-1004-reason.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"FARMER-1004\",\"id_type\":\"farmer_id\"},\"claims\":[\"${manual_review_claim}\"],\"disclosure\":\"value\",\"format\":\"${claim_result_format}\"}"
check "FARMER-1004 inactive registration reason" assert_claim_value "${output_dir}/agri-evaluation-farmer-1004-reason.json" "${manual_review_claim}" "farmer.registration_status:not_active"

check "manual-review farmer evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-farmer-1005.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"FARMER-1005\",\"id_type\":\"farmer_id\"},\"claims\":[\"${claim}\"],\"disclosure\":\"predicate\",\"format\":\"${claim_result_format}\"}"
check "FARMER-1005 is not auto-eligible" assert_claim_outcome "${output_dir}/agri-evaluation-farmer-1005.json" "${claim}" not_eligible

check "manual-review reason evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-farmer-1005-reason.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"FARMER-1005\",\"id_type\":\"farmer_id\"},\"claims\":[\"${manual_review_claim}\"],\"disclosure\":\"value\",\"format\":\"${claim_result_format}\"}"
check "FARMER-1005 requires manual review" assert_claim_value "${output_dir}/agri-evaluation-farmer-1005-reason.json" "${manual_review_claim}" "data_quality:manual_review_required"

check "eligible livestock movement evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-herd-2001.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${livestock_purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"HERD-2001\",\"id_type\":\"herd_id\"},\"claims\":[\"${livestock_claim}\"],\"disclosure\":\"predicate\",\"format\":\"${claim_result_format}\"}"
check "HERD-2001 is eligible" assert_claim_outcome "${output_dir}/agri-evaluation-herd-2001.json" "${livestock_claim}" eligible

check "expired-vaccination livestock movement evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-herd-2002.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${livestock_purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"HERD-2002\",\"id_type\":\"herd_id\"},\"claims\":[\"${livestock_claim}\"],\"disclosure\":\"predicate\",\"format\":\"${claim_result_format}\"}"
check "HERD-2002 is not eligible" assert_claim_outcome "${output_dir}/agri-evaluation-herd-2002.json" "${livestock_claim}" not_eligible
check "HERD-2002 reason evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-herd-2002-reason.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${livestock_purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"HERD-2002\",\"id_type\":\"herd_id\"},\"claims\":[\"${livestock_reason_claim}\"],\"disclosure\":\"value\",\"format\":\"${claim_result_format}\"}"
check "HERD-2002 expired vaccination reason" assert_claim_value "${output_dir}/agri-evaluation-herd-2002-reason.json" "${livestock_reason_claim}" "livestock.vaccination:expired"

check "quarantine livestock movement evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-herd-2003.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${livestock_purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"HERD-2003\",\"id_type\":\"herd_id\"},\"claims\":[\"${livestock_claim}\"],\"disclosure\":\"predicate\",\"format\":\"${claim_result_format}\"}"
check "HERD-2003 is not eligible" assert_claim_outcome "${output_dir}/agri-evaluation-herd-2003.json" "${livestock_claim}" not_eligible
check "HERD-2003 reason evaluation" curl_json POST "${notary_url}/v1/evaluations" "${AGRI_EVIDENCE_CLIENT_BEARER}" "${output_dir}/agri-evaluation-herd-2003-reason.json" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: ${livestock_purpose}" \
  -H "Accept: ${claim_result_format}" \
  --data "{\"subject\":{\"id\":\"HERD-2003\",\"id_type\":\"herd_id\"},\"claims\":[\"${livestock_reason_claim}\"],\"disclosure\":\"value\",\"format\":\"${claim_result_format}\"}"
check "HERD-2003 quarantine reason" assert_claim_value "${output_dir}/agri-evaluation-herd-2003-reason.json" "${livestock_reason_claim}" "quarantine.origin:active"

check "narrated agricultural client" env DEMO_OUTPUT_DIR="${demo_dir}/output/agri-client" DEMO_CORRELATION_ID="${correlation_id}" "${script_dir}/demo-agri-flow.py"
grep -R "${correlation_id}" "${demo_dir}/output/agri-client" >/dev/null || fail "agricultural client correlation ID artifact"
check "agricultural client discovery stays in agri story" assert_agri_discovery_only "${demo_dir}/output/agri-client/10-discovered-evidence-urls.json"
scenario_artifact="$(find "${demo_dir}/output/agri-client" -maxdepth 1 -name "*-scenario-summary.json" -print -quit)"
row_artifact="$(find "${demo_dir}/output/agri-client" -maxdepth 1 -name "*-positive-farmer-row-read.json" -print -quit)"
credential_denial_artifact="$(find "${demo_dir}/output/agri-client" -maxdepth 1 -name "*-credential-denial-missing-holder-proof.json" -print -quit)"
[[ -n "${scenario_artifact}" ]] || fail "agricultural client scenario summary missing"
[[ -n "${row_artifact}" ]] || fail "agricultural client row artifact missing"
[[ -n "${credential_denial_artifact}" ]] || fail "agricultural client credential denial artifact missing"
check "agricultural client scenario summary" assert_scenario_summary "${scenario_artifact}"
check "agricultural client minimized row artifact" assert_minimized_row_artifact "${row_artifact}"
check "agricultural client denied missing holder proof" assert_denied_status "${credential_denial_artifact}"
credential_artifact="$(find "${demo_dir}/output/agri-client" -maxdepth 1 -name "*-climate-smart-input-voucher-credential.json" -print -quit)"
[[ -n "${credential_artifact}" ]] || fail "agricultural client credential artifact missing"
check "agricultural client issued credential artifact" json_has_key "${credential_artifact}" credential

log_file="${output_dir}/agri-service-logs.txt"
if docker compose -f "${compose_file}" logs --no-color agri-registry-relay nagdi-agriculture-notary > "${log_file}" 2>/dev/null; then
  grep '"error_code":"auth.scope_denied"' "${log_file}" >/dev/null || fail "Relay denied audit event"
  grep '"decision":"evaluate"' "${log_file}" >/dev/null || fail "Notary evaluation audit event"
else
  echo "warning: could not collect agri service logs from compose; skipping audit log grep" >&2
fi

for secret_var in \
  AGRI_METADATA_CLIENT_RAW \
  AGRI_EVIDENCE_SOURCE_RAW \
  AGRI_EVIDENCE_ONLY_RAW \
  AGRI_ROW_READER_RAW \
  AGRI_AGGREGATE_READER_RAW \
  AGRI_EVIDENCE_CLIENT_TOKEN \
  AGRI_EVIDENCE_CLIENT_BEARER
do
  secret_value="${!secret_var:-}"
  if [[ -n "${secret_value}" ]] && grep -R -F -- "${secret_value}" "${output_dir}" "${demo_dir}/output/agri-client" >/dev/null; then
    fail "agricultural artifacts leaked ${secret_var}"
  fi
done

echo "agricultural smoke OK"
