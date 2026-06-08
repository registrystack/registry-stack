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

evaluation_payload() {
  local target_id="$1"
  local identifier_scheme="$2"
  local claim="$3"
  local disclosure="${4:-predicate}"
  local format="${5:-application/vnd.registry-notary.claim-result+json}"
  jq -nc \
    --arg target_id "${target_id}" \
    --arg identifier_scheme "${identifier_scheme}" \
    --arg claim "${claim}" \
    --arg disclosure "${disclosure}" \
    --arg format "${format}" \
    '{
      target: {
        type: "Person",
        identifiers: [{ scheme: $identifier_scheme, value: $target_id }]
      },
      claims: [$claim],
      disclosure: $disclosure,
      format: $format
    }'
}

curl_json_api_key() {
  local method="$1"
  local url="$2"
  local token="$3"
  local out="$4"
  shift 4
  local args=(-fsS -X "${method}" -H "Accept: */*" -H "x-request-id: ${correlation_id}" -H "x-api-key: ${token}")
  args+=("$@" -o "${out}" "${url}")
  curl "${args[@]}"
}

curl_doc() {
  local url="$1"
  local out="$2"
  curl -fsS -H "Accept: text/html" -H "x-request-id: ${correlation_id}" -o "${out}" "${url}"
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

assert_head_contains() {
  local url="$1"
  local expected="$2"
  curl -fsSI -H "x-request-id: ${correlation_id}" "${url}" | tr -d '\r' | grep -F "${expected}" >/dev/null
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

assert_claim_outcome() {
  python - "$1" "$2" "$3" <<'PY'
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
actual = matched.get("satisfied")
if actual is None:
    actual = matched.get("value")
expected_value = expected == "true"
if actual is not expected_value:
    raise SystemExit(f"{claim} expected {expected_value}, got {actual!r}: {matched}")
PY
}

atlas_service_view() {
  local atlas_root
  atlas_root="$("${script_dir}/check-service-first-deps.sh" atlas-path)"
  (
    cd "${atlas_root}"
    cargo run --quiet -p semantic-asset-discovery-cli --bin semantic-asset-discovery -- analyze \
      --entry-url http://127.0.0.1:4331/metadata/cpsv-ap.jsonld \
      "${output_dir}/smoke-static-cpsv-ap.jsonld" > "${output_dir}/smoke-atlas-service-report.json"
    cargo run --quiet -p semantic-asset-discovery-cli --bin semantic-asset-discovery -- service-view \
      https://demo.example.gov/services/health-linked-child-support \
      --report "${output_dir}/smoke-atlas-service-report.json" > "${output_dir}/smoke-atlas-service-view.json"
  )
  python - "${output_dir}/smoke-atlas-service-view.json" <<'PY'
import json
import sys

view = json.load(open(sys.argv[1], encoding="utf-8"))
expected = {
    "requirements": 1,
    "accepted_evidence_types": 4,
    "providers": 4,
    "forms": 1,
}
for key, minimum in expected.items():
    actual = len(view.get(key, []))
    if actual < minimum:
        raise SystemExit(f"{key} expected at least {minimum}, got {actual}")
if view.get("gaps"):
    raise SystemExit(f"service graph has gaps: {view['gaps']}")
option_count = sum(len(req.get("evidence_options", [])) for req in view.get("requirements", []))
if option_count < 2:
    raise SystemExit(f"service graph expected grouped evidence options, got {option_count}")
if not any(
    option.get("satisfiable") is True and len(option.get("evidence_types", [])) == 1
    for req in view.get("requirements", [])
    for option in req.get("evidence_options", [])
):
    raise SystemExit("service graph did not preserve the satisfiable single-record evidence option")
if not any(route.get("kind") == "evidence_access_service" for route in view.get("routes", [])):
    raise SystemExit("service graph has no evidence access service route")
PY
}

mkdir -p "${output_dir}"

if [[ "${REGISTRY_LAB_CHECK_ATLAS:-1}" == "1" ]]; then
  check "service-first sibling dependencies" "${script_dir}/check-service-first-deps.sh" all
else
  check "service-first manifest dependency" "${script_dir}/check-service-first-deps.sh" manifest
fi

wait_http "civil relay health" http://127.0.0.1:4311/healthz "${CIVIL_METADATA_CLIENT_RAW}"
wait_http "social relay health" http://127.0.0.1:4312/healthz "${SOCIAL_METADATA_CLIENT_RAW}"
wait_http "health relay health" http://127.0.0.1:4313/healthz "${HEALTH_METADATA_CLIENT_RAW}"
wait_http "civil evidence discovery" http://127.0.0.1:4321/.well-known/evidence-service "${CIVIL_EVIDENCE_CLIENT_BEARER}"
wait_http "social evidence discovery" http://127.0.0.1:4322/.well-known/evidence-service "${SOCIAL_EVIDENCE_CLIENT_BEARER}"
wait_http "shared evidence discovery" http://127.0.0.1:4323/.well-known/evidence-service "${SHARED_EVIDENCE_CLIENT_BEARER}"
wait_http "static metadata publisher" http://127.0.0.1:4331/.well-known/api-catalog ""

check "civil relay health" curl_json GET http://127.0.0.1:4311/healthz "${CIVIL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-civil-health.json"
check "social relay health" curl_json GET http://127.0.0.1:4312/healthz "${SOCIAL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-social-health.json"
check "health relay health" curl_json GET http://127.0.0.1:4313/healthz "${HEALTH_METADATA_CLIENT_RAW}" "${output_dir}/smoke-health-health.json"

check "civil relay ready" curl_json GET http://127.0.0.1:4311/ready "${CIVIL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-civil-ready.json"
check "social relay ready" curl_json GET http://127.0.0.1:4312/ready "${SOCIAL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-social-ready.json"
check "health relay ready" curl_json GET http://127.0.0.1:4313/ready "${HEALTH_METADATA_CLIENT_RAW}" "${output_dir}/smoke-health-ready.json"

check "civil evidence discovery" curl_json GET http://127.0.0.1:4321/.well-known/evidence-service "${CIVIL_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-civil-evidence-discovery.json"
check "civil evidence discovery x-api-key" curl_json_api_key GET http://127.0.0.1:4321/.well-known/evidence-service "${CIVIL_EVIDENCE_CLIENT_TOKEN}" "${output_dir}/smoke-civil-evidence-discovery-api-key.json"
check "social evidence discovery" curl_json GET http://127.0.0.1:4322/.well-known/evidence-service "${SOCIAL_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-social-evidence-discovery.json"
check "social evidence discovery x-api-key" curl_json_api_key GET http://127.0.0.1:4322/.well-known/evidence-service "${SOCIAL_EVIDENCE_CLIENT_TOKEN}" "${output_dir}/smoke-social-evidence-discovery-api-key.json"
check "shared evidence discovery" curl_json GET http://127.0.0.1:4323/.well-known/evidence-service "${SHARED_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-shared-evidence-discovery.json"
check "shared evidence discovery x-api-key" curl_json_api_key GET http://127.0.0.1:4323/.well-known/evidence-service "${SHARED_EVIDENCE_CLIENT_TOKEN}" "${output_dir}/smoke-shared-evidence-discovery-api-key.json"

check "civil relay OpenAPI" curl_json GET http://127.0.0.1:4311/openapi.json "" "${output_dir}/smoke-civil-openapi.json"
check "social relay OpenAPI" curl_json GET http://127.0.0.1:4312/openapi.json "" "${output_dir}/smoke-social-openapi.json"
check "health relay OpenAPI" curl_json GET http://127.0.0.1:4313/openapi.json "" "${output_dir}/smoke-health-openapi.json"

check "civil Evidence Server OpenAPI" curl_json GET http://127.0.0.1:4321/openapi.json "" "${output_dir}/smoke-civil-evidence-openapi.json"
check "social Evidence Server OpenAPI" curl_json GET http://127.0.0.1:4322/openapi.json "" "${output_dir}/smoke-social-evidence-openapi.json"
check "shared Evidence Server OpenAPI" curl_json GET http://127.0.0.1:4323/openapi.json "" "${output_dir}/smoke-shared-evidence-openapi.json"

check "civil Evidence Server API docs" curl_doc http://127.0.0.1:4321/docs "${output_dir}/smoke-civil-evidence-docs.html"
check "social Evidence Server API docs" curl_doc http://127.0.0.1:4322/docs "${output_dir}/smoke-social-evidence-docs.html"
check "shared Evidence Server API docs" curl_doc http://127.0.0.1:4323/docs "${output_dir}/smoke-shared-evidence-docs.html"

check "civil relay evidence offerings" curl_json GET http://127.0.0.1:4311/metadata/evidence-offerings "${CIVIL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-civil-offerings.json"
check "social relay evidence offerings" curl_json GET http://127.0.0.1:4312/metadata/evidence-offerings "${SOCIAL_METADATA_CLIENT_RAW}" "${output_dir}/smoke-social-offerings.json"
check "health relay evidence offerings" curl_json GET http://127.0.0.1:4313/metadata/evidence-offerings "${HEALTH_METADATA_CLIENT_RAW}" "${output_dir}/smoke-health-offerings.json"
check "static api-catalog media type" assert_head_contains http://127.0.0.1:4331/.well-known/api-catalog "Content-type: application/linkset+json"
check "static api-catalog link header" assert_head_contains http://127.0.0.1:4331/.well-known/api-catalog 'Link: </.well-known/api-catalog>; rel="api-catalog"'
check "static JSON-LD media type" assert_head_contains http://127.0.0.1:4331/metadata/cpsv-ap.jsonld "Content-type: application/ld+json"
check "static metadata bootstrap" curl_json GET http://127.0.0.1:4331/.well-known/api-catalog "" "${output_dir}/smoke-static-api-catalog.json"
check "static legacy metadata bootstrap" curl_json GET http://127.0.0.1:4331/.well-known/registry-manifest.json "" "${output_dir}/smoke-static-well-known.json"
check "static metadata index" curl_json GET http://127.0.0.1:4331/metadata/index.json "" "${output_dir}/smoke-static-metadata-index.json"
check "static evidence offerings" curl_json GET http://127.0.0.1:4331/metadata/evidence-offerings.json "" "${output_dir}/smoke-static-offerings.json"
check "static policy metadata" curl_json GET http://127.0.0.1:4331/metadata/policies.jsonld "" "${output_dir}/smoke-static-policies.json"
check "static BRegDCAT profile route" curl_json GET http://127.0.0.1:4331/metadata/dcat/bregdcat-ap "" "${output_dir}/smoke-static-bregdcat-ap.jsonld"
check "static CPSV-AP service catalogue" curl_json GET http://127.0.0.1:4331/metadata/cpsv-ap.jsonld "" "${output_dir}/smoke-static-cpsv-ap.jsonld"
check "static service form schema" curl_json GET http://127.0.0.1:4331/metadata/forms/health_linked_child_support_form/schema.json "" "${output_dir}/smoke-service-form-schema.json"
check "static bootstrap links CPSV-AP route" python - "${output_dir}/smoke-static-cpsv-ap.jsonld" "${output_dir}/smoke-static-metadata-index.json" "${output_dir}/smoke-static-api-catalog.json" "${output_dir}/smoke-static-well-known.json" <<'PY'
import json
import sys

cpsv_path, index_path, api_catalog_path, discovery_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
cpsv = json.load(open(cpsv_path, encoding="utf-8"))
index = json.load(open(index_path, encoding="utf-8"))
api_catalog = json.load(open(api_catalog_path, encoding="utf-8"))
discovery = json.load(open(discovery_path, encoding="utf-8"))
service_iri = "https://demo.example.gov/services/health-linked-child-support"

graph = cpsv.get("@graph", [])
if not any(
    isinstance(node, dict)
    and node.get("@id") == service_iri
    and "cpsv:PublicService" in ([node.get("@type")] if isinstance(node.get("@type"), str) else node.get("@type", []))
    for node in graph
):
    raise SystemExit("CPSV-AP catalogue does not include the health-linked child support public service")

linksets = api_catalog.get("linkset", [])
if not linksets:
    raise SystemExit("api-catalog does not contain a Linkset")
describedby = linksets[0].get("describedby", [])
items = linksets[0].get("item", [])
if not any(item.get("href") == "/metadata/index.json" for item in describedby):
    raise SystemExit("api-catalog does not describe the metadata index")
if not any(item.get("href") == "/metadata/cpsv-ap.jsonld" for item in items):
    raise SystemExit("api-catalog does not advertise the CPSV-AP JSON-LD service catalogue")

catalogues = discovery.get("service_catalogues", [])
cpsv_entry = next((item for item in catalogues if item.get("id") == "cpsv-ap"), None)
if not cpsv_entry:
    raise SystemExit("well-known discovery does not advertise CPSV-AP")
if cpsv_entry.get("url") != "/metadata/cpsv-ap.jsonld":
    raise SystemExit("well-known discovery does not link /metadata/cpsv-ap.jsonld")
if "/metadata/cpsv-ap" not in cpsv_entry.get("aliases", []):
    raise SystemExit("well-known discovery does not retain /metadata/cpsv-ap alias")
index_catalogues = index.get("service_catalogues", [])
if not any(item.get("id") == "cpsv-ap" and item.get("url") == cpsv_entry.get("url") for item in index_catalogues):
    raise SystemExit("metadata index does not match well-known CPSV-AP URL")
form_schemas = index.get("form_schemas", [])
if not any(item.get("form") == "health_linked_child_support_form" for item in form_schemas):
    raise SystemExit("metadata index does not link the service form JSON Schema")
PY
if [[ "${REGISTRY_LAB_CHECK_ATLAS:-1}" == "1" ]]; then
  check "Atlas service graph discovery" atlas_service_view
fi

status="$(curl_status GET http://127.0.0.1:4312/v1/datasets/social_protection_registry/entities/household/records?limit=1 "${SOCIAL_EVIDENCE_ONLY_RAW}" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo")"
[[ "${status}" == "403" ]] || fail "row denial with evidence-only credential expected 403, got ${status}"
cp /tmp/decentralized-smoke-response.json "${output_dir}/smoke-row-denial.json"
check "row denial stable error code" json_path_equals "${output_dir}/smoke-row-denial.json" code auth.scope_denied

check "positive row read" curl_json GET "http://127.0.0.1:4312/v1/datasets/social_protection_registry/entities/household/records?limit=1" "${SOCIAL_ROW_READER_RAW}" "${output_dir}/smoke-positive-row-read.json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo"
check "positive aggregate consultation" curl_json GET "http://127.0.0.1:4312/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band" "${SOCIAL_AGGREGATE_READER_RAW}" "${output_dir}/smoke-positive-aggregate.json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo"
check "positive EDR collection discovery" curl_json GET "http://127.0.0.1:4312/ogc/edr/v1/collections/social_protection_households_by_district" "${SOCIAL_AGGREGATE_READER_RAW}" "${output_dir}/smoke-positive-edr-collection.json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo"
check "positive EDR area aggregate" curl_json GET "http://127.0.0.1:4312/ogc/edr/v1/collections/social_protection_households_by_district/area?coords=POLYGON%28%28-0.5%200.5%2C1.5%200.5%2C1.5%201.5%2C-0.5%201.5%2C-0.5%200.5%29%29&parameter-name=household_count&group_by=district&f=geojson" "${SOCIAL_AGGREGATE_READER_RAW}" "${output_dir}/smoke-positive-edr-area.json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo"
check "positive EDR area features" json_has_key "${output_dir}/smoke-positive-edr-area.json" features

aggregate_status="$(curl_status GET http://127.0.0.1:4312/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band "${SOCIAL_ROW_READER_RAW}" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo")"
[[ "${aggregate_status}" == "403" ]] || fail "aggregate denial with row-reader credential expected 403, got ${aggregate_status}"
cp /tmp/decentralized-smoke-response.json "${output_dir}/smoke-aggregate-denial.json"
check "aggregate denial stable error code" json_path_equals "${output_dir}/smoke-aggregate-denial.json" code auth.scope_denied

check "civil evidence evaluation" curl_json POST http://127.0.0.1:4321/v1/evaluations "${CIVIL_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-civil-evaluation.json" -H "Content-Type: application/json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo" --data "$(evaluation_payload "NID-1001" "national_id" "person-is-alive")"
check "civil evidence evaluation results" json_has_key "${output_dir}/smoke-civil-evaluation.json" results

check "health evidence evaluation" curl_json POST http://127.0.0.1:4323/v1/evaluations "${SHARED_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-health-evaluation.json" -H "Content-Type: application/json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo" --data "$(evaluation_payload "NID-1001" "national_id" "health-service-available")"
check "health evidence evaluation results" json_has_key "${output_dir}/smoke-health-evaluation.json" results

check "shared evidence evaluation" curl_json POST http://127.0.0.1:4323/v1/evaluations "${SHARED_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-shared-evaluation.json" -H "Content-Type: application/json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo" --data "$(evaluation_payload "NID-1001" "national_id" "eligible-for-combined-support")"
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

matrix_cases=(
  "civil|http://127.0.0.1:4321/v1/evaluations|CIVIL_EVIDENCE_CLIENT_BEARER|person-is-alive|NID-1001|true"
  "civil|http://127.0.0.1:4321/v1/evaluations|CIVIL_EVIDENCE_CLIENT_BEARER|person-is-alive|NID-1002|true"
  "civil|http://127.0.0.1:4321/v1/evaluations|CIVIL_EVIDENCE_CLIENT_BEARER|person-is-alive|NID-1003|false"
  "civil|http://127.0.0.1:4321/v1/evaluations|CIVIL_EVIDENCE_CLIENT_BEARER|person-is-alive|NID-1004|true"
  "civil|http://127.0.0.1:4321/v1/evaluations|CIVIL_EVIDENCE_CLIENT_BEARER|person-is-alive|NID-1005|true"
  "civil|http://127.0.0.1:4321/v1/evaluations|CIVIL_EVIDENCE_CLIENT_BEARER|person-is-alive|NID-1006|true"
  "civil|http://127.0.0.1:4321/v1/evaluations|CIVIL_EVIDENCE_CLIENT_BEARER|person-is-alive|NID-1007|true"
  "civil|http://127.0.0.1:4321/v1/evaluations|CIVIL_EVIDENCE_CLIENT_BEARER|person-is-alive|NID-1008|true"
  "civil|http://127.0.0.1:4321/v1/evaluations|CIVIL_EVIDENCE_CLIENT_BEARER|person-is-alive|NID-1009|true"
  "civil|http://127.0.0.1:4321/v1/evaluations|CIVIL_EVIDENCE_CLIENT_BEARER|person-is-alive|NID-1010|true"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|health-service-available|NID-1001|true"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|health-service-available|NID-1002|false"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|health-service-available|NID-1003|true"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|health-service-available|NID-1004|true"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|health-service-available|NID-1005|false"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|health-service-available|NID-1006|true"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|health-service-available|NID-1007|true"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|health-service-available|NID-1008|true"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|health-service-available|NID-1009|true"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|health-service-available|NID-1010|false"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|eligible-for-combined-support|NID-1001|true"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|eligible-for-combined-support|NID-1002|false"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|eligible-for-combined-support|NID-1003|false"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|eligible-for-combined-support|NID-1004|true"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|eligible-for-combined-support|NID-1005|false"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|eligible-for-combined-support|NID-1006|true"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|eligible-for-combined-support|NID-1007|false"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|eligible-for-combined-support|NID-1008|true"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|eligible-for-combined-support|NID-1009|false"
  "shared|http://127.0.0.1:4323/v1/evaluations|SHARED_EVIDENCE_CLIENT_BEARER|eligible-for-combined-support|NID-1010|false"
)

for matrix_case in "${matrix_cases[@]}"; do
  IFS='|' read -r service_name url token_var claim subject expected <<<"${matrix_case}"
  token="${!token_var}"
  matrix_output="${output_dir}/smoke-matrix-${service_name}-${claim}-${subject}.json"
  check "v1 matrix ${claim} ${subject}" curl_json POST "${url}" "${token}" "${matrix_output}" -H "Content-Type: application/json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo" --data "$(evaluation_payload "${subject}" "national_id" "${claim}")"
  check "v1 matrix ${claim} ${subject} outcome" assert_claim_outcome "${matrix_output}" "${claim}" "${expected}"
done

missing_status="$(curl_status POST http://127.0.0.1:4323/v1/evaluations "${SHARED_EVIDENCE_CLIENT_BEARER}" -H "Content-Type: application/json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo" --data "$(evaluation_payload "NID-9999" "national_id" "eligible-for-combined-support")")"
[[ "${missing_status}" == "409" ]] || fail "missing-subject evaluation expected stable 409, got ${missing_status}"
cp /tmp/decentralized-smoke-response.json "${output_dir}/smoke-missing-subject.json"
check "missing-subject stable error code" json_path_equals "${output_dir}/smoke-missing-subject.json" code evidence.not_available

check "credential-bound evaluation" curl_json POST http://127.0.0.1:4321/v1/evaluations "${CIVIL_EVIDENCE_CLIENT_BEARER}" "${output_dir}/smoke-credential-evaluation.json" -H "Content-Type: application/json" -H "Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo" -H "Accept: application/dc+sd-jwt" --data "$(evaluation_payload "NID-1001" "national_id" "person-is-alive" "predicate" "application/dc+sd-jwt")"

check "full demo flow" env DEMO_OUTPUT_DIR="${output_dir}" DEMO_CORRELATION_ID="${correlation_id}" "${script_dir}/demo-flow.py"
grep -R "${correlation_id}" "${output_dir}" >/dev/null || fail "correlation ID artifact"
decision_artifact="$(find "${output_dir}" -maxdepth 1 -name '*household-benefit-decision.json' -print -quit)"
[[ -n "${decision_artifact}" ]] || fail "household benefit decision artifact"
check "household decision has no Relay write-back" json_path_equals "${decision_artifact}" boundary.relay_write_back false

log_file="/tmp/decentralized-smoke-service-logs.txt"
docker compose -f "${compose_file}" logs --no-color civil-registry-relay social-protection-registry-relay health-registry-relay civil-notary social-protection-notary shared-eligibility-notary > "${log_file}"
grep '"error_code":"auth.scope_denied"' "${log_file}" >/dev/null || fail "Relay denied audit event"
grep '"decision":"evaluate"' "${log_file}" >/dev/null || fail "Evidence Server evaluation audit event"
grep '"status_code":200' "${log_file}" >/dev/null || fail "Relay positive audit event"

for secret_var in \
  CLAIM_VERIFICATION_BINDING_KEY \
  REGISTRY_RELAY_AUDIT_HASH_SECRET \
  REGISTRY_NOTARY_AUDIT_HASH_SECRET \
  REGISTRY_NOTARY_ISSUER_JWK \
  CIVIL_EVIDENCE_ISSUER_JWK \
  SOCIAL_PROTECTION_EVIDENCE_ISSUER_JWK \
  SHARED_ELIGIBILITY_EVIDENCE_ISSUER_JWK \
  CIVIL_METADATA_CLIENT_RAW \
  CIVIL_EVIDENCE_SOURCE_RAW \
  CIVIL_EVIDENCE_ONLY_RAW \
  CIVIL_ROW_READER_RAW \
  CIVIL_AGGREGATE_READER_RAW \
  SHARED_CIVIL_EVIDENCE_SOURCE_RAW \
  SOCIAL_METADATA_CLIENT_RAW \
  SOCIAL_EVIDENCE_SOURCE_RAW \
  SOCIAL_PROTECTION_EVIDENCE_SOURCE_RAW \
  SOCIAL_EVIDENCE_ONLY_RAW \
  SOCIAL_ROW_READER_RAW \
  SOCIAL_AGGREGATE_READER_RAW \
  SHARED_SOCIAL_EVIDENCE_SOURCE_RAW \
  HEALTH_METADATA_CLIENT_RAW \
  HEALTH_EVIDENCE_SOURCE_RAW \
  HEALTH_EVIDENCE_ONLY_RAW \
  HEALTH_ROW_READER_RAW \
  HEALTH_AGGREGATE_READER_RAW \
  SHARED_HEALTH_EVIDENCE_SOURCE_RAW \
  CIVIL_EVIDENCE_CLIENT_TOKEN \
  CIVIL_EVIDENCE_CLIENT_BEARER \
  SOCIAL_EVIDENCE_CLIENT_TOKEN \
  SOCIAL_EVIDENCE_CLIENT_BEARER \
  SOCIAL_PROTECTION_EVIDENCE_CLIENT_TOKEN \
  SOCIAL_PROTECTION_EVIDENCE_CLIENT_BEARER \
  SHARED_EVIDENCE_CLIENT_TOKEN \
  SHARED_EVIDENCE_CLIENT_BEARER
do
  secret_value="${!secret_var:-}"
  if [[ -n "${secret_value}" ]] && grep -F -- "${secret_value}" "${log_file}" >/dev/null; then
    fail "service logs leaked ${secret_var}"
  fi
done

echo "smoke OK"
