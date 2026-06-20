#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
output_dir="${demo_dir}/output/dhis2-openfn"
correlation_id="${DEMO_CORRELATION_ID:-dhis2-demo-correlation-001}"

default_source_dir() {
  local sibling="$1"
  local vendor="$2"
  if [[ -f "${demo_dir}/${sibling}/Cargo.toml" ]]; then
    printf '%s\n' "${demo_dir}/${sibling}"
  else
    printf '%s\n' "${demo_dir}/${vendor}"
  fi
}

has_custom_cel_mapping_source_dir() {
  case "${CEL_MAPPING_SOURCE_DIR:-}" in
    ""|"./vendor/cel-mapping"|"vendor/cel-mapping"|"${demo_dir}/vendor/cel-mapping")
      return 1
      ;;
  esac
  [[ -d "${CEL_MAPPING_SOURCE_DIR}" ]]
}

export REGISTRY_NOTARY_SOURCE_DIR="${REGISTRY_NOTARY_SOURCE_DIR:-$(default_source_dir "../registry-notary" "vendor/registry-notary")}"
export REGISTRY_OPENFN_NOTARY_SOURCE_DIR="${REGISTRY_OPENFN_NOTARY_SOURCE_DIR:-${REGISTRY_NOTARY_SOURCE_DIR}}"
export REGISTRY_PLATFORM_SOURCE_DIR="${REGISTRY_PLATFORM_SOURCE_DIR:-$(default_source_dir "../registry-platform" "vendor/registry-platform")}"
export REGISTRY_NOTARY_PLATFORM_SOURCE_DIR="${REGISTRY_NOTARY_PLATFORM_SOURCE_DIR:-${REGISTRY_PLATFORM_SOURCE_DIR}}"
# CEL_MAPPING_SOURCE_DIR is the deprecated name for CROSSWALK_SOURCE_DIR.
if [[ -z "${CROSSWALK_SOURCE_DIR:-}" ]]; then
  if has_custom_cel_mapping_source_dir; then
    export CROSSWALK_SOURCE_DIR="${CEL_MAPPING_SOURCE_DIR}"
  else
    export CROSSWALK_SOURCE_DIR="${demo_dir}/vendor/crosswalk"
  fi
fi

if [[ -f "${demo_dir}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${demo_dir}/.env"
  set +a
else
  echo "missing .env; run ${script_dir}/generate-demo-secrets.py first" >&2
  exit 1
fi

: "${OPENFN_SIDECAR_TOKEN_RAW:?missing OPENFN_SIDECAR_TOKEN_RAW; rerun scripts/generate-demo-secrets.py}"
: "${DHIS2_EVIDENCE_CLIENT_BEARER:?missing DHIS2_EVIDENCE_CLIENT_BEARER; rerun scripts/generate-demo-secrets.py}"
if [[ -z "${OPENFN_SIDECAR_TOKEN_HASH:-}" ]]; then
  OPENFN_SIDECAR_TOKEN_HASH="$(
    python - "${OPENFN_SIDECAR_TOKEN_RAW}" <<'PY'
import hashlib
import sys
print(f"sha256:{hashlib.sha256(sys.argv[1].encode('ascii')).hexdigest()}")
PY
  )"
  export OPENFN_SIDECAR_TOKEN_HASH
fi

fail() {
  echo "FAILED: $1" >&2
  exit 1
}

wait_http() {
  local name="$1"
  local url="$2"
  local token="${3:-}"
  local deadline="${SMOKE_WAIT_SECONDS:-180}"
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

evaluate_claim() {
  local claim="$1"
  local subject="$2"
  local output_file="$3"
  local response_format="${4:-application/vnd.registry-notary.claim-result+json}"
  curl -fsS \
    -X POST \
    -H "Authorization: Bearer ${DHIS2_EVIDENCE_CLIENT_BEARER}" \
    -H "Content-Type: application/json" \
    -H "Data-Purpose: https://demo.example.gov/purpose/dhis2-openfn-health-evidence" \
    -H "x-request-id: ${correlation_id}" \
    -o "${output_file}" \
    http://127.0.0.1:4326/v1/evaluations \
    --data "$(jq -nc \
      --arg subject "${subject}" \
      --arg claim "${claim}" \
      --arg format "${response_format}" \
      '{target:{type:"TrackedEntity",identifiers:[{scheme:"dhis2_tracked_entity",value:$subject}]},claims:[$claim],disclosure:"predicate",format:$format}')"
}

issue_credential() {
  local evaluation_file="$1"
  local output_file="$2"
  local profile="$3"
  local disclosure="$4"
  local claims_json="$5"
  local holder_file="${6:-}"
  local evaluation_id
  evaluation_id="$(
    python - "${evaluation_file}" <<'PY'
import json
import sys

body = json.load(open(sys.argv[1], encoding="utf-8"))
print(body["results"][0]["evaluation_id"])
PY
  )"
  local payload
  if [[ -n "${holder_file}" ]]; then
    payload="$(
      jq -nc \
        --arg evaluation_id "${evaluation_id}" \
        --arg profile "${profile}" \
        --arg disclosure "${disclosure}" \
        --argjson claims "${claims_json}" \
        --slurpfile holder "${holder_file}" \
        '{
          evaluation_id: $evaluation_id,
          credential_profile: $profile,
          format: "application/dc+sd-jwt",
          claims: $claims,
          disclosure: $disclosure,
          holder: $holder[0].holder
        }'
    )"
  else
    payload="$(
      jq -nc \
        --arg evaluation_id "${evaluation_id}" \
        --arg profile "${profile}" \
        --arg disclosure "${disclosure}" \
        --argjson claims "${claims_json}" \
        '{
          evaluation_id: $evaluation_id,
          credential_profile: $profile,
          format: "application/dc+sd-jwt",
          claims: $claims,
          disclosure: $disclosure
        }'
    )"
  fi
  curl -fsS \
    -X POST \
    -H "Authorization: Bearer ${DHIS2_EVIDENCE_CLIENT_BEARER}" \
    -H "Content-Type: application/json" \
    -H "x-request-id: ${correlation_id}-vc-issue" \
    -o "${output_file}" \
    http://127.0.0.1:4326/v1/credentials \
    --data "${payload}"
}

mkdir -p "${output_dir}"

docker compose -f "${compose_file}" --profile dhis2 up -d --force-recreate --remove-orphans \
  openfn-dhis2-sidecar \
  dhis2-health-notary

wait_http "DHIS2 health notary discovery" http://127.0.0.1:4326/.well-known/evidence-service "${DHIS2_EVIDENCE_CLIENT_BEARER}"

evaluate_claim "dhis2-child-program-active" "PQfMcpmXeFE" "${output_dir}/smoke-dhis2-child-program-active.json"
evaluate_claim "dhis2-maternal-pnc-active" "mXAzn3hMR5a" "${output_dir}/smoke-dhis2-maternal-pnc-active.json"
evaluate_claim "dhis2-child-health-visit-recorded" "vOxUH373fy5" "${output_dir}/smoke-dhis2-child-health-visit-recorded.json"
evaluate_claim "dhis2-tb-program-active" "foc5zag6gbE" "${output_dir}/smoke-dhis2-tb-program-active.json"
evaluate_claim "dhis2-child-program-active" "vOxUH373fy5" "${output_dir}/smoke-dhis2-child-program-active-negative.json"
evaluate_claim "dhis2-maternal-pnc-active" "PQfMcpmXeFE" "${output_dir}/smoke-dhis2-maternal-pnc-active-negative.json"
evaluate_claim "dhis2-child-health-visit-recorded" "PQfMcpmXeFE" "${output_dir}/smoke-dhis2-child-health-visit-recorded-negative.json"
evaluate_claim "dhis2-tb-program-active" "mXAzn3hMR5a" "${output_dir}/smoke-dhis2-tb-program-active-negative.json"

vc_claims='["dhis2-tracked-entity-first-name","dhis2-tracked-entity-last-name","dhis2-child-program-active"]'
curl -fsS \
  -X POST \
  -H "Authorization: Bearer ${DHIS2_EVIDENCE_CLIENT_BEARER}" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: https://demo.example.gov/purpose/dhis2-openfn-health-evidence" \
  -H "x-request-id: ${correlation_id}-vc-evaluation" \
  -o "${output_dir}/smoke-dhis2-child-program-vc-evaluation.json" \
  http://127.0.0.1:4326/v1/evaluations \
  --data "$(jq -nc \
    --arg subject "PQfMcpmXeFE" \
    --argjson claims "${vc_claims}" \
    '{
      target: {
        type: "TrackedEntity",
        identifiers: [{scheme: "dhis2_tracked_entity", value: $subject}]
      },
      claims: $claims,
      disclosure: "value",
      format: "application/dc+sd-jwt"
    }')"
issue_credential \
  "${output_dir}/smoke-dhis2-child-program-vc-evaluation.json" \
  "${output_dir}/smoke-dhis2-child-program-credential.json" \
  "dhis2_child_program_sd_jwt" \
  "value" \
  "${vc_claims}"

programme_claims='["dhis2-tracked-entity-first-name","dhis2-tracked-entity-last-name","dhis2-child-age-band","dhis2-programme-code","dhis2-child-program-active","dhis2-reconciliation-ref"]'
curl -fsS \
  -X POST \
  -H "Authorization: Bearer ${DHIS2_EVIDENCE_CLIENT_BEARER}" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: https://demo.example.gov/purpose/dhis2-openfn-health-evidence" \
  -H "x-request-id: ${correlation_id}-programme-vc-evaluation" \
  -o "${output_dir}/smoke-dhis2-programme-participation-evaluation.json" \
  http://127.0.0.1:4326/v1/evaluations \
  --data "$(jq -nc \
    --arg subject "PQfMcpmXeFE" \
    --argjson claims "${programme_claims}" \
    '{
      target: {
        type: "TrackedEntity",
        identifiers: [{scheme: "dhis2_tracked_entity", value: $subject}]
      },
      claims: $claims,
      disclosure: "value",
      format: "application/dc+sd-jwt"
    }')"

programme_evaluation_id="$(
  python - "${output_dir}/smoke-dhis2-programme-participation-evaluation.json" <<'PY'
import json
import sys

body = json.load(open(sys.argv[1], encoding="utf-8"))
print(body["results"][0]["evaluation_id"])
PY
)"
node "${script_dir}/generate-holder-proof.js" \
  --audience "dhis2-health-notary" \
  --evaluation-id "${programme_evaluation_id}" \
  --credential-profile "dhis2_programme_participation_sd_jwt" \
  --disclosure "value" \
  --claims-json "${programme_claims}" \
  > "${output_dir}/smoke-dhis2-programme-participation-holder.json"

issue_credential \
  "${output_dir}/smoke-dhis2-programme-participation-evaluation.json" \
  "${output_dir}/smoke-dhis2-programme-participation-credential.json" \
  "dhis2_programme_participation_sd_jwt" \
  "value" \
  "${programme_claims}" \
  "${output_dir}/smoke-dhis2-programme-participation-holder.json"

reconciliation_ref="$(
  jq -er '.results[] | select(.claim_id == "dhis2-reconciliation-ref") | .value' \
    "${output_dir}/smoke-dhis2-programme-participation-evaluation.json"
)"
curl -fsS \
  -X POST \
  -H "Authorization: Bearer ${DHIS2_EVIDENCE_CLIENT_BEARER}" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: https://demo.example.gov/purpose/dhis2-openfn-health-evidence" \
  -H "x-request-id: ${correlation_id}-programme-followup" \
  -o "${output_dir}/smoke-dhis2-programme-participation-followup.json" \
  http://127.0.0.1:4326/v1/evaluations \
  --data "$(jq -nc \
    --arg subject "${reconciliation_ref}" \
    '{
      target: {
        type: "TrackedEntity",
        identifiers: [{scheme: "dhis2_tracked_entity", value: $subject}]
      },
      claims: ["dhis2-child-program-active"],
      disclosure: "predicate",
      format: "application/vnd.registry-notary.claim-result+json"
    }')"

python "${script_dir}/summarize-dhis2-programme-vc.py" \
  "${output_dir}/smoke-dhis2-programme-participation-evaluation.json" \
  "${output_dir}/smoke-dhis2-programme-participation-credential.json" \
  "${output_dir}/smoke-dhis2-programme-participation-holder.json" \
  "${output_dir}/smoke-dhis2-programme-participation-followup.json" \
  "${output_dir}/smoke-dhis2-programme-participation-credential-summary.json"

python - "${output_dir}" "${output_dir}/smoke-dhis2-child-program-vc-evaluation.json" "${output_dir}/smoke-dhis2-child-program-credential.json" <<'PY'
import json
import pathlib
import sys

output_dir = pathlib.Path(sys.argv[1])
vc_evaluation_file = pathlib.Path(sys.argv[2])
credential_file = pathlib.Path(sys.argv[3])
checks = {
    "smoke-dhis2-child-program-active.json": ("dhis2-child-program-active", True),
    "smoke-dhis2-maternal-pnc-active.json": ("dhis2-maternal-pnc-active", True),
    "smoke-dhis2-child-health-visit-recorded.json": ("dhis2-child-health-visit-recorded", True),
    "smoke-dhis2-tb-program-active.json": ("dhis2-tb-program-active", True),
    "smoke-dhis2-child-program-active-negative.json": ("dhis2-child-program-active", False),
    "smoke-dhis2-maternal-pnc-active-negative.json": ("dhis2-maternal-pnc-active", False),
    "smoke-dhis2-child-health-visit-recorded-negative.json": ("dhis2-child-health-visit-recorded", False),
    "smoke-dhis2-tb-program-active-negative.json": ("dhis2-tb-program-active", False),
}
for filename, (claim_id, expected) in checks.items():
    body = json.loads((output_dir / filename).read_text(encoding="utf-8"))
    results = body.get("results") or []
    assert len(results) == 1, body
    result = results[0]
    assert result.get("claim_id") == claim_id, body
    assert result.get("satisfied") is expected, body
    assert result.get("disclosure") == "predicate", body
    assert result.get("provenance", {}).get("source_count") == 1, body

vc_evaluation_body = json.loads(vc_evaluation_file.read_text(encoding="utf-8"))
vc_results = {item.get("claim_id"): item for item in vc_evaluation_body.get("results") or []}
expected_vc_claims = {
    "dhis2-tracked-entity-first-name",
    "dhis2-tracked-entity-last-name",
    "dhis2-child-program-active",
}
assert set(vc_results) == expected_vc_claims, vc_evaluation_body
assert vc_results["dhis2-tracked-entity-first-name"].get("value"), vc_evaluation_body
assert vc_results["dhis2-tracked-entity-last-name"].get("value"), vc_evaluation_body
assert vc_results["dhis2-child-program-active"].get("value") is True, vc_evaluation_body
assert vc_results["dhis2-child-program-active"].get("satisfied") is True, vc_evaluation_body

credential_body = json.loads(credential_file.read_text(encoding="utf-8"))
credential = credential_body.get("credential") or ""
issuer_signed_jwt = credential_body.get("issuer_signed_jwt") or ""
disclosures = credential_body.get("disclosures") or []
assert credential_body.get("format") == "application/dc+sd-jwt", credential_body
assert credential_body.get("issuer") == "did:web:dhis2-health-notary.demo.example.gov", credential_body
assert credential_body.get("credential_id"), credential_body
assert credential_body.get("expires_at"), credential_body
assert credential and issuer_signed_jwt, credential_body
assert len(disclosures) == 3, credential_body
summary = {
    "credential_id": credential_body.get("credential_id"),
    "credential_profile": "dhis2_child_program_sd_jwt",
    "format": credential_body.get("format"),
    "issuer": credential_body.get("issuer"),
    "expires_at": credential_body.get("expires_at"),
    "disclosure_count": len(disclosures),
    "credential_compact_length": len(credential),
}
(output_dir / "smoke-dhis2-child-program-credential-summary.json").write_text(
    json.dumps(summary, indent=2) + "\n",
    encoding="utf-8",
)
PY

printf '\nIssued DHIS2 child programme SD-JWT VC summary:\n'
cat "${output_dir}/smoke-dhis2-child-program-credential-summary.json"
printf '\nIssued DHIS2 programme participation SD-JWT VC summary:\n'
cat "${output_dir}/smoke-dhis2-programme-participation-credential-summary.json"
printf 'DHIS2 health evidence and VC smoke passed\n'
