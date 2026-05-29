#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
output_dir="${demo_dir}/output"
correlation_id="${DEMO_CORRELATION_ID:-dhis2-openfn-demo-correlation-001}"

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
    http://127.0.0.1:4326/claims/evaluate \
    --data "{\"subject\":{\"id\":\"${subject}\",\"id_type\":\"dhis2_tracked_entity\"},\"claims\":[\"${claim}\"],\"disclosure\":\"predicate\",\"format\":\"${response_format}\"}"
}

issue_credential() {
  local evaluation_file="$1"
  local output_file="$2"
  local evaluation_id
  evaluation_id="$(
    python - "${evaluation_file}" <<'PY'
import json
import sys

body = json.load(open(sys.argv[1], encoding="utf-8"))
print(body["results"][0]["evaluation_id"])
PY
  )"
  curl -fsS \
    -X POST \
    -H "Authorization: Bearer ${DHIS2_EVIDENCE_CLIENT_BEARER}" \
    -H "Content-Type: application/json" \
    -H "x-request-id: ${correlation_id}-vc-issue" \
    -o "${output_file}" \
    http://127.0.0.1:4326/credentials/issue \
    --data "{\"evaluation_id\":\"${evaluation_id}\",\"credential_profile\":\"dhis2_health_status_sd_jwt\",\"format\":\"application/dc+sd-jwt\",\"claims\":[\"dhis2-child-program-active\"],\"disclosure\":\"predicate\"}"
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
evaluate_claim "dhis2-child-program-active" "PQfMcpmXeFE" "${output_dir}/smoke-dhis2-health-status-vc-evaluation.json" "application/dc+sd-jwt"
issue_credential "${output_dir}/smoke-dhis2-health-status-vc-evaluation.json" "${output_dir}/smoke-dhis2-health-status-credential.json"

python - "${output_dir}" "${output_dir}/smoke-dhis2-health-status-credential.json" <<'PY'
import json
import pathlib
import sys

output_dir = pathlib.Path(sys.argv[1])
credential_file = pathlib.Path(sys.argv[2])
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

credential_body = json.loads(credential_file.read_text(encoding="utf-8"))
credential = credential_body.get("credential") or ""
issuer_signed_jwt = credential_body.get("issuer_signed_jwt") or ""
disclosures = credential_body.get("disclosures") or []
assert credential_body.get("format") == "application/dc+sd-jwt", credential_body
assert credential_body.get("issuer") == "did:web:dhis2-health-notary.demo.example.gov", credential_body
assert credential_body.get("credential_id"), credential_body
assert credential_body.get("expires_at"), credential_body
assert credential and issuer_signed_jwt and disclosures, credential_body
PY

printf 'DHIS2 OpenFn health evidence and VC smoke passed\n'
