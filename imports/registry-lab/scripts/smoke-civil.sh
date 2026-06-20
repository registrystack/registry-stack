#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
output_dir="${demo_dir}/output"
correlation_id="${DEMO_CORRELATION_ID:-civil-demo-correlation-001}"

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
: "${OPENFN_MOCK_REGISTRY_TOKEN_RAW:?missing OPENFN_MOCK_REGISTRY_TOKEN_RAW; rerun scripts/generate-demo-secrets.py}"
: "${CIVIL_EVIDENCE_CLIENT_BEARER:?missing CIVIL_EVIDENCE_CLIENT_BEARER; rerun scripts/generate-demo-secrets.py}"
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

mkdir -p "${output_dir}"

docker compose -f "${compose_file}" up -d --force-recreate --remove-orphans \
  openfn-mock-registry \
  openfn-civil-sidecar \
  openfn-civil-notary

wait_http "OpenFn civil notary discovery" http://127.0.0.1:4324/.well-known/evidence-service "${CIVIL_EVIDENCE_CLIENT_BEARER}"

notary_body="${output_dir}/smoke-openfn-notary-evaluation.json"
vc_evaluation_body="${output_dir}/smoke-openfn-vc-evaluation.json"
credential_body="${output_dir}/smoke-openfn-credential.json"
credential_summary_body="${output_dir}/smoke-openfn-credential-summary.json"
curl -fsS \
  -X POST \
  -H "Authorization: Bearer ${CIVIL_EVIDENCE_CLIENT_BEARER}" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: https://demo.example.gov/purpose/openfn-sidecar-demo" \
  -H "x-request-id: ${correlation_id}" \
  -o "${notary_body}" \
  http://127.0.0.1:4324/v1/evaluations \
  --data '{"target":{"type":"Person","identifiers":[{"scheme":"national_id","value":"person-123"}]},"claims":["date-of-birth"],"disclosure":"value","format":"application/vnd.registry-notary.claim-result+json"}'

curl -fsS \
  -X POST \
  -H "Authorization: Bearer ${CIVIL_EVIDENCE_CLIENT_BEARER}" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: https://demo.example.gov/purpose/openfn-sidecar-demo" \
  -H "x-request-id: ${correlation_id}-vc-evaluation" \
  -o "${vc_evaluation_body}" \
  http://127.0.0.1:4324/v1/evaluations \
  --data '{"target":{"type":"Person","identifiers":[{"scheme":"national_id","value":"person-123"}]},"claims":["date-of-birth"],"disclosure":"value","format":"application/dc+sd-jwt"}'

evaluation_id="$(
  python - "${vc_evaluation_body}" <<'PY'
import json
import sys
body = json.load(open(sys.argv[1], encoding="utf-8"))
print(body["results"][0]["evaluation_id"])
PY
)"

curl -fsS \
  -X POST \
  -H "Authorization: Bearer ${CIVIL_EVIDENCE_CLIENT_BEARER}" \
  -H "Content-Type: application/json" \
  -H "x-request-id: ${correlation_id}-vc-issue" \
  -o "${credential_body}" \
  http://127.0.0.1:4324/v1/credentials \
  --data "$(jq -nc --arg evaluation_id "${evaluation_id}" '{
    evaluation_id: $evaluation_id,
    credential_profile: "openfn_civil_sd_jwt",
    format: "application/dc+sd-jwt",
    claims: ["date-of-birth"],
    disclosure: "value"
  }')"

python - "${notary_body}" "${vc_evaluation_body}" "${credential_body}" "${credential_summary_body}" <<'PY'
import json
import sys
notary_body = json.load(open(sys.argv[1], encoding="utf-8"))
vc_evaluation_body = json.load(open(sys.argv[2], encoding="utf-8"))
credential_body = json.load(open(sys.argv[3], encoding="utf-8"))
summary_path = sys.argv[4]
body = notary_body
results = body.get("results") or []
assert len(results) == 1, body
result = results[0]
assert result.get("claim_id") == "date-of-birth", body
assert result.get("value") == "1990-01-01", body
assert result.get("provenance", {}).get("used", {}).get("source_count") == 1, body

vc_results = vc_evaluation_body.get("results") or []
assert len(vc_results) == 1, vc_evaluation_body
assert vc_results[0].get("claim_id") == "date-of-birth", vc_evaluation_body
assert vc_results[0].get("value") == "1990-01-01", vc_evaluation_body

credential = credential_body.get("credential") or ""
issuer_signed_jwt = credential_body.get("issuer_signed_jwt") or ""
disclosures = credential_body.get("disclosures") or []
assert credential_body.get("format") == "application/dc+sd-jwt", credential_body
assert credential_body.get("issuer") == "did:web:openfn-civil-notary.demo.example", credential_body
assert credential_body.get("credential_id"), credential_body
assert credential_body.get("expires_at"), credential_body
assert credential and issuer_signed_jwt and len(disclosures) == 1, credential_body
summary = {
    "credential_id": credential_body.get("credential_id"),
    "credential_profile": "openfn_civil_sd_jwt",
    "format": credential_body.get("format"),
    "issuer": credential_body.get("issuer"),
    "expires_at": credential_body.get("expires_at"),
    "disclosure_count": len(disclosures),
    "credential_compact_length": len(credential),
}
with open(summary_path, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2)
    handle.write("\n")
PY

printf '\nIssued OpenFn civil SD-JWT VC summary:\n'
cat "${credential_summary_body}"
printf 'Civil sidecar Registry Notary smoke passed\n'
