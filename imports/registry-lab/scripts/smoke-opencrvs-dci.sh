#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
local_env="${demo_dir}/.env.local"
output_dir="${demo_dir}/output/opencrvs-dci"
correlation_id="${DEMO_CORRELATION_ID:-opencrvs-dci-demo-correlation-001}"
curl_connect_timeout="${OPENCRVS_DCI_CURL_CONNECT_TIMEOUT_SECONDS:-10}"
curl_max_time="${OPENCRVS_DCI_CURL_MAX_TIME_SECONDS:-60}"

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

load_env_file() {
  local path="$1"
  if [[ -f "${path}" ]]; then
    set -a
    # shellcheck disable=SC1090
    . "${path}"
    set +a
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

update_local_env() {
  local key="$1"
  local value="$2"
  KEY="${key}" VALUE="${value}" LOCAL_ENV="${local_env}" python - <<'PY'
import os
from pathlib import Path

path = Path(os.environ["LOCAL_ENV"])
key = os.environ["KEY"]
value = os.environ["VALUE"]
lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
updated = False
out = []
for line in lines:
    if line.startswith(f"{key}="):
        out.append(f"{key}={value}")
        updated = True
    else:
        out.append(line)
if not updated:
    out.append(f"{key}={value}")
path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
PY
  chmod 600 "${local_env}"
}

hash_token() {
  python - "$1" <<'PY'
import hashlib
import sys

print(f"sha256:{hashlib.sha256(sys.argv[1].encode('utf-8')).hexdigest()}")
PY
}

ensure_token_hash() {
  local hash_var="$1"
  local token="$2"
  local current="${!hash_var:-}"
  if [[ -z "${current}" || "${current}" =~ ^sha256:0+$ ]]; then
    printf -v "${hash_var}" '%s' "$(hash_token "${token}")"
  fi
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"
}

wait_http() {
  local name="$1"
  local url="$2"
  local api_key="$3"
  local deadline="${SMOKE_WAIT_SECONDS:-120}"
  local start
  start="$(date +%s)"
  local status="000"
  while (( $(date +%s) - start < deadline )); do
    status="$(
      curl -sS -o /dev/null -w "%{http_code}" \
        --connect-timeout "${curl_connect_timeout}" \
        --max-time "${curl_max_time}" \
        -H "Accept: */*" \
        -H "x-api-key: ${api_key}" \
        -H "x-request-id: ${correlation_id}" \
        "${url}" 2>/dev/null || true
    )"
    if [[ "${status}" =~ ^2[0-9][0-9]$ ]]; then
      return 0
    fi
    sleep 1
  done
  fail "${name} did not become ready within ${deadline}s, last status ${status}"
}

fetch_opencrvs_token() {
  curl -fsS \
    --connect-timeout "${curl_connect_timeout}" \
    --max-time "${curl_max_time}" \
    -X POST "${OPENCRVS_DCI_BASE_URL}/oauth2/client/token" \
    -H "accept: application/json" \
    -H "content-type: application/json" \
    --data-raw "{\"client_id\":\"${OPENCRVS_DCI_CLIENT_ID}\",\"client_secret\":\"${OPENCRVS_DCI_CLIENT_SECRET}\",\"grant_type\":\"client_credentials\"}" |
    jq -er ".access_token"
}

discover_subject_uin() {
  local token="$1"
  local now message_id request_body response_body
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  message_id="opencrvs-dci-demo-$(date +%s)"
  request_body="$(mktemp)"
  response_body="$(mktemp)"
  trap 'rm -f "${request_body:-}" "${response_body:-}"' RETURN
  cat > "${request_body}" <<JSON
{"header":{"version":"1.0.0","message_id":"${message_id}","message_ts":"${now}","action":"search","sender_id":"registry-lab","total_count":1,"is_msg_encrypted":false},"message":{"transaction_id":"${message_id}","search_request":[{"reference_id":"${message_id}","timestamp":"${now}","search_criteria":{"version":"1.0.0","reg_type":"ns:org:RegistryType:Civil","reg_event_type":"birth","query_type":"expression","query":{"type":"ns:org:QueryType:expression","value":{"expression":{"query":{}}}},"pagination":{"page_size":1,"page_number":1}}}]}}
JSON
  curl -fsS \
    --connect-timeout "${curl_connect_timeout}" \
    --max-time "${curl_max_time}" \
    -X POST "${OPENCRVS_DCI_BASE_URL}/registry/sync/search" \
    -H "authorization: Bearer ${token}" \
    -H "accept: application/json" \
    -H "content-type: application/json" \
    -o "${response_body}" \
    --data-binary "@${request_body}"
  jq -er '
    .message.search_response[0].data.reg_records[0].identifier[]
    | select(.identifier_type == "UIN")
    | .identifier_value
  ' "${response_body}"
}

require_tool curl
require_tool docker
require_tool jq
require_tool python

if [[ -f "${demo_dir}/.env" ]]; then
  load_env_file "${demo_dir}/.env"
else
  fail "missing .env; run scripts/generate-demo-secrets.py first"
fi

if [[ -f "${local_env}" ]]; then
  load_env_file "${local_env}"
elif [[ -z "${OPENCRVS_DCI_CLIENT_ID:-}" || -z "${OPENCRVS_DCI_CLIENT_SECRET:-}" ]]; then
  fail "missing .env.local; copy .env.example OpenCRVS values or create it with OPENCRVS_DCI_CLIENT_ID and OPENCRVS_DCI_CLIENT_SECRET"
fi

: "${OPENCRVS_DCI_BASE_URL:=https://dci-crvs-api.farajaland-integration.opencrvs.dev}"
: "${OPENCRVS_EVIDENCE_CLIENT_TOKEN:=api-token}"
: "${OPENCRVS_EVIDENCE_DENY_ASSURANCE_TOKEN:=api-deny-assurance-token}"
: "${OPENCRVS_EVIDENCE_DENY_JURISDICTION_TOKEN:=api-deny-jurisdiction-token}"
: "${OPENCRVS_EVIDENCE_DENY_LEGAL_BASIS_TOKEN:=api-deny-legal-basis-token}"
: "${OPENCRVS_EVIDENCE_DENY_CONSENT_TOKEN:=api-deny-consent-token}"
: "${SHARED_EVIDENCE_CLIENT_TOKEN:=shared-api-token}"
: "${SHARED_EVIDENCE_DENY_ASSURANCE_TOKEN:=shared-deny-assurance-token}"
: "${SHARED_EVIDENCE_DENY_JURISDICTION_TOKEN:=shared-deny-jurisdiction-token}"
: "${SHARED_EVIDENCE_DENY_LEGAL_BASIS_TOKEN:=shared-deny-legal-basis-token}"
: "${SHARED_EVIDENCE_DENY_CONSENT_TOKEN:=shared-deny-consent-token}"
: "${OPENCRVS_DCI_NOTARY_PORT:=4352}"
: "${OPENCRVS_DCI_CLIENT_ID:?missing OPENCRVS_DCI_CLIENT_ID in .env.local}"
: "${OPENCRVS_DCI_CLIENT_SECRET:?missing OPENCRVS_DCI_CLIENT_SECRET in .env.local}"
: "${REGISTRY_NOTARY_AUDIT_HASH_SECRET:?missing REGISTRY_NOTARY_AUDIT_HASH_SECRET; run scripts/generate-demo-secrets.py first}"

ensure_token_hash OPENCRVS_EVIDENCE_CLIENT_TOKEN_HASH "${OPENCRVS_EVIDENCE_CLIENT_TOKEN}"
ensure_token_hash OPENCRVS_EVIDENCE_DENY_ASSURANCE_TOKEN_HASH "${OPENCRVS_EVIDENCE_DENY_ASSURANCE_TOKEN}"
ensure_token_hash OPENCRVS_EVIDENCE_DENY_JURISDICTION_TOKEN_HASH "${OPENCRVS_EVIDENCE_DENY_JURISDICTION_TOKEN}"
ensure_token_hash OPENCRVS_EVIDENCE_DENY_LEGAL_BASIS_TOKEN_HASH "${OPENCRVS_EVIDENCE_DENY_LEGAL_BASIS_TOKEN}"
ensure_token_hash OPENCRVS_EVIDENCE_DENY_CONSENT_TOKEN_HASH "${OPENCRVS_EVIDENCE_DENY_CONSENT_TOKEN}"
ensure_token_hash SHARED_EVIDENCE_CLIENT_TOKEN_HASH "${SHARED_EVIDENCE_CLIENT_TOKEN}"
ensure_token_hash SHARED_EVIDENCE_DENY_ASSURANCE_TOKEN_HASH "${SHARED_EVIDENCE_DENY_ASSURANCE_TOKEN}"
ensure_token_hash SHARED_EVIDENCE_DENY_JURISDICTION_TOKEN_HASH "${SHARED_EVIDENCE_DENY_JURISDICTION_TOKEN}"
ensure_token_hash SHARED_EVIDENCE_DENY_LEGAL_BASIS_TOKEN_HASH "${SHARED_EVIDENCE_DENY_LEGAL_BASIS_TOKEN}"
ensure_token_hash SHARED_EVIDENCE_DENY_CONSENT_TOKEN_HASH "${SHARED_EVIDENCE_DENY_CONSENT_TOKEN}"
export OPENCRVS_DCI_BASE_URL
export OPENCRVS_EVIDENCE_CLIENT_TOKEN
export OPENCRVS_EVIDENCE_CLIENT_TOKEN_HASH
export OPENCRVS_EVIDENCE_DENY_ASSURANCE_TOKEN
export OPENCRVS_EVIDENCE_DENY_ASSURANCE_TOKEN_HASH
export OPENCRVS_EVIDENCE_DENY_JURISDICTION_TOKEN
export OPENCRVS_EVIDENCE_DENY_JURISDICTION_TOKEN_HASH
export OPENCRVS_EVIDENCE_DENY_LEGAL_BASIS_TOKEN
export OPENCRVS_EVIDENCE_DENY_LEGAL_BASIS_TOKEN_HASH
export OPENCRVS_EVIDENCE_DENY_CONSENT_TOKEN
export OPENCRVS_EVIDENCE_DENY_CONSENT_TOKEN_HASH
export SHARED_EVIDENCE_CLIENT_TOKEN
export SHARED_EVIDENCE_CLIENT_TOKEN_HASH
export SHARED_EVIDENCE_DENY_ASSURANCE_TOKEN
export SHARED_EVIDENCE_DENY_ASSURANCE_TOKEN_HASH
export SHARED_EVIDENCE_DENY_JURISDICTION_TOKEN
export SHARED_EVIDENCE_DENY_JURISDICTION_TOKEN_HASH
export SHARED_EVIDENCE_DENY_LEGAL_BASIS_TOKEN
export SHARED_EVIDENCE_DENY_LEGAL_BASIS_TOKEN_HASH
export SHARED_EVIDENCE_DENY_CONSENT_TOKEN
export SHARED_EVIDENCE_DENY_CONSENT_TOKEN_HASH
export OPENCRVS_DCI_NOTARY_PORT
export REGISTRY_NOTARY_SOURCE_DIR="${REGISTRY_NOTARY_SOURCE_DIR:-../registry-notary}"
export REGISTRY_NOTARY_PLATFORM_SOURCE_DIR="${REGISTRY_NOTARY_PLATFORM_SOURCE_DIR:-${REGISTRY_PLATFORM_SOURCE_DIR:-../registry-platform}}"
# CEL_MAPPING_SOURCE_DIR is the deprecated name for CROSSWALK_SOURCE_DIR.
if [[ -z "${CROSSWALK_SOURCE_DIR:-}" ]]; then
  if has_custom_cel_mapping_source_dir; then
    export CROSSWALK_SOURCE_DIR="${CEL_MAPPING_SOURCE_DIR}"
  else
    export CROSSWALK_SOURCE_DIR="${demo_dir}/vendor/crosswalk"
  fi
fi

opencrvs_dci_token="$(fetch_opencrvs_token)"
update_local_env "OPENCRVS_DCI_BASE_URL" "${OPENCRVS_DCI_BASE_URL}"
update_local_env "OPENCRVS_EVIDENCE_CLIENT_TOKEN" "${OPENCRVS_EVIDENCE_CLIENT_TOKEN}"
update_local_env "OPENCRVS_EVIDENCE_CLIENT_TOKEN_HASH" "${OPENCRVS_EVIDENCE_CLIENT_TOKEN_HASH}"
update_local_env "OPENCRVS_EVIDENCE_DENY_ASSURANCE_TOKEN" "${OPENCRVS_EVIDENCE_DENY_ASSURANCE_TOKEN}"
update_local_env "OPENCRVS_EVIDENCE_DENY_ASSURANCE_TOKEN_HASH" "${OPENCRVS_EVIDENCE_DENY_ASSURANCE_TOKEN_HASH}"
update_local_env "OPENCRVS_EVIDENCE_DENY_JURISDICTION_TOKEN" "${OPENCRVS_EVIDENCE_DENY_JURISDICTION_TOKEN}"
update_local_env "OPENCRVS_EVIDENCE_DENY_JURISDICTION_TOKEN_HASH" "${OPENCRVS_EVIDENCE_DENY_JURISDICTION_TOKEN_HASH}"
update_local_env "OPENCRVS_EVIDENCE_DENY_LEGAL_BASIS_TOKEN" "${OPENCRVS_EVIDENCE_DENY_LEGAL_BASIS_TOKEN}"
update_local_env "OPENCRVS_EVIDENCE_DENY_LEGAL_BASIS_TOKEN_HASH" "${OPENCRVS_EVIDENCE_DENY_LEGAL_BASIS_TOKEN_HASH}"
update_local_env "OPENCRVS_EVIDENCE_DENY_CONSENT_TOKEN" "${OPENCRVS_EVIDENCE_DENY_CONSENT_TOKEN}"
update_local_env "OPENCRVS_EVIDENCE_DENY_CONSENT_TOKEN_HASH" "${OPENCRVS_EVIDENCE_DENY_CONSENT_TOKEN_HASH}"
update_local_env "SHARED_EVIDENCE_CLIENT_TOKEN" "${SHARED_EVIDENCE_CLIENT_TOKEN}"
update_local_env "SHARED_EVIDENCE_CLIENT_TOKEN_HASH" "${SHARED_EVIDENCE_CLIENT_TOKEN_HASH}"
update_local_env "SHARED_EVIDENCE_DENY_ASSURANCE_TOKEN" "${SHARED_EVIDENCE_DENY_ASSURANCE_TOKEN}"
update_local_env "SHARED_EVIDENCE_DENY_ASSURANCE_TOKEN_HASH" "${SHARED_EVIDENCE_DENY_ASSURANCE_TOKEN_HASH}"
update_local_env "SHARED_EVIDENCE_DENY_JURISDICTION_TOKEN" "${SHARED_EVIDENCE_DENY_JURISDICTION_TOKEN}"
update_local_env "SHARED_EVIDENCE_DENY_JURISDICTION_TOKEN_HASH" "${SHARED_EVIDENCE_DENY_JURISDICTION_TOKEN_HASH}"
update_local_env "SHARED_EVIDENCE_DENY_LEGAL_BASIS_TOKEN" "${SHARED_EVIDENCE_DENY_LEGAL_BASIS_TOKEN}"
update_local_env "SHARED_EVIDENCE_DENY_LEGAL_BASIS_TOKEN_HASH" "${SHARED_EVIDENCE_DENY_LEGAL_BASIS_TOKEN_HASH}"
update_local_env "SHARED_EVIDENCE_DENY_CONSENT_TOKEN" "${SHARED_EVIDENCE_DENY_CONSENT_TOKEN}"
update_local_env "SHARED_EVIDENCE_DENY_CONSENT_TOKEN_HASH" "${SHARED_EVIDENCE_DENY_CONSENT_TOKEN_HASH}"
update_local_env "OPENCRVS_DCI_NOTARY_PORT" "${OPENCRVS_DCI_NOTARY_PORT}"

subject_uin="${OPENCRVS_DEMO_SUBJECT_UIN:-}"
if [[ -z "${subject_uin}" ]]; then
  subject_uin="$(discover_subject_uin "${opencrvs_dci_token}")"
fi
[[ -n "${subject_uin}" ]] || fail "could not find an OpenCRVS demo UIN"
update_local_env "OPENCRVS_DEMO_SUBJECT_UIN" "${subject_uin}"

mkdir -p "${output_dir}"

docker compose -f "${compose_file}" --profile opencrvs up -d --build --force-recreate opencrvs-dci-notary

notary_url="http://127.0.0.1:${OPENCRVS_DCI_NOTARY_PORT}"
wait_http "OpenCRVS DCI notary discovery" "${notary_url}/.well-known/evidence-service" "${OPENCRVS_EVIDENCE_CLIENT_TOKEN}"

evaluation_body="${output_dir}/evaluation.json"
summary_body="${output_dir}/summary.json"
vc_evaluation_body="${output_dir}/vc-evaluation.json"
credential_body="${output_dir}/credential.json"
credential_summary_body="${output_dir}/credential-summary.json"
live_fixture_output="${output_dir}/evidence-gateway-live-sp-dci.json"
check "SP DCI live evidence gateway fixtures" python3 "${script_dir}/run-evidence-gateway-live-fixtures.py" --profile sp-dci/v1 --base-url "${notary_url}" --auth api-key --token "${OPENCRVS_EVIDENCE_CLIENT_TOKEN}" --subject-id "${subject_uin}" --output "${live_fixture_output}" --correlation-prefix "${correlation_id}-evidence-gateway"
payload="$(
  jq -nc --arg subject "${subject_uin}" '{
    target: {
      type: "Person",
      identifiers: [{ scheme: "UIN", value: $subject, issuer: "opencrvs" }]
    },
    claims: [
      "opencrvs-birth-record-exists",
      "opencrvs-date-of-birth",
      "opencrvs-sex",
      "opencrvs-age-band",
      "opencrvs-child-given-name",
      "opencrvs-child-family-name",
      "opencrvs-child-date-of-birth",
      "opencrvs-child-place-of-birth"
    ],
    disclosure: "value",
    format: "application/vnd.registry-notary.claim-result+json"
  }'
)"

curl -fsS \
  --connect-timeout "${curl_connect_timeout}" \
  --max-time "${curl_max_time}" \
  -X POST "${notary_url}/v1/evaluations" \
  -H "x-api-key: ${OPENCRVS_EVIDENCE_CLIENT_TOKEN}" \
  -H "content-type: application/json" \
  -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci-lab" \
  -H "x-request-id: ${correlation_id}" \
  -o "${evaluation_body}" \
  --data-raw "${payload}"

python - "${evaluation_body}" "${summary_body}" <<'PY'
import json
import sys

source, target = sys.argv[1], sys.argv[2]
body = json.load(open(source, encoding="utf-8"))
results = body.get("results") or []
by_claim = {result.get("claim_id"): result for result in results}
expected = [
    "opencrvs-birth-record-exists",
    "opencrvs-date-of-birth",
    "opencrvs-sex",
    "opencrvs-age-band",
    "opencrvs-child-given-name",
    "opencrvs-child-family-name",
    "opencrvs-child-date-of-birth",
    "opencrvs-child-place-of-birth",
]
missing = [claim for claim in expected if claim not in by_claim]
if missing:
    raise SystemExit(f"missing claims: {missing}")
if by_claim["opencrvs-birth-record-exists"].get("value") is not True:
    raise SystemExit("OpenCRVS birth record existence claim was not true")
def source_count(result):
    provenance = result.get("provenance", {})
    if isinstance(provenance.get("source_count"), int):
        return provenance["source_count"]
    used = provenance.get("used", {})
    if isinstance(used, dict):
        return used.get("source_count")
    return None
for claim in expected:
    if source_count(by_claim[claim]) != 1:
        raise SystemExit(f"{claim} did not record exactly one source")
summary = {
    "claims": [
        {
            "claim_id": claim,
            "value": by_claim[claim].get("value"),
            "satisfied": by_claim[claim].get("satisfied"),
            "disclosure": by_claim[claim].get("disclosure"),
            "source_count": source_count(by_claim[claim]),
        }
        for claim in expected
    ]
}
json.dump(summary, open(target, "w", encoding="utf-8"), indent=2)
PY

cat "${summary_body}"

vc_payload="$(
  jq -nc --arg subject "${subject_uin}" '{
    target: {
      type: "Person",
      identifiers: [{ scheme: "UIN", value: $subject, issuer: "opencrvs" }]
    },
    claims: [
      "opencrvs-child-given-name",
      "opencrvs-child-family-name",
      "opencrvs-child-date-of-birth",
      "opencrvs-child-place-of-birth"
    ],
    disclosure: "value",
    format: "application/dc+sd-jwt"
  }'
)"
curl -fsS \
  --connect-timeout "${curl_connect_timeout}" \
  --max-time "${curl_max_time}" \
  -X POST "${notary_url}/v1/evaluations" \
  -H "x-api-key: ${OPENCRVS_EVIDENCE_CLIENT_TOKEN}" \
  -H "content-type: application/json" \
  -H "data-purpose: https://demo.example.gov/purpose/opencrvs-dci-lab" \
  -H "x-request-id: ${correlation_id}-vc-evaluate" \
  -o "${vc_evaluation_body}" \
  --data-raw "${vc_payload}"

evaluation_id="$(jq -er '.results[0].evaluation_id' "${vc_evaluation_body}")"
issue_payload="$(
  jq -nc --arg evaluation_id "${evaluation_id}" '{
    evaluation_id: $evaluation_id,
    credential_profile: "opencrvs_birth_attributes_sd_jwt",
    format: "application/dc+sd-jwt",
    claims: [
      "opencrvs-child-given-name",
      "opencrvs-child-family-name",
      "opencrvs-child-date-of-birth",
      "opencrvs-child-place-of-birth"
    ],
    disclosure: "value"
  }'
)"
curl -fsS \
  --connect-timeout "${curl_connect_timeout}" \
  --max-time "${curl_max_time}" \
  -X POST "${notary_url}/v1/credentials" \
  -H "x-api-key: ${OPENCRVS_EVIDENCE_CLIENT_TOKEN}" \
  -H "content-type: application/json" \
  -H "x-request-id: ${correlation_id}-vc-issue" \
  -o "${credential_body}" \
  --data-raw "${issue_payload}"

python - "${credential_body}" "${credential_summary_body}" <<'PY'
import json
import sys

source, target = sys.argv[1], sys.argv[2]
body = json.load(open(source, encoding="utf-8"))
credential = body.get("credential") or ""
issuer_signed_jwt = body.get("issuer_signed_jwt") or ""
disclosures = body.get("disclosures") or []
if body.get("format") != "application/dc+sd-jwt":
    raise SystemExit("credential response did not use SD-JWT VC media type")
if not credential or not issuer_signed_jwt or not disclosures:
    raise SystemExit("credential response is missing SD-JWT VC material")
summary = {
    "credential_id": body.get("credential_id"),
    "credential_profile": "opencrvs_birth_attributes_sd_jwt",
    "format": body.get("format"),
    "issuer": body.get("issuer"),
    "expires_at": body.get("expires_at"),
    "disclosure_count": len(disclosures),
    "credential_compact_length": len(credential),
}
json.dump(summary, open(target, "w", encoding="utf-8"), indent=2)
PY

printf "\nIssued OpenCRVS SD-JWT VC summary:\n"
cat "${credential_summary_body}"
printf "\nIssued OpenCRVS birth attribute SD-JWT VC\n"

log_file="${output_dir}/opencrvs-dci-service-logs.txt"
docker compose -f "${compose_file}" logs --no-color opencrvs-dci-notary > "${log_file}"
check "SP DCI live evidence gateway audit log" python3 "${script_dir}/run-evidence-gateway-live-fixtures.py" --profile sp-dci/v1 --output "${live_fixture_output}" --audit-log-path "${log_file}" --audit-only

for secret_var in \
  OPENCRVS_DCI_CLIENT_SECRET \
  OPENCRVS_EVIDENCE_CLIENT_TOKEN \
  OPENCRVS_EVIDENCE_DENY_ASSURANCE_TOKEN \
  OPENCRVS_EVIDENCE_DENY_JURISDICTION_TOKEN \
  OPENCRVS_EVIDENCE_DENY_LEGAL_BASIS_TOKEN \
  OPENCRVS_EVIDENCE_DENY_CONSENT_TOKEN
do
  secret_value="${!secret_var:-}"
  if [[ -n "${secret_value}" ]] && grep -F -- "${secret_value}" "${log_file}" >/dev/null; then
    fail "service logs leaked ${secret_var}"
  fi
done

echo "OpenCRVS DCI smoke OK"
