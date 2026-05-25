#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
output_dir="${demo_dir}/output/citizen-oid4vci"
self_attestation_dir="${CITIZEN_OID4VCI_SELF_ATTESTATION_DIR:-${demo_dir}/output/citizen-self-attestation}"
base_url="${CITIZEN_OID4VCI_WITNESS_BASE_URL:-http://127.0.0.1:${CITIZEN_WITNESS_PORT:-4325}}"
metadata_url="${CITIZEN_OID4VCI_METADATA_URL:-${base_url%/}/.well-known/openid-credential-issuer}"
access_token="${CITIZEN_OID4VCI_ACCESS_TOKEN:-${ESIGNET_CITIZEN_ACCESS_TOKEN:-}}"
id_token="${CITIZEN_OID4VCI_ID_TOKEN:-${ESIGNET_CITIZEN_ID_TOKEN:-}}"
correlation_id="${DEMO_CORRELATION_ID:-citizen-oid4vci-demo-001}"

metadata_path="${output_dir}/issuer-metadata.json"
offer_path="${output_dir}/credential-offer.json"
negative_offer_path="${output_dir}/credential-offer-unknown-denied.json"
nonce_path="${output_dir}/nonce.json"
nonce_request_path="${output_dir}/nonce-request.json"
credential_request_path="${output_dir}/credential-request.json"
credential_response_path="${output_dir}/credential-response.json"
metadata_env_path="${output_dir}/issuer-metadata.env"
report_path="${output_dir}/report.md"
transcript_path="${output_dir}/flow-transcript.txt"

fail() {
  write_report "failed" "$1"
  echo "FAILED: $1" >&2
  echo "OID4VCI evidence was written to ${output_dir}" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAILED: missing required command: $1" >&2
    exit 1
  }
}

request() {
  local name="$1"
  local method="$2"
  local url="$3"
  local body_path="$4"
  shift 4
  local headers_path="${output_dir}/${name}.headers"
  local status_path="${output_dir}/${name}.status"
  local args=(-sS -D "${headers_path}" -o "${body_path}" -w "%{http_code}" -X "${method}"
    -H "Accept: application/json"
    -H "x-request-id: ${correlation_id}")
  if [[ -n "${access_token}" ]]; then
    args+=(-H "Authorization: Bearer ${access_token}")
  fi
  if [[ -n "${id_token}" ]]; then
    args+=(-H "x-registry-witness-oidc-id-token: ${id_token}")
  fi
  local status
  status="$(curl "${args[@]}" "$@" "${url}" || true)"
  printf '%s\n' "${status}" >"${status_path}"
  printf '%s %s %s -> %s\n' "${method}" "${url}" "${body_path}" "${status}" >>"${transcript_path}"
}

status_for() {
  cat "${output_dir}/$1.status" 2>/dev/null || printf '000'
}

is_2xx() {
  [[ "$1" =~ ^2[0-9][0-9]$ ]]
}

json_value() {
  local path="$1"
  local expression="$2"
  python3 - "${path}" "${expression}" <<'PY'
import json
import sys
from pathlib import Path

path, expression = sys.argv[1:]
data = json.loads(Path(path).read_text(encoding="utf-8"))
value = data
for part in expression.split("."):
    if not part:
        continue
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break
if isinstance(value, (dict, list)):
    print(json.dumps(value, separators=(",", ":")))
elif value is None:
    print("")
else:
    print(value)
PY
}

json_present() {
  [[ -n "$(json_value "$1" "$2")" ]] && printf true || printf false
}

make_oid4vci_proof() {
  local proof_path="$1"
  local audience="$2"
  local nonce="$3"
  local key_dir
  key_dir="$(mktemp -d "${TMPDIR:-/tmp}/registry-lab-oid4vci-holder.XXXXXX")"
  local key_path="${key_dir}/holder-key.pem"
  local signing_input_path="${output_dir}/holder-proof.signing-input"
  local signature_path="${output_dir}/holder-proof.signature"
  local public_x
  openssl genpkey -algorithm ED25519 -out "${key_path}" >/dev/null 2>&1
  public_x="$(
    openssl pkey -in "${key_path}" -pubout -outform DER |
      tail -c 32 |
      openssl base64 -A |
      tr '+/' '-_' |
      tr -d '='
  )"
  python3 - "${signing_input_path}" "${audience}" "${nonce}" "${public_x}" <<'PY'
import base64
import json
import sys
import time
from pathlib import Path

signing_input_path, audience, nonce, public_x = sys.argv[1:]

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

public_jwk = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": public_x,
    "alg": "EdDSA",
}
holder_id = "did:jwk:" + b64url(json.dumps(public_jwk, separators=(",", ":"), sort_keys=True).encode())
now = int(time.time())
header = {"alg": "EdDSA", "typ": "openid4vci-proof+jwt", "jwk": public_jwk}
payload = {"iss": holder_id, "aud": audience, "iat": now, "exp": now + 60, "nonce": nonce}
header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
Path(signing_input_path).write_text(f"{header_b64}.{payload_b64}", encoding="utf-8")
PY
  openssl pkeyutl -sign -rawin -inkey "${key_path}" -in "${signing_input_path}" -out "${signature_path}"
  printf '%s.%s' \
    "$(cat "${signing_input_path}")" \
    "$(openssl base64 -A <"${signature_path}" | tr '+/' '-_' | tr -d '=')" \
    >"${proof_path}"
  rm -rf "${key_dir}"
}

write_report() {
  local result="$1"
  local detail="$2"
  python3 - \
    "${report_path}" \
    "${transcript_path}" \
    "${metadata_path}" \
    "${offer_path}" \
    "${negative_offer_path}" \
    "${nonce_path}" \
    "${nonce_request_path}" \
    "${credential_request_path}" \
    "${credential_response_path}" \
    "${self_attestation_dir}" \
    "${base_url}" \
    "${metadata_url}" \
    "${result}" \
    "${detail}" \
    "$(status_for metadata)" \
    "$(status_for offer)" \
    "$(status_for negative_offer)" \
    "$(status_for nonce)" \
    "$(status_for credential)" <<'PY'
import json
import sys
from pathlib import Path

(
    report_path,
    transcript_path,
    metadata_path,
    offer_path,
    negative_offer_path,
    nonce_path,
    nonce_request_path,
    credential_request_path,
    credential_response_path,
    self_attestation_dir,
    base_url,
    metadata_url,
    result,
    detail,
    metadata_status,
    offer_status,
    negative_offer_status,
    nonce_status,
    credential_status,
) = sys.argv[1:]

def load_json(path):
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None

metadata = load_json(metadata_path) or {}
offer = load_json(offer_path) or {}
negative_offer = load_json(negative_offer_path) or {}
nonce = load_json(nonce_path) or {}
nonce_request = load_json(nonce_request_path) or {}
credential_request = load_json(credential_request_path) or {}
credential_response = load_json(credential_response_path) or {}
configs = metadata.get("credential_configurations_supported") or {}
config_ids = sorted(configs.keys())
credential = credential_response.get("credential")
credential_length = len(credential) if isinstance(credential, str) else 0

lines = [
    "# Citizen OID4VCI Demo Probe Report",
    "",
    "## Result",
    "",
    f"- Overall: `{result}`",
    f"- Detail: {detail}",
    f"- Witness base URL: `{base_url}`",
    f"- Issuer metadata URL: `{metadata_url}`",
    "",
    "## Endpoint Evidence",
    "",
    f"- Metadata status: `{metadata_status}`",
    f"- Offer status: `{offer_status}`",
    f"- Unknown offer status: `{negative_offer_status}`",
    f"- Nonce status: `{nonce_status}`",
    f"- Credential status: `{credential_status}`",
    "",
    "## Metadata Summary",
    "",
    f"- Credential issuer: `{metadata.get('credential_issuer', '')}`",
    f"- Credential endpoint: `{metadata.get('credential_endpoint', '')}`",
    f"- Nonce endpoint: `{metadata.get('nonce_endpoint', '')}`",
    f"- Credential configurations: `{', '.join(config_ids)}`",
    "",
    "## Offer Summary",
    "",
    f"- Offer issuer: `{offer.get('credential_issuer', '')}`",
    f"- Offered configurations: `{', '.join(offer.get('credential_configuration_ids') or [])}`",
    f"- Authorization code grant present: `{bool((offer.get('grants') or {}).get('authorization_code'))}`",
    f"- Unknown offer probe received OAuth error: `{negative_offer.get('error', '')}`",
    f"- Unknown offer detail: `{negative_offer.get('error_description', '')}`",
    "",
    "## Nonce Summary",
    "",
    f"- Requested configuration: `{nonce_request.get('credential_configuration_id', '')}`",
    f"- Nonce present: `{bool(nonce.get('c_nonce'))}`",
    f"- Nonce TTL: `{nonce.get('c_nonce_expires_in', '')}`",
    "",
    "## Credential Probe",
    "",
    f"- Requested format: `{credential_request.get('format', '')}`",
    f"- Requested configuration: `{credential_request.get('credential_configuration_id', '')}`",
    f"- Holder proof present: `{bool((credential_request.get('proof') or {}).get('jwt'))}`",
    f"- Credential issued: `{bool(credential)}`",
    f"- Credential format: `{credential_response.get('format', '')}`",
    f"- Credential size: `{credential_length}` characters",
    f"- Follow-up nonce present: `{bool(credential_response.get('c_nonce'))}`",
    f"- Response error: `{credential_response.get('error') or credential_response.get('code') or ''}`",
    f"- Response detail: `{credential_response.get('error_description') or credential_response.get('detail') or ''}`",
    "",
    "## Inputs",
    "",
    f"- Self-attestation artifacts: `{self_attestation_dir}`",
    f"- Sensitive demo artifacts: `intentionally retained locally for replay/debugging`",
    f"- Raw eSignet tokens: `not printed by this probe; may exist in the self-attestation output used to launch it`",
    f"- Raw proof and credential bodies: `written under {Path(credential_request_path).parent}`",
    "",
    "## Artifacts",
    "",
    f"- `{metadata_path}`",
    f"- `{offer_path}`",
    f"- `{negative_offer_path}`",
    f"- `{nonce_path}`",
    f"- `{nonce_request_path}`",
    f"- `{credential_request_path}`",
    f"- `{credential_response_path}`",
    f"- `{transcript_path}`",
    "",
]
Path(report_path).write_text("\n".join(lines), encoding="utf-8")
PY
}

need curl
need python3
need openssl

mkdir -p "${output_dir}"
cat >"${transcript_path}" <<EOF
Citizen OID4VCI demo probe transcript
correlation_id=${correlation_id}
base_url=${base_url}
metadata_url=${metadata_url}
tokens=redacted
EOF

request metadata GET "${metadata_url}" "${metadata_path}"
metadata_status="$(status_for metadata)"
is_2xx "${metadata_status}" ||
  fail "issuer metadata endpoint did not return 2xx; status ${metadata_status}. This usually means the current Witness build/config does not expose OID4VCI yet."

if ! python3 - "${metadata_path}" "${metadata_env_path}" "${CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID:-}" 2>"${output_dir}/issuer-metadata-parse.error" <<'PY'
import json
import shlex
import sys

metadata_path, env_path, requested_config_id = sys.argv[1:]
metadata = json.load(open(metadata_path, encoding="utf-8"))
configs = metadata.get("credential_configurations_supported")
if not isinstance(configs, dict) or not configs:
    raise SystemExit("issuer metadata missing non-empty credential_configurations_supported")
credential_endpoint = metadata.get("credential_endpoint")
credential_issuer = metadata.get("credential_issuer")
offer_endpoint = metadata.get("offer_endpoint")
nonce_endpoint = metadata.get("nonce_endpoint")
if not credential_issuer:
    raise SystemExit("issuer metadata missing credential_issuer")
if not credential_endpoint:
    raise SystemExit("issuer metadata missing credential_endpoint")
if not nonce_endpoint:
    raise SystemExit("issuer metadata missing nonce_endpoint")
if requested_config_id:
    if requested_config_id not in configs:
        raise SystemExit(f"metadata does not advertise requested credential configuration {requested_config_id!r}")
    config_id = requested_config_id
else:
    preferred = ["person_is_alive_sd_jwt", "citizen_civil_status_sd_jwt"]
    config_id = next((value for value in preferred if value in configs), next(iter(configs)))
with open(env_path, "w", encoding="utf-8") as handle:
    handle.write(f"CITIZEN_OID4VCI_CREDENTIAL_ISSUER={shlex.quote(str(credential_issuer))}\n")
    handle.write(f"CITIZEN_OID4VCI_CREDENTIAL_ENDPOINT={shlex.quote(str(credential_endpoint))}\n")
    handle.write(f"CITIZEN_OID4VCI_OFFER_ENDPOINT={shlex.quote(str(offer_endpoint or ''))}\n")
    handle.write(f"CITIZEN_OID4VCI_NONCE_ENDPOINT={shlex.quote(str(nonce_endpoint))}\n")
    handle.write(f"CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID={shlex.quote(str(config_id))}\n")
PY
then
  fail "issuer metadata was reachable but did not match the expected OID4VCI shape; see ${output_dir}/issuer-metadata-parse.error."
fi

# shellcheck disable=SC1090
. "${metadata_env_path}"

echo "OID4VCI metadata received."
echo "  issuer: $(json_value "${metadata_path}" "credential_issuer")"
echo "  credential endpoint: ${CITIZEN_OID4VCI_CREDENTIAL_ENDPOINT}"
echo "  nonce endpoint: ${CITIZEN_OID4VCI_NONCE_ENDPOINT}"
echo "  selected credential configuration: ${CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID}"

if [[ -n "${CITIZEN_OID4VCI_OFFER_ENDPOINT}" ]]; then
  offer_url="${CITIZEN_OID4VCI_OFFER_ENDPOINT}?credential_configuration_id=${CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID}"
else
  offer_url="${base_url%/}/oid4vci/credential-offer?credential_configuration_id=${CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID}"
fi
request offer GET "${offer_url}" "${offer_path}"
offer_status="$(status_for offer)"
is_2xx "${offer_status}" ||
  fail "credential offer endpoint did not return 2xx; status ${offer_status}."
echo "Credential offer received."
echo "  status: ${offer_status}"
echo "  offered configurations: $(json_value "${offer_path}" "credential_configuration_ids")"

negative_offer_url="${CITIZEN_OID4VCI_OFFER_ENDPOINT:-${base_url%/}/oid4vci/credential-offer}?credential_configuration_id=unknown"
request negative_offer GET "${negative_offer_url}" "${negative_offer_path}"
negative_offer_status="$(status_for negative_offer)"
[[ "${negative_offer_status}" == "400" ]] ||
  fail "unknown credential offer request should return 400; status ${negative_offer_status}."
[[ "$(json_value "${negative_offer_path}" "error")" == "invalid_request" ]] ||
  fail "unknown credential offer request did not return OAuth error invalid_request."
echo "Negative offer probe received OAuth error shape."
echo "  status: ${negative_offer_status}"
echo "  error: $(json_value "${negative_offer_path}" "error")"

python3 - "${nonce_request_path}" "${CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID}" <<'PY'
import json
import sys
from pathlib import Path

path, config_id = sys.argv[1:]
Path(path).write_text(
    json.dumps({"credential_configuration_id": config_id}, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

request nonce POST "${CITIZEN_OID4VCI_NONCE_ENDPOINT}" "${nonce_path}" \
  -H "Content-Type: application/json" \
  --data @"${nonce_request_path}"
nonce_status="$(status_for nonce)"
is_2xx "${nonce_status}" ||
  fail "nonce endpoint did not return 2xx; status ${nonce_status}."
echo "Nonce received."
echo "  status: ${nonce_status}"
echo "  bound credential configuration: ${CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID}"
echo "  nonce present: $(json_present "${nonce_path}" "c_nonce")"
echo "  ttl seconds: $(json_value "${nonce_path}" "c_nonce_expires_in")"

if [[ -z "${CITIZEN_OID4VCI_PROOF_JWT:-}" ]]; then
  c_nonce="$(
    python3 - "${nonce_path}" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("c_nonce", ""))
PY
  )"
  [[ -n "${c_nonce}" ]] || fail "nonce endpoint returned 2xx without c_nonce."
  proof_path="${output_dir}/holder-proof.jwt"
  make_oid4vci_proof "${proof_path}" "${CITIZEN_OID4VCI_CREDENTIAL_ISSUER}" "${c_nonce}" ||
    fail "could not generate local holder proof JWT. Ensure openssl supports Ed25519."
  CITIZEN_OID4VCI_PROOF_JWT="$(cat "${proof_path}")"
  echo "Generated ephemeral holder proof JWT."
  echo "  proof JWT: redacted"
  echo "  audience: ${CITIZEN_OID4VCI_CREDENTIAL_ISSUER}"
  echo "  nonce source: ${CITIZEN_OID4VCI_NONCE_ENDPOINT}"
fi

python3 - \
  "${credential_request_path}" \
  "${CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID}" \
  "${CITIZEN_OID4VCI_PROOF_JWT:-}" <<'PY'
import json
import sys

path, config_id, proof_jwt = sys.argv[1:]
body = {
    "format": "dc+sd-jwt",
    "credential_configuration_id": config_id,
    "credential_identifier": config_id,
}
if proof_jwt:
    body["proof"] = {"proof_type": "jwt", "jwt": proof_jwt}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(body, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

request credential POST "${CITIZEN_OID4VCI_CREDENTIAL_ENDPOINT}" "${credential_response_path}" \
  -H "Content-Type: application/json" \
  --data @"${credential_request_path}"
credential_status="$(status_for credential)"

is_2xx "${credential_status}" ||
  fail "credential endpoint did not issue with the generated holder proof JWT; status ${credential_status}."
echo "Credential response received."
echo "  status: ${credential_status}"
echo "  format: $(json_value "${credential_response_path}" "format")"
echo "  credential present: $(json_present "${credential_response_path}" "credential")"
echo "  credential value: redacted"
write_report "passed" "OID4VCI issuer metadata, offer, nonce, and credential issuance succeeded."

cat <<EOF
Citizen OID4VCI probe passed.

Artifacts:
  ${report_path}
  ${transcript_path}
  ${metadata_path}
  ${offer_path}
  ${negative_offer_path}
  ${nonce_path}
  ${credential_request_path}
  ${credential_response_path}
EOF
