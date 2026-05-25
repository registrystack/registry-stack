#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
witness_dir="${REGISTRY_WITNESS_SOURCE_DIR:-"${demo_dir}/../registry-witness"}"
output_dir="${demo_dir}/output/citizen-self-attestation"
config_path="${output_dir}/citizen-civil-witness.yaml"
log_path="${output_dir}/citizen-civil-witness.log"
discovery_path="${output_dir}/citizen-witness-discovery.json"
self_eval_path="${output_dir}/citizen-self-evaluation.json"
other_eval_path="${output_dir}/citizen-other-subject-denied.json"
token_claims_path="${output_dir}/citizen-access-token-claims.json"
id_token_claims_path="${output_dir}/citizen-id-token-claims.json"
userinfo_claims_path="${output_dir}/citizen-userinfo-claims.json"
correlation_id="${DEMO_CORRELATION_ID:-citizen-self-attestation-demo-001}"

port="${CITIZEN_WITNESS_PORT:-4325}"
subject_claim="${ESIGNET_SUBJECT_CLAIM:-national_id}"
subject_claim_source="${ESIGNET_SUBJECT_CLAIM_SOURCE:-access_token}"
assurance_claim_source="${ESIGNET_ASSURANCE_CLAIM_SOURCE:-access_token}"
self_subject="${ESIGNET_CITIZEN_SUBJECT:-NID-1001}"
other_subject="${ESIGNET_OTHER_SUBJECT:-NID-1002}"
self_attestation_scope="${ESIGNET_SELF_ATTESTATION_SCOPE:-self_attestation}"
self_attestation_scope_policy="${ESIGNET_SELF_ATTESTATION_SCOPE_POLICY:-disabled}"
if [[ "${self_attestation_scope_policy}" == "disabled" ]]; then
  authorize_scope="${ESIGNET_AUTHORIZE_SCOPE:-openid}"
else
  authorize_scope="${ESIGNET_AUTHORIZE_SCOPE:-openid ${self_attestation_scope}}"
fi
redirect_uri="${ESIGNET_REDIRECT_URI:-http://127.0.0.1:${port}/callback}"

fail() {
  echo "FAILED: $1" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

restore_dotenv_value() {
  local key="$1"
  local value
  value="$(grep -E "^${key}=" "${demo_dir}/.env" | tail -n 1 | cut -d= -f2- || true)"
  if [[ -n "${value}" ]]; then
    export "${key}=${value}"
  fi
}

wait_http() {
  local name="$1"
  local url="$2"
  local token="${3:-}"
  local request_id_token="${4:-${id_token:-}}"
  local deadline="${SMOKE_WAIT_SECONDS:-120}"
  local start
  start="$(date +%s)"
  local status="000"
  while (( $(date +%s) - start < deadline )); do
    local args=(-sS -o /dev/null -w "%{http_code}" -H "Accept: */*" -H "x-request-id: ${correlation_id}")
    if [[ -n "${token}" ]]; then
      args+=(-H "Authorization: Bearer ${token}")
    fi
    if [[ -n "${request_id_token}" ]]; then
      args+=(-H "x-registry-witness-oidc-id-token: ${request_id_token}")
    fi
    status="$(curl "${args[@]}" "${url}" 2>/dev/null || true)"
    if [[ "${status}" =~ ^2[0-9][0-9]$ ]]; then
      return 0
    fi
    sleep 1
  done
  fail "${name} did not become ready within ${deadline}s, last status ${status}"
}

base64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

private_key_jwt() {
  local client_id="$1"
  local token_endpoint="$2"
  local key_file="$3"
  local kid="${ESIGNET_CLIENT_ASSERTION_KID:-}"
  local now exp jti header payload signing_input signature
  now="$(date +%s)"
  exp="$((now + 300))"
  jti="$(openssl rand -hex 16)"
  header="$(
    python3 - "${kid}" <<'PY'
import json
import sys

kid = sys.argv[1]
header = {"alg": "RS256", "typ": "JWT"}
if kid:
    header["kid"] = kid
print(json.dumps(header, separators=(",", ":")))
PY
  )"
  payload="$(
    python3 - "${client_id}" "${token_endpoint}" "${now}" "${exp}" "${jti}" <<'PY'
import json
import sys

client_id, token_endpoint, now, exp, jti = sys.argv[1:]
payload = {
    "iss": client_id,
    "sub": client_id,
    "aud": token_endpoint,
    "iat": int(now),
    "exp": int(exp),
    "jti": jti,
}
print(json.dumps(payload, separators=(",", ":")))
PY
  )"
  signing_input="$(printf '%s' "${header}" | base64url).$(printf '%s' "${payload}" | base64url)"
  signature="$(printf '%s' "${signing_input}" | openssl dgst -sha256 -sign "${key_file}" | base64url)"
  printf '%s.%s\n' "${signing_input}" "${signature}"
}

write_pkce_request() {
  local issuer="$1"
  local client_id="$2"
  local discovery_json="$3"
  local pkce_file="${output_dir}/esignet-pkce.env"
  local verifier challenge authorization_endpoint state nonce auth_url

  verifier="$(openssl rand -base64 64 | tr '+/' '-_' | tr -d '=' | cut -c1-64)"
  challenge="$(printf '%s' "${verifier}" | openssl dgst -binary -sha256 | base64url)"
  state="$(openssl rand -hex 16)"
  nonce="$(openssl rand -hex 16)"
  authorization_endpoint="$(python3 - "${discovery_json}" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["authorization_endpoint"])
PY
  )"
  auth_url="$(
    python3 - "${authorization_endpoint}" "${client_id}" "${redirect_uri}" "${authorize_scope}" "${state}" "${nonce}" "${challenge}" <<'PY'
from urllib.parse import urlencode
import sys

endpoint, client_id, redirect_uri, scope, state, nonce, challenge = sys.argv[1:]
query = urlencode({
    "response_type": "code",
    "client_id": client_id,
    "redirect_uri": redirect_uri,
    "scope": scope,
    "state": state,
    "nonce": nonce,
    "code_challenge": challenge,
    "code_challenge_method": "S256",
})
print(f"{endpoint}?{query}")
PY
  )"
  cat >"${pkce_file}" <<EOF
ESIGNET_ISSUER=${issuer}
ESIGNET_CLIENT_ID=${client_id}
ESIGNET_REDIRECT_URI=${redirect_uri}
ESIGNET_CODE_VERIFIER=${verifier}
ESIGNET_STATE=${state}
ESIGNET_NONCE=${nonce}
EOF
  cat >&2 <<EOF
No ESIGNET_CITIZEN_ACCESS_TOKEN or ESIGNET_AUTHORIZATION_CODE was provided.

Open this eSignet authorization URL, complete citizen authentication, then
rerun this script with ESIGNET_AUTHORIZATION_CODE set to the callback code.
The PKCE verifier was saved to:
  ${pkce_file}

${auth_url}
EOF
  exit 2
}

exchange_authorization_code() {
  local code="$1"
  local token_endpoint="$2"
  local client_id="$3"
  local key_file="$4"
  local verifier="$5"
  local assertion token_response
  assertion="$(private_key_jwt "${client_id}" "${token_endpoint}" "${key_file}")"
  token_response="${output_dir}/esignet-token-response.json"
  curl --silent --show-error --fail-with-body \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=${code}" \
    --data-urlencode "redirect_uri=${redirect_uri}" \
    --data-urlencode "client_id=${client_id}" \
    --data-urlencode "code_verifier=${verifier}" \
    --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "client_assertion=${assertion}" \
    -o "${token_response}" \
    "${token_endpoint}"
  python3 - "${token_response}" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["access_token"])
PY
}

decode_jwt_claims() {
  local token="$1"
  local output_path="$2"
  python3 - "${token}" "${output_path}" <<'PY'
import base64
import json
import sys

token, claims_path = sys.argv[1:]
parts = token.split(".")
if len(parts) < 2:
    raise SystemExit("token is not a JWT")

def decode(part):
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part.encode()))

header = decode(parts[0])
claims = decode(parts[1])
snapshot = {"header": header, "claims": claims}
with open(claims_path, "w", encoding="utf-8") as handle:
    json.dump(snapshot, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

decode_access_token() {
  local token="$1"
  local metadata_env="$2"
  decode_jwt_claims "${token}" "${token_claims_path}"
  python3 - "${token_claims_path}" "${subject_claim}" "${self_subject}" "${self_attestation_scope}" "${self_attestation_scope_policy}" "${subject_claim_source}" "${assurance_claim_source}" >"${metadata_env}" <<'PY'
import json
import shlex
import sys

claims_path, subject_claim, expected_subject, required_scope, scope_policy, subject_claim_source, assurance_claim_source = sys.argv[1:]
snapshot = json.load(open(claims_path, encoding="utf-8"))
header = snapshot["header"]
claims = snapshot["claims"]
if subject_claim_source == "access_token":
    subject = claims.get(subject_claim)
    if subject != expected_subject:
        raise SystemExit(
            f"access token claim {subject_claim!r} must equal {expected_subject!r}; got {subject!r}"
        )
if assurance_claim_source == "access_token" and not isinstance(claims.get("auth_time"), int):
    raise SystemExit("access token must include numeric auth_time, or set ESIGNET_ASSURANCE_CLAIM_SOURCE=id_token")
issuer = claims.get("iss")
if not issuer:
    raise SystemExit("token must include iss")
aud = claims.get("aud") or []
if isinstance(aud, str):
    aud = [aud]
client_id = claims.get("azp") or claims.get("client_id")
scope = claims.get("scope") or ""
scope_values = set(str(scope).split())
if scope_policy == "required" and required_scope not in scope_values:
    raise SystemExit(f"access token scope must include {required_scope!r}; got {scope!r}")
if scope_policy == "optional" and scope and required_scope not in scope_values:
    raise SystemExit(f"access token scope was present but did not include {required_scope!r}; got {scope!r}")
print(f"TOKEN_ISSUER={shlex.quote(str(issuer))}")
print(f"TOKEN_ALG={shlex.quote(str(header.get('alg') or 'RS256'))}")
print(f"TOKEN_CLIENT_ID={shlex.quote(str(client_id or ''))}")
print(f"TOKEN_AUDIENCES_JSON={shlex.quote(json.dumps(aud))}")
print(f"TOKEN_AUDIENCE_FIRST={shlex.quote(str(aud[0] if aud else client_id or ''))}")
print(f"TOKEN_SCOPE={shlex.quote(str(scope))}")
PY
}

validate_id_token() {
  local token="$1"
  decode_jwt_claims "${token}" "${id_token_claims_path}"
  python3 - "${token_claims_path}" "${id_token_claims_path}" <<'PY'
import json
import sys

access = json.load(open(sys.argv[1], encoding="utf-8"))["claims"]
claims = json.load(open(sys.argv[2], encoding="utf-8"))["claims"]
if claims.get("sub") != access.get("sub"):
    raise SystemExit("ID token sub must match access token sub")
if not isinstance(claims.get("auth_time"), int):
    raise SystemExit("ID token must include numeric auth_time")
if "acr" not in claims:
    raise SystemExit("ID token must include acr")
PY
}

fetch_and_validate_userinfo() {
  local endpoint="$1"
  local token="$2"
  local userinfo_jwt="${output_dir}/citizen-userinfo.jwt"
  curl --silent --show-error --fail-with-body \
    -H "Authorization: Bearer ${token}" \
    -H "Accept: application/jwt" \
    -o "${userinfo_jwt}" \
    "${endpoint}" ||
    fail "could not read eSignet UserInfo endpoint at ${endpoint}"
  decode_jwt_claims "$(cat "${userinfo_jwt}")" "${userinfo_claims_path}"
  python3 - "${token_claims_path}" "${userinfo_claims_path}" "${subject_claim}" "${self_subject}" <<'PY'
import json
import sys

access = json.load(open(sys.argv[1], encoding="utf-8"))["claims"]
claims = json.load(open(sys.argv[2], encoding="utf-8"))["claims"]
subject_claim, expected_subject = sys.argv[3:]
if claims.get("sub") != access.get("sub"):
    raise SystemExit("UserInfo sub must match access token sub")
subject = claims.get(subject_claim)
if subject != expected_subject:
    raise SystemExit(
        f"UserInfo claim {subject_claim!r} must equal {expected_subject!r}; got {subject!r}"
    )
PY
}

write_witness_config() {
  local issuer="$1"
  local jwks_uri="$2"
  local userinfo_endpoint="$3"
  local alg="$4"
  local client_id="$5"
  local audience_json="$6"
  local scope="$7"
  python3 - "${config_path}" "${port}" "${issuer}" "${jwks_uri}" "${userinfo_endpoint}" "${alg}" "${client_id}" "${audience_json}" "${scope}" "${self_attestation_scope_policy}" "${subject_claim}" "${subject_claim_source}" "${assurance_claim_source}" <<'PY'
import json
import sys

path, port, issuer, jwks_uri, userinfo_endpoint, alg, client_id, audience_json, scope, scope_policy, subject_claim, subject_claim_source, assurance_claim_source = sys.argv[1:]
audiences = json.loads(audience_json)
if not audiences:
    audiences = [client_id]
if not client_id:
    raise SystemExit("client_id/azp is required; set ESIGNET_CLIENT_ID if the token omits it")
audience_lines = "\n".join(f"      - {json.dumps(value)}" for value in audiences)
allowed_client_lines = f"      - {json.dumps(client_id)}"
userinfo_line = f"    userinfo_endpoint: {json.dumps(userinfo_endpoint)}\n" if userinfo_endpoint else ""
required_scopes_block = ""
if scope_policy != "disabled":
    required_scopes_block = f"""  required_scopes:
    - {json.dumps(scope)}
"""
text = f"""# Generated by scripts/smoke-citizen-self-attestation.sh. Do not edit by hand.
server:
  bind: 127.0.0.1:{port}

auth:
  mode: oidc
  oidc:
    issuer: {json.dumps(issuer)}
    jwks_uri: {json.dumps(jwks_uri)}
{userinfo_line.rstrip()}
    audiences:
{audience_lines}
    allowed_clients:
{allowed_client_lines}
    allowed_algorithms:
      - {json.dumps(alg)}
    allowed_typ:
      - JWT
      - at+jwt
    scope_claim: scope
    scope_separator: " "
    principal_claim: sub
    leeway_seconds: 60
    allow_insecure_localhost: true
    scope_map:
      {json.dumps(scope)}:
        - {json.dumps(scope)}

audit:
  sink: stdout
  hash_secret_env: REGISTRY_WITNESS_AUDIT_HASH_SECRET

evidence:
  enabled: true
  service_id: citizen-civil-witness
  api_base_url: http://127.0.0.1:{port}
  inline_batch_limit: 20
  source_connections:
    civil:
      base_url: http://127.0.0.1:4311
      allow_insecure_localhost: true
      token_env: CIVIL_EVIDENCE_SOURCE_RAW
      dci:
        search_path: /dci/crvs/registry/sync/search
        query_type: idtype-value
        records_path: /message/search_response/0/data/reg_records
        field_paths:
          national_id: /person/national_id
          deceased: /person/deceased
  credential_profiles:
    citizen_civil_status_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:citizen-civil-witness.demo.example
      issuer_key_env: REGISTRY_WITNESS_ISSUER_JWK
      issuer_kid: did:web:citizen-civil-witness.demo.example#citizen-civil-demo-key-1
      vct: https://demo.example/credentials/citizen-civil-status/v1
      validity_seconds: 600
      allowed_claims:
        - person-is-alive
      holder_binding:
        mode: did
        proof_of_possession: required
        allowed_did_methods:
          - did:jwk
      disclosure:
        allowed:
          - predicate
  claims:
    - id: person-is-alive
      title: Person is alive
      version: 2026-05
      subject_type: person
      purpose: citizen_self_attestation
      value:
        type: boolean
      inputs:
        - name: subject_id
          type: string
      source_bindings:
        civil:
          connector: dci
          connection: civil
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: subject_id
            field: NATIONAL_ID
            op: eq
            cardinality: one
          fields:
            deceased:
              field: deceased
              type: boolean
              required: true
      rule:
        type: cel
        expression: "source.civil.deceased == false"
      disclosure:
        default: predicate
        allowed:
          - predicate
          - redacted
      formats:
        - application/vnd.registry-witness.claim-result+json
        - application/dc+sd-jwt
      credential_profiles:
        - citizen_civil_status_sd_jwt

self_attestation:
  enabled: true
  subject_binding:
    token_claim: {json.dumps(subject_claim)}
    claim_source: {json.dumps(subject_claim_source)}
    id_type: national_id
  citizen_clients:
    allowed_client_ids:
      - {json.dumps(client_id)}
    allowed_audiences:
{audience_lines}
  token_policy:
    assurance_claim_source: {json.dumps(assurance_claim_source)}
    max_auth_age_seconds: 900
    max_access_token_lifetime_seconds: 900
    max_evaluation_age_seconds: 600
    max_credential_validity_seconds: 600
    max_clock_leeway_seconds: 60
  allowed_operations:
    evaluate: true
    render: true
    issue_credential: false
    batch_evaluate: false
  allowed_purposes:
    - citizen_self_attestation
  allowed_claims:
    - person-is-alive
  allowed_formats:
    - application/vnd.registry-witness.claim-result+json
    - application/dc+sd-jwt
  allowed_disclosures:
    - predicate
    - redacted
  scope_policy: {json.dumps(scope_policy)}
{required_scopes_block.rstrip()}
  credential_profiles:
    - citizen_civil_status_sd_jwt
  allowed_wallet_origins:
    - https://wallet.example.gov
  rate_limits:
    mode: in_process
    invalid_token_per_client_address_per_minute: 20
    per_principal_per_minute: 10
    subject_mismatch_per_principal_per_hour: 5
    per_holder_per_hour: 10
    credential_issuance_per_principal_per_hour: 5
"""
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
}

curl_json() {
  local method="$1"
  local url="$2"
  local output="$3"
  local expected="$4"
  shift 4
  local status
  local args=(-sS -o "${output}" -w "%{http_code}" -X "${method}"
    -H "Authorization: Bearer ${access_token}"
    -H "Content-Type: application/json"
    -H "x-request-id: ${correlation_id}")
  if [[ -n "${id_token:-}" ]]; then
    args+=(-H "x-registry-witness-oidc-id-token: ${id_token}")
  fi
  status="$(curl "${args[@]}" "$@" "${url}")"
  if [[ "${status}" != "${expected}" ]]; then
    echo "Expected ${url} to return ${expected}, got ${status}" >&2
    cat "${output}" >&2 || true
    exit 1
  fi
}

need curl
need python3
need openssl

mkdir -p "${output_dir}"

case "${subject_claim_source}" in
  access_token | userinfo) ;;
  *) fail "ESIGNET_SUBJECT_CLAIM_SOURCE must be access_token or userinfo" ;;
esac
case "${assurance_claim_source}" in
  access_token | id_token) ;;
  *) fail "ESIGNET_ASSURANCE_CLAIM_SOURCE must be access_token or id_token" ;;
esac
case "${self_attestation_scope_policy}" in
  required | optional | disabled) ;;
  *) fail "ESIGNET_SELF_ATTESTATION_SCOPE_POLICY must be required, optional, or disabled" ;;
esac

if [[ -f "${demo_dir}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${demo_dir}/.env"
  set +a
  restore_dotenv_value REGISTRY_WITNESS_ISSUER_JWK
else
  fail "missing .env; run scripts/generate-demo-secrets.py first"
fi
: "${CIVIL_METADATA_CLIENT_RAW:?missing CIVIL_METADATA_CLIENT_RAW; rerun scripts/generate-demo-secrets.py}"
: "${CIVIL_EVIDENCE_SOURCE_RAW:?missing CIVIL_EVIDENCE_SOURCE_RAW; rerun scripts/generate-demo-secrets.py}"
: "${REGISTRY_WITNESS_AUDIT_HASH_SECRET:?missing REGISTRY_WITNESS_AUDIT_HASH_SECRET; rerun scripts/generate-demo-secrets.py}"

issuer="${ESIGNET_ISSUER:-}"
if [[ -z "${issuer}" && -n "${ESIGNET_CITIZEN_ACCESS_TOKEN:-}" ]]; then
  issuer="$(
    python3 - "${ESIGNET_CITIZEN_ACCESS_TOKEN}" <<'PY'
import base64
import json
import sys

payload = sys.argv[1].split(".")[1]
payload += "=" * (-len(payload) % 4)
print(json.loads(base64.urlsafe_b64decode(payload)).get("iss", ""))
PY
  )"
fi
[[ -n "${issuer}" ]] || fail "set ESIGNET_ISSUER or ESIGNET_CITIZEN_ACCESS_TOKEN"

discovery_json="${output_dir}/esignet-openid-configuration.json"
discovery_url="${ESIGNET_DISCOVERY_URL:-${issuer%/}/.well-known/openid-configuration}"
curl --silent --show-error --fail-with-body \
  -o "${discovery_json}" \
  "${discovery_url}" ||
  fail "could not read eSignet OpenID discovery at ${discovery_url}"

jwks_uri="${ESIGNET_JWKS_URI:-$(python3 - "${discovery_json}" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["jwks_uri"])
PY
)}"
token_endpoint="${ESIGNET_TOKEN_ENDPOINT:-$(python3 - "${discovery_json}" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("token_endpoint", ""))
PY
)}"
userinfo_endpoint="${ESIGNET_USERINFO_ENDPOINT:-$(python3 - "${discovery_json}" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("userinfo_endpoint", ""))
PY
)}"

access_token="${ESIGNET_CITIZEN_ACCESS_TOKEN:-}"
id_token="${ESIGNET_CITIZEN_ID_TOKEN:-}"
if [[ -z "${access_token}" ]]; then
  client_id="${ESIGNET_CLIENT_ID:-}"
  [[ -n "${client_id}" ]] || fail "set ESIGNET_CLIENT_ID when requesting a citizen token"
  if [[ -z "${ESIGNET_AUTHORIZATION_CODE:-}" ]]; then
    write_pkce_request "${issuer}" "${client_id}" "${discovery_json}"
  fi
  key_file="${ESIGNET_CLIENT_PRIVATE_KEY_FILE:-}"
  [[ -n "${key_file}" && -f "${key_file}" ]] ||
    fail "set ESIGNET_CLIENT_PRIVATE_KEY_FILE to an RSA private key for private-key-jwt token exchange"
  [[ -n "${token_endpoint}" ]] || fail "eSignet discovery did not include token_endpoint"
  verifier="${ESIGNET_CODE_VERIFIER:-}"
  if [[ -z "${verifier}" && -f "${output_dir}/esignet-pkce.env" ]]; then
    # shellcheck disable=SC1091
    . "${output_dir}/esignet-pkce.env"
    verifier="${ESIGNET_CODE_VERIFIER:-}"
  fi
  [[ -n "${verifier}" ]] || fail "missing ESIGNET_CODE_VERIFIER; rerun without ESIGNET_AUTHORIZATION_CODE to generate a PKCE request"
  access_token="$(exchange_authorization_code "${ESIGNET_AUTHORIZATION_CODE}" "${token_endpoint}" "${client_id}" "${key_file}" "${verifier}")"
  if [[ -z "${id_token}" && -f "${output_dir}/esignet-token-response.json" ]]; then
    id_token="$(
      python3 - "${output_dir}/esignet-token-response.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("id_token", ""))
PY
    )"
  fi
fi

metadata_env="${output_dir}/citizen-token.env"
decode_access_token "${access_token}" "${metadata_env}"
# shellcheck disable=SC1090
. "${metadata_env}"

if [[ "${assurance_claim_source}" == "id_token" ]]; then
  [[ -n "${id_token}" ]] ||
    fail "ESIGNET_ASSURANCE_CLAIM_SOURCE=id_token requires ESIGNET_CITIZEN_ID_TOKEN or an auth-code token response with id_token"
  validate_id_token "${id_token}"
fi
if [[ "${subject_claim_source}" == "userinfo" ]]; then
  [[ -n "${userinfo_endpoint}" ]] ||
    fail "ESIGNET_SUBJECT_CLAIM_SOURCE=userinfo requires a discovery userinfo_endpoint or ESIGNET_USERINFO_ENDPOINT"
  fetch_and_validate_userinfo "${userinfo_endpoint}" "${access_token}"
fi

client_id="${ESIGNET_CLIENT_ID:-${TOKEN_CLIENT_ID:-}}"
[[ -n "${client_id}" ]] || fail "token omitted azp/client_id; set ESIGNET_CLIENT_ID"
alg="${ESIGNET_TOKEN_ALGORITHM:-${TOKEN_ALG:-RS256}}"
audiences_json="${ESIGNET_AUDIENCES_JSON:-${TOKEN_AUDIENCES_JSON}}"

write_witness_config "${issuer}" "${jwks_uri}" "${userinfo_endpoint}" "${alg}" "${client_id}" "${audiences_json}" "${self_attestation_scope}"

docker compose -f "${compose_file}" up -d civil-registry-relay
wait_http "civil relay health" "http://127.0.0.1:4311/health" "${CIVIL_METADATA_CLIENT_RAW}"

rm -f "${log_path}"
(
  cd "${witness_dir}"
  cargo run -p registry-witness-bin -- --config "${config_path}"
) >"${log_path}" 2>&1 &
witness_pid="$!"
trap 'kill "${witness_pid}" >/dev/null 2>&1 || true' EXIT

wait_http "citizen civil witness discovery" "http://127.0.0.1:${port}/.well-known/evidence-service" "${access_token}"

curl_json GET "http://127.0.0.1:${port}/.well-known/evidence-service" "${discovery_path}" 200

curl_json POST "http://127.0.0.1:${port}/claims/evaluate" "${self_eval_path}" 200 \
  --data "{\"subject\":{\"id\":\"${self_subject}\",\"id_type\":\"national_id\"},\"claims\":[\"person-is-alive\"],\"disclosure\":\"predicate\",\"format\":\"application/vnd.registry-witness.claim-result+json\"}"

python3 - "${self_eval_path}" <<'PY'
import json
import sys

body = json.load(open(sys.argv[1], encoding="utf-8"))
results = body.get("results") or []
assert len(results) == 1, body
result = results[0]
assert result.get("claim_id") == "person-is-alive", body
assert result.get("value") is True, body
assert result.get("provenance", {}).get("source_count") == 1, body
PY

curl_json POST "http://127.0.0.1:${port}/claims/evaluate" "${other_eval_path}" 403 \
  --data "{\"subject\":{\"id\":\"${other_subject}\",\"id_type\":\"national_id\"},\"claims\":[\"person-is-alive\"],\"disclosure\":\"predicate\",\"format\":\"application/vnd.registry-witness.claim-result+json\"}"

sleep 1
grep -q '"access_mode":"self_attestation"' "${log_path}" ||
  fail "Witness audit log did not include access_mode=self_attestation"

cat <<EOF
Citizen self-attestation smoke passed.

Artifacts:
  ${discovery_path}
  ${self_eval_path}
  ${other_eval_path}
  ${token_claims_path}
  ${log_path}
EOF
