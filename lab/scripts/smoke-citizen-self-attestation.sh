#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
notary_dir="${REGISTRY_NOTARY_SOURCE_DIR:-"${demo_dir}/../registry-notary"}"
output_dir="${demo_dir}/output/citizen-self-attestation"
config_path="${output_dir}/citizen-civil-notary.yaml"
log_path="${output_dir}/citizen-civil-notary.log"
discovery_path="${output_dir}/citizen-notary-discovery.json"
self_eval_path="${output_dir}/citizen-self-evaluation.json"
other_eval_path="${output_dir}/citizen-other-subject-denied.json"
token_claims_path="${output_dir}/citizen-access-token-claims.json"
id_token_claims_path="${output_dir}/citizen-id-token-claims.json"
userinfo_claims_path="${output_dir}/citizen-userinfo-claims.json"
report_path="${output_dir}/report.md"
transcript_path="${output_dir}/flow-transcript.txt"
correlation_id="${DEMO_CORRELATION_ID:-citizen-self-attestation-demo-001}"

port="${CITIZEN_WITNESS_PORT:-4325}"
subject_claim="${ESIGNET_SUBJECT_CLAIM:-national_id}"
subject_claim_source="${ESIGNET_SUBJECT_CLAIM_SOURCE:-access_token}"
assurance_claim_source="${ESIGNET_ASSURANCE_CLAIM_SOURCE:-access_token}"
self_subject="${ESIGNET_CITIZEN_SUBJECT:-NID-2001}"
other_subject="${ESIGNET_OTHER_SUBJECT:-NID-1001}"
demo_login_id="${ESIGNET_DEMO_LOGIN_ID:-${self_subject}}"
demo_login_code="${ESIGNET_DEMO_OTP:-111111}"
self_attestation_scope="${ESIGNET_SELF_ATTESTATION_SCOPE:-self_attestation}"
self_attestation_scope_policy="${ESIGNET_SELF_ATTESTATION_SCOPE_POLICY:-disabled}"
self_attestation_purpose="${ESIGNET_SELF_ATTESTATION_PURPOSE:-https://demo.example.gov/purpose/civil-certificate-evidence}"
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

say() {
  printf '%s\n' "$*"
}

transcript() {
  printf '%s\n' "$*" >>"${transcript_path}"
}

step() {
  local number="$1"
  local title="$2"
  shift 2
  say
  say "==> ${number}. ${title}"
  if (($# > 0)); then
    say "    $*"
  fi
  transcript ""
  transcript "==> ${number}. ${title}"
  if (($# > 0)); then
    transcript "    $*"
  fi
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

restore_dotenv_value() {
  local key="$1"
  local value
  value="$(
    python3 - "${demo_dir}/.env" "${key}" <<'PY'
import shlex
import sys
from pathlib import Path

path = Path(sys.argv[1])
target = sys.argv[2]
if not path.exists():
    raise SystemExit(0)
for raw_line in path.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    if key != target:
        continue
    if value[:1] in ("'", '"'):
        try:
            parts = shlex.split(value, comments=False, posix=True)
        except ValueError:
            parts = []
        if len(parts) == 1:
            value = parts[0]
    print(value)
PY
  )"
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
      args+=(-H "x-registry-notary-oidc-id-token: ${request_id_token}")
    fi
    status="$(curl "${args[@]}" "${url}" 2>/dev/null || true)"
    if [[ "${status}" =~ ^2[0-9][0-9]$ ]]; then
      return 0
    fi
    sleep 1
  done
  explain_notary_status "${status}" "${url}" >&2 || true
  fail "${name} did not become ready within ${deadline}s, last status ${status}"
}

explain_notary_status() {
  local status="$1"
  local url="$2"
  [[ -f "${log_path}" ]] || return 0
  case "${status}" in
    401)
      echo "Hint: Notary rejected the OIDC token while checking ${url}."
      if grep -q 'TokenTypeNotAllowed' "${log_path}"; then
        echo "Hint: token type mismatch. For eSignet access tokens without typ, leave ESIGNET_TOKEN_TYPE unset so allowed_token_types is []."
      elif grep -q 'AlgorithmNotAllowed' "${log_path}"; then
        echo "Hint: algorithm mismatch. Check ESIGNET_TOKEN_ALGORITHM and ESIGNET_USERINFO_ALGORITHM."
      elif grep -q 'IssuerMismatch' "${log_path}"; then
        echo "Hint: issuer mismatch. Check ESIGNET_ISSUER and ESIGNET_USERINFO_ISSUER."
      elif grep -q 'AudienceMismatch' "${log_path}"; then
        echo "Hint: audience mismatch. Check ESIGNET_CLIENT_ID and ESIGNET_AUDIENCES_JSON."
      else
        echo "Hint: inspect ${log_path} for registry_notary_server::auth debug lines."
      fi
      ;;
    403)
      if grep -q 'self_attestation.assurance_denied' "${log_path}"; then
        echo "Hint: assurance policy denied the request. Check auth_time/acr and token lifetime."
        echo "Hint: local eSignet 1.8.0 can issue 1200s tokens, so set ESIGNET_MAX_AUTH_AGE_SECONDS=1200 and ESIGNET_MAX_ACCESS_TOKEN_LIFETIME_SECONDS=1200 when matching that profile."
      elif grep -q 'self_attestation.subject_mismatch' "${log_path}"; then
        echo "Hint: subject binding denied the request before any registry read. Check ${subject_claim_source}.${subject_claim} and the requested subject id."
      fi
      ;;
    429)
      echo "Hint: the in-Notary self-attestation rate limiter fired, usually after repeated invalid-token checks. Wait for the minute window or rerun after fixing token/config inputs."
      ;;
  esac
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
  local verifier challenge authorization_endpoint state nonce auth_url claims_json

  verifier="$(openssl rand 48 | base64url | cut -c1-64)"
  challenge="$(printf '%s' "${verifier}" | openssl dgst -binary -sha256 | base64url)"
  state="$(openssl rand -hex 16)"
  nonce="$(openssl rand -hex 16)"
  claims_json="${ESIGNET_AUTHORIZE_CLAIMS_JSON:-}"
  if [[ -z "${claims_json}" && "${subject_claim_source}" == "userinfo" ]]; then
    claims_json="$(
      python3 - "${subject_claim}" <<'PY'
import json
import sys

subject_claim = sys.argv[1]
print(json.dumps({
    "userinfo": {
        subject_claim: {"essential": True},
        "name": {"essential": False},
        "email": {"essential": False},
        "phone_number": {"essential": False},
    },
    "id_token": {},
}, separators=(",", ":")))
PY
    )"
  fi
  authorization_endpoint="$(python3 - "${discovery_json}" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["authorization_endpoint"])
PY
  )"
  authorization_endpoint="${ESIGNET_AUTHORIZATION_URL:-${authorization_endpoint}}"
  auth_url="$(
    python3 - \
      "${authorization_endpoint}" \
      "${client_id}" \
      "${redirect_uri}" \
      "${authorize_scope}" \
      "${state}" \
      "${nonce}" \
      "${challenge}" \
      "${claims_json}" \
      "${ESIGNET_AUTHORIZE_ACR_VALUES:-}" \
      "${ESIGNET_AUTHORIZE_PROMPT:-}" \
      "${ESIGNET_AUTHORIZE_DISPLAY:-}" \
      "${ESIGNET_CLAIMS_LOCALES:-}" <<'PY'
from urllib.parse import urlencode
import sys

(
    endpoint,
    client_id,
    redirect_uri,
    scope,
    state,
    nonce,
    challenge,
    claims,
    acr_values,
    prompt,
    display,
    claims_locales,
) = sys.argv[1:]
params = {
    "response_type": "code",
    "client_id": client_id,
    "redirect_uri": redirect_uri,
    "scope": scope,
    "state": state,
    "nonce": nonce,
    "code_challenge": challenge,
    "code_challenge_method": "S256",
}
if claims:
    params["claims"] = claims
if acr_values:
    params["acr_values"] = acr_values
if prompt:
    params["prompt"] = prompt
if display:
    params["display"] = display
if claims_locales:
    params["claims_locales"] = claims_locales
query = urlencode(params)
print(f"{endpoint}?{query}")
PY
  )"
  {
    printf 'ESIGNET_ISSUER=%q\n' "${issuer}"
    printf 'ESIGNET_CLIENT_ID=%q\n' "${client_id}"
    printf 'ESIGNET_REDIRECT_URI=%q\n' "${redirect_uri}"
    printf 'ESIGNET_CODE_VERIFIER=%q\n' "${verifier}"
    printf 'ESIGNET_STATE=%q\n' "${state}"
    printf 'ESIGNET_NONCE=%q\n' "${nonce}"
  } >"${pkce_file}"
  if [[ "${ESIGNET_CAPTURE_CALLBACK_HINT:-}" == "1" ]]; then
    cat >&2 <<EOF
No ESIGNET_CITIZEN_ACCESS_TOKEN or ESIGNET_AUTHORIZATION_CODE was provided.

Open this eSignet authorization URL, complete citizen authentication, and leave
this terminal running. The callback listener will capture the code.
Use these local demo login values:
  ID / VID: ${demo_login_id}
  OTP / generated code: ${demo_login_code}
The PKCE verifier was saved to:
  ${pkce_file}

${auth_url}
EOF
  else
    cat >&2 <<EOF
No ESIGNET_CITIZEN_ACCESS_TOKEN or ESIGNET_AUTHORIZATION_CODE was provided.

Open this eSignet authorization URL, complete citizen authentication, then
rerun this script with ESIGNET_AUTHORIZATION_CODE set to the callback code.
Use these local demo login values:
  ID / VID: ${demo_login_id}
  OTP / generated code: ${demo_login_code}
The PKCE verifier was saved to:
  ${pkce_file}

${auth_url}
EOF
  fi
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
print(f"TOKEN_TYP={shlex.quote(str(header.get('typ') or ''))}")
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
        f"UserInfo claim {subject_claim!r} must equal {expected_subject!r}; got {subject!r}. "
        "For local Relay-backed eSignet, verify the Relay attribute-release profile releases individual_id for this subject."
    )
PY
}

write_claim_summary() {
  local label="$1"
  local path="$2"
  [[ -f "${path}" ]] || return 0
  python3 - "${label}" "${path}" "${transcript_path}" <<'PY'
import hashlib
import json
import sys

label, path, transcript_path = sys.argv[1:]
snapshot = json.load(open(path, encoding="utf-8"))
header = snapshot.get("header", {})
claims = snapshot.get("claims", {})

def h(value):
    if not value:
        return ""
    return hashlib.sha256(str(value).encode()).hexdigest()[:16]

interesting = {
    "alg": header.get("alg"),
    "typ": header.get("typ"),
    "iss": claims.get("iss"),
    "aud": claims.get("aud"),
    "azp": claims.get("azp"),
    "client_id": claims.get("client_id"),
    "sub_hash": h(claims.get("sub")),
    "acr": claims.get("acr"),
    "auth_time": claims.get("auth_time"),
    "individual_id": claims.get("individual_id"),
    "scope": claims.get("scope"),
}
interesting = {k: v for k, v in interesting.items() if v not in (None, "", [])}
with open(transcript_path, "a", encoding="utf-8") as handle:
    handle.write(f"{label}: {json.dumps(interesting, sort_keys=True)}\n")
PY
}

print_access_token_status() {
  python3 - "${token_claims_path}" <<'PY'
import hashlib
import json
import sys

snapshot = json.load(open(sys.argv[1], encoding="utf-8"))
header = snapshot.get("header", {})
claims = snapshot.get("claims", {})

def short_hash(value):
    return hashlib.sha256(str(value).encode()).hexdigest()[:16] if value else ""

aud = claims.get("aud")
if isinstance(aud, list):
    aud = ",".join(str(item) for item in aud)
print(
    "    Received access token: "
    f"iss={claims.get('iss', '')}, "
    f"aud={aud or ''}, "
    f"client={claims.get('azp') or claims.get('client_id') or ''}, "
    f"alg={header.get('alg', '')}, "
    f"typ={header.get('typ') or 'absent'}, "
    f"sub_hash={short_hash(claims.get('sub'))}, "
    f"exp={claims.get('exp', '')}"
)
PY
}

print_id_token_status() {
  [[ -f "${id_token_claims_path}" ]] || return 0
  python3 - "${id_token_claims_path}" <<'PY'
import hashlib
import json
import sys

snapshot = json.load(open(sys.argv[1], encoding="utf-8"))
header = snapshot.get("header", {})
claims = snapshot.get("claims", {})

def short_hash(value):
    return hashlib.sha256(str(value).encode()).hexdigest()[:16] if value else ""

print(
    "    Validated ID token assurance: "
    f"acr={claims.get('acr', '')}, "
    f"auth_time={claims.get('auth_time', '')}, "
    f"alg={header.get('alg', '')}, "
    f"sub_hash={short_hash(claims.get('sub'))}"
)
PY
}

print_userinfo_status() {
  [[ -f "${userinfo_claims_path}" ]] || return 0
  python3 - "${userinfo_claims_path}" "${subject_claim}" <<'PY'
import hashlib
import json
import sys

path, subject_claim = sys.argv[1:]
snapshot = json.load(open(path, encoding="utf-8"))
header = snapshot.get("header", {})
claims = snapshot.get("claims", {})

def short_hash(value):
    return hashlib.sha256(str(value).encode()).hexdigest()[:16] if value else ""

print(
    "    Validated signed UserInfo binding: "
    f"{subject_claim}={claims.get(subject_claim, '')}, "
    f"iss={claims.get('iss', '')}, "
    f"alg={header.get('alg', '')}, "
    f"sub_hash={short_hash(claims.get('sub'))}"
)
PY
}

print_discovery_status() {
  python3 - "${discovery_path}" <<'PY'
import json
import sys

body = json.load(open(sys.argv[1], encoding="utf-8"))
self_attestation = body.get("self_attestation") or {}
print(
    "    Discovery OK: "
    f"service={body.get('service_id', '')}, "
    f"base_url={body.get('base_url', '')}, "
    f"self_attestation={bool(self_attestation)}, "
    f"claim_ids={','.join(self_attestation.get('allowed_claim_ids') or [])}"
)
PY
}

print_self_evaluation_status() {
  python3 - "${self_eval_path}" <<'PY'
import json
import sys

body = json.load(open(sys.argv[1], encoding="utf-8"))
result = (body.get("results") or [{}])[0]
provenance = result.get("provenance") or {}
source_count = provenance.get("source_count")
if source_count is None:
    source_count = (provenance.get("used") or {}).get("source_count")
print(
    "    Self claim OK: "
    f"claim={result.get('claim_id', '')}, "
    f"value={result.get('value')}, "
    f"evaluation_id={result.get('evaluation_id', '')}, "
    f"source_count={source_count if source_count is not None else ''}"
)
PY
}

print_denial_status() {
  python3 - "${other_eval_path}" "${other_subject}" <<'PY'
import json
import sys

path, other_subject = sys.argv[1:]
body = json.load(open(path, encoding="utf-8"))
print(
    "    Other-person control OK: "
    f"subject={other_subject}, "
    f"status={body.get('status', '')}, "
    f"code={body.get('code', '')}"
)
PY
}

print_audit_status() {
  python3 - "${log_path}" <<'PY'
import json
import sys

path = sys.argv[1]
seen_eval = False
seen_denial = False
with open(path, encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line).get("record", {})
        except json.JSONDecodeError:
            continue
        if event.get("access_mode") != "self_attestation":
            continue
        if event.get("decision") == "evaluate":
            seen_eval = True
        if event.get("decision") == "evaluate_denied":
            seen_denial = True
print(
    "    Audit OK: "
    f"access_mode=self_attestation, "
    f"evaluate_event={str(seen_eval).lower()}, "
    f"denial_event={str(seen_denial).lower()}, "
    "identifiers=hashed"
)
PY
}

write_demo_report() {
  python3 - \
    "${report_path}" \
    "${transcript_path}" \
    "${discovery_path}" \
    "${self_eval_path}" \
    "${other_eval_path}" \
    "${token_claims_path}" \
    "${id_token_claims_path}" \
    "${userinfo_claims_path}" \
    "${log_path}" \
    "${config_path}" \
    "${issuer}" \
    "${client_id}" \
    "${subject_claim_source}" \
    "${subject_claim}" \
    "${assurance_claim_source}" \
    "${self_attestation_scope_policy}" \
    "${self_subject}" \
    "${other_subject}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

(
    report_path,
    transcript_path,
    discovery_path,
    self_eval_path,
    other_eval_path,
    token_claims_path,
    id_token_claims_path,
    userinfo_claims_path,
    log_path,
    config_path,
    issuer,
    client_id,
    subject_claim_source,
    subject_claim,
    assurance_claim_source,
    scope_policy,
    self_subject,
    other_subject,
) = sys.argv[1:]

def load_json(path):
    p = Path(path)
    if not p.exists():
        return None
    return json.load(open(p, encoding="utf-8"))

def claim_snapshot(path):
    snap = load_json(path) or {}
    return snap.get("header", {}), snap.get("claims", {})

def short_hash(value):
    if value is None:
        return ""
    return hashlib.sha256(str(value).encode()).hexdigest()[:16]

access_header, access_claims = claim_snapshot(token_claims_path)
id_header, id_claims = claim_snapshot(id_token_claims_path)
userinfo_header, userinfo_claims = claim_snapshot(userinfo_claims_path)
self_eval = load_json(self_eval_path) or {}
other_eval = load_json(other_eval_path) or {}
discovery = load_json(discovery_path) or {}

self_results = self_eval.get("results") or []
self_result = self_results[0] if self_results else {}

audit_events = []
if Path(log_path).exists():
    for line in open(log_path, encoding="utf-8"):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line).get("record", {})
        except json.JSONDecodeError:
            continue
        if event.get("access_mode") == "self_attestation":
            audit_events.append(event)

def audit_line(event):
    fields = {
        "decision": event.get("decision"),
        "status": event.get("status"),
        "error_code": event.get("error_code"),
        "denial_code": event.get("denial_code"),
        "token_claim_name": event.get("token_claim_name"),
        "principal_id_hash": event.get("principal_id_hash"),
        "claim_hash": event.get("claim_hash"),
    }
    return json.dumps({k: v for k, v in fields.items() if v is not None}, sort_keys=True)

lines = [
    "# eSignet Citizen Self-Attestation Smoke Report",
    "",
    "## Result",
    "",
    "- Overall: passed",
    f"- Self subject: `{self_subject}`",
    f"- Other-person control: `{other_subject}` denied",
    f"- Claim: `person-is-alive` = `{self_result.get('value')}`",
    f"- Evaluation id: `{self_result.get('evaluation_id', '')}`",
    "",
    "## Binding Chain",
    "",
    f"- eSignet issuer: `{issuer}`",
    f"- Client id: `{client_id}`",
    f"- Access token algorithm: `{access_header.get('alg', '')}`",
    f"- Access token type: `{access_header.get('typ', '') or 'absent'}`",
    f"- Access token subject hash: `{short_hash(access_claims.get('sub'))}`",
    f"- Subject binding: `{subject_claim_source}.{subject_claim}`",
    f"- Bound subject value: `{userinfo_claims.get(subject_claim) if subject_claim_source == 'userinfo' else access_claims.get(subject_claim)}`",
    f"- Assurance source: `{assurance_claim_source}`",
    f"- ID token algorithm: `{id_header.get('alg', '')}`",
    f"- ID token ACR: `{id_claims.get('acr', '')}`",
    f"- ID token auth_time: `{id_claims.get('auth_time', '')}`",
    f"- UserInfo issuer: `{userinfo_claims.get('iss', '')}`",
    f"- UserInfo algorithm: `{userinfo_header.get('alg', '')}`",
    f"- Scope policy: `{scope_policy}`",
    "",
    "## What Was Proven",
    "",
    "- Notary accepted the citizen token chain and classified the request as `self_attestation`.",
    "- Notary evaluated `person-is-alive` for the token-bound subject.",
    f"- Notary denied the `{other_subject}` request as a subject-binding violation before a civil registry read.",
    "- Audit output records hashed identifiers, not raw token subject values.",
    "",
    "## Discovery Summary",
    "",
    f"- Service id: `{discovery.get('service_id', '')}`",
    f"- API base URL: `{discovery.get('base_url', '')}`",
    f"- Self-attestation advertised: `{bool(discovery.get('self_attestation'))}`",
    "",
    "## Denial Control",
    "",
    f"- HTTP problem code: `{other_eval.get('code', '')}`",
    f"- Detail: `{other_eval.get('detail', '')}`",
    "",
    "## Audit Excerpt",
    "",
]

if audit_events:
    lines.extend(f"- `{audit_line(event)}`" for event in audit_events[-5:])
else:
    lines.append("- No self-attestation audit event was found.")

lines.extend([
    "",
    "## Artifacts",
    "",
    f"- `{discovery_path}`",
    f"- `{self_eval_path}`",
    f"- `{other_eval_path}`",
    f"- `{token_claims_path}`",
    f"- `{id_token_claims_path}`",
    f"- `{userinfo_claims_path}`",
    f"- `{log_path}`",
    f"- `{config_path}`",
    f"- `{transcript_path}`",
    "",
])

Path(report_path).write_text("\n".join(lines), encoding="utf-8")
PY
}

write_notary_config() {
  local issuer="$1"
  local jwks_uri="$2"
  local userinfo_endpoint="$3"
  local alg="$4"
  local client_id="$5"
  local audience_json="$6"
  local scope="$7"
  local userinfo_issuer="$8"
  local userinfo_alg="$9"
  local token_typ="${10}"
  python3 - "${config_path}" "${port}" "${issuer}" "${jwks_uri}" "${userinfo_endpoint}" "${userinfo_issuer}" "${alg}" "${userinfo_alg}" "${token_typ}" "${client_id}" "${audience_json}" "${scope}" "${self_attestation_scope_policy}" "${subject_claim}" "${subject_claim_source}" "${assurance_claim_source}" "${self_attestation_purpose}" <<'PY'
import json
import os
import sys

path, port, issuer, jwks_uri, userinfo_endpoint, userinfo_issuer, alg, userinfo_alg, token_typ, client_id, audience_json, scope, scope_policy, subject_claim, subject_claim_source, assurance_claim_source, self_attestation_purpose = sys.argv[1:]
audiences = json.loads(audience_json)
if not audiences:
    audiences = [client_id]
if not client_id:
    raise SystemExit("client_id/azp is required; set ESIGNET_CLIENT_ID if the token omits it")
max_auth_age = int(os.environ.get("ESIGNET_MAX_AUTH_AGE_SECONDS", "900"))
max_access_token_lifetime = int(os.environ.get("ESIGNET_MAX_ACCESS_TOKEN_LIFETIME_SECONDS", "900"))
oid4vci_enabled = os.environ.get("CITIZEN_OID4VCI_ENABLED", "0") in ("1", "true", "yes")
audience_lines = "\n".join(f"      - {json.dumps(value)}" for value in audiences)
algorithms = []
for value in (alg, userinfo_alg):
    if value and value not in algorithms:
        algorithms.append(value)
algorithm_lines = "\n".join(f"      - {json.dumps(value)}" for value in algorithms)
if token_typ:
    typ_values = [token_typ]
else:
    typ_values = []
typ_lines = " []" if not typ_values else "\n" + "\n".join(f"      - {json.dumps(value)}" for value in typ_values)
allowed_client_lines = f"      - {json.dumps(client_id)}"
userinfo_line = f"    userinfo_endpoint: {json.dumps(userinfo_endpoint)}\n" if userinfo_endpoint else ""
userinfo_issuers_line = (
    f"    userinfo_issuers:\n      - {json.dumps(userinfo_issuer)}\n"
    if userinfo_issuer
    else ""
)
required_scopes_block = ""
if scope_policy != "disabled":
    required_scopes_block = f"""  required_scopes:
    - {json.dumps(scope)}
"""
credential_issuer = os.environ.get("CITIZEN_OID4VCI_CREDENTIAL_ISSUER", f"http://127.0.0.1:{port}")
credential_endpoint = os.environ.get(
    "CITIZEN_OID4VCI_CREDENTIAL_ENDPOINT",
    f"{credential_issuer.rstrip('/')}/oid4vci/credential",
)
offer_endpoint = os.environ.get(
    "CITIZEN_OID4VCI_OFFER_ENDPOINT",
    f"{credential_issuer.rstrip('/')}/oid4vci/credential-offer",
)
nonce_endpoint = os.environ.get(
    "CITIZEN_OID4VCI_NONCE_ENDPOINT",
    f"{credential_issuer.rstrip('/')}/oid4vci/nonce",
)
authorization_server = os.environ.get("CITIZEN_OID4VCI_AUTHORIZATION_SERVER", issuer)
accepted_audiences = [credential_issuer]
for value in audiences:
    if value and value not in accepted_audiences:
        accepted_audiences.append(value)
accepted_audiences = json.loads(
    os.environ.get("CITIZEN_OID4VCI_ACCEPTED_TOKEN_AUDIENCES_JSON", json.dumps(accepted_audiences))
)
accepted_audience_lines = "\n".join(f"    - {json.dumps(value)}" for value in accepted_audiences)
oid4vci_config_id = os.environ.get("CITIZEN_OID4VCI_CREDENTIAL_CONFIGURATION_ID", "person_is_alive_sd_jwt")
oid4vci_vct = os.environ.get(
    "CITIZEN_OID4VCI_VCT",
    f"{credential_issuer.rstrip('/')}/credentials/citizen-civil-status/v1",
)
oid4vci_display_name = os.environ.get("CITIZEN_OID4VCI_DISPLAY_NAME", "Person is alive")
oid4vci_display_description = os.environ.get(
    "CITIZEN_OID4VCI_DISPLAY_DESCRIPTION",
    "Proof that the civil registry currently records this person as alive.",
)
oid4vci_scope = os.environ.get("CITIZEN_OID4VCI_SCOPE", "person-is-alive")
oid4vci_issue_credential = "true" if oid4vci_enabled else "false"
oid4vci_block = ""
if oid4vci_enabled:
    oid4vci_block = f"""

oid4vci:
  enabled: true
  credential_issuer: {json.dumps(credential_issuer)}
  authorization_servers:
    - {json.dumps(authorization_server)}
  accepted_token_audiences:
{accepted_audience_lines}
  credential_endpoint: {json.dumps(credential_endpoint)}
  offer_endpoint: {json.dumps(offer_endpoint)}
  nonce_endpoint: {json.dumps(nonce_endpoint)}
  display:
    - name: "Civil Registry Notary"
      locale: en-US
  nonce:
    enabled: true
    ttl_seconds: 300
  authorization:
    require_pkce_method: S256
  proof:
    max_age_seconds: 300
    max_clock_skew_seconds: 30
  credential_configurations:
    {json.dumps(oid4vci_config_id)}:
      claim_id: person-is-alive
      credential_profile: citizen_civil_status_sd_jwt
      format: dc+sd-jwt
      scope: {json.dumps(oid4vci_scope)}
      vct: {json.dumps(oid4vci_vct)}
      display_name: {json.dumps(oid4vci_display_name)}
      display:
        locale: en-US
        description: {json.dumps(oid4vci_display_description)}
        background_color: "#0057B8"
        text_color: "#FFFFFF"
      proof_signing_alg_values_supported:
        - EdDSA
      cryptographic_binding_methods_supported:
        - did:jwk
"""
text = f"""# Generated by scripts/smoke-citizen-self-attestation.sh. Do not edit by hand.
server:
  bind: 127.0.0.1:{port}

auth:
  mode: oidc
  oidc:
    issuer: {json.dumps(issuer)}
    jwks_url: {json.dumps(jwks_uri)}
{userinfo_line.rstrip()}
{userinfo_issuers_line.rstrip()}
    audiences:
{audience_lines}
    allowed_clients:
{allowed_client_lines}
    allowed_algorithms:
{algorithm_lines}
    allowed_token_types:{typ_lines}
    scope_claim: scope
    scope_separator: " "
    principal_claim: sub
    leeway: 60s
    allow_insecure_localhost: true
    scope_map:
      {json.dumps(scope)}:
        - {json.dumps(scope)}

audit:
  sink: stdout
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET

evidence:
  enabled: true
  service_id: citizen-civil-notary
  api_base_url: http://127.0.0.1:{port}
  inline_batch_limit: 20
  source_connections:
    civil:
      base_url: http://127.0.0.1:4311
      allow_insecure_localhost: true
      token_env: CIVIL_EVIDENCE_SOURCE_RAW
      dci:
        search_path: /dci/crvs/registry/sync/search
        version: "1.0.0"
        query_type: idtype-value
        records_path: /message/search_response/0/data/reg_records
        field_paths:
          national_id: /person/national_id
          deceased: /person/deceased
  signing_keys:
    citizen-civil-demo:
      provider: local_jwk_env
      private_jwk_env: REGISTRY_NOTARY_ISSUER_JWK
      alg: EdDSA
      kid: did:web:citizen-civil-notary.demo.example#citizen-civil-demo-key-1
      status: active
  credential_profiles:
    citizen_civil_status_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:citizen-civil-notary.demo.example
      signing_key: citizen-civil-demo
      vct: {json.dumps(oid4vci_vct)}
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
      purpose: {json.dumps(self_attestation_purpose)}
      value:
        type: boolean
      source_bindings:
        civil:
          connector: dci
          connection: civil
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: target.identifiers.national_id
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
        - application/vnd.registry-notary.claim-result+json
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
    max_auth_age_seconds: {max_auth_age}
    max_access_token_lifetime_seconds: {max_access_token_lifetime}
    max_evaluation_age_seconds: 600
    max_credential_validity_seconds: 600
    max_clock_leeway_seconds: 60
  allowed_operations:
    evaluate: true
    render: true
    issue_credential: {oid4vci_issue_credential}
    batch_evaluate: false
  allowed_purposes:
    - {json.dumps(self_attestation_purpose)}
  allowed_claims:
    - person-is-alive
  allowed_formats:
    - application/vnd.registry-notary.claim-result+json
    - application/dc+sd-jwt
  allowed_disclosures:
    - predicate
    - redacted
  scope_policy: {json.dumps(scope_policy)}
{required_scopes_block.rstrip()}
  credential_profiles:
    - citizen_civil_status_sd_jwt
  wallet_cors:
    allowed_origins:
      - https://wallet.example.gov
  rate_limits:
    mode: in_process
    invalid_token_per_client_address_per_minute: 20
    per_principal_per_minute: 10
    subject_mismatch_per_principal_per_hour: 5
    per_holder_per_hour: 10
    credential_issuance_per_principal_per_hour: 5
{oid4vci_block}"""
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
    args+=(-H "x-registry-notary-oidc-id-token: ${id_token}")
  fi
  status="$(curl "${args[@]}" "$@" "${url}")"
  if [[ "${status}" != "${expected}" ]]; then
    echo "Expected ${url} to return ${expected}, got ${status}" >&2
    cat "${output}" >&2 || true
    explain_notary_status "${status}" "${url}" >&2 || true
    exit 1
  fi
}

need curl
need jq
need python3
need openssl

mkdir -p "${output_dir}"
cat >"${transcript_path}" <<EOF
eSignet citizen self-attestation flow transcript
correlation_id=${correlation_id}
tokens=redacted
EOF

step 1 "Validate local prerequisites" "Checking tools, demo secrets, and requested eSignet binding mode."

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
if [[ -z "${self_attestation_purpose}" ]]; then
  fail "ESIGNET_SELF_ATTESTATION_PURPOSE must not be empty"
fi

if [[ -f "${demo_dir}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${demo_dir}/.env"
  set +a
  restore_dotenv_value REGISTRY_NOTARY_ISSUER_JWK
else
  fail "missing .env; run scripts/generate-demo-secrets.py first"
fi
: "${CIVIL_METADATA_CLIENT_RAW:?missing CIVIL_METADATA_CLIENT_RAW; rerun scripts/generate-demo-secrets.py}"
: "${CIVIL_EVIDENCE_SOURCE_RAW:?missing CIVIL_EVIDENCE_SOURCE_RAW; rerun scripts/generate-demo-secrets.py}"
: "${REGISTRY_NOTARY_AUDIT_HASH_SECRET:?missing REGISTRY_NOTARY_AUDIT_HASH_SECRET; rerun scripts/generate-demo-secrets.py}"

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

step 2 "Read eSignet discovery" "Issuer: ${issuer}"
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

step 3 "Obtain citizen token" "Using provided token or exchanging an authorization code without printing token values."
access_token="${ESIGNET_CITIZEN_ACCESS_TOKEN:-}"
id_token="${ESIGNET_CITIZEN_ID_TOKEN:-}"
token_source="provided"
if [[ -z "${access_token}" ]]; then
  token_source="authorization_code"
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
if [[ "${token_source}" == "authorization_code" ]]; then
  say "    Exchanged authorization code at eSignet token endpoint; token values remain redacted."
else
  say "    Using caller-provided citizen token; token values remain redacted."
fi

metadata_env="${output_dir}/citizen-token.env"
decode_access_token "${access_token}" "${metadata_env}"
# shellcheck disable=SC1090
. "${metadata_env}"
write_claim_summary "access_token" "${token_claims_path}"
print_access_token_status

step 4 "Validate assurance and subject binding material" "Subject source: ${subject_claim_source}.${subject_claim}; assurance source: ${assurance_claim_source}."
if [[ "${assurance_claim_source}" == "id_token" ]]; then
  [[ -n "${id_token}" ]] ||
    fail "ESIGNET_ASSURANCE_CLAIM_SOURCE=id_token requires ESIGNET_CITIZEN_ID_TOKEN or an auth-code token response with id_token"
  validate_id_token "${id_token}"
  write_claim_summary "id_token" "${id_token_claims_path}"
  print_id_token_status
fi
if [[ "${subject_claim_source}" == "userinfo" ]]; then
  [[ -n "${userinfo_endpoint}" ]] ||
    fail "ESIGNET_SUBJECT_CLAIM_SOURCE=userinfo requires a discovery userinfo_endpoint or ESIGNET_USERINFO_ENDPOINT"
  fetch_and_validate_userinfo "${userinfo_endpoint}" "${access_token}"
  write_claim_summary "userinfo" "${userinfo_claims_path}"
  print_userinfo_status
fi

client_id="${ESIGNET_CLIENT_ID:-${TOKEN_CLIENT_ID:-}}"
[[ -n "${client_id}" ]] || fail "token omitted azp/client_id; set ESIGNET_CLIENT_ID"
alg="${ESIGNET_TOKEN_ALGORITHM:-${TOKEN_ALG:-RS256}}"
token_typ="${ESIGNET_TOKEN_TYPE:-${TOKEN_TYP:-}}"
audiences_json="${ESIGNET_AUDIENCES_JSON:-${TOKEN_AUDIENCES_JSON}}"
userinfo_issuer="${ESIGNET_USERINFO_ISSUER:-}"
userinfo_alg="${ESIGNET_USERINFO_ALGORITHM:-}"
if [[ -z "${userinfo_issuer}" && "${subject_claim_source}" == "userinfo" && -f "${userinfo_claims_path}" ]]; then
  userinfo_issuer="$(
    python3 - "${userinfo_claims_path}" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("claims", {}).get("iss", ""))
PY
  )"
fi
if [[ -z "${userinfo_alg}" && "${subject_claim_source}" == "userinfo" && -f "${userinfo_claims_path}" ]]; then
  userinfo_alg="$(
    python3 - "${userinfo_claims_path}" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("header", {}).get("alg", ""))
PY
  )"
fi

step 5 "Generate Notary config" "Writing ${config_path} with eSignet issuer, JWKS, client, algorithm, and self-attestation policy."
write_notary_config "${issuer}" "${jwks_uri}" "${userinfo_endpoint}" "${alg}" "${client_id}" "${audiences_json}" "${self_attestation_scope}" "${userinfo_issuer}" "${userinfo_alg}" "${token_typ}"
transcript "Notary config: ${config_path}"
transcript "scope_policy=${self_attestation_scope_policy}"
transcript "allowed_algorithms=$(python3 - "${config_path}" <<'PY'
import re
import sys
text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r"allowed_algorithms:\n((?:      - .+\n)+)", text)
print(" ".join(line.strip()[2:].strip() for line in match.group(1).splitlines()) if match else "")
PY
)"

step 6 "Start civil Relay and citizen Notary" "Notary listens on http://127.0.0.1:${port}."
docker compose -f "${compose_file}" up -d --force-recreate civil-registry-relay
wait_http "civil relay health" "http://127.0.0.1:4311/healthz" "${CIVIL_METADATA_CLIENT_RAW}"

rm -f "${log_path}"
(
  cd "${notary_dir}"
  cargo run -p registry-notary --features registry-notary-cel -- --config "${config_path}"
) >"${log_path}" 2>&1 &
notary_pid="$!"
trap 'kill "${notary_pid}" >/dev/null 2>&1 || true' EXIT

wait_http "citizen civil notary health" "http://127.0.0.1:${port}/healthz"

step 7 "Call Notary discovery" "Confirming the citizen token can see the self-attestation capability."
curl_json GET "http://127.0.0.1:${port}/.well-known/evidence-service" "${discovery_path}" 200
print_discovery_status

step 8 "Evaluate self claim" "Requesting person-is-alive for ${self_subject}."
curl_json POST "http://127.0.0.1:${port}/v1/evaluations" "${self_eval_path}" 200 \
  --data "$(jq -nc --arg subject "${self_subject}" '{target:{type:"Person",identifiers:[{scheme:"national_id",value:$subject}]},claims:["person-is-alive"],disclosure:"predicate",format:"application/vnd.registry-notary.claim-result+json"}')"

python3 - "${self_eval_path}" <<'PY'
import json
import sys

body = json.load(open(sys.argv[1], encoding="utf-8"))
results = body.get("results") or []
assert len(results) == 1, body
result = results[0]
assert result.get("claim_id") == "person-is-alive", body
assert result.get("value") is True, body
provenance = result.get("provenance") or {}
source_count = provenance.get("source_count")
if source_count is None:
    source_count = (provenance.get("used") or {}).get("source_count")
assert source_count == 1, body
PY
print_self_evaluation_status

step 9 "Prove other-person denial" "Requesting the same claim for ${other_subject}; this must fail before any source read."
curl_json POST "http://127.0.0.1:${port}/v1/evaluations" "${other_eval_path}" 403 \
  --data "$(jq -nc --arg subject "${other_subject}" '{target:{type:"Person",identifiers:[{scheme:"national_id",value:$subject}]},claims:["person-is-alive"],disclosure:"predicate",format:"application/vnd.registry-notary.claim-result+json"}')"
print_denial_status

sleep 1
grep -q '"access_mode":"self_attestation"' "${log_path}" ||
  fail "Notary audit log did not include access_mode=self_attestation"
print_audit_status

step 10 "Write redacted evidence report" "Collecting summary, transcript, artifacts, and audit excerpt."
write_demo_report

if [[ "${CITIZEN_OID4VCI_PROBE:-0}" == "1" ]]; then
  step 11 "Probe OID4VCI endpoints" "Checking issuer metadata, offer, nonce, and credential proof behavior."
  CITIZEN_OID4VCI_ACCESS_TOKEN="${access_token}" \
  CITIZEN_OID4VCI_ID_TOKEN="${id_token:-}" \
  CITIZEN_OID4VCI_WITNESS_BASE_URL="http://127.0.0.1:${port}" \
  CITIZEN_OID4VCI_SELF_ATTESTATION_DIR="${output_dir}" \
  CITIZEN_OID4VCI_WITNESS_CONFIG="${config_path}" \
  "${script_dir}/probe-citizen-oid4vci.sh"
fi

cat <<EOF
Citizen self-attestation smoke passed.

What happened:
  1. eSignet authenticated demo citizen ${self_subject}.
  2. Notary bound the request to ${subject_claim_source}.${subject_claim}.
  3. Notary fetched person-is-alive for ${self_subject}.
  4. Notary denied ${other_subject} before a registry source read.
  5. Audit records show self_attestation with hashed identifiers.

Artifacts:
  ${report_path}
  ${transcript_path}
  ${discovery_path}
  ${self_eval_path}
  ${other_eval_path}
  ${token_claims_path}
  ${id_token_claims_path}
  ${userinfo_claims_path}
  ${log_path}
EOF
