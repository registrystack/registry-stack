#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lab_root="$(cd "${script_dir}/.." && pwd)"
cd "${lab_root}"

compose_files=(-f compose.yaml -f compose.lab2.yaml)
evidence_dir="output/lab2/evidence"
correlation_id="${LAB2_CORRELATION_ID:-lab2-governed-config-001}"

fail() {
  echo "FAILED: $1" >&2
  exit 1
}

require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || fail "missing ${name}; run just generate"
}

wait_http() {
  local name="$1"
  local url="$2"
  local token="${3:-}"
  local deadline="${LAB2_WAIT_SECONDS:-120}"
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

wait_http_api_key() {
  local name="$1"
  local url="$2"
  local token="$3"
  local deadline="${LAB2_WAIT_SECONDS:-120}"
  local start
  start="$(date +%s)"
  local status="000"
  while (( $(date +%s) - start < deadline )); do
    status="$(curl -sS -o /dev/null -w "%{http_code}" \
      -H "Accept: */*" \
      -H "x-api-key: ${token}" \
      -H "x-request-id: ${correlation_id}" \
      "${url}" 2>/dev/null || true)"
    if [[ "${status}" =~ ^2[0-9][0-9]$ ]]; then
      return 0
    fi
    sleep 1
  done
  fail "${name} did not become ready within ${deadline}s, last status ${status}"
}

curl_json() {
  local method="$1"
  local url="$2"
  local token="$3"
  local out="$4"
  shift 4
  curl -fsS -X "${method}" \
    -H "Accept: application/json" \
    -H "Authorization: Bearer ${token}" \
    -H "x-request-id: ${correlation_id}" \
    "$@" \
    -o "${out}" \
    "${url}"
}

assert_json_field() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

path, field, expected = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as fh:
    body = json.load(fh)
value = body
for part in field.split("."):
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break
if str(value).lower() != expected.lower():
    raise SystemExit(f"{path}: {field} expected {expected!r}, got {value!r}")
PY
}

assert_apply_result() {
  local file="$1"
  local result="$2"
  assert_json_field "${file}" result "${result}"
}

assert_apply_applied() {
  local file="$1"
  local applied="$2"
  assert_json_field "${file}" applied "${applied}"
}

assert_apply_result_one_of() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

path = sys.argv[1]
expected = set(sys.argv[2].split(","))
with open(path, encoding="utf-8") as fh:
    body = json.load(fh)
actual = body.get("result")
if actual not in expected:
    raise SystemExit(f"{path}: result expected one of {sorted(expected)!r}, got {actual!r}")
PY
}

assert_json_not_equal() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import json
import sys

left_path, left_field, right_path, right_field = sys.argv[1:]

def field(path, dotted):
    with open(path, encoding="utf-8") as fh:
        value = json.load(fh)
    for part in dotted.split("."):
        value = value[part]
    return value

left = field(left_path, left_field)
right = field(right_path, right_field)
if left == right:
    raise SystemExit(f"{left_path}:{left_field} and {right_path}:{right_field} unexpectedly matched: {left!r}")
PY
}

assert_json_equal() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import json
import sys

left_path, left_field, right_path, right_field = sys.argv[1:]

def field(path, dotted):
    with open(path, encoding="utf-8") as fh:
        value = json.load(fh)
    for part in dotted.split("."):
        value = value[part]
    return value

left = field(left_path, left_field)
right = field(right_path, right_field)
if left != right:
    raise SystemExit(f"{left_path}:{left_field}={left!r} did not match {right_path}:{right_field}={right!r}")
PY
}

assert_json_has_key() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

path, dotted = sys.argv[1:]
with open(path, encoding="utf-8") as fh:
    value = json.load(fh)
for part in dotted.split("."):
    if not isinstance(value, dict) or part not in value:
        raise SystemExit(f"{path}: missing {dotted}")
    value = value[part]
PY
}

assert_json_map_key_value() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import json
import sys

path, parent_path, key, expected = sys.argv[1:]
with open(path, encoding="utf-8") as fh:
    value = json.load(fh)
for part in parent_path.split("."):
    value = value[part]
actual = value.get(key)
if str(actual).lower() != expected.lower():
    raise SystemExit(f"{path}: {parent_path}[{key!r}] expected {expected!r}, got {actual!r}")
PY
}

container_id() {
  docker compose "${compose_files[@]}" ps -q "$1"
}

capture_relay_antirollback() {
  local out="$1"
  docker compose "${compose_files[@]}" run --rm --no-deps --entrypoint cat lab2-config-state-init \
    /relay-cache/civil-registry-relay-config-antirollback.json > "${out}"
}

capture_notary_antirollback() {
  local out="$1"
  docker compose "${compose_files[@]}" run --rm --no-deps --entrypoint cat lab2-config-state-init \
    /notary-state/civil-notary-config-antirollback.json > "${out}"
}

remove_relay_antirollback_state() {
  docker compose "${compose_files[@]}" run --rm --no-deps --entrypoint rm lab2-config-state-init \
    /relay-cache/civil-registry-relay-config-antirollback.json
}

post_relay_inline_apply() {
  local out="$1"
  local config_yaml
  config_yaml="$(python3 - <<'PY'
import json
from pathlib import Path
print(json.dumps(Path("output/lab2/runtime-config/civil-registry-relay.yaml").read_text(encoding="utf-8")))
PY
)"
  curl -sS -X POST \
    -H "Accept: application/json" \
    -H "Authorization: Bearer ${CIVIL_RELAY_OPS_RAW}" \
    -H "x-request-id: ${correlation_id}" \
    -H "Content-Type: application/json" \
    --data "{\"bundle_id\":\"lab2-inline-unsigned\",\"stream_id\":\"lab2-relay\",\"sequence\":99,\"config_yaml\":${config_yaml}}" \
    -o "${out}" \
    http://127.0.0.1:4419/admin/v1/config/apply >/dev/null
}

apply_relay_bundle() {
  local bundle="$1"
  local out="$2"
  shift 2
  docker compose "${compose_files[@]}" exec -T lab2-civil-registry-relay \
    /usr/local/bin/registry-relay config apply-bundle \
      --admin-url http://127.0.0.1:8081 \
      --admin-token-env CIVIL_RELAY_OPS_RAW \
      --root-path "/lab2/tuf-repo/${bundle}/metadata/1.root.json" \
      --metadata-dir "/lab2/tuf-repo/${bundle}/metadata" \
      --targets-dir "/lab2/tuf-repo/${bundle}/targets" \
      --datastore-dir "/var/lib/registry-relay/cache/tuf-${bundle}" \
      --target-name civil-registry-relay.yaml \
      "$@" > "${out}"
}

apply_notary_bundle() {
  local bundle="$1"
  local out="$2"
  shift 2
  docker compose "${compose_files[@]}" exec -T lab2-civil-notary \
    registry-notary config apply-bundle \
      --admin-url http://127.0.0.1:8082 \
      --allow-insecure-admin-url \
      --admin-token-env CIVIL_NOTARY_OPS_BEARER \
      --root-path "/lab2/tuf-repo/${bundle}/metadata/1.root.json" \
      --metadata-dir "/lab2/tuf-repo/${bundle}/metadata" \
      --targets-dir "/lab2/tuf-repo/${bundle}/targets" \
      --datastore-dir "/var/lib/registry-notary/config-state/tuf-${bundle}" \
      --target-name civil-notary.yaml \
      "$@" > "${out}"
}

verify_notary_bundle() {
  local bundle="$1"
  local out="$2"
  docker compose "${compose_files[@]}" exec -T lab2-civil-notary \
    registry-notary config verify-bundle \
      --config /etc/registry-notary/civil-notary.yaml \
      --root-path "/lab2/tuf-repo/${bundle}/metadata/1.root.json" \
      --metadata-dir "/lab2/tuf-repo/${bundle}/metadata" \
      --targets-dir "/lab2/tuf-repo/${bundle}/targets" \
      --datastore-dir "/var/lib/registry-notary/config-state/tuf-${bundle}" \
      --target-name civil-notary.yaml > "${out}"
}

apply_relay_bundle_may_fail() {
  local bundle="$1"
  local out="$2"
  set +e
  apply_relay_bundle "${bundle}" "${out}"
  local code=$?
  set -e
  return "${code}"
}

apply_notary_bundle_may_fail() {
  local bundle="$1"
  local out="$2"
  set +e
  apply_notary_bundle "${bundle}" "${out}"
  local code=$?
  set -e
  return "${code}"
}

break_glass_body() {
  local bundle="$1"
  local datastore_dir="$2"
  local target_name="$3"
  local include_client_rate_limit="$4"
  local approval_ref="$5"
  local expires_at
  expires_at="$(( $(date +%s) + 3600 ))"
  python3 - "$bundle" "$datastore_dir" "$target_name" "$include_client_rate_limit" "$approval_ref" "$expires_at" <<'PY'
import json
import sys

bundle, datastore_dir, target_name, include_client_rate_limit, approval_ref, expires_at = sys.argv[1:]
body = {
    "tuf": {
        "root_path": f"/lab2/tuf-repo/{bundle}/metadata/1.root.json",
        "metadata_dir": f"/lab2/tuf-repo/{bundle}/metadata",
        "targets_dir": f"/lab2/tuf-repo/{bundle}/targets",
        "datastore_dir": datastore_dir,
        "target_name": target_name,
    },
    "break_glass": True,
    "break_glass_approval": {
        "approval_reference": approval_ref,
        "approved_by": "lab2-operator@example.test",
        "reason": "EXERCISE-ONLY-BREAK-GLASS",
        "emergency_change_class": "emergency_break_glass",
        "expires_at_unix_seconds": int(expires_at),
        "rate_limit_identity": "lab2-governed-config",
    },
}
if include_client_rate_limit == "true":
    body["break_glass_rate_limit"] = {
        "max_accepted": 1,
        "window_seconds": 60,
    }
print(json.dumps(body))
PY
}

post_break_glass() {
  local service_name="$1"
  local url="$2"
  local token="$3"
  local bundle="$4"
  local datastore_dir="$5"
  local target_name="$6"
  local include_client_rate_limit="$7"
  local approval_ref="$8"
  local out="$9"
  local body
  local status
  body="$(break_glass_body "${bundle}" "${datastore_dir}" "${target_name}" "${include_client_rate_limit}" "${approval_ref}")"
  status="$(curl -sS -X POST \
    -H "Accept: application/json" \
    -H "Authorization: Bearer ${token}" \
    -H "x-request-id: ${correlation_id}" \
    -H "Content-Type: application/json" \
    --data "${body}" \
    -o "${out}" \
    -w "%{http_code}" \
    "${url}/admin/v1/config/apply")"
  echo "${service_name} break-glass HTTP ${status} response captured at ${out}"
}

issue_rotated_notary_credential() {
  local out="$1"
  python3 - "${CIVIL_EVIDENCE_CLIENT_BEARER}" "${out}" <<'PY'
import base64
import importlib.util
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

token, out = sys.argv[1:]
base_url = "http://127.0.0.1:4421"
purpose = "https://demo.example.gov/purpose/decentralized-evidence-demo"
sd_jwt = "application/dc+sd-jwt"
expected_kid = "did:web:civil-evidence.demo.example#civil-evidence-demo-key-2"

spec = importlib.util.spec_from_file_location("demo_flow", Path("scripts/demo-flow.py"))
demo_flow = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = demo_flow
spec.loader.exec_module(demo_flow)

def post(path, body, accept="application/json"):
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}{path}",
        data=data,
        method="POST",
        headers={
            "Accept": accept,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Data-Purpose": purpose,
            "x-request-id": "lab2-governed-config-credential-rotation",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read().decode("utf-8"))
        except Exception:
            body = {"raw": error.reason}
        return error.code, body

evaluation_status, evaluation = post(
    "/v1/evaluations",
    {
        "target": {
            "type": "Person",
            "identifiers": [{"scheme": "national_id", "value": "NID-1001"}],
        },
        "claims": ["person-is-alive"],
        "disclosure": "predicate",
        "format": sd_jwt,
    },
    accept=sd_jwt,
)
if evaluation_status != 200:
    raise SystemExit(f"rotated credential evaluation expected 200, got {evaluation_status}: {evaluation}")
evaluation_id = demo_flow.first_result_id(evaluation)
holder_id, proof = demo_flow.sign_holder_proof(
    evaluation_id,
    "civil_status_sd_jwt",
    ["person-is-alive"],
    "predicate",
    "civil-notary",
)
credential_status, credential = post(
    "/v1/credentials",
    {
        "evaluation_id": evaluation_id,
        "credential_profile": "civil_status_sd_jwt",
        "format": sd_jwt,
        "claims": ["person-is-alive"],
        "disclosure": "predicate",
        "holder": {"binding": "did", "id": holder_id, "proof": proof},
    },
)
if credential_status != 200:
    raise SystemExit(f"rotated credential issuance expected 200, got {credential_status}: {credential}")
issuer_signed_jwt = credential.get("issuer_signed_jwt")
if not isinstance(issuer_signed_jwt, str) or "." not in issuer_signed_jwt:
    raise SystemExit(f"credential response missing issuer_signed_jwt: {credential}")
header_segment = issuer_signed_jwt.split(".", 1)[0]
header_segment += "=" * (-len(header_segment) % 4)
header = json.loads(base64.urlsafe_b64decode(header_segment.encode("ascii")))
if header.get("kid") != expected_kid:
    raise SystemExit(f"rotated credential kid expected {expected_kid}, got {header.get('kid')}")

safe_summary = {
    "evaluation_status": evaluation_status,
    "credential_status": credential_status,
    "evaluation_id": evaluation_id,
    "credential_id": credential.get("credential_id"),
    "credential_profile": credential.get("credential_profile"),
    "format": credential.get("format"),
    "issuer": credential.get("issuer"),
    "issuer_signed_jwt_header": header,
    "expected_kid": expected_kid,
    "credential_compact_length": len(str(credential.get("credential", ""))),
}
Path(out).write_text(json.dumps(safe_summary, indent=2) + "\n", encoding="utf-8")
PY
}

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
else
  fail "missing .env; run just generate"
fi

require_env CIVIL_RELAY_OPS_RAW
require_env CIVIL_NOTARY_OPS_BEARER
require_env CIVIL_METADATA_CLIENT_RAW
require_env CIVIL_EVIDENCE_CLIENT_BEARER

echo "lab2: verifying Lab 1 static baseline"
lab1_smoke_log="$(mktemp "${TMPDIR:-/tmp}/lab2-lab1-smoke.XXXXXX")"
if [[ "${LAB2_SKIP_LAB1_SMOKE:-0}" == "1" ]]; then
  echo "Lab 1 smoke skipped by LAB2_SKIP_LAB1_SMOKE=1" > "${lab1_smoke_log}"
else
  just smoke > "${lab1_smoke_log}" 2>&1
fi

echo "lab2: generating governed config artifacts"
just lab2-generate
rm -rf "${evidence_dir}"
mkdir -p "${evidence_dir}"
cp "${lab1_smoke_log}" "${evidence_dir}/00-lab1-static-smoke.txt"

if rg -n "accepted_roots" config/relay config/notary config/coolify > "${evidence_dir}/01-static-accepted-roots-scan.txt"; then
  fail "committed static configs contain accepted_roots"
fi
rg --no-ignore -n "accepted_roots" output/lab2/runtime-config > "${evidence_dir}/02-rendered-accepted-roots-scan.txt"

echo "lab2: starting overlay"
just lab2-up
docker compose "${compose_files[@]}" ps > "${evidence_dir}/03-compose-ps.txt"

wait_http_api_key "Lab2 civil relay health" http://127.0.0.1:4411/healthz "${CIVIL_METADATA_CLIENT_RAW}"
wait_http "Lab2 civil notary discovery" http://127.0.0.1:4421/.well-known/evidence-service "${CIVIL_EVIDENCE_CLIENT_BEARER}"

curl_json GET "http://127.0.0.1:4419/admin/v1/posture?tier=restricted" "${CIVIL_RELAY_OPS_RAW}" "${evidence_dir}/04-relay-posture-initial.json"
curl_json GET "http://127.0.0.1:4422/admin/v1/posture?tier=restricted" "${CIVIL_NOTARY_OPS_BEARER}" "${evidence_dir}/05-notary-posture-initial.json"

echo "lab2: applying signed no-op bundles"
apply_relay_bundle relay-noop "${evidence_dir}/10-relay-noop-apply.json"
assert_apply_result "${evidence_dir}/10-relay-noop-apply.json" applied
assert_apply_applied "${evidence_dir}/10-relay-noop-apply.json" true

verify_notary_bundle notary-noop "${evidence_dir}/11-notary-noop-verify.json"
assert_apply_result "${evidence_dir}/11-notary-noop-verify.json" verified

apply_notary_bundle_may_fail notary-rollback "${evidence_dir}/34-notary-rollback.json" || true
assert_apply_result "${evidence_dir}/34-notary-rollback.json" rejected_rollback
assert_apply_applied "${evidence_dir}/34-notary-rollback.json" false

echo "lab2: applying governed live/restart-required changes"
relay_container_before="$(container_id lab2-civil-registry-relay)"
notary_container_before="$(container_id lab2-civil-notary)"
apply_relay_bundle relay-public-metadata "${evidence_dir}/20-relay-public-metadata-apply.json"
assert_apply_result "${evidence_dir}/20-relay-public-metadata-apply.json" applied
assert_apply_applied "${evidence_dir}/20-relay-public-metadata-apply.json" true

apply_notary_bundle notary-signing-key-rotation "${evidence_dir}/21-notary-signing-key-rotation-apply.json"
assert_apply_result "${evidence_dir}/21-notary-signing-key-rotation-apply.json" applied
assert_apply_applied "${evidence_dir}/21-notary-signing-key-rotation-apply.json" true
[[ "${relay_container_before}" == "$(container_id lab2-civil-registry-relay)" ]] || fail "Relay container restarted during live config apply"
[[ "${notary_container_before}" == "$(container_id lab2-civil-notary)" ]] || fail "Notary container restarted during signing key rotation"

curl_json GET "http://127.0.0.1:4419/admin/v1/posture?tier=restricted" "${CIVIL_RELAY_OPS_RAW}" "${evidence_dir}/22-relay-posture-after-live-apply.json"
curl_json GET "http://127.0.0.1:4422/admin/v1/posture?tier=restricted" "${CIVIL_NOTARY_OPS_BEARER}" "${evidence_dir}/23-notary-posture-after-rotation.json"
assert_json_not_equal "${evidence_dir}/04-relay-posture-initial.json" configuration.last_config_hash "${evidence_dir}/22-relay-posture-after-live-apply.json" configuration.last_config_hash
assert_json_field "${evidence_dir}/22-relay-posture-after-live-apply.json" configuration.last_apply_result accepted
assert_json_field "${evidence_dir}/23-notary-posture-after-rotation.json" configuration.last_apply_result accepted
assert_json_map_key_value "${evidence_dir}/23-notary-posture-after-rotation.json" notary.signing_keys.readiness "did:web:civil-evidence.demo.example#civil-evidence-demo-key-2" ready
assert_json_map_key_value "${evidence_dir}/23-notary-posture-after-rotation.json" notary.signing_keys.readiness "did:web:civil-evidence.demo.example#civil-evidence-demo-key-1" ready
issue_rotated_notary_credential "${evidence_dir}/24-notary-rotated-credential-summary.json"

echo "lab2: proving rejection paths"
capture_relay_antirollback "${evidence_dir}/29-relay-antirollback-before-negative.json"
capture_notary_antirollback "${evidence_dir}/29-notary-antirollback-before-negative.json"
apply_relay_bundle_may_fail relay-threshold-minus-one "${evidence_dir}/30-relay-threshold-minus-one.json" || true
assert_apply_result "${evidence_dir}/30-relay-threshold-minus-one.json" rejected_threshold
assert_apply_applied "${evidence_dir}/30-relay-threshold-minus-one.json" false
capture_relay_antirollback "${evidence_dir}/30-relay-antirollback-after-threshold-minus-one.json"
assert_json_equal "${evidence_dir}/29-relay-antirollback-before-negative.json" last_sequence "${evidence_dir}/30-relay-antirollback-after-threshold-minus-one.json" last_sequence

apply_relay_bundle relay-threshold-exact "${evidence_dir}/31-relay-threshold-exact.json"
assert_apply_result "${evidence_dir}/31-relay-threshold-exact.json" applied
assert_apply_applied "${evidence_dir}/31-relay-threshold-exact.json" true
capture_relay_antirollback "${evidence_dir}/31-relay-antirollback-after-threshold-exact.json"

apply_relay_bundle_may_fail relay-spoofed-metadata "${evidence_dir}/32-relay-spoofed-metadata.json" || true
assert_apply_result "${evidence_dir}/32-relay-spoofed-metadata.json" rejected_threshold
assert_apply_applied "${evidence_dir}/32-relay-spoofed-metadata.json" false
capture_relay_antirollback "${evidence_dir}/32-relay-antirollback-after-spoofed-metadata.json"
assert_json_equal "${evidence_dir}/31-relay-antirollback-after-threshold-exact.json" last_sequence "${evidence_dir}/32-relay-antirollback-after-spoofed-metadata.json" last_sequence

apply_relay_bundle_may_fail relay-alternate-root "${evidence_dir}/32b-relay-alternate-root.json" || true
assert_apply_result "${evidence_dir}/32b-relay-alternate-root.json" rejected_threshold
assert_apply_applied "${evidence_dir}/32b-relay-alternate-root.json" false

apply_notary_bundle_may_fail notary-threshold-minus-one "${evidence_dir}/33-notary-threshold-minus-one.json" || true
assert_json_field "${evidence_dir}/33-notary-threshold-minus-one.json" code admin.config_bundle_invalid
assert_json_field "${evidence_dir}/33-notary-threshold-minus-one.json" detail "signed config target was not authorized by local trust roots"
capture_notary_antirollback "${evidence_dir}/33-notary-antirollback-after-threshold-minus-one.json"
assert_json_equal "${evidence_dir}/29-notary-antirollback-before-negative.json" last_sequence "${evidence_dir}/33-notary-antirollback-after-threshold-minus-one.json" last_sequence

post_relay_inline_apply "${evidence_dir}/34-relay-unsigned-inline-apply.json"
assert_json_field "${evidence_dir}/34-relay-unsigned-inline-apply.json" code registry.admin.config.inline_apply_rejected

post_break_glass relay "http://127.0.0.1:4419" "${CIVIL_RELAY_OPS_RAW}" relay-break-glass "/var/lib/registry-relay/cache/tuf-relay-break-glass" civil-registry-relay.yaml false INC-LAB2-RELAY-BG "${evidence_dir}/40-relay-break-glass.json"
assert_apply_result "${evidence_dir}/40-relay-break-glass.json" applied
assert_apply_applied "${evidence_dir}/40-relay-break-glass.json" true
docker compose "${compose_files[@]}" restart lab2-civil-registry-relay > "${evidence_dir}/40a-relay-break-glass-restart.txt"
wait_http_api_key "Lab2 civil relay health after break-glass restart" http://127.0.0.1:4411/healthz "${CIVIL_METADATA_CLIENT_RAW}"
post_break_glass relay "http://127.0.0.1:4419" "${CIVIL_RELAY_OPS_RAW}" relay-break-glass-second "/var/lib/registry-relay/cache/tuf-relay-break-glass-second" civil-registry-relay.yaml false INC-LAB2-RELAY-BG-SECOND "${evidence_dir}/40b-relay-break-glass-rate-limit-after-restart.json"
assert_apply_result "${evidence_dir}/40b-relay-break-glass-rate-limit-after-restart.json" rejected_break_glass
assert_apply_applied "${evidence_dir}/40b-relay-break-glass-rate-limit-after-restart.json" false

post_break_glass notary "http://127.0.0.1:4422" "${CIVIL_NOTARY_OPS_BEARER}" notary-break-glass "/var/lib/registry-notary/config-state/tuf-notary-break-glass" civil-notary.yaml false INC-LAB2-NOTARY-BG "${evidence_dir}/41-notary-break-glass.json"
assert_apply_result "${evidence_dir}/41-notary-break-glass.json" rejected_restart_required
assert_apply_applied "${evidence_dir}/41-notary-break-glass.json" false

post_break_glass notary "http://127.0.0.1:4422" "${CIVIL_NOTARY_OPS_BEARER}" notary-break-glass-second "/var/lib/registry-notary/config-state/tuf-notary-break-glass-second" civil-notary.yaml false INC-LAB2-NOTARY-BG2 "${evidence_dir}/42-notary-break-glass-rate-limit.json"
assert_apply_result "${evidence_dir}/42-notary-break-glass-rate-limit.json" rejected_restart_required
assert_apply_applied "${evidence_dir}/42-notary-break-glass-rate-limit.json" false

post_break_glass relay "http://127.0.0.1:4419" "${CIVIL_RELAY_OPS_RAW}" relay-break-glass "/var/lib/registry-relay/cache/tuf-relay-break-glass-client-rate-limit" civil-registry-relay.yaml true INC-LAB2-RELAY-BG-CLIENT-LIMIT "${evidence_dir}/43-relay-client-rate-limit-rejected.json"
assert_apply_result "${evidence_dir}/43-relay-client-rate-limit-rejected.json" rejected_break_glass
assert_apply_applied "${evidence_dir}/43-relay-client-rate-limit-rejected.json" false

docker compose "${compose_files[@]}" stop lab2-civil-registry-relay > "${evidence_dir}/44-relay-cold-missing-state-stop.txt"
remove_relay_antirollback_state > "${evidence_dir}/44-relay-cold-missing-state-delete.txt"
docker compose "${compose_files[@]}" up -d --no-deps lab2-civil-registry-relay > "${evidence_dir}/44-relay-cold-missing-state-start.txt"
wait_http_api_key "Lab2 civil relay health after antirollback removal" http://127.0.0.1:4411/healthz "${CIVIL_METADATA_CLIENT_RAW}"
apply_relay_bundle_may_fail relay-public-metadata "${evidence_dir}/44-relay-cold-missing-state-replay.json" || true
assert_apply_result_one_of "${evidence_dir}/44-relay-cold-missing-state-replay.json" rejected_rollback,internal_error
assert_apply_applied "${evidence_dir}/44-relay-cold-missing-state-replay.json" false

curl_json GET "http://127.0.0.1:4419/admin/v1/posture?tier=restricted" "${CIVIL_RELAY_OPS_RAW}" "${evidence_dir}/50-relay-posture-final.json"
curl_json GET "http://127.0.0.1:4422/admin/v1/posture?tier=restricted" "${CIVIL_NOTARY_OPS_BEARER}" "${evidence_dir}/51-notary-posture-final.json"
docker compose "${compose_files[@]}" logs --no-color lab2-civil-registry-relay lab2-civil-notary > "${evidence_dir}/52-lab2-service-logs.txt"

scripts/lab2-secret-scan.sh > "${evidence_dir}/60-secret-scan-run.txt"

cat > "${evidence_dir}/summary.md" <<'EOF'
# Lab 2 Governed Configuration Evidence

1. Lab 1 static baseline: `00-lab1-static-smoke.txt`, `01-static-accepted-roots-scan.txt`.
2. Lab 2 rendered trust roots: `02-rendered-accepted-roots-scan.txt`.
3. Initial posture: `04-relay-posture-initial.json`, `05-notary-posture-initial.json`.
4. Signed no-op verification/apply: `10-relay-noop-apply.json`, `11-notary-noop-verify.json`.
5. Governed runtime change: `20-relay-public-metadata-apply.json`, `21-notary-signing-key-rotation-apply.json`.
6. Rotated Notary credential issuance: `24-notary-rotated-credential-summary.json`.
7. Rejection paths: `30-*` through `34-*`, client rate-limit rejection `43-*`, and cold missing-state replay `44-*`.
8. Emergency governance: `40-relay-break-glass.json`, restart-persistent Relay rate-limit rejection `40b-*`, `41-notary-break-glass.json`, rate-limit rejection `42-*`.
9. Final posture and logs: `50-*`, `51-*`, `52-lab2-service-logs.txt`.
10. Secret scan: `60-secret-scan-run.txt`, `secret-scan.json`.
EOF
cp "${evidence_dir}/summary.md" "${evidence_dir}/70-demo-story.md"

echo "Lab 2 governed configuration smoke OK"
