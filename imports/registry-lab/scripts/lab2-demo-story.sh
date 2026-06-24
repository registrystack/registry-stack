#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lab_root="$(cd "${script_dir}/.." && pwd)"
cd "${lab_root}"

compose_files=(-f compose.yaml -f compose.lab2.yaml)
evidence_dir="output/lab2/evidence/demo"
story_file="${evidence_dir}/story.md"
correlation_id="${LAB2_CORRELATION_ID:-lab2-governed-config-demo}"
pause_enabled="${LAB2_DEMO_PAUSE:-0}"

fail() {
  echo "FAILED: $1" >&2
  exit 1
}

require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || fail "missing ${name}; run just generate"
}

pause() {
  if [[ "${pause_enabled}" == "1" ]]; then
    read -r -p "Press return to continue..." _
  fi
}

narrate() {
  printf '\n%s\n' "$1"
  printf '\n%s\n' "$1" >> "${story_file}"
}

note() {
  printf '  %s\n' "$1"
  printf '%s\n' "$1" >> "${story_file}"
}

command_block() {
  printf '\n```bash\n%s\n```\n' "$1" >> "${story_file}"
}

write_story_header() {
  mkdir -p "${evidence_dir}"
  cat > "${story_file}" <<EOF
# Lab 2 Governed Configuration Demo

Correlation id: \`${correlation_id}\`

This narrated run shows simple local config, opt-in governed config, signed live
apply, signing-key rotation, authorization guardrails, and governed break-glass.

EOF
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

curl_json_bearer() {
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

curl_json_api_key() {
  local method="$1"
  local url="$2"
  local token="$3"
  local out="$4"
  shift 4
  curl -fsS -X "${method}" \
    -H "Accept: application/json" \
    -H "x-api-key: ${token}" \
    -H "x-request-id: ${correlation_id}" \
    "$@" \
    -o "${out}" \
    "${url}"
}

json_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

path, dotted = sys.argv[1:]
with open(path, encoding="utf-8") as fh:
    value = json.load(fh)
for part in dotted.split("."):
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break
if isinstance(value, (dict, list)):
    print(json.dumps(value, sort_keys=True))
elif value is None:
    print("null")
else:
    print(value)
PY
}

assert_json_field() {
  local path="$1"
  local field="$2"
  local expected="$3"
  local actual
  actual="$(json_field "${path}" "${field}")"
  [[ "${actual,,}" == "${expected,,}" ]] || fail "${path}: ${field} expected ${expected}, got ${actual}"
}

assert_json_not_equal() {
  local left_path="$1"
  local left_field="$2"
  local right_path="$3"
  local right_field="$4"
  local left
  local right
  left="$(json_field "${left_path}" "${left_field}")"
  right="$(json_field "${right_path}" "${right_field}")"
  [[ "${left}" != "${right}" ]] || fail "${left_path}:${left_field} unexpectedly matched ${right_path}:${right_field}"
}

container_id() {
  docker compose "${compose_files[@]}" ps -q "$1"
}

apply_relay_bundle() {
  local bundle="$1"
  local out="$2"
  local err="${out%.json}.stderr.txt"
  docker compose "${compose_files[@]}" exec -T lab2-civil-registry-relay \
    /usr/local/bin/registry-relay config apply-bundle \
      --admin-url http://127.0.0.1:8081 \
      --admin-token-env CIVIL_RELAY_OPS_RAW \
      --root-path "/lab2/tuf-repo/${bundle}/metadata/1.root.json" \
      --metadata-dir "/lab2/tuf-repo/${bundle}/metadata" \
      --targets-dir "/lab2/tuf-repo/${bundle}/targets" \
      --datastore-dir "/var/lib/registry-relay/cache/tuf-${bundle}" \
      --target-name civil-registry-relay.yaml \
      > "${out}" 2> "${err}"
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

apply_notary_bundle() {
  local bundle="$1"
  local out="$2"
  local err="${out%.json}.stderr.txt"
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
      > "${out}" 2> "${err}"
}

break_glass_body() {
  local bundle="$1"
  local datastore_dir="$2"
  local target_name="$3"
  local approval_ref="$4"
  local expires_at
  expires_at="$(( $(date +%s) + 3600 ))"
  python3 - "$bundle" "$datastore_dir" "$target_name" "$approval_ref" "$expires_at" <<'PY'
import json
import sys

bundle, datastore_dir, target_name, approval_ref, expires_at = sys.argv[1:]
print(json.dumps({
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
        "reason": "LAB2-DEMO-EMERGENCY-CHANGE",
        "emergency_change_class": "emergency_break_glass",
        "expires_at_unix_seconds": int(expires_at),
        "rate_limit_identity": "lab2-governed-config-demo",
    },
}))
PY
}

post_break_glass() {
  local bundle="$1"
  local datastore_dir="$2"
  local approval_ref="$3"
  local out="$4"
  local body
  local status
  body="$(break_glass_body "${bundle}" "${datastore_dir}" civil-registry-relay.yaml "${approval_ref}")"
  status="$(curl -sS -X POST \
    -H "Accept: application/json" \
    -H "Authorization: Bearer ${CIVIL_RELAY_OPS_RAW}" \
    -H "x-request-id: ${correlation_id}" \
    -H "Content-Type: application/json" \
    --data "${body}" \
    -o "${out}" \
    -w "%{http_code}" \
    http://127.0.0.1:4419/admin/v1/config/apply)"
  printf '%s' "${status}" > "${out%.json}.http-status.txt"
}

issue_notary_credential() {
  local expected_kid="$1"
  local out="$2"
  python3 - "${CIVIL_EVIDENCE_CLIENT_BEARER}" "${expected_kid}" "${out}" <<'PY'
import base64
import importlib.util
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

token, expected_kid, out = sys.argv[1:]
base_url = "http://127.0.0.1:4421"
purpose = "https://demo.example.gov/purpose/decentralized-evidence-demo"
sd_jwt = "application/dc+sd-jwt"

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
            "x-request-id": "lab2-governed-config-demo-credential",
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
    raise SystemExit(f"credential evaluation expected 200, got {evaluation_status}: {evaluation}")
evaluation_id = demo_flow.first_result_id(evaluation)
holder_id, proof = demo_flow.sign_holder_proof(
    evaluation_id,
    "life_stage_sd_jwt",
    ["person-is-alive"],
    "predicate",
    "civil-notary",
)
credential_status, credential = post(
    "/v1/credentials",
    {
        "evaluation_id": evaluation_id,
        "credential_profile": "life_stage_sd_jwt",
        "format": sd_jwt,
        "claims": ["person-is-alive"],
        "disclosure": "predicate",
        "holder": {"binding": "did", "id": holder_id, "proof": proof},
    },
)
if credential_status != 200:
    raise SystemExit(f"credential issuance expected 200, got {credential_status}: {credential}")
issuer_signed_jwt = credential.get("issuer_signed_jwt")
if not isinstance(issuer_signed_jwt, str) or "." not in issuer_signed_jwt:
    raise SystemExit(f"credential response missing issuer_signed_jwt: {credential}")
header_segment = issuer_signed_jwt.split(".", 1)[0]
header_segment += "=" * (-len(header_segment) % 4)
header = json.loads(base64.urlsafe_b64decode(header_segment.encode("ascii")))
actual_kid = header.get("kid")
if actual_kid != expected_kid:
    raise SystemExit(f"credential kid expected {expected_kid}, got {actual_kid}")

summary = {
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
Path(out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
PY
}

summarize_posture() {
  local in_path="$1"
  local out_path="$2"
  jq '{
    configuration: {
      source: .configuration.source,
      dynamic_reload_supported: .configuration.dynamic_reload_supported,
      last_apply_result: .configuration.last_apply_result,
      last_bundle_id: .configuration.last_bundle_id,
      last_bundle_sequence: .configuration.last_bundle_sequence,
      last_config_hash: .configuration.last_config_hash
    },
    signing_keys: .notary.signing_keys
  }' "${in_path}" > "${out_path}"
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

echo "Lab 2 governed configuration narrated demo"
echo "  evidence: ${evidence_dir}"
echo "  pause: ${pause_enabled}"

echo "lab2-demo: generating governed artifacts"
generate_log="$(mktemp "${TMPDIR:-/tmp}/lab2-demo-generate.XXXXXX")"
if ! just lab2-generate > "${generate_log}" 2>&1; then
  cat "${generate_log}" >&2
  fail "lab2-generate failed"
fi
write_story_header
cp "${generate_log}" "${evidence_dir}/00-lab2-generate.txt"
rm -f "${generate_log}"

narrate "## 1. Simple local config stays simple"
if rg -n "accepted_roots" config/relay config/notary config/coolify > "${evidence_dir}/01-static-accepted-roots-scan.txt"; then
  fail "committed static configs contain accepted_roots"
fi
note "Committed static configs contain no accepted_roots, so Lab 1 remains a local-config deployment."
pause

narrate "## 2. Lab 2 opts into governed config"
rg --no-ignore -n "accepted_roots" output/lab2/runtime-config > "${evidence_dir}/02-rendered-accepted-roots-scan.txt"
cp output/lab2/bundles/relay-public-metadata.json "${evidence_dir}/03-relay-public-metadata-bundle.json"
cp output/lab2/bundles/notary-signing-key-rotation.json "${evidence_dir}/04-notary-signing-key-rotation-bundle.json"
note "Rendered Lab 2 configs contain accepted_roots under output/lab2/runtime-config only."
note "Relay public metadata bundle sequence: $(json_field "${evidence_dir}/03-relay-public-metadata-bundle.json" sequence)"
note "Notary signing key rotation bundle sequence: $(json_field "${evidence_dir}/04-notary-signing-key-rotation-bundle.json" sequence)"
pause

narrate "## 3. Start the governed overlay and make baseline requests"
if ! just lab2-down > "${evidence_dir}/05a-lab2-down.txt" 2>&1; then
  tail -n 80 "${evidence_dir}/05a-lab2-down.txt" >&2
  fail "lab2-down failed"
fi
if ! just lab2-up > "${evidence_dir}/05b-lab2-up.txt" 2>&1; then
  tail -n 120 "${evidence_dir}/05b-lab2-up.txt" >&2
  fail "lab2-up failed"
fi
docker compose "${compose_files[@]}" ps > "${evidence_dir}/05-compose-ps.txt"
wait_http_api_key "Lab2 civil relay health" http://127.0.0.1:4411/healthz "${CIVIL_METADATA_CLIENT_RAW}"
wait_http "Lab2 civil notary discovery" http://127.0.0.1:4421/.well-known/evidence-service "${CIVIL_EVIDENCE_CLIENT_BEARER}"
command_block 'curl -H "x-api-key: $CIVIL_METADATA_CLIENT_RAW" http://127.0.0.1:4411/metadata'
curl_json_api_key GET http://127.0.0.1:4411/metadata "${CIVIL_METADATA_CLIENT_RAW}" "${evidence_dir}/06-relay-metadata-before.json"
curl_json_bearer GET 'http://127.0.0.1:4419/admin/v1/posture?tier=restricted' "${CIVIL_RELAY_OPS_RAW}" "${evidence_dir}/07-relay-posture-before.json"
curl_json_bearer GET 'http://127.0.0.1:4422/admin/v1/posture?tier=restricted' "${CIVIL_NOTARY_OPS_BEARER}" "${evidence_dir}/08-notary-posture-before.json"
summarize_posture "${evidence_dir}/07-relay-posture-before.json" "${evidence_dir}/07-relay-posture-before-summary.json"
summarize_posture "${evidence_dir}/08-notary-posture-before.json" "${evidence_dir}/08-notary-posture-before-summary.json"
note "Relay metadata request returned title: $(json_field "${evidence_dir}/06-relay-metadata-before.json" catalog.title)"
note "Relay config source before apply: $(json_field "${evidence_dir}/07-relay-posture-before.json" configuration.source)"
note "Relay last_apply_result before apply: $(json_field "${evidence_dir}/07-relay-posture-before.json" configuration.last_apply_result)"
pause

narrate "## 4. Deployment-profile doctor reports make lab posture visible"
command_block 'LAB2_DOCTOR_PROFILE=hosted_lab just lab2-doctor'
LAB2_DOCTOR_PROFILE=hosted_lab LAB2_DOCTOR_EVIDENCE_DIR="${evidence_dir}/doctor" just lab2-doctor > "${evidence_dir}/08a-doctor-profile.txt"
note "Hosted-lab doctor summary: doctor/summary-hosted_lab.json"
pause

narrate "## 5. A credential request uses the current Notary signing key"
issue_notary_credential \
  "did:web:civil-evidence.demo.example#civil-evidence-demo-key-1" \
  "${evidence_dir}/09-notary-credential-before-rotation.json"
note "Credential before rotation used kid: $(json_field "${evidence_dir}/09-notary-credential-before-rotation.json" issuer_signed_jwt_header.kid)"
pause

narrate "## 6. Apply a signed Relay public_metadata bundle live"
diff -u \
  output/lab2/tuf-repo/relay-noop/source/civil-registry-relay.yaml \
  output/lab2/tuf-repo/relay-public-metadata/source/civil-registry-relay.yaml \
  > "${evidence_dir}/10-relay-public-metadata-config.diff" || true
relay_container_before="$(container_id lab2-civil-registry-relay)"
apply_relay_bundle relay-noop "${evidence_dir}/10a-relay-noop-apply.json"
assert_json_field "${evidence_dir}/10a-relay-noop-apply.json" result applied
assert_json_field "${evidence_dir}/10a-relay-noop-apply.json" applied true
command_block 'registry-relay config apply-bundle --admin-url http://127.0.0.1:8081 --root-path /lab2/tuf-repo/relay-public-metadata/metadata/1.root.json --target-name civil-registry-relay.yaml'
apply_relay_bundle relay-public-metadata "${evidence_dir}/11-relay-public-metadata-apply.json"
assert_json_field "${evidence_dir}/11-relay-public-metadata-apply.json" result applied
assert_json_field "${evidence_dir}/11-relay-public-metadata-apply.json" applied true
[[ "${relay_container_before}" == "$(container_id lab2-civil-registry-relay)" ]] || fail "Relay container restarted during live config apply"
curl_json_bearer GET 'http://127.0.0.1:4419/admin/v1/posture?tier=restricted' "${CIVIL_RELAY_OPS_RAW}" "${evidence_dir}/13-relay-posture-after-public-metadata.json"
summarize_posture "${evidence_dir}/13-relay-posture-after-public-metadata.json" "${evidence_dir}/13-relay-posture-after-public-metadata-summary.json"
assert_json_not_equal "${evidence_dir}/07-relay-posture-before.json" configuration.last_config_hash "${evidence_dir}/13-relay-posture-after-public-metadata.json" configuration.last_config_hash
assert_json_field "${evidence_dir}/13-relay-posture-after-public-metadata.json" instance.owner "Civil Registration Operations Team"
note "Signed no-op apply result: $(json_field "${evidence_dir}/10a-relay-noop-apply.json" result)"
note "Signed metadata apply result: $(json_field "${evidence_dir}/11-relay-public-metadata-apply.json" result)"
note "Relay posture owner after apply: $(json_field "${evidence_dir}/13-relay-posture-after-public-metadata.json" instance.owner)"
note "Relay config hash changed without container restart."
pause

narrate "## 7. Apply a signed Notary signing-key rotation"
diff -u \
  output/lab2/tuf-repo/notary-noop/source/civil-notary.yaml \
  output/lab2/tuf-repo/notary-signing-key-rotation/source/civil-notary.yaml \
  > "${evidence_dir}/20-notary-signing-key-rotation.diff" || true
notary_container_before="$(container_id lab2-civil-notary)"
command_block 'registry-notary config apply-bundle --admin-url http://127.0.0.1:8082 --root-path /lab2/tuf-repo/notary-signing-key-rotation/metadata/1.root.json --target-name civil-notary.yaml'
apply_notary_bundle notary-signing-key-rotation "${evidence_dir}/21-notary-signing-key-rotation-apply.json"
assert_json_field "${evidence_dir}/21-notary-signing-key-rotation-apply.json" result applied
assert_json_field "${evidence_dir}/21-notary-signing-key-rotation-apply.json" applied true
[[ "${notary_container_before}" == "$(container_id lab2-civil-notary)" ]] || fail "Notary container restarted during signing key rotation"
curl_json_bearer GET 'http://127.0.0.1:4422/admin/v1/posture?tier=restricted' "${CIVIL_NOTARY_OPS_BEARER}" "${evidence_dir}/22-notary-posture-after-rotation.json"
summarize_posture "${evidence_dir}/22-notary-posture-after-rotation.json" "${evidence_dir}/22-notary-posture-after-rotation-summary.json"
issue_notary_credential \
  "did:web:civil-evidence.demo.example#civil-evidence-demo-key-2" \
  "${evidence_dir}/23-notary-credential-after-rotation.json"
note "Credential after rotation used kid: $(json_field "${evidence_dir}/23-notary-credential-after-rotation.json" issuer_signed_jwt_header.kid)"
note "Posture keeps old and new evidence signing kids ready during no-drop rotation."
pause

narrate "## 8. Guardrails reject under-authorized signed config"
command_block 'registry-relay config apply-bundle ... /lab2/tuf-repo/relay-threshold-minus-one/...'
apply_relay_bundle_may_fail relay-threshold-minus-one "${evidence_dir}/30-relay-threshold-minus-one.json" || true
assert_json_field "${evidence_dir}/30-relay-threshold-minus-one.json" result rejected_threshold
assert_json_field "${evidence_dir}/30-relay-threshold-minus-one.json" applied false
apply_relay_bundle relay-threshold-exact "${evidence_dir}/31-relay-threshold-exact.json"
assert_json_field "${evidence_dir}/31-relay-threshold-exact.json" result applied
assert_json_field "${evidence_dir}/31-relay-threshold-exact.json" applied true
note "Threshold-minus-one result: $(json_field "${evidence_dir}/30-relay-threshold-minus-one.json" result)"
note "Exact-threshold result: $(json_field "${evidence_dir}/31-relay-threshold-exact.json" result)"
pause

narrate "## 9. Break-glass is accepted once, then rate-limited across restart"
command_block 'curl -X POST http://127.0.0.1:4419/admin/v1/config/apply --data @signed-break-glass-request.json'
post_break_glass relay-break-glass "/var/lib/registry-relay/cache/tuf-relay-break-glass" INC-LAB2-DEMO-BG "${evidence_dir}/40-relay-break-glass.json"
assert_json_field "${evidence_dir}/40-relay-break-glass.json" result applied
assert_json_field "${evidence_dir}/40-relay-break-glass.json" applied true
docker compose "${compose_files[@]}" restart lab2-civil-registry-relay > "${evidence_dir}/41-relay-break-glass-restart.txt"
wait_http_api_key "Lab2 civil relay health after break-glass restart" http://127.0.0.1:4411/healthz "${CIVIL_METADATA_CLIENT_RAW}"
post_break_glass relay-break-glass-second "/var/lib/registry-relay/cache/tuf-relay-break-glass-second" INC-LAB2-DEMO-BG-SECOND "${evidence_dir}/42-relay-break-glass-second.json"
assert_json_field "${evidence_dir}/42-relay-break-glass-second.json" result rejected_break_glass
assert_json_field "${evidence_dir}/42-relay-break-glass-second.json" applied false
note "First break-glass result: $(json_field "${evidence_dir}/40-relay-break-glass.json" result)"
note "Second break-glass result after restart: $(json_field "${evidence_dir}/42-relay-break-glass-second.json" result)"

curl_json_bearer GET 'http://127.0.0.1:4419/admin/v1/posture?tier=restricted' "${CIVIL_RELAY_OPS_RAW}" "${evidence_dir}/50-relay-posture-final.json"
curl_json_bearer GET 'http://127.0.0.1:4422/admin/v1/posture?tier=restricted' "${CIVIL_NOTARY_OPS_BEARER}" "${evidence_dir}/51-notary-posture-final.json"
scripts/lab2-secret-scan.sh > "${evidence_dir}/60-secret-scan-run.txt"

cat >> "${story_file}" <<EOF

## Evidence Index

- Static config scan: \`01-static-accepted-roots-scan.txt\`
- Generated artifact log: \`00-lab2-generate.txt\`
- Rendered governed config scan: \`02-rendered-accepted-roots-scan.txt\`
- Overlay setup logs: \`05a-lab2-down.txt\`, \`05b-lab2-up.txt\`
- Deployment profile doctor: \`doctor/summary-hosted_lab.json\`, \`doctor/relay-doctor-hosted_lab.json\`, \`doctor/notary-doctor-hosted_lab.json\`
- Relay baseline metadata: \`06-relay-metadata-before.json\`
- Relay live apply: \`10-relay-public-metadata-config.diff\`, \`11-relay-public-metadata-apply.json\`, \`13-relay-posture-after-public-metadata-summary.json\`
- Notary key rotation: \`09-notary-credential-before-rotation.json\`, \`20-notary-signing-key-rotation.diff\`, \`21-notary-signing-key-rotation-apply.json\`, \`23-notary-credential-after-rotation.json\`
- Guardrails: \`30-relay-threshold-minus-one.json\`, \`31-relay-threshold-exact.json\`
- Break-glass: \`40-relay-break-glass.json\`, \`42-relay-break-glass-second.json\`
- Final posture: \`50-relay-posture-final.json\`, \`51-notary-posture-final.json\`
- Secret scan: \`60-secret-scan-run.txt\`
EOF

echo
echo "Lab 2 narrated demo OK"
echo "Story: ${story_file}"
