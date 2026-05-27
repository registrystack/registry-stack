#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
output_dir="${FEDERATION_SMOKE_OUTPUT_DIR:-${demo_dir}/output/federation}"
correlation_id="${DEMO_CORRELATION_ID:-default-federation-correlation-001}"

if [[ -f "${demo_dir}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${demo_dir}/.env"
  set +a
else
  echo "missing .env; run scripts/generate-demo-secrets.py first" >&2
  exit 1
fi

fail() {
  echo "FAILED: $1" >&2
  exit 1
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

assert_artifact() {
  local path="$1"
  [[ -s "${path}" ]] || fail "missing artifact ${path}"
}

civil_url="${CIVIL_WITNESS_URL:-http://127.0.0.1:4321}"
social_url="${SOCIAL_WITNESS_URL:-http://127.0.0.1:4322}"
static_url="${STATIC_METADATA_URL:-http://127.0.0.1:4331}"

wait_http "civil Witness discovery" "${civil_url}/.well-known/evidence-service" "${CIVIL_EVIDENCE_CLIENT_BEARER}"
wait_http "social protection Witness discovery" "${social_url}/.well-known/evidence-service" "${SOCIAL_EVIDENCE_CLIENT_BEARER}"
wait_http "default federation client JWKS" "${static_url}/federation/default-benefits-jwks.json" ""

DEMO_CORRELATION_ID="${correlation_id}" \
CIVIL_WITNESS_URL="${civil_url}" \
SOCIAL_WITNESS_URL="${social_url}" \
python "${script_dir}/demo-federation.py" --output-dir "${output_dir}"

assert_artifact "${output_dir}/civil-age-band-verified-response.json"
assert_artifact "${output_dir}/civil-alive-verified-response.json"
assert_artifact "${output_dir}/social-beneficiary-active-verified-response.json"
assert_artifact "${output_dir}/social-household-band-verified-response.json"
assert_artifact "${output_dir}/replay-denial.json"
assert_artifact "${output_dir}/unsupported-purpose-denial.json"
assert_artifact "${output_dir}/composed-benefit-screen.json"

python - "${output_dir}" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
age = json.load(open(out / "civil-age-band-verified-response.json", encoding="utf-8"))
alive = json.load(open(out / "civil-alive-verified-response.json", encoding="utf-8"))
active = json.load(open(out / "social-beneficiary-active-verified-response.json", encoding="utf-8"))
band = json.load(open(out / "social-household-band-verified-response.json", encoding="utf-8"))
replay = json.load(open(out / "replay-denial.json", encoding="utf-8"))
purpose = json.load(open(out / "unsupported-purpose-denial.json", encoding="utf-8"))
decision = json.load(open(out / "composed-benefit-screen.json", encoding="utf-8"))

if age["result"]["claims"]["age-band"]["value"] != "child":
    raise SystemExit("civil age-band value did not disclose child")
if alive["result"]["claims"]["person-is-alive"]["satisfied"] is not True:
    raise SystemExit("civil alive predicate did not satisfy")
if active["result"]["claims"]["beneficiary-active"]["satisfied"] is not True:
    raise SystemExit("beneficiary active predicate did not satisfy")
if band["result"]["claims"]["household-eligibility-band"]["value"] != "priority":
    raise SystemExit("household eligibility band did not disclose priority")
if replay["status"] != 409:
    raise SystemExit(f"expected replay 409, got {replay['status']}")
if purpose["status"] != 403:
    raise SystemExit(f"expected unsupported purpose 403, got {purpose['status']}")
if decision["boundary"]["raw_registry_rows_embedded"] is not False:
    raise SystemExit("composed decision must not embed raw rows")
PY

for secret_value in \
  "${DEFAULT_FEDERATION_CLIENT_JWK}" \
  "${CIVIL_FEDERATION_RESPONSE_JWK}" \
  "${SOCIAL_FEDERATION_RESPONSE_JWK}" \
  "${CIVIL_FEDERATION_PAIRWISE_SUBJECT_HASH_SECRET}" \
  "${SOCIAL_FEDERATION_PAIRWISE_SUBJECT_HASH_SECRET}"; do
  if [[ -n "${secret_value}" ]] && grep -R -F -- "${secret_value}" "${output_dir}" >/dev/null; then
    fail "federation secret leaked into output artifacts"
  fi
done

echo "default federation smoke OK"
