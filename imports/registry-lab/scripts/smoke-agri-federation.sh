#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
output_dir="${AGRI_FEDERATION_SMOKE_OUTPUT_DIR:-${demo_dir}/output/agri-federation}"
correlation_id="${DEMO_CORRELATION_ID:-nagdi-agri-federation-correlation-001}"

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

witness_url="${AGRI_WITNESS_URL:-http://127.0.0.1:4342}"
static_url="${AGRI_STATIC_METADATA_URL:-http://127.0.0.1:4343}"

wait_http "agriculture Witness discovery" "${witness_url}/.well-known/evidence-service" "${AGRI_EVIDENCE_CLIENT_BEARER}"
wait_http "agriculture federation client JWKS" "${static_url}/federation/benefits-jwks.json" ""

DEMO_CORRELATION_ID="${correlation_id}" \
AGRI_WITNESS_URL="${witness_url}" \
python "${script_dir}/demo-agri-federation.py" --output-dir "${output_dir}"

assert_artifact "${output_dir}/voucher-eligible-verified-response.json"
assert_artifact "${output_dir}/voucher-not-eligible-verified-response.json"
assert_artifact "${output_dir}/livestock-eligible-verified-response.json"
assert_artifact "${output_dir}/voucher-replay-denial.json"
assert_artifact "${output_dir}/unsupported-purpose-denial.json"
assert_artifact "${output_dir}/composed-benefits-decision.json"

python - "${output_dir}" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
eligible = json.load(open(out / "voucher-eligible-verified-response.json", encoding="utf-8"))
not_eligible = json.load(open(out / "voucher-not-eligible-verified-response.json", encoding="utf-8"))
livestock = json.load(open(out / "livestock-eligible-verified-response.json", encoding="utf-8"))
replay = json.load(open(out / "voucher-replay-denial.json", encoding="utf-8"))
purpose = json.load(open(out / "unsupported-purpose-denial.json", encoding="utf-8"))
decision = json.load(open(out / "composed-benefits-decision.json", encoding="utf-8"))

if eligible["result"]["claims"]["eligible-for-climate-smart-input-voucher"]["satisfied"] is not True:
    raise SystemExit("voucher positive predicate did not satisfy")
if not_eligible["result"]["claims"]["eligible-for-climate-smart-input-voucher"]["satisfied"] is not False:
    raise SystemExit("voucher negative predicate did not fail")
if livestock["result"]["claims"]["eligible-for-livestock-movement-permit"]["satisfied"] is not True:
    raise SystemExit("livestock positive predicate did not satisfy")
if replay["status"] != 409:
    raise SystemExit(f"expected replay 409, got {replay['status']}")
if purpose["status"] != 403:
    raise SystemExit(f"expected unsupported purpose 403, got {purpose['status']}")
if decision["boundary"]["raw_registry_rows_embedded"] is not False:
    raise SystemExit("composed decision must not embed raw rows")
PY

for secret_value in "${AGRI_FEDERATION_CLIENT_JWK}" "${AGRI_FEDERATION_RESPONSE_JWK}" "${AGRI_FEDERATION_PAIRWISE_SUBJECT_HASH_SECRET}"; do
  if [[ -n "${secret_value}" ]] && grep -R -F -- "${secret_value}" "${output_dir}" >/dev/null; then
    fail "federation secret leaked into output artifacts"
  fi
done

echo "agricultural federation smoke OK"
