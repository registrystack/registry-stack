#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
output_dir="${demo_dir}/output"
correlation_id="${DEMO_CORRELATION_ID:-decentralized-demo-correlation-001}"

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
curl -fsS \
  -X POST \
  -H "Authorization: Bearer ${CIVIL_EVIDENCE_CLIENT_BEARER}" \
  -H "Content-Type: application/json" \
  -H "Data-Purpose: https://demo.example.gov/purpose/openfn-sidecar-demo" \
  -H "x-request-id: ${correlation_id}" \
  -o "${notary_body}" \
  http://127.0.0.1:4324/claims/evaluate \
  --data '{"subject":{"id":"person-123","id_type":"national_id"},"claims":["date-of-birth"],"disclosure":"value","format":"application/vnd.registry-notary.claim-result+json"}'

python - "${notary_body}" <<'PY'
import json
import sys
body = json.load(open(sys.argv[1], encoding="utf-8"))
results = body.get("results") or []
assert len(results) == 1, body
result = results[0]
assert result.get("claim_id") == "date-of-birth", body
assert result.get("value") == "1990-01-01", body
assert result.get("provenance", {}).get("source_count") == 1, body
PY

printf 'OpenFn sidecar Registry Notary smoke passed\n'
