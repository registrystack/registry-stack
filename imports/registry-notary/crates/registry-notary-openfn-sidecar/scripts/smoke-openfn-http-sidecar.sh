#!/bin/sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
sidecar_port="${OPENFN_HTTP_DEMO_SIDECAR_PORT:-19291}"

OPENFN_HTTP_DEMO_SIDECAR_PORT="$sidecar_port" \
OPENFN_HTTP_DEMO_REGISTRY_PORT="${OPENFN_HTTP_DEMO_REGISTRY_PORT:-19292}" \
  "$script_dir/run-openfn-http-demo.sh" start >/dev/null

cleanup() {
  OPENFN_HTTP_DEMO_SIDECAR_PORT="$sidecar_port" \
  OPENFN_HTTP_DEMO_REGISTRY_PORT="${OPENFN_HTTP_DEMO_REGISTRY_PORT:-19292}" \
    "$script_dir/run-openfn-http-demo.sh" stop >/dev/null || true
}
trap cleanup EXIT INT TERM

lookup() {
  value="$1"
  curl -sS \
    -H "Authorization: Bearer dev-sidecar-token" \
    -H "Data-Purpose: smoke-test" \
    "http://127.0.0.1:$sidecar_port/v1/datasets/civil_registry/entities/civil_person/records?national_id=$value&fields=national_id,birth_date&limit=2"
}

lookup person-123 |
  jq -e '.data | length == 1 and .[0].national_id == "person-123" and .[0].birth_date == "1990-01-01" and (.[0] | has("ignored_extra") | not)' >/dev/null

lookup missing-person |
  jq -e '.data | length == 0' >/dev/null

lookup ambiguous-person |
  jq -e '.data | length == 2' >/dev/null

auth_status="$(
  curl -sS -o /tmp/openfn-http-auth.json -w "%{http_code}" \
    -H "Authorization: Bearer dev-sidecar-token" \
    -H "Data-Purpose: smoke-test" \
    "http://127.0.0.1:$sidecar_port/v1/datasets/civil_registry/entities/civil_person/records?national_id=target-auth&fields=national_id,birth_date&limit=2"
)"
test "$auth_status" = "502"
jq -e '.code == "target_auth"' /tmp/openfn-http-auth.json >/dev/null

rate_headers="/tmp/openfn-http-rate-limit.headers"
rate_status="$(
  curl -sS -D "$rate_headers" -o /tmp/openfn-http-rate-limit.json -w "%{http_code}" \
    -H "Authorization: Bearer dev-sidecar-token" \
    -H "Data-Purpose: smoke-test" \
    "http://127.0.0.1:$sidecar_port/v1/datasets/civil_registry/entities/civil_person/records?national_id=target-rate-limit&fields=national_id,birth_date&limit=2"
)"
test "$rate_status" = "503"
jq -e '.code == "target_rate_limit"' /tmp/openfn-http-rate-limit.json >/dev/null
grep -i '^retry-after: 5' "$rate_headers" >/dev/null

printf 'OpenFn HTTP sidecar smoke passed\n'
