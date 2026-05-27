#!/bin/sh
set -eu

crate_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
repo_dir="$(CDPATH= cd -- "$crate_dir/../.." && pwd)"
smoke_dir="$repo_dir/target/openfn-sidecar-smoke"
worker="$smoke_dir/openfn_worker.mjs"
manifest="$smoke_dir/openfn-sidecar.yaml"
log="$smoke_dir/sidecar.log"
port="${OPENFN_SIDECAR_SMOKE_PORT:-19191}"

rm -rf "$smoke_dir"
mkdir -p "$smoke_dir"
cp "$crate_dir/workers/openfn_worker.mjs" "$worker"

cat >"$smoke_dir/package.json" <<'JSON'
{
  "private": true,
  "type": "module",
  "dependencies": {
    "@openfn/compiler": "1.2.5",
    "@openfn/runtime": "1.9.3",
    "@openfn/language-common": "3.2.3"
  }
}
JSON

npm install --prefix "$smoke_dir" --ignore-scripts --no-audit --no-fund >/dev/null

cat >"$manifest" <<YAML
server:
  bind: "127.0.0.1:$port"
auth:
  bearer_tokens:
    - id: witness
      hash_env: DEV_SIDECAR_TOKEN_HASH
limits:
  max_workers: 2
  worker_timeout_ms: 10000
  max_worker_memory_mb: 512
  max_output_bytes: 1048576
  max_request_bytes: 16384
  max_query_parameter_bytes: 1024
  liveness_window_ms: 30000
  retry_after_seconds: 1
openfn:
  cli_build_tool: "1.2.5"
  runtime: "1.9.3"
worker:
  command: "node"
  args:
    - "--experimental-vm-modules"
    - "$worker"
  version_args:
    - "--experimental-vm-modules"
    - "$worker"
    - "--version"
    - "--require-adaptor"
    - "@openfn/language-common@3.2.3"
sources:
  example_people:
    dataset: civil_registry
    entity: civil_person
    workflow:
      start: prepare_lookup
      steps:
        - id: prepare_lookup
          expression: "$crate_dir/examples/jobs/common-prepare-lookup.js"
          adaptors:
            - "@openfn/language-common@3.2.3"
          next:
            filter_records: true
        - id: filter_records
          expression: "$crate_dir/examples/jobs/common-filter-records.js"
          adaptors:
            - "@openfn/language-common@3.2.3"
          next:
            return_rda: true
        - id: return_rda
          expression: "$crate_dir/examples/jobs/common-return-rda.js"
          adaptors:
            - "@openfn/language-common@3.2.3"
    credential_env: EXAMPLE_PERSON_LOOKUP_CREDENTIAL_JSON
    smoke_lookup:
      field: national_id
      value: person-123
      fields: ["national_id", "birth_date"]
      purpose: startup-readiness-smoke
YAML

export DEV_SIDECAR_TOKEN_HASH='sha256:a61cb2a28977890d2e95d2eb9f5355b184d48dc2aec23252bdeb08eca7f42544'
export EXAMPLE_PERSON_LOOKUP_CREDENTIAL_JSON='{"fixture_records":[{"national_id":"person-123","birth_date":"1990-01-01","extra":"sidecar-must-trim"},{"national_id":"person-456","birth_date":"1985-05-05"}],"apiToken":"redacted-placeholder"}'

cargo run -p registry-witness-openfn-sidecar --bin registry-witness-openfn-sidecar -- --config "$manifest" >"$log" 2>&1 &
sidecar_pid="$!"

cleanup() {
  kill "$sidecar_pid" >/dev/null 2>&1 || true
  wait "$sidecar_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

ready=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$port/ready" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$sidecar_pid" >/dev/null 2>&1; then
    cat "$log"
    exit 1
  fi
  sleep 1
done

if [ "$ready" -ne 1 ]; then
  cat "$log"
  exit 1
fi

response="$(
  curl -fsS \
    -H "Authorization: Bearer dev-sidecar-token" \
    -H "Data-Purpose: smoke-test" \
    -H "X-Correlation-Id: openfn-sidecar-smoke" \
    "http://127.0.0.1:$port/datasets/civil_registry/civil_person?national_id=person-123&fields=national_id,birth_date&limit=2"
)"

printf '%s\n' "$response" |
  jq -e '.data | length == 1 and .[0].national_id == "person-123" and .[0].birth_date == "1990-01-01" and (.[0] | has("extra") | not)' >/dev/null

auth_json="$smoke_dir/target-auth.json"
auth_status="$(
  curl -sS \
    -o "$auth_json" \
    -H "Authorization: Bearer dev-sidecar-token" \
    -H "Data-Purpose: smoke-test" \
    -H "X-Correlation-Id: openfn-sidecar-smoke" \
    "http://127.0.0.1:$port/datasets/civil_registry/civil_person?national_id=target-auth&fields=national_id,birth_date&limit=2" \
    -w "%{http_code}"
)"
if [ "$auth_status" != "502" ]; then
  cat "$auth_json"
  exit 1
fi
cat "$auth_json" |
  jq -e '.code == "target_auth"' >/dev/null

rate_limit_response_headers="$smoke_dir/rate-limit.headers"
rate_limit_json="$smoke_dir/rate-limit.json"
rate_limit_status="$(
  curl -sS \
    -D "$rate_limit_response_headers" \
    -o "$rate_limit_json" \
    -H "Authorization: Bearer dev-sidecar-token" \
    -H "Data-Purpose: smoke-test" \
    -H "X-Correlation-Id: openfn-sidecar-smoke" \
    "http://127.0.0.1:$port/datasets/civil_registry/civil_person?national_id=target-rate-limit&fields=national_id,birth_date&limit=2" \
    -w "%{http_code}"
)"
if [ "$rate_limit_status" != "503" ]; then
  cat "$rate_limit_json"
  exit 1
fi
cat "$rate_limit_json" |
  jq -e '.code == "target_rate_limit"' >/dev/null
grep -i '^retry-after: 5' "$rate_limit_response_headers" >/dev/null

printf 'OpenFn sidecar smoke passed\n'
