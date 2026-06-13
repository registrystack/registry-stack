#!/bin/sh
set -eu

crate_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
repo_dir="$(CDPATH= cd -- "$crate_dir/../.." && pwd)"
port="${HTTP_FLOW_DHIS2_CANARY_PORT:-19397}"
smoke_dir="$repo_dir/target/http-flow-dhis2-sidecar-smoke-$port"
manifest="$smoke_dir/http-flow-dhis2-sidecar.yaml"
log="$smoke_dir/sidecar.log"
response_json="$smoke_dir/batch-response.json"
metrics_txt="$smoke_dir/metrics.txt"

dhis2_base_url="${HTTP_FLOW_DHIS2_HOST_URL:-https://play.im.dhis2.org/stable-2-43-0}"
dhis2_base_url="${dhis2_base_url%/}"
dhis2_username="${HTTP_FLOW_DHIS2_USERNAME:-admin}"
dhis2_password="${HTTP_FLOW_DHIS2_PASSWORD:-}"
if [ -z "$dhis2_password" ]; then
  printf 'HTTP_FLOW_DHIS2_PASSWORD is required for the live DHIS2 http_flow canary\n' >&2
  exit 2
fi
sidecar_token="${HTTP_FLOW_DHIS2_CANARY_SIDECAR_TOKEN:-http-flow-dhis2-canary-$$-$(date +%s)}"
if command -v sha256sum >/dev/null 2>&1; then
  sidecar_token_digest="$(printf '%s' "$sidecar_token" | sha256sum | awk '{print $1}')"
else
  sidecar_token_digest="$(printf '%s' "$sidecar_token" | shasum -a 256 | awk '{print $1}')"
fi
sidecar_token_hash="sha256:$sidecar_token_digest"

rm -rf "$smoke_dir"
mkdir -p "$smoke_dir"

cat >"$manifest" <<YAML
server:
  bind: "127.0.0.1:$port"
auth:
  bearer_tokens:
    - id: notary
      hash_env: HTTP_FLOW_DHIS2_CANARY_SIDECAR_TOKEN_HASH
limits:
  max_workers: 2
  worker_timeout_ms: 15000
  max_worker_memory_mb: 512
  max_output_bytes: 1048576
  max_request_bytes: 16384
  max_query_parameter_bytes: 2048
  liveness_window_ms: 30000
  retry_after_seconds: 1
  max_batch_items: 10
  batch_timeout_ms: 30000
sources:
  dhis2_org_units:
    engine: http_flow
    dataset: dhis2
    entity: organisationUnit
    credential_env: HTTP_FLOW_DHIS2_CREDENTIAL_JSON
    credential_public_fields:
      - baseUrl
    allowed_base_urls:
      - "$dhis2_base_url"
    http_flow:
      timeout_ms: 15000
      max_steps: 2
      steps:
        - id: find_org_unit
          request:
            method: GET
            base_url: "$dhis2_base_url"
            path: "/api/organisationUnits.json"
            query:
              filter:
                cel: 'lookup.field + ":eq:" + lookup.value'
              fields:
                cel: '"id,name,level"'
              paging:
                cel: '"false"'
            auth:
              type: basic
              username:
                secret: username
              password:
                secret: password
          response:
            bind:
              org_unit_id:
                cel: "size(body.organisationUnits) == 0 ? null : body.organisationUnits[0].id"
        - id: fetch_org_unit
          when:
            cel: org_unit_id != null
          request:
            method: GET
            base_url: "$dhis2_base_url"
            path: "/api/organisationUnits.json"
            query:
              filter:
                cel: '"id:eq:" + org_unit_id'
              fields:
                cel: '"id,name,level"'
              paging:
                cel: '"false"'
            auth:
              type: basic
              username:
                secret: username
              password:
                secret: password
          response:
            bind:
              org_units:
                cel: body.organisationUnits
      output:
        records:
          cel: "org_units == null ? [] : org_units"
    smoke_lookup:
      field: name
      value: Sierra Leone
      fields: ["id", "name", "level"]
      purpose: startup-readiness-smoke
YAML

redact_log() {
  sed \
    -e "s/$dhis2_password/[REDACTED_DHIS2_PASSWORD]/g" \
    -e "s/$sidecar_token/[REDACTED_SIDECAR_TOKEN]/g" \
    "$log"
}

export HTTP_FLOW_DHIS2_CANARY_SIDECAR_TOKEN_HASH="$sidecar_token_hash"
if [ -z "${HTTP_FLOW_DHIS2_CREDENTIAL_JSON:-}" ]; then
  export HTTP_FLOW_DHIS2_CREDENTIAL_JSON="$(
    jq -cn \
      --arg baseUrl "$dhis2_base_url" \
      --arg username "$dhis2_username" \
      --arg password "$dhis2_password" \
      '{baseUrl:$baseUrl,username:$username,password:$password}'
  )"
fi

cargo run -p registry-notary-openfn-sidecar --bin registry-notary-openfn-sidecar -- \
  --config "$manifest" \
  --allow-unsigned-dev-config >"$log" 2>&1 &
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
    redact_log
    exit 1
  fi
  sleep 1
done

if [ "$ready" -ne 1 ]; then
  redact_log
  exit 1
fi

curl -fsS \
  -H "Authorization: Bearer $sidecar_token" \
  -H "Data-Purpose: live-dhis2-canary" \
  -H "X-Correlation-Id: http-flow-dhis2-canary-correlation" \
  -H "Content-Type: application/json" \
  -d '{"fields":["id","name","level"],"query_signature":[{"field":"name","op":"eq"}],"items":[{"id":"hit","values":["Sierra Leone"]},{"id":"miss","values":["Not A Real Org Unit"]}]}' \
  "http://127.0.0.1:$port/v1/datasets/dhis2/entities/organisationUnit/records:batchMatch" >"$response_json"

jq -e '
  (.items | length == 2) and
  (.items[0].id == "hit") and
  (.items[0].data | length == 1) and
  (.items[0].data[0].id == "ImspTQPwCqd") and
  (.items[0].data[0].name == "Sierra Leone") and
  (.items[0].data[0] | has("path") | not) and
  (.items[1].id == "miss") and
  (.items[1].data | length == 0)
' "$response_json" >/dev/null

curl -fsS "http://127.0.0.1:$port/metrics" >"$metrics_txt"
grep 'registry_notary_openfn_sidecar_lookup_total{source_id="dhis2_org_units",outcome="batch_success"}' "$metrics_txt" >/dev/null

for secret in "$dhis2_password" "$sidecar_token" "http-flow-dhis2-canary-correlation"; do
  if grep -F "$secret" "$response_json" "$metrics_txt" "$log" >/dev/null 2>&1; then
    printf 'secret-like value leaked in DHIS2 http_flow sidecar smoke artifacts\n' >&2
    exit 1
  fi
done

printf 'http_flow DHIS2 sidecar smoke passed\n'
