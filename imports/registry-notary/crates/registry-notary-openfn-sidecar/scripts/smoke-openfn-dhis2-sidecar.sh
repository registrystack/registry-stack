#!/bin/sh
set -eu

crate_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
repo_dir="$(CDPATH= cd -- "$crate_dir/../.." && pwd)"
port="${OPENFN_DHIS2_CANARY_PORT:-19394}"
smoke_dir="$repo_dir/target/openfn-dhis2-sidecar-smoke-$port"
worker="$smoke_dir/openfn_worker.mjs"
job="$smoke_dir/dhis2-orgunit-lookup.js"
manifest="$smoke_dir/openfn-dhis2-sidecar.yaml"
log="$smoke_dir/sidecar.log"
response_json="$smoke_dir/batch-response.json"
metrics_txt="$smoke_dir/metrics.txt"

dhis2_base_url="${OPENFN_DHIS2_HOST_URL:-https://play.im.dhis2.org/stable-2-43-0}"
dhis2_base_url="${dhis2_base_url%/}"
dhis2_username="${OPENFN_DHIS2_USERNAME:-admin}"
dhis2_password="${OPENFN_DHIS2_PASSWORD:-}"
if [ -z "$dhis2_password" ]; then
  printf 'OPENFN_DHIS2_PASSWORD is required for the live DHIS2 canary\n' >&2
  exit 2
fi
sidecar_token="${OPENFN_DHIS2_CANARY_SIDECAR_TOKEN:-dhis2-canary-$$-$(date +%s)}"
if command -v sha256sum >/dev/null 2>&1; then
  sidecar_token_digest="$(printf '%s' "$sidecar_token" | sha256sum | awk '{print $1}')"
else
  sidecar_token_digest="$(printf '%s' "$sidecar_token" | shasum -a 256 | awk '{print $1}')"
fi
sidecar_token_hash="sha256:$sidecar_token_digest"

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
    "@openfn/language-common": "3.2.3",
    "@openfn/language-http": "7.3.1"
  }
}
JSON

npm install --prefix "$smoke_dir" --ignore-scripts --no-audit --no-fund >/dev/null

cat >"$job" <<'JS'
execute(
  get(
    '/api/organisationUnits.json',
    {
      query: state => {
        const lookup = state.data.lookup ?? {};
        return {
          filter: `${lookup.field}:eq:${lookup.value}`,
          fields: 'id,name,level',
          paging: 'false',
        };
      },
      authentication: state => ({
        username: state.configuration.username,
        password: state.configuration.password,
      }),
      parseAs: 'json',
    },
  ),
  fn(state => {
    const records = Array.isArray(state.data?.organisationUnits)
      ? state.data.organisationUnits
      : Array.isArray(state.response?.body?.organisationUnits)
        ? state.response.body.organisationUnits
        : [];
    return {
      ...state,
      data: { records },
    };
  }),
);
JS

cat >"$manifest" <<YAML
server:
  bind: "127.0.0.1:$port"
auth:
  bearer_tokens:
    - id: notary
      hash_env: OPENFN_DHIS2_CANARY_SIDECAR_TOKEN_HASH
limits:
  max_workers: 2
  worker_timeout_ms: 15000
  max_worker_memory_mb: 12288
  max_output_bytes: 1048576
  max_request_bytes: 16384
  max_query_parameter_bytes: 2048
  liveness_window_ms: 30000
  retry_after_seconds: 1
  max_batch_items: 10
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
    - "@openfn/language-http@7.3.1"
sources:
  dhis2_org_units:
    dataset: dhis2
    entity: organisationUnit
    workflow:
      steps:
        - id: lookup
          expression: "$job"
          adaptors:
            - "@openfn/language-http@7.3.1"
    credential_env: OPENFN_DHIS2_DEMO_CREDENTIAL_JSON
    allowed_base_urls:
      - "$dhis2_base_url"
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

export OPENFN_DHIS2_CANARY_SIDECAR_TOKEN_HASH="$sidecar_token_hash"
if [ -z "${OPENFN_DHIS2_DEMO_CREDENTIAL_JSON:-}" ]; then
  export OPENFN_DHIS2_DEMO_CREDENTIAL_JSON="$(
    jq -cn \
      --arg hostUrl "$dhis2_base_url" \
      --arg username "$dhis2_username" \
      --arg password "$dhis2_password" \
      '{hostUrl:$hostUrl,baseUrl:$hostUrl,username:$username,password:$password}'
  )"
fi

cargo run -p registry-notary-openfn-sidecar --bin registry-notary-openfn-sidecar -- --config "$manifest" >"$log" 2>&1 &
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
  -H "X-Correlation-Id: dhis2-canary-correlation" \
  -H "Content-Type: application/json" \
  -d '{"fields":["id","name","level"],"query_signature":[{"field":"name","op":"eq"}],"items":[{"id":"hit","values":["Sierra Leone"]},{"id":"miss","values":["Not A Real Org Unit"]}]}' \
  "http://127.0.0.1:$port/v1/datasets/dhis2/entities/organisationUnit/records:batchMatch" >"$response_json"

jq -e '
  (.items | length == 2) and
  (.items[0].id == "hit") and
  (.items[0].data | length == 1) and
  (.items[0].data[0].id == "ImspTQPwCqd") and
  (.items[0].data[0].name == "Sierra Leone") and
  (.items[1].id == "miss") and
  (.items[1].data | length == 0)
' "$response_json" >/dev/null

curl -fsS "http://127.0.0.1:$port/metrics" >"$metrics_txt"
grep 'registry_notary_openfn_sidecar_lookup_total{source_id="dhis2_org_units",outcome="batch_success"}' "$metrics_txt" >/dev/null

for secret in "$dhis2_password" "$sidecar_token" "dhis2-canary-correlation"; do
  if grep -F "$secret" "$response_json" "$metrics_txt" "$log" >/dev/null 2>&1; then
    printf 'secret-like value leaked in DHIS2 sidecar smoke artifacts\n' >&2
    exit 1
  fi
done

printf 'OpenFn DHIS2 sidecar smoke passed\n'
