#!/bin/sh
set -eu

crate_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
repo_dir="$(CDPATH= cd -- "$crate_dir/../.." && pwd)"
sidecar_port="${LOAD_HTTP_JSON_SIDECAR_PORT:-19311}"
registry_port="${LOAD_HTTP_JSON_REGISTRY_PORT:-19312}"
scenario="${LOAD_HTTP_JSON_SCENARIO:-lookup}"
batch_mode="${LOAD_HTTP_JSON_BATCH_MODE:-sequential_lookup}"
load_dir="$repo_dir/target/http-json-sidecar-load-$sidecar_port-$registry_port-$scenario-$batch_mode"
manifest="$load_dir/http-json-sidecar-load.yaml"
sidecar_log="$load_dir/sidecar.log"
registry_log="$load_dir/registry.log"
report_json="$load_dir/report.json"
metrics_txt="$load_dir/metrics.txt"
registry_stats_json="$load_dir/registry-stats.json"
sidecar_pid=""
registry_pid=""

sidecar_token="${LOAD_HTTP_JSON_SIDECAR_TOKEN:-load-sidecar-token}"
target_token="${LOAD_HTTP_JSON_TARGET_TOKEN:-load-target-token}"
target_delay_ms="${LOAD_HTTP_JSON_TARGET_DELAY_MS:-2}"
target_jitter_ms="${LOAD_HTTP_JSON_TARGET_JITTER_MS:-2}"
max_workers="${LOAD_HTTP_JSON_MAX_WORKERS:-32}"
max_in_flight="${LOAD_HTTP_JSON_MAX_IN_FLIGHT:-32}"
max_parallel="${LOAD_HTTP_JSON_MAX_PARALLEL:-8}"
requests_per_second="${LOAD_HTTP_JSON_REQUESTS_PER_SECOND:-}"
burst="${LOAD_HTTP_JSON_BURST:-}"
cache_block="${LOAD_HTTP_JSON_CACHE_BLOCK:-}"
release="${LOAD_HTTP_JSON_RELEASE:-0}"

case "$scenario" in
  lookup | cache)
    driver_scenario="$scenario"
    ;;
  batch)
    driver_scenario="batch"
    ;;
  *)
    printf 'LOAD_HTTP_JSON_SCENARIO must be lookup, cache, or batch\n' >&2
    exit 2
    ;;
esac

case "$batch_mode" in
  sequential_lookup | parallel_lookup | native_batch)
    ;;
  *)
    printf 'LOAD_HTTP_JSON_BATCH_MODE must be sequential_lookup, parallel_lookup, or native_batch\n' >&2
    exit 2
    ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  sidecar_token_digest="$(printf '%s' "$sidecar_token" | sha256sum | awk '{print $1}')"
else
  sidecar_token_digest="$(printf '%s' "$sidecar_token" | shasum -a 256 | awk '{print $1}')"
fi
sidecar_token_hash="sha256:$sidecar_token_digest"

rm -rf "$load_dir"
mkdir -p "$load_dir"

limits_extra=""
if [ -n "$requests_per_second" ]; then
  limits_extra="$limits_extra
      requests_per_second: $requests_per_second"
fi
if [ -n "$burst" ]; then
  limits_extra="$limits_extra
      burst: $burst"
fi

cache_yaml=""
if [ "$scenario" = "cache" ]; then
  cache_yaml="
    cache:
      exact_match_ttl_ms: 60000
      not_found_ttl_ms: 60000"
elif [ -n "$cache_block" ]; then
  cache_yaml="$cache_block"
fi

batch_yaml=""
if [ "$driver_scenario" = "batch" ]; then
  if [ "$batch_mode" = "parallel_lookup" ]; then
    batch_yaml="
    batch:
      mode: parallel_lookup
      max_parallel: $max_parallel"
  elif [ "$batch_mode" = "native_batch" ]; then
    batch_yaml="
    batch:
      mode: native_batch"
  fi
fi

native_batch_yaml=""
if [ "$driver_scenario" = "batch" ] && [ "$batch_mode" = "native_batch" ]; then
  native_batch_yaml="
      batch:
        method: POST
        path: \"/native\"
        response:
          records:
            cel: body.results
          record_key:
            cel: record.national_id
          item_key:
            cel: item.values[0]"
fi

cat >"$manifest" <<YAML
server:
  bind: "127.0.0.1:$sidecar_port"
auth:
  bearer_tokens:
    - id: notary
      hash_env: LOAD_HTTP_JSON_SIDECAR_TOKEN_HASH
limits:
  max_workers: $max_workers
  worker_timeout_ms: 10000
  max_worker_memory_mb: 512
  max_output_bytes: 1048576
  max_request_bytes: 65536
  max_query_parameter_bytes: 2048
  liveness_window_ms: 30000
  retry_after_seconds: 1
  max_batch_items: 200
  batch_timeout_ms: 30000
sources:
  http_people:
    engine: http_json
    dataset: civil_registry
    entity: civil_person
    credential_env: LOAD_HTTP_JSON_CREDENTIAL_JSON
    credential_public_fields:
      - baseUrl
    allowed_base_urls:
      - "http://127.0.0.1:$registry_port"
    allow_insecure_localhost: true$batch_yaml$cache_yaml
    limits:
      max_in_flight: $max_in_flight$limits_extra
    http_json:
      method: GET
      base_url:
        cel: credential_public.baseUrl
      path: "/people"
      query:
        id:
          cel: lookup.value
      auth:
        type: bearer
        token:
          secret: apiToken
      response:
        records:
          cel: body.results$native_batch_yaml
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields: ["national_id", "birth_date"]
      purpose: startup-readiness-smoke
YAML

redact_log() {
  if [ -f "$sidecar_log" ]; then
    sed \
      -e "s/$sidecar_token/[REDACTED_SIDECAR_TOKEN]/g" \
      -e "s/$target_token/[REDACTED_TARGET_TOKEN]/g" \
      "$sidecar_log"
  fi
}

export LOAD_HTTP_JSON_TARGET_TOKEN="$target_token"
export LOAD_HTTP_JSON_TARGET_DELAY_MS="$target_delay_ms"
export LOAD_HTTP_JSON_TARGET_JITTER_MS="$target_jitter_ms"
export LOAD_HTTP_JSON_REGISTRY_PORT="$registry_port"
node "$crate_dir/scripts/load-http-json-mock-registry.mjs" >"$registry_log" 2>&1 &
registry_pid="$!"

cleanup() {
  if [ -n "$sidecar_pid" ]; then
    kill "$sidecar_pid" >/dev/null 2>&1 || true
    wait "$sidecar_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$registry_pid" ]; then
    kill "$registry_pid" >/dev/null 2>&1 || true
    wait "$registry_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

ready=0
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$registry_port/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$registry_pid" >/dev/null 2>&1; then
    cat "$registry_log"
    exit 1
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  cat "$registry_log"
  exit 1
fi

export LOAD_HTTP_JSON_SIDECAR_TOKEN_HASH="$sidecar_token_hash"
export LOAD_HTTP_JSON_CREDENTIAL_JSON="{\"baseUrl\":\"http://127.0.0.1:$registry_port\",\"apiToken\":\"$target_token\"}"
cargo_args="run -p registry-notary-openfn-sidecar --bin registry-notary-openfn-sidecar"
if [ "$release" = "1" ]; then
  cargo_args="run --release -p registry-notary-openfn-sidecar --bin registry-notary-openfn-sidecar"
fi
cargo $cargo_args -- \
  --config "$manifest" \
  --allow-unsigned-dev-config >"$sidecar_log" 2>&1 &
sidecar_pid="$!"

ready=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$sidecar_port/ready" >/dev/null 2>&1; then
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

LOAD_HTTP_JSON_SIDECAR_URL="http://127.0.0.1:$sidecar_port" \
LOAD_HTTP_JSON_SIDECAR_TOKEN="$sidecar_token" \
LOAD_HTTP_JSON_SCENARIO="$driver_scenario" \
node "$crate_dir/scripts/load-http-json-sidecar.mjs" >"$report_json"

curl -fsS "http://127.0.0.1:$sidecar_port/metrics" >"$metrics_txt"
curl -fsS "http://127.0.0.1:$registry_port/stats" >"$registry_stats_json"

if [ "$scenario" = "cache" ]; then
  grep 'registry_notary_openfn_sidecar_lookup_total{source_id="http_people",outcome="source_cache_hit"}' "$metrics_txt" >/dev/null
fi

for secret in "$sidecar_token" "$target_token"; do
  if grep -F "$secret" "$report_json" "$metrics_txt" "$sidecar_log" "$registry_log" >/dev/null 2>&1; then
    printf 'secret-like value leaked in load-test artifacts\n' >&2
    exit 1
  fi
done

printf 'http_json sidecar load test passed\n'
printf 'report: %s\n' "$report_json"
cat "$report_json"
