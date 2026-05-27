#!/bin/sh
set -eu

sidecar_port="${OPENFN_HTTP_DEMO_SIDECAR_PORT:-19191}"
registry_port="${OPENFN_HTTP_DEMO_REGISTRY_PORT:-19192}"
crate_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
repo_dir="$(CDPATH= cd -- "$crate_dir/../.." && pwd)"
demo_dir="$repo_dir/target/openfn-http-demo-$sidecar_port-$registry_port"
sidecar_pid_file="$demo_dir/sidecar.pid"
registry_pid_file="$demo_dir/registry.pid"

stop_pid() {
  pid_file="$1"
  if [ ! -f "$pid_file" ]; then
    return
  fi
  pid="$(cat "$pid_file")"
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
  rm -f "$pid_file"
}

mode="${1:-start}"
case "$mode" in
  start)
    ;;
  foreground)
    ;;
  stop)
    stop_pid "$sidecar_pid_file"
    stop_pid "$registry_pid_file"
    printf 'OpenFn HTTP demo stopped\n'
    exit 0
    ;;
  *)
    printf 'usage: %s [start|foreground|stop]\n' "$0" >&2
    exit 2
    ;;
esac

mkdir -p "$demo_dir"
stop_pid "$sidecar_pid_file"
stop_pid "$registry_pid_file"

worker="$demo_dir/openfn_worker.mjs"
manifest="$demo_dir/openfn-http-sidecar.yaml"
sidecar_log="$demo_dir/sidecar.log"
registry_log="$demo_dir/registry.log"

cp "$crate_dir/workers/openfn_worker.mjs" "$worker"
cat >"$demo_dir/package.json" <<'JSON'
{
  "private": true,
  "type": "module",
  "dependencies": {
    "@openfn/compiler": "1.2.5",
    "@openfn/runtime": "1.9.3",
    "@openfn/language-common": "3.2.3",
    "@openfn/language-http": "7.2.0"
  }
}
JSON
npm install --prefix "$demo_dir" --ignore-scripts --no-audit --no-fund >/dev/null

cat >"$manifest" <<YAML
server:
  bind: "127.0.0.1:$sidecar_port"
auth:
  bearer_tokens:
    - id: witness
      hash_env: DEV_SIDECAR_TOKEN_HASH
limits:
  max_workers: 2
  worker_timeout_ms: 10000
  max_worker_memory_mb: 12288
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
    - "--require-adaptor"
    - "@openfn/language-http@7.2.0"
sources:
  http_people:
    dataset: civil_registry
    entity: civil_person
    workflow:
      start: prepare_request
      steps:
        - id: prepare_request
          expression: "$crate_dir/examples/jobs/http-prepare-person-request.js"
          adaptors:
            - "@openfn/language-common@3.2.3"
          next:
            fetch_person: true
        - id: fetch_person
          expression: "$crate_dir/examples/jobs/http-fetch-person.js"
          adaptors:
            - "@openfn/language-http@7.2.0"
          next:
            normalize_response: true
        - id: normalize_response
          expression: "$crate_dir/examples/jobs/http-normalize-person-response.js"
          adaptors:
            - "@openfn/language-common@3.2.3"
    credential_env: OPENFN_HTTP_DEMO_CREDENTIAL_JSON
    allowed_base_urls:
      - "http://127.0.0.1:$registry_port"
    smoke_lookup:
      field: national_id
      value: person-123
      fields: ["national_id", "birth_date"]
      purpose: startup-readiness-smoke
YAML

nohup env \
  MOCK_REGISTRY_PORT="$registry_port" \
  MOCK_REGISTRY_TOKEN="demo-target-token" \
  node "$crate_dir/examples/mock-registry-server.mjs" >"$registry_log" 2>&1 &
registry_pid="$!"
printf '%s\n' "$registry_pid" >"$registry_pid_file"

ready=0
for _ in $(seq 1 30); do
  if curl -fsS -H "Authorization: Bearer demo-target-token" "http://127.0.0.1:$registry_port/people/person-123" >/dev/null 2>&1; then
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

export OPENFN_HTTP_DEMO_CREDENTIAL_JSON="{\"baseUrl\":\"http://127.0.0.1:$registry_port\",\"apiToken\":\"demo-target-token\"}"
export DEV_SIDECAR_TOKEN_HASH='sha256:a61cb2a28977890d2e95d2eb9f5355b184d48dc2aec23252bdeb08eca7f42544'
nohup cargo run -p registry-witness-openfn-sidecar --bin registry-witness-openfn-sidecar -- --config "$manifest" >"$sidecar_log" 2>&1 &
sidecar_pid="$!"
printf '%s\n' "$sidecar_pid" >"$sidecar_pid_file"

ready=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$sidecar_port/ready" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$sidecar_pid" >/dev/null 2>&1; then
    cat "$sidecar_log"
    exit 1
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  cat "$sidecar_log"
  exit 1
fi

printf 'OpenFn HTTP sidecar demo is running\n'
printf 'RDA endpoint: http://127.0.0.1:%s/datasets/civil_registry/civil_person\n' "$sidecar_port"
printf '\nTry:\n'
printf 'curl -sS -H "Authorization: Bearer dev-sidecar-token" -H "Data-Purpose: demo" "%s" | jq\n' \
  "http://127.0.0.1:$sidecar_port/datasets/civil_registry/civil_person?national_id=person-123&fields=national_id,birth_date&limit=2"
printf '\nStop:\n%s stop\n' "$0"

if [ "$mode" = "foreground" ]; then
  trap 'stop_pid "$sidecar_pid_file"; stop_pid "$registry_pid_file"' INT TERM EXIT
  while kill -0 "$sidecar_pid" >/dev/null 2>&1 && kill -0 "$registry_pid" >/dev/null 2>&1; do
    sleep 1
  done
  cat "$sidecar_log"
  cat "$registry_log"
  exit 1
fi
