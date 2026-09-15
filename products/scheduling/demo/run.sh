#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# The Registry Scheduling local acceptance demo. This script builds the real
# `scheduling` and `schedulingctl` binaries, stands up a disposable
# PostgreSQL database (its own container unless --database-url names one),
# publishes the standalone-exact-time policy with demo environment records,
# serves the runtime on loopback, and drives four acceptance scenarios over
# the public HTTP contract: AT-01 (two-caller race for the last unit),
# AT-05 (hold expiry), AT-06 (lost-confirmation idempotent replay), and
# AT-19 (the daylight-saving fold grid). See README.md beside this script.

demo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$demo_dir/../../.." && pwd)
run_dir="$demo_dir/.run"
support="$demo_dir/support/demo.py"
example="$root/products/scheduling/examples/standalone-exact-time"
database_url=''
database_root_ca=''
installed=false

usage() {
  cat >&2 <<'HELP'
usage: products/scheduling/demo/run.sh [--database-url URL [--database-root-ca PATH]] [--installed]

Run the Scheduling acceptance demo. Without --database-url the script starts
and removes its own TLS-enabled PostgreSQL 17 container, which requires
Docker; the URL form runs against a disposable TLS-enabled database you own
(migrations are applied and its data is replaced), and --database-root-ca
names the PEM file holding the authority that signed that server's chain.
--installed uses scheduling and schedulingctl from PATH instead of building
from this checkout. Docker, cargo (unless --installed), openssl, python3,
and curl are required. The run directory is kept when a scenario fails, for
inspection.
HELP
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --database-url)
      [[ $# -ge 2 ]] || usage
      database_url="$2"
      shift 2
      ;;
    --database-root-ca)
      [[ $# -ge 2 ]] || usage
      database_root_ca="$2"
      shift 2
      ;;
    --installed) installed=true; shift ;;
    --help|-h) usage ;;
    *) usage ;;
  esac
done
if [[ -n "$database_root_ca" && -z "$database_url" ]]; then
  printf '%s\n' '--database-root-ca applies to --database-url.' >&2
  usage
fi

for command in python3 openssl curl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf '%s is required.\n' "$command" >&2
    exit 2
  fi
done

if [[ "$installed" == true ]]; then
  scheduling=$(command -v scheduling) || { printf '%s\n' 'scheduling is required in --installed mode.' >&2; exit 2; }
  schedulingctl=$(command -v schedulingctl) || { printf '%s\n' 'schedulingctl is required in --installed mode.' >&2; exit 2; }
else
  command -v cargo >/dev/null 2>&1 || { printf '%s\n' 'cargo is required.' >&2; exit 2; }
  export CARGO_INCREMENTAL=0
  cargo build --manifest-path "$root/Cargo.toml" --locked \
    -p registry-scheduling -p registry-schedulingctl --bins >/dev/null
  scheduling="$root/target/debug/scheduling"
  schedulingctl="$root/target/debug/schedulingctl"
fi

if [[ -e "$run_dir" ]]; then
  printf 'demo state path already exists: %s. Remove it after stopping any session that owns it.\n' "$run_dir" >&2
  exit 2
fi
umask 077
mkdir -m 700 "$run_dir"

container=''

cleanup() {
  exit_code=$?
  [[ -n "${serve_pid:-}" ]] && kill "$serve_pid" >/dev/null 2>&1 || true
  if [[ -n "$container" ]] && command -v docker >/dev/null 2>&1; then
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  if [[ "$exit_code" -eq 0 ]]; then
    rm -rf -- "$run_dir"
  else
    printf 'demo failed; run state kept at %s\n' "$run_dir" >&2
  fi
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

read -r db_port http_port < <(python3 - "$support" <<'PY'
import socket
ports = []
with socket.socket() as first, socket.socket() as second:
    first.bind(("127.0.0.1", 0))
    second.bind(("127.0.0.1", 0))
    ports = [first.getsockname()[1], second.getsockname()[1]]
print(*ports)
PY
)

if [[ -z "$database_root_ca" ]]; then
  root_ca_args=()
else
  root_ca_args=(--database-root-ca "$database_root_ca")
fi
python3 "$support" prepare \
  --root "$run_dir" \
  --example "$example" \
  --database-url "${database_url:-postgres://postgres:demo@127.0.0.1:${db_port}/postgres}" \
  --port "$http_port" \
  "${root_ca_args[@]}"

if [[ -z "$database_url" ]]; then
  command -v docker >/dev/null 2>&1 || { printf '%s\n' 'docker is required without --database-url.' >&2; exit 2; }
  container="scheduling-demo-pg-$$"
  printf 'starting disposable TLS-enabled PostgreSQL on 127.0.0.1:%s\n' "$db_port"
  # The runtime requires TLS to PostgreSQL even locally, so the container
  # serves the demo's own throwaway certificate: the wrapper copies it where
  # the postgres user can read it, then hands off to the stock entrypoint.
  docker run -d --rm --name "$container" \
    -e POSTGRES_PASSWORD=demo \
    -p "127.0.0.1:${db_port}:5432" \
    -v "$run_dir/db-tls:/tls:ro" \
    postgres:17-alpine \
    sh -c 'cp /tls/ca.crt /tls/server.crt /tls/server.key /var/lib/postgresql/ && \
      chown postgres:postgres /var/lib/postgresql/server.crt /var/lib/postgresql/server.key && \
      chmod 600 /var/lib/postgresql/server.key && \
      exec docker-entrypoint.sh postgres \
        -c ssl=on \
        -c ssl_cert_file=/var/lib/postgresql/server.crt \
        -c ssl_key_file=/var/lib/postgresql/server.key' >/dev/null
  # Wait on TCP inside the container, not the unix socket: the stock
  # entrypoint's initdb phase runs a temporary socket-only server, so a
  # socket probe can report ready before the real TLS listener exists.
  ready=false
  for _ in $(seq 1 60); do
    if docker exec "$container" pg_isready -h 127.0.0.1 -p 5432 -U postgres -d postgres >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 1
  done
  if [[ "$ready" != true ]]; then
    printf 'the demo PostgreSQL did not become ready; its logs follow.\n' >&2
    docker logs "$container" >&2 || true
    exit 1
  fi
fi

project="$run_dir/project"
"$schedulingctl" check --deny-findings "$project" >/dev/null
"$schedulingctl" test "$project" >/dev/null
"$schedulingctl" package "$project" >/dev/null
"$scheduling" --runtime-config "$run_dir/runtime.yaml" migrate
"$schedulingctl" records apply "$run_dir/runtime.yaml" "$run_dir/records.yaml" >/dev/null

printf 'serving the Scheduling runtime on 127.0.0.1:%s\n' "$http_port"
"$scheduling" --runtime-config "$run_dir/runtime.yaml" serve >"$run_dir/serve.log" 2>&1 &
serve_pid=$!

ready=false
for _ in $(seq 1 60); do
  if curl --silent --fail --max-time 2 "http://127.0.0.1:${http_port}/readyz" >/dev/null 2>&1; then
    ready=true
    break
  fi
  if ! kill -0 "$serve_pid" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if [[ "$ready" != true ]]; then
  printf 'the runtime did not become ready; the serve log follows.\n' >&2
  cat "$run_dir/serve.log" >&2 || true
  exit 1
fi

python3 "$support" verify \
  --base-url "http://127.0.0.1:${http_port}" \
  --signing-key "$run_dir/demo-signing-key.pem"
