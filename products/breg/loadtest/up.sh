#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
product_dir=$(cd -- "$loadtest_dir/.." && pwd)
repository_root=$(cd -- "$product_dir/../.." && pwd)
support="$loadtest_dir/support/loadenv.py"
run_dir="$loadtest_dir/.run"
fixture="$product_dir/acceptance/business-establishments"
mint_key_material="$repository_root/crates/registry-mint/demo/support/key_material.py"
postgres_image='postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675'
pool_max=32
keep=false

cleanup_failed_start() {
  local status=$?
  if [[ "$status" -ne 0 && -f "$run_dir/env.json" ]]; then
    printf '%s\n' 'Load-test startup failed; stopping resources started by this environment.' >&2
    "$loadtest_dir/down.sh" >/dev/null 2>&1 ||
      printf '%s\n' "Automatic cleanup failed; inspect $run_dir and run down.sh." >&2
  fi
  exit "$status"
}
trap cleanup_failed_start EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pool-max)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
        printf '%s\n' '--pool-max requires a number.' >&2
        exit 2
      fi
      pool_max="$2"
      shift 2
      ;;
    --keep)
      keep=true
      shift
      ;;
    *)
      printf '%s\n' "usage: products/breg/loadtest/up.sh [--pool-max N] [--keep]" >&2
      exit 2
      ;;
  esac
done

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "$1 is required for the Base Registry Engine load-test environment." >&2
    exit 2
  fi
}

for command in cargo docker openssl python3 uv; do
  require_command "$command"
done

if [[ -e "$run_dir/env.json" ]]; then
  printf '%s\n' "A load-test environment is already recorded at $run_dir/env.json." >&2
  printf '%s\n' "Run products/breg/loadtest/down.sh before starting another one." >&2
  exit 2
fi
if [[ -L "$run_dir" ]]; then
  printf '%s\n' 'load-test run directory must not be a symbolic link.' >&2
  exit 2
fi
if [[ -d "$run_dir" ]]; then
  rm -rf -- "$run_dir"
elif [[ -e "$run_dir" ]]; then
  printf '%s\n' 'load-test run path exists and is not a directory.' >&2
  exit 2
fi
umask 077
mkdir -m 700 "$run_dir" "$run_dir/secrets" "$run_dir/keys" "$run_dir/logs" "$run_dir/tls"

ports=$(python3 "$support" ports)
read -r database_port mint_port breg_port metrics_port <<EOF
$ports
EOF

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

printf '%s\n' '== Building Base Registry Engine, its CLI, and Mint'
cargo build --manifest-path "$repository_root/Cargo.toml" --locked \
  -p registry-breg --features registry-breg/runtime \
  -p registry-bregctl \
  -p registry-mint \
  --bins >/dev/null

breg="$repository_root/target/debug/breg"
bregctl="$repository_root/target/debug/bregctl"
mint="$repository_root/target/debug/mint"
container="breg-loadtest-${PPID}-$$"

printf '%s\n' '== Preparing the local business-establishments project'
python3 "$support" local-project --fixture "$fixture" --project "$run_dir/project"
"$bregctl" --format json check "$run_dir/project" >"$run_dir/check-report.json"

printf '%s\n' '== Generating disposable local keys and configuration'
uv run --quiet "$mint_key_material" p256 \
  --private-out "$run_dir/keys/mint/signing-p256-private-jwk" \
  --public-out "$run_dir/keys/mint-public.jwk.json"
uv run --quiet "$mint_key_material" p256 \
  --private-out "$run_dir/keys/operator/signing-p256-private-jwk" \
  --public-out "$run_dir/keys/operator-public.jwk.json"
uv run --quiet "$mint_key_material" secret-hex \
  --out "$run_dir/keys/mint/audit-hmac-key"
uv run --quiet "$mint_key_material" secret-hex \
  --out "$run_dir/secrets/audit-key"
uv run --quiet "$mint_key_material" secret-hex \
  --out "$run_dir/secrets/cursor-key"
openssl rand -hex 24 >"$run_dir/secrets/database-password"
chmod 600 "$run_dir/secrets/database-password"

driver_secret_fingerprint=$("$mint" client-secret generate --out "$run_dir/secrets/driver-client-secret")
chmod 600 "$run_dir/secrets/driver-client-secret"

python3 "$support" prepare \
  --root "$run_dir" \
  --database-port "$database_port" \
  --mint-port "$mint_port" \
  --breg-port "$breg_port" \
  --metrics-port "$metrics_port" \
  --driver-secret-fingerprint "$driver_secret_fingerprint" \
  --pool-max "$pool_max"

openssl req -x509 -new -nodes -newkey rsa:2048 -sha256 -days 2 \
  -subj '/CN=Base Registry Engine load-test CA' \
  -keyout "$run_dir/tls/ca.key" -out "$run_dir/tls/ca.pem" >/dev/null 2>&1
openssl req -new -nodes -newkey rsa:2048 \
  -subj '/CN=localhost' \
  -keyout "$run_dir/tls/server.key" -out "$run_dir/tls/server.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:localhost' >"$run_dir/tls/server.ext"
openssl x509 -req -sha256 -days 2 \
  -in "$run_dir/tls/server.csr" \
  -CA "$run_dir/tls/ca.pem" \
  -CAkey "$run_dir/tls/ca.key" \
  -CAcreateserial \
  -extfile "$run_dir/tls/server.ext" \
  -out "$run_dir/tls/server.crt" >/dev/null 2>&1
chmod 600 "$run_dir/tls/ca.key" "$run_dir/tls/server.key"
chmod 644 "$run_dir/tls/ca.pem" "$run_dir/tls/server.crt"

# Record every cleanup target before the first external resource starts. If a
# later startup step fails, the EXIT trap can safely drive the ordinary
# teardown path instead of leaving a container or reused PID behind.
python3 - "$run_dir" "$container" "$database_port" "$mint_port" "$breg_port" "$metrics_port" "$pool_max" "$keep" <<'PY'
import json
import sys
from pathlib import Path

run_dir, container, database_port, mint_port, breg_port, metrics_port, pool_max, keep = sys.argv[1:]
environment = {
    "breg_url": f"http://127.0.0.1:{breg_port}",
    "metrics_url": f"http://127.0.0.1:{metrics_port}/metrics",
    "token_url": f"http://127.0.0.1:{mint_port}/token",
    "database": {
        "container": container,
        "port": database_port,
        "user": "registry_loadtest_runtime",
        "database": "business_loadtest",
        "password_file": str(Path(run_dir) / "secrets/business_loadtest-runtime-database-url"),
    },
    "driver_client_id": "loadtest-driver",
    "driver_secret": str(Path(run_dir) / "secrets/driver-client-secret"),
    "operator_key": str(Path(run_dir) / "keys/operator/signing-p256-private-jwk"),
    "pool_max": int(pool_max),
    "keep": keep == "True" or keep == "true",
    "run_dir": str(Path(run_dir)),
}
(Path(run_dir) / "env.json").write_text(json.dumps(environment, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

printf '%s\n' '== Starting disposable PostgreSQL 17 with TLS and pg_stat_statements'
docker run --detach --name "$container" \
  --label org.registrystack.loadtest=breg \
  --env-file "$run_dir/database/postgres.env" \
  --publish "127.0.0.1:${database_port}:5432" \
  "$postgres_image" \
  -c shared_preload_libraries=pg_stat_statements >"$run_dir/postgres-container-id"

for attempt in $(seq 1 120); do
  if [[ "$(docker exec "$container" cat /proc/1/comm)" == postgres ]] &&
    docker exec "$container" pg_isready -q -U postgres; then
    break
  fi
  if [[ "$attempt" -eq 120 ]]; then
    printf '%s\n' "PostgreSQL did not become ready; see $run_dir/logs." >&2
    docker rm -f "$container" >/dev/null 2>&1 || true
    exit 1
  fi
  sleep 0.25
done

postgres_data_directory=$(docker exec "$container" sh -c 'printf %s "$PGDATA"')
case "$postgres_data_directory" in
  /var/lib/postgresql/*) ;;
  *)
    printf '%s\n' 'PostgreSQL reported an unsafe data directory.' >&2
    docker rm -f "$container" >/dev/null 2>&1 || true
    exit 1
    ;;
esac
docker cp "$run_dir/tls/server.crt" "$container:$postgres_data_directory/server.crt"
docker cp "$run_dir/tls/server.key" "$container:$postgres_data_directory/server.key"
docker exec --user root "$container" sh -eu -c '
  chown postgres:postgres "$1/server.crt" "$1/server.key"
  chmod 644 "$1/server.crt"
  chmod 600 "$1/server.key"
  printf "\nssl = on\nssl_cert_file = '\''server.crt'\''\nssl_key_file = '\''server.key'\''\n" >> "$1/postgresql.conf"
  sed -i "s/^host /hostssl /" "$1/pg_hba.conf"
' sh "$postgres_data_directory"
docker exec --user postgres "$container" \
  pg_ctl -D "$postgres_data_directory" reload >/dev/null

docker exec -i "$container" psql -v ON_ERROR_STOP=1 -q -U postgres -d postgres \
  <"$run_dir/database/bootstrap.sql"
docker exec "$container" createdb -U postgres business_loadtest_test
docker exec "$container" createdb -U postgres business_loadtest
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -q -U postgres -d business_loadtest_test \
  <"$run_dir/database/initialize.sql"
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -q -U postgres -d business_loadtest \
  <"$run_dir/database/initialize-runtime.sql"

printf '%s\n' '== Starting Registry Mint (background)'
nohup "$mint" serve --config "$run_dir/mint/mint.yaml" \
  >"$run_dir/logs/mint.log" 2>&1 &
echo $! >"$run_dir/mint.pid"
python3 "$support" wait-http --url "http://127.0.0.1:${mint_port}/ready" --timeout 30

"$mint" token \
  --url "http://127.0.0.1:${mint_port}/token" \
  --client-id loadtest-operator \
  --key "$run_dir/keys/operator/signing-p256-private-jwk" |
  python3 "$support" store-token --out "$run_dir/secrets/operator-token"
"$mint" token \
  --url "http://127.0.0.1:${mint_port}/token" \
  --client-id loadtest-no-purpose \
  --key "$run_dir/keys/operator/signing-p256-private-jwk" |
  python3 "$support" store-token --out "$run_dir/secrets/no-purpose-token"

printf '%s\n' '== Testing, packaging, and activating the local Registry'
export SSL_CERT_FILE="$run_dir/tls/ca.pem"
"$bregctl" --format json test "$run_dir/project" \
  --runtime-config "$run_dir/runtime-test.yaml" \
  --credentials "$run_dir/schema-test-credentials.yaml" \
  --database-id business-establishments-loadtest \
  --output "$run_dir/schema-test-receipt.json" \
  >"$run_dir/test-report.json"
schema_fingerprint=$(python3 "$support" json-field --path "$run_dir/test-report.json" --field schemaFingerprint)

"$bregctl" --format json package "$run_dir/project" \
  --database-id business-establishments-loadtest \
  --schema-fingerprint "$schema_fingerprint" \
  --test-receipt "$run_dir/schema-test-receipt.json" \
  --output "$run_dir/build" \
  >"$run_dir/package-report.json"
package_revision=$(python3 "$support" json-field --path "$run_dir/package-report.json" --field packageRevision)
python3 "$support" render-runtime --root "$run_dir" --revision "$package_revision" --pool-max "$pool_max"

"$bregctl" apply \
  --runtime-config "$run_dir/runtime.yaml" \
  --package "$run_dir/build/package" \
  --initial >/dev/null
"$bregctl" verify --runtime-config "$run_dir/runtime.yaml" >/dev/null

printf '%s\n' '== Starting Base Registry Engine on loopback (background, metrics enabled)'
BREG_LOG=info nohup "$breg" --config "$run_dir/runtime.yaml" \
  >"$run_dir/logs/breg.log" 2>&1 &
echo $! >"$run_dir/breg.pid"
python3 "$support" wait-http --url "http://127.0.0.1:${breg_port}/ready" --timeout 30
python3 "$support" wait-http --url "http://127.0.0.1:${metrics_port}/metrics" --timeout 30

printf '\n%s\n' 'Base Registry Engine load-test environment is ready.'
printf '  Base Registry Engine:  http://127.0.0.1:%s\n' "$breg_port"
printf '  Metrics:          http://127.0.0.1:%s/metrics\n' "$metrics_port"
printf '  Registry Mint:    http://127.0.0.1:%s\n' "$mint_port"
printf '  Database:         127.0.0.1:%s (container %s)\n' "$database_port" "$container"
printf '  Pool max size:    %s\n' "$pool_max"
printf '  Environment:      %s\n' "$run_dir/env.json"
printf '  Seed next:        products/breg/loadtest/seed.py --count 100000\n'
printf '  Then run:         products/breg/loadtest/run.sh --profile steady\n'
printf '  Tear down with:   products/breg/loadtest/down.sh\n'

if [[ "$keep" == true ]]; then
  printf '%s\n' 'Note: --keep only records the environment for down.sh; data is not persisted across down/up cycles.'
fi
trap - EXIT
