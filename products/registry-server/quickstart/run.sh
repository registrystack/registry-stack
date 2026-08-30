#!/usr/bin/env bash
set -euo pipefail

quickstart_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
product_dir=$(cd -- "$quickstart_dir/.." && pwd)
repository_root=$(cd -- "$product_dir/../.." && pwd)
support="$quickstart_dir/support/quickstart.py"
run_dir="$quickstart_dir/.run"
mint_key_material="$repository_root/crates/registry-mint/demo/support/key_material.py"
postgres_image='postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675'
mode=serve

for argument in "$@"; do
  case "$argument" in
    --smoke)
      if [[ "$mode" == smoke ]]; then
        printf '%s\n' 'the --smoke option may be supplied only once.' >&2
        exit 2
      fi
      mode=smoke
      ;;
    *)
      printf '%s\n' 'usage: products/registry-server/quickstart/run.sh [--smoke]' >&2
      exit 2
      ;;
  esac
done

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "$1 is required for the Registry Server generic quickstart." >&2
    exit 2
  fi
}

for command in cargo docker openssl python3 uv; do
  require_command "$command"
done

case "$run_dir" in
  "$quickstart_dir/.run") ;;
  *)
    printf '%s\n' 'quickstart run directory escaped its owned location.' >&2
    exit 2
    ;;
esac
if [[ -L "$run_dir" ]]; then
  printf '%s\n' 'quickstart run directory must not be a symbolic link.' >&2
  exit 2
fi
if [[ -d "$run_dir" ]]; then
  rm -rf -- "$run_dir"
elif [[ -e "$run_dir" ]]; then
  printf '%s\n' 'quickstart run path exists and is not a directory.' >&2
  exit 2
fi
umask 077
mkdir -m 700 "$run_dir" "$run_dir/secrets" "$run_dir/keys" "$run_dir/logs" "$run_dir/tls"

mint_pid=""
server_pid=""
postgres_container="registry-server-quickstart-${PPID}-$$"
cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${mint_pid:-}" ]]; then
    kill "$mint_pid" >/dev/null 2>&1 || true
    wait "$mint_pid" >/dev/null 2>&1 || true
  fi
  docker rm -f "$postgres_container" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

ports=$(python3 "$support" ports)
read -r database_port mint_port server_port <<EOF
$ports
EOF

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

printf '%s\n' '== Building Registry Server, its CLI, and Mint'
cargo build --manifest-path "$repository_root/Cargo.toml" --locked \
  -p registry-server --features registry-server/runtime \
  -p registry-serverctl \
  -p registry-mint \
  --bins >/dev/null

registry_server="$repository_root/target/debug/registry-server"
registry_serverctl="$repository_root/target/debug/registry-serverctl"
mint="$repository_root/target/debug/mint"

printf '%s\n' '== Initializing and checking a generic Registry project'
"$registry_serverctl" --format json init "$run_dir/project" >"$run_dir/init-report.json"
python3 "$support" assert-canonical-project --project "$run_dir/project"
python3 "$support" enrich-local-package --project "$run_dir/project"
"$registry_serverctl" --format json check "$run_dir/project" >"$run_dir/check-report.json"

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

python3 "$support" prepare \
  --root "$run_dir" \
  --database-port "$database_port" \
  --mint-port "$mint_port" \
  --server-port "$server_port"

openssl req -x509 -new -nodes -newkey rsa:2048 -sha256 -days 2 \
  -subj '/CN=Registry Server generic quickstart CA' \
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

printf '%s\n' '== Starting disposable PostgreSQL 17 with TLS'
docker run --detach --name "$postgres_container" \
  --env-file "$run_dir/database/postgres.env" \
  --publish "127.0.0.1:${database_port}:5432" \
  "$postgres_image" >"$run_dir/postgres-container-id"

for attempt in $(seq 1 120); do
  if [[ "$(docker exec "$postgres_container" cat /proc/1/comm)" == postgres ]] &&
    docker exec "$postgres_container" pg_isready -q -U postgres; then
    break
  fi
  if [[ "$attempt" -eq 120 ]]; then
    printf '%s\n' "PostgreSQL did not become ready; see $run_dir/logs." >&2
    exit 1
  fi
  sleep 0.25
done

postgres_data_directory=$(docker exec "$postgres_container" sh -c 'printf %s "$PGDATA"')
case "$postgres_data_directory" in
  /var/lib/postgresql/*) ;;
  *)
    printf '%s\n' 'PostgreSQL reported an unsafe data directory.' >&2
    exit 1
    ;;
esac
if [[ "$postgres_data_directory" == *..* ]]; then
  printf '%s\n' 'PostgreSQL data directory contains parent traversal.' >&2
  exit 1
fi
docker cp "$run_dir/tls/server.crt" "$postgres_container:$postgres_data_directory/server.crt"
docker cp "$run_dir/tls/server.key" "$postgres_container:$postgres_data_directory/server.key"
docker exec --user root "$postgres_container" sh -eu -c '
  chown postgres:postgres "$1/server.crt" "$1/server.key"
  chmod 644 "$1/server.crt"
  chmod 600 "$1/server.key"
  printf "\nssl = on\nssl_cert_file = '\''server.crt'\''\nssl_key_file = '\''server.key'\''\n" >> "$1/postgresql.conf"
  sed -i "s/^host /hostssl /" "$1/pg_hba.conf"
' sh "$postgres_data_directory"
docker exec --user postgres "$postgres_container" \
  pg_ctl -D "$postgres_data_directory" reload >/dev/null

docker exec -i "$postgres_container" psql -v ON_ERROR_STOP=1 -q -U postgres -d postgres \
  <"$run_dir/database/bootstrap.sql"
docker exec "$postgres_container" createdb -U postgres registry_quickstart_test
docker exec "$postgres_container" createdb -U postgres registry_quickstart
docker exec -i "$postgres_container" psql -v ON_ERROR_STOP=1 -q -U postgres -d registry_quickstart_test \
  <"$run_dir/database/initialize.sql"
docker exec -i "$postgres_container" psql -v ON_ERROR_STOP=1 -q -U postgres -d registry_quickstart \
  <"$run_dir/database/initialize-runtime.sql"

printf '%s\n' '== Starting Registry Mint for local schema-test credentials'
"$mint" serve --config "$run_dir/mint/mint.yaml" >"$run_dir/logs/mint.log" 2>&1 &
mint_pid=$!
python3 "$support" wait-http --url "http://127.0.0.1:${mint_port}/ready" --timeout 30

"$mint" token \
  --url "http://127.0.0.1:${mint_port}/token" \
  --client-id generic-quickstart \
  --key "$run_dir/keys/operator/signing-p256-private-jwk" |
  python3 "$support" store-token --out "$run_dir/secrets/schema-test-token"

printf '%s\n' '== Testing, packaging, and activating the local Registry'
export SSL_CERT_FILE="$run_dir/tls/ca.pem"
"$registry_serverctl" --format json test "$run_dir/project" \
  --runtime-config "$run_dir/runtime-test.yaml" \
  --credentials "$run_dir/schema-test-credentials.yaml" \
  --database-id generic-registry-local-db \
  --output "$run_dir/schema-test-receipt.json" \
  >"$run_dir/test-report.json"
schema_fingerprint=$(python3 "$support" json-field --path "$run_dir/test-report.json" --field schemaFingerprint)

"$registry_serverctl" --format json package "$run_dir/project" \
  --database-id generic-registry-local-db \
  --schema-fingerprint "$schema_fingerprint" \
  --test-receipt "$run_dir/schema-test-receipt.json" \
  --output "$run_dir/build" \
  >"$run_dir/package-report.json"
package_revision=$(python3 "$support" json-field --path "$run_dir/package-report.json" --field packageRevision)
python3 "$support" render-runtime --root "$run_dir" --revision "$package_revision"

"$registry_serverctl" apply \
  --runtime-config "$run_dir/runtime.yaml" \
  --package "$run_dir/build/package" \
  --initial >/dev/null
"$registry_serverctl" verify --runtime-config "$run_dir/runtime.yaml" >/dev/null

printf '%s\n' '== Starting Registry Server on loopback'
REGISTRY_SERVER_LOG=error "$registry_server" --config "$run_dir/runtime.yaml" \
  >"$run_dir/logs/registry-server.log" 2>&1 &
server_pid=$!
python3 "$support" wait-http --url "http://127.0.0.1:${server_port}/ready" --timeout 30

printf '%s\n' '== Obtaining a short-lived operator token from Registry Mint'
"$mint" token \
  --url "http://127.0.0.1:${mint_port}/token" \
  --client-id generic-quickstart \
  --key "$run_dir/keys/operator/signing-p256-private-jwk" |
  python3 "$support" store-token --out "$run_dir/secrets/operator-token"

printf '%s\n' '== Posting and reading one generic record'
created_id=$(python3 "$support" request --root "$run_dir" --action create --code QS-001 --label 'Quickstart example record')
python3 "$support" request --root "$run_dir" --action get --record-id "$created_id" >"$run_dir/created-record.json"

printf '\n%s\n' 'Registry Server generic quickstart is ready.'
printf '  Registry Server: http://127.0.0.1:%s\n' "$server_port"
printf '  Registry Mint:   http://127.0.0.1:%s\n' "$mint_port"
printf '  Project:         %s\n' "$run_dir/project"
printf '  Runtime config:  %s\n' "$run_dir/runtime.yaml"
printf '  Operator token:  %s\n' "$run_dir/secrets/operator-token"
printf '  Created record:  %s\n' "$created_id"
printf '  GET helper:      %s get %s\n' "$quickstart_dir/query.sh" "$created_id"
printf '  Logs:            %s\n' "$run_dir/logs"

if [[ "$mode" == smoke ]]; then
  printf '%s\n' 'Registry Server generic quickstart smoke passed.'
  exit 0
fi

printf '\n%s\n' 'Leave this terminal running. Press Ctrl-C to stop the services.'
while kill -0 "$mint_pid" >/dev/null 2>&1 && kill -0 "$server_pid" >/dev/null 2>&1; do
  sleep 1
done
printf '%s\n' "A quickstart service stopped unexpectedly; inspect $run_dir/logs." >&2
exit 1
