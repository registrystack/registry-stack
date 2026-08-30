#!/usr/bin/env bash
set -euo pipefail

require_env() {
  local name=$1
  if [[ -z "${!name:-}" ]]; then
    printf '%s\n' "$name must be set for the PostgreSQL TLS proof." >&2
    exit 2
  fi
}

require_env REGISTRY_SERVER_TEST_TLS_POSTGRES_CONTAINER_ID
require_env REGISTRY_SERVER_TEST_TLS_DATABASE_URL
require_env REGISTRY_SERVER_TEST_TLS_HOSTNAME_MISMATCH_DATABASE_URL
require_env REGISTRY_SERVER_TEST_TLS_DATABASE_HOST

postgres_container_id=$REGISTRY_SERVER_TEST_TLS_POSTGRES_CONTAINER_ID
database_url=$REGISTRY_SERVER_TEST_TLS_DATABASE_URL
hostname_mismatch_database_url=$REGISTRY_SERVER_TEST_TLS_HOSTNAME_MISMATCH_DATABASE_URL
database_host=$REGISTRY_SERVER_TEST_TLS_DATABASE_HOST
caller_ca_der_path=${REGISTRY_SERVER_TEST_TLS_CA_DER_PATH:-}
caller_ca_pem_path=${REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH:-}

validate_caller_output_path() {
  local name=$1
  local path=$2
  local parent
  local parent_real

  [[ -z "$path" ]] && return 0
  case "$path" in
    /*) ;;
    *)
      printf '%s\n' "$name must be an absolute caller-owned file path." >&2
      exit 2
      ;;
  esac
  case "$path" in
    *$'\n'* | */../* | */..)
      printf '%s\n' "$name must be a lexical file path without parent traversal." >&2
      exit 2
      ;;
  esac
  parent=$(dirname -- "$path")
  if [[ ! -d "$parent" || -L "$parent" ]]; then
    printf '%s\n' "$name parent must be an existing non-symlink directory." >&2
    exit 2
  fi
  parent_real=$(cd -- "$parent" && pwd -P)
  case "$parent_real" in
    / | /tmp | /private/tmp | /var/tmp | /private/var/tmp)
      printf '%s\n' "$name parent must not be a broad shared temporary directory." >&2
      exit 2
      ;;
  esac
  if [[ -L "$path" || ( -e "$path" && ! -f "$path" ) ]]; then
    printf '%s\n' "$name must be a regular file target, not a symlink or directory." >&2
    exit 2
  fi
}

if [[ ! "$postgres_container_id" =~ ^[0-9a-f]{12,64}$ ]]; then
  printf '%s\n' 'REGISTRY_SERVER_TEST_TLS_POSTGRES_CONTAINER_ID must be a Docker container ID.' >&2
  exit 2
fi
if [[ ! "$database_host" =~ ^[A-Za-z0-9.-]+$ ]]; then
  printf '%s\n' 'REGISTRY_SERVER_TEST_TLS_DATABASE_HOST must be a DNS hostname.' >&2
  exit 2
fi
case "$database_url" in
  *"@$database_host:"* | *"@$database_host/"*) ;;
  *)
    printf '%s\n' 'REGISTRY_SERVER_TEST_TLS_DATABASE_URL must use REGISTRY_SERVER_TEST_TLS_DATABASE_HOST.' >&2
    exit 2
    ;;
esac
case "$hostname_mismatch_database_url" in
  *"@127.0.0.1:"* | *"@127.0.0.1/"*) ;;
  *)
    printf '%s\n' 'REGISTRY_SERVER_TEST_TLS_HOSTNAME_MISMATCH_DATABASE_URL must use 127.0.0.1.' >&2
    exit 2
    ;;
esac
validate_caller_output_path REGISTRY_SERVER_TEST_TLS_CA_DER_PATH "$caller_ca_der_path"
validate_caller_output_path REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH "$caller_ca_pem_path"

tls_dir=$(mktemp -d /tmp/registry-server-postgres-tls.XXXXXX)
cleanup() {
  case "${tls_dir:-}" in
    /tmp/registry-server-postgres-tls.*)
      if [[ -d "$tls_dir" && "$(basename -- "$tls_dir")" == registry-server-postgres-tls.* ]]; then
        rm -rf -- "$tls_dir"
      fi
      ;;
  esac
}
trap cleanup EXIT
umask 077

openssl req -x509 -new -nodes -newkey rsa:2048 -sha256 -days 2 \
  -subj '/CN=Registry Server PostgreSQL TLS test CA' \
  -keyout "$tls_dir/trusted-ca.key" -out "$tls_dir/trusted-ca.pem" >/dev/null 2>&1
openssl req -new -nodes -newkey rsa:2048 \
  -subj "/CN=$database_host" \
  -keyout "$tls_dir/server.key" -out "$tls_dir/server.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:%s\n' "$database_host" >"$tls_dir/server.ext"
openssl x509 -req -sha256 -days 2 \
  -in "$tls_dir/server.csr" \
  -CA "$tls_dir/trusted-ca.pem" \
  -CAkey "$tls_dir/trusted-ca.key" \
  -CAcreateserial \
  -extfile "$tls_dir/server.ext" \
  -out "$tls_dir/server.crt" >/dev/null 2>&1
openssl req -x509 -new -nodes -newkey rsa:2048 -sha256 -days 2 \
  -subj '/CN=Registry Server PostgreSQL TLS wrong CA' \
  -keyout "$tls_dir/wrong-ca.key" -out "$tls_dir/wrong-ca.pem" >/dev/null 2>&1
openssl x509 -in "$tls_dir/trusted-ca.pem" -outform DER -out "$tls_dir/trusted-ca.der"
openssl x509 -in "$tls_dir/wrong-ca.pem" -outform DER -out "$tls_dir/wrong-ca.der"
chmod 600 "$tls_dir"/*.key
chmod 644 "$tls_dir"/*.pem "$tls_dir"/*.crt "$tls_dir"/*.der
if [[ -n "$caller_ca_der_path" ]]; then
  caller_ca_der_tmp=$(mktemp "$(dirname -- "$caller_ca_der_path")/.registry-server-postgres-ca-der.XXXXXX")
  cp "$tls_dir/trusted-ca.der" "$caller_ca_der_tmp"
  chmod 644 "$caller_ca_der_tmp"
  mv -f -- "$caller_ca_der_tmp" "$caller_ca_der_path"
fi
if [[ -n "$caller_ca_pem_path" ]]; then
  caller_ca_pem_tmp=$(mktemp "$(dirname -- "$caller_ca_pem_path")/.registry-server-postgres-ca-pem.XXXXXX")
  cp "$tls_dir/trusted-ca.pem" "$caller_ca_pem_tmp"
  chmod 644 "$caller_ca_pem_tmp"
  mv -f -- "$caller_ca_pem_tmp" "$caller_ca_pem_path"
fi

postgres_data_directory=$(docker exec "$postgres_container_id" sh -c 'printf %s "$PGDATA"')
if [[ ! "$postgres_data_directory" =~ ^/var/lib/postgresql/[A-Za-z0-9_./-]+$ || "$postgres_data_directory" == *..* ]]; then
  printf '%s\n' 'PostgreSQL service reported an unsafe PGDATA path.' >&2
  exit 1
fi

docker cp "$tls_dir/server.crt" "$postgres_container_id:$postgres_data_directory/server.crt"
docker cp "$tls_dir/server.key" "$postgres_container_id:$postgres_data_directory/server.key"
docker exec --user root "$postgres_container_id" sh -eu -c '
  chown postgres:postgres "$1/server.crt" "$1/server.key"
  chmod 644 "$1/server.crt"
  chmod 600 "$1/server.key"
  printf "\\nssl = on\\nssl_cert_file = '\''server.crt'\''\\nssl_key_file = '\''server.key'\''\\n" >> "$1/postgresql.conf"
  sed -i "s/^host /hostssl /" "$1/pg_hba.conf"
' sh "$postgres_data_directory"

docker exec --user postgres "$postgres_container_id" \
  pg_ctl -D "$postgres_data_directory" reload >/dev/null
for attempt in {1..30}; do
  if docker exec "$postgres_container_id" pg_isready -q \
    && pg_isready -q -d "$database_url"; then
    break
  fi
  if [[ "$attempt" == 30 ]]; then
    printf '%s\n' 'PostgreSQL service did not become ready after TLS reconfiguration.' >&2
    exit 1
  fi
  sleep 1
done

export REGISTRY_SERVER_TEST_TLS_CA_DER_PATH="${caller_ca_der_path:-$tls_dir/trusted-ca.der}"
export REGISTRY_SERVER_TEST_TLS_WRONG_CA_DER_PATH="$tls_dir/wrong-ca.der"
export REGISTRY_SERVER_TEST_TLS_DATABASE_URL="$database_url"
export REGISTRY_SERVER_TEST_TLS_HOSTNAME_MISMATCH_DATABASE_URL="$hostname_mismatch_database_url"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER=

cargo test --locked -p registry-server --features postgres-tls-test --test postgres_tls
