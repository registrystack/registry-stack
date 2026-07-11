#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set +x
set +v
set -euo pipefail
umask 077

readonly POSTGRES_IMAGE="postgres:16"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

safe_file_mode() {
  local path="$1"
  local mode
  if mode="$(stat -f '%Lp' -- "$path" 2>/dev/null)"; then
    :
  else
    mode="$(stat -c '%a' -- "$path" 2>/dev/null)" || return 1
  fi
  case "$mode" in
    400|600) return 0 ;;
    *) return 1 ;;
  esac
}

owned_by_current_user() {
  local path="$1"
  local owner
  if owner="$(stat -f '%u' -- "$path" 2>/dev/null)"; then
    :
  else
    owner="$(stat -c '%u' -- "$path" 2>/dev/null)" || return 1
  fi
  [[ "$owner" == "$(id -u)" ]]
}

readonly live_env_file="${REGISTRY_RELAY_LIVE_ENV_FILE:-}"
[[ -n "$live_env_file" ]] || fail \
  "REGISTRY_RELAY_LIVE_ENV_FILE must name the authorized mode-0600 environment file"
[[ -f "$live_env_file" && ! -L "$live_env_file" ]] || fail \
  "REGISTRY_RELAY_LIVE_ENV_FILE must be a regular non-symlink file"
safe_file_mode "$live_env_file" || fail \
  "REGISTRY_RELAY_LIVE_ENV_FILE must have mode 0600 or 0400"
owned_by_current_user "$live_env_file" || fail \
  "REGISTRY_RELAY_LIVE_ENV_FILE must be owned by the current user"

# shellcheck disable=SC1090
source "$live_env_file"
set +x
set +v

[[ -n "${DHIS2_BASE_URL:-}" ]] || fail "DHIS2_BASE_URL is required"
[[ -n "${DHIS2_USERNAME:-}" ]] || fail "DHIS2_USERNAME is required"
[[ -n "${DHIS2_PASSWORD:-}" ]] || fail "DHIS2_PASSWORD is required"
export DHIS2_BASE_URL DHIS2_USERNAME DHIS2_PASSWORD
unset OPENCRVS_DCI_BASE_URL
unset OPENCRVS_DCI_CLIENT_ID
unset OPENCRVS_DCI_CLIENT_SECRET
unset OPENCRVS_DCI_SHA_SECRET

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v docker >/dev/null 2>&1 || fail "Docker is required"
command -v openssl >/dev/null 2>&1 || fail "openssl is required"
docker info >/dev/null 2>&1 || fail "the Docker daemon is unavailable"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "$script_dir/../../.." && pwd)"
readonly repository_root
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/registry-relay-live-dhis2.XXXXXX")"
readonly temporary_root
readonly certificate_input="$temporary_root/certificate-input"
readonly docker_env_file="$temporary_root/postgres.env"
readonly container_name="registry-relay-live-dhis2-${$}-${RANDOM}"
readonly certificate_volume="registry-relay-live-dhis2-certs-${$}-${RANDOM}"

container_started=0
volume_created=0

cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  unset REGISTRY_RELAY_LIVE_POSTGRES_ADMIN_URL
  unset REGISTRY_RELAY_LIVE_POSTGRES_CA_PATH
  unset POSTGRES_PASSWORD
  if [[ "$container_started" == 1 ]]; then
    docker rm --force "$container_name" >/dev/null 2>&1 || true
  fi
  if [[ "$volume_created" == 1 ]]; then
    docker volume rm "$certificate_volume" >/dev/null 2>&1 || true
  fi
  rm -rf "$temporary_root"
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

mkdir -m 700 "$certificate_input"
openssl req \
  -x509 \
  -newkey rsa:3072 \
  -sha256 \
  -nodes \
  -days 1 \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,digitalSignature,keyCertSign' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$certificate_input/server.key" \
  -out "$certificate_input/server.crt" \
  >/dev/null 2>&1 || fail "could not generate the disposable PostgreSQL TLS identity"
chmod 0600 "$certificate_input/server.key"
chmod 0644 "$certificate_input/server.crt"

postgres_password="$(openssl rand -hex 32)" || fail \
  "could not generate the disposable PostgreSQL password"
{
  printf 'POSTGRES_USER=postgres\n'
  printf 'POSTGRES_DB=relay_live\n'
  printf 'POSTGRES_PASSWORD=%s\n' "$postgres_password"
} >"$docker_env_file"
chmod 0600 "$docker_env_file"
unset postgres_password

docker volume create "$certificate_volume" >/dev/null
volume_created=1
docker run --rm \
  --user 0:0 \
  --volume "$certificate_volume:/certificates" \
  --volume "$certificate_input:/input:ro" \
  "$POSTGRES_IMAGE" \
  sh -eu -c \
  'cp /input/server.crt /certificates/server.crt
   cp /input/server.key /certificates/server.key
   chown postgres:postgres /certificates/server.crt /certificates/server.key
   chmod 0644 /certificates/server.crt
   chmod 0600 /certificates/server.key' \
  >/dev/null

docker run --detach \
  --name "$container_name" \
  --env-file "$docker_env_file" \
  --publish 127.0.0.1::5432 \
  --volume "$certificate_volume:/certificates:ro" \
  "$POSTGRES_IMAGE" \
  -c ssl=on \
  -c ssl_cert_file=/certificates/server.crt \
  -c ssl_key_file=/certificates/server.key \
  >/dev/null
container_started=1

ready=0
for _ in $(seq 1 60); do
  if docker exec "$container_name" pg_isready --username postgres --dbname relay_live \
    >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[[ "$ready" == 1 ]] || fail "the disposable PostgreSQL 16 instance did not become ready"

port_mapping="$(docker port "$container_name" 5432/tcp)" || fail \
  "the disposable PostgreSQL port could not be resolved"
postgres_port="${port_mapping##*:}"
[[ "$postgres_port" =~ ^[0-9]+$ ]] || fail \
  "the disposable PostgreSQL port mapping was invalid"

# shellcheck disable=SC1090
source "$docker_env_file"
# shellcheck disable=SC2153
export REGISTRY_RELAY_LIVE_POSTGRES_ADMIN_URL=\
"postgresql://postgres:${POSTGRES_PASSWORD}@127.0.0.1:${postgres_port}/relay_live?sslmode=require"
export REGISTRY_RELAY_LIVE_POSTGRES_CA_PATH="$certificate_input/server.crt"
unset POSTGRES_PASSWORD
unset port_mapping
unset postgres_port

cd "$repository_root"
cargo test \
  --package registry-relay \
  --locked \
  --test live_dhis2_consultation \
  live_dhis2_consultation_lifecycle \
  -- \
  --ignored
