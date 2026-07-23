#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set +x
set +v
set -euo pipefail
umask 077

readonly POSTGRES_IMAGE="postgres:16-trixie@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20"

[[ "$#" -le 1 ]] || {
  printf '%s\n' "usage: $0 [dhis2|rhai|synthetic]" >&2
  exit 1
}
readonly product="${1:-dhis2}"
case "$product" in
  dhis2)
    readonly test_name="live_dhis2_consultation_lifecycle"
    readonly temporary_label="dhis2"
    ;;
  rhai)
    readonly test_name="live_dhis2_script_consultation_lifecycle"
    readonly temporary_label="dhis2-rhai"
    ;;
  synthetic)
    readonly test_name="synthetic_snapshot_exact_consultation_lifecycle"
    readonly temporary_label="synthetic-snapshot"
    ;;
  *)
    printf '%s\n' "usage: $0 [dhis2|rhai|synthetic]" >&2
    exit 1
    ;;
esac

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

if [[ "$product" == "dhis2" ]]; then
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

  case "$product" in
    dhis2)
      [[ -n "${DHIS2_BASE_URL:-}" ]] || fail "DHIS2_BASE_URL is required"
      [[ -n "${DHIS2_USERNAME:-}" ]] || fail "DHIS2_USERNAME is required"
      [[ -n "${DHIS2_PASSWORD:-}" ]] || fail "DHIS2_PASSWORD is required"
      selected_base_url="$DHIS2_BASE_URL"
      selected_principal="$DHIS2_USERNAME"
      selected_secret="$DHIS2_PASSWORD"
      ;;
  esac

  unset DHIS2_BASE_URL DHIS2_USERNAME DHIS2_PASSWORD
  unset OPENCRVS_DCI_BASE_URL OPENCRVS_DCI_CLIENT_ID
  unset OPENCRVS_DCI_CLIENT_SECRET OPENCRVS_DCI_SHA_SECRET
  case "$product" in
    dhis2)
      export DHIS2_BASE_URL="$selected_base_url"
      export DHIS2_USERNAME="$selected_principal"
      export DHIS2_PASSWORD="$selected_secret"
      ;;
  esac
  unset selected_base_url selected_principal selected_secret
fi

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v docker >/dev/null 2>&1 || fail "Docker is required"
command -v openssl >/dev/null 2>&1 || fail "openssl is required"
docker info >/dev/null 2>&1 || fail "the Docker daemon is unavailable"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "$script_dir/../../.." && pwd)"
readonly repository_root
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/registry-relay-live-${temporary_label}.XXXXXX")"
readonly temporary_root
readonly certificate_input="$temporary_root/certificate-input"
readonly docker_env_file="$temporary_root/postgres.env"
readonly rhai_test_env_file="$temporary_root/rhai-test.env"
readonly container_name="registry-relay-live-${temporary_label}-${$}-${RANDOM}"
readonly certificate_volume="registry-relay-live-${temporary_label}-certs-${$}-${RANDOM}"
readonly network_name="registry-relay-live-${temporary_label}-network-${$}-${RANDOM}"

container_started=0
volume_created=0
network_created=0

cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  unset REGISTRY_RELAY_LIVE_POSTGRES_ADMIN_URL
  unset REGISTRY_RELAY_LIVE_POSTGRES_CA_PATH
  unset POSTGRES_PASSWORD
  unset DHIS2_BASE_URL DHIS2_USERNAME DHIS2_PASSWORD
  unset OPENCRVS_DCI_BASE_URL OPENCRVS_DCI_CLIENT_ID
  unset OPENCRVS_DCI_CLIENT_SECRET OPENCRVS_DCI_SHA_SECRET
  if [[ "$container_started" == 1 ]]; then
    docker rm --force "$container_name" >/dev/null 2>&1 || true
  fi
  if [[ "$volume_created" == 1 ]]; then
    docker volume rm "$certificate_volume" >/dev/null 2>&1 || true
  fi
  if [[ "$network_created" == 1 ]]; then
    docker network rm "$network_name" >/dev/null 2>&1 || true
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
  -subj '/CN=registry-relay-live-root' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$certificate_input/ca.key" \
  -out "$certificate_input/ca.crt" \
  >/dev/null 2>&1 || fail "could not generate the disposable TLS root"
openssl req \
  -new \
  -newkey rsa:3072 \
  -sha256 \
  -nodes \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,DNS:host.docker.internal,DNS:rhai-runner,IP:127.0.0.1' \
  -keyout "$certificate_input/server.key" \
  -out "$certificate_input/server.csr" \
  >/dev/null 2>&1 || fail "could not generate the disposable TLS identity request"
openssl x509 \
  -req \
  -in "$certificate_input/server.csr" \
  -CA "$certificate_input/ca.crt" \
  -CAkey "$certificate_input/ca.key" \
  -CAcreateserial \
  -days 1 \
  -sha256 \
  -copy_extensions copy \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n') \
  -out "$certificate_input/server.crt" \
  >/dev/null 2>&1 || fail "could not sign the disposable TLS identity"
chmod 0600 "$certificate_input/ca.key"
chmod 0644 "$certificate_input/ca.crt"
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
docker network create "$network_name" >/dev/null
network_created=1
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
if [[ "$product" == "rhai" ]]; then
  {
    printf 'CARGO_TARGET_DIR=/target\n'
    printf 'REGISTRY_RELAY_LIVE_POSTGRES_ADMIN_URL=postgresql://postgres:%s@host.docker.internal:%s/relay_live?sslmode=require\n' \
      "$POSTGRES_PASSWORD" "$postgres_port"
    printf 'REGISTRY_RELAY_LIVE_POSTGRES_CA_PATH=/live-postgres-ca/ca.crt\n'
    printf 'REGISTRY_RELAY_LIVE_RELAY_BINARY=/target/debug/registry-relay\n'
    printf 'REGISTRY_RELAY_LIVE_REGISTRYCTL_BINARY=/target/debug/registryctl\n'
    printf 'REGISTRY_RELAY_LIVE_SOURCE_CERT_PATH=/live-postgres-ca/server.crt\n'
    printf 'REGISTRY_RELAY_LIVE_SOURCE_KEY_PATH=/live-postgres-ca/server.key\n'
  } >"$rhai_test_env_file"
  chmod 0600 "$rhai_test_env_file"
else
  # shellcheck disable=SC2153
  export REGISTRY_RELAY_LIVE_POSTGRES_ADMIN_URL="postgresql://postgres:${POSTGRES_PASSWORD}@127.0.0.1:${postgres_port}/relay_live?sslmode=require"
  export REGISTRY_RELAY_LIVE_POSTGRES_CA_PATH="$certificate_input/ca.crt"
fi
unset POSTGRES_PASSWORD
unset port_mapping
unset postgres_port

cd "$repository_root"
if [[ "$product" == "rhai" ]]; then
  docker run --rm \
    --add-host host.docker.internal:host-gateway \
    --network "$network_name" \
    --network-alias rhai-runner \
    --env-file "$rhai_test_env_file" \
    --volume "$repository_root:/workspace" \
    --volume "$certificate_input:/live-postgres-ca:ro" \
    --volume "$HOME/.cargo/registry:/usr/local/cargo/registry" \
    --volume "$HOME/.cargo/git:/usr/local/cargo/git" \
    --volume registry-relay-linux-target:/target \
    --workdir /workspace \
    rust:1.95-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 \
    sh -eu -c \
    'cp /live-postgres-ca/ca.crt /usr/local/share/ca-certificates/registry-live-source.crt
     update-ca-certificates >/dev/null 2>&1
     cargo build --locked --package registry-relay --bin registry-relay --bin registry-relay-rhai-worker --package registryctl --bin registryctl
     cargo test --locked --package registry-relay --test live_consultation_journeys live_dhis2_script_consultation_lifecycle -- --ignored'
else
  cargo test \
    --package registry-relay \
    --locked \
    --test live_consultation_journeys \
    "$test_name" \
    -- \
    --ignored
fi
