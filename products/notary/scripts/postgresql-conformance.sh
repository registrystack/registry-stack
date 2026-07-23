#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

postgresql_major="${1:-}"
case "${postgresql_major}" in
  16)
    default_source_image="postgres:16.13-alpine"
    default_target_image="postgres:16.14-alpine"
    default_restore_image="postgres:17.10-alpine"
    restore_major="17"
    ;;
  17)
    default_source_image="postgres:17.9-alpine"
    default_target_image="postgres:17.10-alpine"
    default_restore_image="postgres:18.4-alpine"
    restore_major="18"
    ;;
  18)
    default_source_image="postgres:18.3-alpine"
    default_target_image="postgres:18.4-alpine"
    default_restore_image="postgres:18.4-alpine"
    restore_major="18"
    ;;
  *)
    echo "usage: $0 <16|17|18>" >&2
    exit 2
    ;;
esac

source_image="${NOTARY_POSTGRES_SOURCE_IMAGE:-${default_source_image}}"
target_image="${NOTARY_POSTGRES_TARGET_IMAGE:-${default_target_image}}"
restore_image="${NOTARY_POSTGRES_RESTORE_IMAGE:-${default_restore_image}}"
notary_bin="${NOTARY_BIN:-target/debug/registry-notary}"
run_id="${GITHUB_RUN_ID:-local}-$$"
postgres_container="notary-postgres-conformance-${run_id}"
postgres_data_volume="notary-postgres-data-${run_id}"
postgres_cert_volume="notary-postgres-certs-${run_id}"
postgres_port="${NOTARY_POSTGRES_PORT:-$((30000 + ($$ % 8000)))}"
notary_port_a="${NOTARY_CONFORMANCE_PORT_A:-$((41000 + ($$ % 4000)))}"
notary_port_b="${NOTARY_CONFORMANCE_PORT_B:-$((45000 + ($$ % 4000)))}"
notary_negative_port="${NOTARY_CONFORMANCE_NEGATIVE_PORT:-$((50000 + ($$ % 4000)))}"
unsupported_postgres_image="postgres:15.18-alpine"
unsupported_postgres_container="${postgres_container}-unsupported"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/notary-postgres-conformance.XXXXXX")"
notary_pid_a=""
notary_pid_b=""
lost_ack_pid=""
negative_listener_pid=""

fail() {
  echo "notary PostgreSQL conformance failed: $1" >&2
  exit 1
}

stop_process() {
  local pid="${1:-}"
  if [[ -z "${pid}" ]] || ! kill -0 "${pid}" 2>/dev/null; then
    return 0
  fi
  kill "${pid}" 2>/dev/null || true
  for _ in {1..20}; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      wait "${pid}" 2>/dev/null || true
      return 0
    fi
    sleep 0.25
  done
  kill -KILL "${pid}" 2>/dev/null || true
  wait "${pid}" 2>/dev/null || true
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  stop_process "${notary_pid_a}"
  stop_process "${notary_pid_b}"
  stop_process "${lost_ack_pid}"
  stop_process "${negative_listener_pid}"
  docker rm -f "${unsupported_postgres_container}" >/dev/null 2>&1
  docker rm -f "${postgres_container}" >/dev/null 2>&1
  docker volume rm -f "${postgres_data_volume}" "${postgres_cert_volume}" >/dev/null 2>&1
  rm -rf "${work_dir}"
  exit "${status}"
}
trap cleanup EXIT INT TERM

for command in cargo curl docker jq openssl python3; do
  command -v "${command}" >/dev/null 2>&1 || fail "required command is unavailable"
done
[[ -x "${notary_bin}" ]] || fail "registry-notary binary is unavailable"
"${notary_bin}" build-info | jq --exit-status '.capabilities.cel == true' >/dev/null \
  || fail "registry-notary binary lacks CEL support"
[[ "${source_image}" != "${target_image}" ]] || fail "minor-upgrade images must differ"

admin_password="$(openssl rand -hex 24)"
migrator_password="$(openssl rand -hex 24)"
runtime_password="$(openssl rand -hex 24)"
api_key="$(openssl rand -hex 32)"
audit_secret="$(openssl rand -hex 32)"
sensitive_state_key="$(openssl rand -base64 32 | tr -d '\n=' | tr '+/' '-_')"
sensitive_probe_pin="$(python3 -c \
  'import secrets, string; print("".join(secrets.choice(string.ascii_uppercase) for _ in range(6)))')"
[[ "${sensitive_probe_pin}" =~ ^[A-Z]{6}$ ]] \
  || fail "sensitive-state probe PIN generation failed"
sensitive_state_key_id="$(NOTARY_SENSITIVE_KEY="${sensitive_state_key}" python3 - <<'PY'
import base64
import hashlib
import hmac
import os

encoded = os.environ["NOTARY_SENSITIVE_KEY"]
master = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
fields = [b"registry-notary/preauthorization/kdf/v1", b"key-id"]
message = b"".join(len(field).to_bytes(8, "big") + field for field in fields)
print(hmac.new(master, message, hashlib.sha256).hexdigest())
PY
)"
[[ "${sensitive_state_key_id}" =~ ^[0-9a-f]{64}$ ]] \
  || fail "sensitive-state key identifier derivation failed"
idempotency_key_a="conformance-a-${run_id}"
idempotency_key_b="conformance-b-${run_id}"
idempotency_key_c="conformance-c-${run_id}"
target_a="synthetic-subject-a-${run_id}"
target_b="synthetic-subject-b-${run_id}"
target_c="synthetic-subject-c-${run_id}"

echo "notary PostgreSQL ${postgresql_major} conformance: preparing isolated cluster"

api_key_hash="$(printf '%s\n' "${api_key}" | "${notary_bin}" hash-api-key --stdin --hash-only \
  2>"${work_dir}/hash-api-key.log")"
[[ "${api_key_hash}" == sha256:* ]] || fail "API key hash output is invalid"

{
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj "/CN=Notary conformance CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "${work_dir}/ca.key" -out "${work_dir}/ca.crt"
  openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
    -keyout "${work_dir}/server.key" -out "${work_dir}/server.csr"
  openssl x509 -req -days 2 -in "${work_dir}/server.csr" \
    -CA "${work_dir}/ca.crt" -CAkey "${work_dir}/ca.key" -CAcreateserial \
    -extfile <(printf '%s\n' \
      'subjectAltName=DNS:localhost,IP:127.0.0.1' \
      'basicConstraints=critical,CA:FALSE' \
      'keyUsage=critical,digitalSignature,keyEncipherment' \
      'extendedKeyUsage=serverAuth') \
    -out "${work_dir}/server.crt"
  chmod 600 "${work_dir}/server.key"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj "/CN=Untrusted Notary conformance CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "${work_dir}/untrusted-ca.key" -out "${work_dir}/untrusted-ca.crt"
  openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
    -keyout "${work_dir}/untrusted-server.key" -out "${work_dir}/untrusted-server.csr"
  openssl x509 -req -days 2 -in "${work_dir}/untrusted-server.csr" \
    -CA "${work_dir}/untrusted-ca.crt" -CAkey "${work_dir}/untrusted-ca.key" \
    -CAcreateserial \
    -extfile <(printf '%s\n' \
      'subjectAltName=DNS:localhost,IP:127.0.0.1' \
      'basicConstraints=critical,CA:FALSE' \
      'keyUsage=critical,digitalSignature,keyEncipherment' \
      'extendedKeyUsage=serverAuth') \
    -out "${work_dir}/untrusted-server.crt"
  chmod 600 "${work_dir}/untrusted-server.key"
} >"${work_dir}/openssl.log" 2>&1

docker pull "${source_image}" >"${work_dir}/docker-pull.log" 2>&1
docker pull "${target_image}" >>"${work_dir}/docker-pull.log" 2>&1
if [[ "${restore_image}" != "${source_image}" && "${restore_image}" != "${target_image}" ]]; then
  docker pull "${restore_image}" >>"${work_dir}/docker-pull.log" 2>&1
fi
if [[ "${postgresql_major}" == "18" ]]; then
  docker pull "${unsupported_postgres_image}" >>"${work_dir}/docker-pull.log" 2>&1
fi
docker volume create "${postgres_data_volume}" >/dev/null
docker volume create "${postgres_cert_volume}" >/dev/null

install_postgres_certificate() {
  local stem="$1"
  docker run --rm --user root \
    --env "CERTIFICATE_STEM=${stem}" \
    --mount "type=bind,source=${work_dir},target=/source,readonly" \
    --mount "type=volume,source=${postgres_cert_volume},target=/certs" \
    "${source_image}" sh -ec \
    'cp "/source/${CERTIFICATE_STEM}.crt" /certs/server.crt; \
     cp "/source/${CERTIFICATE_STEM}.key" /certs/server.key; \
     chown 70:70 /certs/server.crt /certs/server.key; \
     chmod 600 /certs/server.key' \
    >>"${work_dir}/certificate-install.log" 2>&1
}

install_postgres_certificate server

postgres_ready() {
  docker exec "${postgres_container}" pg_isready --host 127.0.0.1 \
    --username postgres --dbname postgres >/dev/null 2>&1 || return 1

  local probe
  probe="$(docker exec --env "PGPASSWORD=${admin_password}" "${postgres_container}" \
    psql --host 127.0.0.1 --username postgres --dbname postgres \
    --tuples-only --no-align --set ON_ERROR_STOP=1 --command 'SELECT 1' 2>/dev/null)" \
    || return 1
  [[ "${probe}" == "1" ]]
}

wait_for_postgres() {
  local deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    if postgres_ready; then
      return 0
    fi
    sleep 1
  done
  fail "PostgreSQL did not become ready"
}

start_postgres() {
  local image="$1"
  docker run --detach --name "${postgres_container}" \
    --env "POSTGRES_PASSWORD=${admin_password}" \
    --env "PGDATA=/var/lib/postgresql/pgdata" \
    --mount "type=volume,source=${postgres_data_volume},target=/var/lib/postgresql" \
    --mount "type=volume,source=${postgres_cert_volume},target=/certs,readonly" \
    --publish "127.0.0.1:${postgres_port}:5432" \
    "${image}" \
    -c ssl=on \
    -c ssl_cert_file=/certs/server.crt \
    -c ssl_key_file=/certs/server.key \
    -c fsync=on \
    -c synchronous_commit=on \
    -c full_page_writes=on >/dev/null

  wait_for_postgres
}

admin_sql() {
  local database="$1"
  local sql="$2"
  printf '%s\n' "${sql}" | docker exec --interactive "${postgres_container}" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "${database}" \
    >"${work_dir}/admin-sql.log" 2>&1
}

admin_scalar() {
  local database="$1"
  local sql="$2"
  docker exec "${postgres_container}" \
    psql --tuples-only --no-align --set ON_ERROR_STOP=1 \
      --username postgres --dbname "${database}" --command "${sql}"
}

runtime_scalar() {
  local sql="$1"
  docker exec --env "PGPASSWORD=${runtime_password}" --env PGSSLMODE=require \
    "${postgres_container}" psql --tuples-only --no-align --set ON_ERROR_STOP=1 \
      --host 127.0.0.1 --username registry_notary_runtime \
      --dbname registry_notary --command "${sql}"
}

role_oid_pair() {
  docker exec "${postgres_container}" psql --tuples-only --no-align \
    --username postgres --dbname postgres --command \
    "SELECT owner_role.oid::text || ':' || runtime_role.oid::text
       FROM pg_catalog.pg_roles AS owner_role,
            pg_catalog.pg_roles AS runtime_role
      WHERE owner_role.rolname = 'registry_notary_owner'
        AND runtime_role.rolname = 'registry_notary_runtime';"
}

runtime_connection_count() {
  docker exec "${postgres_container}" psql --tuples-only --no-align \
    --username postgres --dbname postgres --command \
    "SELECT pg_catalog.count(*) FROM pg_catalog.pg_stat_activity
      WHERE datname = 'registry_notary'
        AND usename = 'registry_notary_runtime';"
}

database_session_count() {
  docker exec "${postgres_container}" psql --tuples-only --no-align \
    --username postgres --dbname postgres --command \
    "SELECT sessions FROM pg_catalog.pg_stat_database
      WHERE datname = 'registry_notary';"
}

completed_batch_count() {
  admin_scalar registry_notary \
    "SELECT pg_catalog.count(*) FROM registry_notary_private.batch_idempotency
      WHERE state = 'completed';"
}

provision_roles() {
  local shifted_oids="$1"
  local log_file="$2"
  if [[ "${shifted_oids}" == "true" ]]; then
    admin_sql postgres 'CREATE ROLE notary_conformance_oid_padding NOLOGIN;'
  fi
  docker exec --interactive \
    --env "NOTARY_MIGRATOR_PASSWORD=${migrator_password}" \
    --env "NOTARY_RUNTIME_PASSWORD=${runtime_password}" \
    "${postgres_container}" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname postgres \
    >"${log_file}" 2>&1 <<'SQL'
\getenv migrator_password NOTARY_MIGRATOR_PASSWORD
\getenv runtime_password NOTARY_RUNTIME_PASSWORD
CREATE ROLE registry_notary_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE registry_notary_migrator
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
  PASSWORD :'migrator_password';
CREATE ROLE registry_notary_runtime
  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
  PASSWORD :'runtime_password';
GRANT registry_notary_owner TO registry_notary_migrator;
CREATE DATABASE registry_notary OWNER registry_notary_owner;
REVOKE ALL ON DATABASE registry_notary FROM PUBLIC;
GRANT CONNECT ON DATABASE registry_notary TO registry_notary_migrator, registry_notary_runtime;
\connect registry_notary
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
}

start_postgres "${source_image}"
docker exec "${postgres_container}" sh -ec \
  'cp "${PGDATA}/pg_hba.conf" "${PGDATA}/pg_hba.conf.conformance"; \
   { printf "%s\n" "hostssl postgres all 0.0.0.0/0 trust"; \
     cat "${PGDATA}/pg_hba.conf.conformance"; } >"${PGDATA}/pg_hba.conf"' \
  >"${work_dir}/postgres-test-auth.log" 2>&1
docker exec "${postgres_container}" psql --username postgres --dbname postgres \
  --command 'SELECT pg_catalog.pg_reload_conf();' \
  >>"${work_dir}/postgres-test-auth.log" 2>&1
echo "notary PostgreSQL ${postgresql_major} conformance: typed state contracts"
REGISTRY_NOTARY_STATE_POSTGRES_TEST_URL="postgresql://postgres@localhost:${postgres_port}/postgres?sslmode=require" \
REGISTRY_NOTARY_STATE_POSTGRES_TEST_CA="${work_dir}/ca.crt" \
  cargo test --locked -p registry-notary-server --lib \
    state_plane::migration::tests::postgres_v1_typed_state_contracts_and_drift_rejection \
    -- --ignored --exact \
    >"${work_dir}/rust-state-contracts.log" 2>&1 \
  || { sed -n '1,240p' "${work_dir}/rust-state-contracts.log" >&2; \
       fail "typed PostgreSQL state contract test failed"; }
REGISTRY_NOTARY_STATE_POSTGRES_TEST_URL="postgresql://postgres@localhost:${postgres_port}/postgres?sslmode=require" \
REGISTRY_NOTARY_STATE_POSTGRES_TEST_CA="${work_dir}/ca.crt" \
  cargo test --locked -p registry-notary-server --lib \
    state_plane::migration::tests::postgres_v1_logical_restore_rebind_requires_exact_owner_and_catalog \
    -- --ignored --exact \
    >"${work_dir}/rust-restore-role-contract.log" 2>&1 \
  || { sed -n '1,240p' "${work_dir}/rust-restore-role-contract.log" >&2; \
       fail "logical restore role contract test failed"; }
docker exec "${postgres_container}" sh -ec \
  'mv "${PGDATA}/pg_hba.conf.conformance" "${PGDATA}/pg_hba.conf"' \
  >>"${work_dir}/postgres-test-auth.log" 2>&1
docker exec "${postgres_container}" psql --username postgres --dbname postgres \
  --command 'SELECT pg_catalog.pg_reload_conf();' \
  >>"${work_dir}/postgres-test-auth.log" 2>&1
provision_roles false "${work_dir}/role-install.log"
source_role_oids="$(role_oid_pair)"
[[ "${source_role_oids}" =~ ^[0-9]+:[0-9]+$ ]] || fail "source role identities are unavailable"

runtime_database_url="postgresql://registry_notary_runtime:${runtime_password}@localhost:${postgres_port}/registry_notary?sslmode=require"
migrator_database_url="postgresql://registry_notary_migrator:${migrator_password}@localhost:${postgres_port}/registry_notary?sslmode=require"
export REGISTRY_NOTARY_POSTGRES_URL="${runtime_database_url}"
export REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL="${migrator_database_url}"
export REGISTRY_NOTARY_SENSITIVE_STATE_KEY="${sensitive_state_key}"
export REGISTRY_NOTARY_AUDIT_HASH_SECRET="${audit_secret}"
export NOTARY_CONFORMANCE_API_KEY_HASH="${api_key_hash}"

config_path="${work_dir}/notary.yaml"
cat >"${config_path}" <<YAML
deployment:
  profile: local
  multi_instance: true
instance:
  environment: conformance
  id: notary-postgres-conformance
server:
  bind: 127.0.0.1:${notary_port_a}
  request_timeout: 30s
state:
  storage: postgresql
  postgresql:
    url_env: REGISTRY_NOTARY_POSTGRES_URL
    root_certificate_path: ${work_dir}/ca.crt
    connect_timeout_ms: 2000
    operation_timeout_ms: 2000
    max_connections: 1
    sensitive_state_key_env: REGISTRY_NOTARY_SENSITIVE_STATE_KEY
auth:
  api_keys:
    - id: conformance-client
      fingerprint:
        provider: env
        name: NOTARY_CONFORMANCE_API_KEY_HASH
      scopes: [notary:conformance]
audit:
  sink: stdout
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: notary-postgres-conformance
  api_base_url: http://localhost
  inline_batch_limit: 1
  allowed_purposes: [conformance]
  machine_quota:
    enabled: true
    subjects_per_minute: 2
  claims:
    - id: conformance-eligible
      title: Conformance eligible
      version: "1"
      subject_type: person
      evidence_mode:
        type: self_attested
      value:
        type: boolean
        nullable: false
      purpose: conformance
      required_scopes: [notary:conformance]
      rule:
        type: cel
        expression: "true"
        bindings: {}
      operations:
        evaluate:
          enabled: true
        batch_evaluate:
          enabled: true
          max_subjects: 1
      disclosure:
        default: predicate
        allowed: [predicate, redacted]
        downgrade: deny
      formats:
        - application/vnd.registry-notary.claim-result+json
YAML

"${notary_bin}" --config "${config_path}" state install \
  --migration-url-env REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL \
  --owner-role registry_notary_owner \
  --runtime-role registry_notary_runtime \
  >"${work_dir}/state-install.log" 2>&1 || fail "schema installation failed"
"${notary_bin}" --config "${config_path}" state doctor \
  >"${work_dir}/state-doctor.log" 2>&1 || fail "schema attestation failed"

echo "notary PostgreSQL ${postgresql_major} conformance: multi-instance and recovery"

start_notary() {
  local bind="$1"
  local log_file="$2"
  local pid_variable="$3"
  "${notary_bin}" --config "${config_path}" --bind "${bind}" >"${log_file}" 2>&1 &
  printf -v "${pid_variable}" '%s' "$!"
}

NEGATIVE_LISTENER_PORT="${notary_negative_port}" python3 -c '
import os
import socket
import time

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", int(os.environ["NEGATIVE_LISTENER_PORT"])))
listener.listen(1)
print("ready", flush=True)
while True:
    time.sleep(60)
' >"${work_dir}/negative-listener.log" 2>&1 &
negative_listener_pid=$!
negative_listener_deadline=$((SECONDS + 10))
while ! grep --fixed-strings --line-regexp --quiet ready "${work_dir}/negative-listener.log"; do
  kill -0 "${negative_listener_pid}" 2>/dev/null \
    || fail "negative startup listener exited"
  (( SECONDS < negative_listener_deadline )) \
    || fail "negative startup listener did not become ready"
  sleep 0.1
done

expect_startup_failure() {
  local label="$1"
  local expected_error="$2"
  local log_file="${work_dir}/startup-${label}.log"
  if "${notary_bin}" --config "${config_path}" \
    --bind "127.0.0.1:${notary_negative_port}" >"${log_file}" 2>&1; then
    fail "${label} state failure allowed startup"
  fi
  if ! grep --fixed-strings --quiet -- "${expected_error}" "${log_file}"; then
    sed -n '1,120p' "${log_file}" >&2
    fail "${label} startup did not report the expected closed error"
  fi
  if grep --extended-regexp --quiet -- 'Address already in use|os error (48|98)' "${log_file}"; then
    fail "${label} reached listener binding before state activation failed"
  fi
}

ready_status() {
  local url="$1"
  curl --silent --show-error --max-time 8 --output /dev/null --write-out '%{http_code}' \
    "${url}/ready" 2>>"${work_dir}/curl.log" || true
}

wait_ready() {
  local url="$1"
  local pid="$2"
  local deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    [[ "$(ready_status "${url}")" == "200" ]] && return 0
    kill -0 "${pid}" 2>/dev/null || return 1
    sleep 1
  done
  return 1
}

wait_not_ready() {
  local url="$1"
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    [[ "$(ready_status "${url}")" == "503" ]] && return 0
    sleep 1
  done
  return 1
}

batch_request() {
  local url="$1"
  local key="$2"
  local request_file="$3"
  local response_file="$4"
  local expected_status="$5"
  local status
  status="$(curl --silent --show-error --max-time 30 \
    --output "${response_file}" --write-out '%{http_code}' \
    --header "x-api-key: ${api_key}" \
    --header "idempotency-key: ${key}" \
    --header 'content-type: application/json' \
    --data-binary "@${request_file}" \
    "${url}/v1/batch-evaluations" 2>>"${work_dir}/curl.log")" || return 1
  [[ "${status}" == "${expected_status}" ]]
}

write_batch_request() {
  local target="$1"
  local output="$2"
  jq --null-input --compact-output --arg target "${target}" '{
    items: [{target: {type: "Person", id: $target}}],
    claims: ["conformance-eligible"],
    disclosure: "predicate",
    format: "application/vnd.registry-notary.claim-result+json",
    purpose: "conformance"
  }' >"${output}"
}

run_sensitive_probe() {
  local mode="$1"
  REGISTRY_NOTARY_STATE_SENSITIVE_TEST_URL="${runtime_database_url}" \
  REGISTRY_NOTARY_STATE_POSTGRES_TEST_CA="${work_dir}/ca.crt" \
  REGISTRY_NOTARY_STATE_SENSITIVE_TEST_KEY="${sensitive_state_key}" \
  REGISTRY_NOTARY_STATE_SENSITIVE_PROBE_MODE="${mode}" \
  REGISTRY_NOTARY_STATE_SENSITIVE_PROBE_PIN="${sensitive_probe_pin}" \
    cargo test --locked -p registry-notary-server --lib \
      state_plane::migration::tests::postgres_v1_sensitive_restart_restore_probe \
      -- --ignored --exact \
      >"${work_dir}/sensitive-${mode}-probe.log" 2>&1 \
    || { sed -n '1,200p' "${work_dir}/sensitive-${mode}-probe.log" >&2; \
         fail "${mode} sensitive-state probe failed"; }
}

machine_quota_window_started_at=""

seed_restart_domain_state() {
  [[ "$(runtime_scalar "SELECT registry_notary_api.replay_insert_v1(
    decode(repeat('d1', 32), 'hex'), decode(repeat('d2', 32), 'hex'),
    pg_catalog.clock_timestamp() + interval '1 day');")" == "t" ]] \
    || fail "restart replay fixture was not inserted"
  [[ "$(runtime_scalar "SELECT registry_notary_api.nonce_reserve_v1(
    decode(repeat('d3', 32), 'hex'), decode(repeat('d4', 32), 'hex'),
    pg_catalog.clock_timestamp() + interval '1 day');")" == "t" ]] \
    || fail "restart nonce fixture was not reserved"
  [[ "$(runtime_scalar "SELECT registry_notary_api.evaluation_insert_v1(
    'restart-evaluation', decode(repeat('d5', 32), 'hex'),
    decode(repeat('d6', 32), 'hex'), 'conformance', 2::smallint,
    '{\"decision\":\"allow\"}'::jsonb, pg_catalog.clock_timestamp(),
    pg_catalog.clock_timestamp() + interval '1 day');")" == "t" ]] \
    || fail "restart evaluation fixture was not inserted"
  [[ "$(runtime_scalar "SELECT registry_notary_api.credential_status_insert_v1(
    'restart-credential', 'restart-issuer', 'restart-profile',
    pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp() + interval '1 day', 3600);")" == "t" ]] \
    || fail "restart credential-status fixture was not inserted"
  [[ "$(runtime_scalar "SELECT outcome FROM registry_notary_api.credential_status_update_v1(
    'restart-credential', 'revoked');")" == "updated" ]] \
    || fail "restart credential-status fixture was not revoked"
  [[ "$(runtime_scalar "SELECT allowed FROM registry_notary_api.machine_quota_debit_v1(
    decode(repeat('d7', 32), 'hex'), 10, 3);")" == "t" ]] \
    || fail "restart machine-quota fixture was not debited"
  machine_quota_window_started_at="$(admin_scalar registry_notary \
    "SELECT window_started_at::text FROM registry_notary_private.machine_quota
      WHERE principal_hash = decode(repeat('d7', 32), 'hex');")"
  [[ -n "${machine_quota_window_started_at}" ]] \
    || fail "restart machine-quota window was unavailable"
  [[ "$(runtime_scalar "SELECT allowed FROM registry_notary_api.subject_access_quota_debit_v1(
    ARRAY['per_principal']::text[], ARRAY[decode(repeat('d8', 32), 'hex')]::bytea[],
    ARRAY[1]::integer[], ARRAY[3600]::integer[]);")" == "t" ]] \
    || fail "restart subject-quota fixture was not debited"
  run_sensitive_probe seed
}

assert_restart_domain_state() {
  local phase="$1"
  [[ "$(runtime_scalar "SELECT NOT registry_notary_api.replay_insert_v1(
    decode(repeat('d1', 32), 'hex'), decode(repeat('d2', 32), 'hex'),
    pg_catalog.clock_timestamp() + interval '1 day');")" == "t" ]] \
    || fail "${phase} reopened a replay identifier"
  [[ "$(runtime_scalar "SELECT registry_notary_api.nonce_reservation_generation_v1(
    decode(repeat('d3', 32), 'hex'), decode(repeat('d4', 32), 'hex'));")" == "1" ]] \
    || fail "${phase} changed the nonce generation"
  [[ "$(runtime_scalar "SELECT EXISTS (SELECT 1 FROM registry_notary_api.evaluation_get_v1(
    'restart-evaluation', decode(repeat('d5', 32), 'hex')));")" == "t" ]] \
    || fail "${phase} lost the evaluation"
  [[ "$(runtime_scalar "SELECT EXISTS (SELECT 1 FROM registry_notary_api.credential_status_get_v1(
    'restart-credential') WHERE status = 'revoked');")" == "t" ]] \
    || fail "${phase} changed the terminal credential status"
  [[ "$(runtime_scalar "SELECT outcome FROM registry_notary_api.credential_status_update_v1(
    'restart-credential', 'valid');")" == "invalid_transition" ]] \
    || fail "${phase} reopened a terminal credential status"
  [[ "$(admin_scalar registry_notary "SELECT used FROM registry_notary_private.machine_quota
    WHERE principal_hash = decode(repeat('d7', 32), 'hex');")" == "3" ]] \
    || fail "${phase} lost the machine-quota debit"
  [[ "$(admin_scalar registry_notary "SELECT window_started_at::text
    FROM registry_notary_private.machine_quota
    WHERE principal_hash = decode(repeat('d7', 32), 'hex');")" \
     == "${machine_quota_window_started_at}" ]] \
    || fail "${phase} changed the machine-quota window"
  [[ "$(admin_scalar registry_notary "SELECT used FROM registry_notary_private.subject_access_quota
    WHERE bucket_kind = 'per_principal'
      AND key_hash = decode(repeat('d8', 32), 'hex');")" == "1" ]] \
    || fail "${phase} lost the subject-quota debit"
  [[ "$(runtime_scalar "SELECT registry_notary_api.preauthorization_key_attest_v1(
    decode('${sensitive_state_key_id}', 'hex'));")" == "t" ]] \
    || fail "${phase} changed the sensitive-state key generation"
  run_sensitive_probe "${phase}"
}

url_a="http://127.0.0.1:${notary_port_a}"
url_b="http://127.0.0.1:${notary_port_b}"
start_notary "127.0.0.1:${notary_port_a}" "${work_dir}/notary-a.log" notary_pid_a
start_notary "127.0.0.1:${notary_port_b}" "${work_dir}/notary-b.log" notary_pid_b
wait_ready "${url_a}" "${notary_pid_a}" || fail "first Notary instance did not become ready"
wait_ready "${url_b}" "${notary_pid_b}" || fail "second Notary instance did not become ready"
[[ "$(runtime_connection_count)" == "2" ]] \
  || fail "per-replica PostgreSQL connection cap was not enforced"

request_a="${work_dir}/request-a.json"
request_b="${work_dir}/request-b.json"
request_c="${work_dir}/request-c.json"
write_batch_request "${target_a}" "${request_a}"
write_batch_request "${target_b}" "${request_b}"
write_batch_request "${target_c}" "${request_c}"

batch_request "${url_a}" "${idempotency_key_a}" "${request_a}" "${work_dir}/response-a1.json" 200 &
curl_pid_a=$!
batch_request "${url_b}" "${idempotency_key_a}" "${request_a}" "${work_dir}/response-a2.json" 200 &
curl_pid_b=$!
wait "${curl_pid_a}" || fail "first concurrent batch request failed"
wait "${curl_pid_b}" || fail "second concurrent batch request failed"

batch_id="$(jq --exit-status --raw-output '.batch_id | select(type == "string" and length > 0)' "${work_dir}/response-a1.json")"
if [[ "$(jq --raw-output '.summary.succeeded' "${work_dir}/response-a1.json")" != "1" ]]; then
  jq --compact-output \
    '{summary, items: [.items[] | {input_index, status, error_codes: [.errors[].code]}]}' \
    "${work_dir}/response-a1.json" >&2 || true
  jq --compact-output \
    '{summary, items: [.items[] | {input_index, status, error_codes: [.errors[].code]}]}' \
    "${work_dir}/response-a2.json" >&2 || true
  fail "the concurrent batch did not produce one successful evaluation"
fi
evaluation_id="$(jq --exit-status --raw-output '.items[0].evaluation_id | select(type == "string" and length > 0)' "${work_dir}/response-a1.json")"
[[ "$(jq --raw-output '.batch_id' "${work_dir}/response-a2.json")" == "${batch_id}" ]] \
  || fail "concurrent instances did not observe one batch owner"
[[ "$(jq --raw-output '.items[0].evaluation_id' "${work_dir}/response-a2.json")" == "${evaluation_id}" ]] \
  || fail "concurrent instances did not observe one evaluation"

sessions_before_reuse="$(database_session_count)"
for reuse_attempt in {1..4}; do
  batch_request "${url_a}" "${idempotency_key_a}" "${request_a}" \
    "${work_dir}/response-reuse-${reuse_attempt}.json" 200 \
    || fail "sequential pooled state request failed"
done
sessions_after_reuse="$(database_session_count)"
[[ "${sessions_after_reuse}" == "${sessions_before_reuse}" ]] \
  || fail "sequential state operations did not reuse the physical connection"
[[ "$(runtime_connection_count)" == "2" ]] \
  || fail "state traffic exceeded the configured PostgreSQL connection cap"

seed_restart_domain_state
stop_process "${notary_pid_a}"
notary_pid_a=""
start_notary "127.0.0.1:${notary_port_a}" "${work_dir}/notary-a-restart.log" notary_pid_a
wait_ready "${url_a}" "${notary_pid_a}" || fail "restarted Notary instance did not become ready"
assert_restart_domain_state process
batch_request "${url_a}" "${idempotency_key_a}" "${request_a}" "${work_dir}/response-a-restart.json" 200 \
  || fail "restart replay failed"
[[ "$(jq --raw-output '.batch_id' "${work_dir}/response-a-restart.json")" == "${batch_id}" ]] \
  || fail "restart did not preserve the completed decision"

completed_before_lost_ack="$(completed_batch_count)"
LOST_ACK_PORT="${notary_port_b}" LOST_ACK_API_KEY="${api_key}" \
LOST_ACK_IDEMPOTENCY_KEY="${idempotency_key_b}" LOST_ACK_REQUEST="${request_b}" \
  python3 -c '
import os
import socket
import time

body = open(os.environ["LOST_ACK_REQUEST"], "rb").read()
port = os.environ["LOST_ACK_PORT"]
api_key = os.environ["LOST_ACK_API_KEY"]
idempotency_key = os.environ["LOST_ACK_IDEMPOTENCY_KEY"]
headers = (
    "POST /v1/batch-evaluations HTTP/1.1\r\n"
    f"Host: 127.0.0.1:{port}\r\n"
    "Connection: close\r\n"
    f"x-api-key: {api_key}\r\n"
    f"idempotency-key: {idempotency_key}\r\n"
    "content-type: application/json\r\n"
    f"content-length: {len(body)}\r\n\r\n"
).encode("ascii")
with socket.create_connection(("127.0.0.1", int(port)), timeout=10) as connection:
    connection.sendall(headers + body)
    while True:
        time.sleep(60)
' >"${work_dir}/lost-ack-client.log" 2>&1 &
lost_ack_pid=$!
completed_after_lost_ack="${completed_before_lost_ack}"
lost_ack_deadline=$((SECONDS + 30))
while (( SECONDS < lost_ack_deadline )); do
  completed_after_lost_ack="$(completed_batch_count)"
  if (( completed_after_lost_ack > completed_before_lost_ack )); then
    break
  fi
  kill -0 "${lost_ack_pid}" 2>/dev/null || fail "lost-ack request ended before commit"
  sleep 0.25
done
(( completed_after_lost_ack > completed_before_lost_ack )) \
  || fail "lost-ack request did not commit"
stop_process "${lost_ack_pid}"
lost_ack_pid=""
batch_request "${url_b}" "${idempotency_key_b}" "${request_b}" \
  "${work_dir}/response-b-retry-1.json" 200 \
  || fail "lost-ack retry did not replay the committed result"
batch_request "${url_a}" "${idempotency_key_b}" "${request_b}" \
  "${work_dir}/response-b-retry-2.json" 200 \
  || fail "peer lost-ack retry did not replay the committed result"
[[ "$(jq --raw-output '.batch_id' "${work_dir}/response-b-retry-1.json")" \
   == "$(jq --raw-output '.batch_id' "${work_dir}/response-b-retry-2.json")" ]] \
  || fail "lost-ack retry reopened the committed batch"
[[ "$(jq --raw-output '.items[0].evaluation_id' "${work_dir}/response-b-retry-1.json")" \
   == "$(jq --raw-output '.items[0].evaluation_id' "${work_dir}/response-b-retry-2.json")" ]] \
  || fail "lost-ack retry changed the committed evaluation"
batch_request "${url_a}" "${idempotency_key_c}" "${request_c}" "${work_dir}/response-c-denied.json" 429 \
  || fail "shared machine quota did not reject excess work"

admin_sql postgres \
  "ALTER DATABASE registry_notary SET default_transaction_read_only = on;
   SELECT pg_catalog.pg_terminate_backend(pid)
     FROM pg_catalog.pg_stat_activity
    WHERE datname = 'registry_notary'
      AND usename = 'registry_notary_runtime';"
wait_not_ready "${url_a}" || fail "read-only PostgreSQL did not fail readiness"
if "${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-read-only.log" 2>&1; then
  fail "state doctor accepted read-only PostgreSQL"
fi
expect_startup_failure read-only "Notary PostgreSQL database is unavailable"
admin_sql postgres 'ALTER DATABASE registry_notary RESET default_transaction_read_only;'
wait_ready "${url_a}" "${notary_pid_a}" || fail "readiness did not recover after read-only repair"
"${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-read-only-recovered.log" 2>&1 \
  || fail "state doctor did not recover after read-only repair"

admin_sql registry_notary \
  'ALTER FUNCTION registry_notary_api.replay_insert_v1(bytea, bytea, timestamptz) IMMUTABLE;'
wait_not_ready "${url_a}" || fail "schema drift did not fail readiness"
if "${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-schema-drift.log" 2>&1; then
  fail "state doctor accepted schema drift"
fi
expect_startup_failure catalog-drift "Notary PostgreSQL state schema is incompatible"
admin_sql registry_notary \
  'ALTER FUNCTION registry_notary_api.replay_insert_v1(bytea, bytea, timestamptz) VOLATILE;'
wait_ready "${url_a}" "${notary_pid_a}" || fail "readiness did not recover after schema repair"
"${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-schema-recovered.log" 2>&1 \
  || fail "state doctor did not recover after schema repair"

schema_fingerprint="$(admin_scalar registry_notary \
  'SELECT schema_fingerprint FROM registry_notary_private.schema_metadata WHERE singleton = TRUE;')"
[[ "${schema_fingerprint}" =~ ^[0-9a-f]{64}$ ]] \
  || fail "schema metadata fingerprint was unavailable"
admin_sql registry_notary \
  "UPDATE registry_notary_private.schema_metadata
      SET schema_fingerprint = repeat('0', 64)
    WHERE singleton = TRUE;"
wait_not_ready "${url_a}" || fail "metadata fingerprint drift did not fail readiness"
if "${notary_bin}" --config "${config_path}" state doctor \
  >"${work_dir}/doctor-fingerprint-drift.log" 2>&1; then
  fail "state doctor accepted metadata fingerprint drift"
fi
expect_startup_failure fingerprint-drift "Notary PostgreSQL state schema is incompatible"
if "${notary_bin}" --config "${config_path}" state install \
  --migration-url-env REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL \
  --owner-role registry_notary_owner \
  --runtime-role registry_notary_runtime \
  >"${work_dir}/state-install-fingerprint-drift.log" 2>&1; then
  fail "state install repaired metadata fingerprint drift"
fi
[[ "$(admin_scalar registry_notary \
  'SELECT schema_fingerprint FROM registry_notary_private.schema_metadata WHERE singleton = TRUE;')" \
   == "$(printf '0%.0s' {1..64})" ]] \
  || fail "rejected state install changed metadata fingerprint drift"
admin_sql registry_notary \
  "UPDATE registry_notary_private.schema_metadata
      SET schema_fingerprint = '${schema_fingerprint}'
    WHERE singleton = TRUE;"
wait_ready "${url_a}" "${notary_pid_a}" \
  || fail "readiness did not recover after metadata fingerprint repair"
"${notary_bin}" --config "${config_path}" state doctor \
  >"${work_dir}/doctor-fingerprint-recovered.log" 2>&1 \
  || fail "state doctor did not recover after metadata fingerprint repair"

admin_sql registry_notary \
  'REVOKE EXECUTE ON FUNCTION registry_notary_api.nonce_consume_v1(bytea, bytea, bigint) FROM registry_notary_runtime;'
wait_not_ready "${url_a}" || fail "runtime permission drift did not fail readiness"
if "${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-permission-drift.log" 2>&1; then
  fail "state doctor accepted runtime permission drift"
fi
expect_startup_failure permission-drift "Notary PostgreSQL state schema is incompatible"
admin_sql registry_notary \
  'GRANT EXECUTE ON FUNCTION registry_notary_api.nonce_consume_v1(bytea, bytea, bigint) TO registry_notary_runtime;'
wait_ready "${url_a}" "${notary_pid_a}" || fail "readiness did not recover after permission repair"
"${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-permission-recovered.log" 2>&1 \
  || fail "state doctor did not recover after permission repair"

bound_runtime_role_oid="$(admin_scalar registry_notary \
  'SELECT runtime_role_oid FROM registry_notary_private.schema_metadata WHERE singleton = TRUE;')"
[[ "${bound_runtime_role_oid}" =~ ^[0-9]+$ ]] \
  || fail "bound runtime role identity was unavailable"
admin_sql registry_notary \
  "UPDATE registry_notary_private.schema_metadata
      SET runtime_role_oid = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'postgres')
    WHERE singleton = TRUE;"
wait_not_ready "${url_a}" || fail "wrong runtime role did not fail readiness"
if "${notary_bin}" --config "${config_path}" state doctor \
  >"${work_dir}/doctor-role-incompatible.log" 2>&1; then
  fail "state doctor accepted the wrong runtime role"
fi
grep --fixed-strings --quiet role_incompatible "${work_dir}/doctor-role-incompatible.log" \
  || fail "state doctor did not report the role-incompatible component"
expect_startup_failure role-incompatible "Notary PostgreSQL runtime role is incompatible"
admin_sql registry_notary \
  "UPDATE registry_notary_private.schema_metadata
      SET runtime_role_oid = ${bound_runtime_role_oid}
    WHERE singleton = TRUE;"
wait_ready "${url_a}" "${notary_pid_a}" \
  || fail "readiness did not recover after runtime role repair"

if [[ "${postgresql_major}" == "18" ]]; then
  docker stop --time 20 "${postgres_container}" >/dev/null
  docker run --detach --name "${unsupported_postgres_container}" \
    --env "POSTGRES_USER=registry_notary_runtime" \
    --env "POSTGRES_PASSWORD=${runtime_password}" \
    --env "POSTGRES_DB=registry_notary" \
    --mount "type=volume,source=${postgres_cert_volume},target=/certs,readonly" \
    --publish "127.0.0.1:${postgres_port}:5432" \
    "${unsupported_postgres_image}" \
    -c ssl=on \
    -c ssl_cert_file=/certs/server.crt \
    -c ssl_key_file=/certs/server.key \
    -c fsync=on \
    -c synchronous_commit=on \
    -c full_page_writes=on >/dev/null
  unsupported_deadline=$((SECONDS + 90))
  while (( SECONDS < unsupported_deadline )); do
    if docker exec "${unsupported_postgres_container}" pg_isready --host 127.0.0.1 \
      --username registry_notary_runtime --dbname registry_notary >/dev/null 2>&1 \
      && [[ "$(docker exec --env "PGPASSWORD=${runtime_password}" \
        "${unsupported_postgres_container}" psql --host 127.0.0.1 \
        --username registry_notary_runtime --dbname registry_notary --tuples-only --no-align \
        --set ON_ERROR_STOP=1 --command 'SELECT 1' 2>/dev/null)" == "1" ]]; then
      break
    fi
    sleep 1
  done
  (( SECONDS < unsupported_deadline )) \
    || fail "unsupported PostgreSQL test server did not become ready"
  wait_not_ready "${url_a}" || fail "unsupported PostgreSQL major did not fail readiness"
  if "${notary_bin}" --config "${config_path}" state doctor \
    >"${work_dir}/doctor-unsupported-major.log" 2>&1; then
    fail "state doctor accepted an unsupported PostgreSQL major"
  fi
  expect_startup_failure unsupported-major "Notary PostgreSQL server major is unsupported"
  docker rm -f "${unsupported_postgres_container}" >/dev/null
  docker start "${postgres_container}" >/dev/null
  wait_for_postgres
  wait_ready "${url_a}" "${notary_pid_a}" \
    || fail "readiness did not recover after supported PostgreSQL restoration"
fi

docker stop --time 20 "${postgres_container}" >/dev/null
wait_not_ready "${url_a}" || fail "unavailable PostgreSQL did not fail readiness"
if "${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-unavailable.log" 2>&1; then
  fail "state doctor accepted unavailable PostgreSQL"
fi
expect_startup_failure unavailable "Notary PostgreSQL database is unavailable"
install_postgres_certificate untrusted-server
docker start "${postgres_container}" >/dev/null
wait_for_postgres
wait_not_ready "${url_a}" || fail "untrusted PostgreSQL certificate did not fail readiness"
if "${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-tls.log" 2>&1; then
  fail "state doctor accepted an untrusted PostgreSQL certificate"
fi
expect_startup_failure tls "Notary PostgreSQL database is unavailable"
docker stop --time 20 "${postgres_container}" >/dev/null
install_postgres_certificate server
docker start "${postgres_container}" >/dev/null
wait_for_postgres
wait_ready "${url_a}" "${notary_pid_a}" \
  || fail "running Notary did not reconnect after PostgreSQL recovery"
wait_ready "${url_b}" "${notary_pid_b}" \
  || fail "running peer Notary did not reconnect after PostgreSQL recovery"
batch_request "${url_a}" "${idempotency_key_a}" "${request_a}" \
  "${work_dir}/response-a-outage-recovered.json" 200 \
  || fail "running Notary could not use state after PostgreSQL recovery"
assert_restart_domain_state database
[[ "$(runtime_connection_count)" == "2" ]] \
  || fail "outage recovery exceeded the configured PostgreSQL connection cap"
stop_process "${notary_pid_a}"
stop_process "${notary_pid_b}"
notary_pid_a=""
notary_pid_b=""

echo "notary PostgreSQL ${postgresql_major} conformance: minor upgrade"

source_version="$(docker exec "${postgres_container}" psql --tuples-only --no-align --username postgres --dbname postgres --command 'SHOW server_version_num')"
[[ "${source_version}" =~ ^[0-9]+$ ]] || fail "source PostgreSQL version is unavailable"
(( source_version / 10000 == postgresql_major )) || fail "source PostgreSQL major does not match the matrix"
docker stop --time 30 "${postgres_container}" >/dev/null
docker rm "${postgres_container}" >/dev/null
start_postgres "${target_image}"
target_version="$(docker exec "${postgres_container}" psql --tuples-only --no-align --username postgres --dbname postgres --command 'SHOW server_version_num')"
[[ "${target_version}" =~ ^[0-9]+$ ]] || fail "target PostgreSQL version is unavailable"
(( target_version / 10000 == postgresql_major )) || fail "target PostgreSQL major does not match the matrix"
(( target_version > source_version )) || fail "PostgreSQL minor version did not advance"
"${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-upgraded.log" 2>&1 \
  || fail "state attestation failed after the minor upgrade"

start_notary "127.0.0.1:${notary_port_a}" "${work_dir}/notary-a-upgraded.log" notary_pid_a
wait_ready "${url_a}" "${notary_pid_a}" || fail "Notary did not become ready after the minor upgrade"
batch_request "${url_a}" "${idempotency_key_a}" "${request_a}" "${work_dir}/response-a-upgraded.json" 200 \
  || fail "completed decision was unavailable after the minor upgrade"
[[ "$(jq --raw-output '.batch_id' "${work_dir}/response-a-upgraded.json")" == "${batch_id}" ]] \
  || fail "minor upgrade reopened a completed decision"

render_status="$(curl --silent --show-error --max-time 30 \
  --output "${work_dir}/render-upgraded.json" --write-out '%{http_code}' \
  --header "x-api-key: ${api_key}" \
  --header 'content-type: application/json' \
  --data '{"format":"application/vnd.registry-notary.claim-result+json","disclosure":"predicate","claims":["conformance-eligible"],"purpose":"conformance"}' \
  "${url_a}/v1/evaluations/${evaluation_id}/render" 2>>"${work_dir}/curl.log")" \
  || fail "persisted evaluation render request failed"
[[ "${render_status}" == "200" ]] || fail "persisted evaluation was unavailable after the minor upgrade"

"${notary_bin}" --config "${config_path}" state doctor \
  >"${work_dir}/doctor-pre-backup.log" 2>&1 \
  || fail "state attestation failed before backup"

if [[ "${restore_major}" == "${postgresql_major}" ]]; then
  echo "notary PostgreSQL ${postgresql_major} conformance: logical backup and restore"
else
  echo "notary PostgreSQL ${postgresql_major}->${restore_major} conformance: logical upgrade"
fi
  stop_process "${notary_pid_a}"
  notary_pid_a=""
  docker exec --env "PGPASSWORD=${migrator_password}" --env PGSSLMODE=require \
    "${postgres_container}" pg_dump --host 127.0.0.1 \
    --username registry_notary_migrator --role registry_notary_owner \
    --dbname registry_notary --format custom --no-acl \
    --file /tmp/notary-conformance.dump \
    >"${work_dir}/pg-dump.log" 2>&1
  docker cp "${postgres_container}:/tmp/notary-conformance.dump" "${work_dir}/notary-conformance.dump" \
    >"${work_dir}/docker-copy.log" 2>&1
  docker stop --time 30 "${postgres_container}" >/dev/null
  docker rm "${postgres_container}" >/dev/null
  docker volume rm "${postgres_data_volume}" >/dev/null
  docker volume create "${postgres_data_volume}" >/dev/null
  start_postgres "${restore_image}"
  restored_version="$(docker exec "${postgres_container}" psql --tuples-only --no-align \
    --username postgres --dbname postgres --command 'SHOW server_version_num')"
  [[ "${restored_version}" =~ ^[0-9]+$ ]] || fail "restore PostgreSQL version is unavailable"
  (( restored_version / 10000 == restore_major )) || fail "restore PostgreSQL major does not match"
  provision_roles true "${work_dir}/role-restore-install.log"
  restored_role_oids="$(role_oid_pair)"
  [[ "${restored_role_oids}" =~ ^[0-9]+:[0-9]+$ ]] || fail "restored role identities are unavailable"
  [[ "${restored_role_oids}" != "${source_role_oids}" ]] || fail "fresh-cluster role identities did not change"
  docker cp "${work_dir}/notary-conformance.dump" "${postgres_container}:/tmp/notary-conformance-restore.dump" \
    >>"${work_dir}/docker-copy.log" 2>&1
  docker exec --env "PGPASSWORD=${migrator_password}" --env PGSSLMODE=require \
    "${postgres_container}" pg_restore --host 127.0.0.1 \
    --exit-on-error --single-transaction --no-acl --no-owner \
    --role registry_notary_owner --username registry_notary_migrator \
    --dbname registry_notary /tmp/notary-conformance-restore.dump \
    >"${work_dir}/pg-restore.log" 2>&1
  "${notary_bin}" --config "${config_path}" state install \
    --migration-url-env REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL \
    --owner-role registry_notary_owner \
    --runtime-role registry_notary_runtime \
    >"${work_dir}/state-install-restored.log" 2>&1 \
    || fail "schema role binding failed after logical restore"
  "${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-restored.log" 2>&1 \
    || fail "state attestation failed after logical restore"
  assert_restart_domain_state restore
  [[ "$(runtime_scalar "SELECT registry_notary_api.nonce_consume_v1(
    decode(repeat('d3', 32), 'hex'), decode(repeat('d4', 32), 'hex'), 1);")" == "t" ]] \
    || fail "restored nonce could not be consumed"
  [[ "$(runtime_scalar "SELECT registry_notary_api.nonce_consume_v1(
    decode(repeat('d3', 32), 'hex'), decode(repeat('d4', 32), 'hex'), 1);")" == "f" ]] \
    || fail "restored nonce had more than one consume winner"
  machine_window_is_live="$(admin_scalar registry_notary \
    "SELECT window_expires_at > pg_catalog.clock_timestamp()
       FROM registry_notary_private.machine_quota
      WHERE principal_hash = decode(repeat('d7', 32), 'hex');")"
  machine_followup_allowed="$(runtime_scalar \
    "SELECT allowed FROM registry_notary_api.machine_quota_debit_v1(
       decode(repeat('d7', 32), 'hex'), 10, 8);")"
  if [[ "${machine_window_is_live}" == "t" ]]; then
    [[ "${machine_followup_allowed}" == "f" ]] \
      || fail "restored live machine-quota window admitted excess cost"
    [[ "$(admin_scalar registry_notary "SELECT used
      FROM registry_notary_private.machine_quota
      WHERE principal_hash = decode(repeat('d7', 32), 'hex');")" == "3" ]] \
      || fail "rejected restored machine-quota debit changed the counter"
  else
    [[ "${machine_followup_allowed}" == "t" ]] \
      || fail "expired restored machine-quota window did not reopen from database time"
    [[ "$(admin_scalar registry_notary "SELECT used
      FROM registry_notary_private.machine_quota
      WHERE principal_hash = decode(repeat('d7', 32), 'hex');")" == "8" ]] \
      || fail "expired restored machine-quota window did not reset atomically"
  fi
  [[ "$(runtime_scalar "SELECT allowed FROM registry_notary_api.subject_access_quota_check_v1(
    ARRAY['per_principal']::text[], ARRAY[decode(repeat('d8', 32), 'hex')]::bytea[],
    ARRAY[1]::integer[], ARRAY[3600]::integer[]);")" == "f" ]] \
    || fail "restored subject quota reopened its exhausted bucket"
  start_notary "127.0.0.1:${notary_port_a}" "${work_dir}/notary-a-restored.log" notary_pid_a
  wait_ready "${url_a}" "${notary_pid_a}" || fail "Notary did not become ready after logical restore"
  batch_request "${url_a}" "${idempotency_key_a}" "${request_a}" "${work_dir}/response-a-restored.json" 200 \
    || fail "completed decision was unavailable after logical restore"
  [[ "$(jq --raw-output '.batch_id' "${work_dir}/response-a-restored.json")" == "${batch_id}" ]] \
    || fail "logical restore reopened a completed decision"

for output in "${work_dir}"/*.log; do
  [[ -f "${output}" ]] || continue
  for forbidden in \
    "${admin_password}" "${migrator_password}" "${runtime_password}" \
    "${api_key}" "${api_key_hash}" "${audit_secret}" "${sensitive_state_key}" \
    "${idempotency_key_a}" "${idempotency_key_b}" "${idempotency_key_c}" \
    "${target_a}" "${target_b}" "${target_c}" \
    "restart-process-pkce-secret" "restart-database-pkce-secret" \
    "restart-restore-pkce-secret" "restart-process-login-nonce" \
    "restart-database-login-nonce" "restart-restore-login-nonce" \
    "${sensitive_probe_pin}"; do
    if grep --fixed-strings --quiet -- "${forbidden}" "${output}"; then
      fail "a log or diagnostic exposed a synthetic sensitive value"
    fi
  done
done
for output in "${work_dir}"/response-*.json "${work_dir}"/render-*.json; do
  [[ -f "${output}" ]] || continue
  for forbidden in "${target_a}" "${target_b}" "${target_c}"; do
    if grep --fixed-strings --quiet -- "${forbidden}" "${output}"; then
      fail "an API response exposed a raw target identifier"
    fi
  done
done

echo "notary PostgreSQL ${postgresql_major} conformance OK"
