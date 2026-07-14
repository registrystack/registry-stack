#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

postgresql_major="${1:-}"
case "${postgresql_major}" in
  16)
    default_source_image="postgres:16.13-alpine"
    default_target_image="postgres:16.14-alpine"
    ;;
  17)
    default_source_image="postgres:17.9-alpine"
    default_target_image="postgres:17.10-alpine"
    ;;
  18)
    default_source_image="postgres:18.3-alpine"
    default_target_image="postgres:18.4-alpine"
    ;;
  *)
    echo "usage: $0 <16|17|18>" >&2
    exit 2
    ;;
esac

source_image="${NOTARY_POSTGRES_SOURCE_IMAGE:-${default_source_image}}"
target_image="${NOTARY_POSTGRES_TARGET_IMAGE:-${default_target_image}}"
notary_bin="${NOTARY_BIN:-target/debug/registry-notary}"
run_id="${GITHUB_RUN_ID:-local}-$$"
postgres_container="notary-postgres-conformance-${run_id}"
postgres_data_volume="notary-postgres-data-${run_id}"
postgres_cert_volume="notary-postgres-certs-${run_id}"
postgres_port="${NOTARY_POSTGRES_PORT:-$((30000 + ($$ % 8000)))}"
notary_port_a="${NOTARY_CONFORMANCE_PORT_A:-$((41000 + ($$ % 4000)))}"
notary_port_b="${NOTARY_CONFORMANCE_PORT_B:-$((45000 + ($$ % 4000)))}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/notary-postgres-conformance.XXXXXX")"
notary_pid_a=""
notary_pid_b=""

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
  docker rm -f "${postgres_container}" >/dev/null 2>&1
  docker volume rm -f "${postgres_data_volume}" "${postgres_cert_volume}" >/dev/null 2>&1
  rm -rf "${work_dir}"
  exit "${status}"
}
trap cleanup EXIT INT TERM

for command in cargo curl docker jq openssl; do
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
idempotency_key_a="conformance-a-${run_id}"
idempotency_key_b="conformance-b-${run_id}"
idempotency_key_c="conformance-c-${run_id}"
target_a="synthetic-subject-a-${run_id}"
target_b="synthetic-subject-b-${run_id}"
target_c="synthetic-subject-c-${run_id}"

api_key_hash="$(printf '%s\n' "${api_key}" | "${notary_bin}" hash-api-key --stdin --hash-only \
  2>"${work_dir}/hash-api-key.log")"
[[ "${api_key_hash}" == sha256:* ]] || fail "API key hash output is invalid"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj "/CN=Notary conformance CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "${work_dir}/ca.key" -out "${work_dir}/ca.crt" \
  >"${work_dir}/openssl.log" 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
  -keyout "${work_dir}/server.key" -out "${work_dir}/server.csr" \
  >>"${work_dir}/openssl.log" 2>&1
openssl x509 -req -days 2 -in "${work_dir}/server.csr" \
  -CA "${work_dir}/ca.crt" -CAkey "${work_dir}/ca.key" -CAcreateserial \
  -extfile <(printf '%s\n' \
    'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth') \
  -out "${work_dir}/server.crt" >>"${work_dir}/openssl.log" 2>&1
chmod 600 "${work_dir}/server.key"

docker pull "${source_image}" >"${work_dir}/docker-pull.log" 2>&1
docker pull "${target_image}" >>"${work_dir}/docker-pull.log" 2>&1
docker volume create "${postgres_data_volume}" >/dev/null
docker volume create "${postgres_cert_volume}" >/dev/null
docker run --rm --user root \
  --mount "type=bind,source=${work_dir},target=/source,readonly" \
  --mount "type=volume,source=${postgres_cert_volume},target=/certs" \
  "${source_image}" sh -ec \
  'cp /source/server.crt /certs/server.crt; cp /source/server.key /certs/server.key; chown 70:70 /certs/server.crt /certs/server.key; chmod 600 /certs/server.key' \
  >"${work_dir}/certificate-install.log" 2>&1

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

  local deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    if docker exec "${postgres_container}" pg_isready --username postgres --dbname postgres \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "PostgreSQL did not become ready"
}

admin_sql() {
  local database="$1"
  local sql="$2"
  printf '%s\n' "${sql}" | docker exec --interactive "${postgres_container}" \
    psql --set ON_ERROR_STOP=1 --username postgres --dbname "${database}" \
    >"${work_dir}/admin-sql.log" 2>&1
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
REGISTRY_NOTARY_STATE_POSTGRES_TEST_URL="postgresql://postgres@localhost:${postgres_port}/postgres?sslmode=require" \
REGISTRY_NOTARY_STATE_POSTGRES_TEST_CA="${work_dir}/ca.crt" \
  cargo test --locked -p registry-notary-server --lib \
    state_plane::migration::tests::postgres_v1_typed_state_contracts_and_drift_rejection \
    -- --ignored --exact \
    >"${work_dir}/rust-state-contracts.log" 2>&1 \
  || { sed -n '1,240p' "${work_dir}/rust-state-contracts.log" >&2; \
       fail "typed PostgreSQL state contract test failed"; }
docker exec "${postgres_container}" sh -ec \
  'mv "${PGDATA}/pg_hba.conf.conformance" "${PGDATA}/pg_hba.conf"' \
  >>"${work_dir}/postgres-test-auth.log" 2>&1
docker exec "${postgres_container}" psql --username postgres --dbname postgres \
  --command 'SELECT pg_catalog.pg_reload_conf();' \
  >>"${work_dir}/postgres-test-auth.log" 2>&1
provision_roles false "${work_dir}/role-install.log"
source_role_oids="$(role_oid_pair)"
[[ "${source_role_oids}" =~ ^[0-9]+:[0-9]+$ ]] || fail "source role identities are unavailable"

export REGISTRY_NOTARY_POSTGRES_URL="postgresql://registry_notary_runtime:${runtime_password}@localhost:${postgres_port}/registry_notary?sslmode=require"
export REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL="postgresql://registry_notary_migrator:${migrator_password}@localhost:${postgres_port}/registry_notary?sslmode=require"
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
    sensitive_state_key_env: REGISTRY_NOTARY_SENSITIVE_STATE_KEY
auth:
  mode: api_key
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

start_notary() {
  local bind="$1"
  local log_file="$2"
  local pid_variable="$3"
  "${notary_bin}" --config "${config_path}" --bind "${bind}" >"${log_file}" 2>&1 &
  printf -v "${pid_variable}" '%s' "$!"
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

url_a="http://127.0.0.1:${notary_port_a}"
url_b="http://127.0.0.1:${notary_port_b}"
start_notary "127.0.0.1:${notary_port_a}" "${work_dir}/notary-a.log" notary_pid_a
start_notary "127.0.0.1:${notary_port_b}" "${work_dir}/notary-b.log" notary_pid_b
wait_ready "${url_a}" "${notary_pid_a}" || fail "first Notary instance did not become ready"
wait_ready "${url_b}" "${notary_pid_b}" || fail "second Notary instance did not become ready"

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
[[ "$(jq --raw-output '.summary.succeeded' "${work_dir}/response-a1.json")" == "1" ]] \
  || fail "the concurrent batch did not produce one successful evaluation"
evaluation_id="$(jq --exit-status --raw-output '.items[0].evaluation_id | select(type == "string" and length > 0)' "${work_dir}/response-a1.json")"
[[ "$(jq --raw-output '.batch_id' "${work_dir}/response-a2.json")" == "${batch_id}" ]] \
  || fail "concurrent instances did not observe one batch owner"
[[ "$(jq --raw-output '.items[0].evaluation_id' "${work_dir}/response-a2.json")" == "${evaluation_id}" ]] \
  || fail "concurrent instances did not observe one evaluation"

stop_process "${notary_pid_a}"
notary_pid_a=""
start_notary "127.0.0.1:${notary_port_a}" "${work_dir}/notary-a-restart.log" notary_pid_a
wait_ready "${url_a}" "${notary_pid_a}" || fail "restarted Notary instance did not become ready"
batch_request "${url_a}" "${idempotency_key_a}" "${request_a}" "${work_dir}/response-a-restart.json" 200 \
  || fail "restart replay failed"
[[ "$(jq --raw-output '.batch_id' "${work_dir}/response-a-restart.json")" == "${batch_id}" ]] \
  || fail "restart did not preserve the completed decision"

batch_request "${url_b}" "${idempotency_key_b}" "${request_b}" "${work_dir}/response-b.json" 200 \
  || fail "second unique batch failed"
batch_request "${url_a}" "${idempotency_key_c}" "${request_c}" "${work_dir}/response-c-denied.json" 429 \
  || fail "shared machine quota did not reject excess work"

admin_sql postgres 'ALTER DATABASE registry_notary SET default_transaction_read_only = on;'
wait_not_ready "${url_a}" || fail "read-only PostgreSQL did not fail readiness"
if "${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-read-only.log" 2>&1; then
  fail "state doctor accepted read-only PostgreSQL"
fi
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
admin_sql registry_notary \
  'ALTER FUNCTION registry_notary_api.replay_insert_v1(bytea, bytea, timestamptz) VOLATILE;'
wait_ready "${url_a}" "${notary_pid_a}" || fail "readiness did not recover after schema repair"
"${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-schema-recovered.log" 2>&1 \
  || fail "state doctor did not recover after schema repair"

docker stop --time 20 "${postgres_container}" >/dev/null
wait_not_ready "${url_a}" || fail "unavailable PostgreSQL did not fail readiness"
if "${notary_bin}" --config "${config_path}" state doctor >"${work_dir}/doctor-unavailable.log" 2>&1; then
  fail "state doctor accepted unavailable PostgreSQL"
fi
stop_process "${notary_pid_a}"
stop_process "${notary_pid_b}"
notary_pid_a=""
notary_pid_b=""

docker start "${postgres_container}" >/dev/null
for _ in {1..90}; do
  docker exec "${postgres_container}" pg_isready --username postgres --dbname postgres >/dev/null 2>&1 && break
  sleep 1
done
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

if [[ "${postgresql_major}" == "18" ]]; then
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
  start_postgres "${target_image}"
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
  start_notary "127.0.0.1:${notary_port_a}" "${work_dir}/notary-a-restored.log" notary_pid_a
  wait_ready "${url_a}" "${notary_pid_a}" || fail "Notary did not become ready after logical restore"
  batch_request "${url_a}" "${idempotency_key_a}" "${request_a}" "${work_dir}/response-a-restored.json" 200 \
    || fail "completed decision was unavailable after logical restore"
  [[ "$(jq --raw-output '.batch_id' "${work_dir}/response-a-restored.json")" == "${batch_id}" ]] \
    || fail "logical restore reopened a completed decision"
fi

for output in "${work_dir}"/*.log; do
  [[ -f "${output}" ]] || continue
  for forbidden in \
    "${admin_password}" "${migrator_password}" "${runtime_password}" \
    "${api_key}" "${api_key_hash}" "${audit_secret}" "${sensitive_state_key}" \
    "${idempotency_key_a}" "${idempotency_key_b}" "${idempotency_key_c}" \
    "${target_a}" "${target_b}" "${target_c}"; do
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
