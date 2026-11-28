#!/usr/bin/env bash
set -euo pipefail

# Logical backup/restore of a submitted ReviewPolicy using the public Casework
# CLI and service against a PostgreSQL container this script starts and removes.
# It needs no `rstack dev` run: the script writes the runtime configuration,
# signs its own test tokens and serves with `casework serve`. At the backup point a task is held. A decision after the dump
# is absent after restore, while the activation ledger and holding return
# exactly to the backup point. The audit journal remains append-only outside
# PostgreSQL. A freshly authenticated reviewer can continue the restored task.

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
. "$repository_root/scripts/cargo-runtime-library-path.sh"
temporary_root=""
container=""
server_pid=""
[[ "$#" == 0 ]] || { printf '%s\n' 'usage: test-backup-restore.sh' >&2; exit 2; }

checkpoint() { printf 'casework backup and restore: %s\n' "$1" >&2; }
fail() { printf 'casework backup and restore failed: %s\n' "$1" >&2; exit 1; }
require_command() {
  command -v "$1" >/dev/null 2>&1 || { printf '%s is required\n' "$1" >&2; exit 2; }
}
cleanup() {
  local status=$?
  stop_server
  if [[ "${CASEWORK_RESTORE_KEEP_TEMP:-0}" == 1 ]]; then
    printf 'preserved synthetic session: %s (PostgreSQL container %s)\n' "$temporary_root" "$container" >&2
    return "$status"
  fi
  if [[ -n "$container" ]]; then
    docker rm --force --volumes "$container" >/dev/null 2>&1 ||
      printf '%s\n' 'could not remove the owned PostgreSQL container' >&2
  fi
  case "$temporary_root" in
    "$repository_root"/.casework-restore.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    "") ;;
    *) printf '%s\n' 'temporary root did not match the owned location' >&2; return 1 ;;
  esac
  return "$status"
}
trap cleanup EXIT

start_server() {
  "$casework" --runtime-config "$runtime_config" serve >>"$work/casework.log" 2>&1 &
  server_pid=$!
  local attempt
  for ((attempt=0; attempt<60; attempt++)); do
    [[ "$(curl -sS -o /dev/null -w '%{http_code}' "$casework_origin/ready" 2>/dev/null || true)" == 200 ]] && return 0
    kill -0 "$server_pid" 2>/dev/null || break
    sleep 1
  done
  tail -n 20 "$work/casework.log" >&2 || true
  fail 'Casework did not become ready'
}
stop_server() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=""
  fi
}

for command in curl docker jq sha256sum python3 openssl; do require_command "$command"; done
docker info >/dev/null 2>&1 || fail 'a running Docker daemon is required'
umask 077
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
target_directory=${CARGO_TARGET_DIR:-"$repository_root/target"}
caseworkctl=${CASEWORKCTL_BIN:-"$target_directory/debug/caseworkctl"}
casework=${CASEWORK_BIN:-"$target_directory/debug/casework"}
# Plaintext PostgreSQL on loopback is available only to builds with the
# `postgres-test` feature, which this disposable database needs.
build_arguments=(--manifest-path "$repository_root/Cargo.toml" --locked -j2
  -p registry-caseworkctl -p registry-casework
  --features "registry-caseworkctl/postgres-test,registry-casework/postgres-test")
checkpoint 'building the candidate Casework binaries'
registry_cargo_build "$repository_root" "${build_arguments[@]}"
for binary in "$caseworkctl" "$casework"; do
  [[ -x "$binary" ]] || fail "candidate binary is not executable: $binary"
done

temporary_root=$(mktemp -d "$repository_root/.casework-restore.XXXXXX")
casework_project="$temporary_root/casework"
work="$temporary_root/work"
secrets="$temporary_root/secrets"
mkdir -m 700 "$work" "$secrets" "$temporary_root/audit"
free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
casework_port=$(free_port)
casework_origin="http://127.0.0.1:$casework_port"
audit_file="$temporary_root/audit/audit.ndjson"
issuer=https://identity.backup-restore.example.test
runtime_config="$temporary_root/runtime.yaml"

run_json() {
  local output=$1 status=0
  shift
  "$@" >"$output" || status=$?
  if [[ "$status" != 0 ]]; then
    printf 'command refused (exit %s): %s\n' "$status" \
      "$(jq -r '[.diagnostics[]? | "\(.code): \(.message)"] | join("; ")' "$output" 2>/dev/null || printf unavailable)" >&2
    return "$status"
  fi
}
assert_json() {
  [[ "$(jq -r "$2" "$1")" == true ]] || fail "$3"
}

# Signs a short-lived access token for one caller and writes the request
# header file curl reads, so the token never appears on a command line.
header_for() {
  local person=$1 scope=$2 human=$3 profile=$4 header="$work/header-$1"
  python3 - "$temporary_root/issuer.pem" "$issuer" "$person" "$scope" "$human" "$profile" "$header" <<'PY'
import base64, json, subprocess, sys, time, uuid
key, issuer, person, scope, human, profile, output = sys.argv[1:]
def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=").decode()
now = int(time.time())
claims = {"iss": issuer, "aud": "urn:example:casework-restore", "sub": person, "client_id": person,
          "scope": scope, "iat": now, "exp": now + 300, "jti": str(uuid.uuid4())}
if human == "human":
    claims["registry_actor_kind"] = "human"
signing_input = f"{b64({'alg': 'ES256', 'kid': 'restore-issuer', 'typ': 'at+jwt'})}.{b64(claims)}"
der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key],
                     input=signing_input.encode(), check=True, capture_output=True).stdout
# openssl writes an ASN.1 (r, s) pair. A JWS carries both as fixed-width integers.
def integer(offset):
    length = der[offset + 1]
    return int.from_bytes(der[offset + 2:offset + 2 + length], "big"), offset + 2 + length
r, next_offset = integer(2 + (der[1] & 0x7F if der[1] & 0x80 else 0))
s, _ = integer(next_offset)
signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
token = f"{signing_input}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"
open(output, "w", encoding="ascii").write(f"Authorization: Bearer {token}\nRegistry-Casework-Profile: {profile}\nRegistry-Review-Profile: {profile}\n")
PY
  printf '%s' "$header"
}
http() {
  local method=$1 url=$2 header_file=$3 output=$4
  shift 4
  local arguments=(-sS -o "$output" -w '%{http_code}' -X "$method" -H "@$header_file")
  while [[ "$#" -gt 0 ]]; do
    if [[ "$1" == -- ]]; then
      arguments+=(-H 'content-type: application/json' --data-binary "$2")
      shift 2
    else
      arguments+=(-H "$1")
      shift
    fi
  done
  curl "${arguments[@]}" "$url"
}
expect_status() {
  if [[ "$2" != "$1" ]]; then
    printf '%s answered HTTP %s; body: ' "$4" "$2" >&2
    head -c 1000 "$3" >&2 || true
    printf '\n' >&2
    fail "$4 did not answer HTTP $1"
  fi
}
call_as() {
  local person=$1 scope=$2 human=$3 method=$4 path=$5 output=$6
  shift 6
  # Each caller is named for the access profile the starter declares for it.
  http "$method" "$casework_origin$path" "$(header_for "$person" "$scope" "$human" "$person")" "$output" "$@"
}
as_staff() { call_as staff casework:staff human "$@"; }
as_requester() { call_as requester casework:request service "$@"; }
casework_status() {
  run_json "$1" "$caseworkctl" --format json status --runtime-config "$runtime_config"
}
psql_admin() { docker exec "$container" psql -U postgres -v ON_ERROR_STOP=1 -qAt "$@"; }
database_ready() { docker exec "$container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; }

checkpoint 'starting a disposable PostgreSQL and a standalone submitted review project'
postgres_password=$(openssl rand -hex 16)
container=$(docker run --detach --publish 127.0.0.1::5432 \
  --label org.registrystack.casework-restore=1 \
  --env POSTGRES_PASSWORD="$postgres_password" \
  docker.io/library/postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675)
for ((attempt=0; attempt<60; attempt++)); do
  database_ready && break
  sleep 1
done
database_ready || fail 'the owned PostgreSQL did not start'
database_port=$(docker port "$container" 5432/tcp | head -n 1 | sed 's/.*://')
psql_admin -c 'CREATE DATABASE casework_restore'
# The URL stays in the environment of the Casework processes. No file or
# command line carries it.
export CASEWORK_RESTORE_DATABASE_URL="postgresql://postgres:$postgres_password@127.0.0.1:$database_port/casework_restore"

"$caseworkctl" init "$casework_project" --template standalone-decision >/dev/null
# The starter trusts a teaching issuer and a placeholder subject. Bind it to
# this proof's issuer and to the requester caller the proof signs for.
python3 - "$casework_project/casework.yaml" "$issuer" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
for before, after in (("issuer: http://127.0.0.1:8093", f"issuer: {sys.argv[2]}"),
                      ("subject: b75315b2-5854-70f3-8867-511dd771a6da", "subject: requester")):
    assert text.count(before) == 1, before
    text = text.replace(before, after)
path.write_text(text)
PY
run_json "$work/check.json" "$caseworkctl" --format json check "$casework_project"
assert_json "$work/check.json" '.policyBindings | length == 1' 'the starter did not compile one policy'
run_json "$work/explain.json" "$caseworkctl" --format json explain "$casework_project"
assert_json "$work/explain.json" \
  '.contextProviders == [] and all(.reviewPolicies[]; .context.mode == "submitted" and .dependencies.taskTemplates == [])' \
  'the backup fixture inherited external context or task-grant authority'
run_json "$work/package.json" "$caseworkctl" --format json package "$casework_project" \
  --output "$temporary_root/package"

openssl rand -hex 32 >"$secrets/casework-audit-key"
openssl ecparam -name prime256v1 -genkey -noout -out "$temporary_root/issuer.pem" >/dev/null 2>&1
python3 - "$temporary_root/issuer.pem" "$secrets/jwks" <<'PY'
import base64, json, subprocess, sys
der = subprocess.run(["openssl", "pkey", "-in", sys.argv[1], "-pubout", "-outform", "DER"],
                     check=True, capture_output=True).stdout
def coordinate(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
jwk = {"alg": "ES256", "crv": "P-256", "kid": "restore-issuer", "kty": "EC", "use": "sig",
       "x": coordinate(der[-64:-32]), "y": coordinate(der[-32:])}
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps({"keys": [jwk]}))
PY
cat >"$runtime_config" <<YAML
apiVersion: id.registrystack.org/formats/casework/runtime/v1alpha1
kind: CaseworkRuntimeConfig
package:
  root: $temporary_root/package
secretProviders:
  file:
    root: $secrets
  environment: {}
database:
  runtimeUrlRef: secret:env/CASEWORK_RESTORE_DATABASE_URL
  migrationUrlRef: secret:env/CASEWORK_RESTORE_DATABASE_URL
  testOnlyPlaintext: true
identity:
  databaseId: casework-backup-restore
listener:
  bind: 127.0.0.1:$casework_port
  tlsTermination: loopback-plaintext
audit:
  hashKeyRef: secret:file/casework-audit-key
  path: $audit_file
authentication:
  oidc:
    issuer: $issuer
    audience: urn:example:casework-restore
    allowedClients: [requester, staff, administrator]
    scopeClaim: scope
    humanIdentity: {claim: registry_actor_kind, value: human}
    jwksSource: {type: static, documentRef: secret:file/jwks}
YAML
run_json "$work/apply.json" "$caseworkctl" --format json apply --runtime-config "$runtime_config"
start_server
casework_status "$work/status-first.json"

checkpoint 'staffing the queue, then creating and claiming a submitted review before the backup'
status=$(call_as administrator casework:admin human POST /v1/directory/bootstrap "$work/bootstrap.json" \
  'if-match: "0"' 'idempotency-key: backup-restore-staff' \
  -- "{\"teamId\":\"decisions-team\",\"queueId\":\"decisions\",\"staff\":[{\"issuer\":\"$issuer\",\"subject\":\"staff\"}],\"supervisors\":[]}")
expect_status 200 "$status" "$work/bootstrap.json" 'staffing the queue'
[[ -s "$audit_file" ]] || fail 'the Casework audit journal is missing'
subject_digest="sha256:$(printf 'backup-restore-batch-v1\n' | sha256sum | cut -d' ' -f1)"
request=$(jq -cn --arg digest "$subject_digest" \
  '{policy:{id:"decision"},subject:{source:"standalone",type:"batch",id:"backup-restore-batch",version:"1",digest:$digest},requesterReference:"backup-restore-batch",context:{mode:"submitted",snapshot:{summary:"Check the synthetic batch",reference:"backup-restore-batch"}}}')
status=$(as_requester POST '/v1/review-requests' "$work/accepted.json" \
  'idempotency-key: backup-restore-create' -- "$request")
expect_status 201 "$status" "$work/accepted.json" 'creating the review'
request_id=$(jq -r '.requestId' "$work/accepted.json")
status=$(as_staff GET '/v1/review-tasks?queue=decisions&limit=25' "$work/tasks.json")
expect_status 200 "$status" "$work/tasks.json" 'reading the review inbox'
assert_json "$work/tasks.json" \
  "[.items[] | select(.requestId == \"$request_id\")] | length == 1" \
  'the submitted request has no visible review task'
task_id=$(jq -r --arg id "$request_id" '.items[] | select(.requestId == $id) | .taskId' "$work/tasks.json")
revision=$(jq -r --arg id "$request_id" '.items[] | select(.requestId == $id) | .revision' "$work/tasks.json")
status=$(as_staff POST "/v1/review-tasks/$task_id/claim" "$work/claimed.json" \
  "if-match: \"$revision\"" 'idempotency-key: backup-restore-claim')
expect_status 200 "$status" "$work/claimed.json" 'claiming the review'
jq -e '.state.held.holder.subject == "staff"' "$work/claimed.json" >/dev/null ||
  fail 'the review was not held by the staff caller'
jq -S '{taskId,requestId,revision,state}' "$work/claimed.json" >"$work/backup-task.json"

checkpoint 'recording activation and taking a logical backup'
casework_status "$work/status-backup.json"
assert_json "$work/status-backup.json" \
  '.activation.active.activationId != null and (.activation.history | length) == 1' \
  'the backup-point activation ledger does not name one active package'
docker exec "$container" pg_dump -U postgres -Fc casework_restore >"$work/casework.dump"
[[ -s "$work/casework.dump" ]] || fail 'pg_dump wrote no archive'
audit_backup_length=$(wc -c <"$audit_file" | tr -d ' ')
audit_backup_digest=$(head -c "$audit_backup_length" "$audit_file" | sha256sum | cut -d' ' -f1)

checkpoint 'deciding after the backup point'
claimed_revision=$(jq -r '.revision' "$work/claimed.json")
status=$(as_staff POST "/v1/review-tasks/$task_id/decisions" "$work/decided.json" \
  "if-match: \"$claimed_revision\"" 'idempotency-key: backup-restore-answer' \
  -- '{"decision":{"type":"answer","outcome":"confirmed"}}')
expect_status 204 "$status" "$work/decided.json" 'deciding after backup'
status=$(as_requester GET "/v1/review-requests/$request_id/result" "$work/result-lost-window.json")
expect_status 200 "$status" "$work/result-lost-window.json" 'reading the post-backup result'
assert_json "$work/result-lost-window.json" '.status == "answered"' \
  'the post-backup decision did not produce an answer result'
if [[ $(jq -r 'select(.record.event == "casework.review-decided" and .phase == "response") | .eventId' "$audit_file" | wc -l | tr -d ' ') != 1 ]]; then
  fail 'the post-backup decision was not audited'
fi

checkpoint 'stopping Casework and restoring into a newly provisioned database'
stop_server
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "$casework_origin/ready" 2>/dev/null || true)" != 200 ]] ||
  fail 'the stopped Casework still answers readiness'
psql_admin -c 'DROP DATABASE casework_restore WITH (FORCE)' -c 'CREATE DATABASE casework_restore'
casework_status "$work/status-empty.json"
assert_json "$work/status-empty.json" '.activation.active == null' \
  'the fresh database unexpectedly reported an active package'
docker exec -i "$container" pg_restore -U postgres --exit-on-error --single-transaction \
  -d casework_restore <"$work/casework.dump"

checkpoint 'verifying the restored activation and readiness'
casework_status "$work/status-restored.json"
diff <(jq -S '.activation' "$work/status-backup.json") \
  <(jq -S '.activation' "$work/status-restored.json") >/dev/null ||
  fail 'the restored activation ledger differs from the backup point'
run_json "$work/plan-restored.json" "$caseworkctl" --format json plan \
  --runtime-config "$runtime_config"
assert_json "$work/plan-restored.json" \
  '.plan.changesPending == false and .plan.databaseIdCheck == "matches" and ([.plan.refusals[].code] == ["casework.activation.already-active"])' \
  'plan does not recognize the restored active package and database identity'
start_server
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "$casework_origin/ready")" == 200 ]] ||
  fail 'the restored service is not ready'
casework_status "$work/status-serving.json"
diff <(jq -S '.activation' "$work/status-backup.json") \
  <(jq -S '.activation' "$work/status-serving.json") >/dev/null ||
  fail 'serving changed the restored activation ledger'

checkpoint 'checking the held task and missing later decision'
status=$(as_staff GET "/v1/review-tasks/$task_id" "$work/restored-task.json")
expect_status 200 "$status" "$work/restored-task.json" 'reading the restored task'
jq -S '{taskId,requestId,revision,state}' "$work/restored-task.json" >"$work/restored-task-core.json"
cmp -s "$work/backup-task.json" "$work/restored-task-core.json" ||
  fail 'the restored task lost its backup-point holding or revision'
status=$(as_requester GET "/v1/review-requests/$request_id/result" "$work/result-restored.json")
expect_status 202 "$status" "$work/result-restored.json" \
  'reading the restored still-pending result'
status=$(as_requester GET "/v1/review-tasks/$task_id" "$work/requester-task.json")
expect_status 403 "$status" "$work/requester-task.json" \
  'refusing producer access to the human task'

checkpoint 'continuing under a fresh reviewer credential'
status=$(as_staff POST "/v1/review-tasks/$task_id/decisions" "$work/continued.json" \
  "if-match: \"$claimed_revision\"" 'idempotency-key: backup-restore-continued-answer' \
  -- '{"decision":{"type":"answer","outcome":"confirmed"}}')
expect_status 204 "$status" "$work/continued.json" 'deciding the restored task'
status=$(as_requester GET "/v1/review-requests/$request_id/result" "$work/result-continued.json")
expect_status 200 "$status" "$work/result-continued.json" 'reading the recovered result'
assert_json "$work/result-continued.json" '.status == "answered"' \
  'fresh reviewer operation did not settle the restored request'

checkpoint 'checking the audit journal was not rewound'
[[ "$(head -c "$audit_backup_length" "$audit_file" | sha256sum | cut -d' ' -f1)" == "$audit_backup_digest" ]] ||
  fail 'the audit file lost or rewrote its backup-point prefix'
(( $(wc -c <"$audit_file") > audit_backup_length )) ||
  fail 'the restored Casework appended no audit entry'
jq -s -e 'all(.[]; .schema == "registry-casework-audit/v1") and ([.[] | select(.record.event == "casework.review-decided" and .phase == "response")] | length == 2)' \
  "$audit_file" >/dev/null || fail 'audit does not retain both the lost-window and continued decisions'

checkpoint 'passed'
