#!/usr/bin/env bash
set -euo pipefail

# Logical backup/restore of a submitted ReviewPolicy using the public Casework
# CLI and service. At the backup point a task is held. A decision after the dump
# is absent after restore, while the activation ledger and holding return
# exactly to the backup point. The audit journal remains append-only outside
# PostgreSQL. A freshly authenticated reviewer can continue the restored task.

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
. "$repository_root/scripts/cargo-runtime-library-path.sh"
temporary_root=""
casework_started=0
[[ "$#" == 0 ]] || { printf '%s\n' 'usage: test-backup-restore.sh' >&2; exit 2; }

checkpoint() { printf 'casework backup and restore: %s\n' "$1" >&2; }
fail() { printf 'casework backup and restore failed: %s\n' "$1" >&2; exit 1; }
require_command() {
  command -v "$1" >/dev/null 2>&1 || { printf '%s is required\n' "$1" >&2; exit 2; }
}
cleanup() {
  local status=$?
  if [[ "${CASEWORK_RESTORE_KEEP_TEMP:-0}" == 1 ]]; then
    printf 'preserved synthetic session: %s\n' "$temporary_root" >&2
    return "$status"
  fi
  if [[ "$casework_started" == 1 ]]; then
    "$caseworkctl" --format json dev stop --remove "$casework_project" >/dev/null 2>&1 ||
      printf '%s\n' 'could not remove the owned Casework dev session' >&2
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

for command in curl docker jq sha256sum python3; do require_command "$command"; done
docker info >/dev/null 2>&1 || fail 'a running Docker daemon is required'
umask 077
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
target_directory=${CARGO_TARGET_DIR:-"$repository_root/target"}
caseworkctl=${CASEWORKCTL_BIN:-"$target_directory/debug/caseworkctl"}
casework=${CASEWORK_BIN:-"$target_directory/debug/casework"}
build_arguments=(--manifest-path "$repository_root/Cargo.toml" --locked -j2
  -p registry-caseworkctl -p registry-casework)
checkpoint 'building the candidate Casework binaries'
registry_cargo_build "$repository_root" "${build_arguments[@]}"
for binary in "$caseworkctl" "$casework"; do
  [[ -x "$binary" ]] || fail "candidate binary is not executable: $binary"
done
[[ "$(basename -- "$casework")" == casework ]] || fail 'CASEWORK_BIN must name casework'
# The dev supervisor resolves the service executable from PATH.
PATH="$(dirname -- "$casework"):$PATH"
export PATH

temporary_root=$(mktemp -d "$repository_root/.casework-restore.XXXXXX")
casework_project="$temporary_root/casework"
work="$temporary_root/work"
mkdir -m 700 "$work"
casework_port=${CASEWORK_RESTORE_CASEWORK_PORT:-8092}
issuer_port=${CASEWORK_RESTORE_ISSUER_PORT:-8093}
database_port=${CASEWORK_RESTORE_DATABASE_PORT:-15433}
casework_origin="http://127.0.0.1:$casework_port"
audit_file="$casework_project/.casework/dev/audit/casework.ndjson"

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
header_for() {
  run_json "$work/token-$1.json" "$caseworkctl" --format json dev token "$1" "$casework_project"
  jq -r '.data.headerFile' "$work/token-$1.json"
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
  local client=$1 method=$2 path=$3 output=$4
  shift 4
  http "$method" "$casework_origin$path" "$(header_for "$client")" "$output" "$@"
}
casework_status() {
  run_json "$1" "$caseworkctl" --format json status --runtime-config "$operator_config"
}
psql_admin() { docker exec "$container" psql -U postgres -v ON_ERROR_STOP=1 -qAt "$@"; }
database_ready() { docker exec "$container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; }

checkpoint 'starting a standalone submitted review session'
"$caseworkctl" init "$casework_project" --template standalone-decision >/dev/null
# The starter pins its teaching issuer to the default port. Keep the owned
# project binding exact when this proof uses alternate collision-free ports.
if [[ "$issuer_port" != 8093 ]]; then
  python3 - "$casework_project/casework.yaml" "$issuer_port" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
original = path.read_text()
before = 'issuer: http://127.0.0.1:8093'
assert original.count(before) == 1
path.write_text(original.replace(before, f'issuer: http://127.0.0.1:{sys.argv[2]}'))
PY
fi
run_json "$work/check.json" "$caseworkctl" --format json check "$casework_project"
assert_json "$work/check.json" '.data.policyBindings | length == 1' 'the starter did not compile one policy'
run_json "$work/explain.json" "$caseworkctl" --format json explain "$casework_project"
assert_json "$work/explain.json" \
  '.data.contextProviders == [] and all(.data.reviewPolicies[]; .context.mode == "submitted" and .dependencies.taskTemplates == [])' \
  'the backup fixture inherited external context or task-grant authority'
casework_started=1
run_json "$work/dev-start.json" "$caseworkctl" --format json dev start "$casework_project" \
  --casework-port "$casework_port" --issuer-port "$issuer_port" --database-port "$database_port"
operator_config=$(jq -r '.data.operatorConfig' "$work/dev-start.json")
container=$(jq -r '.containerId // empty' "$casework_project/.casework/dev/state.json")
[[ -n "$container" ]] || fail 'the owned session names no database container'
[[ -s "$audit_file" ]] || fail 'the Casework audit journal is missing'

checkpoint 'creating and claiming a submitted review before the backup'
policy=$(jq -c '.data.policyBindings[] | select(.id == "decision")' "$work/check.json")
[[ -n "$policy" ]] || fail 'the exact compiled policy binding is missing'
subject_digest="sha256:$(printf 'backup-restore-batch-v1\n' | sha256sum | cut -d' ' -f1)"
request=$(jq -cn --argjson policy "$policy" --arg digest "$subject_digest" \
  '{policy:$policy,subject:{source:"standalone",type:"batch",id:"backup-restore-batch",version:"1",digest:$digest},requesterReference:"backup-restore-batch",context:{mode:"submitted",snapshot:{summary:"Check the synthetic batch",reference:"backup-restore-batch"}}}')
status=$(call_as requester POST '/v1/review-requests' "$work/accepted.json" \
  'idempotency-key: backup-restore-create' -- "$request")
expect_status 201 "$status" "$work/accepted.json" 'creating the review'
request_id=$(jq -r '.requestId' "$work/accepted.json")
status=$(call_as staff GET '/v1/review-tasks?queue=decisions&limit=25' "$work/tasks.json")
expect_status 200 "$status" "$work/tasks.json" 'reading the review inbox'
assert_json "$work/tasks.json" \
  "[.items[] | select(.requestId == \"$request_id\")] | length == 1" \
  'the submitted request has no visible review task'
task_id=$(jq -r --arg id "$request_id" '.items[] | select(.requestId == $id) | .taskId' "$work/tasks.json")
revision=$(jq -r --arg id "$request_id" '.items[] | select(.requestId == $id) | .revision' "$work/tasks.json")
status=$(call_as staff POST "/v1/review-tasks/$task_id/claim" "$work/claimed.json" \
  "if-match: \"$revision\"" 'idempotency-key: backup-restore-claim')
expect_status 200 "$status" "$work/claimed.json" 'claiming the review'
run_json "$work/staff-identity.json" "$caseworkctl" --format json dev identity staff
staff_subject=$(jq -r '.data.subject' "$work/staff-identity.json")
jq -e --arg subject "$staff_subject" \
  '.state.held.holder.subject == $subject' "$work/claimed.json" >/dev/null ||
  fail 'the review was not held by the staff caller'
jq -S '{taskId,requestId,revision,state}' "$work/claimed.json" >"$work/backup-task.json"

checkpoint 'recording activation and taking a logical backup'
casework_status "$work/status-backup.json"
assert_json "$work/status-backup.json" \
  '.data.activation.active.activationId != null and (.data.activation.history | length) == 1' \
  'the backup-point activation ledger does not name one active package'
docker exec "$container" pg_dump -U postgres -Fc casework_dev >"$work/casework.dump"
[[ -s "$work/casework.dump" ]] || fail 'pg_dump wrote no archive'
audit_backup_length=$(wc -c <"$audit_file" | tr -d ' ')
audit_backup_digest=$(head -c "$audit_backup_length" "$audit_file" | sha256sum | cut -d' ' -f1)

checkpoint 'deciding after the backup point'
claimed_revision=$(jq -r '.revision' "$work/claimed.json")
status=$(call_as staff POST "/v1/review-tasks/$task_id/decisions" "$work/decided.json" \
  "if-match: \"$claimed_revision\"" 'idempotency-key: backup-restore-answer' \
  -- '{"decision":{"type":"answer","outcome":"confirmed"}}')
expect_status 204 "$status" "$work/decided.json" 'deciding after backup'
status=$(call_as requester GET "/v1/review-requests/$request_id/result" "$work/result-lost-window.json")
expect_status 200 "$status" "$work/result-lost-window.json" 'reading the post-backup result'
assert_json "$work/result-lost-window.json" '.status == "answered"' \
  'the post-backup decision did not produce an answer result'
if [[ $(jq -r 'select(.record.event == "casework.review-decided" and .phase == "response") | .eventId' "$audit_file" | wc -l | tr -d ' ') != 1 ]]; then
  fail 'the post-backup decision was not audited'
fi

checkpoint 'stopping Casework and restoring into a newly provisioned database'
run_json "$work/dev-stop.json" "$caseworkctl" --format json dev stop "$casework_project"
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "$casework_origin/ready" 2>/dev/null || true)" != 200 ]] ||
  fail 'the stopped Casework still answers readiness'
docker start "$container" >/dev/null
for ((attempt=0; attempt<60; attempt++)); do
  database_ready && break
  sleep 1
done
database_ready || fail 'the owned PostgreSQL did not restart'
psql_admin -c 'DROP DATABASE casework_dev WITH (FORCE)' -c 'CREATE DATABASE casework_dev'
mapfile -t casework_roles < <(psql_admin -c \
  "SELECT rolname FROM pg_roles WHERE rolname IN ('casework_dev_migration', 'casework_dev_runtime') ORDER BY rolname")
[[ "${casework_roles[0]:-}" == casework_dev_migration ]] || fail 'the migration role is missing'
provision='REVOKE ALL ON DATABASE casework_dev FROM PUBLIC; ALTER SCHEMA public OWNER TO casework_dev_migration; REVOKE ALL ON SCHEMA public FROM PUBLIC;'
if [[ "${casework_roles[1]:-}" == casework_dev_runtime ]]; then
  provision+=' GRANT CONNECT ON DATABASE casework_dev TO casework_dev_migration, casework_dev_runtime; GRANT USAGE ON SCHEMA public TO casework_dev_runtime; ALTER DEFAULT PRIVILEGES FOR ROLE casework_dev_migration IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO casework_dev_runtime; ALTER DEFAULT PRIVILEGES FOR ROLE casework_dev_migration IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO casework_dev_runtime;'
else
  provision+=' GRANT CONNECT ON DATABASE casework_dev TO casework_dev_migration;'
fi
psql_admin -d casework_dev -1 -c "$provision"
casework_status "$work/status-empty.json"
assert_json "$work/status-empty.json" '.data.activation.active == null' \
  'the fresh database unexpectedly reported an active package'
docker exec -i "$container" pg_restore -U postgres --exit-on-error --single-transaction \
  -d casework_dev <"$work/casework.dump"

checkpoint 'verifying the restored activation and readiness'
casework_status "$work/status-restored.json"
diff <(jq -S '.data.activation' "$work/status-backup.json") \
  <(jq -S '.data.activation' "$work/status-restored.json") >/dev/null ||
  fail 'the restored activation ledger differs from the backup point'
run_json "$work/plan-restored.json" "$caseworkctl" --format json plan \
  --runtime-config "$operator_config"
assert_json "$work/plan-restored.json" \
  '.data.plan.changesPending == false and .data.plan.databaseIdCheck == "matches" and ([.data.plan.refusals[].code] == ["casework.activation.already-active"])' \
  'plan does not recognize the restored active package and database identity'
run_json "$work/dev-restart.json" "$caseworkctl" --format json dev start "$casework_project" \
  --casework-port "$casework_port" --issuer-port "$issuer_port" --database-port "$database_port"
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "$casework_origin/ready")" == 200 ]] ||
  fail 'the restored service is not ready'
casework_status "$work/status-serving.json"
diff <(jq -S '.data.activation' "$work/status-backup.json") \
  <(jq -S '.data.activation' "$work/status-serving.json") >/dev/null ||
  fail 'serving changed the restored activation ledger'

checkpoint 'checking the held task and missing later decision'
status=$(call_as staff GET "/v1/review-tasks/$task_id" "$work/restored-task.json")
expect_status 200 "$status" "$work/restored-task.json" 'reading the restored task'
jq -S '{taskId,requestId,revision,state}' "$work/restored-task.json" >"$work/restored-task-core.json"
cmp -s "$work/backup-task.json" "$work/restored-task-core.json" ||
  fail 'the restored task lost its backup-point holding or revision'
status=$(call_as requester GET "/v1/review-requests/$request_id/result" "$work/result-restored.json")
expect_status 202 "$status" "$work/result-restored.json" \
  'reading the restored still-pending result'
status=$(call_as requester GET "/v1/review-tasks/$task_id" "$work/requester-task.json")
expect_status 403 "$status" "$work/requester-task.json" \
  'refusing producer access to the human task'

checkpoint 'continuing under a fresh reviewer credential'
status=$(call_as staff POST "/v1/review-tasks/$task_id/decisions" "$work/continued.json" \
  "if-match: \"$claimed_revision\"" 'idempotency-key: backup-restore-continued-answer' \
  -- '{"decision":{"type":"answer","outcome":"confirmed"}}')
expect_status 204 "$status" "$work/continued.json" 'deciding the restored task'
status=$(call_as requester GET "/v1/review-requests/$request_id/result" "$work/result-continued.json")
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
