#!/usr/bin/env bash
set -euo pipefail

# Proves the documented logical backup and restore of a Registry Casework
# database with the public binaries, over the paired professional-licences
# registry and professional-review Casework templates run by `bregctl dev` and
# `caseworkctl dev`. Before the backup a scope correction is submitted in the
# registry, Casework observes it as a work item and opens its review task, and
# staff claims that task. After `pg_dump` the original approves the review,
# the registry applies the correction, and a second correction is submitted
# and delivered to Casework before Casework stops. The dump is restored into a
# freshly provisioned database. The restored Casework must report the same
# activation ledger, start, and serve Casework-only state at the backup point
# (the claim, but not the later decision) while it replays source-backed work
# from the registry: the applied correction's work item settles and the second
# correction appears as fresh work. The registry reports the second review as
# unknown to its authority, and `bregctl review-recovery resubmit` delivers it
# again. The audit file is not rewound: it keeps the lost window's entries and
# continues after them. One claim on the recovered review succeeds.

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
. "$repository_root/scripts/cargo-runtime-library-path.sh"
temporary_root=""
registry_started=0
casework_started=0
if [[ "$#" -ne 0 ]]; then
  printf '%s\n' 'usage: test-backup-restore.sh' >&2
  exit 2
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "$1 is required for the Casework backup and restore workflow." >&2
    exit 2
  fi
}

checkpoint() {
  printf 'casework backup and restore workflow: %s\n' "$1" >&2
}

fail() {
  printf 'casework backup and restore workflow failed: %s\n' "$1" >&2
  exit 1
}

cleanup() {
  local status=$?
  if [[ "${CASEWORK_RESTORE_KEEP_TEMP:-0}" == "1" ]]; then
    printf '%s\n' "casework backup and restore workflow preserved its sessions and temporary root: $temporary_root" >&2
    return "$status"
  fi
  if [[ "$casework_started" == 1 ]]; then
    "$caseworkctl" --format json dev stop --remove "$temporary_root/casework" >/dev/null 2>&1 ||
      printf '%s\n' 'casework backup and restore workflow could not remove its Casework session' >&2
  fi
  if [[ "$registry_started" == 1 ]]; then
    "$bregctl" --format json dev stop --remove "$temporary_root/registry" >/dev/null 2>&1 ||
      printf '%s\n' 'casework backup and restore workflow could not remove its registry session' >&2
  fi
  case "$temporary_root" in
    "$repository_root"/.casework-restore.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    "") ;;
    *)
      printf '%s\n' 'casework backup and restore workflow temporary directory did not match its validated location' >&2
      return 1
      ;;
  esac
  return "$status"
}
trap cleanup EXIT HUP INT TERM

require_command curl
require_command docker
require_command jq
require_command python3
require_command sha256sum

umask 077
checkpoint "building the candidate binaries"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"
target_directory=${CARGO_TARGET_DIR:-"$repository_root/target"}
bregctl=${BREGCTL_BIN:-"$target_directory/debug/bregctl"}
breg=${BREG_BIN:-"$target_directory/debug/breg"}
caseworkctl=${CASEWORKCTL_BIN:-"$target_directory/debug/caseworkctl"}
casework=${CASEWORK_BIN:-"$target_directory/debug/casework"}
build_arguments=(
  --manifest-path "$repository_root/Cargo.toml" --locked
  -p registry-bregctl
  -p registry-breg
  -p registry-caseworkctl
  -p registry-casework
  --features registry-breg/runtime
)
if [[ "${CASEWORK_RESTORE_SKIP_BUILD:-0}" != "1" ]]; then
  registry_cargo_build "$repository_root" "${build_arguments[@]}"
else
  registry_prepare_cargo_runtime "$repository_root" "${build_arguments[@]}"
fi
for binary in "$bregctl" "$breg" "$caseworkctl" "$casework"; do
  if [[ ! -x "$binary" ]]; then
    printf 'candidate binary is not executable: %s\n' "$binary" >&2
    exit 2
  fi
done
if [[ "$(basename -- "$breg")" != breg || "$(basename -- "$casework")" != casework ]]; then
  printf '%s\n' 'BREG_BIN and CASEWORK_BIN must name files called breg and casework.' >&2
  exit 2
fi
# Both dev supervisors resolve their runtime from PATH.
PATH="$(dirname -- "$casework"):$(dirname -- "$breg"):$PATH"
export PATH

temporary_root=$(mktemp -d "$repository_root/.casework-restore.XXXXXX")
registry_project="$temporary_root/registry"
casework_project="$temporary_root/casework"
work="$temporary_root/work"
mkdir -m 700 "$work"
breg_origin=http://127.0.0.1:8090
casework_origin=http://127.0.0.1:8092

# Runs one ctl command with a JSON report and names the refusal codes on
# failure. The report never carries a credential or a connection URL.
run_json() {
  local output=$1
  local status=0
  shift
  "$@" >"$output" || status=$?
  if [[ "$status" != 0 ]]; then
    printf '%s %s refused; diagnostics: %s\n' "$(basename -- "$1")" "$3" \
      "$(jq -r '[.diagnostics[]? | "\(.code): \(.message)"] | join("; ")' "$output" 2>/dev/null || printf unavailable)" >&2
    return "$status"
  fi
}

# Asserts one jq expression over a JSON file is true.
assert_json() {
  local file=$1
  local expression=$2
  local message=$3
  if [[ "$(jq -r "$expression" "$file")" != true ]]; then
    fail "$message"
  fi
}

# Writes a fresh bearer header file for a local client and prints its path.
# The header file is owner-only and its token is never printed.
breg_header() {
  run_json "$work/breg-token.json" "$bregctl" --format json dev token "$1" "$registry_project"
  jq -r .headerFile "$work/breg-token.json"
}

casework_header() {
  run_json "$work/casework-token.json" "$caseworkctl" --format json dev token "$1" "$casework_project"
  jq -r .headerFile "$work/casework-token.json"
}

# http METHOD URL HEADER_FILE OUTPUT [extra header]... [-- BODY]
# Prints the HTTP status. The bearer stays in its header file.
http() {
  local method=$1
  local url=$2
  local header_file=$3
  local output=$4
  shift 4
  local arguments=(-sS -o "$output" -w '%{http_code}' -X "$method" -H @"$header_file")
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
  local expected=$1
  local actual=$2
  local output=$3
  local description=$4
  if [[ "$actual" != "$expected" ]]; then
    printf '%s\n' "$description answered HTTP $actual; body:" >&2
    head -c 2000 "$output" >&2 || true
    printf '\n' >&2
    fail "$description did not answer HTTP $expected"
  fi
}

# casework_call METHOD PATH OUTPUT [extra header]... [-- BODY], as staff
# reading the registry through its reviewer profile. The staff header file
# already carries Registry-Casework-Profile.
casework_call() {
  local method=$1
  local path=$2
  local output=$3
  shift 3
  http "$method" "$casework_origin$path" "$(casework_header staff)" "$output" \
    'registry-source-profile: reviewer' "$@"
}

review_tasks() {
  local status
  status=$(casework_call GET '/v1/review-tasks?queue=corrections' "$1")
  expect_status 200 "$status" "$1" "the corrections review inbox"
}

work_items() {
  local status
  status=$(casework_call GET '/v1/work-items?view=my-teams&queue=corrections' "$1")
  expect_status 200 "$status" "$1" "the corrections work-item inbox"
}

# Reads a scope correction through the registry's reviewer profile.
correction_view() {
  local status
  status=$(http GET "$breg_origin/v1/records/scope-corrections/$1?accessProfile=reviewer" \
    "$(breg_header staff)" "$2")
  expect_status 200 "$status" "$2" "the reviewer view of correction $1"
}

# wait_for DESCRIPTION SECONDS COMMAND...: retries COMMAND once a second.
wait_for() {
  local description=$1
  local seconds=$2
  local attempt
  shift 2
  for ((attempt = 0; attempt < seconds; attempt++)); do
    if "$@"; then
      return 0
    fi
    sleep 1
  done
  fail "timed out waiting for $description"
}

# Creates a scope correction of the licence as the editor, submits it, and
# prints its record identifier.
submit_correction() {
  local tag=$1
  local header status identifier href if_match
  header=$(breg_header editor)
  status=$(http POST "$breg_origin/v1/records/scope-corrections?accessProfile=editor" \
    "$header" "$work/correction-$tag.json" "idempotency-key: correction-$tag" \
    -- "$(jq -cn --arg record "$licence_id" --arg tag "$tag" \
      '{data:{record:$record,licensedActivities:["example-assessment","example-advisory-services"],authorizationConditions:"",reason:("correction " + $tag),supportingReference:("board-minute-" + $tag)}}')")
  expect_status 201 "$status" "$work/correction-$tag.json" "creating correction $tag"
  identifier=$(jq -r .data.recordIdentifier "$work/correction-$tag.json")
  status=$(http GET "$breg_origin/v1/records/scope-corrections/$identifier?accessProfile=editor" \
    "$header" "$work/correction-$tag-draft.json")
  expect_status 200 "$status" "$work/correction-$tag-draft.json" "reading correction $tag"
  href=$(jq -r '.data.request.actions[] | select(.operation == "submit-request") | .href' "$work/correction-$tag-draft.json")
  if_match=$(jq -r '.data.request.actions[] | select(.operation == "submit-request") | .ifMatch' "$work/correction-$tag-draft.json")
  status=$(http POST "$breg_origin$href" "$header" "$work/correction-$tag-submitted.json" \
    "idempotency-key: submit-$tag" "if-match: $if_match" -- '{}')
  expect_status 200 "$status" "$work/correction-$tag-submitted.json" "submitting correction $tag"
  printf '%s\n' "$identifier"
}

# Succeeds once the registry records the Casework review request a
# correction was submitted as; review_request_of then prints it.
review_request_known() {
  correction_view "$1" "$work/view-$1.json"
  [[ -n "$(jq -r '.data.request.review.submission.requestId // empty' "$work/view-$1.json")" ]]
}

# Succeeds once a resubmitted review is accepted again; the registry records
# the request id the restored Casework answered with only after that.
review_accepted_again() {
  correction_view "$1" "$work/view-$1.json"
  jq -e '.data.request.review.submission | .state == "accepted" and (.requestId // "") != ""' \
    "$work/view-$1.json" >/dev/null
}

review_request_of() {
  jq -r '.data.request.review.submission.requestId' "$work/view-$1.json"
}

task_for_request_open() {
  review_tasks "$work/tasks.json"
  [[ "$(jq -r --arg request "$1" '[.items[] | select(.requestId == $request and .state == "open")] | length' "$work/tasks.json")" == 1 ]]
}

item_for_subject_waiting() {
  work_items "$work/items.json"
  [[ "$(jq -r --arg subject "$1" '[.items[] | select(.subject.id == $subject and .state == "waiting-application")] | length' "$work/items.json")" == 1 ]]
}

# Absence counts only on a page that read every candidate.
item_for_subject_absent() {
  work_items "$work/items.json"
  [[ "$(jq -r --arg subject "$1" '.status == "complete" and ([.items[] | select(.subject.id == $subject)] | length) == 0' "$work/items.json")" == true ]]
}

item_completed() {
  local status
  status=$(casework_call GET "/v1/work-items/$1" "$work/item-$1.json")
  expect_status 200 "$status" "$work/item-$1.json" "reading work item $1"
  [[ "$(jq -r .state "$work/item-$1.json")" == completed ]]
}

review_result_is() {
  correction_view "$1" "$work/view-$1.json"
  [[ "$(jq -r '.data.request.review.result.state' "$work/view-$1.json")" == "$2" ]]
}

review_recovery_is() {
  correction_view "$1" "$work/view-$1.json"
  [[ "$(jq -r '.data.request.review.recovery.code // "none"' "$work/view-$1.json")" == "$2" ]]
}

task_id_for_request() {
  review_tasks "$work/tasks.json"
  jq -r --arg request "$1" '.items[] | select(.requestId == $request) | .taskId' "$work/tasks.json"
}

casework_status() {
  run_json "$1" "$caseworkctl" --format json status --runtime-config "$operator_config"
}

casework_container() {
  jq -r '.containerId // empty' "$casework_project/.casework/dev/state.json"
}

database_ready() {
  docker exec "$container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1
}

psql_admin() {
  docker exec "$container" psql -U postgres -v ON_ERROR_STOP=1 -qAt "$@"
}

checkpoint "authoring the paired registry and Casework projects"
"$bregctl" init "$registry_project" --template professional-licences >/dev/null
"$caseworkctl" init "$casework_project" --template professional-review >/dev/null
run_json "$work/source-add.json" "$caseworkctl" --format json source add "$registry_project" \
  --project "$casework_project" --source-id professional-licences --apply

checkpoint "starting the registry and Casework development sessions"
registry_started=1
run_json "$work/registry-start.json" "$bregctl" --format json dev start "$registry_project"
casework_started=1
run_json "$work/casework-start.json" "$caseworkctl" --format json dev start "$casework_project" \
  --source-project "$registry_project"
operator_config=$(jq -r .operatorConfig "$work/casework-start.json")
registry_runtime_config="$registry_project/.breg/dev/runtime.yaml"
audit_file="$casework_project/.casework/dev/audit/casework.ndjson"
container=$(casework_container)
[[ -n "$container" ]] || fail "the Casework session names no database container"

checkpoint "committing a licence and a submitted correction, and claiming its review"
status=$(http POST "$breg_origin/v1/records/professional-licenses?accessProfile=editor" \
  "$(breg_header editor)" "$work/licence.json" 'idempotency-key: licence-0001' \
  -- '{"data":{"localIdentifier":"licence-0001","personReference":"person-0001","regulatorReference":"regulator-0001","jurisdictionReference":"jurisdiction-0001","professionCode":"example-nursing","licenceStatus":"recorded-active","validFrom":"2026-01-01","licensedActivities":["example-assessment"],"authorizationConditions":"Supervised practice only."}}')
expect_status 201 "$status" "$work/licence.json" "creating the licence"
licence_id=$(jq -r .data.recordIdentifier "$work/licence.json")
first_correction=$(submit_correction first)
wait_for "the first correction's submission to Casework" 60 review_request_known "$first_correction"
first_review=$(review_request_of "$first_correction")
wait_for "the first review task" 60 task_for_request_open "$first_review"
wait_for "the first correction's work item" 60 item_for_subject_waiting "$first_correction"
first_task=$(task_id_for_request "$first_review")
first_item=$(jq -r --arg subject "$first_correction" '.items[] | select(.subject.id == $subject) | .itemId' "$work/items.json")
status=$(casework_call POST "/v1/review-tasks/$first_task/claim" "$work/claim-first.json" \
  'if-match: "1"' 'idempotency-key: claim-first')
expect_status 200 "$status" "$work/claim-first.json" "claiming the first review"
assert_json "$work/claim-first.json" '.revision == 2 and (.state.held.holder.subject | type == "string")' \
  "the claimed review is not held at revision 2"
jq -S '.state' "$work/claim-first.json" >"$work/claim-first-state.json"

checkpoint "recording the activation ledger and taking the logical backup"
casework_status "$work/status-backup.json"
assert_json "$work/status-backup.json" '.active.activationId != null and (.history | length) == 1' \
  "the backup-point ledger does not name one active package"
docker exec "$container" pg_dump -U postgres -Fc casework_dev >"$work/casework.dump"
[[ -s "$work/casework.dump" ]] || fail "pg_dump wrote no archive"
audit_backup_length=$(wc -c <"$audit_file" | tr -d ' ')
audit_backup_digest=$(sha256sum <"$audit_file" | cut -d' ' -f1)

checkpoint "working after the backup: deciding, applying, and submitting again"
status=$(casework_call POST "/v1/review-tasks/$first_task/decisions" "$work/approve-first.json" \
  'if-match: "2"' 'idempotency-key: approve-first' -- '{"decision":{"type":"approve"}}')
expect_status 204 "$status" "$work/approve-first.json" "approving the first review"
wait_for "the registry to record the approval" 120 review_result_is "$first_correction" approved
correction_view "$first_correction" "$work/approved-first.json"
apply_href=$(jq -r '.data.request.actions[] | select(.operation == "apply-request") | .href' "$work/approved-first.json")
apply_if_match=$(jq -r '.data.request.actions[] | select(.operation == "apply-request") | .ifMatch' "$work/approved-first.json")
status=$(http POST "$breg_origin$apply_href" "$(breg_header staff)" "$work/applied-first.json" \
  'idempotency-key: apply-first' "if-match: $apply_if_match" \
  -- "$(jq -c '{proposalVersion: .data.request.proposalVersion, effectDigest: .data.request.effectDigest}' "$work/approved-first.json")")
expect_status 200 "$status" "$work/applied-first.json" "applying the first correction"
wait_for "the applied correction's work item to settle" 60 item_for_subject_absent "$first_correction"
second_correction=$(submit_correction second)
wait_for "the second correction's submission to Casework" 60 review_request_known "$second_correction"
second_review=$(review_request_of "$second_correction")
wait_for "the second review task" 60 task_for_request_open "$second_review"
wait_for "the second correction's work item" 60 item_for_subject_waiting "$second_correction"
lost_second_item=$(jq -r --arg subject "$second_correction" '.items[] | select(.subject.id == $subject) | .itemId' "$work/items.json")
[[ "$(jq -r 'select(.record.event == "casework.review-decided" and .phase == "response") | .eventId' "$audit_file" | wc -l | tr -d ' ')" == 1 ]] ||
  fail "the lost decision was not audited before the restore"

checkpoint "stopping Casework for good and restoring the dump into a fresh database"
run_json "$work/casework-stop.json" "$caseworkctl" --format json dev stop "$casework_project"
if curl -fsS -o /dev/null "$casework_origin/ready" 2>/dev/null; then
  fail "the stopped Casework still answers"
fi
docker start "$container" >/dev/null
wait_for "the Casework PostgreSQL to accept connections" 60 database_ready
psql_admin -c 'DROP DATABASE casework_dev WITH (FORCE)' -c 'CREATE DATABASE casework_dev'
# Provision the fresh database the way the development session provisioned
# the original: the migration role owns the public schema, and a runtime
# role, when the session split one out, reads and writes through it.
mapfile -t casework_roles < <(psql_admin -c "SELECT rolname FROM pg_roles WHERE rolname IN ('casework_dev_migration', 'casework_dev_runtime') ORDER BY rolname")
[[ "${casework_roles[0]:-}" == casework_dev_migration ]] || fail "the Casework migration role is missing"
provision='REVOKE ALL ON DATABASE casework_dev FROM PUBLIC; ALTER SCHEMA public OWNER TO casework_dev_migration; REVOKE ALL ON SCHEMA public FROM PUBLIC;'
if [[ "${casework_roles[1]:-}" == casework_dev_runtime ]]; then
  provision+=' GRANT CONNECT ON DATABASE casework_dev TO casework_dev_migration, casework_dev_runtime; GRANT USAGE ON SCHEMA public TO casework_dev_runtime; ALTER DEFAULT PRIVILEGES FOR ROLE casework_dev_migration IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO casework_dev_runtime; ALTER DEFAULT PRIVILEGES FOR ROLE casework_dev_migration IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO casework_dev_runtime;'
else
  provision+=' GRANT CONNECT ON DATABASE casework_dev TO casework_dev_migration;'
fi
psql_admin -d casework_dev -1 -c "$provision"
casework_status "$work/status-empty.json"
assert_json "$work/status-empty.json" '.active == null' "a fresh database reported an active package"
doctor_status=0
"$caseworkctl" --format json doctor --runtime-config "$operator_config" >"$work/doctor-empty.json" || doctor_status=$?
[[ "$doctor_status" != 0 ]] || fail "doctor accepted a database with no Casework schema"
assert_json "$work/doctor-empty.json" '[.diagnostics[].code] == ["casework.doctor.check-failed"]' \
  "doctor did not refuse the empty database by its schema"
docker exec -i "$container" pg_restore -U postgres --exit-on-error --single-transaction \
  -d casework_dev <"$work/casework.dump"

checkpoint "checking the restored activation ledger before serving"
casework_status "$work/status-restored.json"
if ! diff <(jq -S 'del(.diagnostics)' "$work/status-backup.json") \
  <(jq -S 'del(.diagnostics)' "$work/status-restored.json") >/dev/null; then
  fail "the restored ledger differs from the backup point"
fi
plan_status=0
"$caseworkctl" --format json plan --runtime-config "$operator_config" >"$work/plan-restored.json" || plan_status=$?
[[ "$plan_status" == 0 ]] || fail "plan refused the restored database"
assert_json "$work/plan-restored.json" \
  '.changesPending == false and .databaseIdCheck == "matches" and ([.refusals[].code] == ["casework.activation.already-active"])' \
  "plan does not report the restored package as already active on the same database"
run_json "$work/doctor-restored.json" "$caseworkctl" --format json doctor --runtime-config "$operator_config"

checkpoint "serving the restored database"
run_json "$work/casework-restart.json" "$caseworkctl" --format json dev start "$casework_project" \
  --source-project "$registry_project"
[[ "$(curl -sS -o /dev/null -w '%{http_code}' "$casework_origin/ready")" == 200 ]] ||
  fail "the restored Casework is not ready"
casework_status "$work/status-serving.json"
if ! diff <(jq -S 'del(.diagnostics)' "$work/status-backup.json") \
  <(jq -S 'del(.diagnostics)' "$work/status-serving.json") >/dev/null; then
  fail "starting the restored Casework changed its ledger"
fi

checkpoint "proving Casework-only state is at the backup point"
review_tasks "$work/tasks-restored.json"
assert_json "$work/tasks-restored.json" \
  "[.items[] | select(.taskId == \"$first_task\" and .revision == 2)] | length == 1" \
  "the first review is not back at its backup-point revision"
jq -S --arg task "$first_task" '.items[] | select(.taskId == $task) | .state' "$work/tasks-restored.json" >"$work/restored-first-state.json"
cmp -s "$work/claim-first-state.json" "$work/restored-first-state.json" ||
  fail "the first review is not held by its backup-point claimant"
assert_json "$work/tasks-restored.json" \
  "[.items[] | select(.requestId == \"$second_review\")] | length == 0" \
  "the restored Casework knows a review submitted after the backup"
correction_view "$first_correction" "$work/registry-first.json"
assert_json "$work/registry-first.json" \
  '.data.request.bregState == "applied" and .data.request.review.result.state == "approved"' \
  "the registry no longer holds the decision Casework lost"

checkpoint "proving source-backed work is replayed from the registry"
wait_for "the applied correction's restored work item to settle" 60 item_completed "$first_item"
wait_for "the second correction to reappear as work" 60 item_for_subject_waiting "$second_correction"
replayed_second_item=$(jq -r --arg subject "$second_correction" '.items[] | select(.subject.id == $subject) | .itemId' "$work/items.json")
[[ "$replayed_second_item" != "$lost_second_item" ]] ||
  fail "the replayed work item reused the identifier the restore lost"

checkpoint "recovering the review the restore lost through the registry"
wait_for "the registry to report the lost review" 180 \
  review_recovery_is "$second_correction" result-unknown-to-authority
# The development registry's PostgreSQL presents a certificate from the
# session's own authority, which operator commands trust through SSL_CERT_FILE.
(
  export SSL_CERT_FILE="$registry_project/.breg/dev/tls/ca.pem"
  run_json "$work/resubmit.json" "$bregctl" --format json review-recovery resubmit \
    --runtime-config "$registry_runtime_config" \
    --request-entity scope-correction \
    --request-id "$second_correction" \
    --proposal-version 1
)
assert_json "$work/resubmit.json" \
  '.ok == true and .previousCode == "result-unknown-to-authority" and .state == "pending"' \
  "review recovery did not return the lost review to pending"
wait_for "the resubmitted review's acceptance" 60 review_accepted_again "$second_correction"
recovered_review=$(review_request_of "$second_correction")
wait_for "the resubmitted review task" 60 task_for_request_open "$recovered_review"
recovered_task=$(task_id_for_request "$recovered_review")
status=$(casework_call POST "/v1/review-tasks/$recovered_task/claim" "$work/claim-recovered.json" \
  'if-match: "1"' 'idempotency-key: claim-recovered')
expect_status 200 "$status" "$work/claim-recovered.json" "claiming the recovered review"
assert_json "$work/claim-recovered.json" '.revision == 2' "the recovered review claim did not commit"

checkpoint "checking that the audit file continues instead of rewinding"
[[ "$(head -c "$audit_backup_length" "$audit_file" | sha256sum | cut -d' ' -f1)" == "$audit_backup_digest" ]] ||
  fail "the audit file lost or rewrote its backup-point prefix"
(($(wc -c <"$audit_file") > audit_backup_length)) || fail "the restored Casework appended no audit entry"
jq -s -e 'all(.[]; (keys == ["correlation", "eventId", "phase", "record", "schema", "time"]) and .schema == "registry-casework-audit/v1")' \
  "$audit_file" >/dev/null || fail "an audit entry has an unexpected shape"
[[ "$(jq -r 'select(.record.event == "casework.review-decided" and .phase == "response") | .eventId' "$audit_file" | wc -l | tr -d ' ')" == 1 ]] ||
  fail "the audit file does not keep the one decision the restore lost"
# The applied correction's item completed before the restore and again after
# it, both entries under the same item pseudonym; the second correction was
# observed as two different items, the lost one and the replayed one.
jq -s -e '[.[] | select(.record.event == "casework.completed")] | length == 2 and (map(.record.itemPseudonym) | unique | length) == 1' \
  "$audit_file" >/dev/null || fail "the settled item's completion is not recorded before and after the restore"
jq -s -e '[.[] | select(.record.event == "casework.observed" and .record.itemRevision == 1) | .record.itemPseudonym] | unique | length == 3' \
  "$audit_file" >/dev/null || fail "the replayed item was not observed under a fresh pseudonym"

checkpoint "passed"
