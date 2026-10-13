#!/usr/bin/env bash
# Exercise Messaging against a BReg-owned ThunderID session through public CLIs.
#
# Run from any directory:
#   products/messaging/scripts/test-dev-shared-issuer.sh
#
# The script builds registry-messagingctl, registry-bregctl, and the BReg runtime
# unless MESSAGING_SHARED_ISSUER_SKIP_BUILD=1. MESSAGINGCTL_BIN, BREGCTL_BIN, and
# BREG_BIN may name already-built executables. Docker, curl, and python3 are
# required. Every generated file is private and the script removes only the
# Messaging session and BReg owner it creates.
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
# shellcheck source-path=SCRIPTDIR/../../..
# shellcheck source=scripts/cargo-runtime-library-path.sh
# shellcheck disable=SC1091
. "$repository_root/scripts/cargo-runtime-library-path.sh"

test_name=messaging-shared-issuer
temporary_root=
temporary_base=$(CDPATH='' cd -- "${TMPDIR:-/tmp}" && pwd -P)
owner_project=
messaging_project=
messaging_pid=
docker_bin=

fail() {
  printf '%s: %s\n' "$test_name" "$1" >&2
  exit 1
}

checkpoint() {
  printf '%s: %s\n' "$test_name" "$1"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

process_runs() {
  [[ -n "${1:-}" ]] && kill -0 "$1" 2>/dev/null
}

wait_for_exit() {
  local pid=$1 seconds=$2
  local deadline=$((SECONDS + seconds))
  while process_runs "$pid"; do
    ((SECONDS <= deadline)) || return 1
    sleep 1
  done
}

stop_messaging_process() {
  if ! process_runs "$messaging_pid"; then
    return 0
  fi
  kill -INT "$messaging_pid" 2>/dev/null || :
  if ! wait_for_exit "$messaging_pid" 60; then
    kill -KILL "$messaging_pid" 2>/dev/null || :
    wait_for_exit "$messaging_pid" 10 || :
    return 1
  fi
}

cleanup() {
  local exit_code=$?
  trap - EXIT HUP INT TERM
  if [[ -n "$messaging_pid" ]]; then
    stop_messaging_process || :
    wait "$messaging_pid" 2>/dev/null || :
    messaging_pid=
  fi
  if [[ -n "$messaging_project" && -f "$messaging_project/.messaging/dev/session.json" ]]; then
    python3 - "$messaging_project/.messaging/dev/session.json" <<'PY' |
import json, sys
for container in json.load(open(sys.argv[1], encoding="utf-8")).get("containers", []):
    if isinstance(container, str):
        print(container)
PY
    while IFS= read -r container; do
      "$docker_bin" rm --force --volumes "$container" >/dev/null 2>&1 || :
    done
  fi
  if [[ -n "$owner_project" && -d "$owner_project" && -x "${bregctl:-}" ]]; then
    "$bregctl" --format json dev stop --remove --docker-bin "$docker_bin" \
      "$owner_project" >/dev/null 2>&1 || :
  fi
  case "$temporary_root" in
    "$temporary_base"/messaging-shared-issuer.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    '') ;;
    *) printf '%s: kept unexpected temporary root %s\n' "$test_name" "$temporary_root" >&2 ;;
  esac
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

json_member() {
  python3 - "$1" "$2" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for key in sys.argv[2].split("."):
    value = value[key]
print(value)
PY
}

file_sha256() {
  python3 - "$1" <<'PY'
import hashlib, sys
digest = hashlib.sha256()
with open(sys.argv[1], "rb") as source:
    for block in iter(lambda: source.read(65536), b""):
        digest.update(block)
print(digest.hexdigest())
PY
}

free_ports() {
  python3 - "$1" <<'PY'
import socket, sys
sockets = []
ports = []
for _ in range(int(sys.argv[1])):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
    ports.append(sock.getsockname()[1])
print(*ports)
for sock in sockets:
    sock.close()
PY
}

wait_for_messaging_ready() {
  local pid=$1 output=$2 seconds=$3
  local deadline=$((SECONDS + seconds))
  while :; do
    if grep -q '"state":"ready"' "$output" 2>/dev/null; then
      return 0
    fi
    if ! process_runs "$pid"; then
      return 1
    fi
    ((SECONDS <= deadline)) || return 2
    sleep 1
  done
}

ready_report() {
  python3 - "$1" <<'PY'
import json, sys
text = open(sys.argv[1], encoding="utf-8").read()
decoder = json.JSONDecoder()
offset = 0
while offset < len(text):
    while offset < len(text) and text[offset].isspace():
        offset += 1
    if offset == len(text):
        break
    report, offset = decoder.raw_decode(text, offset)
    if report.get("state") == "ready":
        print(json.dumps(report, separators=(",", ":")))
        raise SystemExit(0)
raise SystemExit("Messaging emitted no ready report")
PY
}

require_breg_ready_report() {
  python3 - "$1" <<'PY'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
if report.get("ok") is not True or report.get("status") != "ready":
    raise SystemExit("BReg owner did not reach ready")
for member in ("bregUrl", "issuer", "tokenEndpoint"):
    if not isinstance(report.get(member), str) or not report[member]:
        raise SystemExit(f"BReg owner omitted {member}")
PY
}

messaging_header() {
  local client=$1 report=$2
  "$messagingctl" --format json dev token "$client" "$messaging_project" >"$report"
  local header
  header=$(json_member "$report" headerFile)
  [[ "$header" == "$messaging_project"/.messaging/dev/tokens/*.header ]] ||
    fail "dev token reported a header outside the Messaging session"
  [[ -f "$header" && ! -L "$header" ]] || fail "dev token did not write a regular header file"
  printf '%s\n' "$header"
}

submit_message() {
  local header=$1 key=$2 body=$3 output=$4
  curl --silent --show-error --fail-with-body --connect-timeout 2 --max-time 30 \
    -X POST "$messaging_api/v1/messages" \
    -H @"$header" -H 'content-type: application/json' \
    -H "Idempotency-Key: $key" --data-binary @"$body" >"$output"
  json_member "$output" id
}

wait_for_message_status() {
  local header=$1 message=$2 expected=$3 output=$4
  local seconds=${MESSAGING_SHARED_ISSUER_SETTLE_SECONDS:-60}
  local deadline=$((SECONDS + seconds)) status=
  while :; do
    curl --silent --show-error --fail-with-body --connect-timeout 2 --max-time 10 \
      "$messaging_api/v1/messages/$message" -H @"$header" >"$output"
    status=$(json_member "$output" status)
    [[ "$status" == "$expected" ]] && return 0
    ((SECONDS <= deadline)) ||
      fail "message $message remained $status instead of reaching $expected"
    sleep 0.5
  done
}

if [[ "$#" -ne 0 ]]; then
  printf 'usage: %s\n' "${0##*/}" >&2
  exit 2
fi

for command in docker curl python3; do
  require_command "$command"
done
docker_bin=$(command -v docker)

target_directory=${CARGO_TARGET_DIR:-"$repository_root/target"}
messagingctl=${MESSAGINGCTL_BIN:-"$target_directory/debug/messagingctl"}
bregctl=${BREGCTL_BIN:-"$target_directory/debug/bregctl"}
breg=${BREG_BIN:-"$target_directory/debug/breg"}

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"
if [[ "${MESSAGING_SHARED_ISSUER_SKIP_BUILD:-0}" != 1 ]]; then
  checkpoint "building Messaging and BReg development binaries"
  registry_cargo_build "$repository_root" --manifest-path "$repository_root/Cargo.toml" \
    --locked -p registry-messagingctl -p registry-bregctl -p registry-breg \
    --features registry-breg/runtime
else
  registry_prepare_cargo_runtime "$repository_root" \
    --manifest-path "$repository_root/Cargo.toml" --locked \
    -p registry-messagingctl -p registry-bregctl -p registry-breg \
    --features registry-breg/runtime
fi
for executable in "$messagingctl" "$bregctl" "$breg"; do
  [[ -x "$executable" ]] || fail "$executable is not executable"
done

umask 077
temporary_root=$(mktemp -d "$temporary_base/messaging-shared-issuer.XXXXXX")
chmod 700 "$temporary_root"
owner_project="$temporary_root/owner"
messaging_project="$temporary_root/messaging"

checkpoint "initializing the BReg issuer owner"
"$bregctl" --format json init "$owner_project" >"$temporary_root/breg-init.json"
cat >>"$owner_project/dev-clients.yaml" <<'YAML'
  - id: case-system
    accessProfiles: []
    scopes: [messaging:send]
    claims:
      registry_actor_kind: service
  - id: operations-console
    accessProfiles: []
    scopes: [messaging:operate]
    claims: {}
issuer:
  resources:
    - audience: urn:registrystack:messaging-dev
      scopes: [messaging:send, messaging:operate]
  clientResources:
    case-system: urn:registrystack:messaging-dev
    operations-console: urn:registrystack:messaging-dev
YAML
"$bregctl" --format json check "$owner_project" >"$temporary_root/breg-check.json"

read -r breg_port issuer_port database_port wrong_api_port wrong_metrics_port \
  messaging_api_port messaging_metrics_port < <(free_ports 7)

checkpoint "starting the BReg owner and ThunderID"
"$bregctl" --format json dev start --breg-bin "$breg" --docker-bin "$docker_bin" \
  --breg-port "$breg_port" --issuer-port "$issuer_port" \
  --database-port "$database_port" "$owner_project" >"$temporary_root/breg-start.json"
require_breg_ready_report "$temporary_root/breg-start.json"
breg_url=$(json_member "$temporary_root/breg-start.json" bregUrl)
issuer_url=$(json_member "$temporary_root/breg-start.json" issuer)

checkpoint "initializing the Messaging starter with the published mock provider"
"$messagingctl" --format json init "$messaging_project" >"$temporary_root/messaging-init.json"
rm -rf -- "$messaging_project/providers/sms-gateway"
mkdir -p "$messaging_project/providers/sms-gateway"
cp "$repository_root/products/messaging/examples/providers/mock/provider.yaml" \
  "$messaging_project/providers/sms-gateway/provider.yaml"
cp -R "$repository_root/products/messaging/examples/providers/mock/scripts" \
  "$messaging_project/providers/sms-gateway/scripts"
"$messagingctl" --format json check --project "$messaging_project" \
  >"$temporary_root/messaging-check.json"

checkpoint "refusing an unregistered Messaging resource before ready"
"$messagingctl" --format json dev "$messaging_project" \
  --issuer-project "$owner_project" --resource urn:registrystack:messaging-dev-wrong \
  --bregctl-bin "$bregctl" --port "$wrong_api_port" --metrics-port "$wrong_metrics_port" \
  >"$temporary_root/wrong-resource.out" 2>"$temporary_root/wrong-resource.err" &
wrong_pid=$!
if ! wait_for_exit "$wrong_pid" "${MESSAGING_SHARED_ISSUER_REFUSAL_SECONDS:-180}"; then
  kill -INT "$wrong_pid" 2>/dev/null || :
  wait "$wrong_pid" 2>/dev/null || :
  fail "the wrong-resource session did not refuse within its deadline"
fi
if wait "$wrong_pid"; then
  fail "the wrong-resource session succeeded"
else
  wrong_status=$?
fi
[[ "$wrong_status" -ne 0 ]] || fail "the wrong-resource session returned success"
if grep -q '"state":"ready"' "$temporary_root/wrong-resource.out"; then
  fail "the wrong-resource session reported ready before refusing"
fi
python3 - "$temporary_root/wrong-resource.out" <<'PY'
import json, sys
text = open(sys.argv[1], encoding="utf-8").read()
decoder = json.JSONDecoder()
reports = []
offset = 0
while offset < len(text):
    while offset < len(text) and text[offset].isspace():
        offset += 1
    if offset == len(text):
        break
    report, offset = decoder.raw_decode(text, offset)
    reports.append(report)
if not reports or not any(report.get("ok") is False for report in reports):
    raise SystemExit("wrong-resource start emitted no structured refusal")
PY

checkpoint "starting Messaging with the shared issuer"
"$messagingctl" --format json dev "$messaging_project" \
  --issuer-project "$owner_project" --resource urn:registrystack:messaging-dev \
  --bregctl-bin "$bregctl" --port "$messaging_api_port" \
  --metrics-port "$messaging_metrics_port" \
  >"$temporary_root/messaging-dev.out" 2>"$temporary_root/messaging-dev.err" &
messaging_pid=$!
if wait_for_messaging_ready "$messaging_pid" "$temporary_root/messaging-dev.out" \
  "${MESSAGING_SHARED_ISSUER_READY_SECONDS:-600}"; then
  ready_status=0
else
  ready_status=$?
fi
case $ready_status in
  0) ;;
  1)
    cat "$temporary_root/messaging-dev.out" >&2
    cat "$temporary_root/messaging-dev.err" >&2
    fail "Messaging stopped before reaching ready"
    ;;
  2) fail "Messaging did not reach ready before its deadline" ;;
esac
ready_report "$temporary_root/messaging-dev.out" >"$temporary_root/messaging-ready.json"
messaging_api=$(json_member "$temporary_root/messaging-ready.json" api)
messaging_mailpit=$(json_member "$temporary_root/messaging-ready.json" mailpit)

case_header=$(messaging_header case-system "$temporary_root/case-token.json")
operations_header=$(messaging_header operations-console "$temporary_root/operations-token.json")

cat >"$temporary_root/sms.json" <<'JSON'
{"senderProfile":"reminders-sms","to":{"phone":"+15555550100"},"template":{"id":"appointment-reminder-sms","version":"1"},"locale":"en","data":{"name":"Ada","day":"2026-10-01","office":"North"}}
JSON
cat >"$temporary_root/email.json" <<'JSON'
{"senderProfile":"transactional","to":{"email":"ada@example.org"},"template":{"id":"appointment-reminder","version":"1"},"locale":"en","data":{"name":"Ada","day":"2026-10-01","office":"North"},"correlationId":"shared-issuer"}
JSON

checkpoint "sending SMS and email with a ThunderID-issued Messaging token"
sms=$(submit_message "$case_header" shared-issuer-sms "$temporary_root/sms.json" \
  "$temporary_root/sms-submit.json")
email=$(submit_message "$case_header" shared-issuer-email "$temporary_root/email.json" \
  "$temporary_root/email-submit.json")
wait_for_message_status "$case_header" "$sms" delivered "$temporary_root/sms-status.json"
wait_for_message_status "$case_header" "$email" submitted "$temporary_root/email-status.json"

mailpit_total=$(curl --silent --show-error --fail-with-body --connect-timeout 2 --max-time 10 \
  "$messaging_mailpit/api/v1/messages" | python3 -c 'import json, sys; print(json.load(sys.stdin)["total"])')
[[ "$mailpit_total" == 1 ]] || fail "Mailpit holds $mailpit_total messages instead of one"

checkpoint "refusing message submission from the operator profile"
operator_status=$(curl --silent --show-error --connect-timeout 2 --max-time 30 \
  -o "$temporary_root/operator-submit.json" \
  -w '%{http_code}' -X POST "$messaging_api/v1/messages" -H @"$operations_header" \
  -H 'content-type: application/json' -H 'Idempotency-Key: shared-issuer-operator' \
  --data-binary @"$temporary_root/email.json")
[[ "$operator_status" == 403 ]] ||
  fail "operator submission returned HTTP $operator_status instead of 403"

checkpoint "restarting the retained BReg owner while Messaging remains ready"
"$bregctl" --format json dev stop --docker-bin "$docker_bin" "$owner_project" \
  >"$temporary_root/breg-stop.json"
curl --silent --show-error --fail --connect-timeout 2 --max-time 10 \
  "$messaging_api/ready" >/dev/null
curl --silent --show-error --fail-with-body --connect-timeout 2 --max-time 10 \
  "$messaging_api/v1/messages/$sms" -H @"$case_header" \
  >"$temporary_root/outage-status.json"
[[ "$(json_member "$temporary_root/outage-status.json" status)" == delivered ]] ||
  fail "the retained Messaging token could not read its message during the issuer outage"
case_header_before=$(file_sha256 "$case_header")
if "$messagingctl" --format json dev token case-system "$messaging_project" \
  >"$temporary_root/outage-token.out" 2>"$temporary_root/outage-token.err"; then
  fail "Messaging issued a fresh borrowed token while the owner was stopped"
fi
[[ "$(file_sha256 "$case_header")" == "$case_header_before" ]] ||
  fail "the refused outage token request replaced the retained header"
"$bregctl" --format json dev start --breg-bin "$breg" --docker-bin "$docker_bin" \
  "$owner_project" >"$temporary_root/breg-restart.json"
require_breg_ready_report "$temporary_root/breg-restart.json"
[[ "$(json_member "$temporary_root/breg-restart.json" issuer)" == "$issuer_url" ]] ||
  fail "the retained BReg owner changed issuer origin"

refreshed_header=$(messaging_header case-system "$temporary_root/refreshed-token.json")
curl --silent --show-error --fail-with-body --connect-timeout 2 --max-time 10 \
  "$messaging_api/v1/messages/$sms" \
  -H @"$refreshed_header" >"$temporary_root/refreshed-status.json"
[[ "$(json_member "$temporary_root/refreshed-status.json" status)" == delivered ]] ||
  fail "the refreshed token did not retain the caller's message visibility"

checkpoint "stopping Messaging without stopping the shared issuer"
stop_messaging_process || fail "Messaging did not stop within its deadline"
if ! wait "$messaging_pid"; then
  fail "Messaging returned a failure while stopping"
fi
messaging_pid=
python3 - "$temporary_root/messaging-dev.out" <<'PY'
import json, sys
text = open(sys.argv[1], encoding="utf-8").read()
decoder = json.JSONDecoder()
reports = []
offset = 0
while offset < len(text):
    while offset < len(text) and text[offset].isspace():
        offset += 1
    if offset == len(text):
        break
    report, offset = decoder.raw_decode(text, offset)
    reports.append(report)
if not reports or reports[-1].get("state") != "stopped" or reports[-1].get("containersRemoved") is not True:
    raise SystemExit("Messaging did not report a clean owned-container stop")
PY

if "$messagingctl" --format json dev token case-system "$messaging_project" \
  >"$temporary_root/stopped-token.out" 2>"$temporary_root/stopped-token.err"; then
  fail "Messaging issued a borrowed token after its session stopped"
fi

"$bregctl" --format json dev token case-system "$owner_project" \
  >"$temporary_root/owner-token.json"
owner_header=$(json_member "$temporary_root/owner-token.json" headerFile)
[[ "$owner_header" == "$owner_project"/.breg/dev/secrets/case-system.header ]] ||
  fail "BReg reported its retained header outside the owner session"
[[ -f "$owner_header" && ! -L "$owner_header" ]] ||
  fail "BReg did not write its retained client header"

curl --silent --show-error --fail --connect-timeout 2 --max-time 10 \
  "$breg_url/ready" >/dev/null
curl --silent --show-error --fail --connect-timeout 2 --max-time 10 \
  "$issuer_url/.well-known/openid-configuration" >/dev/null

checkpoint "removing the retained BReg owner through its public lifecycle"
"$bregctl" --format json dev stop --remove --docker-bin "$docker_bin" \
  "$owner_project" >"$temporary_root/breg-remove.json"
owner_project=

checkpoint "passed"
