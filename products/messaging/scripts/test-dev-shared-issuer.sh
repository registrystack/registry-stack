#!/usr/bin/env bash
# Verify delivery, authorization and fresh key loading with a stock issuer.
set -euo pipefail
dev_name=test-dev-shared-issuer
# shellcheck source=products/messaging/scripts/dev-session.sh
. "$(dirname -- "${BASH_SOURCE[0]}")/dev-session.sh"
dev_prepare
fixture=${JOURNEY_ISSUER_BIN:-"${CARGO_TARGET_DIR:-$dev_repo_root/target}/debug/examples/journey-issuer"}
if [[ ! -x "$fixture" ]]; then
  registry_cargo_build "$dev_repo_root" --locked -p registry-thunderid-tooling --features session --example journey-issuer
fi
issuer_root=
clean_issuer() {
  local status=$?
  if [[ -n "$issuer_root" && -f "$issuer_root/fixture.json" ]]; then
    "$fixture" stop "$issuer_root" || :
  fi
  dev_cleanup "$status"
}
trap clean_issuer EXIT HUP INT TERM

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
issuer="http://127.0.0.1:$port"
resource=urn:example:messaging
other=urn:example:other
registration="$dev_work/issuer-clients.json"
python3 - "$registration" "$other" "$dev_project" "$issuer" <<'PY'
import json
from pathlib import Path
import sys

registration, other, project, issuer = sys.argv[1:]
Path(registration).write_text(json.dumps({
    "clients": [{
        "id": "case-system", "scopes": ["messaging:send"],
        "grants": [{"audience": other, "scopes": ["messaging:send"]}],
        "claims": {"registry_actor_kind": "service"},
    }, {
        "id": "operations-console", "scopes": ["messaging:operate"],
        "claims": {"registry_actor_kind": "service"},
    }],
    "issuer": {"resources": [{"audience": other, "scopes": ["messaging:send"]}]},
}))
project = Path(project)
plan = project / "dev.yaml"
text = plan.read_text()
plan.write_text(text.replace("issuer: https://identity.starter.example.test",
                             f"issuer: {issuer}\nexternalJwksUri: {issuer}/oauth2/jwks"))
scenarios = project / "tests/scenarios.yaml"
scenarios.write_text(scenarios.read_text().split("scenarios:", 1)[0] + "scenarios: []\n")
PY
chmod 600 "$registration"

start_fixture() {
  issuer_root="$dev_work/$1"
  local id
  id=$(python3 -c 'import uuid; print(uuid.uuid4())')
  "$fixture" start "$issuer_root" "$registration" "$id" "$port" "$resource"
}

read_status() {
  curl --silent --show-error -o /dev/null -w '%{http_code}'     "$dev_api/v1/messages/$message" -H @"$1"
}

start_fixture original
"$fixture" token "$issuer_root" "$registration" case-system "$dev_work/original.header"
"$fixture" token "$issuer_root" "$registration" case-system "$dev_work/other.header" "$other"
"$fixture" token "$issuer_root" "$registration" operations-console "$dev_work/operator.header"
dev_start
if "$rstack_bin" --format json dev token "$dev_run" --as case-system >"$dev_work/token-refusal.json"; then
  printf '%s: the runner issued a token for an external issuer\n' "$dev_name" >&2
  exit 1
fi
grep -Fq 'Obtain tokens from that issuer' "$dev_work/token-refusal.json"
sms_body='{"senderProfile":"reminders-sms","to":{"phone":"+15555550100"},"template":{"id":"appointment-reminder-sms","version":"1"},"locale":"en","data":{"name":"Ada","day":"2026-10-01","office":"North"}}'
email_body='{"senderProfile":"transactional","to":{"email":"ada@example.org"},"template":{"id":"appointment-reminder","version":"1"},"locale":"en","data":{"name":"Ada","day":"2026-10-01","office":"North"}}'
submit() {
  local header=$1 key=$2 body=$3
  shift 3
  curl --silent --show-error -X POST "$dev_api/v1/messages" \
    -H @"$header" -H 'content-type: application/json' -H "Idempotency-Key: $key" \
    --data "$body" "$@"
}

operator_status=$(submit "$dev_work/operator.header" operator-forbidden "$sms_body" \
  -o /dev/null -w '%{http_code}')
[[ "$operator_status" == 403 ]]
message=$(submit "$dev_work/original.header" before-rotation "$sms_body" --fail-with-body | dev_member id)
[[ "$(read_status "$dev_work/original.header")" == 200 ]]
[[ "$(read_status "$dev_work/other.header")" == 401 ]]
email=$(submit "$dev_work/original.header" before-rotation-email "$email_body" --fail-with-body | dev_member id)
delivery_status() {
  curl --silent --show-error --fail-with-body "$dev_api/v1/messages/$1" \
    -H @"$dev_work/original.header" | dev_member status
}

deadline=$((SECONDS + 30))
until [[ "$(delivery_status "$message")" == delivered && "$(delivery_status "$email")" == submitted ]]; do
  if (( SECONDS >= deadline )); then
    printf '%s: SMS and email did not settle within 30 seconds\n' "$dev_name" >&2
    exit 1
  fi
  sleep 0.5
done
[[ "$(curl --silent --show-error --fail-with-body "$dev_mailpit/api/v1/messages" | dev_member total)" == 1 ]]
dev_log "delivered SMS, submitted one Mailpit email, refused operator submit and a different audience"

dev_stop
"$fixture" stop "$issuer_root"
start_fixture rotated
"$fixture" token "$issuer_root" "$registration" case-system "$dev_work/rotated.header"
dev_start
message=$(submit "$dev_work/rotated.header" after-rotation "$sms_body" --fail-with-body | dev_member id)
new_status=$(read_status "$dev_work/rotated.header")
old_status=$(read_status "$dev_work/original.header")
if [[ "$new_status" != 200 || "$old_status" != 401 ]]; then
  printf 'rotated token returned %s and original token returned %s\n' "$new_status" "$old_status" >&2
  exit 1
fi
dev_log "a fresh run accepted the rotated key and refused the old token"
dev_stop
