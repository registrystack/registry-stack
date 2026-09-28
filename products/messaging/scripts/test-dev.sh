#!/usr/bin/env bash
# End to end through `messagingctl dev`: start a session on a fresh starter
# package whose SMS provider is the example mock provider, send one email and
# one SMS, and require the SMS to be reported delivered by a signed callback,
# the email to be submitted to Mailpit, and the session to remove its
# containers when it stops. Needs Docker, curl, and python3.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

dev_name=test-dev
settle_seconds=30
# shellcheck source=products/messaging/scripts/dev-session.sh
. "$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/dev-session.sh"

# The script takes no arguments; the session helpers take their own.
# shellcheck disable=SC2119
dev_prepare
dev_log "starter package with the mock SMS provider at $dev_project"
# shellcheck disable=SC2119
dev_start
dev_log "session ready: api $dev_api, mailpit $dev_mailpit"

header=$("$messagingctl_bin" dev token case-system "$dev_project" --format json | dev_member headerFile)
dev_log "token header file written for case-system"

submit() {
  local key=$1 body=$2
  curl --silent --show-error --fail-with-body -X POST "$dev_api/v1/messages" \
    -H @"$header" -H 'content-type: application/json' -H "Idempotency-Key: $key" \
    --data "$body" | dev_member id
}

sms=$(submit dev-e2e-sms '{"senderProfile":"reminders-sms","to":{"phone":"+15555550100"},"template":{"id":"appointment-reminder-sms","version":"1"},"locale":"en","data":{"name":"Ada","day":"2026-10-01","office":"North"}}')
email=$(submit dev-e2e-email '{"senderProfile":"transactional","to":{"email":"ada@example.org"},"template":{"id":"appointment-reminder","version":"1"},"locale":"en","data":{"name":"Ada","day":"2026-10-01","office":"North"},"correlationId":"case-42"}')
dev_log "accepted sms $sms and email $email"

status() {
  curl --silent --show-error --fail-with-body "$dev_api/v1/messages/$1" -H @"$header" |
    dev_member status
}

deadline=$((SECONDS + settle_seconds))
while :; do
  sms_status=$(status "$sms")
  email_status=$(status "$email")
  if [[ "$sms_status" == delivered && "$email_status" == submitted ]]; then
    break
  fi
  if ((SECONDS > deadline)); then
    printf 'test-dev: after %s seconds the sms is %s and the email is %s\n' \
      "$settle_seconds" "$sms_status" "$email_status" >&2
    exit 1
  fi
  sleep 0.5
done
dev_log "GET /v1/messages/$sms: status $sms_status"
dev_log "GET /v1/messages/$email: status $email_status"

delivered=$(curl --silent --show-error --fail-with-body "$dev_mailpit/api/v1/messages" |
  dev_member total)
if [[ "$delivered" != 1 ]]; then
  printf 'test-dev: Mailpit holds %s messages, expected 1\n' "$delivered" >&2
  exit 1
fi
dev_log "Mailpit holds 1 message"

callbacks=$(curl --silent --show-error --fail-with-body "$dev_metrics" |
  python3 -c 'import sys
for line in sys.stdin:
    if line.startswith("messaging_provider_callbacks_total{outcome=\"applied\"}"):
        print(line.split()[-1])')
if [[ "$callbacks" != 1 ]]; then
  printf 'test-dev: %s signed callbacks were applied, expected 1\n' "${callbacks:-no}" >&2
  exit 1
fi
dev_log "1 signed delivery callback applied"

dev_stop
dev_log "session stopped and removed its containers"
dev_log "passed"
