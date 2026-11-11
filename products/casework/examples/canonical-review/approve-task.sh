#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if (($# != 4)); then
  printf 'Usage: bash approve-task.sh CASEWORK_URL TASK_ID STAFF_HEADER_FILE SOURCE_PROFILE\n' >&2
  exit 2
fi

casework_url=${1%/}
task_id=$2
staff_header=$3
source_profile=$4
if [[ ! "$task_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ || ! -r "$staff_header" || -z "$source_profile" ]]; then
  printf 'Supply an exact task UUID, a readable Staff header file and a BReg source profile.\n' >&2
  exit 2
fi

task_url="$casework_url/v1/review-tasks/$task_id"
api() {
  curl -q --globoff --proto '=http,https' --silent --show-error --fail \
    --max-time 15 --header "@$staff_header" "$@"
}
open_work() {
  api --header "Registry-Source-Profile: $source_profile" "$@"
}

task=$(open_work --url "$task_url")
revision=$(jq -er '.revision' <<<"$task")

holding=$(open_work --request POST --url "$task_url/claim" \
  --header "If-Match: \"$revision\"" \
  --header "Idempotency-Key: claim-$task_id-$revision")
holding_revision=$(jq -er --arg id "$task_id" \
  'select(.taskId == $id and (.state | objects | has("held"))) | .revision' <<<"$holding")

status=$(open_work --request POST --url "$task_url/decisions" \
  --header "If-Match: \"$holding_revision\"" \
  --header "Idempotency-Key: approve-$task_id-$holding_revision" \
  --header 'Content-Type: application/json' \
  --data '{"decision":{"type":"approve","outcome":"approved"}}' \
  --output /dev/null --write-out '%{http_code}')
if [[ "$status" != 204 ]]; then
  printf 'Expected HTTP 204 from the decision request, received %s.\n' "$status" >&2
  exit 1
fi

# Read the retained Casework receipt under the same reviewer identity.
receipt=$(api --url "$task_url")
jq -e --arg id "$task_id" \
  'select(.taskId == $id and .decidedByCaller == true) | .decisionReceipt
   | select(.decision == "approve" and .outcome == "approved")' <<<"$receipt"
