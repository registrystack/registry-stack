#!/bin/sh
set -eu

crate_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
repo_dir="$(CDPATH= cd -- "$crate_dir/../.." && pwd)"
smoke_dir="$repo_dir/target/openfn-worker-smoke"
worker="$smoke_dir/openfn_worker.mjs"
prepare_job="$crate_dir/examples/jobs/common-prepare-lookup.js"
filter_job="$crate_dir/examples/jobs/common-filter-records.js"
return_job="$crate_dir/examples/jobs/common-return-rda.js"

rm -rf "$smoke_dir"
mkdir -p "$smoke_dir"
cp "$crate_dir/workers/openfn_worker.mjs" "$worker"

cat >"$smoke_dir/package.json" <<'JSON'
{
  "private": true,
  "type": "module",
  "dependencies": {
    "@openfn/compiler": "1.2.5",
    "@openfn/runtime": "1.9.3",
    "@openfn/language-common": "3.2.3"
  }
}
JSON

npm install --prefix "$smoke_dir" --ignore-scripts --no-audit --no-fund >/dev/null

node --experimental-vm-modules "$worker" \
  --version \
  --require-adaptor "@openfn/language-common@3.2.3" |
  grep "@openfn/language-common@3.2.3:3.2.3=" >/dev/null

request="$(jq -nc \
  --arg prepare_job "$prepare_job" \
  --arg filter_job "$filter_job" \
  --arg return_job "$return_job" '{
  source_id: "smoke",
  dataset: "civil_registry",
  entity: "civil_person",
  workflow: {
    start: "prepare_lookup",
    steps: [
      {
        id: "prepare_lookup",
        expression: $prepare_job,
        adaptors: ["@openfn/language-common@3.2.3"],
        next: {
          filter_records: true
        }
      },
      {
        id: "filter_records",
        expression: $filter_job,
        adaptors: ["@openfn/language-common@3.2.3"],
        next: {
          return_rda: true
        }
      },
      {
        id: "return_rda",
        expression: $return_job,
        adaptors: ["@openfn/language-common@3.2.3"]
      }
    ]
  },
  lookup: {field: "national_id", value: "person-123"},
  fields: ["national_id", "birth_date"],
  limit: 2,
  purpose: "smoke-test",
  correlation_id: "openfn-worker-smoke",
  configuration: {
    fixture_records: [
      {national_id: "person-123", birth_date: "1990-01-01", extra: "not requested"},
      {national_id: "person-456", birth_date: "1985-05-05"}
    ],
    apiToken: "secret-value-used-to-check-redaction"
  }
}')"

output="$(
  printf '%s\n' "$request" |
    node --experimental-vm-modules "$worker"
)"

printf '%s\n' "$output" |
  jq -e '.data | length == 1 and .[0].national_id == "person-123" and .[0].birth_date == "1990-01-01"' >/dev/null

batch_request="$(printf '%s\n' "$request" | jq -c '
  del(.lookup) |
  .mode = "batch_match" |
  .query_signature = [{field: "national_id", op: "eq"}] |
  .items = [
    {id: "hit", values: ["person-123"]},
    {id: "miss", values: ["missing-person"]}
  ]
')"
batch_output="$(
  printf '%s\n' "$batch_request" |
    node --experimental-vm-modules "$worker"
)"
printf '%s\n' "$batch_output" |
  jq -e '
    (.items | length == 2) and
    (.items[0].id == "hit") and
    (.items[0].data | length == 1) and
    (.items[0].data[0].national_id == "person-123") and
    (.items[0].data[0].birth_date == "1990-01-01") and
    (.items[1].id == "miss") and
    (.items[1].data | length == 0)
  ' >/dev/null

auth_request="$(printf '%s\n' "$request" | jq -c '.lookup.value = "target-auth"')"
auth_output="$(
  printf '%s\n' "$auth_request" |
    node --experimental-vm-modules "$worker"
)"
printf '%s\n' "$auth_output" |
  jq -e '.error.code == "target_auth"' >/dev/null

rate_limit_request="$(printf '%s\n' "$request" | jq -c '.lookup.value = "target-rate-limit"')"
rate_limit_output="$(
  printf '%s\n' "$rate_limit_request" |
    node --experimental-vm-modules "$worker"
)"
printf '%s\n' "$rate_limit_output" |
  jq -e '.error.code == "target_rate_limit" and .error.retry_after_seconds == 5' >/dev/null

cycle_request="$(printf '%s\n' "$request" | jq -c '.workflow.steps[2].next = {prepare_lookup: true}')"
cycle_output="$(
  printf '%s\n' "$cycle_request" |
    node --experimental-vm-modules "$worker"
)"
printf '%s\n' "$cycle_output" |
  jq -e '.error.code == "openfn_execution"' >/dev/null

multi_leaf_request="$(printf '%s\n' "$request" | jq -c '.workflow.steps[0].next = {filter_records: true, return_rda: true} | .workflow.steps[1].next = null')"
multi_leaf_output="$(
  printf '%s\n' "$multi_leaf_request" |
    node --experimental-vm-modules "$worker"
)"
printf '%s\n' "$multi_leaf_output" |
  jq -e '.error.code == "invalid_job_result"' >/dev/null

printf 'OpenFn worker smoke passed\n'
