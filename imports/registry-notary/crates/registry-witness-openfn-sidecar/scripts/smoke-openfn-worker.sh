#!/bin/sh
set -eu

crate_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
repo_dir="$(CDPATH= cd -- "$crate_dir/../.." && pwd)"
smoke_dir="$repo_dir/target/openfn-worker-smoke"
worker="$smoke_dir/openfn_worker.mjs"
job="$crate_dir/examples/jobs/common-person-lookup.js"

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

request="$(jq -nc --arg job "$job" '{
  source_id: "smoke",
  dataset: "civil_registry",
  entity: "civil_person",
  job: $job,
  adaptor: "@openfn/language-common@3.2.3",
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

printf 'OpenFn worker smoke passed\n'
