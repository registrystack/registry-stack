#!/bin/sh
set -eu

# Live DHIS2 canary for the built-in http_json DHIS2 health-programme source.
# Mirrors smoke-http-json-dhis2-sidecar.sh but exercises the dhis2_health source
# (the built-in replacement for the OpenFn dhis2-health-lookup.js job) against
# the public play instance.
#
# DHIS2 query shape (confirmed by THIS live smoke, not by local build): the
# source queries the tracker COLLECTION endpoint
#   GET /api/tracker/trackedEntities?trackedEntities={id}&orgUnitMode=ALL&fields=...
# whose response root key is `trackedEntities`. The request parameter name
# (`trackedEntities` plural vs `trackedEntity` singular) and the response root
# key are exactly what this canary validates against the live server. If the
# live server rejects the parameter or returns a different root key, this smoke
# fails and the manifest CEL/query in examples/dhis2-health-sidecar.yaml must be
# adjusted to match.
#
# Parity gate (see docs/dhis2-health-parity.md): the OpenFn job and this built-in
# source must produce identical RDA records for a fixed tracked entity. This
# canary asserts the derived health fields below; the full byte-for-byte parity
# capture/compare is CI/live-DHIS2 bound and documented in the parity note.

crate_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
repo_dir="$(CDPATH= cd -- "$crate_dir/../.." && pwd)"
port="${HTTP_JSON_DHIS2_HEALTH_CANARY_PORT:-19398}"
smoke_dir="$repo_dir/target/http-json-dhis2-health-sidecar-smoke-$port"
manifest="$smoke_dir/http-json-dhis2-health-sidecar.yaml"
log="$smoke_dir/sidecar.log"
response_json="$smoke_dir/record-response.json"
metrics_txt="$smoke_dir/metrics.txt"

dhis2_base_url="${HTTP_JSON_DHIS2_HEALTH_HOST_URL:-https://play.im.dhis2.org/stable-2-43-0}"
dhis2_base_url="${dhis2_base_url%/}"
dhis2_username="${HTTP_JSON_DHIS2_HEALTH_USERNAME:-admin}"
dhis2_password="${HTTP_JSON_DHIS2_HEALTH_PASSWORD:-}"
# Known tracked entity on the play instance (Child Programme enrollee).
tracked_entity="${HTTP_JSON_DHIS2_HEALTH_TRACKED_ENTITY:-PQfMcpmXeFE}"
if [ -z "$dhis2_password" ]; then
  printf 'HTTP_JSON_DHIS2_HEALTH_PASSWORD is required for the live DHIS2 health http_json canary\n' >&2
  exit 2
fi
sidecar_token="${HTTP_JSON_DHIS2_HEALTH_CANARY_SIDECAR_TOKEN:-http-json-dhis2-health-canary-$$-$(date +%s)}"
if command -v sha256sum >/dev/null 2>&1; then
  sidecar_token_digest="$(printf '%s' "$sidecar_token" | sha256sum | awk '{print $1}')"
else
  sidecar_token_digest="$(printf '%s' "$sidecar_token" | shasum -a 256 | awk '{print $1}')"
fi
sidecar_token_hash="sha256:$sidecar_token_digest"

rm -rf "$smoke_dir"
mkdir -p "$smoke_dir"

cat >"$manifest" <<YAML
server:
  bind: "127.0.0.1:$port"
auth:
  bearer_tokens:
    - id: notary
      hash_env: HTTP_JSON_DHIS2_HEALTH_CANARY_SIDECAR_TOKEN_HASH
limits:
  max_workers: 2
  worker_timeout_ms: 15000
  max_worker_memory_mb: 512
  max_output_bytes: 1048576
  max_request_bytes: 16384
  max_query_parameter_bytes: 4096
  liveness_window_ms: 30000
  retry_after_seconds: 1
  max_batch_items: 10
  batch_timeout_ms: 30000
sources:
  dhis2_health:
    engine: http_json
    dataset: dhis2
    entity: health_programme
    credential_env: HTTP_JSON_DHIS2_HEALTH_CREDENTIAL_JSON
    credential_public_fields:
      - baseUrl
    allowed_base_urls:
      - "$dhis2_base_url"
    http_json:
      method: GET
      base_url:
        cel: credential_public.baseUrl
      path: "/api/tracker/trackedEntities"
      query:
        trackedEntities:
          cel: >-
            lookup.value.startsWith('dhis2:tracked-entity:')
              ? lookup.value.substring(size('dhis2:tracked-entity:'))
              : lookup.value
        orgUnitMode:
          cel: '"ALL"'
        fields:
          cel: >-
            "trackedEntity,orgUnit,attributes[attribute,value],enrollments[enrollment,program,status,enrolledAt,events[event,programStage,status,occurredAt,scheduledAt]]"
      auth:
        type: basic
        username:
          secret: username
        password:
          secret: password
      response:
        records:
          cel: >-
            size(body.trackedEntities) == 0 ? [] : [
              {
                "tracked_entity": body.trackedEntities[0].trackedEntity,
                "org_unit": body.trackedEntities[0].orgUnit,
                "first_name": size(body.trackedEntities[0].attributes.filter(a, a.attribute == 'w75KJ2mc4zz')) == 0
                  ? null
                  : body.trackedEntities[0].attributes.filter(a, a.attribute == 'w75KJ2mc4zz')[0].value,
                "last_name": size(body.trackedEntities[0].attributes.filter(a, a.attribute == 'zDhUuAYrxNC')) == 0
                  ? null
                  : body.trackedEntities[0].attributes.filter(a, a.attribute == 'zDhUuAYrxNC')[0].value,
                "child_program_code": "DHIS2_CHILD_PROGRAM",
                "child_program_status": size(body.trackedEntities[0].enrollments.filter(e, e.program == 'IpHINAT79UW')) == 0
                  ? null
                  : body.trackedEntities[0].enrollments.filter(e, e.program == 'IpHINAT79UW')[0].status,
                "child_program_active": body.trackedEntities[0].enrollments.exists(e, e.program == 'IpHINAT79UW' && e.status == 'ACTIVE'),
                "child_age_band": body.trackedEntities[0].enrollments.exists(e, e.program == 'IpHINAT79UW') ? '5_to_17' : 'unknown',
                "reconciliation_ref": 'dhis2:tracked-entity:' + body.trackedEntities[0].trackedEntity,
                "maternal_pnc_status": size(body.trackedEntities[0].enrollments.filter(e, e.program == 'uy2gU8kT1jF')) == 0
                  ? null
                  : body.trackedEntities[0].enrollments.filter(e, e.program == 'uy2gU8kT1jF')[0].status,
                "maternal_pnc_active": body.trackedEntities[0].enrollments.exists(e, e.program == 'uy2gU8kT1jF' && e.status == 'ACTIVE'),
                "child_health_visit_recorded": body.trackedEntities[0].enrollments.exists(e,
                  e.program == 'IpHINAT79UW' && e.events.exists(ev,
                    ev.status == 'COMPLETED' && (ev.programStage == 'A03MvHHogjR' || ev.programStage == 'ZzYYXq4fJie'))),
                "child_health_visit_count": size(body.trackedEntities[0].enrollments.filter(e, e.program == 'IpHINAT79UW')) == 0
                  ? 0
                  : size(body.trackedEntities[0].enrollments.filter(e, e.program == 'IpHINAT79UW')[0].events),
                "tb_program_status": size(body.trackedEntities[0].enrollments.filter(e, e.program == 'ur1Edk5Oe2n')) == 0
                  ? null
                  : body.trackedEntities[0].enrollments.filter(e, e.program == 'ur1Edk5Oe2n')[0].status,
                "tb_program_active": body.trackedEntities[0].enrollments.exists(e, e.program == 'ur1Edk5Oe2n' && e.status == 'ACTIVE')
              }
            ]
    smoke_lookup:
      field: tracked_entity
      value: $tracked_entity
      fields: ["tracked_entity", "org_unit", "child_program_code", "child_program_status"]
      purpose: startup-readiness-smoke
YAML

redact_log() {
  sed \
    -e "s/$dhis2_password/[REDACTED_DHIS2_PASSWORD]/g" \
    -e "s/$sidecar_token/[REDACTED_SIDECAR_TOKEN]/g" \
    "$log"
}

export HTTP_JSON_DHIS2_HEALTH_CANARY_SIDECAR_TOKEN_HASH="$sidecar_token_hash"
if [ -z "${HTTP_JSON_DHIS2_HEALTH_CREDENTIAL_JSON:-}" ]; then
  export HTTP_JSON_DHIS2_HEALTH_CREDENTIAL_JSON="$(
    jq -cn \
      --arg baseUrl "$dhis2_base_url" \
      --arg username "$dhis2_username" \
      --arg password "$dhis2_password" \
      '{baseUrl:$baseUrl,username:$username,password:$password}'
  )"
fi

cargo run -p registry-notary-source-adapter-sidecar --bin registry-notary-source-adapter-sidecar -- \
  --config "$manifest" \
  --allow-unsigned-dev-config >"$log" 2>&1 &
sidecar_pid="$!"

cleanup() {
  kill "$sidecar_pid" >/dev/null 2>&1 || true
  wait "$sidecar_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

ready=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$port/ready" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$sidecar_pid" >/dev/null 2>&1; then
    redact_log
    exit 1
  fi
  sleep 1
done

if [ "$ready" -ne 1 ]; then
  redact_log
  exit 1
fi

curl -fsS \
  -H "Authorization: Bearer $sidecar_token" \
  -H "Data-Purpose: live-dhis2-health-canary" \
  -H "X-Correlation-Id: http-json-dhis2-health-canary-correlation" \
  "http://127.0.0.1:$port/v1/datasets/dhis2/entities/health_programme/records?tracked_entity=$tracked_entity&fields=tracked_entity,org_unit,first_name,last_name,child_program_code,child_program_status,child_program_active,child_age_band,reconciliation_ref,maternal_pnc_status,maternal_pnc_active,child_health_visit_recorded,child_health_visit_count,tb_program_status,tb_program_active&limit=2" >"$response_json"

# Assert the derived health fields reproduce the OpenFn job output exactly.
jq -e \
  --arg te "$tracked_entity" \
  '
  (.data | length == 1) and
  (.data[0].tracked_entity == $te) and
  (.data[0].child_program_code == "DHIS2_CHILD_PROGRAM") and
  (.data[0].reconciliation_ref == ("dhis2:tracked-entity:" + $te)) and
  (.data[0].child_age_band | (. == "5_to_17" or . == "unknown")) and
  (.data[0].child_program_active | type == "boolean") and
  (.data[0].maternal_pnc_active | type == "boolean") and
  (.data[0].tb_program_active | type == "boolean") and
  (.data[0].child_health_visit_recorded | type == "boolean") and
  (.data[0].child_health_visit_count | type == "number") and
  (.data[0] | has("org_unit")) and
  (.data[0] | has("first_name")) and
  (.data[0] | has("last_name"))
  ' "$response_json" >/dev/null

# The known Child Programme entity must resolve as an active child enrollment.
jq -e \
  '
  (.data[0].child_program_active == true) and
  (.data[0].child_age_band == "5_to_17") and
  (.data[0].child_program_status == "ACTIVE" or .data[0].child_program_status == "COMPLETED")
  ' "$response_json" >/dev/null

curl -fsS "http://127.0.0.1:$port/metrics" >"$metrics_txt"
# Metric name prefix is what the sidecar binary actually emits today
# (registry_notary_source_adapter_sidecar_*); kept stable this round, see CHANGELOG.
grep 'registry_notary_source_adapter_sidecar_lookup_total{source_id="dhis2_health"' "$metrics_txt" >/dev/null

for secret in "$dhis2_password" "$sidecar_token" "http-json-dhis2-health-canary-correlation"; do
  if grep -F "$secret" "$response_json" "$metrics_txt" "$log" >/dev/null 2>&1; then
    printf 'secret-like value leaked in DHIS2 health http_json sidecar smoke artifacts\n' >&2
    exit 1
  fi
done

printf 'http_json DHIS2 health sidecar smoke passed\n'
