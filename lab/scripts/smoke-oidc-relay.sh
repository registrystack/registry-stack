#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
relay_dir="${REGISTRY_RELAY_SOURCE_DIR:-"${demo_dir}/vendor/registry-relay"}"
output_dir="${demo_dir}/output"
env_file="${REGISTRY_LAB_ZITADEL_ENV_FILE:-"${output_dir}/zitadel.env"}"
config_path="${output_dir}/oidc-social-protection-relay.yaml"
log_path="${output_dir}/oidc-social-protection-relay.log"
port="${REGISTRY_LAB_OIDC_RELAY_PORT:-4314}"
relay_features="${REGISTRY_RELAY_FEATURES:-spdci-api-standards,standards-cel-mapping,ogcapi-edr}"

wait_zitadel_init() {
  local deadline="${ZITADEL_WAIT_SECONDS:-180}"
  local start
  start="$(date +%s)"
  while (( $(date +%s) - start < deadline )); do
    local cid
    cid="$(docker compose -f "${compose_file}" ps -a -q zitadel-init 2>/dev/null || true)"
    if [[ -n "${cid}" ]]; then
      local state
      state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "${cid}")"
      if [[ "${state}" == "exited 0" ]]; then
        return 0
      fi
      if [[ "${state}" == exited\ * && "${state}" != "exited 0" ]]; then
        docker compose -f "${compose_file}" logs --no-color zitadel-init >&2 || true
        echo "Zitadel init failed (${state})" >&2
        return 1
      fi
    fi
    sleep 2
  done
  docker compose -f "${compose_file}" logs --no-color zitadel-init >&2 || true
  echo "Zitadel init did not complete within ${deadline}s" >&2
  return 1
}

mint_token() {
  local token_url="${OIDC_ISSUER%/}/oauth/v2/token"
  local scope="${OIDC_SCOPE:-openid}"
  curl --silent --show-error --fail-with-body \
    --user "${OIDC_SA_CLIENT_ID}:${OIDC_SA_CLIENT_SECRET}" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "scope=${scope}" \
    "${token_url}" |
    python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}

audience_yaml() {
  python - "$1" <<'PY'
import base64
import json
import sys

token = sys.argv[1]
payload = token.split(".")[1]
payload += "=" * (-len(payload) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload))
aud = claims.get("aud")
if isinstance(aud, str):
    aud = [aud]
if not aud:
    raise SystemExit("token did not include aud")
for value in aud:
    print(f"      - {json.dumps(value)}")
PY
}

write_config() {
  local token="$1"
  local audience_block
  audience_block="$(audience_yaml "${token}")"
  cat >"${config_path}" <<EOF
deployment:
  profile: local

server:
  bind: 127.0.0.1:${port}
  cache_dir: ${output_dir}/oidc-relay-cache

catalog:
  title: OIDC Social Protection Registry Relay (Registry Lab)
  base_url: http://127.0.0.1:${port}
  publisher: Social Protection Authority (OIDC Demo)
  participant_id: did:web:social-protection-oidc.demo.example.gov

vocabularies:
  demo: https://demo.example.gov/vocab/

auth:
  mode: oidc
  oidc:
    issuer: ${OIDC_ISSUER}
    allow_dev_insecure_fetch_urls: true
    audiences:
${audience_block}
    discovery_url: ${OIDC_ISSUER%/}/.well-known/openid-configuration
    allowed_algorithms: [RS256, ES256, EdDSA]
    jwks_cache_ttl: 10m
    leeway: 60s
    scope_claim: scope
    scope_map:
      "social-registry-reader": "social_protection_registry:rows"
      "social-registry-aggregate": "social_protection_registry:aggregate"
    allowed_clients: []
    allowed_token_types: [JWT, at+jwt]

audit:
  sink: stdout
  format: jsonl
  hash_secret_env: REGISTRY_RELAY_AUDIT_HASH_SECRET

datasets:
  - id: social_protection_registry
    title: Social Protection Registry
    description: OIDC-protected slice of the registry-lab social protection fixture.
    owner: Social Protection Authority
    sensitivity: personal
    access_rights: restricted
    update_frequency: weekly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: households_table
        materialization: snapshot
        source:
          type: file
          path: ${demo_dir}/data/social-protection/social-protection.xlsx
          format:
            xlsx:
              sheet: Households
              header_row: 1
        primary_key: household_id
        schema:
          strict: true
          fields:
            - name: household_id
              type: string
              nullable: false
            - name: national_id
              type: string
              nullable: false
              sensitive: true
            - name: district
              type: string
              nullable: false
            - name: poverty_score
              type: number
              nullable: false
            - name: eligibility_band
              type: string
              nullable: false
            - name: household_size
              type: integer
              nullable: false
            - name: active_members
              type: integer
              nullable: false
            - name: deceased_member_count
              type: integer
              nullable: false
    entities:
      - name: household
        title: Household
        description: OIDC-protected household projection.
        table: households_table
        concept_uri: demo:Household
        fields:
          - name: id
            from: household_id
          - name: national_id
          - name: district
          - name: poverty_score
          - name: eligibility_band
          - name: household_size
          - name: active_members
          - name: deceased_member_count
        access:
          metadata_scope: social_protection_registry:metadata
          aggregate_scope: social_protection_registry:aggregate
          read_scope: social_protection_registry:rows
          evidence_verification_scope: social_protection_registry:evidence_verification
        api:
          default_limit: 25
          max_limit: 100
          require_purpose_header: true
          allowed_filters:
            - field: id
              ops: [eq, in]
            - field: national_id
              ops: [eq, in]
EOF
}

wait_http() {
  local deadline="${OIDC_RELAY_WAIT_SECONDS:-90}"
  local start
  start="$(date +%s)"
  while (( $(date +%s) - start < deadline )); do
    if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "OIDC Relay did not become healthy within ${deadline}s" >&2
  return 1
}

cd "${demo_dir}"
docker compose -f "${compose_file}" up -d zitadel-init
wait_zitadel_init
mkdir -p "${output_dir}"
docker compose -f "${compose_file}" cp zitadel-init:/seed/zitadel.env "${env_file}" >/dev/null 2>&1

if [[ ! -f "${demo_dir}/.env" ]]; then
  echo "missing .env; run ${script_dir}/generate-demo-secrets.py first" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
. "${demo_dir}/.env"
# shellcheck disable=SC1090
. "${env_file}"
set +a
: "${OIDC_ISSUER:?missing OIDC_ISSUER in ${env_file}}"
: "${OIDC_SA_CLIENT_ID:?missing OIDC_SA_CLIENT_ID in ${env_file}}"
: "${OIDC_SA_CLIENT_SECRET:?missing OIDC_SA_CLIENT_SECRET in ${env_file}}"
: "${REGISTRY_RELAY_AUDIT_HASH_SECRET:?missing REGISTRY_RELAY_AUDIT_HASH_SECRET; run scripts/generate-demo-secrets.py}"

token="$(mint_token)"
write_config "${token}"

rm -rf "${output_dir}/oidc-relay-cache"
(
  cd "${relay_dir}"
  cargo build --bin registry-relay --features "${relay_features}"
)
(
  cd "${relay_dir}"
  cargo run --bin registry-relay --features "${relay_features}" -- --config "${config_path}"
) >"${log_path}" 2>&1 &
relay_pid="$!"
trap 'kill "${relay_pid}" >/dev/null 2>&1 || true' EXIT

wait_http

status="$(
  curl -sS -o "${output_dir}/smoke-oidc-relay-row.json" -w "%{http_code}" \
    -H "Authorization: Bearer ${token}" \
    -H "Data-Purpose: https://demo.example.gov/purpose/oidc-relay-demo" \
    "http://127.0.0.1:${port}/v1/datasets/social_protection_registry/entities/household/records?limit=1"
)"

case "${status}" in
  200)
    echo "OIDC Relay accepted the Zitadel token and authorized row access."
    ;;
  403)
    echo "OIDC Relay accepted the Zitadel token, then denied row access because this machine token did not carry mapped roles."
    ;;
  *)
    echo "Expected OIDC Relay row read to return 200 or 403, got ${status}" >&2
    echo "Relay log: ${log_path}" >&2
    exit 1
    ;;
esac
