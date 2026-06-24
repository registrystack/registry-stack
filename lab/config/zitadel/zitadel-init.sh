#!/usr/bin/env bash
# BSL-1.1
# Idempotently provisions a Zitadel org, project, OIDC application, project
# roles, user grants, test human user, and API service account for the
# Registry Lab dev stack, then writes OIDC credentials to
# /seed/zitadel.env.
#
# Intended to run as the zitadel-init one-shot container inside the dev Compose
# stack once Zitadel is healthy. Safe to re-run: every create call checks for
# an existing resource first and skips creation if found.
#
# Authentication:
#   Zitadel writes a Personal Access Token (PAT) to ZITADEL_FIRSTINSTANCE_PATPATH
#   on first boot when a bootstrap machine user is configured (see dev.compose.yaml).
#   This script reads that PAT and uses it as a Bearer token for all Management
#   and Admin API calls.
#
# Output: /seed/zitadel.env  — sourced by the workbench or used with --env-file.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (all overridable via environment)
# ---------------------------------------------------------------------------
ZITADEL_BASE_URL="${ZITADEL_BASE_URL:-http://zitadel:8080}"
# Public-facing issuer URL used by clients running outside the compose network
# (workbench dev server, browsers). Defaults to localhost since that's what
# Zitadel's ExternalDomain is set to in the dev stack.
ZITADEL_PUBLIC_URL="${ZITADEL_PUBLIC_URL:-http://localhost:8080}"
PAT_FILE="${PAT_FILE:-/seed/zitadel-pat}"

ORG_NAME="${ORG_NAME:-publicschema-dev}"
PROJECT_NAME="${PROJECT_NAME:-Registry Lab}"
APP_NAME="${APP_NAME:-registry-lab-dev}"
SPA_APP_NAME="${SPA_APP_NAME:-registry-lab-spa}"

REDIRECT_URI="${REDIRECT_URI:-http://localhost:5174/auth/callback}"
POST_LOGOUT_URI="${POST_LOGOUT_URI:-http://localhost:5174}"

SPA_REDIRECT_URI="${SPA_REDIRECT_URI:-http://localhost:5174/auth/callback}"
SPA_POST_LOGOUT_URI="${SPA_POST_LOGOUT_URI:-http://localhost:5174}"
SPA_LEGACY_REDIRECT_URI="${SPA_LEGACY_REDIRECT_URI:-http://localhost:5173/auth/callback}"
SPA_LEGACY_POST_LOGOUT_URI="${SPA_LEGACY_POST_LOGOUT_URI:-http://localhost:5173}"

TEST_USER_EMAIL="${TEST_USER_EMAIL:-alice@example.com}"
TEST_USER_FIRST="${TEST_USER_FIRST:-Alice}"
TEST_USER_LAST="${TEST_USER_LAST:-Example}"
TEST_USER_PASSWORD="${TEST_USER_PASSWORD:-Alice1234!}"

SERVICE_ACCOUNT_USERNAME="${SERVICE_ACCOUNT_USERNAME:-registry-lab-api}"
SERVICE_ACCOUNT_NAME="${SERVICE_ACCOUNT_NAME:-Registry Lab API}"

OUTPUT_FILE="${OUTPUT_FILE:-/seed/zitadel.env}"

MGMT="${ZITADEL_BASE_URL}/management/v1"
ADMIN="${ZITADEL_BASE_URL}/admin/v1"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { printf '[zitadel-init] %s\n' "$*"; }

# Perform a curl call and print the response body.
# Usage: zapi METHOD PATH [BODY_JSON] [ORG_ID]
zapi() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local org_id="${4:-}"

  # Zitadel resolves the instance by the request's Host header, not the URL.
  # Inside the compose network the URL host is "zitadel:8080" but the instance
  # is registered against ExternalDomain ("localhost"), so we override Host.
  local args=(
    --silent --show-error --fail-with-body
    -X "${method}"
    -H "Host: localhost"
    -H "Authorization: Bearer ${PAT}"
    -H "Content-Type: application/json"
    -H "Accept: application/json"
  )

  if [[ -n "${org_id}" ]]; then
    args+=(-H "x-zitadel-orgid: ${org_id}")
  fi

  if [[ -n "${body}" ]]; then
    args+=(--data "${body}")
  fi

  curl "${args[@]}" "${path}"
}

# Return 0 if the jq expression evaluates to a non-empty non-null value.
jq_nonempty() {
  local expr="$1"
  local json="$2"
  local result
  result="$(printf '%s' "${json}" | jq -r "${expr} // empty" 2>/dev/null)"
  [[ -n "${result}" ]]
}

# ---------------------------------------------------------------------------
# 1. Wait for Zitadel readiness
# ---------------------------------------------------------------------------
log "Waiting for Zitadel at ${ZITADEL_BASE_URL} ..."
until curl --silent --fail --output /dev/null "${ZITADEL_BASE_URL}/debug/healthz"; do
  sleep 2
done
log "Zitadel is healthy."

# ---------------------------------------------------------------------------
# 2. Read the bootstrap PAT written by Zitadel on first boot
# ---------------------------------------------------------------------------
log "Reading PAT from ${PAT_FILE} ..."
# Retry briefly; the file is written right as Zitadel finishes first-instance
# setup which may trail the healthz check by a second or two.
for i in $(seq 1 15); do
  if [[ -s "${PAT_FILE}" ]]; then
    break
  fi
  log "PAT file not yet available (attempt ${i}/15), waiting ..."
  sleep 2
done

if [[ ! -s "${PAT_FILE}" ]]; then
  log "ERROR: PAT file ${PAT_FILE} is empty or missing after waiting."
  log "Ensure ZITADEL_FIRSTINSTANCE_PATPATH is set to ${PAT_FILE} in dev.compose.yaml."
  exit 1
fi

PAT="$(cat "${PAT_FILE}")"
log "PAT loaded."

# ---------------------------------------------------------------------------
# 3. Resolve or create the organisation
# ---------------------------------------------------------------------------
log "Resolving organisation '${ORG_NAME}' ..."

# Search for existing org by name.
search_resp="$(zapi POST "${ADMIN}/orgs/_search" \
  '{"queries":[{"nameQuery":{"name":"'"${ORG_NAME}"'","method":"TEXT_QUERY_METHOD_EQUALS"}}]}')"

ORG_ID="$(printf '%s' "${search_resp}" | jq -r '.result[0].id // empty')"

if [[ -n "${ORG_ID}" ]]; then
  log "Organisation '${ORG_NAME}' already exists (id=${ORG_ID})."
else
  log "Creating organisation '${ORG_NAME}' ..."
  create_resp="$(zapi POST "${MGMT}/orgs" '{"name":"'"${ORG_NAME}"'"}')"
  ORG_ID="$(printf '%s' "${create_resp}" | jq -r '.id')"
  log "Organisation created (id=${ORG_ID})."
fi

# ---------------------------------------------------------------------------
# 4. Resolve or create the project
#    Note: Zitadel places projects in the org of the calling user (the
#    bootstrap PAT owner), regardless of the x-zitadel-orgid header. The
#    actual resource owner is read back after creation and stored in
#    PROJECT_ORG_ID, which is used for write operations scoped to the project
#    (role creation, user grants). Read/search operations are more permissive
#    and work with either org header.
# ---------------------------------------------------------------------------
log "Resolving project '${PROJECT_NAME}' ..."

# Search without org header so we find the project regardless of which org
# the PAT owner placed it in on the initial run.
proj_search="$(zapi POST "${MGMT}/projects/_search" \
  '{"queries":[{"nameQuery":{"name":"'"${PROJECT_NAME}"'","method":"TEXT_QUERY_METHOD_EQUALS"}}]}')"

PROJECT_ID="$(printf '%s' "${proj_search}" | jq -r '.result[0].id // empty')"

if [[ -n "${PROJECT_ID}" ]]; then
  log "Project '${PROJECT_NAME}' already exists (id=${PROJECT_ID})."
else
  log "Creating project '${PROJECT_NAME}' ..."
  proj_create="$(zapi POST "${MGMT}/projects" \
    '{"name":"'"${PROJECT_NAME}"'"}' \
    "" "${ORG_ID}")"
  PROJECT_ID="$(printf '%s' "${proj_create}" | jq -r '.id')"
  log "Project created (id=${PROJECT_ID})."
fi

# Resolve the project's actual resource owner org; Zitadel assigns the project
# to the PAT owner's org, which may differ from ORG_ID. All project-scoped
# write operations (role creation, user grants) must use this org ID.
proj_detail="$(zapi GET "${MGMT}/projects/${PROJECT_ID}")"
PROJECT_ORG_ID="$(printf '%s' "${proj_detail}" | jq -r '.project.details.resourceOwner')"
log "Project '${PROJECT_NAME}' resource owner org: ${PROJECT_ORG_ID}."

# ---------------------------------------------------------------------------
# 5. Resolve or create the OIDC application
#    Grant types: AUTHORIZATION_CODE (0) + REFRESH_TOKEN (2)
#    App type: WEB (0)
#    Auth method: BASIC (0)  — legacy confidential client kept for compatibility env output
#    Dev mode: true          — required for http:// redirect URIs
#    accessTokenRoleAssertion: true — required so role claims appear in access tokens
#
#    Note: Zitadel WEB apps do not support client_credentials; that grant is
#    silently dropped at write time. Machine-to-machine token minting uses the
#    service account's own client_credentials (username + generated secret).
# ---------------------------------------------------------------------------
log "Resolving OIDC application '${APP_NAME}' ..."

app_search="$(zapi POST "${MGMT}/projects/${PROJECT_ID}/apps/_search" \
  '{"queries":[{"nameQuery":{"name":"'"${APP_NAME}"'","method":"TEXT_QUERY_METHOD_EQUALS"}}]}' \
  "" "${PROJECT_ORG_ID}")"

APP_ID="$(printf '%s' "${app_search}" | jq -r '.result[0].id // empty')"
CLIENT_ID=""
CLIENT_SECRET=""

if [[ -n "${APP_ID}" ]]; then
  log "OIDC application '${APP_NAME}' already exists (id=${APP_ID})."
  # Retrieve config to get clientId (secret is not retrievable after creation).
  app_detail="$(zapi GET "${MGMT}/projects/${PROJECT_ID}/apps/${APP_ID}" "" "${PROJECT_ORG_ID}")"
  CLIENT_ID="$(printf '%s' "${app_detail}" | jq -r '.app.oidcConfig.clientId // empty')"
  log "Existing clientId=${CLIENT_ID}."
  log "NOTE: client secret cannot be re-read. If /seed/zitadel.env is missing it,"
  log "delete the app in the Zitadel console and re-run this script."

  # Ensure accessTokenRoleAssertion is set on the existing app. We always PUT
  # the full config; the app's redirectUris / postLogoutRedirectUris are
  # preserved by reading them back first.
  # Note: Zitadel returns HTTP 400 "No changes" when the config is already
  # identical to what we're submitting; treat that as success.
  existing_redirect_uris="$(printf '%s' "${app_detail}" | jq -r '.app.oidcConfig.redirectUris // [] | @json')"
  existing_post_logout_uris="$(printf '%s' "${app_detail}" | jq -r '.app.oidcConfig.postLogoutRedirectUris // [] | @json')"
  oidc_update_body="$(
    jq -cn \
      --argjson redirects "${existing_redirect_uris}" \
      --argjson post_logouts "${existing_post_logout_uris}" \
      '{
      "redirectUris": $redirects,
      "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
      "grantTypes": [
        "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
        "OIDC_GRANT_TYPE_REFRESH_TOKEN"
      ],
      "appType": "OIDC_APP_TYPE_WEB",
      "authMethodType": "OIDC_AUTH_METHOD_TYPE_BASIC",
      "postLogoutRedirectUris": $post_logouts,
      "devMode": true,
      "accessTokenType": "OIDC_TOKEN_TYPE_JWT",
      "accessTokenRoleAssertion": true,
      "idTokenRoleAssertion": true,
      "idTokenUserinfoAssertion": true
    }'
  )"
  oidc_update_status="$(
    curl --silent --output /dev/null --write-out '%{http_code}' \
      -X PUT \
      -H "Host: localhost" \
      -H "Authorization: Bearer ${PAT}" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      -H "x-zitadel-orgid: ${PROJECT_ORG_ID}" \
      --data "${oidc_update_body}" \
      "${MGMT}/projects/${PROJECT_ID}/apps/${APP_ID}/oidc_config"
  )"
  # 200 = updated; 400 "No changes" = already in desired state.
  if [[ "${oidc_update_status}" == "200" || "${oidc_update_status}" == "400" ]]; then
    log "OIDC application config ensured (accessTokenRoleAssertion=true)."
  else
    log "ERROR: unexpected status ${oidc_update_status} updating OIDC app config."
    exit 1
  fi
else
  log "Creating OIDC application '${APP_NAME}' ..."
  oidc_body="$(
    jq -cn \
      --arg name "${APP_NAME}" \
      --arg redirect "${REDIRECT_URI}" \
      --arg post_logout "${POST_LOGOUT_URI}" \
      '{
      "name": $name,
      "redirectUris": [$redirect],
      "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
      "grantTypes": [
        "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
        "OIDC_GRANT_TYPE_REFRESH_TOKEN"
      ],
      "appType": "OIDC_APP_TYPE_WEB",
      "authMethodType": "OIDC_AUTH_METHOD_TYPE_BASIC",
      "postLogoutRedirectUris": [$post_logout],
      "version": "OIDC_VERSION_1_0",
      "devMode": true,
      "accessTokenType": "OIDC_TOKEN_TYPE_JWT",
      "accessTokenRoleAssertion": true,
      "idTokenRoleAssertion": true,
      "idTokenUserinfoAssertion": true
    }'
  )"
  app_create="$(zapi POST "${MGMT}/projects/${PROJECT_ID}/apps/oidc" \
    "${oidc_body}" "" "${PROJECT_ORG_ID}")"
  APP_ID="$(printf '%s' "${app_create}" | jq -r '.appId')"
  CLIENT_ID="$(printf '%s' "${app_create}" | jq -r '.clientId')"
  CLIENT_SECRET="$(printf '%s' "${app_create}" | jq -r '.clientSecret')"
  log "OIDC application created (id=${APP_ID}, clientId=${CLIENT_ID})."
fi

# ---------------------------------------------------------------------------
# 5b. Resolve or create the SPA OIDC application (PKCE, no client secret)
#    Grant types: AUTHORIZATION_CODE + REFRESH_TOKEN
#    App type: USER_AGENT (SPA)
#    Auth method: NONE       — public client; PKCE only, no client secret
#    Dev mode: true          — required for http:// redirect URIs
#
#    Used by apps/workbench-v3 (Vite + react-oidc-context). The BASIC client
#    above is retained only for backwards-compatible bootstrap scripts.
# ---------------------------------------------------------------------------
log "Resolving OIDC SPA application '${SPA_APP_NAME}' ..."

spa_app_search="$(zapi POST "${MGMT}/projects/${PROJECT_ID}/apps/_search" \
  '{"queries":[{"nameQuery":{"name":"'"${SPA_APP_NAME}"'","method":"TEXT_QUERY_METHOD_EQUALS"}}]}' \
  "" "${PROJECT_ORG_ID}")"

SPA_APP_ID="$(printf '%s' "${spa_app_search}" | jq -r '.result[0].id // empty')"
SPA_CLIENT_ID=""

if [[ -n "${SPA_APP_ID}" ]]; then
  log "OIDC SPA application '${SPA_APP_NAME}' already exists (id=${SPA_APP_ID})."
  # SPA apps have no client secret to preserve; we just need the clientId.
  spa_app_detail="$(zapi GET "${MGMT}/projects/${PROJECT_ID}/apps/${SPA_APP_ID}" "" "${PROJECT_ORG_ID}")"
  SPA_CLIENT_ID="$(printf '%s' "${spa_app_detail}" | jq -r '.app.oidcConfig.clientId // empty')"
  log "Existing SPA clientId=${SPA_CLIENT_ID}."

  if printf '%s' "${spa_app_detail}" | jq -e \
    --arg redirect "${SPA_REDIRECT_URI}" \
    --arg post_logout "${SPA_POST_LOGOUT_URI}" \
    '((.app.oidcConfig.redirectUris // []) | index($redirect)) and ((.app.oidcConfig.postLogoutRedirectUris // []) | index($post_logout))' \
    >/dev/null; then
    log "OIDC SPA application already allows ${SPA_REDIRECT_URI}."
  else
    spa_redirects="$(
      printf '%s' "${spa_app_detail}" | jq -c \
        --arg redirect "${SPA_REDIRECT_URI}" \
        --arg legacy "${SPA_LEGACY_REDIRECT_URI}" \
        '((.app.oidcConfig.redirectUris // []) + [$redirect, $legacy]) | unique'
    )"
    spa_post_logouts="$(
      printf '%s' "${spa_app_detail}" | jq -c \
        --arg post_logout "${SPA_POST_LOGOUT_URI}" \
        --arg legacy "${SPA_LEGACY_POST_LOGOUT_URI}" \
        '((.app.oidcConfig.postLogoutRedirectUris // []) + [$post_logout, $legacy]) | unique'
    )"
    spa_oidc_update_body="$(
      jq -cn \
        --argjson redirects "${spa_redirects}" \
        --argjson post_logouts "${spa_post_logouts}" \
        '{
        "redirectUris": $redirects,
        "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
        "grantTypes": [
          "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
          "OIDC_GRANT_TYPE_REFRESH_TOKEN"
        ],
        "appType": "OIDC_APP_TYPE_USER_AGENT",
        "authMethodType": "OIDC_AUTH_METHOD_TYPE_NONE",
        "postLogoutRedirectUris": $post_logouts,
        "devMode": true,
        "accessTokenType": "OIDC_TOKEN_TYPE_JWT",
        "idTokenRoleAssertion": true,
        "idTokenUserinfoAssertion": true
      }'
    )"
    zapi PUT "${MGMT}/projects/${PROJECT_ID}/apps/${SPA_APP_ID}/oidc_config" \
      "${spa_oidc_update_body}" "" "${PROJECT_ORG_ID}" >/dev/null
    log "OIDC SPA application config ensured for ${SPA_REDIRECT_URI}."
  fi
else
  log "Creating OIDC SPA application '${SPA_APP_NAME}' ..."
  spa_oidc_body="$(
    jq -cn \
      --arg name "${SPA_APP_NAME}" \
      --arg redirect "${SPA_REDIRECT_URI}" \
      --arg legacy_redirect "${SPA_LEGACY_REDIRECT_URI}" \
      --arg post_logout "${SPA_POST_LOGOUT_URI}" \
      --arg legacy_post_logout "${SPA_LEGACY_POST_LOGOUT_URI}" \
      '{
      "name": $name,
      "redirectUris": [$redirect, $legacy_redirect],
      "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
      "grantTypes": [
        "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
        "OIDC_GRANT_TYPE_REFRESH_TOKEN"
      ],
      "appType": "OIDC_APP_TYPE_USER_AGENT",
      "authMethodType": "OIDC_AUTH_METHOD_TYPE_NONE",
      "postLogoutRedirectUris": [$post_logout, $legacy_post_logout],
      "version": "OIDC_VERSION_1_0",
      "devMode": true,
      "accessTokenType": "OIDC_TOKEN_TYPE_JWT",
      "accessTokenRoleAssertion": false,
      "idTokenRoleAssertion": true,
      "idTokenUserinfoAssertion": true
    }'
  )"
  spa_app_create="$(zapi POST "${MGMT}/projects/${PROJECT_ID}/apps/oidc" \
    "${spa_oidc_body}" "" "${PROJECT_ORG_ID}")"
  SPA_APP_ID="$(printf '%s' "${spa_app_create}" | jq -r '.appId')"
  SPA_CLIENT_ID="$(printf '%s' "${spa_app_create}" | jq -r '.clientId')"
  # PKCE public clients have no secret; Zitadel may return an empty string.
  # Discard it explicitly so it never leaks into env files or logs.
  log "OIDC SPA application created (id=${SPA_APP_ID}, clientId=${SPA_CLIENT_ID})."
fi

# ---------------------------------------------------------------------------
# 6. Resolve or create the test human user
# ---------------------------------------------------------------------------
log "Resolving test user '${TEST_USER_EMAIL}' ..."

user_search="$(zapi GET \
  "${MGMT}/global/users/_by_login_name?loginName=${TEST_USER_EMAIL}" \
  "" "${ORG_ID}" 2>/dev/null || true)"

USER_ID="$(printf '%s' "${user_search}" | jq -r '.user.id // empty')"

if [[ -n "${USER_ID}" ]]; then
  log "Test user '${TEST_USER_EMAIL}' already exists (id=${USER_ID})."
else
  log "Creating test user '${TEST_USER_EMAIL}' ..."
  human_body="$(
    jq -cn \
      --arg username "${TEST_USER_EMAIL}" \
      --arg first "${TEST_USER_FIRST}" \
      --arg last "${TEST_USER_LAST}" \
      --arg email "${TEST_USER_EMAIL}" \
      --arg password "${TEST_USER_PASSWORD}" \
      '{
      "userName": $username,
      "profile": {
        "firstName": $first,
        "lastName": $last
      },
      "email": {
        "email": $email,
        "isEmailVerified": true
      },
      "password": $password,
      "passwordChangeRequired": false
    }'
  )"
  human_create="$(zapi POST "${MGMT}/users/human/_import" \
    "${human_body}" "" "${ORG_ID}")"
  USER_ID="$(printf '%s' "${human_create}" | jq -r '.userId')"
  log "Test user created (id=${USER_ID})."
fi

# ---------------------------------------------------------------------------
# 7. Resolve or create the API service account
# ---------------------------------------------------------------------------
log "Resolving service account '${SERVICE_ACCOUNT_USERNAME}' ..."

svc_search="$(zapi POST "${MGMT}/users/_search" \
  '{"queries":[{"userNameQuery":{"userName":"'"${SERVICE_ACCOUNT_USERNAME}"'","method":"TEXT_QUERY_METHOD_EQUALS"}}]}' \
  "" "${ORG_ID}")"

SVC_ID="$(printf '%s' "${svc_search}" | jq -r '.result[0].id // empty')"

if [[ -n "${SVC_ID}" ]]; then
  log "Service account '${SERVICE_ACCOUNT_USERNAME}' already exists (id=${SVC_ID})."
else
  log "Creating service account '${SERVICE_ACCOUNT_USERNAME}' ..."
  svc_body="$(
    jq -cn \
      --arg username "${SERVICE_ACCOUNT_USERNAME}" \
      --arg name "${SERVICE_ACCOUNT_NAME}" \
      '{
      "userName": $username,
      "name": $name,
      "description": "API service account for the PublicSchema core service"
    }'
  )"
  svc_create="$(zapi POST "${MGMT}/users/machine" \
    "${svc_body}" "" "${ORG_ID}")"
  SVC_ID="$(printf '%s' "${svc_create}" | jq -r '.userId')"
  log "Service account created (id=${SVC_ID})."
fi

# ---------------------------------------------------------------------------
# 7b. Configure the SA for the registry_relay integration path.
#     The relay verifies bearer JWTs (no opaque tokens), so the SA must
#     emit JWT-typed access tokens. It also needs a client_credentials
#     secret so machine-to-machine token minting works against the
#     OAuth /token endpoint.
#
#     Zitadel notes:
#     - The SA's resourceOwner can differ from ORG_ID (we have seen it
#       land in the bootstrap org rather than the publicschema-dev org).
#       Resolve it from the SA record before issuing per-SA writes.
#     - The accessTokenType enum in v2.66 is ACCESS_TOKEN_TYPE_JWT
#       (numeric 1). The string OIDC_TOKEN_TYPE_JWT is silently ignored
#       on PUT, so we send the integer.
#     - PUT /users/{id}/machine validates name length > 0 even when
#       only changing accessTokenType, so we resend the full triple.
#     - Zitadel returns HTTP 400 "Errors.User.NotChanged" when the body
#       matches the current state; treat that as success.
#     - PUT /users/{id}/secret regenerates the secret and returns it
#       once. We only regen when the env file does not already carry
#       OIDC_SA_CLIENT_SECRET, so reruns preserve the existing value.
#
#     Project-level `projectRoleAssertion` is intentionally not toggled
#     here: the integration test asserts auth wiring (sub, aud, iss,
#     signature), not the roles claim. Enabling role assertion on the
#     client_credentials path against a Zitadel machine user is a
#     known-fiddly area in v2.66 and is left as a follow-up.
# ---------------------------------------------------------------------------
log "Configuring SA '${SERVICE_ACCOUNT_USERNAME}' for client_credentials + JWT ..."

svc_detail="$(zapi GET "${MGMT}/users/${SVC_ID}" "" "${PROJECT_ORG_ID}")"
SVC_RESOURCE_OWNER="$(printf '%s' "${svc_detail}" | jq -r '.user.details.resourceOwner // empty')"

if [[ -z "${SVC_RESOURCE_OWNER}" ]]; then
  log "ERROR: could not read resourceOwner for SA ${SVC_ID}."
  exit 1
fi
log "SA resourceOwner=${SVC_RESOURCE_OWNER}."

svc_token_type="$(printf '%s' "${svc_detail}" | jq -r '.user.machine.accessTokenType // empty')"
if [[ "${svc_token_type}" == "ACCESS_TOKEN_TYPE_JWT" ]]; then
  log "SA accessTokenType already JWT."
else
  log "Setting SA accessTokenType=JWT (current=${svc_token_type:-default-bearer}) ..."
  machine_body="$(
    jq -cn \
      --arg name "${SERVICE_ACCOUNT_NAME}" \
      --arg desc "API service account for the PublicSchema core service" \
      '{name: $name, description: $desc, accessTokenType: 1}'
  )"
  machine_http_status="$(
    curl --silent --output /dev/null --write-out '%{http_code}' \
      -X PUT \
      -H "Host: localhost" \
      -H "Authorization: Bearer ${PAT}" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      -H "x-zitadel-orgid: ${SVC_RESOURCE_OWNER}" \
      --data "${machine_body}" \
      "${MGMT}/users/${SVC_ID}/machine"
  )"
  # 200 = changed; 400 = "Errors.User.NotChanged" when fields already match.
  if [[ "${machine_http_status}" != "200" && "${machine_http_status}" != "400" ]]; then
    log "ERROR: PUT /users/${SVC_ID}/machine returned ${machine_http_status}."
    exit 1
  fi
  log "SA accessTokenType ensured (status=${machine_http_status})."
fi

# Generate a fresh service-account client secret by default. Registry Lab
# scripts mint tokens from the current /seed/zitadel.env, so freshness is
# simpler than preserving stale demo credentials. Set
# PRESERVE_SA_CLIENT_SECRET=1 to keep an existing secret across init runs.
SA_CLIENT_ID="${SERVICE_ACCOUNT_USERNAME}"
SA_CLIENT_SECRET=""

if [[ "${PRESERVE_SA_CLIENT_SECRET:-0}" == "1" && -f "${OUTPUT_FILE}" ]]; then
  existing_sa_client_id="$(grep '^OIDC_SA_CLIENT_ID=' "${OUTPUT_FILE}" | cut -d= -f2- || true)"
  existing_sa_secret="$(grep '^OIDC_SA_CLIENT_SECRET=' "${OUTPUT_FILE}" | cut -d= -f2- || true)"
  if [[ "${existing_sa_client_id}" == "${SA_CLIENT_ID}" && -n "${existing_sa_secret}" ]]; then
    SA_CLIENT_SECRET="${existing_sa_secret}"
    log "Preserving existing SA client secret from ${OUTPUT_FILE}."
  elif [[ -n "${existing_sa_secret}" ]]; then
    log "Not preserving existing SA client secret because it belongs to '${existing_sa_client_id:-unknown}'."
  fi
fi

if [[ -z "${SA_CLIENT_SECRET}" ]]; then
  log "Generating SA client secret ..."
  secret_resp="$(zapi PUT "${MGMT}/users/${SVC_ID}/secret" "{}" "${SVC_RESOURCE_OWNER}")"
  SA_CLIENT_ID="$(printf '%s' "${secret_resp}" | jq -r '.clientId')"
  SA_CLIENT_SECRET="$(printf '%s' "${secret_resp}" | jq -r '.clientSecret')"
  if [[ -z "${SA_CLIENT_ID}" || -z "${SA_CLIENT_SECRET}" ]]; then
    log "ERROR: PUT /users/${SVC_ID}/secret did not return clientId/clientSecret."
    exit 1
  fi
  log "SA client secret generated (clientId=${SA_CLIENT_ID})."
fi

# ---------------------------------------------------------------------------
# 8. Resolve or create project roles on the Workbench project.
#    These roles are asserted in access tokens when accessTokenRoleAssertion is
#    true on the OIDC app. Zitadel emits them under the claim:
#      urn:zitadel:iam:org:project:roles
#    as an object keyed by role name, e.g.:
#      {"social-registry-reader": {"<orgId>": "<domain>"}, ...}
#    See compose/seed/zitadel-bootstrap.md for the full claim shape and the
#    registry_relay scope_map configuration implications.
# ---------------------------------------------------------------------------
log "Resolving project roles on project '${PROJECT_NAME}' ..."

roles_search="$(zapi POST "${MGMT}/projects/${PROJECT_ID}/roles/_search" \
  '{}' "" "${PROJECT_ORG_ID}")"

ensure_project_role() {
  local role_key="$1"
  local display_name="$2"
  local group="$3"

  local existing
  existing="$(printf '%s' "${roles_search}" | jq -r \
    --arg key "${role_key}" '.result[]? | select(.key == $key) | .key // empty')"

  if [[ -n "${existing}" ]]; then
    log "Project role '${role_key}' already exists."
  else
    log "Creating project role '${role_key}' ..."
    local role_body
    role_body="$(
      jq -cn \
        --arg key "${role_key}" \
        --arg displayName "${display_name}" \
        --arg group "${group}" \
        '{"roleKey": $key, "displayName": $displayName, "group": $group}'
    )"
    local http_status
    http_status="$(
      curl --silent --output /dev/null --write-out '%{http_code}' \
        -X POST \
        -H "Host: localhost" \
        -H "Authorization: Bearer ${PAT}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -H "x-zitadel-orgid: ${PROJECT_ORG_ID}" \
        --data "${role_body}" \
        "${MGMT}/projects/${PROJECT_ID}/roles"
    )"
    # 200 = created; 409 = already exists (concurrent run or partial state).
    if [[ "${http_status}" == "200" || "${http_status}" == "409" ]]; then
      log "Project role '${role_key}' created (or already existed, status=${http_status})."
    else
      log "ERROR: unexpected status ${http_status} creating project role '${role_key}'."
      exit 1
    fi
  fi
}

ensure_project_role "social-registry-reader" "Social Registry Reader" "registry-relay"
ensure_project_role "social-registry-aggregate" "Social Registry Aggregate" "registry-relay"

# ---------------------------------------------------------------------------
# 9. Grant both project roles to the machine user and the human test user.
#    A user grant ties a user to a set of roles on a project within an org.
#    Zitadel returns HTTP 409 if a grant already exists for the same
#    user + project combination; that is treated as success.
# ---------------------------------------------------------------------------
log "Granting project roles to users ..."

ensure_user_grant() {
  local user_id="$1"
  local user_label="$2"

  # Search for an existing grant for this user on the Workbench project.
  local grant_search
  grant_search="$(
    zapi POST "${MGMT}/users/grants/_search" \
      "$(jq -cn --arg uid "${user_id}" --arg pid "${PROJECT_ID}" \
        '{"queries": [
            {"userIdQuery": {"userId": $uid}},
            {"projectIdQuery": {"projectId": $pid}}
          ]}')" \
      "" "${PROJECT_ORG_ID}"
  )"

  local grant_id
  grant_id="$(printf '%s' "${grant_search}" | jq -r '.result[0].id // empty')"

  if [[ -n "${grant_id}" ]]; then
    log "User grant for '${user_label}' on '${PROJECT_NAME}' already exists (id=${grant_id})."
    # Ensure both roles are present in the existing grant by updating it.
    # Zitadel returns 400 "No changes" when the grant already has the desired
    # roles; treat that as success.
    local update_body
    update_body="$(jq -cn '{"roleKeys": ["social-registry-reader", "social-registry-aggregate"]}')"
    local update_status
    update_status="$(
      curl --silent --output /dev/null --write-out '%{http_code}' \
        -X PUT \
        -H "Host: localhost" \
        -H "Authorization: Bearer ${PAT}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -H "x-zitadel-orgid: ${PROJECT_ORG_ID}" \
        --data "${update_body}" \
        "${MGMT}/users/${user_id}/grants/${grant_id}"
    )"
    if [[ "${update_status}" == "200" || "${update_status}" == "400" ]]; then
      log "User grant roles ensured for '${user_label}'."
    else
      log "ERROR: unexpected status ${update_status} updating user grant for '${user_label}'."
      exit 1
    fi
  else
    log "Creating user grant for '${user_label}' on '${PROJECT_NAME}' ..."
    local grant_body
    grant_body="$(
      jq -cn \
        --arg pid "${PROJECT_ID}" \
        '{"projectId": $pid, "roleKeys": ["social-registry-reader", "social-registry-aggregate"]}'
    )"
    local http_status
    http_status="$(
      curl --silent --output /dev/null --write-out '%{http_code}' \
        -X POST \
        -H "Host: localhost" \
        -H "Authorization: Bearer ${PAT}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -H "x-zitadel-orgid: ${PROJECT_ORG_ID}" \
        --data "${grant_body}" \
        "${MGMT}/users/${user_id}/grants"
    )"
    if [[ "${http_status}" == "200" || "${http_status}" == "409" ]]; then
      log "User grant for '${user_label}' created (or already existed, status=${http_status})."
    else
      log "ERROR: unexpected status ${http_status} creating user grant for '${user_label}'."
      exit 1
    fi
  fi
}

ensure_user_grant "${SVC_ID}" "${SERVICE_ACCOUNT_USERNAME}"
ensure_user_grant "${USER_ID}" "${TEST_USER_EMAIL}"

# ---------------------------------------------------------------------------
# 10. Write /seed/zitadel.env
#     The file is written atomically (write to tmp, then move) so a partial
#     write is never visible to readers.
# ---------------------------------------------------------------------------
log "Writing credentials to ${OUTPUT_FILE} ..."

TMP_FILE="${OUTPUT_FILE}.tmp"

# If CLIENT_SECRET is empty (app already existed on a previous run), preserve
# whatever was in the output file from the first run.
if [[ -z "${CLIENT_SECRET}" && -f "${OUTPUT_FILE}" ]]; then
  existing_secret="$(grep '^OIDC_CLIENT_SECRET=' "${OUTPUT_FILE}" | cut -d= -f2- || true)"
  CLIENT_SECRET="${existing_secret}"
fi

cat >"${TMP_FILE}" <<EOF
# Generated by zitadel-init.sh — do not edit by hand.
# Re-run 'docker compose -f compose/dev.compose.yaml restart zitadel-init'
# to regenerate (requires the Zitadel app to be deleted first if the secret
# is lost; see compose/seed/zitadel-bootstrap.md).
#
# OIDC_CLIENT_ID / OIDC_CLIENT_SECRET belong to the workbench-dev OIDC app
# (authorization_code flow for human login). OIDC_SA_CLIENT_ID and
# OIDC_SA_CLIENT_SECRET belong to the publicschema-api machine user
# (client_credentials flow for machine-to-machine, including the
# registry_relay integration test).

OIDC_ISSUER=${ZITADEL_PUBLIC_URL}
OIDC_CLIENT_ID=${CLIENT_ID}
OIDC_CLIENT_SECRET=${CLIENT_SECRET}
OIDC_TEST_USER=${TEST_USER_EMAIL}
OIDC_TEST_USER_PASSWORD=${TEST_USER_PASSWORD}
OIDC_SPA_CLIENT_ID=${SPA_CLIENT_ID}
OIDC_PROJECT_ID=${PROJECT_ID}
OIDC_SA_CLIENT_ID=${SA_CLIENT_ID}
OIDC_SA_CLIENT_SECRET=${SA_CLIENT_SECRET}
EOF

mv "${TMP_FILE}" "${OUTPUT_FILE}"

log "Done. Credentials written to ${OUTPUT_FILE}:"
log "  OIDC_ISSUER=${ZITADEL_PUBLIC_URL}"
log "  OIDC_CLIENT_ID=${CLIENT_ID}"
log "  OIDC_CLIENT_SECRET=<redacted>"
log "  OIDC_TEST_USER=${TEST_USER_EMAIL}"
log "  OIDC_SPA_CLIENT_ID=${SPA_CLIENT_ID}"
log "  OIDC_PROJECT_ID=${PROJECT_ID}"
log "  OIDC_SA_CLIENT_ID=${SA_CLIENT_ID}"
log "  OIDC_SA_CLIENT_SECRET=<redacted>"
