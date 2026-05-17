#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Mint a bearer JWT against a Zitadel OIDC application via the OAuth2
# client_credentials grant, sourcing credentials from the env file
# produced by the publicschema.com dev compose bootstrap
# (compose/seed/zitadel.env). Prints the access_token on stdout; intended
# for piping into a curl invocation or assigning to a shell variable
# before running the oidc_zitadel integration test.
#
# Usage:
#   ./scripts/mint-zitadel-token.sh                       # default env file
#   ./scripts/mint-zitadel-token.sh path/to/zitadel.env   # explicit
#
# Optional: set OIDC_SCOPE to request specific scopes (e.g. a resource
# scope mapped to a relay role). Left unset, the IdP grants the
# application's default scopes; `openid`/`profile` are intentionally
# omitted because client_credentials does not issue ID tokens.
#
# Requires: curl, jq.
# Requires the OIDC application to have the `client_credentials` grant
# type enabled on the IdP side. The publicschema.com bootstrap configures
# this for the registry-relay path; older snapshots may need the grant
# toggled on via the Zitadel console.

set -euo pipefail

env_file="${1:-../publicschema.com/compose/seed/zitadel.env}"

if [[ ! -f "${env_file}" ]]; then
  cat >&2 <<EOF
mint-zitadel-token: env file not found: ${env_file}
Pass the path as the first argument, or run from a directory where the
publicschema.com Zitadel bootstrap output is reachable at
../publicschema.com/compose/seed/zitadel.env.
EOF
  exit 2
fi

# shellcheck disable=SC1090
source "${env_file}"

: "${OIDC_ISSUER:?OIDC_ISSUER must be set in ${env_file}}"
: "${OIDC_CLIENT_ID:?OIDC_CLIENT_ID must be set in ${env_file}}"
: "${OIDC_CLIENT_SECRET:?OIDC_CLIENT_SECRET must be set in ${env_file}}"

token_url="${OIDC_ISSUER%/}/oauth/v2/token"

scope="${OIDC_SCOPE:-}"

curl_args=(
  --silent --show-error --fail-with-body
  --user "${OIDC_CLIENT_ID}:${OIDC_CLIENT_SECRET}"
  --data-urlencode 'grant_type=client_credentials'
)
if [[ -n "${scope}" ]]; then
  curl_args+=(--data-urlencode "scope=${scope}")
fi
curl_args+=("${token_url}")

response="$(curl "${curl_args[@]}")"

token="$(printf '%s' "${response}" | jq -r '.access_token // empty')"

if [[ -z "${token}" ]]; then
  printf 'mint-zitadel-token: no access_token in response: %s\n' "${response}" >&2
  exit 1
fi

printf '%s\n' "${token}"
