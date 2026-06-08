#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Mint a bearer JWT against the publicschema-api Zitadel machine user via
# the OAuth2 client_credentials grant, sourcing credentials from the env
# file produced by the publicschema.com dev compose bootstrap
# (compose/seed/zitadel.env). Prints the access_token on stdout; intended
# for piping into a curl invocation or assigning to a shell variable
# before running the oidc_zitadel integration test.
#
# Usage:
#   ./scripts/mint-zitadel-token.sh                       # default env file
#   ./scripts/mint-zitadel-token.sh path/to/zitadel.env   # explicit
#
# Optional: set OIDC_SCOPE to request specific scopes (e.g. the project
# audience scope `urn:zitadel:iam:org:project:id:<projectId>:aud` to bind
# the token to a specific Zitadel project). Default is `openid`, which is
# the minimal placeholder Zitadel requires for machine-user
# client_credentials: Zitadel rejects requests without any scope, and
# `openid` is harmless because client_credentials never issues an ID
# token.
#
# Why the machine user and not the OIDC application: Zitadel WEB-typed
# OIDC apps silently drop the client_credentials grant at write time, so
# we authenticate as the publicschema-api SA whose ACCESS_TOKEN_TYPE is
# set to JWT. The publicschema.com bootstrap provisions this SA, sets the
# JWT token type, and writes OIDC_SA_CLIENT_ID / OIDC_SA_CLIENT_SECRET
# into the env file. See apps/publicschema.com/compose/seed/zitadel-init.sh
# section 7b for the provisioning details.
#
# Requires: curl, jq.

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
: "${OIDC_SA_CLIENT_ID:?OIDC_SA_CLIENT_ID must be set in ${env_file} (re-run zitadel-init)}"
: "${OIDC_SA_CLIENT_SECRET:?OIDC_SA_CLIENT_SECRET must be set in ${env_file} (re-run zitadel-init)}"

token_url="${OIDC_ISSUER%/}/oauth/v2/token"

scope="${OIDC_SCOPE:-openid}"

reject_multiline() {
  local name="$1"
  local value="$2"
  if [[ "${value}" == *$'\n'* || "${value}" == *$'\r'* ]]; then
    printf 'mint-zitadel-token: %s must be a single line\n' "${name}" >&2
    exit 2
  fi
}

curl_config_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "${value}"
}

reject_multiline OIDC_ISSUER "${OIDC_ISSUER}"
reject_multiline OIDC_SA_CLIENT_ID "${OIDC_SA_CLIENT_ID}"
reject_multiline OIDC_SA_CLIENT_SECRET "${OIDC_SA_CLIENT_SECRET}"
reject_multiline OIDC_SCOPE "${scope}"

curl_config="$(mktemp "${TMPDIR:-/tmp}/mint-zitadel-token.XXXXXX")"
chmod 600 "${curl_config}"
cleanup() {
  rm -f "${curl_config}"
}
trap cleanup EXIT

{
  printf 'silent\n'
  printf 'show-error\n'
  printf 'fail-with-body\n'
  printf 'user = "%s"\n' "$(curl_config_escape "${OIDC_SA_CLIENT_ID}:${OIDC_SA_CLIENT_SECRET}")"
  printf 'data-urlencode = "grant_type=client_credentials"\n'
  printf 'data-urlencode = "%s"\n' "$(curl_config_escape "scope=${scope}")"
  printf 'url = "%s"\n' "$(curl_config_escape "${token_url}")"
} >"${curl_config}"

response="$(curl --config "${curl_config}")"

token="$(printf '%s' "${response}" | jq -r '.access_token // empty')"

if [[ -z "${token}" ]]; then
  printf 'mint-zitadel-token: no access_token in response: %s\n' "${response}" >&2
  exit 1
fi

printf '%s\n' "${token}"
