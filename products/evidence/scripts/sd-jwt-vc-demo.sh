#!/usr/bin/env bash
# Run the Evidence SD-JWT VC demo end to end with curl.
#
# The demo is deterministic and credential-free: a local mock stands in for the
# upstream source and an in-memory test JWKS authenticates the requester. No
# DHIS2, OpenCRVS, or other live provider is called and nothing is written
# outside products/evidence/.sd-jwt-vc-demo/.
#
# The steps are the ones a relying party actually performs: request the signed
# default, request the same assertion as an SD-JWT VC, fetch the issuer's keys
# from the published metadata route, and re-verify the stored credential
# offline against a policy built from the accepted transaction.
set -euo pipefail

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
state_root="$repository_root/products/evidence/.sd-jwt-vc-demo"
harness_log="$state_root/harness.log"
base_url="http://127.0.0.1:18081"
readiness_timeout_seconds=600
harness_pid=

for tool in cargo curl jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'The demo needs %s on PATH.\n' "$tool" >&2
    exit 1
  fi
done

# Decode one unpadded base64url segment read from standard input. jq is already
# required above, so the demo needs no GNU-only coreutils.
decode_base64url() {
  jq -Rr '
    (gsub("-"; "+") | gsub("_"; "/")) as $standard
    | ((4 - ($standard | length) % 4) % 4) as $padding
    | (if $padding == 0 then $standard else $standard + ("=" * $padding) end)
    | @base64d
  '
}

# cargo spawns the test binary as a child, so terminating cargo alone would
# leave the server holding the port. Job control puts the harness in its own
# process group, and the group is what gets signalled.
cleanup() {
  if [[ -n "$harness_pid" ]] && kill -0 "$harness_pid" 2>/dev/null; then
    kill -TERM -- -"$harness_pid" 2>/dev/null || kill -TERM "$harness_pid" 2>/dev/null || true
    wait "$harness_pid" 2>/dev/null || true
  fi
  unset EVIDENCE_ACCESS_TOKEN
}
trap cleanup EXIT HUP INT PIPE TERM

cd "$repository_root"
mkdir -p "$state_root"
chmod 700 "$state_root"
rm -f "$harness_log"

if curl --silent --output /dev/null --max-time 2 "$base_url/health"; then
  printf 'Something is already serving %s. Stop it before running the demo.\n' "$base_url" >&2
  exit 1
fi

printf 'Starting the deterministic Evidence demo server. The first run compiles the crate.\n'
set -m
CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked -p registry-evidence \
  sd_jwt_vc_demo_serves_a_credential_for_curl \
  -- --ignored --nocapture >"$harness_log" 2>&1 &
harness_pid=$!
set +m

waited=0
until grep -q 'demo server is ready' "$harness_log" 2>/dev/null; do
  if ! kill -0 "$harness_pid" 2>/dev/null; then
    printf 'The demo server exited before it was ready:\n' >&2
    cat "$harness_log" >&2
    exit 1
  fi
  if ((waited >= readiness_timeout_seconds)); then
    printf 'The demo server was not ready within %ss.\n' "$readiness_timeout_seconds" >&2
    cat "$harness_log" >&2
    exit 1
  fi
  sleep 2
  waited=$((waited + 2))
done
printf 'Server ready at %s\n\n' "$base_url"

# The short-lived synthetic bearer token stays in shell memory and is passed to
# curl through standard input, never on a command line and never in the log.
set -a
# shellcheck source=/dev/null
. "$state_root/session.env"
set +a

printf '1. Fetch the issuer keys from the published metadata route (no token)\n'
curl --config - <<CURL_CONFIG
url = "$base_url/.well-known/jwt-vc-issuer"
header = "Accept: application/json"
output = "$state_root/issuer-metadata.json"
write-out = "   HTTP %{http_code} %{content_type}\n"
silent
show-error
fail-with-body
CURL_CONFIG
jq '{keys: .jwks.keys}' "$state_root/issuer-metadata.json" >"$state_root/trusted.jwks.json"
printf '   issuer: %s\n' "$(jq -r .issuer "$state_root/issuer-metadata.json")"

printf '2. Request the signed default (Accept: application/jose+json)\n'
curl --config - <<CURL_CONFIG
url = "$base_url/v1/evidence"
request = "POST"
header = "Authorization: Bearer $EVIDENCE_ACCESS_TOKEN"
header = "Content-Type: application/json"
header = "Accept: application/jose+json"
data-binary = "@$state_root/request.json"
output = "$state_root/response.jws.json"
write-out = "   HTTP %{http_code} %{content_type}\n"
silent
show-error
fail-with-body
CURL_CONFIG

printf '3. Request the same assertion as an SD-JWT VC (Accept: application/dc+sd-jwt)\n'
curl --config - <<CURL_CONFIG
url = "$base_url/v1/evidence"
request = "POST"
header = "Authorization: Bearer $EVIDENCE_ACCESS_TOKEN"
header = "Content-Type: application/json"
header = "Accept: application/dc+sd-jwt"
data-binary = "@$state_root/request.json"
output = "$state_root/credential.txt"
write-out = "   HTTP %{http_code} %{content_type}\n"
silent
show-error
fail-with-body
CURL_CONFIG

unset EVIDENCE_ACCESS_TOKEN
printf '\n'

# The harness verifies the credential against the signed transaction, checks
# minimization and audit, writes the policy document, and then exits.
if ! wait "$harness_pid"; then
  harness_pid=
  printf 'The demo server did not pass its own checks:\n' >&2
  cat "$harness_log" >&2
  exit 1
fi
harness_pid=
grep '^PASS:' "$harness_log"
printf '\n'

printf '4. The credential: an issuer-signed JWT, one disclosure per supported value,\n'
printf '   and a trailing tilde where a key-binding JWT would go\n'
credential=$(cat "$state_root/credential.txt")
IFS='~' read -r -a segments <<<"$credential"
if [[ "${credential: -1}" != '~' ]]; then
  printf 'The credential does not end with a tilde, so it is not the issued form.\n' >&2
  exit 1
fi
printf '   %s disclosure(s), no key-binding JWT\n' "$((${#segments[@]} - 1))"
printf '   protected header: %s\n' "$(printf '%s' "${segments[0]%%.*}" | decode_base64url)"
printf '   disclosures (salt, claim name, claim value):\n'
for disclosure in "${segments[@]:1}"; do
  printf '     %s\n' "$(printf '%s' "$disclosure" | decode_base64url)"
done
printf '\n'

printf '5. Re-verify the stored credential offline, no network and no server\n'
cargo run --locked --quiet -p registry-evidence -- verify \
  --sd-jwt-vc "$state_root/credential.txt" \
  --jwks "$state_root/trusted.jwks.json" \
  --policy "$state_root/verification-policy.yaml"

printf '\n6. Tamper with one disclosure and re-verify: selective disclosure is not\n'
printf '   an invitation to edit the claim after issuance\n'
disclosure="${segments[1]}"
if [[ "${disclosure: -1}" == 'A' ]]; then replacement='B'; else replacement='A'; fi
tampered_segments=("${segments[@]}")
tampered_segments[1]="${disclosure%?}$replacement"
printf '%s~' "${tampered_segments[@]}" >"$state_root/tampered-credential.txt"
if cargo run --locked --quiet -p registry-evidence -- verify \
  --sd-jwt-vc "$state_root/tampered-credential.txt" \
  --jwks "$state_root/trusted.jwks.json" \
  --policy "$state_root/verification-policy.yaml" >/dev/null 2>"$state_root/tampered.stderr"; then
  printf 'A tampered credential verified. That is a defect, not a demo.\n' >&2
  exit 1
fi
printf '   rejected: %s\n' "$(cat "$state_root/tampered.stderr")"

cat <<SUMMARY

Done. The demo artifacts are gitignored and kept for inspection in
products/evidence/.sd-jwt-vc-demo/:

  request.json              the exact request, including its single-use requestNonce
  response.jws.json         the signed flattened JWS default
  credential.txt            the SD-JWT VC
  issuer-metadata.json      the published issuer identity and key set
  trusted.jwks.json         the pinned key set the offline verifier used
  verification-policy.yaml  expectations taken from the accepted transaction
  tampered-credential.txt   the same credential with one edited disclosure
  harness.log               the demo server's own checks

session.env holds only the short-lived synthetic bearer token. Do not paste it
anywhere. Walkthrough and explanation: products/evidence/SD-JWT-VC-DEMO.md
SUMMARY
