#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
registry_serverctl="$repository_root/target/debug/registry-serverctl"
temporary_root=""
created_databases=()
created_roles=()
asset_project="$repository_root/products/registry-server/acceptance/asset-site-placement-change-requests"
household_project="$repository_root/products/registry-server/acceptance/publicschema-household-change-requests"

usage() {
  cat >&2 <<'USAGE'
usage: products/registry-server/scripts/test-change-request-examples.sh [--env FILE] [--asset-project DIR] [--household-project DIR]

Runs both Registry Server change-request example fixtures through registry-serverctl test.
Set REGISTRY_SERVER_TEST_DATABASE_URL and REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH, or pass --env FILE.
Requires Python 3 with PyYAML. Use --asset-project or --household-project to run a disposable edited copy instead of the committed fixture.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env)
      if [[ $# -lt 2 ]]; then
        usage
        exit 2
      fi
      env_file=$2
      shift 2
      ;;
    --asset-project)
      if [[ $# -lt 2 ]]; then
        usage
        exit 2
      fi
      asset_project=$2
      shift 2
      ;;
    --household-project)
      if [[ $# -lt 2 ]]; then
        usage
        exit 2
      fi
      household_project=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -n "${env_file:-}" ]]; then
  if [[ ! -f "$env_file" || -L "$env_file" ]]; then
    printf '%s\n' 'change-request env file is unavailable or unsafe.' >&2
    exit 1
  fi
  source "$env_file"
fi

if [[ -z "${REGISTRY_SERVER_TEST_DATABASE_URL:-}" ]]; then
  printf '%s\n' 'REGISTRY_SERVER_TEST_DATABASE_URL is required.' >&2
  exit 1
fi
if [[ -z "${REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH:-}" || ! -f "$REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH" ]]; then
  printf '%s\n' 'REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH is required.' >&2
  exit 1
fi

cleanup() {
  local database
  local role
  for database in "${created_databases[@]:-}"; do
    psql "$REGISTRY_SERVER_TEST_DATABASE_URL" -v ON_ERROR_STOP=0 -q \
      -c "DROP DATABASE IF EXISTS \"$database\" WITH (FORCE);" >/dev/null 2>&1 || true
  done
  for role in "${created_roles[@]:-}"; do
    psql "$REGISTRY_SERVER_TEST_DATABASE_URL" -v ON_ERROR_STOP=0 -q \
      -c "DROP ROLE IF EXISTS \"$role\";" >/dev/null 2>&1 || true
  done
  case "$temporary_root" in
    "$repository_root"/.registry-server-cr-examples.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    "") ;;
    *)
      printf '%s\n' 'change-request example temp directory escaped its owned location.' >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "$1 is required for change-request example tests." >&2
    exit 1
  fi
}

normalize_project() {
  local label=$1
  local project=$2
  if [[ -z "$project" || ! -d "$project" || -L "$project" ]]; then
    printf '%s\n' "$label project directory is unavailable or unsafe." >&2
    exit 1
  fi
  if [[ ! -f "$project/registry.yaml" || -L "$project/registry.yaml" ]]; then
    printf '%s\n' "$label project registry.yaml is unavailable or unsafe." >&2
    exit 1
  fi
  if [[ ! -f "$project/tests/journeys.yaml" || -L "$project/tests/journeys.yaml" ]]; then
    printf '%s\n' "$label project tests/journeys.yaml is unavailable or unsafe." >&2
    exit 1
  fi
  python3 - "$project" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve(strict=True))
PY
}

assert_json_ok() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
if value.get("ok") is not True or value.get("command") != sys.argv[2]:
    raise SystemExit(f"{sys.argv[2]} did not complete")
PY
}

print_json_diagnostics() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
try:
    value = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print(f"registry-serverctl {sys.argv[2]} failed before writing a JSON report", file=sys.stderr)
    raise SystemExit(0)
diagnostics = value.get("diagnostics", [])
if not diagnostics:
    print(f"registry-serverctl {sys.argv[2]} refused; diagnostics: unavailable", file=sys.stderr)
else:
    print(f"registry-serverctl {sys.argv[2]} refused; diagnostics:", file=sys.stderr)
    for item in diagnostics:
        code = item.get("code", "unknown")
        path = item.get("path", "/")
        message = item.get("message", "")
        print(f"  {code} at {path}: {message}", file=sys.stderr)
PY
}

write_public_jwk() {
  local private_key=$1
  local key_id=$2
  local output=$3
  openssl pkey -in "$private_key" -pubout -outform DER >"$output.der"
  python3 - "$output.der" "$key_id" "$output" <<'PY'
import base64
import json
import sys
from pathlib import Path
der = Path(sys.argv[1]).read_bytes()
if len(der) < 32:
    raise SystemExit("public key document is outside the expected Ed25519 bound")
x = base64.urlsafe_b64encode(der[-32:]).rstrip(b"=").decode("ascii")
jwk = {"alg": "EdDSA", "crv": "Ed25519", "kid": sys.argv[2], "kty": "OKP", "x": x}
Path(sys.argv[3]).write_text(json.dumps(jwk, sort_keys=True, separators=(",", ":")), encoding="utf-8")
PY
  rm -f -- "$output.der"
}

write_jwks() {
  local public_jwk=$1
  local output=$2
  python3 - "$public_jwk" "$output" <<'PY'
import json
import sys
jwk = json.load(open(sys.argv[1], encoding="utf-8"))
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps({"keys": [jwk]}, sort_keys=True, separators=(",", ":")))
PY
}

write_trust_anchor() {
  local public_jwk=$1
  local database_id=$2
  local instance_id=$3
  local output=$4
  python3 - "$public_jwk" "$database_id" "$instance_id" "$output" <<'PY'
import json
import sys
jwk = json.load(open(sys.argv[1], encoding="utf-8"))
anchor = {
    "apiVersion": "registry.registrystack.org/package-trust/v1",
    "databaseId": sys.argv[2],
    "environment": "acceptance",
    "instanceId": sys.argv[3],
    "keys": [{"jwk": jwk, "keyId": jwk["kid"]}],
    "threshold": 1,
}
open(sys.argv[4], "w", encoding="utf-8").write(json.dumps(anchor, sort_keys=True, separators=(",", ":")))
PY
}

write_jwt() {
  local private_key=$1
  local key_id=$2
  local principal=$3
  local purpose=$4
  local scopes=$5
  local output=$6
  python3 - "$key_id" "$principal" "$purpose" "$scopes" "$output.signing-input" <<'PY'
import base64
import json
import sys
import time

def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=").decode("ascii")

now = int(time.time())
claims = {
    "aud": "urn:registry-server:change-request-example",
    "client_id": "registry-change-request-example",
    "exp": now + 3600,
    "iat": now,
    "iss": "https://issuer.example/change-request-example",
    "jti": f"change-request-example-{now}-{sys.argv[2]}",
    "registry_principal": sys.argv[2],
    "sub": sys.argv[2],
}
if sys.argv[3]:
    claims["registry_purpose"] = sys.argv[3]
if sys.argv[4]:
    claims["scope"] = sys.argv[4]
header = {"alg": "EdDSA", "kid": sys.argv[1], "typ": "JWT"}
open(sys.argv[5], "w", encoding="ascii").write(f"{b64(header)}.{b64(claims)}")
PY
  openssl pkeyutl -sign -rawin -inkey "$private_key" -in "$output.signing-input" -out "$output.signature"
  python3 - "$output.signing-input" "$output.signature" "$output" <<'PY'
import base64
import sys
from pathlib import Path
signing_input = Path(sys.argv[1]).read_text(encoding="ascii")
signature = base64.urlsafe_b64encode(Path(sys.argv[2]).read_bytes()).rstrip(b"=").decode("ascii")
Path(sys.argv[3]).write_text(f"{signing_input}.{signature}", encoding="ascii")
PY
  rm -f -- "$output.signing-input" "$output.signature"
}

derive_urls() {
  local database=$1
  local migration_role=$2
  local runtime_role=$3
  local password=$4
  python3 - "$REGISTRY_SERVER_TEST_DATABASE_URL" "$database" "$migration_role" "$runtime_role" "$password" <<'PY'
import sys
from urllib.parse import quote, urlsplit, urlunsplit
admin = urlsplit(sys.argv[1])
database, migration_role, runtime_role, password = sys.argv[2:]
if admin.scheme not in {"postgres", "postgresql"} or not admin.hostname:
    raise SystemExit("REGISTRY_SERVER_TEST_DATABASE_URL must be a PostgreSQL URL")
netloc_suffix = admin.hostname if admin.port is None else f"{admin.hostname}:{admin.port}"
query = admin.query
def url(role):
    userinfo = f"{quote(role, safe='')}:{quote(password, safe='')}"
    return urlunsplit((admin.scheme, f"{userinfo}@{netloc_suffix}", f"/{quote(database, safe='')}", query, ""))
print(url(migration_role))
print(url(runtime_role))
PY
}

admin_database_url() {
  local database=$1
  python3 - "$REGISTRY_SERVER_TEST_DATABASE_URL" "$database" <<'PY'
import sys
from urllib.parse import quote, urlsplit, urlunsplit
admin = urlsplit(sys.argv[1])
if admin.scheme not in {"postgres", "postgresql"} or not admin.hostname:
    raise SystemExit("REGISTRY_SERVER_TEST_DATABASE_URL must be a PostgreSQL URL")
print(urlunsplit((admin.scheme, admin.netloc, f"/{quote(sys.argv[2], safe='')}", admin.query, "")))
PY
}

provision_database() {
  local database=$1
  local migration_role=$2
  local runtime_role=$3
  local db_admin
  db_admin=$(admin_database_url "$database")
  psql "$REGISTRY_SERVER_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -q \
    -c "CREATE DATABASE \"$database\";" >/dev/null
  created_databases+=("$database")
  psql "$db_admin" -v ON_ERROR_STOP=1 -q \
    -c "CREATE EXTENSION IF NOT EXISTS btree_gist;" \
    -c "REVOKE ALL ON DATABASE \"$database\" FROM PUBLIC;" \
    -c "GRANT CONNECT ON DATABASE \"$database\" TO \"$migration_role\", \"$runtime_role\";" \
    -c "CREATE SCHEMA registry_internal AUTHORIZATION \"$migration_role\";" \
    -c "CREATE SCHEMA registry_data AUTHORIZATION \"$migration_role\";" \
    -c "CREATE SCHEMA registry_source AUTHORIZATION \"$migration_role\";" \
    -c "CREATE SCHEMA registry_derived AUTHORIZATION \"$migration_role\";" \
    -c "CREATE SCHEMA registry_context AUTHORIZATION \"$migration_role\";" \
    -c "REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context FROM PUBLIC;" >/dev/null
}

render_runtime_config() {
  local output=$1
  local database_id=$2
  local runtime_ref=$3
  local migration_ref=$4
  local source_revision=$5
  local instance_id=$6
  local migration_role=$7
  local runtime_role=$8
  local trust_anchor=$9
  cat >"$output" <<EOF_RUNTIME
apiVersion: registry.registrystack.org/server-runtime/v1alpha1
kind: RegistryServerRuntimeConfig
listener:
  bind: 127.0.0.1:0
  trustedProxy: direct
identity:
  environment: acceptance
  instanceId: $instance_id
  databaseId: $database_id
  databaseInitializationEnvironment: acceptance
secretProviders:
  file:
    root: $temporary_root/secrets
database:
  runtimeUrlRef: $runtime_ref
  migrationUrlRef: $migration_ref
  pool:
    maxSize: 4
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: $migration_role
    runtime: $runtime_role
package:
  root: $temporary_root/empty-package-root
  trustAnchorPath: $trust_anchor
  compilerSourceRevision: $source_revision
  activeRevision: sha256:1111111111111111111111111111111111111111111111111111111111111111
  activeSequence: 1
authentication:
  oidc:
    issuer: https://issuer.example/change-request-example
    audience: urn:registry-server:change-request-example
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-change-request-example]
    deniedKids: []
    maxTokenLifetimeSeconds: 3600
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 0
    jwksSource:
      kind: static
      documentRef: secret:file/oidc-jwks
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
eventDestinations: {}
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
EOF_RUNTIME
}

write_credentials_from_project() {
  local project=$1
  local output=$2
  shift 2
  python3 - "$project/tests/journeys.yaml" "$output" "$@" <<'PY'
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError as error:
    raise SystemExit("PyYAML is required for change-request example credential generation") from error

journeys_path = Path(sys.argv[1])
output = Path(sys.argv[2])
profile_tokens = {}
for value in sys.argv[3:]:
    if "=" not in value:
        raise SystemExit("credential profile mapping is malformed")
    profile, token = value.split("=", 1)
    if not profile or not token:
        raise SystemExit("credential profile mapping is incomplete")
    profile_tokens[profile] = token

with journeys_path.open(encoding="utf-8") as handle:
    document = yaml.safe_load(handle)
if not isinstance(document, dict):
    raise SystemExit("journey document is malformed")
journeys = document.get("journeys")
if not isinstance(journeys, list) or not journeys:
    raise SystemExit("journey suite was not found or had no steps")

bindings = []
for journey in journeys:
    if not isinstance(journey, dict):
        raise SystemExit("journey entry is malformed")
    journey_id = journey.get("id")
    steps = journey.get("steps")
    if not isinstance(journey_id, str) or not isinstance(steps, list) or not steps:
        raise SystemExit("journey entry is incomplete")
    for step in steps:
        if not isinstance(step, dict):
            raise SystemExit("journey step is malformed")
        step_id = step.get("id")
        profile = step.get("accessProfile")
        if not isinstance(step_id, str) or not isinstance(profile, str):
            raise SystemExit("journey step is missing id or accessProfile")
        token = profile_tokens.get(profile)
        if token is None:
            raise SystemExit(f"journey step {step_id} uses unmapped accessProfile {profile}")
        bindings.append({
            "journeyId": journey_id,
            "stepId": step_id,
            "credential": {"type": "bearer", "tokenRef": f"secret:file/{token}"},
        })

if not bindings:
    raise SystemExit("journey suite was not found or had no steps")

document = {
    "apiVersion": "registry.registrystack.org/server-schema-test-credentials/v1",
    "kind": "SchemaTestCredentials",
    "bindings": bindings,
}
output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

run_fixture() {
  local fixture_name=$1
  local project_path=$2
  local database=$3
  local database_id=$4
  local runtime_secret=$5
  local migration_secret=$6
  local source_revision=$7
  local instance_id=$8
  local credentials=$9
  local expected_journey=${10}
  local urls
  local migration_url
  local runtime_url
  local report="$temporary_root/$fixture_name-report.json"
  local receipt="$temporary_root/$fixture_name-receipt.json"

  urls=$(derive_urls "$database" "$migration_role" "$runtime_role" "$role_password")
  migration_url=$(printf '%s\n' "$urls" | sed -n '1p')
  runtime_url=$(printf '%s\n' "$urls" | sed -n '2p')
  printf '%s' "$runtime_url" >"$temporary_root/secrets/$runtime_secret"
  printf '%s' "$migration_url" >"$temporary_root/secrets/$migration_secret"
  chmod 600 "$temporary_root/secrets/$runtime_secret" "$temporary_root/secrets/$migration_secret"

  provision_database "$database" "$migration_role" "$runtime_role"
  local trust_anchor="$temporary_root/$fixture_name-trust-anchor.json"
  write_trust_anchor "$package_public_jwk" "$database_id" "$instance_id" "$trust_anchor"
  render_runtime_config "$temporary_root/$fixture_name-runtime-test.yaml" \
    "$database_id" "secret:file/$runtime_secret" "secret:file/$migration_secret" \
    "$source_revision" "$instance_id" "$migration_role" "$runtime_role" "$trust_anchor"

  printf 'running change-request fixture: %s\n' "$fixture_name"
  "$registry_serverctl" check "$project_path" >/dev/null
  if ! "$registry_serverctl" --format json test "$project_path" \
    --database-id "$database_id" \
    --signature-threshold 1 \
    --signature-key-id change-request-example-package-key \
    --runtime-config "$temporary_root/$fixture_name-runtime-test.yaml" \
    --credentials "$credentials" \
    --output "$receipt" >"$report"; then
    print_json_diagnostics "$report" test
    return 1
  fi
  assert_json_ok "$report" test
  python3 - "$report" "$expected_journey" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
expected = sys.argv[2]
if expected not in report.get("successfulJourneyIds", []):
    raise SystemExit(f"{expected} was not reported as successful")
PY
  printf 'change-request fixture passed: %s\n' "$fixture_name"
}

require_tool cargo
require_tool openssl
require_tool psql
require_tool python3
asset_project=$(normalize_project asset "$asset_project")
household_project=$(normalize_project household "$household_project")

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"
export SSL_CERT_FILE="$REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH"

temporary_root=$(mktemp -d "$repository_root/.registry-server-cr-examples.XXXXXX")
case "$temporary_root" in
  "$repository_root"/.registry-server-cr-examples.*) ;;
  *)
    printf '%s\n' 'change-request example temp directory escaped its owned location.' >&2
    exit 1
    ;;
esac
umask 077
mkdir -p "$temporary_root/secrets" "$temporary_root/empty-package-root"
chmod 700 "$temporary_root/secrets"
printf '%s' '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' >"$temporary_root/secrets/audit-key"
printf '%s' 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789' >"$temporary_root/secrets/cursor-key"

suffix=$(python3 - <<'PY'
import secrets
print(secrets.token_hex(4))
PY
)
migration_role="rs_cr_migration_$suffix"
runtime_role="rs_cr_runtime_$suffix"
role_password=$(python3 - <<'PY'
import secrets
print(secrets.token_hex(18))
PY
)
psql "$REGISTRY_SERVER_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -q \
  -c "CREATE ROLE \"$migration_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$role_password';" \
  -c "CREATE ROLE \"$runtime_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$role_password';" >/dev/null
created_roles+=("$runtime_role" "$migration_role")

openssl genpkey -algorithm ED25519 -out "$temporary_root/oidc-signer.pem" >/dev/null 2>&1
openssl genpkey -algorithm ED25519 -out "$temporary_root/package-signer.pem" >/dev/null 2>&1
chmod 600 "$temporary_root/oidc-signer.pem" "$temporary_root/package-signer.pem"
write_public_jwk "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "$temporary_root/oidc-signer.public.jwk"
write_public_jwk "$temporary_root/package-signer.pem" "change-request-example-package-key" "$temporary_root/package-signer.public.jwk"
package_public_jwk="$temporary_root/package-signer.public.jwk"
write_jwks "$temporary_root/oidc-signer.public.jwk" "$temporary_root/secrets/oidc-jwks"
chmod 600 "$temporary_root/secrets/oidc-jwks"

write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "asset-operator" "asset-management" "" "$temporary_root/secrets/asset-operator-token"
write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "correction-submitter" "asset-correction" "registry:corrections:submit" "$temporary_root/secrets/correction-submitter-token"
write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "correction-reviewer" "asset-correction-review" "registry:corrections:review" "$temporary_root/secrets/correction-reviewer-token"
write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "correction-supervisor" "asset-correction-review" "registry:corrections:supervise" "$temporary_root/secrets/correction-supervisor-token"
write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "correction-applier" "asset-correction-apply" "registry:corrections:apply" "$temporary_root/secrets/correction-applier-token"
write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "household-operator" "household-administration" "registry:household:operate" "$temporary_root/secrets/household-operator-token"
write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "household-contact-submitter" "household-contact-registration" "registry:household-contact:submit" "$temporary_root/secrets/household-contact-submitter-token"
write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "household-contact-reviewer" "household-contact-review" "registry:household-contact:review" "$temporary_root/secrets/household-contact-reviewer-token"
write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "household-contact-supervisor" "household-contact-review" "registry:household-contact:supervise" "$temporary_root/secrets/household-contact-supervisor-token"
write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "household-contact-applier" "household-contact-apply" "registry:household-contact:apply" "$temporary_root/secrets/household-contact-applier-token"

asset_credentials="$temporary_root/asset-site-placement-change-requests-credentials.yaml"
household_credentials="$temporary_root/publicschema-household-change-requests-credentials.yaml"
write_credentials_from_project "$asset_project" "$asset_credentials" \
  asset-operator=asset-operator-token \
  correction-submitter=correction-submitter-token \
  correction-reviewer=correction-reviewer-token \
  correction-supervisor=correction-supervisor-token \
  correction-applier=correction-applier-token
write_credentials_from_project "$household_project" "$household_credentials" \
  household-operator=household-operator-token \
  household-contact-submitter=household-contact-submitter-token \
  household-contact-reviewer=household-contact-reviewer-token \
  household-contact-supervisor=household-contact-supervisor-token \
  household-contact-applier=household-contact-applier-token
chmod 600 "$asset_credentials" "$household_credentials"

cargo build --manifest-path "$repository_root/Cargo.toml" --locked \
  -p registry-serverctl \
  -p registry-server \
  --features registry-server/runtime >/dev/null

run_fixture \
  asset-site-placement-change-requests \
  "$asset_project" \
  "rs_cr_asset_$suffix" \
  asset-site-placement-change-requests-local-db \
  asset-runtime-url \
  asset-migration-url \
  asset-site-placement-change-requests-acceptance-0.1.0 \
  asset-site-placement-change-requests-acceptance \
  "$asset_credentials" \
  placement-correction-request-flow

run_fixture \
  publicschema-household-change-requests \
  "$household_project" \
  "rs_cr_household_$suffix" \
  publicschema-household-change-requests-local-db \
  household-runtime-url \
  household-migration-url \
  publicschema-household-change-requests-acceptance-0.1.0 \
  publicschema-household-change-requests-acceptance \
  "$household_credentials" \
  household-contact-registration-request-flow
