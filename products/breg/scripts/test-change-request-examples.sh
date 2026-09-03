#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository_root=$(cd -- "$script_dir/../../.." && pwd -P)
bregctl="$repository_root/target/debug/bregctl"
temporary_root=""
created_databases=()
created_roles=()
mode="change-request"
asset_project=""
household_project=""
rhai_project=""
installed=false

usage() {
  cat >&2 <<'USAGE'
usage: products/breg/scripts/test-change-request-examples.sh [--installed] [--env FILE] [--asset-project DIR] [--household-project DIR] [--rhai-project DIR] [--mode change-request|immediate-actions]

Runs the Base Registry Engine change-request example fixtures through bregctl test.
Use --mode immediate-actions to run the immediate-action fixtures through the same closed harness.
Set BREG_TEST_DATABASE_URL and BREG_TEST_TLS_CA_PEM_PATH, or pass --env FILE.
Requires Python 3 with PyYAML. Use a project override to run a disposable edited copy instead of the committed fixture.
With --installed, the runner uses the breg and bregctl found on PATH instead of building them,
which is how a released install runs it.
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
    --rhai-project)
      if [[ $# -lt 2 ]]; then
        usage
        exit 2
      fi
      rhai_project=$2
      shift 2
      ;;
    --mode)
      if [[ $# -lt 2 ]]; then
        usage
        exit 2
      fi
      case "$2" in
        change-request|immediate-actions)
          mode=$2
          ;;
        *)
          usage
          exit 2
          ;;
      esac
      shift 2
      ;;
    --installed)
      if [[ "$installed" == true ]]; then
        printf '%s\n' 'the --installed option may be supplied only once.' >&2
        exit 2
      fi
      installed=true
      shift
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

case "$mode" in
  change-request)
    run_label="change-request"
    temp_slug="cr"
    role_slug="cr"
    default_asset_project="$repository_root/products/breg/acceptance/asset-site-placement-change-requests"
    default_household_project="$repository_root/products/breg/acceptance/publicschema-household-change-requests"
    default_rhai_project="$repository_root/products/breg/acceptance/person-name-change-rhai"
    ;;
  immediate-actions)
    if [[ -n "$rhai_project" ]]; then
      usage
      exit 2
    fi
    run_label="immediate-action"
    temp_slug="ia"
    role_slug="ia"
    default_asset_project="$repository_root/products/breg/fixtures/asset-registration-actions"
    default_household_project="$repository_root/products/breg/fixtures/household-contact-actions"
    ;;
esac

asset_project="${asset_project:-$default_asset_project}"
household_project="${household_project:-$default_household_project}"
if [[ "$mode" == "change-request" ]]; then
  rhai_project="${rhai_project:-$default_rhai_project}"
fi

if [[ -n "${env_file:-}" ]]; then
  if [[ ! -f "$env_file" || -L "$env_file" ]]; then
    printf '%s\n' "$run_label env file is unavailable or unsafe." >&2
    exit 1
  fi
  source "$env_file"
fi

if [[ -z "${BREG_TEST_DATABASE_URL:-}" ]]; then
  printf '%s\n' 'BREG_TEST_DATABASE_URL is required.' >&2
  exit 1
fi
if [[ -z "${BREG_TEST_TLS_CA_PEM_PATH:-}" || ! -f "$BREG_TEST_TLS_CA_PEM_PATH" ]]; then
  printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH is required.' >&2
  exit 1
fi

cleanup() {
  local database
  local role
  for database in "${created_databases[@]:-}"; do
    psql_admin -v ON_ERROR_STOP=0 -q \
      -c "DROP DATABASE IF EXISTS \"$database\" WITH (FORCE);" >/dev/null 2>&1 || true
  done
  for role in "${created_roles[@]:-}"; do
    psql_admin -v ON_ERROR_STOP=0 -q \
      -c "DROP ROLE IF EXISTS \"$role\";" >/dev/null 2>&1 || true
  done
  case "$temporary_root" in
    "$repository_root"/.breg-cr-examples.*|"$repository_root"/.breg-ia-examples.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    "") ;;
    *)
      printf '%s\n' "$run_label example temp directory escaped its owned location." >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "$1 is required for $run_label example tests." >&2
    exit 1
  fi
}

resolve_installed_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "$1 is required for $run_label example tests in --installed mode; $2." >&2
    exit 2
  fi
  command -v "$1"
}

psql_admin() {
  psql_database "$BREG_TEST_DATABASE_URL" "$@"
}

psql_database() {
  local database_url=$1
  shift
  # libpq does not expand a URL supplied through PGDATABASE. Decode it into
  # native connection variables so credentials never enter the process argv.
  BREG_EXAMPLE_PSQL_URL="$database_url" python3 -c '
import os
import sys
from urllib.parse import parse_qsl, unquote, urlsplit

environment = dict(os.environ)
url = urlsplit(environment.pop("BREG_EXAMPLE_PSQL_URL"))
if url.scheme not in {"postgres", "postgresql"} or not url.hostname:
    raise SystemExit("the example database connection must be a PostgreSQL URL")
environment["PGHOST"] = url.hostname
environment["PGPORT"] = str(url.port or 5432)
environment["PGDATABASE"] = unquote(url.path.removeprefix("/"))
if url.username is not None:
    environment["PGUSER"] = unquote(url.username)
if url.password is not None:
    environment["PGPASSWORD"] = unquote(url.password)
query_variables = {
    "application_name": "PGAPPNAME",
    "channel_binding": "PGCHANNELBINDING",
    "connect_timeout": "PGCONNECT_TIMEOUT",
    "hostaddr": "PGHOSTADDR",
    "options": "PGOPTIONS",
    "sslmode": "PGSSLMODE",
    "sslrootcert": "PGSSLROOTCERT",
    "sslcert": "PGSSLCERT",
    "sslkey": "PGSSLKEY",
    "sslcrl": "PGSSLCRL",
    "sslcrldir": "PGSSLCRLDIR",
    "ssl_min_protocol_version": "PGSSLMINPROTOCOLVERSION",
    "ssl_max_protocol_version": "PGSSLMAXPROTOCOLVERSION",
    "target_session_attrs": "PGTARGETSESSIONATTRS",
}
for name, value in parse_qsl(url.query, keep_blank_values=True):
    variable = query_variables.get(name)
    if variable is None:
        raise SystemExit("the example database URL contains an unsupported connection parameter")
    environment[variable] = value
os.execvpe("psql", ["psql", *sys.argv[1:]], environment)
' "$@"
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
    print(f"bregctl {sys.argv[2]} failed before writing a JSON report", file=sys.stderr)
    raise SystemExit(0)
diagnostics = value.get("diagnostics", [])
if not diagnostics:
    print(f"bregctl {sys.argv[2]} refused; diagnostics: unavailable", file=sys.stderr)
else:
    print(f"bregctl {sys.argv[2]} refused; diagnostics:", file=sys.stderr)
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
  local package_environment=$3
  local instance_id=$4
  local output=$5
  python3 - "$public_jwk" "$database_id" "$package_environment" "$instance_id" "$output" <<'PY'
import json
import sys
jwk = json.load(open(sys.argv[1], encoding="utf-8"))
anchor = {
    "apiVersion": "registry.registrystack.org/package-trust/v1",
    "databaseId": sys.argv[2],
    "environment": sys.argv[3],
    "instanceId": sys.argv[4],
    "keys": [{"jwk": jwk, "keyId": jwk["kid"]}],
    "threshold": 1,
}
open(sys.argv[5], "w", encoding="utf-8").write(json.dumps(anchor, sort_keys=True, separators=(",", ":")))
PY
}

write_jwt() {
  local private_key=$1
  local key_id=$2
  local principal=$3
  local purpose=$4
  local scopes=$5
  local output=$6
  local direct_claims=${7:-"{}"}
  python3 - "$key_id" "$principal" "$purpose" "$scopes" "$direct_claims" "$output.signing-input" <<'PY'
import base64
import json
import sys
import time

def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=").decode("ascii")

now = int(time.time())
claims = {
    "aud": "urn:breg:change-request-example",
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
direct_claims = json.loads(sys.argv[5])
if not isinstance(direct_claims, dict):
    raise SystemExit("direct claims must be a JSON object")
for name, value in direct_claims.items():
    if name in claims:
        raise SystemExit("direct claim collides with a registered claim")
    claims[name] = value
header = {"alg": "EdDSA", "kid": sys.argv[1], "typ": "JWT"}
open(sys.argv[6], "w", encoding="ascii").write(f"{b64(header)}.{b64(claims)}")
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
  local password_file=$4
  python3 - "$database" "$migration_role" "$runtime_role" "$password_file" <<'PY'
import os
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit
admin = urlsplit(os.environ.get("BREG_TEST_DATABASE_URL", ""))
database, migration_role, runtime_role, password_file = sys.argv[1:]
password = Path(password_file).read_text(encoding="utf-8")
if admin.scheme not in {"postgres", "postgresql"} or not admin.hostname:
    raise SystemExit("BREG_TEST_DATABASE_URL must be a PostgreSQL URL")
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
  python3 - "$database" <<'PY'
import os
import sys
from urllib.parse import quote, urlsplit, urlunsplit
admin = urlsplit(os.environ.get("BREG_TEST_DATABASE_URL", ""))
if admin.scheme not in {"postgres", "postgresql"} or not admin.hostname:
    raise SystemExit("BREG_TEST_DATABASE_URL must be a PostgreSQL URL")
print(urlunsplit((admin.scheme, admin.netloc, f"/{quote(sys.argv[1], safe='')}", admin.query, "")))
PY
}

provision_database() {
  local database=$1
  local migration_role=$2
  local runtime_role=$3
  local db_admin
  db_admin=$(admin_database_url "$database")
  psql_admin -v ON_ERROR_STOP=1 -q \
    -c "CREATE DATABASE \"$database\";" >/dev/null
  created_databases+=("$database")
  psql_database "$db_admin" -v ON_ERROR_STOP=1 -q \
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
  local package_environment=$3
  local runtime_ref=$4
  local migration_ref=$5
  local source_revision=$6
  local instance_id=$7
  local migration_role=$8
  local runtime_role=$9
  local trust_anchor=${10}
  cat >"$output" <<EOF_RUNTIME
apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:0
identity:
  environment: $package_environment
  instanceId: $instance_id
  databaseId: $database_id
  databaseInitializationEnvironment: $package_environment
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
    audience: urn:breg:change-request-example
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

read_project_package_identity() {
  local project=$1
  python3 - "$project/registry.yaml" <<'PY'
import sys
from pathlib import Path
try:
    import yaml
except ImportError as error:
    raise SystemExit("PyYAML is required for project package identity extraction") from error
path = Path(sys.argv[1])
with path.open(encoding="utf-8") as handle:
    document = yaml.safe_load(handle)
if not isinstance(document, dict):
    raise SystemExit("project registry.yaml is malformed")
package = document.get("package")
if not isinstance(package, dict):
    raise SystemExit("project package block is missing")
for key in ("environment", "instanceId", "sourceRevision"):
    value = package.get(key)
    if not isinstance(value, str) or not value:
        raise SystemExit(f"project package.{key} is missing")
    print(value)
PY
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
step_tokens = {}
for value in sys.argv[3:]:
    if "=" not in value:
        raise SystemExit("credential profile mapping is malformed")
    selector, token = value.split("=", 1)
    if not selector or not token:
        raise SystemExit("credential profile mapping is incomplete")
    if "." in selector:
        step_tokens[selector] = token
    else:
        profile_tokens[selector] = token

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
        token = step_tokens.get(f"{journey_id}.{step_id}", profile_tokens.get(profile))
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
    "apiVersion": "registry.registrystack.org/breg-schema-test-credentials/v1",
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
  local package_environment=$7
  local source_revision=$8
  local instance_id=$9
  local credentials=${10}
  local expected_journeys=${11}
  local urls
  local migration_url
  local runtime_url
  local report="$temporary_root/$fixture_name-report.json"
  local receipt="$temporary_root/$fixture_name-receipt.json"

  urls=$(derive_urls "$database" "$migration_role" "$runtime_role" "$role_password_file")
  migration_url=$(printf '%s\n' "$urls" | sed -n '1p')
  runtime_url=$(printf '%s\n' "$urls" | sed -n '2p')
  printf '%s' "$runtime_url" >"$temporary_root/secrets/$runtime_secret"
  printf '%s' "$migration_url" >"$temporary_root/secrets/$migration_secret"
  chmod 600 "$temporary_root/secrets/$runtime_secret" "$temporary_root/secrets/$migration_secret"

  provision_database "$database" "$migration_role" "$runtime_role"
  local trust_anchor="$temporary_root/$fixture_name-trust-anchor.json"
  write_trust_anchor "$package_public_jwk" "$database_id" "$package_environment" "$instance_id" "$trust_anchor"
  render_runtime_config "$temporary_root/$fixture_name-runtime-test.yaml" \
    "$database_id" "$package_environment" "secret:file/$runtime_secret" "secret:file/$migration_secret" \
    "$source_revision" "$instance_id" "$migration_role" "$runtime_role" "$trust_anchor"

  printf 'running %s fixture: %s\n' "$run_label" "$fixture_name"
  "$bregctl" check "$project_path" >/dev/null
  if ! "$bregctl" --format json test "$project_path" \
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
  python3 - "$report" "$expected_journeys" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
successful = set(report.get("successfulJourneyIds", []))
for expected in sys.argv[2].split(","):
    if expected not in successful:
        raise SystemExit(f"{expected} was not reported as successful")
PY
  printf '%s fixture passed: %s\n' "$run_label" "$fixture_name"
}

if [[ "$installed" == true ]]; then
  breg=$(resolve_installed_command breg 'breg-install.sh provides breg and bregctl')
  bregctl=$(resolve_installed_command bregctl 'breg-install.sh provides breg and bregctl')
  printf '%s\n' '== Using installed breg and bregctl from PATH'
  printf '%s\n' "$breg"
  printf '%s\n' "$bregctl"
else
  require_tool cargo
fi
require_tool openssl
require_tool psql
require_tool python3
asset_project=$(normalize_project asset "$asset_project")
household_project=$(normalize_project household "$household_project")
if [[ "$mode" == "change-request" ]]; then
  rhai_project=$(normalize_project rhai "$rhai_project")
fi

if [[ "$installed" != true ]]; then
  export CARGO_INCREMENTAL=0
  export CARGO_PROFILE_DEV_DEBUG=0
  export CARGO_PROFILE_TEST_DEBUG=0
  export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"
fi
export SSL_CERT_FILE="$BREG_TEST_TLS_CA_PEM_PATH"

temporary_root=$(mktemp -d "$repository_root/.breg-$temp_slug-examples.XXXXXX")
case "$temporary_root" in
  "$repository_root"/.breg-cr-examples.*|"$repository_root"/.breg-ia-examples.*) ;;
  *)
    printf '%s\n' "$run_label example temp directory escaped its owned location." >&2
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
migration_role="breg_${role_slug}_migration_$suffix"
runtime_role="breg_${role_slug}_runtime_$suffix"
role_password_file="$temporary_root/secrets/database-role-password"
python3 - "$role_password_file" <<'PY'
import secrets
import sys
from pathlib import Path
Path(sys.argv[1]).write_text(secrets.token_hex(18), encoding="utf-8")
PY
chmod 600 "$role_password_file"
role_password=$(cat "$role_password_file")
psql_admin -v ON_ERROR_STOP=1 -q >/dev/null <<EOF_SQL
CREATE ROLE "$migration_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$role_password';
CREATE ROLE "$runtime_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$role_password';
EOF_SQL
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
case "$mode" in
  change-request)
    write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "synthetic-person-operator" "person-maintenance" "" "$temporary_root/secrets/person-operator-token"
    write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "synthetic-name-change-submitter" "person-name-change" "registry:person-name:submit" "$temporary_root/secrets/name-change-submitter-token"
    write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "synthetic-assisted-applier" "person-name-apply" "registry:person-name:apply-assisted" "$temporary_root/secrets/assisted-applier-token"
    write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "synthetic-unauthorized-applier" "person-name-apply" "" "$temporary_root/secrets/unauthorized-assisted-applier-token"
    asset_fixture_name=asset-site-placement-change-requests
    household_fixture_name=publicschema-household-change-requests
    rhai_fixture_name=person-name-change-rhai
    asset_database="breg_cr_asset_$suffix"
    household_database="breg_cr_household_$suffix"
    rhai_database="breg_cr_rhai_$suffix"
    asset_database_id=asset-site-placement-change-requests-local-db
    household_database_id=publicschema-household-change-requests-local-db
    rhai_database_id=person-name-change-rhai-local-db
    asset_runtime_secret=asset-runtime-url
    asset_migration_secret=asset-migration-url
    household_runtime_secret=household-runtime-url
    household_migration_secret=household-migration-url
    rhai_runtime_secret=rhai-runtime-url
    rhai_migration_secret=rhai-migration-url
    asset_expected_journeys=placement-correction-request-flow
    household_expected_journeys=household-contact-registration-request-flow
    rhai_expected_journeys=person-name-change-rhai-flow
    asset_credentials="$temporary_root/asset-site-placement-change-requests-credentials.yaml"
    household_credentials="$temporary_root/publicschema-household-change-requests-credentials.yaml"
    rhai_credentials="$temporary_root/person-name-change-rhai-credentials.yaml"
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
    write_credentials_from_project "$rhai_project" "$rhai_credentials" \
      person-operator=person-operator-token \
      name-change-submitter=name-change-submitter-token \
      assisted-applier=assisted-applier-token \
      person-name-change-rhai-flow.caller-without-apply-scope-cannot-list-work-queue=unauthorized-assisted-applier-token
    ;;
  immediate-actions)
    write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "synthetic-asset-registrar" "asset-registration" "registry:asset:register" "$temporary_root/secrets/asset-action-registrar-token" '{"jurisdiction":"north-district"}'
    write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "synthetic-contact-registrar" "contact-registration" "registry:contact:register" "$temporary_root/secrets/contact-registrar-token" '{"district":"north-district"}'
    write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "synthetic-household-operator" "household-administration" "registry:household:operate" "$temporary_root/secrets/household-operator-north-token" '{"district":"north-district"}'
    write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "synthetic-household-operator" "household-administration" "registry:household:operate" "$temporary_root/secrets/household-operator-south-token" '{"district":"south-district"}'
    write_jwt "$temporary_root/oidc-signer.pem" "change-request-example-oidc-key" "synthetic-household-maintainer" "household-maintenance" "registry:household:maintain" "$temporary_root/secrets/household-maintainer-token" '{"district":"north-district"}'
    asset_fixture_name=asset-registration-actions
    household_fixture_name=household-contact-actions
    asset_database="breg_ia_asset_$suffix"
    household_database="breg_ia_household_$suffix"
    asset_database_id=asset-registration-actions-local-db
    household_database_id=household-contact-actions-local-db
    asset_runtime_secret=asset-action-runtime-url
    asset_migration_secret=asset-action-migration-url
    household_runtime_secret=household-action-runtime-url
    household_migration_secret=household-action-migration-url
    asset_expected_journeys=create-asset-and-initial-inspection
    household_expected_journeys=action-only-household-contact-registration,link-only-target-authority-is-still-enforced
    asset_credentials="$temporary_root/asset-registration-actions-credentials.yaml"
    household_credentials="$temporary_root/household-contact-actions-credentials.yaml"
    write_credentials_from_project "$asset_project" "$asset_credentials" \
      asset-action-registrar=asset-action-registrar-token
    write_credentials_from_project "$household_project" "$household_credentials" \
      household-operator=household-operator-north-token \
      household-maintainer=household-maintainer-token \
      contact-registrar=contact-registrar-token \
      link-only-target-authority-is-still-enforced.create-south-service-center=household-operator-south-token
    ;;
esac
asset_package_identity=$(read_project_package_identity "$asset_project")
household_package_identity=$(read_project_package_identity "$household_project")
if [[ "$mode" == "change-request" ]]; then
  rhai_package_identity=$(read_project_package_identity "$rhai_project")
fi
asset_package_environment=$(printf '%s\n' "$asset_package_identity" | sed -n '1p')
asset_instance_id=$(printf '%s\n' "$asset_package_identity" | sed -n '2p')
asset_source_revision=$(printf '%s\n' "$asset_package_identity" | sed -n '3p')
household_package_environment=$(printf '%s\n' "$household_package_identity" | sed -n '1p')
household_instance_id=$(printf '%s\n' "$household_package_identity" | sed -n '2p')
household_source_revision=$(printf '%s\n' "$household_package_identity" | sed -n '3p')
chmod 600 "$asset_credentials" "$household_credentials"
if [[ "$mode" == "change-request" ]]; then
  rhai_package_environment=$(printf '%s\n' "$rhai_package_identity" | sed -n '1p')
  rhai_instance_id=$(printf '%s\n' "$rhai_package_identity" | sed -n '2p')
  rhai_source_revision=$(printf '%s\n' "$rhai_package_identity" | sed -n '3p')
  chmod 600 "$rhai_credentials"
fi

if [[ "$installed" != true ]]; then
  cargo build --manifest-path "$repository_root/Cargo.toml" --locked \
    -p registry-bregctl \
    -p registry-breg \
    --features registry-breg/runtime >/dev/null
fi

run_fixture \
  "$asset_fixture_name" \
  "$asset_project" \
  "$asset_database" \
  "$asset_database_id" \
  "$asset_runtime_secret" \
  "$asset_migration_secret" \
  "$asset_package_environment" \
  "$asset_source_revision" \
  "$asset_instance_id" \
  "$asset_credentials" \
  "$asset_expected_journeys"

run_fixture \
  "$household_fixture_name" \
  "$household_project" \
  "$household_database" \
  "$household_database_id" \
  "$household_runtime_secret" \
  "$household_migration_secret" \
  "$household_package_environment" \
  "$household_source_revision" \
  "$household_instance_id" \
  "$household_credentials" \
  "$household_expected_journeys"

if [[ "$mode" == "change-request" ]]; then
  run_fixture \
    "$rhai_fixture_name" \
    "$rhai_project" \
    "$rhai_database" \
    "$rhai_database_id" \
    "$rhai_runtime_secret" \
    "$rhai_migration_secret" \
    "$rhai_package_environment" \
    "$rhai_source_revision" \
    "$rhai_instance_id" \
    "$rhai_credentials" \
    "$rhai_expected_journeys"
fi
