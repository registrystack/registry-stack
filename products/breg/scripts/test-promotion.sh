#!/usr/bin/env bash
set -euo pipefail

# Promotes one package through two environments with the public binaries: the
# package is built and schema-tested once, then planned, applied, and served
# in staging and in production, whose runtime files differ only in their
# environment values. A reviewed destructive successor follows with one backup
# binding per environment, and the refusals a promotion must hold close the
# run: an older package, a swapped package directory, and a staging runtime
# file pointed at the production database.

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
. "$repository_root/scripts/cargo-runtime-library-path.sh"
temporary_root=""
breg_pids=()
promotion_admin_url=""
promotion_migration_role=""
promotion_runtime_role=""
promotion_databases=()

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "$1 is required for the promotion workflow." >&2
    exit 2
  fi
}

checkpoint() {
  printf 'promotion workflow: %s\n' "$1" >&2
}

stop_servers() {
  local pid
  for pid in "${breg_pids[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  done
  breg_pids=()
}

cleanup() {
  stop_servers
  if [[ "${BREG_PROMOTION_KEEP_TEMP:-0}" == "1" ]]; then
    printf '%s\n' "promotion workflow preserved temporary root and databases: $temporary_root" >&2
    return 0
  fi
  local database
  for database in "${promotion_databases[@]}"; do
    psql "$promotion_admin_url" -v ON_ERROR_STOP=1 -q \
      -c "DROP DATABASE IF EXISTS \"$database\" WITH (FORCE);" >/dev/null 2>&1 || true
  done
  if [[ -n "$promotion_migration_role" && -n "$promotion_runtime_role" ]]; then
    psql "$promotion_admin_url" -v ON_ERROR_STOP=1 -q \
      -c "DROP ROLE IF EXISTS \"$promotion_runtime_role\"; DROP ROLE IF EXISTS \"$promotion_migration_role\";" >/dev/null 2>&1 || true
  fi
  case "$temporary_root" in
    "$repository_root"/.breg-promotion.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    "") ;;
    *)
      printf '%s\n' 'promotion workflow temporary directory did not match its validated location' >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

require_command openssl
require_command psql
require_command python3

if [[ -z "${BREG_TEST_DATABASE_URL:-}" ]]; then
  printf '%s\n' 'BREG_TEST_DATABASE_URL must be set for the promotion workflow.' >&2
  exit 2
fi
if [[ -z "${BREG_TEST_TLS_CA_PEM_PATH:-}" ]]; then
  printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH must be set for the promotion workflow after the PostgreSQL TLS proof.' >&2
  exit 2
fi
case "$BREG_TEST_TLS_CA_PEM_PATH" in
  /*) ;;
  *)
    printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH must be an absolute file path.' >&2
    exit 2
    ;;
esac
if [[ -L "$BREG_TEST_TLS_CA_PEM_PATH" || ! -s "$BREG_TEST_TLS_CA_PEM_PATH" ]]; then
  printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH must name a non-empty regular file.' >&2
  exit 2
fi
openssl x509 -in "$BREG_TEST_TLS_CA_PEM_PATH" -noout >/dev/null 2>&1 || {
  printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH must contain a PEM certificate.' >&2
  exit 2
}

umask 077
checkpoint "preparing disposable TLS PostgreSQL resources and local credentials"
temporary_root=$(mktemp -d "$repository_root/.breg-promotion.XXXXXX")
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

bregctl=${BREGCTL_BIN:-"$repository_root/target/debug/bregctl"}
breg=${BREG_BIN:-"$repository_root/target/debug/breg"}

if [[ "${BREG_SKIP_BUILD:-0}" != "1" ]]; then
  registry_cargo_build "$repository_root" \
    --manifest-path "$repository_root/Cargo.toml" --locked \
    -p registry-bregctl \
    -p registry-breg \
    --features registry-breg/runtime
else
  registry_prepare_cargo_runtime "$repository_root" \
    --manifest-path "$repository_root/Cargo.toml" --locked \
    -p registry-bregctl \
    -p registry-breg \
    --features registry-breg/runtime
fi
for binary in "$bregctl" "$breg"; do
  if [[ ! -x "$binary" ]]; then
    printf 'candidate BReg binary is not executable: %s\n' "$binary" >&2
    exit 2
  fi
done
export SSL_CERT_FILE="$BREG_TEST_TLS_CA_PEM_PATH"

json_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[int(part)] if isinstance(value, list) else value[part]
print(value)
PY
}

# Runs one bregctl command with a JSON report and names the refusal codes on
# failure. The report never carries a credential or a connection URL.
run_json() {
  local output=$1
  local status
  shift
  if "$bregctl" --format json "$@" >"$output"; then
    return 0
  else
    status=$?
  fi
  python3 - "$output" "$1" <<'PY' >&2
import json
import sys
try:
    document = json.load(open(sys.argv[1], encoding="utf-8"))
    diagnostics = [f"{item.get('code')}: {item.get('message')}"
                   for item in document.get("diagnostics", []) if item.get("code")]
except Exception:
    diagnostics = []
print(f"bregctl {sys.argv[2]} refused; diagnostics: {'; '.join(diagnostics) or 'unavailable'}")
PY
  return "$status"
}

assert_json_ok() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
if document.get("ok") is not True or document.get("command") != sys.argv[2]:
    raise SystemExit(f"{sys.argv[2]} did not complete")
PY
}

# Runs a command that must refuse, and asserts the exit status and that the
# report names the expected diagnostic code.
expect_refusal() {
  local output=$1
  local expected_code=$2
  local status=0
  shift 2
  "$bregctl" --format json "$@" >"$output" || status=$?
  if [[ "$status" != 1 ]]; then
    printf 'bregctl %s exited %s where a refusal (1) with %s was required.\n' "$1" "$status" "$expected_code" >&2
    exit 1
  fi
  python3 - "$output" "$expected_code" <<'PY'
import json
import sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
codes = [item.get("code") for item in document.get("diagnostics", [])]
if document.get("ok") is not False or sys.argv[2] not in codes:
    raise SystemExit(f"expected refusal {sys.argv[2]}, got {codes}")
PY
}

derive_database_url() {
  local database=$1
  local role=${2:-}
  python3 - "$BREG_TEST_DATABASE_URL" "$database" "$role" "$promotion_password" <<'PY'
import sys
from urllib.parse import quote, urlsplit, urlunsplit
admin = urlsplit(sys.argv[1])
database, role, password = sys.argv[2:]
if admin.scheme not in {"postgres", "postgresql"} or not admin.hostname:
    raise SystemExit("BREG_TEST_DATABASE_URL must be a PostgreSQL URL")
netloc = admin.netloc
if role:
    host = admin.hostname if admin.port is None else f"{admin.hostname}:{admin.port}"
    netloc = f"{quote(role, safe='')}:{quote(password, safe='')}@{host}"
print(urlunsplit((admin.scheme, netloc, f"/{quote(database, safe='')}", admin.query, "")))
PY
}

provision_database() {
  local database=$1
  local secret_prefix=$2
  local admin_database_url
  promotion_databases+=("$database")
  psql "$promotion_admin_url" -v ON_ERROR_STOP=1 -q -c "CREATE DATABASE \"$database\";"
  admin_database_url=$(derive_database_url "$database")
  psql "$admin_database_url" -v ON_ERROR_STOP=1 -q \
    -c "CREATE EXTENSION IF NOT EXISTS btree_gist;" \
    -c "REVOKE ALL ON DATABASE \"$database\" FROM PUBLIC;" \
    -c "GRANT CONNECT ON DATABASE \"$database\" TO \"$promotion_migration_role\", \"$promotion_runtime_role\";" \
    -c "CREATE SCHEMA registry_internal AUTHORIZATION \"$promotion_migration_role\";" \
    -c "CREATE SCHEMA registry_data AUTHORIZATION \"$promotion_migration_role\";" \
    -c "CREATE SCHEMA registry_source AUTHORIZATION \"$promotion_migration_role\";" \
    -c "CREATE SCHEMA registry_derived AUTHORIZATION \"$promotion_migration_role\";" \
    -c "CREATE SCHEMA registry_context AUTHORIZATION \"$promotion_migration_role\";" \
    -c "REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context FROM PUBLIC;" >/dev/null
  printf '%s' "$(derive_database_url "$database" "$promotion_migration_role")" >"$temporary_root/secrets/$secret_prefix-migration-url"
  printf '%s' "$(derive_database_url "$database" "$promotion_runtime_role")" >"$temporary_root/secrets/$secret_prefix-runtime-url"
}

# A digest of the managed schemas' catalog, used to prove a refusal changed
# nothing. It reads catalog metadata only, never a record.
catalog_digest() {
  psql "$(derive_database_url "$1")" -v ON_ERROR_STOP=1 -Atqc "
    SELECT md5(coalesce(string_agg(entry, ',' ORDER BY entry), ''))
    FROM (
      SELECT table_schema || '.' || table_name || '.' || column_name || ':' || data_type AS entry
      FROM information_schema.columns
      WHERE table_schema LIKE 'registry\\_%'
      UNION ALL
      SELECT 'ledger:' || count(*)::text FROM registry_internal.registry_migrations
    ) AS catalog"
}

select_free_listener() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(f"127.0.0.1:{sock.getsockname()[1]}")
PY
}

# Writes one runtime file. Staging and production pass different environment
# values; every other line is the same for both.
render_runtime_config() {
  local output=$1
  local environment=$2
  local database_prefix=$3
  local package_root=$4
  local listener=$5
  cat >"$output" <<EOF
apiVersion: id.registrystack.org/formats/breg/runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: $listener
identity:
  environment: $environment
  instanceId: generic-registry-$environment
  databaseId: generic-registry-$environment-db
  databaseInitializationEnvironment: $environment
secretProviders:
  file:
    root: $temporary_root/secrets
database:
  runtimeUrlRef: secret:file/$database_prefix-runtime-url
  migrationUrlRef: secret:file/$database_prefix-migration-url
  pool:
    maximumConnections: 4
  roles:
    migration: $promotion_migration_role
    runtime: $promotion_runtime_role
package:
  root: $package_root
authentication:
  oidc:
    issuer: https://issuer.example.invalid
    audience: generic-registry
    allowedAlgorithm: EdDSA
    accessTokenType: at+jwt
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [generic-registry-client]
    maximumTokenLifetimeSeconds: 3600
    leewayMilliseconds: 30000
    jwksSource:
      type: static
      documentRef: secret:file/issuer-jwks
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:file/audit-key
  destination: file
  path: $temporary_root/audit-$environment/breg.jsonl
cursor:
  secretRef: secret:file/cursor-key
EOF
}

issue_token() {
  local principal=$1
  local scope=$2
  local purpose=$3
  local output=$4
  local extra=${5:-}
  python3 - "$principal" "$scope" "$purpose" "$extra" "$output.signing-input" <<'PY'
import base64
import json
import sys
import time

def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=").decode("ascii")

principal, scope, purpose, extra, output = sys.argv[1:]
now = int(time.time())
claims = {
    "aud": "generic-registry", "client_id": "generic-registry-client", "exp": now + 3600,
    "iat": now, "iss": "https://issuer.example.invalid", "registry_actor_kind": "service",
    "registry_principal": principal, "registry_purpose": purpose, "scope": scope, "sub": principal,
}
claims.update(json.loads(extra or "{}"))
header = {"alg": "EdDSA", "kid": "promotion-issuer", "typ": "at+jwt"}
open(output, "w", encoding="ascii").write(f"{b64(header)}.{b64(claims)}")
PY
  openssl pkeyutl -sign -rawin -inkey "$temporary_root/issuer.pem" \
    -in "$output.signing-input" -out "$output.signature"
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

# Sends one request and writes the body and status beside each other. The
# token is read from its file inside the helper and never printed.
http_json() {
  local method=$1
  local url=$2
  local body_file=$3
  local output=$4
  python3 - "$method" "$url" "$temporary_root/secrets/operator-token" "$body_file" "$output" <<'PY'
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
method, url, token_file, body_file, output = sys.argv[1:]
headers = {"Accept": "application/json",
           "Authorization": "Bearer " + Path(token_file).read_text(encoding="ascii").strip()}
data = None
if body_file:
    data = Path(body_file).read_bytes()
    headers["Content-Type"] = "application/json"
    headers["Idempotency-Key"] = str(uuid.uuid4())
request = urllib.request.Request(url, data=data, method=method, headers=headers)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        status, body = response.status, response.read()
except urllib.error.HTTPError as error:
    status, body = error.code, error.read()
Path(output).write_bytes(body)
Path(output + ".status").write_text(str(status), encoding="ascii")
PY
}

assert_status() {
  local actual
  actual=$(<"$1.status")
  if [[ "$actual" != "$2" ]]; then
    printf 'expected HTTP %s for %s, got %s\n' "$2" "$1" "$actual" >&2
    exit 1
  fi
}

# Starts the runtime for one environment and waits until it is ready. The
# process id is kept so cleanup stops it.
start_server() {
  local config=$1
  local url=$2
  local log=$3
  BREG_LOG=error "$breg" --runtime-config "$config" >"$log" 2>&1 &
  breg_pids+=("$!")
  python3 - "${url}ready" <<'PY'
import sys
import time
import urllib.error
import urllib.request
deadline = time.time() + 30
last = None
while time.time() < deadline:
    try:
        with urllib.request.urlopen(sys.argv[1], timeout=2) as response:
            last = response.status
    except urllib.error.HTTPError as error:
        last = error.code
    except Exception:
        last = None
    if last == 200:
        raise SystemExit(0)
    time.sleep(0.5)
raise SystemExit(f"readiness did not reach 200; last status was {last}")
PY
}

# Starts a runtime that must refuse to serve, and asserts that it exits
# non-zero and that its log names the expected refusal.
expect_startup_refusal() {
  local config=$1
  local log=$2
  local expected=$3
  local status=0
  BREG_LOG=error "$breg" --runtime-config "$config" >"$log" 2>&1 || status=$?
  if [[ "$status" == 0 ]]; then
    printf 'breg started with %s where startup had to refuse.\n' "$config" >&2
    exit 1
  fi
  if ! grep -q -- "$expected" "$log"; then
    printf 'breg startup refusal did not name %s.\n' "$expected" >&2
    exit 1
  fi
}

registry_revision_served() {
  local url=$1
  local output=$2
  http_json GET "${url}v1/registry?accessProfile=operator" "" "$output"
  assert_status "$output" 200
  json_field "$output" revision
}

activation_status() {
  local config=$1
  local output=$2
  run_json "$output" status --runtime-config "$config"
  assert_json_ok "$output" status
}

mkdir -p "$temporary_root/secrets" "$temporary_root/empty-package" \
  "$temporary_root/audit-staging" "$temporary_root/audit-production" "$temporary_root/audit-test"
chmod 700 "$temporary_root/secrets"
openssl rand -hex 32 >"$temporary_root/secrets/audit-key"
openssl rand -hex 32 >"$temporary_root/secrets/cursor-key"
openssl genpkey -algorithm ED25519 -out "$temporary_root/issuer.pem" >/dev/null 2>&1
python3 - "$temporary_root/issuer.pem" "$temporary_root/secrets/issuer-jwks" <<'PY'
import base64
import json
import subprocess
import sys
der = subprocess.run(["openssl", "pkey", "-in", sys.argv[1], "-pubout", "-outform", "DER"],
                     check=True, capture_output=True).stdout
x = base64.urlsafe_b64encode(der[-32:]).rstrip(b"=").decode("ascii")
jwk = {"alg": "EdDSA", "crv": "Ed25519", "kid": "promotion-issuer", "kty": "OKP", "x": x}
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps({"keys": [jwk]}, sort_keys=True))
PY
issue_token generic-registry-operator registry:generic:operate registry-operations \
  "$temporary_root/secrets/operator-token"
issue_token generic-registry-reader registry:generic:read registry-reporting \
  "$temporary_root/secrets/reader-token" '{"registry_record_status":"active"}'
python3 - "$temporary_root/credentials.yaml" <<'PY'
import sys
steps = {
    "create-record-group": "operator", "create-record": "operator", "get-record": "operator",
    "read-record-within-the-claim": "reader", "retire-record": "operator",
    "read-record-outside-the-claim": "reader", "list-records": "operator",
}
lines = ["apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1",
         "kind: BRegSchemaTestCredentials", "bindings:"]
for step, token in steps.items():
    lines.append(f"  - {{journeyId: record-lifecycle, stepId: {step}, "
                 f"credential: {{type: bearer, tokenRef: secret:file/{token}-token}}}}")
open(sys.argv[1], "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY

promotion_suffix="rspromo$(date +%s)$$"
promotion_migration_role="breg_promo_migration_${promotion_suffix}"
promotion_runtime_role="breg_promo_runtime_${promotion_suffix}"
promotion_password=$(openssl rand -hex 18)
promotion_admin_url=$BREG_TEST_DATABASE_URL
psql "$promotion_admin_url" -v ON_ERROR_STOP=1 -q \
  -c "CREATE ROLE \"$promotion_migration_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$promotion_password';" \
  -c "CREATE ROLE \"$promotion_runtime_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$promotion_password';"
staging_database="breg_promo_staging_${promotion_suffix}"
production_database="breg_promo_production_${promotion_suffix}"
provision_database "breg_promo_test1_${promotion_suffix}" test-1
provision_database "breg_promo_test2_${promotion_suffix}" test-2
provision_database "$staging_database" staging
provision_database "$production_database" production

checkpoint "authoring the project both environments promote"
project_1="$temporary_root/project-1"
run_json "$temporary_root/init.json" init "$project_1"
assert_json_ok "$temporary_root/init.json" init
python3 - "$project_1/registry.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
needle = "      - {id: status, type: vocabulary-code, vocabulary: record-status, classification: internal}\n"
if needle not in source:
    raise SystemExit("record field insertion point was not found")
path.write_text(source.replace(needle, needle + "      - {id: legacy-note, type: string, required: false, maximumLength: 120, classification: internal}\n", 1), encoding="utf-8")
PY
run_json "$temporary_root/check-1.json" check "$project_1" --production
assert_json_ok "$temporary_root/check-1.json" check

checkpoint "testing and packaging once"
render_runtime_config "$temporary_root/runtime-test-1.yaml" test test-1 "$temporary_root/empty-package" 127.0.0.1:0
run_json "$temporary_root/test-1.json" test "$project_1" \
  --runtime-config "$temporary_root/runtime-test-1.yaml" --credentials "$temporary_root/credentials.yaml" \
  --output "$temporary_root/test-receipt-1.json"
assert_json_ok "$temporary_root/test-1.json" test
schema_fingerprint_1=$(json_field "$temporary_root/test-1.json" schemaFingerprint)
run_json "$temporary_root/package-1.json" package "$project_1" \
  --test-receipt "$temporary_root/test-receipt-1.json" --output "$temporary_root/build-1"
assert_json_ok "$temporary_root/package-1.json" package
package_1="$temporary_root/build-1/package"
package_digest_1=$(json_field "$temporary_root/package-1.json" packageDigest)

# Each environment deploys its own copy of the one package directory, the way
# an operator copies a release artifact onto a host.
declare -A listener_of
for environment in staging production; do
  mkdir -p "$temporary_root/deploy-$environment"
  cp -R "$package_1" "$temporary_root/deploy-$environment/package-1"
  listener_of[$environment]=$(select_free_listener)
  render_runtime_config "$temporary_root/runtime-$environment-1.yaml" "$environment" "$environment" \
    "$temporary_root/deploy-$environment/package-1" "${listener_of[$environment]}"
done
if ! diff <(sed -E 's/(staging|production)/ENVIRONMENT/g; s/127\.0\.0\.1:[0-9]+/LISTENER/' "$temporary_root/runtime-staging-1.yaml") \
  <(sed -E 's/(staging|production)/ENVIRONMENT/g; s/127\.0\.0\.1:[0-9]+/LISTENER/' "$temporary_root/runtime-production-1.yaml") >/dev/null; then
  printf '%s\n' 'staging and production runtime files differ in more than their environment values.' >&2
  exit 1
fi

declare -A revision_of
for environment in staging production; do
  checkpoint "planning, applying, and serving the package in $environment"
  config="$temporary_root/runtime-$environment-1.yaml"
  run_json "$temporary_root/plan-$environment-1.json" plan --runtime-config "$config" \
    --package "$temporary_root/deploy-$environment/package-1"
  assert_json_ok "$temporary_root/plan-$environment-1.json" plan
  [[ "$(json_field "$temporary_root/plan-$environment-1.json" activation)" == initial ]]
  [[ "$(json_field "$temporary_root/plan-$environment-1.json" packageDigest)" == "$package_digest_1" ]]
  run_json "$temporary_root/apply-$environment-1.json" apply --runtime-config "$config" \
    --package "$temporary_root/deploy-$environment/package-1" --initial
  assert_json_ok "$temporary_root/apply-$environment-1.json" apply
  activation_status "$config" "$temporary_root/status-$environment-1.json"
  python3 - "$temporary_root/status-$environment-1.json" "$package_digest_1" <<'PY'
import json
import sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
if status["activePackageDigest"] != sys.argv[2] or status["maintenanceStatus"] != "ready":
    raise SystemExit("status did not report the applied package as active and ready")
entries = status["ledger"]
if [entry["planKind"] for entry in entries] != ["initial"] or entries[0]["outcome"] != "applied":
    raise SystemExit("the ledger did not record exactly one applied initial activation")
PY
  url="http://${listener_of[$environment]}/"
  start_server "$config" "$url" "$temporary_root/server-$environment-1.log"
  revision_of[$environment]=$(registry_revision_served "$url" "$temporary_root/registry-$environment-1.json")
  printf '%s\n' "{\"data\":{\"code\":\"$environment-group\",\"label\":\"Promotion group\"}}" >"$temporary_root/group-$environment.json"
  http_json POST "${url}v1/records/record-groups?accessProfile=operator" \
    "$temporary_root/group-$environment.json" "$temporary_root/group-$environment-response.json"
  assert_status "$temporary_root/group-$environment-response.json" 201
  stop_servers
done
if [[ "${revision_of[staging]}" != "${revision_of[production]}" ]]; then
  printf '%s\n' 'staging and production serve different registry revisions from one package.' >&2
  exit 1
fi
if [[ "$(json_field "$temporary_root/package-1.json" registryRevision)" != "${revision_of[staging]}" ]]; then
  printf '%s\n' 'the served registry revision is not the packaged one.' >&2
  exit 1
fi

checkpoint "exporting the Evidence source from each environment's checkout"
for environment in staging production; do
  cp -R "$project_1" "$temporary_root/checkout-$environment"
  run_json "$temporary_root/evidence-source-$environment.json" generate evidence-source \
    "$temporary_root/checkout-$environment" --access-profile evidence-source --entity record \
    --selector by-code --fields code,status --source-id registry-record --connection registry \
    --output "$temporary_root/evidence-source-$environment"
  assert_json_ok "$temporary_root/evidence-source-$environment.json" generate
done
python3 - "$temporary_root/evidence-source-staging/source-export.json" \
  "$temporary_root/evidence-source-production/source-export.json" "${revision_of[staging]}" <<'PY'
import json
import sys
staging, production = (json.load(open(path, encoding="utf-8"))["provenance"] for path in sys.argv[1:3])
if staging != production:
    raise SystemExit("the Evidence source provenance differs between environments")
if staging["registryRevision"] != sys.argv[3]:
    raise SystemExit("the Evidence source provenance does not name the served registry revision")
PY

checkpoint "authoring the reviewed destructive successor"
project_2="$temporary_root/project-2"
cp -R "$project_1" "$project_2"
python3 - "$project_2/registry.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
field = "      - {id: legacy-note, type: string, required: false, maximumLength: 120, classification: internal}\n"
if field not in source:
    raise SystemExit("the legacy field was not found")
path.write_text(source.replace(field, "", 1), encoding="utf-8")
PY
run_json "$temporary_root/diff-2.json" diff "$project_2" --package "$package_1"
assert_json_ok "$temporary_root/diff-2.json" diff

# Measure the target catalog a reviewer binds the migration to. The
# measurement rolls back, so the schema test below reuses its database.
render_runtime_config "$temporary_root/runtime-test-2.yaml" test test-2 "$temporary_root/empty-package" 127.0.0.1:0
run_json "$temporary_root/measure-2.json" test "$project_2" --fingerprint-only \
  --runtime-config "$temporary_root/runtime-test-2.yaml"
assert_json_ok "$temporary_root/measure-2.json" test
schema_fingerprint_2=$(json_field "$temporary_root/measure-2.json" schemaFingerprint)
postgres_major=$(psql "$(derive_database_url "$staging_database")" -Atqc "SELECT current_setting('server_version_num')::integer / 10000")

# Test-fixture review evidence for one destructive field removal. The step
# drops the column the package's own effective model names.
python3 - "$temporary_root" "$package_1" "$package_digest_1" "$schema_fingerprint_1" "$schema_fingerprint_2" "$postgres_major" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
root, package = Path(sys.argv[1]), Path(sys.argv[2])
prior_digest, prior_fingerprint, final_fingerprint, postgres_major = sys.argv[3:]
changes = json.loads((root / "diff-2.json").read_text())["changes"]
covers = [{"code": item["change"]["code"], "target": item["change"]["target"]}
          for item in changes if item["change"]["class"] != "compatible-additive"]
if [cover["code"] for cover in covers] != ["field-removed"]:
    raise SystemExit(f"the successor did not remove exactly one field: {covers}")
model = json.loads((package / "effective-model.json").read_text())
entity = model["entities"]["record"]
table, column = entity["physicalTable"], entity["fields"]["legacy-note"]["physicalName"]

def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")

def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

base = "modules/record-notes/migrations/remove-legacy-note"
step_sql = f"ALTER TABLE registry_data.{table} DROP COLUMN {column}".encode("ascii")
assertion_sql = f"SELECT pg_catalog.count(*) >= 0 FROM registry_data.{table}".encode("ascii")
fixture = b'{"fixture":"representative"}\n'
descriptor = {
    "apiVersion": "id.registrystack.org/formats/breg/migration-descriptor/v1alpha1",
    "kind": "BRegMigrationDescriptor",
    "id": "remove-legacy-note", "changeClass": "destructive-or-irreversible", "covers": covers,
    "recovery": "exact-target-resume", "lockTimeoutMilliseconds": 1000,
    "statementTimeoutMilliseconds": 60000,
    "steps": [{"type": "transactional-sql", "id": "drop", "sqlPath": f"{base}/steps/drop.sql",
               "objects": [{"schema": "registry_data", "table": table, "entity": "record",
                            "kind": "field", "member": "legacy-note", "physicalName": column}]}],
    "preAssertions": [{"id": "pre", "sqlPath": f"{base}/assertions/pre.sql"}],
    "postAssertions": [{"id": "post", "sqlPath": f"{base}/assertions/post.sql"}],
    "rehearsalReceiptPath": f"{base}/rehearsal.json", "backupBindingPath": f"{base}/backup.json",
}
receipt = {
    "apiVersion": "id.registrystack.org/formats/breg/migration-rehearsal-receipt/v1alpha1",
    "kind": "BRegMigrationRehearsalReceipt",
    "priorPackageDigest": prior_digest, "priorSchemaFingerprint": prior_fingerprint,
    "planDigest": digest(canonical(descriptor)),
    "sqlDigests": [{"path": f"{base}/steps/drop.sql", "digest": digest(step_sql)}],
    "assertionDigests": [{"path": f"{base}/assertions/pre.sql", "digest": digest(assertion_sql)},
                         {"path": f"{base}/assertions/post.sql", "digest": digest(assertion_sql)}],
    "fixtureInventory": [{"id": "representative", "path": f"{base}/fixtures/representative.jsonl",
                          "digest": digest(fixture), "rowCount": 1}],
    "postgresMajor": int(postgres_major), "rowAssertions": [], "finalSchemaFingerprint": final_fingerprint,
}
directory = root / "review-2" / base
for relative, data in {
    "descriptor.json": canonical(descriptor), "rehearsal.json": canonical(receipt),
    "steps/drop.sql": step_sql, "assertions/pre.sql": assertion_sql,
    "assertions/post.sql": assertion_sql, "fixtures/representative.jsonl": fixture,
}.items():
    (directory / relative).parent.mkdir(parents=True, exist_ok=True)
    (directory / relative).write_bytes(data)
(root / "legacy-table").write_text(table, encoding="ascii")
PY
legacy_table=$(<"$temporary_root/legacy-table")

checkpoint "testing and packaging the reviewed successor once"
run_json "$temporary_root/test-2.json" test "$project_2" \
  --runtime-config "$temporary_root/runtime-test-2.yaml" --credentials "$temporary_root/credentials.yaml" \
  --baseline-package "$package_1" --reviewed-migrations "$temporary_root/review-2" \
  --output "$temporary_root/test-receipt-2.json"
assert_json_ok "$temporary_root/test-2.json" test
run_json "$temporary_root/package-2.json" package "$project_2" \
  --test-receipt "$temporary_root/test-receipt-2.json" --baseline-package "$package_1" \
  --reviewed-migrations "$temporary_root/review-2" --output "$temporary_root/build-2"
assert_json_ok "$temporary_root/package-2.json" package
package_2="$temporary_root/build-2/package"
package_digest_2=$(json_field "$temporary_root/package-2.json" packageDigest)

# Takes one environment's backup of the table the successor changes and
# writes the binding apply checks it against. The export stands in for the
# operator's own backup tool; the binding is what BReg verifies.
take_backup() {
  local environment=$1
  local database=$2
  local backup="$temporary_root/backups/$environment.csv"
  mkdir -p "$temporary_root/backups"
  psql "$(derive_database_url "$database")" -v ON_ERROR_STOP=1 -q \
    -c "\\copy (SELECT * FROM registry_data.$legacy_table) TO '$backup' WITH (FORMAT csv, HEADER)"
  chmod 600 "$backup"
  python3 - "$backup" "generic-registry-$environment-db" "$package_digest_1" "$schema_fingerprint_1" \
    "$temporary_root/backups/$environment-binding.json" <<'PY'
import datetime
import hashlib
import json
import sys
from pathlib import Path
backup, database_id, prior_digest, prior_fingerprint, output = sys.argv[1:]
data = Path(backup).read_bytes()
binding = {
    "apiVersion": "id.registrystack.org/formats/breg/backup-binding/v1alpha1",
    "kind": "BRegBackupBinding",
    "database": database_id, "priorPackageDigest": prior_digest,
    "priorSchemaFingerprint": prior_fingerprint, "backupFile": backup,
    "digest": "sha256:" + hashlib.sha256(data).hexdigest(), "sizeBytes": len(data),
    "createdAt": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "maximumAgeSeconds": 3600,
}
Path(output).write_text(json.dumps(binding, sort_keys=True), encoding="utf-8")
PY
}

backup_binding_path="modules/record-notes/migrations/remove-legacy-note/backup.json"
declare -A database_of=([staging]="$staging_database" [production]="$production_database")
for environment in staging production; do
  take_backup "$environment" "${database_of[$environment]}"
done

checkpoint "refusing a backup binding that names another environment's database"
expect_refusal "$temporary_root/apply-production-foreign-backup.json" apply.backup_evidence.refused \
  apply --runtime-config "$temporary_root/runtime-production-1.yaml" --package "$package_2" \
  --backup "$backup_binding_path=$temporary_root/backups/staging-binding.json"

for environment in staging production; do
  checkpoint "planning and applying the reviewed successor in $environment with its backup"
  cp -R "$package_2" "$temporary_root/deploy-$environment/package-2"
  config="$temporary_root/runtime-$environment-1.yaml"
  backup_argument="$backup_binding_path=$temporary_root/backups/$environment-binding.json"
  run_json "$temporary_root/plan-$environment-2.json" plan --runtime-config "$config" \
    --package "$temporary_root/deploy-$environment/package-2" --backup "$backup_argument"
  assert_json_ok "$temporary_root/plan-$environment-2.json" plan
  [[ "$(json_field "$temporary_root/plan-$environment-2.json" activation)" == successor ]]
  run_json "$temporary_root/apply-$environment-2.json" apply --runtime-config "$config" \
    --package "$temporary_root/deploy-$environment/package-2" --backup "$backup_argument" \
    --operator-reference "promotion-$environment-change-2"
  assert_json_ok "$temporary_root/apply-$environment-2.json" apply
  render_runtime_config "$temporary_root/runtime-$environment-2.yaml" "$environment" "$environment" \
    "$temporary_root/deploy-$environment/package-2" "${listener_of[$environment]}"
  activation_status "$temporary_root/runtime-$environment-2.yaml" "$temporary_root/status-$environment-2.json"
  python3 - "$temporary_root/status-$environment-2.json" "$package_digest_1" "$package_digest_2" <<'PY'
import json
import sys
status = json.load(open(sys.argv[1], encoding="utf-8"))
first, second = sys.argv[2:4]
if status["activePackageDigest"] != second:
    raise SystemExit("status did not report the reviewed successor as active")
entries = sorted(status["ledger"], key=lambda entry: entry["applyOrder"])
if [(entry["planKind"], entry["outcome"]) for entry in entries] != [("initial", "applied"), ("successor", "applied")]:
    raise SystemExit("the ledger did not record the initial and reviewed activations in order")
if entries[1]["predecessorPackageDigest"] != first or entries[1]["packageDigest"] != second:
    raise SystemExit("the successor entry does not chain from the initial package")
PY
  psql "$(derive_database_url "${database_of[$environment]}")" -v ON_ERROR_STOP=1 -Atqc \
    "SELECT backup_references FROM registry_internal.registry_migrations ORDER BY apply_order" \
    >"$temporary_root/backup-references-$environment.txt"
  python3 - "$temporary_root/backup-references-$environment.txt" "$backup_binding_path" \
    "$temporary_root/backups/$environment-binding.json" <<'PY'
import json
import sys
initial, successor = (json.loads(line) for line in open(sys.argv[1], encoding="utf-8").read().splitlines())
binding = json.load(open(sys.argv[3], encoding="utf-8"))
if initial != [] or [(reference["bindingPath"], reference["sha256"]) for reference in successor] != [(sys.argv[2], binding["digest"])]:
    raise SystemExit("the ledger does not record the successor's backup binding")
PY
  url="http://${listener_of[$environment]}/"
  start_server "$temporary_root/runtime-$environment-2.yaml" "$url" "$temporary_root/server-$environment-2.log"
  revision_of[$environment]=$(registry_revision_served "$url" "$temporary_root/registry-$environment-2.json")
  http_json GET "${url}v1/records/record-groups?accessProfile=operator" "" "$temporary_root/groups-$environment-2.json"
  assert_status "$temporary_root/groups-$environment-2.json" 200
  python3 - "$temporary_root/groups-$environment-2.json" "$environment-group" <<'PY'
import json
import sys
items = json.load(open(sys.argv[1], encoding="utf-8"))["items"]
if [item["domainData"]["code"] for item in items] != [sys.argv[2]]:
    raise SystemExit("the record written before the successor did not survive it")
PY
  stop_servers
done
if [[ "${revision_of[staging]}" != "${revision_of[production]}" ]]; then
  printf '%s\n' 'staging and production serve different registry revisions after the successor.' >&2
  exit 1
fi

checkpoint "refusing an older package"
before=$(catalog_digest "$staging_database")
expect_refusal "$temporary_root/apply-staging-older.json" apply.package.refused \
  apply --runtime-config "$temporary_root/runtime-staging-2.yaml" --package "$temporary_root/deploy-staging/package-1"
[[ "$(catalog_digest "$staging_database")" == "$before" ]]

checkpoint "refusing a swapped package directory at startup"
swapped="$temporary_root/deploy-production/package-2"
mv "$swapped" "$temporary_root/deploy-production/package-2.held"
cp -R "$package_1" "$swapped"
expect_startup_refusal "$temporary_root/runtime-production-2.yaml" "$temporary_root/server-production-swapped.log" \
  'has not activated the package at package.root'
rm -rf -- "$swapped"
mv "$temporary_root/deploy-production/package-2.held" "$swapped"

checkpoint "refusing a staging runtime file pointed at the production database"
sed -e "s#secret:file/staging-runtime-url#secret:file/production-runtime-url#" \
  -e "s#secret:file/staging-migration-url#secret:file/production-migration-url#" \
  "$temporary_root/runtime-staging-2.yaml" >"$temporary_root/runtime-staging-on-production.yaml"
before=$(catalog_digest "$production_database")
expect_refusal "$temporary_root/plan-staging-on-production.json" apply.database.identity_mismatch \
  plan --runtime-config "$temporary_root/runtime-staging-on-production.yaml" --package "$temporary_root/deploy-staging/package-2"
expect_refusal "$temporary_root/apply-staging-on-production.json" apply.database.identity_mismatch \
  apply --runtime-config "$temporary_root/runtime-staging-on-production.yaml" --package "$temporary_root/deploy-staging/package-2"
expect_startup_refusal "$temporary_root/runtime-staging-on-production.yaml" \
  "$temporary_root/server-staging-on-production.log" 'records a different database id than identity.databaseId'
[[ "$(catalog_digest "$production_database")" == "$before" ]]

checkpoint "all promotion checkpoints passed"
printf '%s\n' 'Base Registry Engine promotion workflow passed'
