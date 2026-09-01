#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
fixture="$repository_root/products/registry-server/acceptance/asset-site-placement"
baseline="$repository_root/products/registry-server/generated/asset-site-placement"
temporary_root=""
server_pid=""
lock_pid=""
adopter_tls_ca_pem_path=""
adopter_admin_url=""
adopter_migration_role=""
adopter_runtime_role=""
adopter_author_role=""
adopter_databases=()

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "$1 is required for the adopter workflow." >&2
    exit 2
  fi
}

cleanup() {
  if [[ -n "${lock_pid:-}" ]]; then
    kill "$lock_pid" >/dev/null 2>&1 || true
    wait "$lock_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  for adopter_database_to_drop in "${adopter_databases[@]}"; do
    psql "$adopter_admin_url" -v ON_ERROR_STOP=1 -q \
      -c "DROP DATABASE IF EXISTS \"$adopter_database_to_drop\" WITH (FORCE);" >/dev/null 2>&1 || true
  done
  if [[ -n "${adopter_migration_role:-}" && -n "${adopter_runtime_role:-}" && -n "${adopter_author_role:-}" ]]; then
    psql "$adopter_admin_url" -v ON_ERROR_STOP=1 -q \
      -c "DROP ROLE IF EXISTS \"$adopter_author_role\"; DROP ROLE IF EXISTS \"$adopter_runtime_role\"; DROP ROLE IF EXISTS \"$adopter_migration_role\";" >/dev/null 2>&1 || true
  fi
  case "$temporary_root" in
    "$repository_root"/.registry-server-adopter.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    "") ;;
    *)
      printf '%s\n' 'adopter-workflow temporary directory did not match its validated location' >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

require_command openssl
require_command psql

if [[ -z "${REGISTRY_SERVER_TEST_DATABASE_URL:-}" ]]; then
  printf '%s\n' 'REGISTRY_SERVER_TEST_DATABASE_URL must be set for the adopter workflow.' >&2
  exit 2
fi
if [[ -z "${REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH:-}" ]]; then
  printf '%s\n' 'REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH must be set for the adopter workflow after the PostgreSQL TLS proof.' >&2
  exit 2
fi
adopter_tls_ca_pem_path=$REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH
case "$adopter_tls_ca_pem_path" in
  /*) ;;
  *)
    printf '%s\n' 'REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH must be an absolute file path.' >&2
    exit 2
    ;;
esac
case "$adopter_tls_ca_pem_path" in
  *$'\n'* | */../* | */..)
    printf '%s\n' 'REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH must be a lexical file path without parent traversal.' >&2
    exit 2
    ;;
esac
if [[ -L "$adopter_tls_ca_pem_path" || ! -f "$adopter_tls_ca_pem_path" ]]; then
  printf '%s\n' 'REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH must name an existing regular file.' >&2
  exit 2
fi
if [[ ! -s "$adopter_tls_ca_pem_path" ]]; then
  printf '%s\n' 'REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH must not be empty.' >&2
  exit 2
fi
ca_pem_bytes=$(wc -c <"$adopter_tls_ca_pem_path")
if [[ "$ca_pem_bytes" -gt 1048576 ]]; then
  printf '%s\n' 'REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH exceeds the 1 MiB CA bound.' >&2
  exit 2
fi
openssl x509 -in "$adopter_tls_ca_pem_path" -noout >/dev/null 2>&1 || {
  printf '%s\n' 'REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH must contain a PEM certificate.' >&2
  exit 2
}
umask 077
temporary_root=$(mktemp -d "$repository_root/.registry-server-adopter.XXXXXX")
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

registry_serverctl="$repository_root/target/debug/registry-serverctl"
registry_server="$repository_root/target/debug/registry-server"

sha256_file() {
  python3 - "$1" <<'PY'
import hashlib
import sys
with open(sys.argv[1], "rb") as handle:
    print(hashlib.sha256(handle.read()).hexdigest())
PY
}

json_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
print(value)
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

write_trust_anchor() {
  local public_jwk=$1
  local output=$2
  python3 - "$public_jwk" "$output" <<'PY'
import json
import sys
jwk = json.load(open(sys.argv[1], encoding="utf-8"))
anchor = {
    "apiVersion": "registry.registrystack.org/package-trust/v1",
    "databaseId": "asset-site-placement-adopter-db",
    "environment": "acceptance",
    "instanceId": "asset-site-placement-acceptance",
    "keys": [{"jwk": jwk, "keyId": jwk["kid"]}],
    "threshold": 1,
}
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(anchor, sort_keys=True, separators=(",", ":")))
PY
}

sign_file_hex() {
  local private_key=$1
  local input=$2
  local output=$3
  openssl pkeyutl -sign -rawin -inkey "$private_key" -in "$input" -out "$output.bin"
  python3 - "$output.bin" "$output" <<'PY'
import sys
from pathlib import Path
Path(sys.argv[2]).write_text(Path(sys.argv[1]).read_bytes().hex(), encoding="utf-8")
PY
  rm -f -- "$output.bin"
}

write_signature_document() {
  local key_id=$1
  local signature_hex=$2
  local output=$3
  python3 - "$key_id" "$signature_hex" "$output" <<'PY'
import json
import sys
document = {"signatures": [{"keyId": sys.argv[1], "signatureHex": open(sys.argv[2], encoding="utf-8").read()}]}
open(sys.argv[3], "w", encoding="utf-8").write(json.dumps(document, sort_keys=True, separators=(",", ":")))
PY
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

write_jwt() {
  local private_key=$1
  local key_id=$2
  local principal=$3
  local purpose=$4
  local output=$5
  python3 - "$key_id" "$principal" "$purpose" "$output.signing-input" <<'PY'
import base64
import json
import sys
import time

def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=").decode("ascii")

now = int(time.time())
claims = {
    "aud": "urn:registry-server:adopter",
    "client_id": "registry-adopter-client",
    "exp": now + 3600,
    "iat": now,
    "iss": "https://issuer.example/adopter",
    "jti": f"adopter-{now}-{sys.argv[2]}-{sys.argv[3] or 'none'}",
    "registry_principal": sys.argv[2],
    "sub": sys.argv[2],
}
if sys.argv[3]:
    claims["registry_purpose"] = sys.argv[3]
header = {"alg": "EdDSA", "kid": sys.argv[1], "typ": "JWT"}
open(sys.argv[4], "w", encoding="ascii").write(f"{b64(header)}.{b64(claims)}")
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

render_runtime_config() {
  local output=$1
  local package_root=$2
  local active_revision=$3
  local active_sequence=$4
  local statement_timeout_ms=$5
  local runtime_ref=$6
  local migration_ref=$7
  local listener=$8
  local compiler_source_revision=$9
  cat >"$output" <<EOF
apiVersion: registry.registrystack.org/server-runtime/v1alpha1
kind: RegistryServerRuntimeConfig
listener:
  bind: $listener
  trustedProxy: direct
identity:
  environment: acceptance
  instanceId: asset-site-placement-acceptance
  databaseId: asset-site-placement-adopter-db
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
    migration: $adopter_migration_role
    runtime: $adopter_runtime_role
package:
  root: $package_root
  trustAnchorPath: $temporary_root/package-trust-anchor.json
  compilerSourceRevision: $compiler_source_revision
  activeRevision: $active_revision
  activeSequence: $active_sequence
authentication:
  oidc:
    issuer: https://issuer.example/adopter
    audience: urn:registry-server:adopter
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-adopter-client]
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
  migrationStatementMilliseconds: $statement_timeout_ms
EOF
}

run_json() {
  local output=$1
  local command=$2
  local status
  shift
  if "$registry_serverctl" --format json "$@" >"$output"; then
    return 0
  else
    status=$?
  fi
  python3 - "$output" "$command" <<'PY'
import json
import sys
try:
    document = json.load(open(sys.argv[1], encoding="utf-8"))
    codes = sorted({str(item.get("code")) for item in document.get("diagnostics", []) if item.get("code")})
except Exception:
    codes = []
summary = ", ".join(codes) if codes else "unavailable"
print(f"registry-serverctl {sys.argv[2]} refused; diagnostics: {summary}", file=sys.stderr)
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

assert_json_failure() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
if document.get("ok") is not False:
    raise SystemExit("expected command refusal")
codes = [diagnostic.get("code") for diagnostic in document.get("diagnostics", [])]
if sys.argv[2] not in codes:
    raise SystemExit(f"expected diagnostic {sys.argv[2]}, got {codes}")
PY
}

wait_ready_status() {
  local url=$1
  local expected=$2
  python3 - "$url" "$expected" <<'PY'
import sys
import time
import urllib.error
import urllib.request
url = sys.argv[1]
expected = int(sys.argv[2])
deadline = time.time() + 30
last = None
while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            last = response.status
    except urllib.error.HTTPError as error:
        last = error.code
    except Exception:
        last = None
    if last == expected:
        raise SystemExit(0)
    time.sleep(0.5)
raise SystemExit(f"readiness did not reach {expected}; last status was {last}")
PY
}

derive_adopter_urls() {
  local database=$1
  python3 - "$REGISTRY_SERVER_TEST_DATABASE_URL" "$database" "$adopter_migration_role" "$adopter_runtime_role" "$adopter_password" <<'PY'
import sys
from urllib.parse import quote, urlsplit, urlunsplit
admin = urlsplit(sys.argv[1])
database, migration_role, runtime_role, password = sys.argv[2:]
if admin.scheme not in {"postgres", "postgresql"} or not admin.hostname:
    raise SystemExit("REGISTRY_SERVER_TEST_DATABASE_URL must be a PostgreSQL URL")
host = admin.hostname
netloc_suffix = host if admin.port is None else f"{host}:{admin.port}"
query = admin.query
def url(role):
    userinfo = f"{quote(role, safe='')}:{quote(password, safe='')}"
    return urlunsplit((admin.scheme, f"{userinfo}@{netloc_suffix}", f"/{quote(database, safe='')}", query, ""))
print(url(migration_role))
print(url(runtime_role))
PY
}

derive_admin_database_url() {
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

write_database_url_secrets() {
  local database=$1
  local runtime_secret=$2
  local migration_secret=$3
  local urls
  local migration_url
  local runtime_url

  urls=$(derive_adopter_urls "$database")
  migration_url=$(printf '%s\n' "$urls" | sed -n '1p')
  runtime_url=$(printf '%s\n' "$urls" | sed -n '2p')
  printf '%s' "$runtime_url" >"$temporary_root/secrets/$runtime_secret"
  printf '%s' "$migration_url" >"$temporary_root/secrets/$migration_secret"
}

provision_adopter_database() {
  local database=$1
  local admin_database_url
  admin_database_url=$(derive_admin_database_url "$database")
  psql "$adopter_admin_url" -v ON_ERROR_STOP=1 -q \
    -c "CREATE DATABASE \"$database\";"
  psql "$admin_database_url" -v ON_ERROR_STOP=1 -q \
    -c "CREATE EXTENSION IF NOT EXISTS btree_gist;" \
    -c "REVOKE ALL ON DATABASE \"$database\" FROM PUBLIC;" \
    -c "GRANT CONNECT ON DATABASE \"$database\" TO \"$adopter_migration_role\", \"$adopter_runtime_role\", \"$adopter_author_role\";" \
    -c "CREATE SCHEMA registry_internal AUTHORIZATION \"$adopter_migration_role\";" \
    -c "CREATE SCHEMA registry_data AUTHORIZATION \"$adopter_migration_role\";" \
    -c "CREATE SCHEMA registry_source AUTHORIZATION \"$adopter_migration_role\";" \
    -c "CREATE SCHEMA registry_derived AUTHORIZATION \"$adopter_migration_role\";" \
    -c "CREATE SCHEMA registry_context AUTHORIZATION \"$adopter_migration_role\";" \
    -c "REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context FROM PUBLIC;" >/dev/null
}

select_free_listener() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(f"127.0.0.1:{sock.getsockname()[1]}")
PY
}

entity_list_path() {
  local package_root=$1
  local entity=$2
  local profile=$3
  python3 - "$package_root/inventories/routes.json" "$entity" "$profile" <<'PY'
import json
import sys
routes = json.load(open(sys.argv[1], encoding="utf-8"))["routes"]
for route in routes:
    if (
        route.get("entityId") == sys.argv[2]
        and route.get("operation") == "list"
        and route.get("method") == "GET"
        and route.get("queryKind") == "list"
        and sys.argv[3] in route.get("accessProfiles", [])
    ):
        print(route["path"])
        raise SystemExit(0)
raise SystemExit("list route was not found")
PY
}

http_get_json() {
  local base_url=$1
  local token_file=$2
  local path_and_query=$3
  local output=$4
  python3 - "$base_url" "$token_file" "$path_and_query" "$output" <<'PY'
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path
base_url, token_file, path_and_query, output = sys.argv[1:]
token = Path(token_file).read_text(encoding="ascii").strip()
url = urllib.parse.urljoin(base_url, path_and_query.lstrip("/"))
request = urllib.request.Request(
    url,
    headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
)
with urllib.request.urlopen(request, timeout=10) as response:
    body = response.read()
    if response.status != 200:
        raise SystemExit(f"GET {path_and_query} returned {response.status}")
json.loads(body)
Path(output).write_bytes(body)
PY
}

cargo build --manifest-path "$repository_root/Cargo.toml" --locked \
  -p registry-serverctl \
  -p registry-server \
  --features registry-server/runtime
export SSL_CERT_FILE="$adopter_tls_ca_pem_path"

server_hash_before=$(sha256_file "$registry_server")

mkdir -p "$temporary_root/secrets" "$temporary_root/empty-package-root"
chmod 700 "$temporary_root/secrets"
printf '%s' '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' >"$temporary_root/secrets/audit-key"
printf '%s' 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789' >"$temporary_root/secrets/cursor-key"

adopter_suffix="rsadopter$(date +%s)$$"
adopter_schema_test_v1_database="rs_test_v1_${adopter_suffix}"
adopter_schema_test_v2_database="rs_test_v2_${adopter_suffix}"
adopter_measure_v3_database="rs_measure_v3_${adopter_suffix}"
adopter_schema_test_v3_database="rs_test_v3_${adopter_suffix}"
adopter_production_database="rs_prod_${adopter_suffix}"
adopter_databases=("$adopter_schema_test_v1_database" "$adopter_schema_test_v2_database" "$adopter_measure_v3_database" "$adopter_schema_test_v3_database" "$adopter_production_database")
adopter_migration_role="rs_migration_${adopter_suffix}"
adopter_runtime_role="rs_runtime_${adopter_suffix}"
adopter_author_role="rs_author_${adopter_suffix}"
adopter_password="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(18))
PY
)"
adopter_admin_url=$REGISTRY_SERVER_TEST_DATABASE_URL

psql "$adopter_admin_url" -v ON_ERROR_STOP=1 -q \
  -c "CREATE ROLE \"$adopter_migration_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$adopter_password';" \
  -c "CREATE ROLE \"$adopter_runtime_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$adopter_password';" \
  -c "CREATE ROLE \"$adopter_author_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$adopter_password';"

for adopter_database in "${adopter_databases[@]}"; do
  provision_adopter_database "$adopter_database"
done

adopter_urls=$(derive_adopter_urls "$adopter_production_database")
adopter_migration_url=$(printf '%s\n' "$adopter_urls" | sed -n '1p')
adopter_runtime_url=$(printf '%s\n' "$adopter_urls" | sed -n '2p')
adopter_production_admin_url=$(derive_admin_database_url "$adopter_production_database")
printf '%s' "$adopter_runtime_url" >"$temporary_root/secrets/production-runtime-url"
printf '%s' "$adopter_migration_url" >"$temporary_root/secrets/production-migration-url"
write_database_url_secrets "$adopter_schema_test_v1_database" schema-test-v1-runtime-url schema-test-v1-migration-url
write_database_url_secrets "$adopter_schema_test_v2_database" schema-test-v2-runtime-url schema-test-v2-migration-url
write_database_url_secrets "$adopter_measure_v3_database" measure-v3-runtime-url measure-v3-migration-url
write_database_url_secrets "$adopter_schema_test_v3_database" schema-test-v3-runtime-url schema-test-v3-migration-url

openssl genpkey -algorithm ED25519 -out "$temporary_root/package-signer.pem" >/dev/null 2>&1
openssl genpkey -algorithm ED25519 -out "$temporary_root/oidc-signer.pem" >/dev/null 2>&1
chmod 600 "$temporary_root/package-signer.pem" "$temporary_root/oidc-signer.pem"
write_public_jwk "$temporary_root/package-signer.pem" "adopter-package-key" "$temporary_root/package-signer.public.jwk"
write_public_jwk "$temporary_root/oidc-signer.pem" "adopter-oidc-key" "$temporary_root/oidc-signer.public.jwk"
write_trust_anchor "$temporary_root/package-signer.public.jwk" "$temporary_root/package-trust-anchor.json"
write_jwks "$temporary_root/oidc-signer.public.jwk" "$temporary_root/secrets/oidc-jwks"

write_jwt "$temporary_root/oidc-signer.pem" "adopter-oidc-key" "synthetic-asset-operator" "asset-management" "$temporary_root/secrets/operator-token"
write_jwt "$temporary_root/oidc-signer.pem" "adopter-oidc-key" "synthetic-site-planner" "site-planning" "$temporary_root/secrets/planner-token"
write_jwt "$temporary_root/oidc-signer.pem" "adopter-oidc-key" "synthetic-site-planner" "" "$temporary_root/secrets/planner-no-purpose-token"

cat >"$temporary_root/schema-test-credentials.yaml" <<'EOF'
apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings:
  - {journeyId: asset-and-site-caller-surfaces, stepId: create-asset, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: planner-gets-asset, credential: {type: bearer, tokenRef: secret:file/planner-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: planner-lists-assets, credential: {type: bearer, tokenRef: secret:file/planner-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: operator-renames-asset, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: create-site, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: planner-gets-site, credential: {type: bearer, tokenRef: secret:file/planner-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: planner-lists-sites, credential: {type: bearer, tokenRef: secret:file/planner-token}}
  - {journeyId: asset-and-site-caller-surfaces, stepId: planner-without-purpose-is-concealed, credential: {type: bearer, tokenRef: secret:file/planner-no-purpose-token}}
EOF

render_runtime_config "$temporary_root/runtime-test-v1.yaml" "$temporary_root/empty-package-root" \
  "sha256:1111111111111111111111111111111111111111111111111111111111111111" 1 60000 \
  "secret:file/schema-test-v1-runtime-url" "secret:file/schema-test-v1-migration-url" \
  "127.0.0.1:0" "asset-site-placement-acceptance-0.1.0"
render_runtime_config "$temporary_root/runtime-author-v1.yaml" "$temporary_root/empty-package-root" \
  "sha256:1111111111111111111111111111111111111111111111111111111111111111" 1 60000 \
  "secret:file/production-runtime-url" "secret:file/missing-migration-url" \
  "127.0.0.1:0" "asset-site-placement-acceptance-0.1.0"

"$registry_serverctl" check "$fixture"
run_json "$temporary_root/production-check.json" check "$fixture" --production
assert_json_ok "$temporary_root/production-check.json" check
run_json "$temporary_root/access.json" explain access "$fixture"
assert_json_ok "$temporary_root/access.json" explain
python3 - "$temporary_root/production-check.json" "$temporary_root/access.json" <<'PY'
import json
import sys

production = json.load(open(sys.argv[1], encoding="utf-8"))
if production.get("profile") != "production":
    raise SystemExit("production profile did not accept the complete fixture closure")

access = json.load(open(sys.argv[2], encoding="utf-8"))
entries = access["explanation"]["routes"]["entries"]
by_entity_operation = {}
for entry in entries:
    key = (entry.get("entityId"), entry.get("operation"))
    by_entity_operation[key] = set(entry.get("profileIds", []))
for operation in ("create", "get", "list", "patch"):
    if by_entity_operation.get(("asset-placement", operation)) != {"asset-operator", "site-planner"}:
        raise SystemExit(f"asset placement {operation} did not compile both expected access profiles")
for operation in ("create", "get", "list"):
    if by_entity_operation.get(("inspection-event", operation)) != {"asset-operator"}:
        raise SystemExit("inspection events must remain operator-only in the fixture")
PY

(
  cd "$temporary_root"
  mkdir ./generated
  for selector in openapi schemas manifest metadata sql; do
    "$registry_serverctl" generate "$selector" "$fixture" --output "./$selector"
    cp -R "./$selector/." ./generated
  done
)
python3 "$script_dir/compare-generated-tree.py" "$baseline" "$temporary_root/generated"

run_json "$temporary_root/schema-test-v1.json" test "$fixture" \
  --runtime-config "$temporary_root/runtime-test-v1.yaml" \
  --credentials "$temporary_root/schema-test-credentials.yaml" \
  --database-id asset-site-placement-adopter-db \
  --signature-threshold 1 \
  --signature-key-id adopter-package-key \
  --output "$temporary_root/schema-test-receipt-v1.json"
assert_json_ok "$temporary_root/schema-test-v1.json" test
schema_fingerprint_v1=$(json_field "$temporary_root/schema-test-v1.json" schemaFingerprint)

run_json "$temporary_root/package-v1-awaiting.json" package "$fixture" \
  --database-id asset-site-placement-adopter-db \
  --schema-fingerprint "$schema_fingerprint_v1" \
  --test-receipt "$temporary_root/schema-test-receipt-v1.json" \
  --signature-threshold 1 \
  --signature-key-id adopter-package-key \
  --output "$temporary_root/build-v1"
assert_json_ok "$temporary_root/package-v1-awaiting.json" package
if [[ "$(json_field "$temporary_root/package-v1-awaiting.json" state)" != "awaiting_signatures" ]]; then
  printf '%s\n' 'initial package did not stop at the external-signature boundary.' >&2
  exit 1
fi
sign_file_hex "$temporary_root/package-signer.pem" "$temporary_root/build-v1/signing-input.json" "$temporary_root/package-v1.sighex"
write_signature_document "adopter-package-key" "$temporary_root/package-v1.sighex" "$temporary_root/package-v1-signatures.json"
run_json "$temporary_root/package-v1-published.json" package "$fixture" \
  --database-id asset-site-placement-adopter-db \
  --schema-fingerprint "$schema_fingerprint_v1" \
  --test-receipt "$temporary_root/schema-test-receipt-v1.json" \
  --signature-threshold 1 \
  --signature-key-id adopter-package-key \
  --signatures "$temporary_root/package-v1-signatures.json" \
  --output "$temporary_root/build-v1"
assert_json_ok "$temporary_root/package-v1-published.json" package
package_revision_v1=$(json_field "$temporary_root/package-v1-published.json" packageRevision)

render_runtime_config "$temporary_root/runtime-operator-v1.yaml" "$temporary_root/build-v1/package" \
  "$package_revision_v1" 1 60000 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "127.0.0.1:0" \
  "asset-site-placement-acceptance-0.1.0"
render_runtime_config "$temporary_root/runtime-author-v1.yaml" "$temporary_root/build-v1/package" \
  "$package_revision_v1" 1 60000 "secret:file/production-runtime-url" \
  "secret:file/missing-migration-url" "127.0.0.1:0" \
  "asset-site-placement-acceptance-0.1.0"

if run_json "$temporary_root/author-apply-v1.json" apply --runtime-config "$temporary_root/runtime-author-v1.yaml" --package "$temporary_root/build-v1/package" --initial; then
  printf '%s\n' 'author runtime unexpectedly applied a production package.' >&2
  exit 1
fi
assert_json_failure "$temporary_root/author-apply-v1.json" apply.database_configuration.refused
if [[ "$(psql "$adopter_production_admin_url" -Atqc "SELECT to_regclass('registry_internal.registry_state') IS NULL")" != "t" ]]; then
  printf '%s\n' 'author refusal changed the production database state.' >&2
  exit 1
fi

run_json "$temporary_root/apply-v1.json" apply --runtime-config "$temporary_root/runtime-operator-v1.yaml" --package "$temporary_root/build-v1/package" --initial
assert_json_ok "$temporary_root/apply-v1.json" apply
run_json "$temporary_root/verify-v1.json" verify --runtime-config "$temporary_root/runtime-operator-v1.yaml"
assert_json_ok "$temporary_root/verify-v1.json" verify

listener=$(select_free_listener)
server_url="http://$listener/"
render_runtime_config "$temporary_root/runtime-server-v1.yaml" "$temporary_root/build-v1/package" \
  "$package_revision_v1" 1 60000 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "$listener" \
  "asset-site-placement-acceptance-0.1.0"
REGISTRY_SERVER_LOG=error "$registry_server" --config "$temporary_root/runtime-server-v1.yaml" >"$temporary_root/server-v1.log" 2>&1 &
server_pid=$!
wait_ready_status "${server_url}ready" 200

cat >"$temporary_root/assets-create.jsonl" <<'EOF'
{"operation":"create","data":{"assetCode":"ASSET-PUBLIC-001","label":"Synthetic public workflow asset","assetClass":"equipment"}}
EOF
run_json "$temporary_root/data-validate-v1.json" data validate \
  --package "$temporary_root/build-v1/package" \
  --entity asset-item \
  --profile asset-operator \
  --operation create \
  --input "$temporary_root/assets-create.jsonl"
assert_json_ok "$temporary_root/data-validate-v1.json" "data validate"
run_json "$temporary_root/data-import-v1.json" data import \
  --package "$temporary_root/build-v1/package" \
  --server-url "$server_url" \
  --access-token-file "$temporary_root/secrets/operator-token" \
  --entity asset-item \
  --profile asset-operator \
  --operation create \
  --input "$temporary_root/assets-create.jsonl" \
  --checkpoint "$temporary_root/assets-import.checkpoint.json"
assert_json_ok "$temporary_root/data-import-v1.json" "data import"
asset_list_path_v1=$(entity_list_path "$temporary_root/build-v1/package" asset-item asset-operator)
http_get_json "$server_url" "$temporary_root/secrets/operator-token" \
  "$asset_list_path_v1?accessProfile=asset-operator" "$temporary_root/assets-list-v1.json"
python3 - "$temporary_root/assets-list-v1.json" <<'PY'
import json
import sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
items = document.get("items", [])
if not any(item.get("data", {}).get("assetCode") == "ASSET-PUBLIC-001" for item in items):
    raise SystemExit("authorized public data read did not include the created record")
PY

cp -R "$fixture" "$temporary_root/project-v2"
python3 - "$temporary_root/project-v2/registry.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
source = source.replace("  sequence: 1\n", "  sequence: 2\n", 1)
needle = """      - id: asset-class
        type: vocabulary-code
        vocabulary: asset-classification
        required: true
        classification: internal
"""
replacement = needle + """      - id: placement-review-note
        type: string
        required: false
        maxLength: 120
        classification: restricted
"""
if needle not in source:
    raise SystemExit("asset item field insertion point was not found")
path.write_text(source.replace(needle, replacement, 1), encoding="utf-8")
PY
render_runtime_config "$temporary_root/runtime-test-v2.yaml" "$temporary_root/build-v1/package" \
  "$package_revision_v1" 1 60000 "secret:file/schema-test-v2-runtime-url" \
  "secret:file/schema-test-v2-migration-url" "127.0.0.1:0" \
  "asset-site-placement-acceptance-0.1.0"

run_json "$temporary_root/diff-v2.json" diff "$temporary_root/project-v2" --runtime-config "$temporary_root/runtime-operator-v1.yaml"
assert_json_ok "$temporary_root/diff-v2.json" diff
python3 - "$temporary_root/diff-v2.json" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
changes = report.get("changes", [])
change = changes[0].get("change", {}) if len(changes) == 1 else {}
if (
    len(changes) != 1
    or changes[0].get("classification") != "compatible_additive"
    or change.get("code") != "field_added_optional"
    or change.get("class") != "compatible_additive"
):
    raise SystemExit(f"successor was not the expected additive field change: {changes}")
PY
run_json "$temporary_root/schema-test-v2.json" test "$temporary_root/project-v2" \
  --runtime-config "$temporary_root/runtime-test-v2.yaml" \
  --credentials "$temporary_root/schema-test-credentials.yaml" \
  --database-id asset-site-placement-adopter-db \
  --baseline-runtime-config "$temporary_root/runtime-operator-v1.yaml" \
  --signature-threshold 1 \
  --signature-key-id adopter-package-key \
  --output "$temporary_root/schema-test-receipt-v2.json"
assert_json_ok "$temporary_root/schema-test-v2.json" test
schema_fingerprint_v2=$(json_field "$temporary_root/schema-test-v2.json" schemaFingerprint)

run_json "$temporary_root/package-v2-awaiting.json" package "$temporary_root/project-v2" \
  --database-id asset-site-placement-adopter-db \
  --baseline-runtime-config "$temporary_root/runtime-operator-v1.yaml" \
  --schema-fingerprint "$schema_fingerprint_v2" \
  --test-receipt "$temporary_root/schema-test-receipt-v2.json" \
  --signature-threshold 1 \
  --signature-key-id adopter-package-key \
  --output "$temporary_root/build-v2"
assert_json_ok "$temporary_root/package-v2-awaiting.json" package
sign_file_hex "$temporary_root/package-signer.pem" "$temporary_root/build-v2/signing-input.json" "$temporary_root/package-v2.sighex"
write_signature_document "adopter-package-key" "$temporary_root/package-v2.sighex" "$temporary_root/package-v2-signatures.json"
run_json "$temporary_root/package-v2-published.json" package "$temporary_root/project-v2" \
  --database-id asset-site-placement-adopter-db \
  --baseline-runtime-config "$temporary_root/runtime-operator-v1.yaml" \
  --schema-fingerprint "$schema_fingerprint_v2" \
  --test-receipt "$temporary_root/schema-test-receipt-v2.json" \
  --signature-threshold 1 \
  --signature-key-id adopter-package-key \
  --signatures "$temporary_root/package-v2-signatures.json" \
  --output "$temporary_root/build-v2"
assert_json_ok "$temporary_root/package-v2-published.json" package
package_revision_v2=$(json_field "$temporary_root/package-v2-published.json" packageRevision)

render_runtime_config "$temporary_root/runtime-operator-v2-fast-timeout.yaml" "$temporary_root/build-v1/package" \
  "$package_revision_v1" 1 1000 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "127.0.0.1:0" \
  "asset-site-placement-acceptance-0.1.0"
asset_table=$(python3 - "$temporary_root/build-v1/package/inventories/physical-names.json" <<'PY'
import json
import sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
print(document["entities"]["asset-item"]["table"])
PY
)
psql "$adopter_migration_url" -v ON_ERROR_STOP=1 -q \
  -c "BEGIN; LOCK TABLE registry_data.\"$asset_table\" IN ACCESS SHARE MODE; SELECT pg_sleep(120);" >/dev/null &
lock_pid=$!
python3 - "$adopter_admin_url" "$adopter_production_database" "$asset_table" "$temporary_root/lock-backend-pid" <<'PY'
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit
admin, database, table, pid_output = sys.argv[1:]
parsed_admin = urlsplit(admin)
database_url = urlunsplit(
    (parsed_admin.scheme, parsed_admin.netloc, f"/{quote(database, safe='')}", parsed_admin.query, "")
)
deadline = time.time() + 20
while time.time() < deadline:
    sql = (
        "SELECT l.pid FROM pg_locks l "
        "JOIN pg_class c ON c.oid = l.relation "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        f"WHERE n.nspname = 'registry_data' AND c.relname = '{table}' "
        "AND l.mode = 'AccessShareLock' AND l.granted LIMIT 1"
    )
    result = subprocess.run(["psql", database_url, "-Atqc", sql], text=True, capture_output=True)
    if result.stdout.strip().isdigit():
        Path(pid_output).write_text(result.stdout.strip(), encoding="ascii")
        raise SystemExit(0)
    time.sleep(0.25)
raise SystemExit("table lock was not acquired")
PY
# Measure a lock-timeout refusal for the metadata-only review fixture below.
# The contender cannot mutate the table: the held AccessShareLock excludes it.
lock_probe_started=$SECONDS
if psql "$adopter_migration_url" -v ON_ERROR_STOP=1 -v VERBOSITY=sqlstate -q \
  -c "BEGIN; SET LOCAL lock_timeout = '1000ms'; SET LOCAL statement_timeout = '60s'; LOCK TABLE registry_data.\"$asset_table\" IN ACCESS EXCLUSIVE MODE; ROLLBACK;" \
  >"$temporary_root/lock-probe.stdout" 2>"$temporary_root/lock-probe.stderr"; then
  printf '%s\n' 'lock-timeout probe unexpectedly acquired the blocked table.' >&2
  exit 1
fi
if [[ "$(<"$temporary_root/lock-probe.stderr")" != *55P03* ]] || (( SECONDS - lock_probe_started > 10 )); then
  printf '%s\n' 'lock-timeout probe did not produce the expected bounded PostgreSQL refusal.' >&2
  exit 1
fi
if run_json "$temporary_root/apply-v2-locked.json" apply --runtime-config "$temporary_root/runtime-operator-v2-fast-timeout.yaml" --package "$temporary_root/build-v2/package"; then
  printf '%s\n' 'successor apply unexpectedly succeeded while the managed table was locked.' >&2
  exit 1
fi
assert_json_failure "$temporary_root/apply-v2-locked.json" apply.migration.failed
wait_ready_status "${server_url}ready" 503
python3 - "$adopter_admin_url" "$adopter_production_database" "$package_revision_v2" <<'PY'
import subprocess
import sys
from urllib.parse import quote, urlsplit, urlunsplit
admin, database, target = sys.argv[1:]
parsed_admin = urlsplit(admin)
database_url = urlunsplit(
    (parsed_admin.scheme, parsed_admin.netloc, f"/{quote(database, safe='')}", parsed_admin.query, "")
)
state = subprocess.check_output([
    "psql", database_url, "-Atqc",
    "SELECT maintenance_status || ' ' || maintenance_target_revision FROM registry_internal.registry_state"
], text=True).strip()
if state != f"failed {target}":
    raise SystemExit(f"unexpected maintenance state: {state}")
ledger = subprocess.check_output([
    "psql", database_url, "-Atqc",
    f"SELECT outcome FROM registry_internal.registry_migrations WHERE target_package_revision = '{target}'"
], text=True).strip()
if ledger != "failed":
    raise SystemExit(f"unexpected migration ledger outcome: {ledger}")
PY
lock_backend_pid=$(<"$temporary_root/lock-backend-pid")
if [[ ! "$lock_backend_pid" =~ ^[0-9]+$ ]] \
  || [[ "$(psql "$adopter_production_admin_url" -Atqc "SELECT pg_terminate_backend($lock_backend_pid)")" != "t" ]]; then
  printf '%s\n' 'external migration blocker could not be released exactly.' >&2
  exit 1
fi
wait "$lock_pid" >/dev/null 2>&1 || true
lock_pid=""

render_runtime_config "$temporary_root/runtime-operator-v2-activation.yaml" "$temporary_root/build-v1/package" \
  "$package_revision_v1" 1 60000 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "127.0.0.1:0" \
  "asset-site-placement-acceptance-0.1.0"
run_json "$temporary_root/apply-v2.json" apply --runtime-config "$temporary_root/runtime-operator-v2-activation.yaml" --package "$temporary_root/build-v2/package"
assert_json_ok "$temporary_root/apply-v2.json" apply

kill "$server_pid" >/dev/null 2>&1 || true
wait "$server_pid" >/dev/null 2>&1 || true
server_pid=""
render_runtime_config "$temporary_root/runtime-server-v2.yaml" "$temporary_root/build-v2/package" \
  "$package_revision_v2" 2 60000 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "$listener" \
  "asset-site-placement-acceptance-0.1.0"
REGISTRY_SERVER_LOG=error "$registry_server" --config "$temporary_root/runtime-server-v2.yaml" >"$temporary_root/server-v2.log" 2>&1 &
server_pid=$!
wait_ready_status "${server_url}ready" 200

asset_list_path_v2=$(entity_list_path "$temporary_root/build-v2/package" asset-item asset-operator)
http_get_json "$server_url" "$temporary_root/secrets/operator-token" \
  "$asset_list_path_v2?accessProfile=asset-operator" "$temporary_root/assets-list-v2.json"
python3 - "$temporary_root/assets-list-v2.json" <<'PY'
import json
import sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
matching = [item for item in document.get("items", []) if item.get("data", {}).get("assetCode") == "ASSET-PUBLIC-001"]
if not matching:
    raise SystemExit("created record did not survive successor activation")
if any("placementReviewNote" in item.get("data", {}) for item in matching):
    raise SystemExit("restricted successor field was disclosed")
PY

# Add an optional field AND disclose it to one profile on the existing database.
# This is a reviewed successor, not an automatic additive upgrade.
cp -R "$temporary_root/project-v2" "$temporary_root/project-v3"
python3 - "$temporary_root/project-v3/registry.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8").replace("  sequence: 2\n", "  sequence: 3\n", 1)
needle = """      - id: placement-review-note
        type: string
        required: false
        maxLength: 120
        classification: restricted
"""
grant = """        readableFields:
          - asset-code
          - label
          - asset-class
        writableFields:
          - asset-code
          - label
          - asset-class
"""
if needle not in source or grant not in source:
    raise SystemExit("reviewed successor insertion points were not found")
source = source.replace(needle, needle + """      - id: maintenance-note
        type: string
        required: false
        maxLength: 120
        classification: internal
""", 1)
source = source.replace(grant, grant.replace("          - asset-class\n", "          - asset-class\n          - maintenance-note\n"), 1)
path.write_text(source, encoding="utf-8")
PY
render_runtime_config "$temporary_root/runtime-test-v3.yaml" "$temporary_root/build-v2/package" \
  "$package_revision_v2" 2 60000 "secret:file/schema-test-v3-runtime-url" \
  "secret:file/schema-test-v3-migration-url" "127.0.0.1:0" \
  "asset-site-placement-acceptance-0.1.0"
reviewed_candidate_args=("$temporary_root/project-v3" --database-id asset-site-placement-adopter-db
  --baseline-runtime-config "$temporary_root/runtime-server-v2.yaml"
  --signature-threshold 1 --signature-key-id adopter-package-key)
if run_json "$temporary_root/missing-review-v3.json" test "${reviewed_candidate_args[@]}" \
  --runtime-config "$temporary_root/runtime-test-v3.yaml" --credentials "$temporary_root/schema-test-credentials.yaml" \
  --output "$temporary_root/schema-test-receipt-v3.json"; then
  printf '%s\n' 'readable-field successor unexpectedly bypassed review.' >&2
  exit 1
fi
assert_json_failure "$temporary_root/missing-review-v3.json" migration.review.required
[[ ! -e "$temporary_root/schema-test-receipt-v3.json" ]]
run_json "$temporary_root/diff-v3.json" diff "$temporary_root/project-v3" --runtime-config "$temporary_root/runtime-server-v2.yaml"
assert_json_ok "$temporary_root/diff-v3.json" diff

# Measure the exact target catalog through the public schema-test command on a
# separate disposable database. Only the package sequence differs. This is not
# upgrade evidence; the in-place apply and record/disclosure checks follow below.
cp -R "$temporary_root/project-v3" "$temporary_root/project-measure-v3"
sed -i.bak 's/  sequence: 3/  sequence: 1/' "$temporary_root/project-measure-v3/registry.yaml"
render_runtime_config "$temporary_root/runtime-measure-v3.yaml" "$temporary_root/empty-package-root" \
  "sha256:1111111111111111111111111111111111111111111111111111111111111111" 1 60000 \
  "secret:file/measure-v3-runtime-url" "secret:file/measure-v3-migration-url" \
  "127.0.0.1:0" "asset-site-placement-acceptance-0.1.0"
run_json "$temporary_root/measure-v3.json" test "$temporary_root/project-measure-v3" \
  --runtime-config "$temporary_root/runtime-measure-v3.yaml" --credentials "$temporary_root/schema-test-credentials.yaml" \
  --database-id asset-site-placement-adopter-db --signature-threshold 1 --signature-key-id adopter-package-key \
  --output "$temporary_root/measure-receipt-v3.json"
assert_json_ok "$temporary_root/measure-v3.json" test
schema_fingerprint_v3=$(json_field "$temporary_root/measure-v3.json" schemaFingerprint)
postgres_major=$(psql "$adopter_production_admin_url" -Atqc 'SELECT current_setting('\''server_version_num'\'')::integer / 10000')

# Test-fixture evidence only, for a metadata-only review with no authored SQL.
# The target fingerprint and lock-timeout refusal above were measured, not guessed.
python3 - "$temporary_root" "$package_revision_v2" "$schema_fingerprint_v2" "$schema_fingerprint_v3" "$postgres_major" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
changes = json.loads((root / "diff-v3.json").read_text())["changes"]
if any(change["classification"] == "unsupported" for change in changes):
    raise SystemExit("reviewed successor was incorrectly classified as unsupported")
covers = [{"code": item["change"]["code"], "target": item["change"]["target"]}
          for item in changes if item["change"]["class"] != "compatible_additive"]
if {cover["code"] for cover in covers} != {"access_profile_changed", "query_inventory_changed"}:
    raise SystemExit("reviewed successor did not have the expected permission changes")
base = "modules/asset-site-placement-core/migrations/read-maintenance-note"
descriptor = {
    "id": "read-maintenance-note", "changeClass": "access_or_disclosure_change",
    "covers": covers, "recovery": "exact_target_resume", "lockTimeoutMs": 1000,
    "statementTimeoutMs": 60000, "steps": [], "preAssertions": [], "postAssertions": [],
    "rehearsalReceiptPath": f"{base}/rehearsal.json",
}
def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
descriptor_bytes = canonical(descriptor)
receipt = {
    "priorRevision": sys.argv[2], "priorSchemaFingerprint": sys.argv[3],
    "planSha256": "sha256:" + hashlib.sha256(descriptor_bytes).hexdigest(),
    "sqlSha256": [], "assertionSha256": [], "fixtureInventory": [], "postgresMajor": int(sys.argv[5]),
    "rowAssertions": [], "finalSchemaFingerprint": sys.argv[4],
    "proofs": {"lockTimeout": True, "chunkResume": False, "destructiveResume": False},
}
directory = root / "review-v3" / base
directory.mkdir(parents=True)
(directory / "descriptor.json").write_bytes(descriptor_bytes)
(directory / "rehearsal.json").write_bytes(canonical(receipt))
PY
reviewed_candidate_args+=(--reviewed-migrations "$temporary_root/review-v3")
review_receipt="$temporary_root/review-v3/modules/asset-site-placement-core/migrations/read-maintenance-note/rehearsal.json"
cp "$review_receipt" "$temporary_root/review-receipt-v3.original.json"
python3 - "$review_receipt" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
receipt = json.loads(path.read_text())
receipt["finalSchemaFingerprint"] = "sha256:" + "0" * 64
path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")), encoding="ascii")
PY
if run_json "$temporary_root/mismatched-review-v3.json" test "${reviewed_candidate_args[@]}" \
  --runtime-config "$temporary_root/runtime-test-v3.yaml" --credentials "$temporary_root/schema-test-credentials.yaml" \
  --output "$temporary_root/schema-test-receipt-v3.json"; then
  printf '%s\n' 'reviewed schema fingerprint unexpectedly overrode the database measurement.' >&2
  exit 1
fi
assert_json_failure "$temporary_root/mismatched-review-v3.json" migration.review.fingerprint_mismatch
[[ ! -e "$temporary_root/schema-test-receipt-v3.json" ]]
cp "$temporary_root/review-receipt-v3.original.json" "$review_receipt"
run_json "$temporary_root/schema-test-v3.json" test "${reviewed_candidate_args[@]}" \
  --runtime-config "$temporary_root/runtime-test-v3.yaml" --credentials "$temporary_root/schema-test-credentials.yaml" \
  --output "$temporary_root/schema-test-receipt-v3.json"
assert_json_ok "$temporary_root/schema-test-v3.json" test
[[ "$(json_field "$temporary_root/schema-test-v3.json" schemaFingerprint)" == "$schema_fingerprint_v3" ]]
reviewed_package_args=("${reviewed_candidate_args[@]}" --schema-fingerprint "$schema_fingerprint_v3"
  --test-receipt "$temporary_root/schema-test-receipt-v3.json" --output "$temporary_root/build-v3")
run_json "$temporary_root/package-v3-awaiting.json" package "${reviewed_package_args[@]}"
assert_json_ok "$temporary_root/package-v3-awaiting.json" package
sign_file_hex "$temporary_root/package-signer.pem" "$temporary_root/build-v3/signing-input.json" "$temporary_root/package-v3.sighex"
write_signature_document "adopter-package-key" "$temporary_root/package-v3.sighex" "$temporary_root/package-v3-signatures.json"
run_json "$temporary_root/package-v3-published.json" package "${reviewed_package_args[@]}" --signatures "$temporary_root/package-v3-signatures.json"
assert_json_ok "$temporary_root/package-v3-published.json" package
package_revision_v3=$(json_field "$temporary_root/package-v3-published.json" packageRevision)
if ! run_json "$temporary_root/apply-v3.json" apply --runtime-config "$temporary_root/runtime-server-v2.yaml" --package "$temporary_root/build-v3/package"; then
  # Compare catalog metadata only. Never print runtime URLs or stored records.
  measure_admin_url=$(derive_admin_database_url "$adopter_measure_v3_database")
  column_order_sql="SELECT string_agg(a.attname, ',' ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid = 'registry_data.\"$asset_table\"'::regclass AND a.attnum > 0 AND NOT a.attisdropped"
  if [[ "$(psql "$adopter_production_admin_url" -Atqc "$column_order_sql")" != "$(psql "$measure_admin_url" -Atqc "$column_order_sql")" ]]; then
    printf '%s\n' 'reviewed activation failed: installed column order differs from the fresh target rehearsal.' >&2
  fi
  exit 1
fi
assert_json_ok "$temporary_root/apply-v3.json" apply
kill "$server_pid" >/dev/null 2>&1 || true
wait "$server_pid" >/dev/null 2>&1 || true
server_pid=""
render_runtime_config "$temporary_root/runtime-server-v3.yaml" "$temporary_root/build-v3/package" \
  "$package_revision_v3" 3 60000 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "$listener" "asset-site-placement-acceptance-0.1.0"
REGISTRY_SERVER_LOG=error "$registry_server" --config "$temporary_root/runtime-server-v3.yaml" >"$temporary_root/server-v3.log" 2>&1 &
server_pid=$!
wait_ready_status "${server_url}ready" 200
printf '%s\n' '{"operation":"create","data":{"assetCode":"ASSET-PUBLIC-002","label":"Reviewed field asset","assetClass":"equipment","maintenanceNote":"Synthetic maintenance note"}}' >"$temporary_root/assets-create-v3.jsonl"
run_json "$temporary_root/data-import-v3.json" data import --package "$temporary_root/build-v3/package" \
  --server-url "$server_url" --access-token-file "$temporary_root/secrets/operator-token" \
  --entity asset-item --profile asset-operator --operation create --input "$temporary_root/assets-create-v3.jsonl" \
  --checkpoint "$temporary_root/assets-import-v3.checkpoint.json"
assert_json_ok "$temporary_root/data-import-v3.json" "data import"
asset_list_path_v3=$(entity_list_path "$temporary_root/build-v3/package" asset-item asset-operator)
for profile in operator planner; do
  access_profile=asset-operator
  [[ "$profile" != planner ]] || access_profile=site-planner
  http_get_json "$server_url" "$temporary_root/secrets/$profile-token" \
    "$asset_list_path_v3?accessProfile=$access_profile" "$temporary_root/assets-$profile-v3.json"
done
python3 - "$temporary_root/assets-operator-v3.json" "$temporary_root/assets-planner-v3.json" <<'PY'
import json
import sys
operator, planner = [json.load(open(path, encoding="utf-8"))["items"] for path in sys.argv[1:]]
records = {item["data"]["assetCode"]: item["data"] for item in operator}
if "ASSET-PUBLIC-001" not in records:
    raise SystemExit("existing record did not survive the reviewed upgrade")
if records.get("ASSET-PUBLIC-002", {}).get("maintenanceNote") != "Synthetic maintenance note":
    raise SystemExit("authorized profile could not round-trip the reviewed field")
if not any(item["data"]["assetCode"] == "ASSET-PUBLIC-002" for item in planner):
    raise SystemExit("planner disclosure test did not observe the new record")
if any("maintenanceNote" in item["data"] for item in planner):
    raise SystemExit("reviewed field leaked to the profile without its grant")
if any("placementReviewNote" in item["data"] for item in operator + planner):
    raise SystemExit("restricted field was disclosed after the reviewed upgrade")
PY

server_hash_after=$(sha256_file "$registry_server")
if [[ "$server_hash_before" != "$server_hash_after" ]]; then
  printf '%s\n' 'registry-server binary changed during the adopter workflow.' >&2
  exit 1
fi

REGISTRY_SERVER_SKIP_BUILD=1 "$script_dir/test-historical-workflow.sh"

printf '%s\n' 'Registry Server clean adopter workflow passed'
