#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
fixture="$repository_root/products/breg/acceptance/household-history"
temporary_root=""
breg_pid=""
history_tls_ca_pem_path=""
history_admin_url=""
history_migration_role=""
history_runtime_role=""
history_author_role=""
history_databases=()

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "$1 is required for the historical workflow." >&2
    exit 2
  fi
}

checkpoint() {
  printf 'historical workflow: %s\n' "$1" >&2
}

cleanup() {
  if [[ "${BREG_HISTORY_KEEP_TEMP:-0}" == "1" ]]; then
    printf '%s\n' "historical workflow preserved temporary root: $temporary_root" >&2
    return 0
  fi
  if [[ -n "${breg_pid:-}" ]]; then
    kill "$breg_pid" >/dev/null 2>&1 || true
    wait "$breg_pid" >/dev/null 2>&1 || true
  fi
  for history_database_to_drop in "${history_databases[@]}"; do
    psql "$history_admin_url" -v ON_ERROR_STOP=1 -q \
      -c "DROP DATABASE IF EXISTS \"$history_database_to_drop\" WITH (FORCE);" >/dev/null 2>&1 || true
  done
  if [[ -n "${history_migration_role:-}" && -n "${history_runtime_role:-}" && -n "${history_author_role:-}" ]]; then
    psql "$history_admin_url" -v ON_ERROR_STOP=1 -q \
      -c "DROP ROLE IF EXISTS \"$history_author_role\"; DROP ROLE IF EXISTS \"$history_runtime_role\"; DROP ROLE IF EXISTS \"$history_migration_role\";" >/dev/null 2>&1 || true
  fi
  case "$temporary_root" in
    "$repository_root"/.breg-history.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    "") ;;
    *)
      printf '%s\n' 'historical workflow temporary directory did not match its validated location' >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

require_command openssl
require_command psql

if [[ -z "${BREG_TEST_DATABASE_URL:-}" ]]; then
  printf '%s\n' 'BREG_TEST_DATABASE_URL must be set for the historical workflow.' >&2
  exit 2
fi
if [[ -z "${BREG_TEST_TLS_CA_PEM_PATH:-}" ]]; then
  printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH must be set for the historical workflow after the PostgreSQL TLS proof.' >&2
  exit 2
fi
history_tls_ca_pem_path=$BREG_TEST_TLS_CA_PEM_PATH
case "$history_tls_ca_pem_path" in
  /*) ;;
  *)
    printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH must be an absolute file path.' >&2
    exit 2
    ;;
esac
case "$history_tls_ca_pem_path" in
  *$'\n'* | */../* | */..)
    printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH must be a lexical file path without parent traversal.' >&2
    exit 2
    ;;
esac
if [[ -L "$history_tls_ca_pem_path" || ! -f "$history_tls_ca_pem_path" ]]; then
  printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH must name an existing regular file.' >&2
  exit 2
fi
if [[ ! -s "$history_tls_ca_pem_path" ]]; then
  printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH must not be empty.' >&2
  exit 2
fi
ca_pem_bytes=$(wc -c <"$history_tls_ca_pem_path")
if [[ "$ca_pem_bytes" -gt 1048576 ]]; then
  printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH exceeds the 1 MiB CA bound.' >&2
  exit 2
fi
openssl x509 -in "$history_tls_ca_pem_path" -noout >/dev/null 2>&1 || {
  printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH must contain a PEM certificate.' >&2
  exit 2
}

umask 077
checkpoint "preparing disposable TLS PostgreSQL resources and local credentials"
temporary_root=$(mktemp -d "$repository_root/.breg-history.XXXXXX")
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

bregctl="$repository_root/target/debug/bregctl"
breg="$repository_root/target/debug/breg"

if [[ "${BREG_SKIP_BUILD:-0}" != "1" ]]; then
  cargo build --manifest-path "$repository_root/Cargo.toml" --locked \
    -p registry-bregctl \
    -p registry-breg \
    --features registry-breg/runtime
fi
export SSL_CERT_FILE="$history_tls_ca_pem_path"

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
    if isinstance(value, list):
        value = value[int(part)]
    else:
        value = value[part]
print(value)
PY
}

json_field_literal() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    if isinstance(value, list):
        value = value[int(part)]
    else:
        value = value[part]
print(json.dumps(value, separators=(",", ":")))
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
    "databaseId": "household-history-adopter-db",
    "environment": "acceptance",
    "instanceId": "household-history-acceptance",
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
  local scope=$5
  local subjects=$6
  local output=$7
  python3 - "$key_id" "$principal" "$purpose" "$scope" "$subjects" "$output.signing-input" <<'PY'
import base64
import json
import sys
import time

def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=").decode("ascii")

now = int(time.time())
claims = {
    "aud": "urn:breg:history",
    "client_id": "registry-history-client",
    "exp": now + 3600,
    "iat": now,
    "iss": "https://issuer.example/history",
    "jti": f"history-{now}-{sys.argv[2]}-{sys.argv[3] or 'none'}",
    "registry_principal": sys.argv[2],
    "sub": sys.argv[2],
}
if sys.argv[3]:
    claims["registry_purpose"] = sys.argv[3]
if sys.argv[4]:
    claims["scope"] = sys.argv[4]
if sys.argv[5]:
    claims["subjects"] = sys.argv[5].split(",")
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

render_runtime_config() {
  local output=$1
  local package_root=$2
  local active_revision=$3
  local active_sequence=$4
  local runtime_ref=$5
  local migration_ref=$6
  local listener=$7
  local compiler_source_revision=$8
  cat >"$output" <<EOF
apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: $listener
identity:
  environment: acceptance
  instanceId: household-history-acceptance
  databaseId: household-history-adopter-db
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
    migration: $history_migration_role
    runtime: $history_runtime_role
package:
  root: $package_root
  trustAnchorPath: $temporary_root/package-trust-anchor.json
  compilerSourceRevision: $compiler_source_revision
  activeRevision: $active_revision
  activeSequence: $active_sequence
authentication:
  oidc:
    issuer: https://issuer.example/history
    audience: urn:breg:history
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-history-client]
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
EOF
}

run_json() {
  local output=$1
  local command=$2
  local status
  shift
  if "$bregctl" --format json "$@" >"$output"; then
    return 0
  else
    status=$?
  fi
  python3 - "$output" "$command" <<'PY'
import json
import sys
try:
    document = json.load(open(sys.argv[1], encoding="utf-8"))
    diagnostics = [
        f"{item.get('code')} at {item.get('path')}: {item.get('message')}"
        for item in document.get("diagnostics", [])
        if item.get("code")
    ]
except Exception:
    diagnostics = []
summary = "; ".join(diagnostics) if diagnostics else "unavailable"
print(f"bregctl {sys.argv[2]} refused; diagnostics: {summary}", file=sys.stderr)
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

derive_history_urls() {
  local database=$1
  python3 - "$BREG_TEST_DATABASE_URL" "$database" "$history_migration_role" "$history_runtime_role" "$history_password" <<'PY'
import sys
from urllib.parse import quote, urlsplit, urlunsplit
admin = urlsplit(sys.argv[1])
database, migration_role, runtime_role, password = sys.argv[2:]
if admin.scheme not in {"postgres", "postgresql"} or not admin.hostname:
    raise SystemExit("BREG_TEST_DATABASE_URL must be a PostgreSQL URL")
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
  python3 - "$BREG_TEST_DATABASE_URL" "$database" <<'PY'
import sys
from urllib.parse import quote, urlsplit, urlunsplit
admin = urlsplit(sys.argv[1])
if admin.scheme not in {"postgres", "postgresql"} or not admin.hostname:
    raise SystemExit("BREG_TEST_DATABASE_URL must be a PostgreSQL URL")
print(urlunsplit((admin.scheme, admin.netloc, f"/{quote(sys.argv[2], safe='')}", admin.query, "")))
PY
}

write_database_url_secrets() {
  local database=$1
  local runtime_secret=$2
  local migration_secret=$3
  local urls
  urls=$(derive_history_urls "$database")
  printf '%s' "$(printf '%s\n' "$urls" | sed -n '2p')" >"$temporary_root/secrets/$runtime_secret"
  printf '%s' "$(printf '%s\n' "$urls" | sed -n '1p')" >"$temporary_root/secrets/$migration_secret"
}

provision_history_database() {
  local database=$1
  local admin_database_url
  admin_database_url=$(derive_admin_database_url "$database")
  psql "$history_admin_url" -v ON_ERROR_STOP=1 -q \
    -c "CREATE DATABASE \"$database\";"
  psql "$admin_database_url" -v ON_ERROR_STOP=1 -q \
    -c "CREATE EXTENSION IF NOT EXISTS btree_gist;" \
    -c "REVOKE ALL ON DATABASE \"$database\" FROM PUBLIC;" \
    -c "GRANT CONNECT ON DATABASE \"$database\" TO \"$history_migration_role\", \"$history_runtime_role\", \"$history_author_role\";" \
    -c "CREATE SCHEMA registry_internal AUTHORIZATION \"$history_migration_role\";" \
    -c "CREATE SCHEMA registry_data AUTHORIZATION \"$history_migration_role\";" \
    -c "CREATE SCHEMA registry_source AUTHORIZATION \"$history_migration_role\";" \
    -c "CREATE SCHEMA registry_derived AUTHORIZATION \"$history_migration_role\";" \
    -c "CREATE SCHEMA registry_context AUTHORIZATION \"$history_migration_role\";" \
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

http_json() {
  local method=$1
  local base_url=$2
  local token_file=$3
  local path_and_query=$4
  local idempotency_key=$5
  local content_type=$6
  local body_file=$7
  local output=$8
  python3 - "$method" "$base_url" "$token_file" "$path_and_query" "$idempotency_key" "$content_type" "$body_file" "$output" <<'PY'
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

method, base_url, token_file, path_and_query, idempotency_key, content_type, body_file, output = sys.argv[1:]
token = Path(token_file).read_text(encoding="ascii").strip()
headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
data = None
if body_file:
    data = Path(body_file).read_bytes()
    headers["Content-Type"] = content_type
if idempotency_key:
    headers["Idempotency-Key"] = idempotency_key
url = urllib.parse.urljoin(base_url, path_and_query.lstrip("/"))
request = urllib.request.Request(url, data=data, method=method, headers=headers)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        status = response.status
        body = response.read()
        response_headers = dict(response.headers.items())
except urllib.error.HTTPError as error:
    status = error.code
    body = error.read()
    response_headers = dict(error.headers.items())
if body:
    json.loads(body)
Path(output).write_bytes(body)
Path(output + ".status").write_text(str(status), encoding="ascii")
Path(output + ".headers.json").write_text(json.dumps(response_headers, sort_keys=True), encoding="utf-8")
PY
}

assert_status() {
  local output=$1
  local expected=$2
  local actual
  actual=$(<"$output.status")
  if [[ "$actual" != "$expected" ]]; then
    printf '%s\n' "expected HTTP $expected for $output, got $actual" >&2
    python3 - "$output" <<'PY' >&2
import json
import sys
try:
    document = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    raise SystemExit(0)
code = document.get("code")
detail = document.get("detail")
if code or detail:
    print(f"problem: {code or 'unknown'}: {detail or ''}")
PY
    exit 1
  fi
}

assert_snapshot_reference() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
from uuid import UUID
document = json.load(open(sys.argv[1], encoding="utf-8"))
value = document
for part in sys.argv[2].split("."):
    value = value[part]
if not isinstance(value, str) or len(value) != 42 or not value.startswith("breg1_"):
    raise SystemExit(f"invalid snapshot reference: {value!r}")
UUID(value[6:])
PY
}

assert_problem_code() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
if document.get("code") != sys.argv[2]:
    raise SystemExit(f"expected problem code {sys.argv[2]}, got {document.get('code')}")
PY
}

response_header() {
  python3 - "$1.headers.json" "$2" <<'PY'
import json
import sys
headers = json.load(open(sys.argv[1], encoding="utf-8"))
target = sys.argv[2].lower()
for key, value in headers.items():
    if key.lower() == target:
        print(value)
        raise SystemExit(0)
raise SystemExit(f"response header {sys.argv[2]} was not found")
PY
}

response_header_literal() {
  python3 - "$1.headers.json" "$2" <<'PY'
import json
import sys
headers = json.load(open(sys.argv[1], encoding="utf-8"))
target = sys.argv[2].lower()
for key, value in headers.items():
    if key.lower() == target:
        print(json.dumps(value, separators=(",", ":")))
        raise SystemExit(0)
raise SystemExit(f"response header {sys.argv[2]} was not found")
PY
}

package_project() {
  local project=$1
  local runtime_test_config=$2
  local output_dir=$3
  local report_prefix=$4
  local baseline_config=${5:-}

  run_json "$temporary_root/$report_prefix-check.json" check "$project" --production
  assert_json_ok "$temporary_root/$report_prefix-check.json" check
  run_json "$temporary_root/$report_prefix-access.json" explain access "$project"
  assert_json_ok "$temporary_root/$report_prefix-access.json" explain
  (
    cd "$temporary_root"
    mkdir -p "$report_prefix-generated"
    for selector in openapi schemas manifest metadata sql; do
      "$bregctl" generate "$selector" "$project" --output "./$report_prefix-$selector"
      cp -R "./$report_prefix-$selector/." "$report_prefix-generated"
    done
  )

  local test_args=(
    test "$project"
    --runtime-config "$runtime_test_config"
    --credentials "$temporary_root/schema-test-credentials.yaml"
    --database-id household-history-adopter-db
    --signature-threshold 1
    --signature-key-id history-package-key
    --output "$temporary_root/$report_prefix-schema-test-receipt.json"
  )
  if [[ -n "$baseline_config" ]]; then
    test_args+=(--baseline-runtime-config "$baseline_config")
  fi
  run_json "$temporary_root/$report_prefix-schema-test.json" "${test_args[@]}"
  assert_json_ok "$temporary_root/$report_prefix-schema-test.json" test
  local schema_fingerprint
  schema_fingerprint=$(json_field "$temporary_root/$report_prefix-schema-test.json" schemaFingerprint)

  local package_args=(
    package "$project"
    --database-id household-history-adopter-db
    --schema-fingerprint "$schema_fingerprint"
    --test-receipt "$temporary_root/$report_prefix-schema-test-receipt.json"
    --signature-threshold 1
    --signature-key-id history-package-key
    --output "$output_dir"
  )
  if [[ -n "$baseline_config" ]]; then
    package_args+=(--baseline-runtime-config "$baseline_config")
  fi
  run_json "$temporary_root/$report_prefix-package-awaiting.json" "${package_args[@]}"
  assert_json_ok "$temporary_root/$report_prefix-package-awaiting.json" package
  sign_file_hex "$temporary_root/package-signer.pem" "$output_dir/signing-input.json" "$temporary_root/$report_prefix.sighex"
  write_signature_document "history-package-key" "$temporary_root/$report_prefix.sighex" "$temporary_root/$report_prefix-signatures.json"
  package_args+=(--signatures "$temporary_root/$report_prefix-signatures.json")
  run_json "$temporary_root/$report_prefix-package-published.json" "${package_args[@]}"
  assert_json_ok "$temporary_root/$report_prefix-package-published.json" package
  PACKAGE_REVISION_RESULT=$(json_field "$temporary_root/$report_prefix-package-published.json" packageRevision)
}

stop_server() {
  if [[ -n "${breg_pid:-}" ]]; then
    kill "$breg_pid" >/dev/null 2>&1 || true
    wait "$breg_pid" >/dev/null 2>&1 || true
    breg_pid=""
  fi
}

start_server() {
  local config=$1
  local url=$2
  local log=$3
  BREG_LOG=error "$breg" --config "$config" >"$log" 2>&1 &
  breg_pid=$!
  wait_ready_status "${url}ready" 200
}

assert_snapshot_answer() {
  local output=$1
  local subject=$2
  local expected_group=$3
  local expected_valid_from=$4
  local expected_valid_to=$5
  local expected_valid_at=${6:-2026-06-05}
  python3 - "$output" "$subject" "$expected_group" "$expected_valid_from" "$expected_valid_to" "$expected_valid_at" <<'PY'
import json
import sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
subject, expected_group, expected_valid_from, expected_valid_to, expected_valid_at = sys.argv[2:]
items = [
    item for item in document.get("items", [])
    if item.get("domainData", {}).get("subject") == subject
]
if len(items) != 1:
    raise SystemExit(f"expected one historical item for {subject}, got {len(items)}")
item = items[0]
data = item["domainData"]
if data.get("group") != expected_group:
    raise SystemExit(f"expected group {expected_group}, got {data.get('group')}")
if data.get("validFrom") != expected_valid_from:
    raise SystemExit(f"expected validFrom {expected_valid_from}, got {data.get('validFrom')}")
if expected_valid_to == "null":
    if data.get("validTo") is not None:
        raise SystemExit(f"expected open end, got {data.get('validTo')}")
elif data.get("validTo") != expected_valid_to:
    raise SystemExit(f"expected validTo {expected_valid_to}, got {data.get('validTo')}")
if not isinstance(item.get("revisionIdentifier"), str) or not item["revisionIdentifier"].isdigit() or int(item["revisionIdentifier"]) < 1:
    raise SystemExit("historical item did not include its actual revision")
if document.get("validAt") != expected_valid_at:
    raise SystemExit(f"validAt was not normalized: {document.get('validAt')}")
PY
}

assert_consumer_decisions() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import json
import sys
first = json.load(open(sys.argv[1], encoding="utf-8"))
second = json.load(open(sys.argv[2], encoding="utf-8"))
ledger_path = sys.argv[3]
package_revision = sys.argv[4]
def decision(document, decision_id):
    item = document["items"][0]
    return {
        "decisionId": decision_id,
        "subject": item["domainData"]["subject"],
        "resultGroup": item["domainData"]["group"],
        "inputRevision": item["revisionIdentifier"],
        "snapshot": document["snapshot"],
        "effectiveDate": document["validAt"],
        "rulePackageRevision": package_revision,
    }
original = decision(first, "decision-before-correction")
reconsidered = decision(second, "decision-after-correction")
if original["resultGroup"] != "B" or reconsidered["resultGroup"] != "A":
    raise SystemExit("consumer decision fixture did not observe the intended B then A answers")
if original["decisionId"] == reconsidered["decisionId"]:
    raise SystemExit("reconsideration must be a distinct downstream decision")
if original["snapshot"] == reconsidered["snapshot"]:
    raise SystemExit("correction must use a distinct snapshot input")
ledger = {"originalDecision": original, "reconsideration": reconsidered}
open(ledger_path, "w", encoding="utf-8").write(json.dumps(ledger, sort_keys=True, indent=2))
PY
}

mkdir -p "$temporary_root/secrets" "$temporary_root/empty-package-root"
chmod 700 "$temporary_root/secrets"
printf '%s' '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' >"$temporary_root/secrets/audit-key"
printf '%s' 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789' >"$temporary_root/secrets/cursor-key"

history_suffix="rshistory$(date +%s)$$"
history_schema_test_v1_database="breg_hist_v1_${history_suffix}"
history_schema_test_v2_database="breg_hist_v2_${history_suffix}"
history_schema_test_v3_database="breg_hist_v3_${history_suffix}"
history_production_database="breg_hist_prod_${history_suffix}"
history_databases=("$history_schema_test_v1_database" "$history_schema_test_v2_database" "$history_schema_test_v3_database" "$history_production_database")
history_migration_role="breg_hist_migration_${history_suffix}"
history_runtime_role="breg_hist_runtime_${history_suffix}"
history_author_role="breg_hist_author_${history_suffix}"
history_password="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(18))
PY
)"
history_admin_url=$BREG_TEST_DATABASE_URL

psql "$history_admin_url" -v ON_ERROR_STOP=1 -q \
  -c "CREATE ROLE \"$history_migration_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$history_password';" \
  -c "CREATE ROLE \"$history_runtime_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$history_password';" \
  -c "CREATE ROLE \"$history_author_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$history_password';"

for history_database in "${history_databases[@]}"; do
  provision_history_database "$history_database"
done

history_urls=$(derive_history_urls "$history_production_database")
history_migration_url=$(printf '%s\n' "$history_urls" | sed -n '1p')
history_runtime_url=$(printf '%s\n' "$history_urls" | sed -n '2p')
history_production_admin_url=$(derive_admin_database_url "$history_production_database")
printf '%s' "$history_runtime_url" >"$temporary_root/secrets/production-runtime-url"
printf '%s' "$history_migration_url" >"$temporary_root/secrets/production-migration-url"
write_database_url_secrets "$history_schema_test_v1_database" schema-test-v1-runtime-url schema-test-v1-migration-url
write_database_url_secrets "$history_schema_test_v2_database" schema-test-v2-runtime-url schema-test-v2-migration-url
write_database_url_secrets "$history_schema_test_v3_database" schema-test-v3-runtime-url schema-test-v3-migration-url

openssl genpkey -algorithm ED25519 -out "$temporary_root/package-signer.pem" >/dev/null 2>&1
openssl genpkey -algorithm ED25519 -out "$temporary_root/oidc-signer.pem" >/dev/null 2>&1
chmod 600 "$temporary_root/package-signer.pem" "$temporary_root/oidc-signer.pem"
write_public_jwk "$temporary_root/package-signer.pem" "history-package-key" "$temporary_root/package-signer.public.jwk"
write_public_jwk "$temporary_root/oidc-signer.pem" "history-oidc-key" "$temporary_root/oidc-signer.public.jwk"
write_trust_anchor "$temporary_root/package-signer.public.jwk" "$temporary_root/package-trust-anchor.json"
write_jwks "$temporary_root/oidc-signer.public.jwk" "$temporary_root/secrets/oidc-jwks"

write_jwt "$temporary_root/oidc-signer.pem" "history-oidc-key" "synthetic-history-operator" "history-maintenance" \
  "history-maintain" "household-001,household-002,household-003,household-journey-schema-test" "$temporary_root/secrets/operator-token"
write_jwt "$temporary_root/oidc-signer.pem" "history-oidc-key" "synthetic-eligibility-consumer" "eligibility-evaluation" \
  "eligibility-read" "household-001,household-002,household-003,household-journey-schema-test" "$temporary_root/secrets/consumer-token"
write_jwt "$temporary_root/oidc-signer.pem" "history-oidc-key" "synthetic-eligibility-consumer" "" \
  "eligibility-read" "household-001,household-002,household-003,household-journey-schema-test" "$temporary_root/secrets/consumer-no-purpose-token"

cat >"$temporary_root/schema-test-credentials.yaml" <<'EOF'
apiVersion: registry.registrystack.org/breg-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings:
  - {journeyId: household-history-caller-surfaces, stepId: create-initial-membership, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: household-history-caller-surfaces, stepId: get-initial-membership, credential: {type: bearer, tokenRef: secret:file/operator-token}}
  - {journeyId: household-history-caller-surfaces, stepId: consumer-lists-initial-membership, credential: {type: bearer, tokenRef: secret:file/consumer-token}}
  - {journeyId: household-history-caller-surfaces, stepId: consumer-without-purpose-cannot-list-memberships, credential: {type: bearer, tokenRef: secret:file/consumer-no-purpose-token}}
EOF

render_runtime_config "$temporary_root/runtime-test-v1.yaml" "$temporary_root/empty-package-root" \
  "sha256:1111111111111111111111111111111111111111111111111111111111111111" 1 \
  "secret:file/schema-test-v1-runtime-url" "secret:file/schema-test-v1-migration-url" \
  "127.0.0.1:0" "household-history-acceptance-0.1.0"

checkpoint "building and schema-testing signed v1 package"
PACKAGE_REVISION_RESULT=""
package_project "$fixture" "$temporary_root/runtime-test-v1.yaml" "$temporary_root/build-v1" v1
package_revision_v1=$PACKAGE_REVISION_RESULT
render_runtime_config "$temporary_root/runtime-operator-v1.yaml" "$temporary_root/build-v1/package" \
  "$package_revision_v1" 1 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "127.0.0.1:0" \
  "household-history-acceptance-0.1.0"
checkpoint "applying v1 package"
run_json "$temporary_root/apply-v1.json" apply --runtime-config "$temporary_root/runtime-operator-v1.yaml" --package "$temporary_root/build-v1/package" --initial
assert_json_ok "$temporary_root/apply-v1.json" apply
run_json "$temporary_root/verify-v1.json" verify --runtime-config "$temporary_root/runtime-operator-v1.yaml"
assert_json_ok "$temporary_root/verify-v1.json" verify

server_hash_before=$(sha256_file "$breg")
listener=$(select_free_listener)
server_url="http://$listener/"
render_runtime_config "$temporary_root/runtime-server-v1.yaml" "$temporary_root/build-v1/package" \
  "$package_revision_v1" 1 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "$listener" \
  "household-history-acceptance-0.1.0"
checkpoint "starting v1 HTTP runtime"
start_server "$temporary_root/runtime-server-v1.yaml" "$server_url" "$temporary_root/server-v1.log"

checkpoint "running v1 correction and historical snapshot journey"
cat >"$temporary_root/create-a.json" <<'EOF'
{"data":{"subject":"household-001","group":"A","validFrom":"2026-01-01","sourceReference":"initial-membership"}}
EOF
http_json POST "$server_url" "$temporary_root/secrets/operator-token" \
  "/v1/records/memberships?accessProfile=registry-operator" initial-a application/json \
  "$temporary_root/create-a.json" "$temporary_root/create-a-response.json"
assert_status "$temporary_root/create-a-response.json" 201
assert_snapshot_reference "$temporary_root/create-a-response.json" data.snapshot
a_id=$(json_field "$temporary_root/create-a-response.json" data.recordIdentifier)
a_etag=$(response_header_literal "$temporary_root/create-a-response.json" ETag)

cat >"$temporary_root/move-june.json" <<EOF
{"items":[
  {"operation":"patch","recordId":"$a_id","ifMatch":$a_etag,"patch":[
    {"op":"replace","path":"/data/validTo","value":"2026-06-01"},
    {"op":"replace","path":"/data/sourceReference","value":"reported-move"}
  ]},
  {"operation":"create","data":{"subject":"household-001","group":"B","validFrom":"2026-06-01","sourceReference":"reported-move"}}
]}
EOF
http_json POST "$server_url" "$temporary_root/secrets/operator-token" \
  "/v1/records/memberships:batch?accessProfile=registry-operator" june-move application/json \
  "$temporary_root/move-june.json" "$temporary_root/move-june-response.json"
assert_status "$temporary_root/move-june-response.json" 200
assert_snapshot_reference "$temporary_root/move-june-response.json" snapshot
first_snapshot=$(json_field "$temporary_root/move-june-response.json" snapshot)
b_id=$(json_field "$temporary_root/move-june-response.json" results.1.id)
b_etag=$(json_field_literal "$temporary_root/move-june-response.json" results.1.etag)
a_move_etag=$(json_field_literal "$temporary_root/move-june-response.json" results.0.etag)

http_json POST "$server_url" "$temporary_root/secrets/operator-token" \
  "/v1/records/memberships:batch?accessProfile=registry-operator" june-move application/json \
  "$temporary_root/move-june.json" "$temporary_root/move-june-replay.json"
assert_status "$temporary_root/move-june-replay.json" 200
cmp "$temporary_root/move-june-response.json" "$temporary_root/move-june-replay.json" >/dev/null

http_json GET "$server_url" "$temporary_root/secrets/consumer-token" \
  "/v1/records/memberships:snapshot?accessProfile=eligibility-consumer&snapshot=$first_snapshot&validAt=2026-06-05" "" "" "" \
  "$temporary_root/consumer-first-snapshot.json"
assert_status "$temporary_root/consumer-first-snapshot.json" 200
assert_snapshot_answer "$temporary_root/consumer-first-snapshot.json" household-001 B 2026-06-01 null

first_outbox_count=$(psql "$history_production_admin_url" -Atqc "SELECT count(*) FROM registry_internal.registry_outbox")
sleep 1
second_outbox_count=$(psql "$history_production_admin_url" -Atqc "SELECT count(*) FROM registry_internal.registry_outbox")
if [[ "$first_outbox_count" != "$second_outbox_count" ]]; then
  printf '%s\n' 'outbox changed after only advancing wall-clock time.' >&2
  exit 1
fi

cat >"$temporary_root/correction-july.json" <<EOF
{"changeContext":{"kind":"correction","reasonCode":"effective-date-corrected","sourceReferences":["case-document:history-correction-001"]},"items":[
  {"operation":"patch","recordId":"$a_id","ifMatch":$a_move_etag,"patch":[
    {"op":"replace","path":"/data/validTo","value":"2026-06-15"},
    {"op":"replace","path":"/data/sourceReference","value":"corrected-effective-date"}
  ]},
  {"operation":"patch","recordId":"$b_id","ifMatch":$b_etag,"patch":[
    {"op":"replace","path":"/data/validFrom","value":"2026-06-15"},
    {"op":"replace","path":"/data/sourceReference","value":"corrected-effective-date"}
  ]}
]}
EOF
http_json POST "$server_url" "$temporary_root/secrets/operator-token" \
  "/v1/records/memberships:batch?accessProfile=registry-operator" july-correction application/json \
  "$temporary_root/correction-july.json" "$temporary_root/correction-july-response.json"
assert_status "$temporary_root/correction-july-response.json" 200
assert_snapshot_reference "$temporary_root/correction-july-response.json" snapshot
second_snapshot=$(json_field "$temporary_root/correction-july-response.json" snapshot)

http_json POST "$server_url" "$temporary_root/secrets/operator-token" \
  "/v1/records/memberships:batch?accessProfile=registry-operator" stale-correction application/json \
  "$temporary_root/correction-july.json" "$temporary_root/stale-correction-response.json"
assert_status "$temporary_root/stale-correction-response.json" 412
assert_problem_code "$temporary_root/stale-correction-response.json" precondition.failed

http_json GET "$server_url" "$temporary_root/secrets/consumer-token" \
  "/v1/records/memberships:snapshot?accessProfile=eligibility-consumer&snapshot=$second_snapshot&validAt=2026-06-05" "" "" "" \
  "$temporary_root/consumer-second-snapshot.json"
assert_status "$temporary_root/consumer-second-snapshot.json" 200
assert_snapshot_answer "$temporary_root/consumer-second-snapshot.json" household-001 A 2026-01-01 2026-06-15
assert_consumer_decisions "$temporary_root/consumer-first-snapshot.json" "$temporary_root/consumer-second-snapshot.json" \
  "$temporary_root/consumer-decision-ledger.json" "$package_revision_v1"
checkpoint "v1 correction journey retained consumer decision and reconsideration inputs"

cat >"$temporary_root/create-second-a.json" <<'EOF'
{"data":{"subject":"household-002","group":"A","validFrom":"2026-01-01","sourceReference":"initial-membership"}}
EOF
http_json POST "$server_url" "$temporary_root/secrets/operator-token" \
  "/v1/records/memberships?accessProfile=registry-operator" second-initial-a application/json \
  "$temporary_root/create-second-a.json" "$temporary_root/create-second-a-response.json"
assert_status "$temporary_root/create-second-a-response.json" 201
second_a_id=$(json_field "$temporary_root/create-second-a-response.json" data.recordIdentifier)
second_a_etag=$(response_header_literal "$temporary_root/create-second-a-response.json" ETag)
cat >"$temporary_root/second-move-june.json" <<EOF
{"items":[
  {"operation":"patch","recordId":"$second_a_id","ifMatch":$second_a_etag,"patch":[{"op":"replace","path":"/data/validTo","value":"2026-06-01"}]},
  {"operation":"create","data":{"subject":"household-002","group":"B","validFrom":"2026-06-01","sourceReference":"reported-move"}}
]}
EOF
http_json POST "$server_url" "$temporary_root/secrets/operator-token" \
  "/v1/records/memberships:batch?accessProfile=registry-operator" second-june-move application/json \
  "$temporary_root/second-move-june.json" "$temporary_root/second-move-june-response.json"
assert_status "$temporary_root/second-move-june-response.json" 200
second_b_id=$(json_field "$temporary_root/second-move-june-response.json" results.1.id)
second_b_etag=$(json_field_literal "$temporary_root/second-move-june-response.json" results.1.etag)
second_a_move_etag=$(json_field_literal "$temporary_root/second-move-june-response.json" results.0.etag)
cat >"$temporary_root/second-correction-july.json" <<EOF
{"changeContext":{"kind":"correction","reasonCode":"effective-date-corrected","sourceReferences":["case-document:history-correction-002"]},"items":[
  {"operation":"patch","recordId":"$second_b_id","ifMatch":$second_b_etag,"patch":[{"op":"replace","path":"/data/validFrom","value":"2026-06-15"}]},
  {"operation":"patch","recordId":"$second_a_id","ifMatch":$second_a_move_etag,"patch":[{"op":"replace","path":"/data/validTo","value":"2026-06-15"}]}
]}
EOF
http_json POST "$server_url" "$temporary_root/secrets/operator-token" \
  "/v1/records/memberships:batch?accessProfile=registry-operator" second-july-correction application/json \
  "$temporary_root/second-correction-july.json" "$temporary_root/second-correction-july-response.json"
assert_status "$temporary_root/second-correction-july-response.json" 200

stop_server
checkpoint "restarting v1 runtime and checking retained bookmark"
start_server "$temporary_root/runtime-server-v1.yaml" "$server_url" "$temporary_root/server-v1-restart.log"
http_json GET "$server_url" "$temporary_root/secrets/consumer-token" \
  "/v1/records/memberships:snapshot?accessProfile=eligibility-consumer&snapshot=$first_snapshot&validAt=2026-06-05" "" "" "" \
  "$temporary_root/consumer-first-after-restart.json"
assert_status "$temporary_root/consumer-first-after-restart.json" 200
assert_snapshot_answer "$temporary_root/consumer-first-after-restart.json" household-001 B 2026-06-01 null
checkpoint "v1 restart preserved snapshot bookmark"

cp -R "$fixture" "$temporary_root/project-v2"
python3 - "$temporary_root/project-v2/registry.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
source = source.replace("  sequence: 1\n", "  sequence: 2\n", 1)
needle = "      - {id: source-reference, type: string, required: false, maxLength: 120, classification: internal}\n"
replacement = needle + "      - {id: review-note, type: string, required: false, maxLength: 120, classification: internal}\n"
if needle not in source:
    raise SystemExit("membership field insertion point was not found")
path.write_text(source.replace(needle, replacement, 1), encoding="utf-8")
PY
render_runtime_config "$temporary_root/runtime-test-v2.yaml" "$temporary_root/build-v1/package" \
  "$package_revision_v1" 1 "secret:file/schema-test-v2-runtime-url" \
  "secret:file/schema-test-v2-migration-url" "127.0.0.1:0" \
  "household-history-acceptance-0.1.0"
checkpoint "building and schema-testing signed v2 additive package"
PACKAGE_REVISION_RESULT=""
package_project "$temporary_root/project-v2" "$temporary_root/runtime-test-v2.yaml" "$temporary_root/build-v2" v2 "$temporary_root/runtime-operator-v1.yaml"
package_revision_v2=$PACKAGE_REVISION_RESULT
render_runtime_config "$temporary_root/runtime-operator-v2.yaml" "$temporary_root/build-v1/package" \
  "$package_revision_v1" 1 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "127.0.0.1:0" \
  "household-history-acceptance-0.1.0"
checkpoint "applying v2 additive package"
run_json "$temporary_root/apply-v2.json" apply --runtime-config "$temporary_root/runtime-operator-v2.yaml" --package "$temporary_root/build-v2/package"
assert_json_ok "$temporary_root/apply-v2.json" apply
render_runtime_config "$temporary_root/runtime-operator-v2-active.yaml" "$temporary_root/build-v2/package" \
  "$package_revision_v2" 2 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "127.0.0.1:0" \
  "household-history-acceptance-0.1.0"
stop_server
render_runtime_config "$temporary_root/runtime-server-v2.yaml" "$temporary_root/build-v2/package" \
  "$package_revision_v2" 2 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "$listener" \
  "household-history-acceptance-0.1.0"
checkpoint "starting v2 HTTP runtime and checking old bookmark"
start_server "$temporary_root/runtime-server-v2.yaml" "$server_url" "$temporary_root/server-v2.log"
http_json GET "$server_url" "$temporary_root/secrets/consumer-token" \
  "/v1/records/memberships:snapshot?accessProfile=eligibility-consumer&snapshot=$first_snapshot&validAt=2026-06-05" "" "" "" \
  "$temporary_root/consumer-first-after-upgrade.json"
assert_status "$temporary_root/consumer-first-after-upgrade.json" 200
assert_snapshot_answer "$temporary_root/consumer-first-after-upgrade.json" household-001 B 2026-06-01 null
checkpoint "v2 upgrade preserved pre-upgrade snapshot bookmark"

checkpoint "running post-upgrade write and new snapshot query"
cat >"$temporary_root/create-after-upgrade.json" <<'EOF'
{"data":{"subject":"household-003","group":"A","validFrom":"2026-07-20","sourceReference":"post-upgrade-membership"}}
EOF
http_json POST "$server_url" "$temporary_root/secrets/operator-token" \
  "/v1/records/memberships?accessProfile=registry-operator" post-upgrade-create application/json \
  "$temporary_root/create-after-upgrade.json" "$temporary_root/create-after-upgrade-response.json"
assert_status "$temporary_root/create-after-upgrade-response.json" 201
assert_snapshot_reference "$temporary_root/create-after-upgrade-response.json" data.snapshot
post_upgrade_snapshot=$(json_field "$temporary_root/create-after-upgrade-response.json" data.snapshot)
http_json GET "$server_url" "$temporary_root/secrets/consumer-token" \
  "/v1/records/memberships:snapshot?accessProfile=eligibility-consumer&snapshot=$post_upgrade_snapshot&validAt=2026-07-20" "" "" "" \
  "$temporary_root/consumer-post-upgrade-snapshot.json"
assert_status "$temporary_root/consumer-post-upgrade-snapshot.json" 200
assert_snapshot_answer "$temporary_root/consumer-post-upgrade-snapshot.json" household-003 A 2026-07-20 null 2026-07-20
checkpoint "v2 post-upgrade write produced a queryable new snapshot"

cp -R "$temporary_root/project-v2" "$temporary_root/project-v3"
python3 - "$temporary_root/project-v3/registry.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
source = source.replace("  sequence: 2\n", "  sequence: 3\n", 1)
old = "operations: [list, snapshot]"
if old not in source:
    raise SystemExit("consumer snapshot grant was not found")
path.write_text(source.replace(old, "operations: [list]", 1), encoding="utf-8")
PY
render_runtime_config "$temporary_root/runtime-test-v3.yaml" "$temporary_root/build-v2/package" \
  "$package_revision_v2" 2 "secret:file/schema-test-v3-runtime-url" \
  "secret:file/schema-test-v3-migration-url" "127.0.0.1:0" \
  "household-history-acceptance-0.1.0"
checkpoint "building and schema-testing signed v3 snapshot-revocation package"
PACKAGE_REVISION_RESULT=""
package_project "$temporary_root/project-v3" "$temporary_root/runtime-test-v3.yaml" "$temporary_root/build-v3" v3 "$temporary_root/runtime-operator-v2-active.yaml"
package_revision_v3=$PACKAGE_REVISION_RESULT
render_runtime_config "$temporary_root/runtime-operator-v3.yaml" "$temporary_root/build-v2/package" \
  "$package_revision_v2" 2 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "127.0.0.1:0" \
  "household-history-acceptance-0.1.0"
checkpoint "applying v3 snapshot-revocation package"
run_json "$temporary_root/apply-v3.json" apply --runtime-config "$temporary_root/runtime-operator-v3.yaml" --package "$temporary_root/build-v3/package"
assert_json_ok "$temporary_root/apply-v3.json" apply
stop_server
render_runtime_config "$temporary_root/runtime-server-v3.yaml" "$temporary_root/build-v3/package" \
  "$package_revision_v3" 3 "secret:file/production-runtime-url" \
  "secret:file/production-migration-url" "$listener" \
  "household-history-acceptance-0.1.0"
checkpoint "starting v3 HTTP runtime and checking revoked snapshot bookmark"
start_server "$temporary_root/runtime-server-v3.yaml" "$server_url" "$temporary_root/server-v3.log"
http_json GET "$server_url" "$temporary_root/secrets/consumer-token" \
  "/v1/records/memberships:snapshot?accessProfile=eligibility-consumer&snapshot=$first_snapshot&validAt=2026-06-05" "" "" "" \
  "$temporary_root/consumer-after-revocation.json"
revoked_status=$(<"$temporary_root/consumer-after-revocation.json.status")
if [[ "$revoked_status" != "404" && "$revoked_status" != "403" ]]; then
  printf '%s\n' "snapshot bookmark authorized after revocation; got HTTP $revoked_status" >&2
  exit 1
fi
checkpoint "v3 revocation refused the old consumer snapshot bookmark"

server_hash_after=$(sha256_file "$breg")
if [[ "$server_hash_before" != "$server_hash_after" ]]; then
  printf '%s\n' 'breg binary changed during the historical workflow.' >&2
  exit 1
fi

checkpoint "all historical workflow checkpoints passed"
printf '%s\n' 'Base Registry Engine historical household workflow passed'
