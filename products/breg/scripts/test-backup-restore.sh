#!/usr/bin/env bash
set -euo pipefail

# Proves the documented logical backup and restore of a Base Registry Engine
# database with the public binaries and the PostgreSQL tools. A registry is
# packaged, applied, and served; it commits records, a patch, an open import
# authority, one delivered webhook, and one webhook still pending when
# `pg_dump` runs. After the backup the original closes the authority, delivers
# the pending webhook, and commits one more record, then stops for good. The
# dump is restored into a fresh database, and the restored copy must refuse to
# serve until `bregctl instance-claim adopt --acknowledge-original-retired`.
# Once adopted it serves the committed state of the backup point, its import
# authority is superseded, it re-sends only the delivery that was pending at
# the backup point, under the same idempotency key, its audit stream continues
# in the same files, and it accepts a write.

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_dir/../../.." && pwd)
. "$repository_root/scripts/cargo-runtime-library-path.sh"
temporary_root=""
breg_pid=""
receiver_pid=""
restore_admin_url=""
restore_migration_role=""
restore_runtime_role=""
restore_databases=()
if [[ "$#" -ne 0 ]]; then
  printf '%s\n' 'usage: test-backup-restore.sh' >&2
  exit 2
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "$1 is required for the backup and restore workflow." >&2
    exit 2
  fi
}

checkpoint() {
  printf 'backup and restore workflow: %s\n' "$1" >&2
}

fail() {
  printf 'backup and restore workflow failed: %s\n' "$1" >&2
  exit 1
}

stop_server() {
  if [[ -n "$breg_pid" ]]; then
    kill "$breg_pid" >/dev/null 2>&1 || true
    wait "$breg_pid" >/dev/null 2>&1 || true
  fi
  breg_pid=""
}

cleanup() {
  stop_server
  if [[ -n "$receiver_pid" ]]; then
    kill "$receiver_pid" >/dev/null 2>&1 || true
    wait "$receiver_pid" >/dev/null 2>&1 || true
  fi
  if [[ "${BREG_RESTORE_KEEP_TEMP:-0}" == "1" ]]; then
    printf '%s\n' "backup and restore workflow preserved temporary root and databases: $temporary_root" >&2
    return 0
  fi
  local database
  for database in "${restore_databases[@]}"; do
    psql "$restore_admin_url" -v ON_ERROR_STOP=1 -q \
      -c "DROP DATABASE IF EXISTS \"$database\" WITH (FORCE);" >/dev/null 2>&1 || true
  done
  if [[ -n "$restore_migration_role" && -n "$restore_runtime_role" ]]; then
    psql "$restore_admin_url" -v ON_ERROR_STOP=1 -q \
      -c "DROP ROLE IF EXISTS \"$restore_runtime_role\"; DROP ROLE IF EXISTS \"$restore_migration_role\";" >/dev/null 2>&1 || true
  fi
  case "$temporary_root" in
    "$repository_root"/.breg-restore.*)
      if [[ -d "$temporary_root" && ! -L "$temporary_root" ]]; then
        rm -rf -- "$temporary_root"
      fi
      ;;
    "") ;;
    *)
      printf '%s\n' 'backup and restore workflow temporary directory did not match its validated location' >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

require_command openssl
require_command psql
require_command python3

if [[ -z "${BREG_TEST_DATABASE_URL:-}" ]]; then
  printf '%s\n' 'BREG_TEST_DATABASE_URL must be set for the backup and restore workflow.' >&2
  exit 2
fi
if [[ -z "${BREG_TEST_TLS_CA_PEM_PATH:-}" ]]; then
  printf '%s\n' 'BREG_TEST_TLS_CA_PEM_PATH must be set for the backup and restore workflow after the PostgreSQL TLS proof.' >&2
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
# The dump and the restore run as the administrator. With a container id they
# run inside the PostgreSQL container, so the client tools always match the
# server's major version; without one the host tools must match it.
postgres_container_id=${BREG_TEST_TLS_POSTGRES_CONTAINER_ID:-}
if [[ -n "$postgres_container_id" ]]; then
  require_command docker
else
  require_command pg_dump
  require_command pg_restore
fi

umask 077
checkpoint "preparing disposable TLS PostgreSQL resources and local credentials"
temporary_root=$(mktemp -d "$repository_root/.breg-restore.XXXXXX")
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

# Runs a command that must refuse, and asserts a non-zero exit and that the
# report names the expected diagnostic code.
expect_refusal() {
  local output=$1
  local expected_code=$2
  local status=0
  shift 2
  "$bregctl" --format json "$@" >"$output" || status=$?
  if [[ "$status" == 0 ]]; then
    fail "bregctl $1 succeeded where a refusal with $expected_code was required"
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
  python3 - "$BREG_TEST_DATABASE_URL" "$database" "$role" "$restore_password" <<'PY'
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

admin_user() {
  python3 - "$BREG_TEST_DATABASE_URL" <<'PY'
import sys
from urllib.parse import unquote, urlsplit
user = urlsplit(sys.argv[1]).username
if not user:
    raise SystemExit("BREG_TEST_DATABASE_URL must name the administrator")
print(unquote(user))
PY
}

# The database-level statements a dump does not carry, as
# `breg-changes.mdx` "Back up and restore the database" lists them.
create_database() {
  local database=$1
  restore_databases+=("$database")
  psql "$restore_admin_url" -v ON_ERROR_STOP=1 -q \
    -c "CREATE DATABASE \"$database\";" \
    -c "REVOKE ALL ON DATABASE \"$database\" FROM PUBLIC;" \
    -c "GRANT CONNECT ON DATABASE \"$database\" TO \"$restore_migration_role\", \"$restore_runtime_role\";" >/dev/null
}

# Provisions a database for a first apply, as `breg.mdx` "Provision
# PostgreSQL" describes.
provision_database() {
  local database=$1
  create_database "$database"
  psql "$(derive_database_url "$database")" -v ON_ERROR_STOP=1 -q \
    -c "CREATE EXTENSION IF NOT EXISTS btree_gist;" \
    -c "CREATE SCHEMA registry_internal AUTHORIZATION \"$restore_migration_role\";" \
    -c "CREATE SCHEMA registry_data AUTHORIZATION \"$restore_migration_role\";" \
    -c "CREATE SCHEMA registry_source AUTHORIZATION \"$restore_migration_role\";" \
    -c "CREATE SCHEMA registry_derived AUTHORIZATION \"$restore_migration_role\";" \
    -c "CREATE SCHEMA registry_context AUTHORIZATION \"$restore_migration_role\";" \
    -c "REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context FROM PUBLIC;" >/dev/null
}

write_database_secrets() {
  local database=$1
  local prefix=$2
  printf '%s' "$(derive_database_url "$database" "$restore_migration_role")" >"$temporary_root/secrets/$prefix-migration-url"
  printf '%s' "$(derive_database_url "$database" "$restore_runtime_role")" >"$temporary_root/secrets/$prefix-runtime-url"
}

dump_database() {
  local database=$1
  local output=$2
  if [[ -n "$postgres_container_id" ]]; then
    docker exec "$postgres_container_id" \
      pg_dump --username "$(admin_user)" --format=custom --dbname "$database" >"$output"
  else
    pg_dump --format=custom --file="$output" --dbname "$(derive_database_url "$database")"
  fi
}

restore_database() {
  local database=$1
  local input=$2
  if [[ -n "$postgres_container_id" ]]; then
    docker exec -i "$postgres_container_id" \
      pg_restore --username "$(admin_user)" --exit-on-error --dbname "$database" <"$input"
  else
    pg_restore --exit-on-error --dbname "$(derive_database_url "$database")" "$input"
  fi
}

select_free_listener() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(f"127.0.0.1:{sock.getsockname()[1]}")
PY
}

# Writes one runtime file. The original and the restored copy differ only in
# the secret files their database references name; the identity, package,
# audit destination, and webhook binding stay the same across the restore.
render_runtime_config() {
  local output=$1
  local database_prefix=$2
  local instance_id=$3
  cat >"$output" <<EOF
apiVersion: id.registrystack.org/formats/breg/runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: $listener
identity:
  environment: production
  instanceId: $instance_id
  databaseId: generic-registry-production-db
  databaseInitializationEnvironment: production
secretProviders:
  file:
    root: $temporary_root/secrets
database:
  runtimeUrlRef: secret:file/$database_prefix-runtime-url
  migrationUrlRef: secret:file/$database_prefix-migration-url
  pool:
    maximumConnections: 4
  roles:
    migration: $restore_migration_role
    runtime: $restore_runtime_role
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
  path: $audit_path
cursor:
  secretRef: secret:file/cursor-key
eventDestinations:
  record-events:
    origin: http://$receiver_address
    path: /events
    networkProfile: loopback-development-http
    dnsFamily: dual-stack-strict
    allowedPrivateCidrs: []
    hmacSha256KeyRef: secret:file/record-events-key
    classificationCeiling: internal
    deliveryCeilings:
      attemptTimeoutMilliseconds: 2000
      maximumAttempts: 5
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
header = {"alg": "EdDSA", "kid": "restore-issuer", "typ": "at+jwt"}
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

# Sends one request and writes the body, the status, and the ETag beside each
# other. The token is read from its file inside the helper and never printed.
http_json() {
  local method=$1
  local url=$2
  local body_file=$3
  local output=$4
  local if_match=${5:-}
  python3 - "$method" "$url" "$temporary_root/secrets/operator-token" "$body_file" "$output" "$if_match" <<'PY'
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
method, url, token_file, body_file, output, if_match = sys.argv[1:]
headers = {"Accept": "application/json",
           "Authorization": "Bearer " + Path(token_file).read_text(encoding="ascii").strip()}
data = None
if body_file:
    data = Path(body_file).read_bytes()
    headers["Content-Type"] = "application/json-patch+json" if method == "PATCH" else "application/json"
    headers["Idempotency-Key"] = str(uuid.uuid4())
if if_match:
    headers["If-Match"] = if_match
request = urllib.request.Request(url, data=data, method=method, headers=headers)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        status, body, etag = response.status, response.read(), response.headers.get("ETag", "")
except urllib.error.HTTPError as error:
    status, body, etag = error.code, error.read(), error.headers.get("ETag", "")
Path(output).write_bytes(body)
Path(output + ".status").write_text(str(status), encoding="ascii")
Path(output + ".etag").write_text(etag or "", encoding="ascii")
PY
}

assert_status() {
  local actual
  actual=$(<"$1.status")
  if [[ "$actual" != "$2" ]]; then
    fail "expected HTTP $2 for $(basename -- "$1"), got $actual"
  fi
}

ready_status() {
  python3 - "${base_url}ready" <<'PY'
import sys
import urllib.error
import urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=2) as response:
        print(response.status)
except urllib.error.HTTPError as error:
    print(error.code)
except Exception:
    print("unreachable")
PY
}

# Starts the runtime and waits until it is ready.
start_server() {
  local config=$1
  local log=$2
  BREG_LOG=error "$breg" --runtime-config "$config" >"$log" 2>&1 &
  breg_pid=$!
  local attempt
  for attempt in $(seq 1 60); do
    if [[ "$(ready_status)" == 200 ]]; then
      return 0
    fi
    if ! kill -0 "$breg_pid" >/dev/null 2>&1; then
      fail "breg exited before it was ready; see $(basename -- "$log")"
    fi
    sleep 0.5
  done
  fail "breg did not become ready (attempts: $attempt)"
}

# Starts a runtime that must refuse to serve, and asserts that it exits
# non-zero within 60 seconds and that its log names the expected refusal. A
# runtime still alive at the deadline is stopped and fails the check, so a
# regression that lets it serve cannot hang the workflow.
expect_startup_refusal() {
  local config=$1
  local log=$2
  local expected=$3
  local status=0
  local refusing_pid
  local attempt
  BREG_LOG=error "$breg" --runtime-config "$config" >"$log" 2>&1 &
  refusing_pid=$!
  for attempt in $(seq 1 120); do
    if ! kill -0 "$refusing_pid" >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
  if kill -0 "$refusing_pid" >/dev/null 2>&1; then
    kill "$refusing_pid" >/dev/null 2>&1 || true
    wait "$refusing_pid" >/dev/null 2>&1 || true
    fail "breg was still running with $(basename -- "$config") after $attempt checks where startup had to refuse"
  fi
  wait "$refusing_pid" || status=$?
  if [[ "$status" == 0 ]]; then
    fail "breg started with $(basename -- "$config") where startup had to refuse"
  fi
  if ! grep -q -- "$expected" "$log"; then
    fail "breg startup refusal did not name: $expected"
  fi
}

# Waits until the receiver log satisfies a Python expression over `receipts`,
# the list of recorded requests.
wait_for_receipts() {
  local description=$1
  local condition=$2
  python3 - "$temporary_root/receiver.jsonl" "$condition" "$description" <<'PY'
import json
import sys
import time
path, condition, description = sys.argv[1:]
deadline = time.time() + 60
while True:
    try:
        receipts = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    except FileNotFoundError:
        receipts = []
    if eval(condition, {"receipts": receipts}):
        raise SystemExit(0)
    if time.time() > deadline:
        raise SystemExit(f"the receiver never saw {description}")
    time.sleep(0.25)
PY
}

create_record() {
  local code=$1
  local output=$2
  printf '{"data":{"code":"%s","label":"Restore record %s","group":"%s","status":"draft"}}\n' \
    "$code" "$code" "$group_id" >"$temporary_root/$code-request.json"
  http_json POST "${base_url}v1/records/records?accessProfile=operator" \
    "$temporary_root/$code-request.json" "$output"
  assert_status "$output" 201
  json_field "$output" data.recordIdentifier
}

# Captures what a client reads about the backup-point state: one record with
# its ETag, its revision history, and the collection listing.
capture_served_state() {
  local prefix=$1
  http_json GET "${base_url}v1/records/records/$record_1?accessProfile=operator" "" "$prefix-record-1.json"
  assert_status "$prefix-record-1.json" 200
  http_json GET "${base_url}v1/records/records/$record_1/revisions?accessProfile=operator" "" "$prefix-revisions-1.json"
  assert_status "$prefix-revisions-1.json" 200
  http_json GET "${base_url}v1/records/records?accessProfile=operator" "" "$prefix-records.json"
  assert_status "$prefix-records.json" 200
}

audit_digest() {
  python3 - "$1" <<'PY'
import hashlib
import sys
from pathlib import Path
data = Path(sys.argv[1]).read_bytes()
print(f"{len(data)}:{hashlib.sha256(data).hexdigest()}")
PY
}

mkdir -p "$temporary_root/secrets" "$temporary_root/empty-package" "$temporary_root/audit" "$temporary_root/audit-test"
chmod 700 "$temporary_root/secrets" "$temporary_root/audit"
openssl rand -hex 32 >"$temporary_root/secrets/audit-key"
openssl rand -hex 32 >"$temporary_root/secrets/cursor-key"
openssl rand -hex 32 | tr -d '\n' >"$temporary_root/secrets/record-events-key"
openssl genpkey -algorithm ED25519 -out "$temporary_root/issuer.pem" >/dev/null 2>&1
python3 - "$temporary_root/issuer.pem" "$temporary_root/secrets/issuer-jwks" <<'PY'
import base64
import json
import subprocess
import sys
der = subprocess.run(["openssl", "pkey", "-in", sys.argv[1], "-pubout", "-outform", "DER"],
                     check=True, capture_output=True).stdout
x = base64.urlsafe_b64encode(der[-32:]).rstrip(b"=").decode("ascii")
jwk = {"alg": "EdDSA", "crv": "Ed25519", "kid": "restore-issuer", "kty": "OKP", "x": x}
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

# A loopback webhook receiver that records every request it answers. Its
# answer is read from a file per request, so the workflow can hold a delivery
# pending by answering 503 and release it by answering 200.
cat >"$temporary_root/receiver.py" <<'PY'
import http.server
import json
import sys
from pathlib import Path

address_file, log_file, answer_file = (Path(value) for value in sys.argv[1:4])


class Receiver(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        status = int(answer_file.read_text(encoding="ascii").strip())
        try:
            record_id = json.loads(body)["data"]["recordId"]
        except (ValueError, KeyError, TypeError):
            record_id = None
        receipt = {
            "idempotencyKey": self.headers.get("Idempotency-Key"),
            "eventId": self.headers.get("ce-id"),
            "type": self.headers.get("ce-type"),
            "source": self.headers.get("ce-source"),
            "attempt": self.headers.get("X-Registry-Delivery-Attempt"),
            "recordId": record_id,
            "answer": status,
        }
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(receipt, sort_keys=True) + "\n")
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_arguments):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
address_file.write_text(f"127.0.0.1:{server.server_address[1]}", encoding="ascii")
server.serve_forever()
PY
printf '200' >"$temporary_root/receiver-answer"
python3 "$temporary_root/receiver.py" "$temporary_root/receiver-address" \
  "$temporary_root/receiver.jsonl" "$temporary_root/receiver-answer" &
receiver_pid=$!
for _ in $(seq 1 40); do
  [[ -s "$temporary_root/receiver-address" ]] && break
  sleep 0.25
done
[[ -s "$temporary_root/receiver-address" ]] || fail "the webhook receiver did not start"
receiver_address=$(<"$temporary_root/receiver-address")

restore_suffix="rsrestore$(date +%s)$$"
restore_migration_role="breg_restore_migration_${restore_suffix}"
restore_runtime_role="breg_restore_runtime_${restore_suffix}"
restore_password=$(openssl rand -hex 18)
restore_admin_url=$BREG_TEST_DATABASE_URL
psql "$restore_admin_url" -v ON_ERROR_STOP=1 -q \
  -c "CREATE ROLE \"$restore_migration_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$restore_password';" \
  -c "CREATE ROLE \"$restore_runtime_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$restore_password';"
test_database="breg_restore_test_${restore_suffix}"
original_database="breg_restore_original_${restore_suffix}"
restored_database="breg_restore_restored_${restore_suffix}"
provision_database "$test_database"
write_database_secrets "$test_database" test
provision_database "$original_database"
write_database_secrets "$original_database" original

checkpoint "authoring a project with an event, a revision grant, and an import grant"
project="$temporary_root/project"
run_json "$temporary_root/init.json" init "$project"
assert_json_ok "$temporary_root/init.json" init
python3 - "$project/registry.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")

def insert_after(needle, addition):
    global source
    if source.count(needle) != 1:
        raise SystemExit(f"insertion point was not found exactly once: {needle.strip()}")
    source = source.replace(needle, needle + addition, 1)

insert_after("      - {id: record-group-code-unique, type: unique, fields: [code]}\n",
             "    batch: {maximumItems: 10, maximumBytes: 65536}\n")
insert_after("      - {id: record-status, fields: [status]}\n",
             "    hooks:\n"
             "      - id: record-created-v1\n"
             "        phase: after\n"
             "        trigger: created\n"
             "        projection: [code, status]\n"
             "        handler: {type: url, destinationId: record-events}\n")
operator_record = ("          operations: [create, get, list, patch]\n"
                   "          readableFields: [code, label, group, status]\n"
                   "          writableFields: [code, label, group, status]\n"
                   "          filterableFields: [code, status]\n")
if source.count(operator_record) != 1:
    raise SystemExit("the operator record grant was not found exactly once")
source = source.replace(operator_record, operator_record.replace(
    "[create, get, list, patch]", "[create, get, list, patch, revisions]") + "          revisionAccess: true\n", 1)
insert_after("accessProfiles:\n",
             "  - id: loader\n"
             "    principalClaim: registry_principal\n"
             "    requiredScopes: [registry:generic:load]\n"
             "    requiredPurposes: [registry-operations]\n"
             "    permissions:\n"
             "      entities:\n"
             "        - entity: record-group\n"
             "          rowBoundaries: unrestricted\n"
             "          operations: [import]\n"
             "          readableFields: [code, label]\n"
             "          writableFields: [code, label]\n")
path.write_text(source, encoding="utf-8")
PY
run_json "$temporary_root/check.json" check "$project" --production
assert_json_ok "$temporary_root/check.json" check

checkpoint "testing and packaging the project"
listener=127.0.0.1:0
audit_path="$temporary_root/audit-test/breg.jsonl"
package_root="$temporary_root/empty-package"
render_runtime_config "$temporary_root/runtime-test.yaml" test generic-registry-test
run_json "$temporary_root/test.json" test "$project" \
  --runtime-config "$temporary_root/runtime-test.yaml" --credentials "$temporary_root/credentials.yaml" \
  --output "$temporary_root/test-receipt.json"
assert_json_ok "$temporary_root/test.json" test
run_json "$temporary_root/package.json" package "$project" \
  --test-receipt "$temporary_root/test-receipt.json" --output "$temporary_root/build"
assert_json_ok "$temporary_root/package.json" package
package_root="$temporary_root/build/package"

checkpoint "applying and serving the original registry"
listener=$(select_free_listener)
base_url="http://$listener/"
audit_path="$temporary_root/audit/breg.jsonl"
companion_audit_path="$temporary_root/audit/breg.bregctl.jsonl"
instance_id=generic-registry-production
original_config="$temporary_root/runtime-original.yaml"
render_runtime_config "$original_config" original "$instance_id"
run_json "$temporary_root/apply.json" apply --runtime-config "$original_config" \
  --package "$package_root" --initial
assert_json_ok "$temporary_root/apply.json" apply
start_server "$original_config" "$temporary_root/server-original-1.log"

checkpoint "committing records, a patch, and a delivered event"
printf '%s\n' '{"data":{"code":"restore-group","label":"Restore group"}}' >"$temporary_root/group-request.json"
http_json POST "${base_url}v1/records/record-groups?accessProfile=operator" \
  "$temporary_root/group-request.json" "$temporary_root/group.json"
assert_status "$temporary_root/group.json" 201
group_id=$(json_field "$temporary_root/group.json" data.recordIdentifier)
record_1=$(create_record record-1 "$temporary_root/record-1-created.json")
printf '%s\n' '[{"op":"replace","path":"/data/status","value":"active"}]' >"$temporary_root/record-1-patch-request.json"
http_json PATCH "${base_url}v1/records/records/$record_1?accessProfile=operator" \
  "$temporary_root/record-1-patch-request.json" "$temporary_root/record-1-patched.json" \
  "$(<"$temporary_root/record-1-created.json.etag")"
assert_status "$temporary_root/record-1-patched.json" 200
wait_for_receipts "the delivered event for the first record" \
  "any(r['recordId'] == '$record_1' and r['answer'] == 200 for r in receipts)"

checkpoint "opening an import authority the backup will hold open"
run_json "$temporary_root/authority-open.json" import-authority open --runtime-config "$original_config" \
  --entity record-group --profile loader --max-items 5 --expires-in 2d \
  --operator-reference restore-change-1 --reason "Restore proof import window"
assert_json_ok "$temporary_root/authority-open.json" "import-authority open"
authority_id=$(json_field "$temporary_root/authority-open.json" authority.authorityId)

checkpoint "holding one event pending at the backup point"
printf '503' >"$temporary_root/receiver-answer"
record_2=$(create_record record-2 "$temporary_root/record-2-created.json")
wait_for_receipts "a refused attempt for the second record" \
  "any(r['recordId'] == '$record_2' and r['answer'] == 503 for r in receipts)"
capture_served_state "$temporary_root/backup-point"
stop_server
run_json "$temporary_root/webhooks-backup-point.json" webhook list --runtime-config "$original_config"
python3 - "$temporary_root/webhooks-backup-point.json" <<'PY'
import json
import sys
deliveries = json.load(open(sys.argv[1], encoding="utf-8"))["deliveries"]
if [delivery["state"] for delivery in deliveries] != ["pending"]:
    raise SystemExit(f"expected exactly one pending delivery at the backup point, got {deliveries}")
PY
run_json "$temporary_root/status-backup-point.json" status --runtime-config "$original_config"
assert_json_ok "$temporary_root/status-backup-point.json" status
run_json "$temporary_root/claim-original.json" instance-claim status --runtime-config "$original_config"
assert_json_ok "$temporary_root/claim-original.json" "instance-claim status"

checkpoint "taking the logical backup with pg_dump"
dump="$temporary_root/backup/registry.dump"
mkdir -p "$temporary_root/backup"
dump_database "$original_database" "$dump"
[[ -s "$dump" ]] || fail "pg_dump wrote no backup"

checkpoint "changing the original after the backup point, then retiring it"
run_json "$temporary_root/authority-close.json" import-authority close --runtime-config "$original_config" \
  --authority-id "$authority_id" --operator-reference restore-change-2 --reason "Closed after the backup"
assert_json_ok "$temporary_root/authority-close.json" "import-authority close"
printf '200' >"$temporary_root/receiver-answer"
start_server "$original_config" "$temporary_root/server-original-2.log"
wait_for_receipts "the original's delivery of the event pending at the backup point" \
  "any(r['recordId'] == '$record_2' and r['answer'] == 200 for r in receipts)"
record_3=$(create_record record-3 "$temporary_root/record-3-created.json")
wait_for_receipts "the delivered event for the record written after the backup" \
  "any(r['recordId'] == '$record_3' and r['answer'] == 200 for r in receipts)"
stop_server
# The original is retired for good: no client may reach it again.
psql "$restore_admin_url" -v ON_ERROR_STOP=1 -q \
  -c "ALTER DATABASE \"$original_database\" WITH ALLOW_CONNECTIONS false;" >/dev/null
audit_at_retirement=$(audit_digest "$audit_path")
cp "$temporary_root/receiver.jsonl" "$temporary_root/receiver-at-retirement.jsonl"

checkpoint "restoring the backup into a fresh database"
create_database "$restored_database"
restore_database "$restored_database" "$dump"
write_database_secrets "$restored_database" restored
restored_config="$temporary_root/runtime-restored.yaml"
render_runtime_config "$restored_config" restored "$instance_id"
if ! diff <(sed 's/secret:file\/restored-/secret:file\/DATABASE-/' "$restored_config") \
  <(sed 's/secret:file\/original-/secret:file\/DATABASE-/' "$original_config") >/dev/null; then
  fail "the restored runtime file differs from the original in more than its database references"
fi
run_json "$temporary_root/verify-restored.json" verify --runtime-config "$restored_config"
assert_json_ok "$temporary_root/verify-restored.json" verify

checkpoint "refusing to serve the restored copy before adoption"
run_json "$temporary_root/claim-restored-before.json" instance-claim status --runtime-config "$restored_config"
assert_json_ok "$temporary_root/claim-restored-before.json" "instance-claim status"
python3 - "$temporary_root/claim-restored-before.json" "$temporary_root/claim-original.json" <<'PY'
import json
import sys
restored = json.load(open(sys.argv[1], encoding="utf-8"))["status"]
original = json.load(open(sys.argv[2], encoding="utf-8"))["status"]
if restored["matches"] is not False:
    raise SystemExit("instance-claim status did not report the restored copy as unclaimed")
if restored["claim"] != original["claim"]:
    raise SystemExit("the restored copy does not carry the original's claim")
if restored["live"]["databaseOid"] == original["live"]["databaseOid"]:
    raise SystemExit("the restored copy has the original's database object identifier")
PY
expect_refusal "$temporary_root/doctor-restored-before.json" startup.instance_claim.mismatch \
  doctor --runtime-config "$restored_config"
expect_startup_refusal "$restored_config" "$temporary_root/server-restored-refused.log" \
  'the Registry database is not the instance its claim names'
run_json "$temporary_root/authorities-before.json" import-authority list --runtime-config "$restored_config"
python3 - "$temporary_root/authorities-before.json" "$authority_id" <<'PY'
import json
import sys
authorities = json.load(open(sys.argv[1], encoding="utf-8"))["authorities"]
if [(item["authorityId"], item["status"]) for item in authorities] != [(sys.argv[2], "open")]:
    raise SystemExit(f"the backup did not bring back the authority closed after it: {authorities}")
PY
expect_refusal "$temporary_root/adopt-unacknowledged.json" instance_claim.acknowledgement.required \
  instance-claim adopt --runtime-config "$restored_config"

checkpoint "adopting the restored copy"
companion_before_adopt=$(audit_digest "$companion_audit_path")
run_json "$temporary_root/adopt.json" instance-claim adopt --runtime-config "$restored_config" \
  --acknowledge-original-retired
assert_json_ok "$temporary_root/adopt.json" "instance-claim adopt"
run_json "$temporary_root/claim-restored-after.json" instance-claim status --runtime-config "$restored_config"
python3 - "$temporary_root/adopt.json" "$temporary_root/claim-restored-after.json" \
  "$temporary_root/claim-original.json" "$authority_id" <<'PY'
import json
import sys
adoption = json.load(open(sys.argv[1], encoding="utf-8"))["adoption"]
after = json.load(open(sys.argv[2], encoding="utf-8"))["status"]
original = json.load(open(sys.argv[3], encoding="utf-8"))["status"]
if adoption["supersededImportAuthorities"] != [sys.argv[4]]:
    raise SystemExit(f"adopt did not supersede the reopened authority: {adoption}")
if adoption["previous"]["databaseOid"] != original["claim"]["databaseOid"]:
    raise SystemExit("adopt did not name the original as the previous claim")
if adoption["current"]["epoch"] != original["claim"]["epoch"] + 1:
    raise SystemExit("adopt did not raise the claim's epoch by one")
if after["matches"] is not True or after["claim"]["databaseOid"] != after["live"]["databaseOid"]:
    raise SystemExit("the claim does not name the restored copy after adopt")
PY
run_json "$temporary_root/authorities-after.json" import-authority list --runtime-config "$restored_config"
python3 - "$temporary_root/authorities-after.json" "$authority_id" <<'PY'
import json
import sys
authorities = json.load(open(sys.argv[1], encoding="utf-8"))["authorities"]
if [(item["authorityId"], item["status"]) for item in authorities] != [(sys.argv[2], "superseded")]:
    raise SystemExit(f"the authority from before the restore is not superseded: {authorities}")
PY
run_json "$temporary_root/status-restored.json" status --runtime-config "$restored_config"
python3 - "$temporary_root/status-backup-point.json" "$temporary_root/status-restored.json" <<'PY'
import json
import sys
backup_point, restored = (json.load(open(path, encoding="utf-8")) for path in sys.argv[1:3])
if not restored.get("ledger") or restored.get("maintenanceStatus") != "ready":
    raise SystemExit("the restored copy has no ready activation ledger")
if backup_point != restored:
    raise SystemExit("the restored activation ledger differs from the backup point's")
PY
checkpoint "refusing a restored runtime file that renames the instance while deliveries are pending"
render_runtime_config "$temporary_root/runtime-restored-renamed.yaml" restored "$instance_id-restored"
expect_refusal "$temporary_root/doctor-restored-renamed.json" startup.instance_id.pending_deliveries \
  doctor --runtime-config "$temporary_root/runtime-restored-renamed.yaml"
run_json "$temporary_root/doctor-restored-after.json" doctor --runtime-config "$restored_config"
assert_json_ok "$temporary_root/doctor-restored-after.json" doctor

checkpoint "serving the backup-point state from the adopted copy"
start_server "$restored_config" "$temporary_root/server-restored.log"
[[ "$(ready_status)" == 200 ]] || fail "the adopted copy is not ready"
capture_served_state "$temporary_root/restored"
python3 - "$temporary_root/backup-point" "$temporary_root/restored" <<'PY'
import json
import sys
from pathlib import Path
backup_point, restored = sys.argv[1:3]
for name in ("record-1.json", "revisions-1.json", "records.json"):
    before = json.loads(Path(f"{backup_point}-{name}").read_bytes())
    after = json.loads(Path(f"{restored}-{name}").read_bytes())
    if before != after:
        raise SystemExit(f"the adopted copy serves a different {name} than the backup point")
if Path(f"{backup_point}-record-1.json.etag").read_text() != Path(f"{restored}-record-1.json.etag").read_text():
    raise SystemExit("the adopted copy serves the backup-point record under another ETag")
revisions = json.loads(Path(f"{restored}-revisions-1.json").read_bytes())["items"]
if sorted(item["mutationKind"] for item in revisions) != ["create", "patch"]:
    raise SystemExit("the restored revision history is not the create and the patch")
PY
http_json GET "${base_url}v1/records/records/$record_3?accessProfile=operator" "" "$temporary_root/restored-record-3.json"
assert_status "$temporary_root/restored-record-3.json" 404

checkpoint "re-sending only the delivery pending at the backup point"
python3 - "$temporary_root/receiver-at-retirement.jsonl" "$record_2" >"$temporary_root/pending-key" <<'PY'
import json
import sys
receipts = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
keys = {receipt["idempotencyKey"] for receipt in receipts if receipt["recordId"] == sys.argv[2]}
if len(keys) != 1:
    raise SystemExit(f"the pending delivery was sent under {len(keys)} idempotency keys")
print(keys.pop())
PY
retired_receipts=$(wc -l <"$temporary_root/receiver-at-retirement.jsonl")
wait_for_receipts "the adopted copy's delivery of the event pending at the backup point" \
  "any(r['recordId'] == '$record_2' and r['answer'] == 200 for r in receipts[$retired_receipts:])"
record_4=$(create_record record-4 "$temporary_root/record-4-created.json")
wait_for_receipts "the delivered event for the write after adoption" \
  "any(r['recordId'] == '$record_4' and r['answer'] == 200 for r in receipts)"
python3 - "$temporary_root/receiver.jsonl" "$retired_receipts" "$(<"$temporary_root/pending-key")" \
  "$record_1" "$record_2" "$record_3" "$record_4" <<'PY'
import json
import sys
path, retired, pending_key, record_1, record_2, record_3, record_4 = sys.argv[1:]
receipts = [json.loads(line) for line in open(path, encoding="utf-8")]
after = receipts[int(retired):]
by_record = {}
for receipt in after:
    by_record.setdefault(receipt["recordId"], []).append(receipt)
if set(by_record) != {record_2, record_4}:
    raise SystemExit("the adopted copy delivered events other than the pending one and its own write")
resent = by_record[record_2]
if [receipt["answer"] for receipt in resent] != [200]:
    raise SystemExit("the pending delivery was not re-sent exactly once")
if resent[0]["idempotencyKey"] != pending_key:
    raise SystemExit("the pending delivery was re-sent under another idempotency key")
delivered_once = [receipt for receipt in receipts if receipt["recordId"] in (record_1, record_3)]
if len(delivered_once) != 2 or any(receipt["answer"] != 200 for receipt in delivered_once):
    raise SystemExit("an event delivered before the restore was delivered again")
PY
http_json GET "${base_url}v1/records/records?accessProfile=operator" "" "$temporary_root/restored-records-final.json"
assert_status "$temporary_root/restored-records-final.json" 200
python3 - "$temporary_root/restored-records-final.json" "$record_1" "$record_2" "$record_4" <<'PY'
import json
import sys
items = json.load(open(sys.argv[1], encoding="utf-8"))["items"]
if sorted(item["recordIdentifier"] for item in items) != sorted(sys.argv[2:]):
    raise SystemExit("the adopted copy does not serve exactly the backup-point records and its own write")
PY
run_json "$temporary_root/webhooks-restored.json" webhook list --runtime-config "$restored_config"
python3 - "$temporary_root/webhooks-restored.json" <<'PY'
import json
import sys
if json.load(open(sys.argv[1], encoding="utf-8"))["deliveries"]:
    raise SystemExit("the adopted copy still holds pending or dead-lettered deliveries")
PY
stop_server

checkpoint "continuing the audit stream in the same files"
python3 - "$audit_path" "$audit_at_retirement" "$companion_audit_path" "$companion_before_adopt" \
  "$authority_id" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
audit_path, at_retirement, companion_path, companion_before, authority_id = sys.argv[1:]

def entries(path):
    lines = Path(path).read_bytes().splitlines()
    parsed = [json.loads(line) for line in lines]
    for entry in parsed:
        if set(entry) != {"schema", "eventId", "time", "phase", "correlation", "record"}:
            raise SystemExit(f"{path} holds an entry of another shape")
    return parsed

def keeps_prefix(path, recorded):
    size, digest = recorded.split(":")
    data = Path(path).read_bytes()
    if len(data) <= int(size) or hashlib.sha256(data[: int(size)]).hexdigest() != digest:
        raise SystemExit(f"{path} was rewritten or did not grow across the restore")

for path in (audit_path, companion_path):
    if Path(path + ".torn").exists():
        raise SystemExit(f"{path} has a torn tail")
keeps_prefix(audit_path, at_retirement)
keeps_prefix(companion_path, companion_before)
# The runtime audit is not rewound by the restore. It keeps the commit and the
# delivery of the write the restore lost, and it records the delivery pending at
# the backup point twice: once by the original, once by the adopted copy, under
# the same idempotency key the receiver saw.
runtime = [entry["record"] for entry in entries(audit_path) if entry["phase"] == "response"]
creates = [record for record in runtime if record.get("operationId") == "records.record.create"
           and record.get("outcome") == "committed"]
if len(creates) != 4:
    raise SystemExit(f"the runtime audit holds {len(creates)} committed record creates, expected 4")
delivered = {}
for record in runtime:
    if record.get("disposition") == "delivered":
        delivered.setdefault(record["eventReference"], []).append(record["attempt"])
if sorted(delivered.values()) != [[1], [1], [1], [2, 2]]:
    raise SystemExit(f"the runtime audit does not record the expected deliveries: {delivered}")
adoptions = [entry["record"] for entry in entries(companion_path)
             if entry["record"].get("operationId") == "breg.instance_claim.adopt"
             and entry["record"].get("phase") == "terminal"]
if [(record.get("event"), record.get("outcome"), record.get("supersededImportAuthorities")) for record in adoptions] \
        != [("adopted", "committed", [authority_id])]:
    raise SystemExit(f"the companion audit does not record one committed adoption: {adoptions}")
PY

checkpoint "all backup and restore checkpoints passed"
printf '%s\n' 'Base Registry Engine backup and restore workflow passed'
