#!/usr/bin/env bash
set -euo pipefail

# Run the complete synthetic native acceptance against a caller-owned TLS
# PostgreSQL cluster. The helper creates uniquely named databases and roles. It
# never drops them, resets the cluster, or prints database credentials or JWTs.

script_dir=$(
	python3 - "${BASH_SOURCE[0]}" <<'PY'
import sys
from pathlib import Path

print(Path(sys.argv[1]).resolve().parent)
PY
)
readonly script_dir
repository_root=$(git --no-optional-locks -C "$script_dir" rev-parse --show-toplevel)
readonly repository_root
readonly fixture="$script_dir"
readonly bregctl=${PAYMENT_FEE_BREGCTL_BIN:-}
readonly breg=${PAYMENT_FEE_BREG_BIN:-}
readonly admin_url=${PAYMENT_FEE_DATABASE_ADMIN_URL:-}
readonly postgres_ca_source=${PAYMENT_FEE_POSTGRES_CA_FILE:-}
readonly acceptance_root=${PAYMENT_FEE_ACCEPTANCE_ROOT:-}
readonly listener_override=${PAYMENT_FEE_LISTENER:-}
readonly keep_running=${PAYMENT_FEE_KEEP_RUNNING:-0}
readonly breg_feature_profile=${PAYMENT_FEE_BREG_FEATURE_PROFILE:-unspecified}
readonly bregctl_feature_profile=${PAYMENT_FEE_BREGCTL_FEATURE_PROFILE:-unspecified}
readonly issuer=https://issuer.example.test/payment-fee-issuance
readonly audience=urn:breg:payment-fee-issuance

# Resolved beside this helper after path validation.
# shellcheck disable=SC1091
source "$script_dir/lifecycle.sh"

refuse() {
	printf 'Refusing: %s\n' "$1" >&2
	exit 2
}

for required in \
	PAYMENT_FEE_BREGCTL_BIN \
	PAYMENT_FEE_BREG_BIN \
	PAYMENT_FEE_DATABASE_ADMIN_URL \
	PAYMENT_FEE_POSTGRES_CA_FILE \
	PAYMENT_FEE_ACCEPTANCE_ROOT; do
	[[ -n "${!required:-}" ]] || refuse "$required is required"
done

[[ "$keep_running" == "0" || "$keep_running" == "1" ]] ||
	refuse "PAYMENT_FEE_KEEP_RUNNING must be 0 or 1"
[[ "$breg_feature_profile" =~ ^[a-z0-9][a-z0-9,._+-]{0,127}$ ]] ||
	refuse "PAYMENT_FEE_BREG_FEATURE_PROFILE must be a bounded lowercase feature label"
[[ "$bregctl_feature_profile" =~ ^[a-z0-9][a-z0-9,._+-]{0,127}$ ]] ||
	refuse "PAYMENT_FEE_BREGCTL_FEATURE_PROFILE must be a bounded lowercase feature label"

for path in "$bregctl" "$breg" "$postgres_ca_source" "$acceptance_root"; do
	[[ "$path" == /* && "$path" != *$'\n'* && "$path" != */../* && "$path" != */.. ]] ||
		refuse "all binary, CA, and acceptance-root paths must be absolute lexical paths"
done
[[ -x "$bregctl" && -f "$bregctl" ]] || refuse "PAYMENT_FEE_BREGCTL_BIN must name an executable file"
[[ -x "$breg" && -f "$breg" ]] || refuse "PAYMENT_FEE_BREG_BIN must name an executable file"
[[ -f "$postgres_ca_source" && ! -L "$postgres_ca_source" ]] ||
	refuse "PAYMENT_FEE_POSTGRES_CA_FILE must name a regular non-symlink file"
[[ -d "$acceptance_root" && ! -L "$acceptance_root" ]] ||
	refuse "PAYMENT_FEE_ACCEPTANCE_ROOT must name an existing non-symlink directory"
case "$acceptance_root" in
/ | /tmp | /private/tmp | /var/tmp | /private/var/tmp)
	refuse "PAYMENT_FEE_ACCEPTANCE_ROOT must not be a broad shared directory"
	;;
esac

if [[ -n "${PAYMENT_FEE_DYLD_FALLBACK_LIBRARY_PATH:-}" ]]; then
	[[ "$PAYMENT_FEE_DYLD_FALLBACK_LIBRARY_PATH" == /* && -d "$PAYMENT_FEE_DYLD_FALLBACK_LIBRARY_PATH" ]] ||
		refuse "PAYMENT_FEE_DYLD_FALLBACK_LIBRARY_PATH must name an absolute directory"
	export DYLD_FALLBACK_LIBRARY_PATH="$PAYMENT_FEE_DYLD_FALLBACK_LIBRARY_PATH"
fi
if [[ -n "${PAYMENT_FEE_DYLD_LIBRARY_PATH:-}" ]]; then
	[[ "$PAYMENT_FEE_DYLD_LIBRARY_PATH" == /* && -d "$PAYMENT_FEE_DYLD_LIBRARY_PATH" ]] ||
		refuse "PAYMENT_FEE_DYLD_LIBRARY_PATH must name an absolute directory"
	export DYLD_LIBRARY_PATH="$PAYMENT_FEE_DYLD_LIBRARY_PATH"
fi
export PGSSLROOTCERT="$postgres_ca_source"

for command in git jq openssl psql python3 yq; do
	command -v "$command" >/dev/null 2>&1 || refuse "$command is required on PATH"
done

python3 - "$admin_url" <<'PY'
import sys
from urllib.parse import parse_qs, urlsplit

url = urlsplit(sys.argv[1])
if url.scheme not in {"postgres", "postgresql"} or not url.hostname or not url.path.strip("/"):
    raise SystemExit("PAYMENT_FEE_DATABASE_ADMIN_URL must be a PostgreSQL URL with host and database")
sslmode = parse_qs(url.query).get("sslmode", [""])[-1]
if sslmode not in {"require", "verify-ca", "verify-full"}:
    raise SystemExit("PAYMENT_FEE_DATABASE_ADMIN_URL must require TLS with sslmode=require or stronger")
PY

umask 077
readonly scratch_root="$acceptance_root/payment-fee-issuance"
run_suffix="$(date -u +%Y%m%dt%H%M%Sz)_$$"
readonly run_suffix
readonly run_root="$scratch_root/runs/$run_suffix"
readonly secrets="$run_root/secrets"
readonly reports="$run_root/reports"
mkdir -p "$secrets" "$reports" "$run_root/audit" "$run_root/empty-package"
chmod 700 "$scratch_root" "$scratch_root/runs" "$run_root" "$secrets" "$reports" "$run_root/audit" "$run_root/empty-package"

readonly test_database="payment_fee_test_$run_suffix"
readonly runtime_database="payment_fee_runtime_$run_suffix"
readonly test_migration_role="payment_fee_test_m_$run_suffix"
readonly test_runtime_role="payment_fee_test_r_$run_suffix"
readonly runtime_migration_role="payment_fee_live_m_$run_suffix"
readonly runtime_runtime_role="payment_fee_live_r_$run_suffix"
test_password="$(openssl rand -hex 24)"
runtime_password="$(openssl rand -hex 24)"
readonly test_password runtime_password

derive_database_url() {
	local database=$1
	local role=$2
	local password=$3
	python3 - "$admin_url" "$database" "$role" "$password" <<'PY'
import sys
from urllib.parse import quote, urlsplit, urlunsplit

admin = urlsplit(sys.argv[1])
database, role, password = sys.argv[2:]
host = admin.hostname if admin.port is None else f"{admin.hostname}:{admin.port}"
userinfo = f"{quote(role, safe='')}:{quote(password, safe='')}"
print(urlunsplit((admin.scheme, f"{userinfo}@{host}", f"/{quote(database, safe='')}", admin.query, "")))
PY
}

derive_admin_database_url() {
	local database=$1
	python3 - "$admin_url" "$database" <<'PY'
import sys
from urllib.parse import quote, urlsplit, urlunsplit

admin = urlsplit(sys.argv[1])
print(urlunsplit((admin.scheme, admin.netloc, f"/{quote(sys.argv[2], safe='')}", admin.query, "")))
PY
}

provision_database() {
	local database=$1
	local migration_role=$2
	local runtime_role=$3
	local database_url
	database_url="$(derive_admin_database_url "$database")"
	psql "$admin_url" -v ON_ERROR_STOP=1 -q <<SQL
CREATE DATABASE "$database" ENCODING 'UTF8' TEMPLATE template0;
SQL
	psql "$database_url" -v ON_ERROR_STOP=1 -q <<SQL
CREATE EXTENSION IF NOT EXISTS btree_gist;
REVOKE ALL ON DATABASE "$database" FROM PUBLIC;
GRANT CONNECT ON DATABASE "$database" TO "$migration_role", "$runtime_role";
CREATE SCHEMA registry_internal AUTHORIZATION "$migration_role";
CREATE SCHEMA registry_data AUTHORIZATION "$migration_role";
CREATE SCHEMA registry_source AUTHORIZATION "$migration_role";
CREATE SCHEMA registry_derived AUTHORIZATION "$migration_role";
CREATE SCHEMA registry_context AUTHORIZATION "$migration_role";
REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source, registry_derived, registry_context FROM PUBLIC;
SQL
}

psql "$admin_url" -v ON_ERROR_STOP=1 -q <<SQL
CREATE ROLE "$test_migration_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$test_password';
CREATE ROLE "$test_runtime_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$test_password';
CREATE ROLE "$runtime_migration_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$runtime_password';
CREATE ROLE "$runtime_runtime_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$runtime_password';
SQL
provision_database "$test_database" "$test_migration_role" "$test_runtime_role"
provision_database "$runtime_database" "$runtime_migration_role" "$runtime_runtime_role"

printf '%s' "$(derive_database_url "$test_database" "$test_migration_role" "$test_password")" >"$secrets/test-migration-url"
printf '%s' "$(derive_database_url "$test_database" "$test_runtime_role" "$test_password")" >"$secrets/test-runtime-url"
printf '%s' "$(derive_database_url "$runtime_database" "$runtime_migration_role" "$runtime_password")" >"$secrets/runtime-migration-url"
printf '%s' "$(derive_database_url "$runtime_database" "$runtime_runtime_role" "$runtime_password")" >"$secrets/runtime-runtime-url"
openssl rand -hex 32 >"$secrets/audit-key"
openssl rand -hex 32 >"$secrets/cursor-key"
cp "$postgres_ca_source" "$secrets/postgres-ca"
openssl genpkey -algorithm ED25519 -out "$secrets/oidc-signer.pem" >/dev/null 2>&1
chmod 600 "$secrets"/*

python3 - "$secrets/oidc-signer.pem" "$secrets/oidc-jwks" <<'PY'
import base64
import json
import subprocess
import sys
from pathlib import Path

der = subprocess.run(
    ["openssl", "pkey", "-in", sys.argv[1], "-pubout", "-outform", "DER"],
    check=True,
    capture_output=True,
).stdout
x = base64.urlsafe_b64encode(der[-32:]).rstrip(b"=").decode("ascii")
jwk = {"alg": "EdDSA", "crv": "Ed25519", "kid": "payment-fee-issuer", "kty": "OKP", "x": x}
Path(sys.argv[2]).write_text(json.dumps({"keys": [jwk]}, sort_keys=True, separators=(",", ":")), encoding="utf-8")
PY

write_jwt() {
	local client_id=$1
	local principal=$2
	local purpose=$3
	local scopes=$4
	local output=$5
	local signing_input="$output.signing-input"
	local signature="$output.signature"
	python3 - "$issuer" "$audience" "$client_id" "$principal" "$purpose" "$scopes" "$signing_input" <<'PY'
import base64
import json
import secrets
import sys
import time
from pathlib import Path

def b64(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")

issuer, audience, client_id, principal, purpose, scopes, output = sys.argv[1:]
now = int(time.time())
claims = {
    "aud": audience,
    "client_id": client_id,
    "exp": now + 7200,
    "iat": now,
    "iss": issuer,
    "jti": f"{client_id}-{principal}-{now}-{secrets.token_hex(8)}",
    "registry_actor_kind": "service",
    "registry_principal": principal,
    "registry_purpose": purpose,
    "scope": scopes,
    "sub": principal,
}
header = {"alg": "EdDSA", "kid": "payment-fee-issuer", "typ": "JWT"}
Path(output).write_text(f"{b64(header)}.{b64(claims)}", encoding="ascii")
PY
	openssl pkeyutl -sign -rawin -inkey "$secrets/oidc-signer.pem" -in "$signing_input" -out "$signature"
	python3 - "$signing_input" "$signature" "$output" <<'PY'
import base64
import sys
from pathlib import Path

signing_input = Path(sys.argv[1]).read_text(encoding="ascii")
signature = base64.urlsafe_b64encode(Path(sys.argv[2]).read_bytes()).rstrip(b"=").decode("ascii")
Path(sys.argv[3]).write_text(f"{signing_input}.{signature}", encoding="ascii")
PY
	chmod 600 "$output" "$signing_input" "$signature"
}

write_jwt issuance-service synthetic-issuance-service service-issuance \
	'registry:fee-bill:create registry:paid-service:issue' "$secrets/issuance-service-token"
write_jwt issuance-service synthetic-issuance-service service-issuance \
	'registry:fee-bill:create' "$secrets/issuance-service-create-token"
write_jwt issuance-service synthetic-issuance-service service-issuance \
	'registry:paid-service:issue' "$secrets/issuance-service-issue-token"
write_jwt payment-adapter synthetic-payment-adapter payment-processing \
	'registry:payment-attempt:bind registry:payment-receipt:report' "$secrets/payment-adapter-token"
write_jwt payment-adapter synthetic-payment-adapter payment-processing \
	'registry:payment-attempt:bind' "$secrets/payment-adapter-bind-token"
write_jwt payment-adapter synthetic-payment-adapter payment-processing \
	'registry:payment-receipt:report' "$secrets/payment-adapter-report-token"
write_jwt payment-adapter synthetic-unauthorized-adapter payment-processing \
	'' "$secrets/payment-adapter-unauthorized-token"
write_jwt service-coordinator synthetic-coordinator service-orchestration \
	'registry:fee-bill:read' "$secrets/service-coordinator-token"

select_free_listener() {
	python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(f"127.0.0.1:{sock.getsockname()[1]}")
PY
}
readonly listener=${listener_override:-$(select_free_listener)}
[[ "$listener" =~ ^127\.0\.0\.1:[1-9][0-9]{0,4}$ ]] ||
	refuse "PAYMENT_FEE_LISTENER must be a 127.0.0.1 host and port"
readonly base_url="http://$listener"

render_runtime_config() {
	local output=$1
	local package_root=$2
	local runtime_ref=$3
	local migration_ref=$4
	local migration_role=$5
	local runtime_role=$6
	local bind=$7
	local database_id=$8
	cat >"$output" <<EOF
apiVersion: id.registrystack.org/formats/breg/runtime/v1alpha1
kind: BRegRuntimeConfig
listener: {bind: $bind}
identity:
  environment: acceptance
  instanceId: payment-fee-issuance-$run_suffix
  databaseId: $database_id
  databaseInitializationEnvironment: acceptance
secretProviders:
  file: {root: $secrets}
database:
  runtimeUrlRef: $runtime_ref
  migrationUrlRef: $migration_ref
  trustedRootCertificateRef: secret:file/postgres-ca
  pool: {maximumConnections: 4, waitTimeoutMilliseconds: 2000, createTimeoutMilliseconds: 2000, recycleTimeoutMilliseconds: 2000}
  roles: {migration: $migration_role, runtime: $runtime_role}
package: {root: $package_root}
authentication:
  oidc:
    issuer: $issuer
    audience: $audience
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [issuance-service, payment-adapter, service-coordinator]
    maximumTokenLifetimeSeconds: 7200
    leewayMilliseconds: 60000
    jwksCache: {cacheTtlSeconds: 600, negativeCacheTtlSeconds: 60, refreshCooldownSeconds: 30, maximumDocumentBytes: 65536, attemptTimeoutMilliseconds: 5000, outageToleranceSeconds: 0}
    jwksSource: {type: static, documentRef: secret:file/oidc-jwks}
  authorityClaims: {principal: registry_principal, purpose: registry_purpose}
audit: {hashKeyRef: secret:file/audit-key, path: $run_root/audit/audit.jsonl}
cursor: {secretRef: secret:file/cursor-key, maximumAgeSeconds: 300}
destinations: {hooks: {}}
operationalTimeouts: {httpRequestMilliseconds: 10000, shutdownGraceMilliseconds: 30000, recordLockMilliseconds: 5000, migrationLockMilliseconds: 30000, migrationStatementMilliseconds: 60000}
EOF
}

render_runtime_config "$run_root/runtime-test.yaml" "$run_root/empty-package" \
	secret:file/test-runtime-url secret:file/test-migration-url \
	"$test_migration_role" "$test_runtime_role" 127.0.0.1:0 "payment-fee-test-$run_suffix"

cat >"$run_root/schema-test-credentials.yaml" <<'EOF'
apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1
kind: BRegSchemaTestCredentials
bindings:
  - {journeyId: exact-fee-before-issuance, stepId: create-authoritative-bill, credential: {type: bearer, tokenRef: secret:file/issuance-service-create-token}}
  - {journeyId: exact-fee-before-issuance, stepId: capture-bill-condition-after-create, credential: {type: bearer, tokenRef: secret:file/payment-adapter-bind-token}}
  - {journeyId: exact-fee-before-issuance, stepId: capture-issue-condition-after-create, credential: {type: bearer, tokenRef: secret:file/issuance-service-issue-token}}
  - {journeyId: exact-fee-before-issuance, stepId: fresh-workflow-cannot-create-another-bill, credential: {type: bearer, tokenRef: secret:file/issuance-service-create-token}}
  - {journeyId: exact-fee-before-issuance, stepId: issue-before-payment-is-refused, credential: {type: bearer, tokenRef: secret:file/issuance-service-issue-token}}
  - {journeyId: exact-fee-before-issuance, stepId: missing-scope-cannot-bind-attempt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-unauthorized-token}}
  - {journeyId: exact-fee-before-issuance, stepId: changed-version-cannot-bind, credential: {type: bearer, tokenRef: secret:file/payment-adapter-bind-token}}
  - {journeyId: exact-fee-before-issuance, stepId: changed-digest-cannot-bind, credential: {type: bearer, tokenRef: secret:file/payment-adapter-bind-token}}
  - {journeyId: exact-fee-before-issuance, stepId: bind-exact-payment-attempt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-bind-token}}
  - {journeyId: exact-fee-before-issuance, stepId: capture-bill-condition-after-bind, credential: {type: bearer, tokenRef: secret:file/payment-adapter-report-token}}
  - {journeyId: exact-fee-before-issuance, stepId: recover-exact-binding, credential: {type: bearer, tokenRef: secret:file/payment-adapter-bind-token}}
  - {journeyId: exact-fee-before-issuance, stepId: capture-bind-condition-after-bind, credential: {type: bearer, tokenRef: secret:file/payment-adapter-bind-token}}
  - {journeyId: exact-fee-before-issuance, stepId: capture-issue-condition-after-bind, credential: {type: bearer, tokenRef: secret:file/issuance-service-issue-token}}
  - {journeyId: exact-fee-before-issuance, stepId: pending-or-unknown-cannot-bind-second-attempt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-bind-token}}
  - {journeyId: exact-fee-before-issuance, stepId: pending-or-unknown-cannot-issue, credential: {type: bearer, tokenRef: secret:file/issuance-service-issue-token}}
  - {journeyId: exact-fee-before-issuance, stepId: missing-scope-cannot-report-receipt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-unauthorized-token}}
  - {journeyId: exact-fee-before-issuance, stepId: changed-bill-fact-cannot-report-receipt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-report-token}}
  - {journeyId: exact-fee-before-issuance, stepId: changed-amount-cannot-report-receipt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-report-token}}
  - {journeyId: exact-fee-before-issuance, stepId: changed-attempt-cannot-report-receipt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-report-token}}
  - {journeyId: exact-fee-before-issuance, stepId: changed-provider-binding-cannot-report-receipt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-report-token}}
  - {journeyId: exact-fee-before-issuance, stepId: simulation-mode-cannot-change-at-receipt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-report-token}}
  - {journeyId: exact-fee-before-issuance, stepId: record-exact-synthetic-receipt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-report-token}}
  - {journeyId: exact-fee-before-issuance, stepId: recover-exact-receipt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-report-token}}
  - {journeyId: exact-fee-before-issuance, stepId: read-exact-receipt-after-lost-acknowledgement, credential: {type: bearer, tokenRef: secret:file/payment-adapter-report-token}}
  - {journeyId: exact-fee-before-issuance, stepId: capture-bill-condition-after-receipt, credential: {type: bearer, tokenRef: secret:file/issuance-service-issue-token}}
  - {journeyId: exact-fee-before-issuance, stepId: capture-receipt-condition-after-receipt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-report-token}}
  - {journeyId: exact-fee-before-issuance, stepId: new-request-identity-cannot-replace-receipt, credential: {type: bearer, tokenRef: secret:file/payment-adapter-report-token}}
  - {journeyId: exact-fee-before-issuance, stepId: issue-after-exact-receipt, credential: {type: bearer, tokenRef: secret:file/issuance-service-issue-token}}
  - {journeyId: exact-fee-before-issuance, stepId: capture-bill-condition-after-issuance, credential: {type: bearer, tokenRef: secret:file/issuance-service-issue-token}}
  - {journeyId: exact-fee-before-issuance, stepId: issuance-is-single-use, credential: {type: bearer, tokenRef: secret:file/issuance-service-issue-token}}
EOF

run_json() {
	local output=$1
	shift
	"$bregctl" --format json "$@" >"$output"
	jq -e '.ok == true' "$output" >/dev/null
}

"$bregctl" --version >"$reports/bregctl-version.txt"
"$breg" --version >"$reports/breg-version.txt"
python3 - "$breg" "$bregctl" "$breg_feature_profile" "$bregctl_feature_profile" "$reports" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

breg, bregctl, breg_profile, bregctl_profile, reports = sys.argv[1:]
reports = Path(reports)

def binary(binary_path, version_file, feature_profile):
    path = Path(binary_path).resolve()
    return {
        "featureProfile": feature_profile,
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "version": (reports / version_file).read_text(encoding="utf-8").strip(),
    }

document = {
    "breg": binary(breg, "breg-version.txt", breg_profile),
    "bregctl": binary(bregctl, "bregctl-version.txt", bregctl_profile),
}
(reports / "binary-provenance.json").write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
git --no-optional-locks -C "$repository_root" rev-parse HEAD >"$reports/source-head.txt"
run_json "$reports/check.json" check "$fixture"
run_json "$reports/test.json" test "$fixture" \
	--runtime-config "$run_root/runtime-test.yaml" \
	--credentials "$run_root/schema-test-credentials.yaml" \
	--output "$run_root/schema-test-receipt.json"
schema_fingerprint=$(jq -er '.schemaFingerprint' "$reports/test.json")
readonly schema_fingerprint
run_json "$reports/package.json" package "$fixture" \
	--schema-fingerprint "$schema_fingerprint" \
	--test-receipt "$run_root/schema-test-receipt.json" \
	--output "$run_root/package-build" \
	--revision "payment-fee-issuance-$run_suffix"
package_digest=$(jq -er '.packageDigest' "$reports/package.json")
readonly package_digest

render_runtime_config "$run_root/runtime.yaml" "$run_root/package-build/package" \
	secret:file/runtime-runtime-url secret:file/runtime-migration-url \
	"$runtime_migration_role" "$runtime_runtime_role" "$listener" "payment-fee-runtime-$run_suffix"
run_json "$reports/plan.json" plan \
	--runtime-config "$run_root/runtime.yaml" \
	--package "$run_root/package-build/package" \
	--expected-digest "$package_digest"
run_json "$reports/apply.json" apply \
	--runtime-config "$run_root/runtime.yaml" \
	--package "$run_root/package-build/package" \
	--initial \
	--operator-reference payment-fee-issuance-native-acceptance \
	--expected-digest "$package_digest"
run_json "$reports/status.json" status --runtime-config "$run_root/runtime.yaml"

breg_pid=
stop_failed_launch() {
	local exit_code=$?
	if [[ "$exit_code" -ne 0 && -n "$breg_pid" ]] && kill -0 "$breg_pid" 2>/dev/null; then
		kill "$breg_pid" 2>/dev/null || true
	fi
}
trap stop_failed_launch EXIT
launch_environment=(BREG_LOG=info)
if [[ -n "${PAYMENT_FEE_DYLD_FALLBACK_LIBRARY_PATH:-}" ]]; then
	launch_environment+=("DYLD_FALLBACK_LIBRARY_PATH=$PAYMENT_FEE_DYLD_FALLBACK_LIBRARY_PATH")
fi
if [[ -n "${PAYMENT_FEE_DYLD_LIBRARY_PATH:-}" ]]; then
	launch_environment+=("DYLD_LIBRARY_PATH=$PAYMENT_FEE_DYLD_LIBRARY_PATH")
fi
nohup env "${launch_environment[@]}" "$breg" --runtime-config "$run_root/runtime.yaml" >"$reports/breg.log" 2>&1 &
breg_pid=$!
printf '%s\n' "$breg_pid" >"$run_root/breg.pid"

python3 - "$base_url/ready" <<'PY'
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

python3 - "$base_url" "$secrets/service-coordinator-token" "$reports/authorization-probes.json" <<'PY'
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

base_url, coordinator_token_file, output = sys.argv[1:]
coordinator_token = Path(coordinator_token_file).read_text(encoding="ascii").strip()
paths = [
    "/v1/actions/bind-payment-attempt?accessProfile=payment-adapter-binder",
    "/v1/actions/record-payment-receipt?accessProfile=payment-adapter-reporter",
]
results = []
for actor, token, expected in [
    ("service-coordinator", coordinator_token, 404),
    ("unauthenticated-citizen", None, 401),
]:
    for path in paths:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Idempotency-Key": f"probe-{actor}-{len(results)}",
        }
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(base_url + path, data=b"{}", method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status, body = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read()
        if status != expected:
            raise SystemExit(f"{actor} authorization probe returned {status}, expected {expected}")
        try:
            problem_code = json.loads(body).get("code")
        except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
            problem_code = None
        if actor == "service-coordinator" and problem_code != "resource.not_found":
            raise SystemExit("coordinator probe did not conceal the Adapter Action")
        results.append({"actor": actor, "path": path, "status": status, "problemCode": problem_code})
Path(output).write_text(json.dumps({"ok": True, "probes": results}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 - "$run_root/handoff.json" "$run_root" "$base_url" "$package_digest" "$schema_fingerprint" "$breg_pid" "$fixture" "$reports/source-head.txt" "$keep_running" "$reports/binary-provenance.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

output, root, base_url, package_digest, schema_fingerprint, pid, fixture, source_head_file, keep_running, binary_provenance_file = sys.argv[1:]
root = Path(root)
fixture = Path(fixture)
source_files = [
    "README.md",
    "lifecycle.sh",
    "registry.yaml",
    "run-native.sh",
    "tests/journeys.yaml",
    "tests/lifecycle-smoke.sh",
]
source_hashes = {
    relative: hashlib.sha256((fixture / relative).read_bytes()).hexdigest()
    for relative in source_files
}
source_inventory = "".join(f"{source_hashes[relative]}  {relative}\n" for relative in source_files)
document = {
    "mode": "synthetic-loopback-only",
    "baseUrl": base_url,
    "recordType": "service-fee-bill",
    "recordRoute": "service-fee-bills",
    "readProfile": "payment-adapter-reporter",
    "bind": {"action": "bind-payment-attempt", "profile": "payment-adapter-binder", "path": "/v1/actions/bind-payment-attempt?accessProfile=payment-adapter-binder"},
    "receipt": {"action": "record-payment-receipt", "profile": "payment-adapter-reporter", "path": "/v1/actions/record-payment-receipt?accessProfile=payment-adapter-reporter"},
    "create": {"action": "create-fee-bill", "profile": "service-biller", "path": "/v1/actions/create-fee-bill?accessProfile=service-biller"},
    "issue": {"action": "issue-paid-service", "profile": "service-issuer", "path": "/v1/actions/issue-paid-service?accessProfile=service-issuer"},
    "credentials": {
        "paymentAdapter": str(root / "secrets/payment-adapter-token"),
        "issuanceService": str(root / "secrets/issuance-service-token"),
        "serviceCoordinator": str(root / "secrets/service-coordinator-token"),
    },
    "runtimeConfig": str(root / "runtime.yaml"),
    "packageRoot": str(root / "package-build/package"),
    "packageDigest": package_digest,
    "schemaFingerprint": schema_fingerprint,
    "binaryProvenance": json.loads(Path(binary_provenance_file).read_text(encoding="utf-8")),
    "binaryProvenanceFile": binary_provenance_file,
    "helperLifetime": {
        "signalForwarding": {"HUP": "TERM", "INT": "INT", "TERM": "TERM"},
        "keepRunning": keep_running == "1",
        "mode": "retained-helper-session" if keep_running == "1" else "detached-handoff",
    },
    "sourceHead": Path(source_head_file).read_text(encoding="ascii").strip(),
    "fixtureSourceSha256": hashlib.sha256(source_inventory.encode("ascii")).hexdigest(),
    "sourceFilesSha256": source_hashes,
    "helperSha256": source_hashes["run-native.sh"],
    "pidFile": str(root / "breg.pid"),
    "pid": int(pid),
}
Path(output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
chmod 600 "$run_root/handoff.json" "$run_root/runtime.yaml" "$run_root/runtime-test.yaml" "$run_root/schema-test-credentials.yaml" "$reports/binary-provenance.json"
printf '%s\n' "$run_root" >"$scratch_root/latest-run"
chmod 600 "$scratch_root/latest-run"
trap - EXIT
printf 'Native BReg fixture is ready. Private handoff: %s\n' "$run_root/handoff.json"
if [[ "$keep_running" == "1" ]]; then
	printf 'Retaining this terminal for the owned BReg process. TERM and INT are forwarded; HUP is mapped to TERM.\n'
	payment_fee_wait_for_owned_child "$breg_pid"
fi
