#!/usr/bin/env bash
#
# Execute the current Registryctl authoring tutorials from fresh reader directories.
#
# This gate builds Registryctl from the checked-out source unless
# REGISTRYCTL_BIN selects exact candidate or released bytes. It proves the
# init, test, check, build, and disposable development smoke contract. The
# tag-triggered release workflow separately exercises the exact installer,
# signed release lock, doctor, release-bound runtime sequence, and governed
# deployment.

set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$SITE_ROOT/../.." && pwd)"
HELPER="$SITE_ROOT/scripts/registryctl-tutorial.mjs"
RELEASED_DOCS_ROOT="${REGISTRYCTL_RELEASED_DOCS_ROOT:-}"
if [[ -n "$RELEASED_DOCS_ROOT" ]]; then
	if [[ "$RELEASED_DOCS_ROOT" != /* || -L "$RELEASED_DOCS_ROOT" || ! -d "$RELEASED_DOCS_ROOT" ]]; then
		printf 'REGISTRYCTL_RELEASED_DOCS_ROOT must be an absolute real directory: %s\n' \
			"$RELEASED_DOCS_ROOT" >&2
		exit 1
	fi
	HTTP_TUTORIAL="$RELEASED_DOCS_ROOT/tutorials/author-registry-project.md"
	SPREADSHEET_TUTORIAL="$RELEASED_DOCS_ROOT/tutorials/publish-spreadsheet-secured-registry-api.md"
	USE_SPREADSHEET_TUTORIAL="$RELEASED_DOCS_ROOT/tutorials/use-your-spreadsheet.md"
	EVIDENCE_TUTORIAL="$RELEASED_DOCS_ROOT/tutorials/verify-claim-registry-api.md"
	OAUTH_TUTORIAL="$RELEASED_DOCS_ROOT/tutorials/configure-project-script-adapter.md"
	OAUTH_HOWTO="$RELEASED_DOCS_ROOT/configure/oauth-client-credentials.md"
	OPENCRVS_TUTORIAL="$RELEASED_DOCS_ROOT/tutorials/verify-opencrvs-claims.md"
	OPENCRVS_OVERLAY="$RELEASED_DOCS_ROOT/examples/registryctl/opencrvs-events-api-overlay-v1.sh"
	PUBLIC_SOURCE_OVERLAY="$RELEASED_DOCS_ROOT/examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh"
else
	HTTP_TUTORIAL="$SITE_ROOT/src/content/docs/tutorials/author-registry-project.mdx"
	SPREADSHEET_TUTORIAL="$SITE_ROOT/src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx"
	USE_SPREADSHEET_TUTORIAL="$SITE_ROOT/src/content/docs/tutorials/use-your-spreadsheet.mdx"
	EVIDENCE_TUTORIAL="$SITE_ROOT/src/content/docs/tutorials/verify-claim-registry-api.mdx"
	OAUTH_TUTORIAL="$SITE_ROOT/src/content/docs/tutorials/configure-project-script-adapter.mdx"
	OAUTH_HOWTO="$SITE_ROOT/src/content/docs/configure/oauth-client-credentials.mdx"
	OPENCRVS_TUTORIAL="$SITE_ROOT/src/content/docs/tutorials/verify-opencrvs-claims.mdx"
	OPENCRVS_OVERLAY="$SITE_ROOT/public/examples/registryctl/opencrvs-events-api-overlay-v1.sh"
	PUBLIC_SOURCE_OVERLAY="$SITE_ROOT/public/examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh"
fi
TARGET_DIR="$REPO_ROOT/target/registryctl-tutorial-source"
BUILD_PROFILE="${REGISTRYCTL_TUTORIAL_CARGO_PROFILE:-ci}"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/registryctl-tutorial-source.XXXXXX")"
REGISTRYCTL_BIN="${REGISTRYCTL_BIN:-}"
EVIDENCE_DIR="${REGISTRYCTL_TUTORIAL_EVIDENCE_DIR:-}"
RETAINED_PROJECT="${REGISTRYCTL_TUTORIAL_PROJECT_DIR:-}"
RETAINED_OAUTH_PROJECT="${REGISTRYCTL_TUTORIAL_OAUTH_PROJECT_DIR:-}"
RUNNER_MODE="source"
REPORT_ROOT="$WORK_ROOT/reports"
REGISTRYCTL_VERSION="unknown"
ACTIVE_DEV_PROJECT=""

cleanup() {
	local exit_code=$?
	set +e
	if [[ -n "$ACTIVE_DEV_PROJECT" && -x "$REGISTRYCTL_BIN" ]]; then
		"$REGISTRYCTL_BIN" -C "$ACTIVE_DEV_PROJECT" dev down >/dev/null 2>&1
	fi
	rm -rf "$WORK_ROOT"
	if ((exit_code == 0)); then
		printf 'Registryctl %s reader journeys: PASS\n' "$REGISTRYCTL_VERSION"
	else
		printf 'Registryctl %s reader journeys: FAIL (exit %d)\n' \
			"$REGISTRYCTL_VERSION" "$exit_code" >&2
	fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for tool in curl node grep python3; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		printf 'required tool not on PATH: %s\n' "$tool" >&2
		exit 1
	fi
done
if [[ ! -f "$OPENCRVS_OVERLAY" ]]; then
	printf 'public OpenCRVS Events API overlay is missing: %s\n' "$OPENCRVS_OVERLAY" >&2
	printf 'run npm run generate before the reader gate\n' >&2
	exit 1
fi
if [[ ! -f "$OPENCRVS_OVERLAY.sha256" ]]; then
	printf 'public OpenCRVS Events API overlay checksum is missing: %s\n' \
		"$OPENCRVS_OVERLAY.sha256" >&2
	printf 'run npm run generate before the reader gate\n' >&2
	exit 1
fi
if [[ ! -f "$PUBLIC_SOURCE_OVERLAY" ]]; then
	printf 'public no-credential source overlay is missing: %s\n' "$PUBLIC_SOURCE_OVERLAY" >&2
	printf 'run npm run generate before the reader gate\n' >&2
	exit 1
fi
if [[ ! -f "$PUBLIC_SOURCE_OVERLAY.sha256" ]]; then
	printf 'public no-credential source overlay checksum is missing: %s\n' \
		"$PUBLIC_SOURCE_OVERLAY.sha256" >&2
	printf 'run npm run generate before the reader gate\n' >&2
	exit 1
fi
if [[ -n "$EVIDENCE_DIR" ]]; then
	if [[ "$EVIDENCE_DIR" != /* ]]; then
		printf 'REGISTRYCTL_TUTORIAL_EVIDENCE_DIR must be absolute: %s\n' "$EVIDENCE_DIR" >&2
		exit 1
	fi
	if [[ -e "$EVIDENCE_DIR" ]]; then
		printf 'tutorial evidence directory must be absent: %s\n' "$EVIDENCE_DIR" >&2
		exit 1
	fi
	mkdir -p "$EVIDENCE_DIR"
	REPORT_ROOT="$EVIDENCE_DIR"
fi
if [[ -n "$RETAINED_PROJECT" ]]; then
	if [[ "$RETAINED_PROJECT" != /* ]]; then
		printf 'REGISTRYCTL_TUTORIAL_PROJECT_DIR must be absolute: %s\n' "$RETAINED_PROJECT" >&2
		exit 1
	fi
	if [[ -e "$RETAINED_PROJECT" ]]; then
		printf 'retained HTTP tutorial project must be absent: %s\n' "$RETAINED_PROJECT" >&2
		exit 1
	fi
fi
if [[ -n "$RETAINED_OAUTH_PROJECT" ]]; then
	if [[ "$RETAINED_OAUTH_PROJECT" != /* ]]; then
		printf 'REGISTRYCTL_TUTORIAL_OAUTH_PROJECT_DIR must be absolute: %s\n' \
			"$RETAINED_OAUTH_PROJECT" >&2
		exit 1
	fi
	if [[ -e "$RETAINED_OAUTH_PROJECT" ]]; then
		printf 'retained OAuth tutorial project must be absent: %s\n' \
			"$RETAINED_OAUTH_PROJECT" >&2
		exit 1
	fi
	if [[ "$RETAINED_OAUTH_PROJECT" == "$RETAINED_PROJECT" ]]; then
		printf 'retained HTTP and OAuth tutorial projects must be distinct\n' >&2
		exit 1
	fi
fi

node "$HELPER" assert-contains "$HTTP_TUTORIAL" \
	'registryctl init my-registry --template http' \
	'registryctl test' \
	'registryctl dev smoke' \
	'registryctl check --explain' \
	'registryctl build'
node "$HELPER" assert-contains "$SPREADSHEET_TUTORIAL" \
	'registryctl init my-first-registry --template spreadsheet' \
	'project-record-snapshot' \
	'registryctl test' \
	'registryctl dev smoke' \
	'registryctl check --explain' \
	'registryctl build'
node "$HELPER" assert-contains "$EVIDENCE_TUTORIAL" \
	'project-status-accepted' \
	'project.status == "planned"' \
	'default_fixture: planned' \
	'registryctl dev --detach' \
	'registryctl dev smoke' \
	'registryctl dev down' \
	'registryctl check --explain' \
	'registryctl build'
node "$HELPER" assert-contains "$OAUTH_HOWTO" \
	'request: form' \
	'request: json' \
	'response_profile: oauth2_bearer' \
	'response_profile: oauth2_bearer_no_expiry' \
	'caching is disabled'
node "$HELPER" assert-contains "$OAUTH_TUTORIAL" \
	'type: oauth2_client_credentials' \
	'capability:' \
	'file: adapter.rhai' \
	'opencrvs-events-api-overlay-v1.sh' \
	'OVERLAY_URL="https://docs.registrystack.org/v/$REGISTRYCTL_VERSION/examples/registryctl/$OVERLAY"' \
	'../verify-opencrvs-claims/' \
	'registryctl test' \
	'registryctl check --explain' \
	'registryctl build'
node "$HELPER" assert-contains "$OPENCRVS_TUTORIAL" \
	'OAuth' \
	'Rhai' \
	'POST /api/events/events/search' \
	'birth-event-found' \
	'birth-event-registered' \
	'opencrvs-events-api-overlay-v1.sh' \
	'OVERLAY_URL="https://docs.registrystack.org/v/$REGISTRYCTL_VERSION/examples/registryctl/$OVERLAY"' \
	'registryctl test' \
	'registryctl check --explain' \
	'registryctl build'

if [[ -n "$REGISTRYCTL_BIN" ]]; then
	if [[ "$REGISTRYCTL_BIN" != /* ]]; then
		printf 'REGISTRYCTL_BIN must be an absolute installed-binary path: %s\n' "$REGISTRYCTL_BIN" >&2
		exit 1
	fi
	RUNNER_MODE="sealed"
	printf 'using the explicitly installed Registryctl binary\n'
else
	if ! command -v cargo >/dev/null 2>&1; then
		printf 'required tool not on PATH: cargo\n' >&2
		exit 1
	fi
	if [[ "$BUILD_PROFILE" != "ci" && "$BUILD_PROFILE" != "release" ]]; then
		printf 'unsupported tutorial Cargo profile: %s (expected ci or release)\n' "$BUILD_PROFILE" >&2
		exit 1
	fi
	printf 'building the exact Registryctl source binary\n'
	CARGO_INCREMENTAL=0 \
	CARGO_PROFILE_DEV_DEBUG=0 \
	CARGO_PROFILE_TEST_DEBUG=0 \
	CARGO_TARGET_DIR="$TARGET_DIR" \
		cargo build --locked --profile "$BUILD_PROFILE" -p registryctl
	REGISTRYCTL_BIN="$TARGET_DIR/$BUILD_PROFILE/registryctl"
fi
if [[ ! -x "$REGISTRYCTL_BIN" ]]; then
	printf 'Registryctl binary is not executable: %s\n' "$REGISTRYCTL_BIN" >&2
	exit 1
fi
REGISTRYCTL_VERSION="$("$REGISTRYCTL_BIN" --version | awk 'NR == 1 { print $2 }')"
if [[ ! "$REGISTRYCTL_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
	printf 'unexpected Registryctl version: %s\n' "$REGISTRYCTL_VERSION" >&2
	exit 1
fi

verify_overlay_asset() {
	local overlay=$1
	python3 - "$overlay" "$overlay.sha256" <<'PY'
import hashlib
import hmac
import sys
from pathlib import Path

overlay = Path(sys.argv[1])
lines = Path(sys.argv[2]).read_text(encoding="ascii").splitlines()
if len(lines) != 1:
    raise SystemExit("overlay checksum file must contain exactly one line")
expected, separator, filename = lines[0].partition("  ")
if separator != "  " or filename != overlay.name:
    raise SystemExit("overlay checksum file names the wrong asset")
actual = hashlib.sha256(overlay.read_bytes()).hexdigest()
if not hmac.compare_digest(actual, expected):
    raise SystemExit("overlay checksum mismatch")
PY
}

verify_overlay_asset "$OPENCRVS_OVERLAY"
verify_overlay_asset "$PUBLIC_SOURCE_OVERLAY"

run_reports() {
	local project_directory=$1
	local label=$2
	local project_id="${3:-}"
	local minimization_mode="${4:-derived}"
	local report_directory="$REPORT_ROOT/$label"
	mkdir -p "$report_directory"

	"$REGISTRYCTL_BIN" -C "$project_directory" test --format json >"$report_directory/test.json"
	"$REGISTRYCTL_BIN" -C "$project_directory" check --format json >"$report_directory/check.json"
	"$REGISTRYCTL_BIN" -C "$project_directory" build --format json >"$report_directory/build.json"
	if [[ -n "$project_id" ]]; then
		node "$HELPER" assert-project-reports \
			"$report_directory/test.json" \
			"$report_directory/check.json" \
			"$report_directory/build.json" \
			"$project_id" \
			"$minimization_mode"
	else
		node "$HELPER" assert-project-reports \
			"$report_directory/test.json" \
			"$report_directory/check.json" \
			"$report_directory/build.json"
	fi

	for lane in relay-public relay-consultation notary; do
		test -f \
			"$project_directory/.registry-stack/build/local/signing-inputs/$lane/signing-input.v1.json"
	done
	test -f "$project_directory/.registry-stack/build/local/artifact-manifest.json"
	test ! -e "$project_directory/.registry-stack/runtime"

	if grep -E -r -n \
		'REGISTRYCTL_LOCAL_.*_RAW=|api_key_raw|audit_hash_secret|client_secret[[:space:]]*:[[:space:]]*[^{$]' \
		"$project_directory/.registry-stack/build"; then
		printf 'secret-shaped material leaked into %s build output\n' "$label" >&2
		exit 1
	fi
}

run_spreadsheet_runtime() {
	local project_directory=$1
	local report_directory=$2
	local project_id=$3
	local district_code=$4
	local sector=$5
	local status=$6
	local records_denied_config
	local records_config
	local evidence_config
	local evidence_body
	local denied_status

	if [[ "$RUNNER_MODE" != "sealed" ]]; then
		return
	fi

	mkdir -p "$report_directory"
	ACTIVE_DEV_PROJECT="$project_directory"
	"$REGISTRYCTL_BIN" -C "$project_directory" dev --detach \
		>"$report_directory/dev-start.txt"
	records_denied_config="$(find \
		"$project_directory/.registry-stack/dev/local" \
		-type f -path '*/credentials/records-denied.curl' -print)"
	records_config="$(find \
		"$project_directory/.registry-stack/dev/local" \
		-type f -path '*/credentials/records-request.curl' -print)"
	evidence_config="$(find \
		"$project_directory/.registry-stack/dev/local" \
		-type f -path '*/credentials/request.curl' -print)"
	evidence_body="$(find \
		"$project_directory/.registry-stack/dev/local" \
		-type f -path '*/credentials/request.json' -print)"
	for request_artifact in \
		"$records_denied_config" \
		"$records_config" \
		"$evidence_config" \
		"$evidence_body"; do
		if [[ -z "$request_artifact" || "$request_artifact" == *$'\n'* ]]; then
			printf 'expected exactly one generated development request artifact per public journey\n' >&2
			exit 1
		fi
	done
	node "$HELPER" assert-contains "$report_directory/dev-start.txt" \
		'Relay API: http://127.0.0.1:4242' \
		'Evidence API: http://127.0.0.1:4243' \
		"Records denied request: curl --config '$records_denied_config'" \
		"Records request: curl --config '$records_config'" \
		"Evidence request: curl --config '$evidence_config'"
	denied_status="$(curl --silent --show-error \
		--config "$records_denied_config" \
		--no-include \
		--output "$report_directory/records-denied.json" \
		--write-out '%{http_code}')"
	if [[ "$denied_status" != "401" ]]; then
		printf 'anonymous records request returned HTTP %s, expected 401\n' \
			"$denied_status" >&2
		exit 1
	fi
	node "$HELPER" assert-json-subset "$report_directory/records-denied.json" \
		'{"status":401,"code":"auth.missing_credential"}'
	curl --silent --show-error --config "$records_config" \
		>"$report_directory/records-request.json"
	node "$HELPER" assert-json-subset "$report_directory/records-request.json" \
		"{\"project_id\":\"$project_id\",\"district_code\":\"$district_code\",\"sector\":\"$sector\",\"status\":\"$status\"}"
	node "$HELPER" assert-not-contains "$report_directory/records-request.json" \
		'PW-002' \
		'PW-003'
	node "$HELPER" assert-json-subset "$evidence_body" \
		"{\"target\":{\"identifiers\":[{\"scheme\":\"project_id\",\"value\":\"$project_id\"}]}}"
	curl --silent --show-error --config "$evidence_config" \
		>"$report_directory/evidence-request.json"
	node "$HELPER" assert-json-subset "$report_directory/evidence-request.json" \
		'{"results":[{"claim_id":"project-record-exists","value":true,"satisfied":true,"disclosure":"predicate"},{"claim_id":"project-status-accepted","value":true,"satisfied":true,"disclosure":"predicate"}]}'
	node "$HELPER" assert-not-contains "$report_directory/evidence-request.json" \
		'north-01' \
		'water' \
		'active' \
		'planned'
	"$REGISTRYCTL_BIN" -C "$project_directory" dev smoke \
		>"$report_directory/dev-smoke.txt"
	node "$HELPER" assert-contains "$report_directory/dev-smoke.txt" \
		'Development smoke: passed.' \
		'unauthorized: status=denied; passed=true; token_counter_delta=unobserved; source_counter_delta=unobserved' \
		'authorized: status=authorized; passed=true; token_counter_delta=unobserved; source_counter_delta=unobserved' \
		'minimized_claim_ids=project-record-exists,project-status-accepted'
	"$REGISTRYCTL_BIN" -C "$project_directory" dev down \
		>"$report_directory/dev-down.txt"
	ACTIVE_DEV_PROJECT=""
}

run_synthetic_runtime() {
	local project_directory=$1
	local report_directory=$2
	local expected_token_delta=$3
	local expected_claim_ids=$4

	if [[ "$RUNNER_MODE" != "sealed" ]]; then
		return
	fi

	mkdir -p "$report_directory"
	ACTIVE_DEV_PROJECT="$project_directory"
	"$REGISTRYCTL_BIN" -C "$project_directory" dev --detach \
		>"$report_directory/dev-start.txt"
	node "$HELPER" assert-contains "$report_directory/dev-start.txt" \
		'Relay API: http://127.0.0.1:4242' \
		'Evidence API: http://127.0.0.1:4243' \
		'Evidence request: curl --config '
	if find "$project_directory/.registry-stack/dev/local" -type f \
		\( -name 'relay-*-tls.*' -o -name 'notary-tls.*' \) -print -quit | grep -q .; then
		printf 'development runtime generated obsolete product listener TLS material\n' >&2
		exit 1
	fi
	"$REGISTRYCTL_BIN" -C "$project_directory" dev smoke \
		>"$report_directory/dev-smoke.txt"
	node "$HELPER" assert-contains "$report_directory/dev-smoke.txt" \
		'Development smoke: passed.' \
		'unauthorized: status=denied; passed=true; token_counter_delta=0; source_counter_delta=0' \
		"authorized: status=authorized; passed=true; token_counter_delta=$expected_token_delta; source_counter_delta=1" \
		"minimized_claim_ids=$expected_claim_ids"
	"$REGISTRYCTL_BIN" -C "$project_directory" dev down \
		>"$report_directory/dev-down.txt"
	ACTIVE_DEV_PROJECT=""
}

HTTP_PROJECT="${RETAINED_PROJECT:-$WORK_ROOT/http-reader}"
mkdir -p "$REPORT_ROOT/http"
"$REGISTRYCTL_BIN" init "$HTTP_PROJECT" --template http >"$REPORT_ROOT/http/init.txt"
node "$HELPER" assert-fence-equals \
	"$REPORT_ROOT/http/init.txt" \
	"$HTTP_TUTORIAL" \
	'Create the bounded HTTP integration' \
	text \
	1 \
	"$HTTP_PROJECT" \
	my-registry
run_reports "$HTTP_PROJECT" http
run_synthetic_runtime \
	"$HTTP_PROJECT" \
	"$REPORT_ROOT/http/runtime" \
	0 \
	'person-active,person-record-exists'
(
	cd "$HTTP_PROJECT"
	"$REGISTRYCTL_BIN" test
) >"$REPORT_ROOT/http/test.txt"
node "$HELPER" assert-fence-equals \
	"$REPORT_ROOT/http/test.txt" "$HTTP_TUTORIAL" 'Test the authored contract' text 1
(
	cd "$HTTP_PROJECT"
	"$REGISTRYCTL_BIN" test \
		--integration person-record \
		--fixture active-person \
		--trace
) >"$REPORT_ROOT/http/trace.txt"
node "$HELPER" assert-fence-equals \
	"$REPORT_ROOT/http/trace.txt" "$HTTP_TUTORIAL" 'Test the authored contract' text 2
(
	cd "$HTTP_PROJECT"
	"$REGISTRYCTL_BIN" build
) >"$REPORT_ROOT/http/build.txt"
node "$HELPER" assert-fence-equals \
	"$REPORT_ROOT/http/build.txt" "$HTTP_TUTORIAL" 'Review and build the project' text 1
printf 'HTTP reader journey: PASS\n'

SPREADSHEET_PROJECT="$WORK_ROOT/spreadsheet-reader"
mkdir -p "$REPORT_ROOT/spreadsheet"
"$REGISTRYCTL_BIN" init "$SPREADSHEET_PROJECT" --template spreadsheet \
	>"$REPORT_ROOT/spreadsheet/init.txt"
node "$HELPER" assert-fence-equals \
	"$REPORT_ROOT/spreadsheet/init.txt" \
	"$SPREADSHEET_TUTORIAL" \
	'Create the spreadsheet registry' \
	text \
	1 \
	"$SPREADSHEET_PROJECT" \
	my-first-registry
run_reports \
	"$SPREADSHEET_PROJECT" \
	spreadsheet \
	fictional-public-works-registry \
	snapshot
(
	cd "$SPREADSHEET_PROJECT"
	"$REGISTRYCTL_BIN" test
) >"$REPORT_ROOT/spreadsheet/test.txt"
node "$HELPER" assert-fence-equals \
		"$REPORT_ROOT/spreadsheet/test.txt" \
		"$SPREADSHEET_TUTORIAL" \
		'Test the starter' \
		text \
		1
run_spreadsheet_runtime \
	"$SPREADSHEET_PROJECT" \
	"$REPORT_ROOT/spreadsheet/runtime" \
	pw_001 \
	north-01 \
	water \
	active
(
	cd "$SPREADSHEET_PROJECT"
	"$REGISTRYCTL_BIN" test \
		--integration project-record-snapshot \
		--fixture match \
		--trace
) >"$REPORT_ROOT/spreadsheet/trace.txt"
node "$HELPER" assert-fence-equals \
		"$REPORT_ROOT/spreadsheet/trace.txt" \
		"$SPREADSHEET_TUTORIAL" \
		'Inspect the contract you own' \
		text \
		1
(
	cd "$SPREADSHEET_PROJECT"
	"$REGISTRYCTL_BIN" build
) >"$REPORT_ROOT/spreadsheet/build.txt"
node "$HELPER" assert-fence-equals \
	"$REPORT_ROOT/spreadsheet/build.txt" \
	"$SPREADSHEET_TUTORIAL" \
	'Build the review inputs' \
	text \
	1
printf 'Spreadsheet reader journey: PASS\n'

ADAPTED_SPREADSHEET_PROJECT="$WORK_ROOT/spreadsheet-adapted-reader"
ADAPTED_SPREADSHEET_REPORT="$REPORT_ROOT/spreadsheet-adapted"
mkdir -p "$ADAPTED_SPREADSHEET_REPORT"
"$REGISTRYCTL_BIN" init "$ADAPTED_SPREADSHEET_PROJECT" --template spreadsheet \
	>"$ADAPTED_SPREADSHEET_REPORT/init.txt"
python3 - "$ADAPTED_SPREADSHEET_PROJECT/data/public_works_projects.xlsx" <<'PY'
import os
import sys
import tempfile
import zipfile
from pathlib import Path

workbook = Path(sys.argv[1])
descriptor, temporary_name = tempfile.mkstemp(dir=workbook.parent, suffix=".xlsx")
os.close(descriptor)
temporary = Path(temporary_name)
replacements = 0
try:
    with zipfile.ZipFile(workbook, "r") as source, zipfile.ZipFile(temporary, "w") as target:
        for entry in source.infolist():
            data = source.read(entry.filename)
            if entry.filename == "xl/worksheets/sheet1.xml":
                updated = data.replace(b">pw_001<", b">institution_001<")
                replacements += updated.count(b">institution_001<")
                data = updated
            target.writestr(entry, data)
    if replacements != 1:
        raise SystemExit("maintained workbook did not contain one pw_001 selector")
    os.replace(temporary, workbook)
finally:
    temporary.unlink(missing_ok=True)
PY
node "$HELPER" replace-fence-pair \
	"$USE_SPREADSHEET_TUTORIAL" \
	'Record the source revision' yaml 1 \
	'Record the source revision' yaml 2 \
	"$ADAPTED_SPREADSHEET_PROJECT/environments/local.yaml"
node "$HELPER" replace-fence-pair \
	"$USE_SPREADSHEET_TUTORIAL" \
	'Select one reviewed smoke row' yaml 1 \
	'Select one reviewed smoke row' yaml 2 \
	"$ADAPTED_SPREADSHEET_PROJECT/environments/local.yaml"
node "$HELPER" replace-fence-pair \
	"$USE_SPREADSHEET_TUTORIAL" \
	'Select one reviewed smoke row' yaml 3 \
	'Select one reviewed smoke row' yaml 4 \
	"$ADAPTED_SPREADSHEET_PROJECT/integrations/project-record-snapshot/fixtures/match.yaml"
(
	cd "$ADAPTED_SPREADSHEET_PROJECT"
	"$REGISTRYCTL_BIN" test
) >"$ADAPTED_SPREADSHEET_REPORT/test.txt"
run_reports \
	"$ADAPTED_SPREADSHEET_PROJECT" \
	spreadsheet-adapted \
	fictional-public-works-registry \
	snapshot
run_spreadsheet_runtime \
	"$ADAPTED_SPREADSHEET_PROJECT" \
	"$ADAPTED_SPREADSHEET_REPORT/runtime" \
	institution_001 \
	north-01 \
	water \
	active
printf 'Adapted spreadsheet reader journey: PASS\n'

EVIDENCE_PROJECT="$SPREADSHEET_PROJECT"
EVIDENCE_REPORT="$REPORT_ROOT/spreadsheet-evidence"
mkdir -p "$EVIDENCE_REPORT"
(
	cd "$EVIDENCE_PROJECT"
	"$REGISTRYCTL_BIN" test \
		--integration project-record-snapshot \
		--fixture planned \
		--trace
) >"$EVIDENCE_REPORT/before-trace.txt"
node "$HELPER" assert-contains "$EVIDENCE_REPORT/before-trace.txt" \
	'PASS project-record-snapshot.planned' \
	'claims: project-record-exists'

node "$HELPER" replace-fence-pair \
	"$EVIDENCE_TUTORIAL" \
	'Change the authored evidence rule' yaml 1 \
	'Change the authored evidence rule' yaml 2 \
	"$EVIDENCE_PROJECT/registry-stack.yaml"
node "$HELPER" replace-fence-pair \
	"$EVIDENCE_TUTORIAL" \
	'Observe the current policy result' yaml 1 \
	'Change the authored evidence rule' yaml 3 \
	"$EVIDENCE_PROJECT/integrations/project-record-snapshot/fixtures/planned.yaml"
node "$HELPER" replace-fence-pair \
	"$EVIDENCE_TUTORIAL" \
	'Run the changed Relay and Notary path' yaml 1 \
	'Run the changed Relay and Notary path' yaml 2 \
	"$EVIDENCE_PROJECT/environments/local.yaml"

(
	cd "$EVIDENCE_PROJECT"
	"$REGISTRYCTL_BIN" test \
		--integration project-record-snapshot \
		--fixture planned \
		--trace
) >"$EVIDENCE_REPORT/after-trace.txt"
node "$HELPER" assert-contains "$EVIDENCE_REPORT/after-trace.txt" \
	'PASS project-record-snapshot.planned' \
	'claims: project-record-exists, project-status-accepted' \
	'outcome: match'
(
	cd "$EVIDENCE_PROJECT"
	"$REGISTRYCTL_BIN" test
) >"$EVIDENCE_REPORT/test.txt"

run_spreadsheet_runtime \
	"$EVIDENCE_PROJECT" \
	"$EVIDENCE_REPORT/runtime" \
	PW-002 \
	central-02 \
	health \
	planned

run_reports \
	"$EVIDENCE_PROJECT" \
	spreadsheet-evidence \
	fictional-public-works-registry \
	snapshot
printf 'Spreadsheet evidence-change reader journey: PASS\n'

PUBLIC_SOURCE_PROJECT="$WORK_ROOT/public-source-reader"
"$REGISTRYCTL_BIN" init "$PUBLIC_SOURCE_PROJECT" --template http \
	>"$REPORT_ROOT/public-source-init.txt"
(
	cd "$PUBLIC_SOURCE_PROJECT"
	sh "$PUBLIC_SOURCE_OVERLAY"
) >"$REPORT_ROOT/public-source-overlay.txt"
"$REGISTRYCTL_BIN" -C "$PUBLIC_SOURCE_PROJECT" test --environment local \
	>"$REPORT_ROOT/public-source-test.txt"
"$REGISTRYCTL_BIN" -C "$PUBLIC_SOURCE_PROJECT" check \
	--environment public-demo --explain \
	>"$REPORT_ROOT/public-source-check.txt"
"$REGISTRYCTL_BIN" -C "$PUBLIC_SOURCE_PROJECT" check \
	--environment public-demo-missing --explain \
	>"$REPORT_ROOT/public-source-missing-check.txt"
node "$HELPER" assert-contains "$REPORT_ROOT/public-source-test.txt" \
	'Registry Stack test: passed for public-json-live-demo.'
node "$HELPER" assert-contains "$REPORT_ROOT/public-source-check.txt" \
	'Registry Stack check: valid for public-json-live-demo.' \
	'Explanation:' \
	'registry.project.explanation.v1' \
	'public-todo' \
	'todo-verification'
node "$HELPER" assert-contains "$REPORT_ROOT/public-source-missing-check.txt" \
	'Registry Stack check: valid for public-json-live-demo.' \
	'public-demo-missing'
if grep -E -r -q 'credential:[[:space:]]' \
	"$PUBLIC_SOURCE_PROJECT/environments" \
	"$PUBLIC_SOURCE_PROJECT/integrations"; then
	printf 'public-source overlay unexpectedly declares a source credential\n' >&2
	exit 1
fi
printf 'Public no-credential source offline journey: PASS\n'

OPENCRVS_PROJECT="${RETAINED_OAUTH_PROJECT:-$WORK_ROOT/opencrvs-reader}"
"$REGISTRYCTL_BIN" init "$OPENCRVS_PROJECT" --template http \
	>"$REPORT_ROOT/opencrvs-init.txt"
(
	cd "$OPENCRVS_PROJECT"
	sh "$OPENCRVS_OVERLAY"
) >"$REPORT_ROOT/opencrvs-overlay.txt"
node "$HELPER" assert-fence-equals \
	"$REPORT_ROOT/opencrvs-overlay.txt" \
	"$OPENCRVS_TUTORIAL" \
	'Before you start' \
	text \
	1

OPENCRVS_PROJECT_FILE="$OPENCRVS_PROJECT/registry-stack.yaml"
OPENCRVS_ENVIRONMENT="$OPENCRVS_PROJECT/environments/local.yaml"
OPENCRVS_INTEGRATION="$OPENCRVS_PROJECT/integrations/birth-event-search/integration.yaml"
OPENCRVS_ADAPTER="$OPENCRVS_PROJECT/integrations/birth-event-search/adapter.rhai"
OPENCRVS_MATCH="$OPENCRVS_PROJECT/integrations/birth-event-search/fixtures/match.yaml"
node "$HELPER" assert-fence-file-equals \
	"$OPENCRVS_TUTORIAL" 'Declare the synthetic event lookup' yaml 1 "$OPENCRVS_INTEGRATION"
node "$HELPER" assert-fence-in-file \
	"$OPENCRVS_TUTORIAL" 'Declare the synthetic event lookup' yaml 2 "$OPENCRVS_PROJECT_FILE"
node "$HELPER" assert-fence-in-file \
	"$OPENCRVS_TUTORIAL" 'Bind OAuth and source origins' yaml 1 "$OPENCRVS_ENVIRONMENT"
node "$HELPER" assert-fence-in-file \
	"$OPENCRVS_TUTORIAL" 'Bind OAuth and source origins' yaml 2 "$OPENCRVS_ENVIRONMENT"
node "$HELPER" assert-fence-file-equals \
	"$OPENCRVS_TUTORIAL" 'Map the minimized outputs' rhai 1 "$OPENCRVS_ADAPTER"
node "$HELPER" assert-fence-in-file \
	"$OPENCRVS_TUTORIAL" 'Keep one consultation-backed claim' yaml 1 "$OPENCRVS_PROJECT_FILE"
node "$HELPER" assert-fence-file-equals \
	"$OPENCRVS_TUTORIAL" 'Author the synthetic match fixture' yaml 1 "$OPENCRVS_MATCH"

if ! grep -E -r -q 'type:[[:space:]]*oauth2_client_credentials' "$OPENCRVS_PROJECT"; then
	printf 'public OpenCRVS overlay does not declare OAuth client credentials\n' >&2
	exit 1
fi
if ! grep -E -r -q 'response_profile:[[:space:]]*oauth2_bearer_no_expiry' "$OPENCRVS_PROJECT"; then
	printf 'public OpenCRVS overlay does not declare the strict no-expiry OAuth profile\n' >&2
	exit 1
fi
if ! grep -E -r -q 'file:[[:space:]]*adapter[.]rhai' "$OPENCRVS_PROJECT"; then
	printf 'public OpenCRVS overlay does not declare its reviewed Rhai adapter\n' >&2
	exit 1
fi
if ! find "$OPENCRVS_PROJECT" -name adapter.rhai -type f -print -quit | grep -q .; then
	printf 'public OpenCRVS overlay does not contain its reviewed Rhai adapter\n' >&2
	exit 1
fi
"$REGISTRYCTL_BIN" -C "$OPENCRVS_PROJECT" check --explain \
	>"$REPORT_ROOT/opencrvs-check-explain.txt"
node "$HELPER" assert-contains "$REPORT_ROOT/opencrvs-check-explain.txt" \
	'Registry Stack check: valid for synthetic-opencrvs-events-api.' \
	'Explanation:' \
	'registry.project.explanation.v1' \
	'birth-event-search' \
	'birth-event-verification' \
	'oauth2_client_credentials' \
	'birth-event-found' \
	'birth-event-registered'
run_reports "$OPENCRVS_PROJECT" opencrvs
run_synthetic_runtime \
	"$OPENCRVS_PROJECT" \
	"$REPORT_ROOT/opencrvs/runtime" \
	1 \
	'birth-event-found,birth-event-registered'
printf 'OAuth and Rhai reader journey: PASS\n'
printf 'OpenCRVS Events API case-study journey: PASS\n'

node "$HELPER" write-evidence-manifest \
	"$REPORT_ROOT" \
	"$RUNNER_MODE" \
	"$REGISTRYCTL_VERSION" \
	"$RETAINED_PROJECT" \
	"$RETAINED_OAUTH_PROJECT"
if [[ -n "$EVIDENCE_DIR" ]]; then
	printf 'reader-journey evidence: %s\n' "$EVIDENCE_DIR"
fi
if [[ -n "$RETAINED_PROJECT" ]]; then
	printf 'retained HTTP project: %s\n' "$RETAINED_PROJECT"
fi
if [[ -n "$RETAINED_OAUTH_PROJECT" ]]; then
	printf 'retained OAuth and Rhai project: %s\n' "$RETAINED_OAUTH_PROJECT"
fi
printf '%s\n' \
	'release-boundary note: disposable runtime runs only with an explicitly installed sealed binary'
