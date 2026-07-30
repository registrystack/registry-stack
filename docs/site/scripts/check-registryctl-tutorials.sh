#!/usr/bin/env bash
#
# Execute the current Registryctl authoring tutorials from fresh reader directories.
#
# This pull-request gate builds Registryctl from the checked-out source and
# proves the offline init, test, check, and build contract. It does not stand in
# for the release workflow, which separately exercises the sealed installer,
# released image lock, doctor, and disposable development runtime.

set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$SITE_ROOT/../.." && pwd)"
HELPER="$SITE_ROOT/scripts/registryctl-tutorial.mjs"
HTTP_TUTORIAL="$SITE_ROOT/src/content/docs/tutorials/author-registry-project.mdx"
OAUTH_TUTORIAL="$SITE_ROOT/src/content/docs/tutorials/configure-project-script-adapter.mdx"
OAUTH_HOWTO="$SITE_ROOT/src/content/docs/configure/oauth-client-credentials.mdx"
OPENCRVS_TUTORIAL="$SITE_ROOT/src/content/docs/tutorials/verify-opencrvs-claims.mdx"
OPENCRVS_OVERLAY="$SITE_ROOT/public/examples/registryctl/opencrvs-events-api-overlay-v1.sh"
PUBLIC_SOURCE_OVERLAY="$SITE_ROOT/public/examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh"
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

cleanup() {
	local exit_code=$?
	set +e
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

for tool in node grep; do
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
if [[ ! -f "$PUBLIC_SOURCE_OVERLAY" ]]; then
	printf 'public no-credential source overlay is missing: %s\n' "$PUBLIC_SOURCE_OVERLAY" >&2
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
		printf 'retained tutorial project must be absent: %s\n' "$RETAINED_PROJECT" >&2
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
	'rm -r integrations/person-record' \
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
	'rm -r integrations/person-record' \
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

run_reports() {
	local project_directory=$1
	local label=$2
	local report_directory="$REPORT_ROOT/$label"
	mkdir -p "$report_directory"

	"$REGISTRYCTL_BIN" -C "$project_directory" test --format json >"$report_directory/test.json"
	"$REGISTRYCTL_BIN" -C "$project_directory" check --format json >"$report_directory/check.json"
	"$REGISTRYCTL_BIN" -C "$project_directory" build --format json >"$report_directory/build.json"
	node "$HELPER" assert-project-reports \
		"$report_directory/test.json" \
		"$report_directory/check.json" \
		"$report_directory/build.json"

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

HTTP_PROJECT="${RETAINED_PROJECT:-$WORK_ROOT/http-reader}"
mkdir -p "$REPORT_ROOT/http"
"$REGISTRYCTL_BIN" init "$HTTP_PROJECT" --template http >"$REPORT_ROOT/http/init.txt"
node "$HELPER" assert-fence-equals \
	"$REPORT_ROOT/http/init.txt" \
	"$HTTP_TUTORIAL" \
	'Create the HTTP project' \
	text \
	1 \
	"$HTTP_PROJECT" \
	my-registry
run_reports "$HTTP_PROJECT" http
"$REGISTRYCTL_BIN" -C "$HTTP_PROJECT" test >"$REPORT_ROOT/http/test.txt"
node "$HELPER" assert-fence-equals \
	"$REPORT_ROOT/http/test.txt" "$HTTP_TUTORIAL" 'Test the authored contract' text 1
"$REGISTRYCTL_BIN" -C "$HTTP_PROJECT" test \
	--integration person-record \
	--fixture active-person \
	--trace >"$REPORT_ROOT/http/trace.txt"
node "$HELPER" assert-fence-equals \
	"$REPORT_ROOT/http/trace.txt" "$HTTP_TUTORIAL" 'Test the authored contract' text 2
"$REGISTRYCTL_BIN" -C "$HTTP_PROJECT" build >"$REPORT_ROOT/http/build.txt"
node "$HELPER" assert-fence-equals \
	"$REPORT_ROOT/http/build.txt" "$HTTP_TUTORIAL" 'Review and build the project' text 1
printf 'HTTP reader journey: PASS\n'

PUBLIC_SOURCE_PROJECT="$WORK_ROOT/public-source-reader"
"$REGISTRYCTL_BIN" init "$PUBLIC_SOURCE_PROJECT" --template http \
	>"$REPORT_ROOT/public-source-init.txt"
rm -r "$PUBLIC_SOURCE_PROJECT/integrations/person-record"
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
rm -r "$OPENCRVS_PROJECT/integrations/person-record"
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
	'release-boundary note: exact runtime sequence is release-gated from the sealed candidate payload'
