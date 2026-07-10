#!/usr/bin/env bash
#
# Execute the two adopter registryctl tutorials against checked-out source.
# This is a source-under-test CI gate: it builds registryctl and the release
# product image shapes from the current checkout. It deliberately does not run
# the published installer or release assets; the fresh-reader release proof is
# tracked separately in GH#198. The generated Compose files are rebound to the
# local images after each registryctl generation command so GH#278 cannot turn
# this gate into either a false failure or a false green.

set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$SITE_ROOT/../.." && pwd)"
HELPER="$SITE_ROOT/scripts/registryctl-tutorial.mjs"
RELAY_TUTORIAL="$SITE_ROOT/src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx"
NOTARY_TUTORIAL="$SITE_ROOT/src/content/docs/tutorials/verify-claim-registry-api.mdx"
BUILDER_IMAGE="rust:1.95-bookworm@sha256:4c2fd73ef19c5ef9d54bee03b06b2839a392604fbfcd578ed948b71b37c1d7fb"
LINUX_TARGET="$REPO_ROOT/target/registryctl-tutorial-linux-amd64"
CARGO_HOME_DIR="$REPO_ROOT/target/registryctl-tutorial-cargo-home"
NATIVE_TARGET="$REPO_ROOT/target/registryctl-tutorial-native"
RUN_ID="${GITHUB_RUN_ID:-local}-$$-$(date -u +%s)"
RELAY_IMAGE="registryctl-tutorial-relay:$RUN_ID"
NOTARY_IMAGE="registryctl-tutorial-notary:$RUN_ID"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/registryctl-tutorial.XXXXXX")"
HTTP_STATUS_PREFIX="__REGISTRYCTL_TUTORIAL_HTTP_STATUS__:"
TUTORIAL_PURPOSE="https://example.local/purpose/tutorial"
CASEWORK_PURPOSE="https://example.local/purpose/casework-review"

PROJECT_DIRS=()
PROJECT_NAMES=()
CURRENT_SECRET_FILE=""
COMMAND_COUNTER=0
REGISTRYCTL_BIN=""
LAST_OUTPUT=""

cleanup_stack() {
	local project_dir="$1"
	local project_name="$2"
	if [[ -f "$project_dir/compose.yaml" ]]; then
		docker compose -p "$project_name" -f "$project_dir/compose.yaml" \
			down -v --remove-orphans >/dev/null 2>&1 || true
	fi
}

cleanup() {
	local exit_code=$?
	set +e
	for index in "${!PROJECT_DIRS[@]}"; do
		cleanup_stack "${PROJECT_DIRS[$index]}" "${PROJECT_NAMES[$index]}"
	done
	docker image rm -f "$RELAY_IMAGE" "$NOTARY_IMAGE" >/dev/null 2>&1 || true
	rm -rf "$WORK_ROOT"
	if ((exit_code == 0)); then
		printf 'registryctl tutorial source check: PASS\n'
	else
		printf 'registryctl tutorial source check: FAIL (exit %d)\n' "$exit_code" >&2
	fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for tool in cargo curl docker node; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		printf 'required tool not on PATH: %s\n' "$tool" >&2
		exit 1
	fi
done
if ! docker info >/dev/null 2>&1; then
	printf 'Docker is not available\n' >&2
	exit 1
fi
if [[ ! -f "$SITE_ROOT/node_modules/yaml/package.json" ]]; then
	printf 'docs dependencies are not installed; run npm ci in %s\n' "$SITE_ROOT" >&2
	exit 1
fi

node "$HELPER" assert-ports-free 4242 4255

build_source_under_test() {
	local image_context="$WORK_ROOT/image-context"
	local host_arch
	mkdir -p "$LINUX_TARGET" "$CARGO_HOME_DIR" "$image_context/dist/image-bin"

	printf 'building current registryctl, Relay, and Notary for linux/amd64\n'
	docker run --rm \
		--platform linux/amd64 \
		--user "$(id -u):$(id -g)" \
		--volume "$REPO_ROOT:/workspace" \
		--workdir /workspace \
		--env CARGO_HOME=/workspace/target/registryctl-tutorial-cargo-home \
		--env CARGO_TARGET_DIR=/workspace/target/registryctl-tutorial-linux-amd64 \
		--env CARGO_TERM_COLOR=always \
		--env HOME=/tmp/registryctl-tutorial-home \
		"$BUILDER_IMAGE" \
		bash -c 'set -euo pipefail
			cargo build --release --locked \
				-p registryctl \
				-p registry-relay \
				-p registry-notary \
				--features registry-relay/spdci-api-standards,registry-relay/standards-cel-mapping,registry-relay/ogcapi-edr,registry-notary/registry-notary-cel,registry-notary/pkcs11'

	cp "$LINUX_TARGET/release/registry-relay" "$image_context/dist/image-bin/registry-relay"
	cp "$LINUX_TARGET/release/registry-notary" "$image_context/dist/image-bin/registry-notary"
	cp "$REPO_ROOT/LICENSE" "$image_context/LICENSE"
	chmod 0755 "$image_context/dist/image-bin/registry-relay" "$image_context/dist/image-bin/registry-notary"

	DOCKER_BUILDKIT=1 docker build \
		--platform linux/amd64 \
		--file "$REPO_ROOT/release/docker/Dockerfile.registry-relay" \
		--tag "$RELAY_IMAGE" \
		"$image_context"
	DOCKER_BUILDKIT=1 docker build \
		--platform linux/amd64 \
		--file "$REPO_ROOT/release/docker/Dockerfile.registry-notary" \
		--tag "$NOTARY_IMAGE" \
		"$image_context"

	host_arch="$(uname -m)"
	if [[ "$(uname -s)" == "Linux" && "$host_arch" == "x86_64" ]]; then
		REGISTRYCTL_BIN="$LINUX_TARGET/release/registryctl"
	else
		printf 'building a native registryctl command for %s/%s\n' "$(uname -s)" "$host_arch"
		CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$NATIVE_TARGET" \
			cargo build --locked -p registryctl
		REGISTRYCTL_BIN="$NATIVE_TARGET/debug/registryctl"
	fi
	[[ -x "$REGISTRYCTL_BIN" ]] || {
		printf 'registryctl source binary is not executable: %s\n' "$REGISTRYCTL_BIN" >&2
		exit 1
	}
}

sanitize_output() {
	local output="$1"
	if [[ -n "$CURRENT_SECRET_FILE" && -f "$CURRENT_SECRET_FILE" ]]; then
		node "$HELPER" sanitize "$output" "$CURRENT_SECRET_FILE"
	else
		node "$HELPER" sanitize "$output"
	fi
}

run_block() {
	local label="$1"
	local block="$2"
	local expected="$3"
	local output status
	COMMAND_COUNTER=$((COMMAND_COUNTER + 1))
	output="$WORK_ROOT/command-$(printf '%03d' "$COMMAND_COUNTER").log"
	printf '\n=== %s ===\n' "$label"
	sed 's/^/  /' "$block"
	set +e
	# shellcheck disable=SC1090
	source "$block" >"$output" 2>&1
	status=$?
	set -e
	sanitize_output "$output"
	case "$expected" in
	success)
			if ((status != 0)); then
				if [[ -f "$PWD/compose.yaml" ]]; then
					local diagnostic
					diagnostic="$WORK_ROOT/command-$(printf '%03d' "$COMMAND_COUNTER")-compose.log"
				docker compose -p "$COMPOSE_PROJECT_NAME" -f "$PWD/compose.yaml" \
					logs --no-color --tail 100 >"$diagnostic" 2>&1 || true
				printf '\n--- sanitized Compose log tail ---\n' >&2
				sanitize_output "$diagnostic" >&2
			fi
			printf '%s failed with exit %d\n' "$label" "$status" >&2
			exit 1
		fi
		;;
	failure)
		if ((status == 0)); then
			printf '%s unexpectedly succeeded\n' "$label" >&2
			exit 1
		fi
		;;
	*)
		printf 'invalid expected status: %s\n' "$expected" >&2
		exit 1
		;;
	esac
	LAST_OUTPUT="$output"
}

curl() {
	command curl "$@" --write-out $'\n'"${HTTP_STATUS_PREFIX}%{http_code}"$'\n'
}

rebind_project() {
	local project_dir="$1"
	node "$HELPER" rebind-project "$project_dir" "$RELAY_IMAGE" "$NOTARY_IMAGE"
	printf 'source-under-test images rebound in %s\n' "$project_dir"
}

registryctl() {
	local status project_dir
	"$REGISTRYCTL_BIN" "$@"
	status=$?
	if ((status == 0)); then
		if [[ "${1:-}" == "init" && "${2:-}" == "relay" && -n "${3:-}" ]]; then
			project_dir="$PWD/$3"
			if ! rebind_project "$project_dir"; then
				return 1
			fi
			CURRENT_SECRET_FILE="$project_dir/secrets/local.env"
		elif [[ "${1:-}" == "add" && "${2:-}" == "notary" ]]; then
			if ! rebind_project "$PWD"; then
				return 1
			fi
			CURRENT_SECRET_FILE="$PWD/secrets/local.env"
		fi
	fi
	return "$status"
}

assert_fence_lines() {
	node "$HELPER" assert-fence-lines "$1" "$2" "$3" "$4" "$5"
}

assert_contains() {
	local output="$1"
	shift
	node "$HELPER" assert-contains "$output" "$@"
}

assert_not_contains() {
	local output="$1"
	shift
	node "$HELPER" assert-not-contains "$output" "$@"
}

assert_http() {
	node "$HELPER" assert-http "$1" "$2"
}

assert_problem() {
	node "$HELPER" assert-problem "$1" "$2" "$3"
}

assert_json_subset() {
	node "$HELPER" assert-json-subset "$1" "$2"
}

build_source_under_test
export DOCKER_DEFAULT_PLATFORM=linux/amd64

run_relay_tutorial() {
	local blocks="$WORK_ROOT/relay-blocks"
	local tutorial_root="$WORK_ROOT/relay-reader"
	local project_name="registryctl-relay-$RUN_ID"
	local expected_install version_block
	mkdir -p "$tutorial_root"

	node "$HELPER" assert-layout "$RELAY_TUTORIAL" \
		'["Install registryctl","Create the sample project","Start the local stack","Run the smoke check","Load local demo keys","Make one denied request","Make one allowed request","Read one protected record","Read one protected record","Inspect the generated contract","Inspect the generated contract","Run an aggregate","Change the disclosure rule","Change the disclosure rule","Change the disclosure rule","Change the disclosure rule","Change the disclosure rule","Stop the stack"]'
	node "$HELPER" extract-shell "$RELAY_TUTORIAL" "$blocks"

	expected_install=$'curl -fsSL https://raw.githubusercontent.com/registrystack/registry-stack/refs/tags/v0.8.4/crates/registryctl/install.sh | REGISTRYCTL_VERSION=v0.8.4 bash\nregistryctl --version'
	if [[ "$(cat "$blocks/01.sh")" != "$expected_install" ]]; then
		printf 'release-only install block changed; update the explicit source-under-test boundary\n' >&2
		exit 1
	fi
	version_block="$WORK_ROOT/source-version.sh"
	printf 'registryctl --version\n' >"$version_block"

	export COMPOSE_PROJECT_NAME="$project_name"
	PROJECT_DIRS+=("$tutorial_root/my-first-api")
	PROJECT_NAMES+=("$project_name")
	CURRENT_SECRET_FILE=""
	cd "$tutorial_root"
	printf '\nrelease installer skipped: this gate uses the checked-out registryctl; GH#198 verifies release assets\n'
	run_block 'Relay 1: source registryctl version' "$version_block" success
	assert_contains "$LAST_OUTPUT" 'registryctl 0.8.4'
	run_block 'Relay 2: Create the sample project' "$blocks/02.sh" success
	CURRENT_SECRET_FILE="$PWD/secrets/local.env"
	run_block 'Relay 3: Start the local stack' "$blocks/03.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Start the local stack' text 1
	run_block 'Relay 4: Run the smoke check' "$blocks/04.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Run the smoke check' text 1
	[[ -s output/smoke-results.json ]] || { printf 'Relay smoke report is missing\n' >&2; exit 1; }
	run_block 'Relay 5: Load local demo keys' "$blocks/05.sh" success
	[[ -n "${METADATA_READER_RAW:-}" && -n "${ROW_READER_RAW:-}" && -n "${AGGREGATE_READER_RAW:-}" ]] || {
		printf 'required Relay tutorial credentials were not loaded\n' >&2
		exit 1
	}
	run_block 'Relay 6: Make one denied request' "$blocks/06.sh" success
	assert_problem "$LAST_OUTPUT" 401 auth.missing_credential
	run_block 'Relay 7: Make one allowed request' "$blocks/07.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_contains "$LAST_OUTPUT" benefits_casework
	run_block 'Relay 8: Read one protected record' "$blocks/08.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_contains "$LAST_OUTPUT" per-2001 hh-1001
	run_block 'Relay 9: Refuse metadata-only row read' "$blocks/09.sh" success
	assert_problem "$LAST_OUTPUT" 403 auth.scope_denied
	run_block 'Relay 10: Inspect the generated contract' "$blocks/10.sh" success
	run_block 'Relay 11: Open the runtime API reference' "$blocks/11.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Inspect the generated contract' text 1
	run_block 'Relay 12: Run an aggregate' "$blocks/12.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_json_subset "$LAST_OUTPUT" '{"disclosure_control":{"min_cell_size":2,"suppression":"omit"},"observations":[{"district":"north","household_count":2},{"district":"south","household_count":2}]}'

	node "$HELPER" set-relay-min-group-size relay/config.yaml benefits_casework by_district 3
	run_block 'Relay 13: Restart with a stronger disclosure floor' "$blocks/13.sh" success
	run_block 'Relay 14: Verify all aggregate groups are suppressed' "$blocks/14.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_json_subset "$LAST_OUTPUT" '{"disclosure_control":{"min_cell_size":3,"suppression":"omit"},"observations":[]}'

	node "$HELPER" set-relay-min-group-size relay/config.yaml benefits_casework by_district 1
	run_block 'Relay 15: Reject a disclosure floor below the invariant' "$blocks/15.sh" failure
	assert_contains "$LAST_OUTPUT" 'Relay did not become healthy and ready before timeout'
	run_block 'Relay 16: Explain the rejected configuration' "$blocks/16.sh" success
	assert_contains "$LAST_OUTPUT" config.validation_error 'min_cell_size >= 2'

	node "$HELPER" set-relay-min-group-size relay/config.yaml benefits_casework by_district 2
	run_block 'Relay 17: Restore the valid disclosure floor' "$blocks/17.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Start the local stack' text 1
	run_block 'Relay 18: Stop the stack' "$blocks/18.sh" success
	cleanup_stack "$tutorial_root/my-first-api" "$project_name"
	node "$HELPER" assert-ports-free 4242 4255
}

run_notary_tutorial() {
	local blocks="$WORK_ROOT/notary-blocks"
	local tutorial_root="$WORK_ROOT/notary-reader"
	local project_name="registryctl-notary-$RUN_ID"
	local permitted_request="$WORK_ROOT/notary-permitted-request.sh"
	mkdir -p "$tutorial_root"

	node "$HELPER" assert-layout "$NOTARY_TUTORIAL" \
		'["Start from the local API","Add Notary","Start Relay and Notary","Run the Notary smoke check","Load local demo keys","Make one denied claim request","List the available claim","Evaluate one claim","Try an unknown person","Compare a row read and a claim result","Compare a row read and a claim result","Inspect the generated claim","Inspect the generated claim","Change the purpose the claim accepts","Change the purpose the claim accepts","Change the purpose the claim accepts","Stop the stack"]'
	node "$HELPER" assert-contains "$NOTARY_TUTORIAL" "$CASEWORK_PURPOSE"
	node "$HELPER" extract-shell "$NOTARY_TUTORIAL" "$blocks"

	export COMPOSE_PROJECT_NAME="$project_name"
	PROJECT_DIRS+=("$tutorial_root/my-first-api")
	PROJECT_NAMES+=("$project_name")
	CURRENT_SECRET_FILE=""
	cd "$tutorial_root"
	run_block 'Notary 1: Recreate and verify the Relay prerequisite' "$blocks/01.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Run the smoke check' text 1
	CURRENT_SECRET_FILE="$PWD/secrets/local.env"
	run_block 'Notary 2: Add Notary' "$blocks/02.sh" success
	run_block 'Notary 3: Start Relay and Notary' "$blocks/03.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$NOTARY_TUTORIAL" 'Start Relay and Notary' text 1
	run_block 'Notary 4: Run the Notary smoke check' "$blocks/04.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$NOTARY_TUTORIAL" 'Run the Notary smoke check' text 1
	[[ -s output/notary-smoke-results.json ]] || { printf 'Notary smoke report is missing\n' >&2; exit 1; }
	run_block 'Notary 5: Load local demo keys' "$blocks/05.sh" success
	[[ -n "${REGISTRY_NOTARY_TUTORIAL_EVALUATOR_RAW:-}" && -n "${ROW_READER_RAW:-}" ]] || {
		printf 'required Notary tutorial credentials were not loaded\n' >&2
		exit 1
	}
	run_block 'Notary 6: Make one denied claim request' "$blocks/06.sh" success
	assert_problem "$LAST_OUTPUT" 401 auth.missing_credential
	run_block 'Notary 7: List the available claim' "$blocks/07.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_contains "$LAST_OUTPUT" benefits-person-exists
	run_block 'Notary 8: Evaluate one claim' "$blocks/08.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_json_subset "$LAST_OUTPUT" '{"results":[{"claim_id":"benefits-person-exists","disclosure":"predicate","format":"application/vnd.registry-notary.claim-result+json","satisfied":true,"subject_type":"person","value":true}]}'
	assert_not_contains "$LAST_OUTPUT" per-2001 hh-1001
	run_block 'Notary 9: Try an unknown person' "$blocks/09.sh" success
	assert_problem "$LAST_OUTPUT" 409 evidence.not_available
	run_block 'Notary 10: Compare the source row read' "$blocks/10.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_contains "$LAST_OUTPUT" per-2001
	run_block 'Notary 11: Compare the minimized claim result' "$blocks/11.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_json_subset "$LAST_OUTPUT" '{"results":[{"claim_id":"benefits-person-exists","satisfied":true,"value":true}]}'
	assert_not_contains "$LAST_OUTPUT" per-2001 hh-1001
	run_block 'Notary 12: Inspect the generated claim' "$blocks/12.sh" success
	assert_contains "$LAST_OUTPUT" allowed_purposes "$TUTORIAL_PURPOSE"
	run_block 'Notary 13: Open the Notary API reference' "$blocks/13.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$NOTARY_TUTORIAL" 'Inspect the generated claim' text 1

	node "$HELPER" set-notary-purposes notary/config.yaml benefits-person-exists person \
		"[\"$CASEWORK_PURPOSE\"]"
	run_block 'Notary 14: Restart with a different allowed purpose' "$blocks/14.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$NOTARY_TUTORIAL" 'Start Relay and Notary' text 1
	run_block 'Notary 15: Refuse the old purpose before evidence lookup' "$blocks/15.sh" success
	assert_problem "$LAST_OUTPUT" 403 pdp.purpose_not_permitted

	node "$HELPER" replace-once "$blocks/15.sh" "$TUTORIAL_PURPOSE" "$CASEWORK_PURPOSE" \
		"$permitted_request"
	run_block 'Notary 15b: Accept the newly allowed purpose' "$permitted_request" success
	assert_http "$LAST_OUTPUT" 200
	assert_json_subset "$LAST_OUTPUT" '{"results":[{"claim_id":"benefits-person-exists","satisfied":true,"value":true}]}'
	assert_not_contains "$LAST_OUTPUT" per-2001 hh-1001

	node "$HELPER" set-notary-purposes notary/config.yaml benefits-person-exists person \
		"[\"$TUTORIAL_PURPOSE\"]"
	run_block 'Notary 16: Restore purpose policy and smoke checks' "$blocks/16.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$NOTARY_TUTORIAL" 'Run the Notary smoke check' text 1
	run_block 'Notary 17: Stop the stack' "$blocks/17.sh" success
	cleanup_stack "$tutorial_root/my-first-api" "$project_name"
	node "$HELPER" assert-ports-free 4242 4255
}

run_relay_tutorial
run_notary_tutorial
