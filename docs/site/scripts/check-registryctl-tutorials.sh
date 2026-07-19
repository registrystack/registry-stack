#!/usr/bin/env bash
#
# Execute the deployable Relay and Notary adopter tutorials against checked-out source.
# This is a source-under-test CI gate: it builds registryctl and the release
# product image shapes from the current checkout. It deliberately does not run
# the published installer or release assets; the fresh-reader release proof is
# tracked separately in GH#198. The gate writes a valid source-under-test image
# lock beside registryctl, then rebinds generated Compose files to the local
# images after each generation command.

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

PROJECT_DIRS=()
PROJECT_NAMES=()
CURRENT_SECRET_FILE=""
COMMAND_COUNTER=0
REGISTRYCTL_BIN=""
LAST_OUTPUT=""
SOURCE_IMAGE_LOCK=""

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
	if [[ -n "$SOURCE_IMAGE_LOCK" ]]; then
		rm -f "$SOURCE_IMAGE_LOCK"
	fi
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
				--features registry-relay/spdci-api-standards,registry-relay/standards-cel-mapping,registry-relay/ogcapi-edr,registry-notary/registry-notary-cel,registry-notary/pkcs11
			cargo build --release --locked \
				-p registry-notary-server \
				--bin registry-notary-cel-worker \
				--features registry-notary-server/registry-notary-cel'

	cp "$LINUX_TARGET/release/registry-relay" "$image_context/dist/image-bin/registry-relay"
	cp "$LINUX_TARGET/release/registry-relay-rhai-worker" "$image_context/dist/image-bin/registry-relay-rhai-worker"
	cp "$LINUX_TARGET/release/registry-notary" "$image_context/dist/image-bin/registry-notary"
	cp "$LINUX_TARGET/release/registry-notary-cel-worker" "$image_context/dist/image-bin/registry-notary-cel-worker"
	cp "$REPO_ROOT/LICENSE" "$image_context/LICENSE"
	chmod 0755 \
		"$image_context/dist/image-bin/registry-relay" \
		"$image_context/dist/image-bin/registry-relay-rhai-worker" \
		"$image_context/dist/image-bin/registry-notary" \
		"$image_context/dist/image-bin/registry-notary-cel-worker"

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

	local registryctl_version source_ref
	registryctl_version="$($REGISTRYCTL_BIN --version | awk '{print $2}')"
	if [[ ! "$registryctl_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		printf 'unexpected registryctl source version: %s\n' "$registryctl_version" >&2
		exit 1
	fi
	source_ref="$(git -C "$REPO_ROOT" rev-parse HEAD)"
	SOURCE_IMAGE_LOCK="$(dirname "$REGISTRYCTL_BIN")/registryctl-v${registryctl_version}-image-lock.json"
	printf '%s\n' \
		'{' \
		'  "schema_version": "registryctl.release_image_lock.v1",' \
		"  \"release_tag\": \"v${registryctl_version}\"," \
		"  \"manifest_source_ref\": \"${source_ref}\"," \
		"  \"tag_target\": \"${source_ref}\"," \
		'  "platform": "linux/amd64",' \
		'  "images": {' \
		'    "registry-relay": "ghcr.io/registrystack/registry-relay@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",' \
		'    "registry-notary": "ghcr.io/registrystack/registry-notary@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
		'  }' \
		'}' >"$SOURCE_IMAGE_LOCK"
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
				{
					docker compose -p "$COMPOSE_PROJECT_NAME" -f "$PWD/compose.yaml" ps --all
					for service in $(docker compose -p "$COMPOSE_PROJECT_NAME" -f "$PWD/compose.yaml" \
						ps --all --services); do
						printf '\n[%s]\n' "$service"
						docker compose -p "$COMPOSE_PROJECT_NAME" -f "$PWD/compose.yaml" \
							logs --no-color --tail 40 "$service"
					done
				} >"$diagnostic" 2>&1 || true
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

assert_json_fence_subset() {
	node "$HELPER" assert-json-fence-subset "$1" "$2" "$3" "$4"
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
		'["Install registryctl","Create the sample project","Start the local stack","Run the smoke check","Load local demo keys","Make one denied request","Make one allowed request","Read one protected record","Read one protected record","Read restricted identity fields","Read restricted identity fields","Inspect the generated contract","Inspect the generated contract","Run an aggregate","Change the disclosure rule","Change the disclosure rule","Change the disclosure rule","Change the disclosure rule","Change the disclosure rule","Stop the stack"]'
	node "$HELPER" extract-shell "$RELAY_TUTORIAL" "$blocks"

	expected_install=$'curl -fsSL https://raw.githubusercontent.com/registrystack/registry-stack/refs/tags/v0.11.0/crates/registryctl/install.sh | REGISTRYCTL_VERSION=v0.11.0 bash\nregistryctl --version'
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
	assert_contains "$LAST_OUTPUT" 'registryctl 0.11.0'
	run_block 'Relay 2: Create the sample project' "$blocks/02.sh" success
	CURRENT_SECRET_FILE="$PWD/secrets/local.env"
	run_block 'Relay 3: Start the local stack' "$blocks/03.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Start the local stack' text 1
	run_block 'Relay 4: Run the smoke check' "$blocks/04.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Run the smoke check' text 1
	[[ -s output/smoke-results.json ]] || { printf 'Relay smoke report is missing\n' >&2; exit 1; }
	run_block 'Relay 5: Load local demo keys' "$blocks/05.sh" success
	[[ -n "${METADATA_READER_RAW:-}" && -n "${ROW_READER_RAW:-}" && -n "${AGGREGATE_READER_RAW:-}" && -n "${IDENTITY_READER_RAW:-}" ]] || {
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
	assert_contains "$LAST_OUTPUT" per-2001 hh-1001 date_of_birth
	assert_not_contains "$LAST_OUTPUT" age_band eligibility_status is_primary_applicant
	assert_json_fence_subset "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Read one protected record' 1
	run_block 'Relay 9: Refuse metadata-only row read' "$blocks/09.sh" success
	assert_problem "$LAST_OUTPUT" 403 auth.scope_denied
	run_block 'Relay 10: Refuse operational key on identity projection' "$blocks/10.sh" success
	assert_problem "$LAST_OUTPUT" 403 auth.scope_denied
	assert_json_fence_subset "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Read restricted identity fields' 1
	run_block 'Relay 11: Read restricted identity projection' "$blocks/11.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_contains "$LAST_OUTPUT" Fae Elm FAKE-856648 '595 River Rd, Southvale'
	assert_json_fence_subset "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Read restricted identity fields' 2
	run_block 'Relay 12: Inspect the generated contract' "$blocks/12.sh" success
	run_block 'Relay 13: Open the runtime API reference' "$blocks/13.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Inspect the generated contract' text 1
	run_block 'Relay 14: Run an aggregate' "$blocks/14.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_json_fence_subset "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Run an aggregate' 1

	node "$HELPER" set-relay-min-group-size relay/config.yaml benefits_casework by_district 3
	run_block 'Relay 15: Restart with a stronger disclosure floor' "$blocks/15.sh" success
	run_block 'Relay 16: Verify all aggregate groups are suppressed' "$blocks/16.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_json_fence_subset "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Change the disclosure rule' 1

	node "$HELPER" set-relay-min-group-size relay/config.yaml benefits_casework by_district 1
	run_block 'Relay 17: Reject a disclosure floor below the invariant' "$blocks/17.sh" failure
	assert_contains "$LAST_OUTPUT" 'Relay did not become healthy and ready before timeout'
	run_block 'Relay 18: Explain the rejected configuration' "$blocks/18.sh" success
	assert_contains "$LAST_OUTPUT" config.validation_error 'min_cell_size >= 2'

	node "$HELPER" set-relay-min-group-size relay/config.yaml benefits_casework by_district 2
	run_block 'Relay 19: Restore the valid disclosure floor' "$blocks/19.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$RELAY_TUTORIAL" 'Start the local stack' text 1
	run_block 'Relay 20: Stop the stack' "$blocks/20.sh" success
	cleanup_stack "$tutorial_root/my-first-api" "$project_name"
	node "$HELPER" assert-ports-free 4242 4255
}

run_relay_tutorial

run_notary_tutorial() {
	local blocks="$WORK_ROOT/notary-blocks"
	local tutorial_root="$WORK_ROOT/relay-reader"
	local project_dir="$tutorial_root/my-first-api"
	local project_name="registryctl-notary-$RUN_ID"
	local edited_claim="$WORK_ROOT/registry-stack-accept-pending.yaml"

	node "$HELPER" assert-layout "$NOTARY_TUTORIAL" \
		'["Add Notary to the project","Inspect the claim","Start Relay and Notary","Load the evaluator key","Evaluate an accepted active registration","Reject a pending registration","Try a non-matching date of birth","Edit the claim rule","Evaluate the edited rule","Stop the stack"]'
	node "$HELPER" extract-shell "$NOTARY_TUTORIAL" "$blocks"

	export COMPOSE_PROJECT_NAME="$project_name"
	PROJECT_DIRS+=("$project_dir")
	PROJECT_NAMES+=("$project_name")
	CURRENT_SECRET_FILE="$project_dir/secrets/local.env"
	cd "$project_dir"

	run_block 'Notary 1: Add Notary to the project' "$blocks/01.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$NOTARY_TUTORIAL" 'Add Notary to the project' text 1
	assert_contains "$LAST_OUTPUT" http://127.0.0.1:4255 notary/project/registry-stack.yaml
	run_block 'Notary 2: Inspect the claim' "$blocks/02.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$NOTARY_TUTORIAL" 'Inspect the claim' yaml 1
	assert_contains "$LAST_OUTPUT" request.target.attributes.given_name request.target.attributes.date_of_birth person-registration-accepted
	run_block 'Notary 3: Start Relay and Notary' "$blocks/03.sh" success
	assert_fence_lines "$LAST_OUTPUT" "$NOTARY_TUTORIAL" 'Start Relay and Notary' text 1
	run_block 'Notary 4: Load the evaluator key' "$blocks/04.sh" success
	[[ -n "${TUTORIAL_EVALUATOR_RAW:-}" ]] || {
		printf 'Notary tutorial evaluator credential was not loaded\n' >&2
		exit 1
	}
	run_block 'Notary 5: Evaluate an accepted active registration' "$blocks/05.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_json_fence_subset "$LAST_OUTPUT" "$NOTARY_TUTORIAL" 'Evaluate an accepted active registration' 1
	assert_not_contains "$LAST_OUTPUT" Jo Elm 2019-02-03 '"active"'
	run_block 'Notary 6: Reject a pending registration' "$blocks/06.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_json_fence_subset "$LAST_OUTPUT" "$NOTARY_TUTORIAL" 'Reject a pending registration' 1
	assert_not_contains "$LAST_OUTPUT" Nia Stone 1998-03-05 '"pending"'
	run_block 'Notary 7: Try a non-matching date of birth' "$blocks/07.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_json_fence_subset "$LAST_OUTPUT" "$NOTARY_TUTORIAL" 'Try a non-matching date of birth' 1
	assert_not_contains "$LAST_OUTPUT" Jo Elm 2019-02-04 '"active"'

	node "$HELPER" replace-once \
		notary/project/registry-stack.yaml \
		'enrollment.registration_status == "active"' \
		'(enrollment.registration_status == "active" || enrollment.registration_status == "pending")' \
		"$edited_claim"
	mv "$edited_claim" notary/project/registry-stack.yaml
	node "$HELPER" replace-once \
		notary/project/integrations/person-demographics/fixtures/pending.yaml \
		'claims: { person-registration-accepted: false }' \
		'claims: { person-registration-accepted: true }' \
		"$edited_claim"
	mv "$edited_claim" notary/project/integrations/person-demographics/fixtures/pending.yaml
	run_block 'Notary 8: Restart with the edited claim rule' "$blocks/08.sh" success
	assert_contains "$LAST_OUTPUT" 'Relay API:' 'Notary API:'
	run_block 'Notary 9: Evaluate the edited rule' "$blocks/09.sh" success
	assert_http "$LAST_OUTPUT" 200
	assert_json_fence_subset "$LAST_OUTPUT" "$NOTARY_TUTORIAL" 'Evaluate the edited rule' 1
	assert_not_contains "$LAST_OUTPUT" Nia Stone 1998-03-05 '"pending"'
	run_block 'Notary 10: Stop the stack' "$blocks/10.sh" success
	cleanup_stack "$project_dir" "$project_name"
	node "$HELPER" assert-ports-free 4242 4255
}

run_notary_tutorial
