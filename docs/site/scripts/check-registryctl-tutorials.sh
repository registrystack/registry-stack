#!/usr/bin/env bash
#
# Verify the canonical first-API tutorial against checked-out source.
#
# This source-contract gate deliberately does not execute the release installer
# or local runtime. The candidate workflow runs the exact sealed installer,
# doctor, start, smoke, denied, allowed, listener, and stop sequence through
# release/scripts/first-country-release-form.py. Keeping those roles separate
# prevents a locally rewritten image reference from standing in for immutable
# candidate evidence.

set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$SITE_ROOT/../.." && pwd)"
HELPER="$SITE_ROOT/scripts/registryctl-tutorial.mjs"
TUTORIAL="$SITE_ROOT/src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx"
TARGET_DIR="$REPO_ROOT/target/registryctl-tutorial-source"
BUILD_PROFILE="${REGISTRYCTL_TUTORIAL_CARGO_PROFILE:-ci}"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/registryctl-tutorial-source.XXXXXX")"
BLOCKS="$WORK_ROOT/blocks"
PROJECT_ROOT="$WORK_ROOT/reader"
REGISTRYCTL_BIN=""
SOURCE_IMAGE_LOCK=""

cleanup() {
	local exit_code=$?
	set +e
	if [[ -n "$SOURCE_IMAGE_LOCK" ]]; then
		rm -f "$SOURCE_IMAGE_LOCK"
	fi
	rm -rf "$WORK_ROOT"
	if ((exit_code == 0)); then
		printf 'registryctl tutorial source contract: PASS\n'
	else
		printf 'registryctl tutorial source contract: FAIL (exit %d)\n' "$exit_code" >&2
	fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for tool in cargo node rg; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		printf 'required tool not on PATH: %s\n' "$tool" >&2
		exit 1
	fi
done
if [[ ! -f "$SITE_ROOT/node_modules/yaml/package.json" ]]; then
	printf 'docs dependencies are not installed; run npm ci in %s\n' "$SITE_ROOT" >&2
	exit 1
fi
if [[ "$BUILD_PROFILE" != "ci" && "$BUILD_PROFILE" != "release" ]]; then
	printf 'unsupported tutorial Cargo profile: %s (expected ci or release)\n' "$BUILD_PROFILE" >&2
	exit 1
fi

node "$HELPER" assert-layout "$TUTORIAL" \
	'["Install Registryctl","Create the canonical project","Run the required preflight","Start the API","Run the maintained checks","Make one denied request","Make one allowed request","Make one allowed request","Inspect the human-owned boundary","Inspect the human-owned boundary","Change one disclosure rule","Stop and clean up"]'
node "$HELPER" extract-shell "$TUTORIAL" "$BLOCKS"

expected_install=$'tag=v0.14.0\ncurl -fsSLO "https://github.com/registrystack/registry-stack/releases/download/${tag}/registryctl-${tag}-install.sh"\nbash "./registryctl-${tag}-install.sh"\nregistryctl --version'
if [[ "$(cat "$BLOCKS/01.sh")" != "$expected_install" ]]; then
	printf 'release-form installer block changed without updating its source contract\n' >&2
	exit 1
fi

printf 'building current registryctl for the canonical source contract\n'
CARGO_TARGET_DIR="$TARGET_DIR" \
	cargo build --locked --profile "$BUILD_PROFILE" -p registryctl
REGISTRYCTL_BIN="$TARGET_DIR/$BUILD_PROFILE/registryctl"
[[ -x "$REGISTRYCTL_BIN" ]] || {
	printf 'registryctl source binary is not executable: %s\n' "$REGISTRYCTL_BIN" >&2
	exit 1
}

registryctl_version="$("$REGISTRYCTL_BIN" --version | awk '{print $2}')"
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

registryctl() {
	"$REGISTRYCTL_BIN" "$@"
}
export -f registryctl
export REGISTRYCTL_BIN REGISTRYCTL_NO_UPDATE_CHECK=1

mkdir -p "$PROJECT_ROOT"
cd "$PROJECT_ROOT"
source "$BLOCKS/02.sh"

test -f registry-stack.yaml
test -f entities/projects.yaml
test -f environments/local.yaml
test -f data/public_works_projects.xlsx
test ! -e relay
test ! -e compose.yaml

registryctl test --project-dir .
registryctl preflight --project-dir . --environment local
registryctl check --project-dir . --environment local --explain
registryctl build --project-dir . --environment local

test -f .registry-stack/build/local/artifact-manifest.json
test -f .registry-stack/build/local/private/relay/config/relay.yaml
test ! -e .registry-stack/runtime/local

if rg -n 'REGISTRYCTL_LOCAL_RELAY_.*_RAW=|api_key_raw|audit_hash_secret' \
	.registry-stack/build registry-stack.yaml entities environments data; then
	printf 'raw local runtime material leaked into the source-contract closure\n' >&2
	exit 1
fi

node "$HELPER" assert-contains \
	<(registryctl check --project-dir . --environment local --explain 2>&1) \
	'Relay-only' 'projects-records'
node "$HELPER" assert-contains \
	.registry-stack/build/local/private/relay/config/relay.yaml \
	'project_id' 'district_code' 'sector' 'status'

printf '%s\n' \
	'source-contract note: the exact runtime sequence is release-gated from the sealed candidate payload'
