#!/usr/bin/env bash
#
# Replay the Relay V2 tutorial's own contract and command fences, end to end.
#
# What this gate is for: proving the reader journey the page documents still
# works. `relayctl init`, a schema fingerprint that is reproducible across
# runs, a contract assembled from the page's own YAML blocks that `check`
# accepts, a production gate that refuses the starter project's unreviewed
# governance by the exact documented codes and passes once that governance is
# on file, a sealed package, and a running `relay` that answers a record,
# narrows it on request, refuses to widen it, refuses an unknown record, and
# records an audit line that names the properties it released without
# recording their values.
#
# What this gate is NOT for: policing what the page says. It pins no fence
# count and no prose. It reads the page's own fences by heading, language and
# occurrence, the same way the Evidence tutorial gate does
# (scripts/evidence-tutorial-fence.sh), so a section is free to grow or reword
# without touching this file. The one thing a section owes this gate is its
# heading: renaming one breaks the address this gate names, by name, before
# any command runs. The tutorial hand-authors one contract across eleven YAML
# blocks rather than pointing at a single product runner, so this gate follows
# that shape instead of the Discovery tutorial gate's thin wrapper.
#
# Usage:
#   scripts/check-relay-tutorial.sh              replay the tutorial
#   scripts/check-relay-tutorial.sh --dry-run     resolve the fences only
#
# Configuration:
#   RELAY_BIN / RELAYCTL_BIN          run these exact binaries instead of
#                                      building from source
#   RELAY_TUTORIAL_CARGO_PROFILE      ci (default) or release
#   RELAY_TUTORIAL_PAGE               tutorial page override (tests)
#   RELAY_TUTORIAL_BIND               override the "127.0.0.1:8080" the page
#                                      documents, for a host where that port is
#                                      already bound
#   CARGO_TARGET_DIR                  defaults to the workspace target
#                                      directory; set it to build in isolation
#                                      from other cargo processes sharing the
#                                      same worktree

set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$SITE_ROOT/../.." && pwd)"
FENCE="$SITE_ROOT/scripts/evidence-tutorial-fence.sh"
TUTORIAL="${RELAY_TUTORIAL_PAGE:-$SITE_ROOT/src/content/docs/tutorials/publish-governed-sqlite-registry.mdx}"
BUILD_PROFILE="${RELAY_TUTORIAL_CARGO_PROFILE:-ci}"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
BIND="${RELAY_TUTORIAL_BIND:-127.0.0.1:8080}"

DRY_RUN=0
case "${1:-}" in
"") ;;
--dry-run) DRY_RUN=1 ;;
*)
	printf 'unknown argument: %s (expected --dry-run)\n' "$1" >&2
	exit 2
	;;
esac

for path in "$TUTORIAL" "$FENCE"; do
	if [[ ! -f "$path" ]]; then
		printf 'required Relay tutorial input not found: %s\n' "$path" >&2
		exit 1
	fi
done

WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/relay-tutorial.XXXXXX")"
FENCES="$WORK_ROOT/fences"
mkdir -p "$FENCES"

cleanup() {
	local exit_code=$?
	set +e
	if [[ -n "${RELAY_PID:-}" ]]; then
		# serve.sh backgrounds a shell that in turn execs relay as its last
		# command; signalling only the shell's PID can leave relay itself
		# running, so this signals the whole background process group.
		kill -TERM -"$RELAY_PID" >/dev/null 2>&1 || true
		wait "$RELAY_PID" >/dev/null 2>&1 || true
	fi
	chmod -R u+w "$WORK_ROOT" 2>/dev/null
	rm -rf "$WORK_ROOT"
	if ((exit_code == 0)); then
		printf 'Relay tutorial gate: PASS\n'
	else
		printf 'Relay tutorial gate: FAIL (exit %d)\n' "$exit_code" >&2
	fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

# Read a fence by heading, language and occurrence into $FENCES/<name>. A
# heading a step names that the page no longer carries fails here, by name,
# whether or not this is a dry run.
wf() {
	bash "$FENCE" write-fence "$TUTORIAL" "$1" "$2" "$3" "$FENCES/$4"
}

# ---------------------------------------------------------------------------
# Resolve every fence this gate replays, in document order. This runs in
# --dry-run too, because it needs no toolchain: it is what turns a renamed
# heading into a named failure instead of a silent skip.
# ---------------------------------------------------------------------------

wf "Start a project" sh 1 init.sh
wf "Build the register database" sql 1 registry.sql
wf "Build the register database" sh 1 build-db.sh
wf "Record the schema you reviewed" sh 1 inspect.sh
wf "Record the schema you reviewed" text 1 inspect-expected.txt
for i in 1 2 3 4 5 6 7 8 9 10 11; do
	wf "Write the contract" yaml "$i" "contract-$i.yaml"
done
wf "Check the contract" sh 1 check.sh
wf "Generate the artifacts" sh 1 generate.sh
wf "See what production refuses" sh 1 check-production-refused.sh
wf "Record the review" yaml 1 classification-review.yaml
wf "Record the review" markdown 1 classification-review-rationale.md
wf "Record the review" yaml 2 legal-basis.yaml
wf "Record the review" yaml 3 record-lifecycle.yaml
wf "Record the review" sh 1 check-production-passed.sh
wf "Seal the package" sh 1 package.sh
wf "Seal the package" text 1 package-expected.txt
wf "Serve it" yaml 1 runtime-expected.yaml
wf "Serve it" sh 1 serve.sh
wf "Ask the register a question" sh 1 ready.sh
wf "Ask the register a question" sh 2 read-record.sh
wf "Ask for less, then try to ask for more" sh 1 narrow.sh
wf "Ask for less, then try to ask for more" sh 2 widen.sh
wf "Ask for less, then try to ask for more" sh 3 unknown-record.sh
wf "Read the audit entry" sh 1 audit.sh
# Named to prove the heading still exists; the reader's own cleanup of their
# directory is out of scope, since this gate manages its own work directory.
wf "Clean up" sh 1 cleanup-reader.sh

fence_count="$(find "$FENCES" -type f | wc -l | tr -d ' ')"
printf 'Relay tutorial: resolved %d fences\n' "$fence_count"

if ((DRY_RUN)); then
	printf 'Relay tutorial reader gate: dry run only\n'
	exit 0
fi

# ---------------------------------------------------------------------------
# Toolset under test
# ---------------------------------------------------------------------------

resolve_profile_dir() {
	case "$BUILD_PROFILE" in
	ci | release) printf '%s' "$BUILD_PROFILE" ;;
	*)
		printf 'unsupported tutorial Cargo profile: %s (expected ci or release)\n' \
			"$BUILD_PROFILE" >&2
		exit 1
		;;
	esac
}

if [[ -z "${RELAY_BIN:-}" || -z "${RELAYCTL_BIN:-}" ]]; then
	profile_dir="$(resolve_profile_dir)"
	(cd "$REPO_ROOT" && CARGO_TARGET_DIR="$TARGET_DIR" \
		CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
		cargo build --locked --profile "$BUILD_PROFILE" \
		-p registry-relay-v2 --features tooling -p registry-relayctl)
	RELAY_BIN="$TARGET_DIR/$profile_dir/relay"
	RELAYCTL_BIN="$TARGET_DIR/$profile_dir/relayctl"
fi
for bin in "$RELAY_BIN" "$RELAYCTL_BIN"; do
	if [[ "$bin" != /* ]]; then
		printf 'toolset binary path must be absolute: %s\n' "$bin" >&2
		exit 1
	fi
	if [[ ! -x "$bin" ]]; then
		printf 'toolset binary not executable: %s\n' "$bin" >&2
		exit 1
	fi
done

# The tutorial calls the binaries by name.
SHIM_DIR="$WORK_ROOT/bin"
mkdir -p "$SHIM_DIR"
ln -s "$RELAY_BIN" "$SHIM_DIR/relay"
ln -s "$RELAYCTL_BIN" "$SHIM_DIR/relayctl"
export PATH="$SHIM_DIR:$PATH"

# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

READER_DIR="$WORK_ROOT/reader"
mkdir -p "$READER_DIR"
cd "$READER_DIR"

printf '==> relayctl init\n'
# shellcheck disable=SC1091  # generated by write-fence at run time
source "$FENCES/init.sh"

printf '==> build the register database\n'
cat "$FENCES/registry.sql" >registry.sql
bash "$FENCES/build-db.sh"

printf '==> relayctl inspect\n'
inspect_output="$(bash "$FENCES/inspect.sh")"
printf '%s\n' "$inspect_output"
fingerprint="$(awk '/fingerprint/ { print $2 }' <<<"$inspect_output")"
if [[ -z "$fingerprint" ]]; then
	printf 'tutorial drift: relayctl inspect printed no fingerprint\n' >&2
	exit 1
fi
# The page claims this fingerprint is reproducible on any machine and every
# run, because it covers only the stored schema statements. That claim is a
# behaviour a successful `inspect` exit does not already prove: a changed
# fingerprint algorithm would still exit zero while printing a different
# value, silently.
expected_fingerprint="$(awk '/fingerprint/ { print $2 }' "$FENCES/inspect-expected.txt")"
if [[ "$fingerprint" != "$expected_fingerprint" ]]; then
	printf 'tutorial behaviour drift: relayctl inspect printed %s, the page documents %s\n' \
		"$fingerprint" "$expected_fingerprint" >&2
	exit 1
fi

printf '==> assemble registry.yaml from the documented contract blocks\n'
: >registry.yaml
for i in 1 2 3 4 5 6 7 8 9 10 11; do
	cat "$FENCES/contract-$i.yaml" >>registry.yaml
	printf '\n' >>registry.yaml
done
contract="$(cat registry.yaml)"
contract="${contract//sha256:<your-schema-fingerprint>/$fingerprint}"
printf '%s' "$contract" >registry.yaml

printf '==> relayctl check\n'
check_output="$(bash "$FENCES/check.sh")"
printf '%s\n' "$check_output"
if [[ "$check_output" != *"Authoring check passed."* ]]; then
	printf 'tutorial behaviour drift: relayctl check did not pass the assembled contract\n' >&2
	exit 1
fi

printf '==> relayctl generate\n'
bash "$FENCES/generate.sh"
starter="generated/governance/classification-review-starter.yaml"
if [[ ! -f "$starter" ]]; then
	printf 'tutorial behaviour drift: relayctl generate did not write %s\n' "$starter" >&2
	exit 1
fi
digest="$(awk -F': ' '/classificationInventoryDigest/ { print $2 }' "$starter")"
if [[ -z "$digest" ]]; then
	printf 'tutorial behaviour drift: %s carries no classificationInventoryDigest\n' "$starter" >&2
	exit 1
fi

printf '==> relayctl check --production (starter project, expected refusal)\n'
set +e
production_refused_output="$(bash "$FENCES/check-production-refused.sh" 2>&1)"
refusal_status=$?
set -e
printf '%s\n' "$production_refused_output"
if ((refusal_status == 0)); then
	printf 'tutorial behaviour drift: production check accepted the unreviewed starter project\n' >&2
	exit 1
fi
for code in \
	codelist.unreviewed \
	classification.review_inventory_stale \
	classification.review_registry_stale \
	classification.review_date_invalid \
	classification.review_unreviewed; do
	if [[ "$production_refused_output" != *"$code"* ]]; then
		printf 'tutorial behaviour drift: production refusal is missing %s\n' "$code" >&2
		exit 1
	fi
done

printf '==> record the review\n'
review="$(cat "$FENCES/classification-review.yaml")"
review="${review//sha256:<inventory-digest>/$digest}"
printf '%s' "$review" >governance/classification-review.yaml
cat "$FENCES/classification-review-rationale.md" >governance/classification-review-rationale.md
cat "$FENCES/legal-basis.yaml" >governance/legal-basis.yaml
cat "$FENCES/record-lifecycle.yaml" >codelists/record-lifecycle.yaml

printf '==> relayctl check --production (reviewed project, expected pass)\n'
production_passed_output="$(bash "$FENCES/check-production-passed.sh")"
printf '%s\n' "$production_passed_output"
if [[ "$production_passed_output" != *"Production check passed."* ]]; then
	printf 'tutorial behaviour drift: production check did not pass the reviewed project\n' >&2
	exit 1
fi

printf '==> relayctl package\n'
package_output="$(bash "$FENCES/package.sh")"
printf '%s\n' "$package_output"
if [[ "$package_output" != *"Sealed a deployment package."* ]]; then
	printf 'tutorial behaviour drift: relayctl package did not seal a package\n' >&2
	exit 1
fi
expected_source_fingerprint="$(awk '/registry  sha256:/ { print $2 }' "$FENCES/package-expected.txt")"
if [[ "$package_output" != *"$expected_source_fingerprint"* ]]; then
	printf 'tutorial behaviour drift: the sealed package does not record the documented source fingerprint %s\n' \
		"$expected_source_fingerprint" >&2
	exit 1
fi

printf '==> serve it\n'
runtime_yaml="$(cat runtime.yaml)"
expected_runtime_yaml="$(cat "$FENCES/runtime-expected.yaml")"
if [[ "$BIND" != "127.0.0.1:8080" ]]; then
	expected_runtime_yaml="${expected_runtime_yaml//127.0.0.1:8080/$BIND}"
	runtime_yaml="${runtime_yaml//127.0.0.1:8080/$BIND}"
	printf '%s' "$runtime_yaml" >runtime.yaml
	# The curl fences below name the same bind address literally, the way the
	# reader's own terminal would.
	for client_fence in ready.sh read-record.sh narrow.sh widen.sh unknown-record.sh; do
		client_content="$(cat "$FENCES/$client_fence")"
		client_content="${client_content//127.0.0.1:8080/$BIND}"
		printf '%s' "$client_content" >"$FENCES/$client_fence"
	done
fi
# `relayctl init` writes runtime.yaml before the reader ever reads it, and the
# page says it needs no edit. If the starter template drifts from what the
# page shows the reader, this catches it.
if [[ "$runtime_yaml" != "$expected_runtime_yaml" ]]; then
	printf 'tutorial behaviour drift: runtime.yaml does not match the documented file\n' >&2
	exit 1
fi

# Job control is off in a non-interactive script, so a background job stays
# in the script's own process group unless monitor mode is enabled here.
# Without it, the negative-PID kill below targets a process group that was
# never created and fails outright instead of reaching relay.
set -m
bash "$FENCES/serve.sh" >"$WORK_ROOT/relay.log" 2>&1 &
RELAY_PID=$!
set +m

ready=0
for _ in $(seq 1 50); do
	if ready_output="$(bash "$FENCES/ready.sh" 2>/dev/null)" && [[ "$ready_output" == '{"status":"ready"}' ]]; then
		ready=1
		break
	fi
	sleep 0.1
done
if ((!ready)); then
	printf 'relay did not become ready; log follows\n' >&2
	cat "$WORK_ROOT/relay.log" >&2
	exit 1
fi

printf '==> ask the register a question\n'
record_output="$(bash "$FENCES/read-record.sh")"
printf '%s\n' "$record_output"
for expected in '"legalName":"Aurora Freight Cooperative"' '"legalForm":"COOPERATIVE"'; do
	if [[ "$record_output" != *"$expected"* ]]; then
		printf 'tutorial behaviour drift: the record answer is missing %s\n' "$expected" >&2
		exit 1
	fi
done
if [[ "$record_output" == *"registeredAddress"* ]]; then
	printf 'tutorial behaviour drift: the disclosure boundary leaked registeredAddress\n' >&2
	exit 1
fi

printf '==> ask for less, then try to ask for more\n'
narrow_output="$(bash "$FENCES/narrow.sh")"
if [[ "$narrow_output" != *'"legalName"'* ]] || [[ "$narrow_output" == *'"legalForm"'* ]]; then
	printf 'tutorial behaviour drift: narrowing to legalName did not select it alone: %s\n' \
		"$narrow_output" >&2
	exit 1
fi

widen_output="$(bash "$FENCES/widen.sh")"
if [[ "$widen_output" != *'"code":"request.fields_invalid"'* ]] || [[ "$widen_output" != *'"status":400'* ]]; then
	printf 'tutorial behaviour drift: widening to registeredAddress was not refused as documented: %s\n' \
		"$widen_output" >&2
	exit 1
fi

unknown_output="$(bash "$FENCES/unknown-record.sh")"
if [[ "$unknown_output" != *'"code":"consultation.unresolved"'* ]] || [[ "$unknown_output" != *'"status":404'* ]]; then
	printf 'tutorial behaviour drift: the unknown record was not refused as documented: %s\n' \
		"$unknown_output" >&2
	exit 1
fi

printf '==> read the audit entry\n'
kill -TERM -"$RELAY_PID"
wait "$RELAY_PID" 2>/dev/null || true
unset RELAY_PID
audit_line="$(bash "$FENCES/audit.sh")"
printf '%s\n' "$audit_line"
for expected in \
	'"prev_hash":null' \
	'"phase":"attempt"' \
	'"selectedProperties":["legalName","legalForm"]'; do
	if [[ "$audit_line" != *"$expected"* ]]; then
		printf 'tutorial behaviour drift: the audit line is missing %s\n' "$expected" >&2
		exit 1
	fi
done
# The whole point of the audit chain in this tutorial: it records what was
# released, never the values themselves.
if [[ "$audit_line" == *"Aurora Freight Cooperative"* ]]; then
	printf 'tutorial behaviour drift: the audit line recorded a released field value\n' >&2
	exit 1
fi

printf 'Checked 1 tutorial.\n'
