#!/usr/bin/env bash
#
# Execute the current Evidence tutorials from a fresh reader directory.
#
# This gate builds the Evidence toolset from the checked-out source unless
# EVIDENCE_BIN and EVIDENCECTL_BIN select exact candidate or released bytes,
# then replays each registered tutorial's own shell fences in its own reader
# directory. Every tutorial creates the files it needs from its documented
# commands, so what CI runs is what a reader copies.
#
# Usage:
#   scripts/check-evidence-tutorials.sh                 replay every tutorial
#   scripts/check-evidence-tutorials.sh --dry-run       drift-check only
#   scripts/check-evidence-tutorials.sh --only <slug>   one tutorial
#
# Registering a tutorial means adding its slug to EVIDENCE_TUTORIALS and a
# branch to load_spec. Each spec pins:
#   SPEC_FENCES     how many sh fences the tutorial holds; bump it when you
#                   intentionally add or remove a documented command block
#   SPEC_STEPS      the reader journey, in order:
#                     run:N or run:N-M   execute those sh fences
#                     edit:H|lang|occ|H2|lang2|occ2|target
#                                        apply a documented before/after fence
#                                        pair to an existing file
#   SPEC_LITERALS   commands and outputs the tutorial must keep documenting
#   SPEC_OUTPUTS    lines the replay transcript must contain
#
# Configuration:
#   EVIDENCE_BIN / EVIDENCECTL_BIN        run these exact binaries instead of
#                                         building from source
#   EVIDENCE_TUTORIAL_CARGO_PROFILE       ci (default) or release
#   EVIDENCE_TUTORIAL_DOCS_ROOT           tutorial directory override (tests)

set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$SITE_ROOT/../.." && pwd)"
# A generic fence helper, not registryctl-specific: it locates a fence by
# heading, language and occurrence and applies it to a file.
HELPER="$SITE_ROOT/scripts/registryctl-tutorial.mjs"
DOCS_ROOT="${EVIDENCE_TUTORIAL_DOCS_ROOT:-$SITE_ROOT/src/content/docs/tutorials}"
BUILD_PROFILE="${EVIDENCE_TUTORIAL_CARGO_PROFILE:-ci}"
TARGET_DIR="$REPO_ROOT/target/evidence-tutorial-source"

# ---------------------------------------------------------------------------
# Registered tutorials
# ---------------------------------------------------------------------------

EVIDENCE_TUTORIALS=(
	first-evidence-assertion
	author-an-acceptance-definition
	connect-an-institution-source
)

load_spec() {
	SPEC_FENCES=0
	SPEC_STEPS=()
	SPEC_LITERALS=()
	SPEC_OUTPUTS=()

	case "$1" in
	first-evidence-assertion)
		SPEC_FENCES=8
		# Fences 1 and 2 download a published release; this gate substitutes the
		# binaries under test, so the on-machine journey starts at fence 3. The
		# released-binary form of that download arrives with plan item F3.
		SPEC_STEPS=('run:3-8')
		# shellcheck disable=SC2016  # the first entry is literal tutorial text
		SPEC_LITERALS=(
			'evidencectl-${tag}-install.sh'
			'evidencectl new hello-evidence'
			'evidencectl keygen signing --out-dir secrets --kid scaffold-signing-key-1'
			'chmod -R a-w bundle && chmod 444 runtime.yaml'
			'evidencectl fixtures run --project .'
			'2 passed, 0 failed (12 cases evaluated)'
		)
		SPEC_OUTPUTS=(
			'PASS: check'
			'PASS: fixtures/cases.yaml (12 cases)'
			'2 passed, 0 failed (12 cases evaluated)'
		)
		;;
	author-an-acceptance-definition)
		SPEC_FENCES=13
		# The reader already has the toolset from the first tutorial, so the
		# whole page is executable. Each edit applies a documented before/after
		# yaml pair under one heading: occurrence 1 is found, 2 replaces it.
		SPEC_STEPS=(
			'run:1-3'
			'edit:Add a narrower selector profile|yaml|1|Add a narrower selector profile|yaml|2|bundle/evidence.yaml'
			'edit:Add the register as a second source|yaml|1|Add the register as a second source|yaml|2|bundle/evidence.yaml'
			'run:4-9'
			'edit:Add the residence-region requirement|yaml|1|Add the residence-region requirement|yaml|2|bundle/evidence.yaml'
			'edit:Grant the new requirement|yaml|1|Grant the new requirement|yaml|2|bundle/evidence.yaml'
			'run:10-13'
		)
		SPEC_LITERALS=(
			'evidencectl new region-evidence'
			'mkdir -p bundle/codelists'
			'chmod -R a-w bundle && chmod 444 runtime.yaml'
			'evidencectl fixtures run --project .'
			'3 passed, 0 failed (23 cases evaluated)'
		)
		SPEC_OUTPUTS=(
			'PASS: check'
			'PASS: fixtures/cases.yaml (12 cases)'
			'PASS: fixtures/residence-region-cases.yaml (11 cases)'
			'3 passed, 0 failed (23 cases evaluated)'
		)
		;;
	connect-an-institution-source)
		SPEC_FENCES=11
		# The drafting tool writes three files into the project, so two of the
		# edits repair its output in place and one repoints the requirement.
		SPEC_STEPS=(
			'run:1-4'
			'edit:Narrow the drafted response schema|yaml|1|Narrow the drafted response schema|yaml|2|bundle/schemas/event-records-response.schema.yaml'
			'run:5-6'
			'edit:Replace the placeholder source|yaml|1|Replace the placeholder source|yaml|2|bundle/evidence.yaml'
			'edit:Repoint the requirement|yaml|1|Repoint the requirement|yaml|2|bundle/evidence.yaml'
			'run:7-11'
		)
		SPEC_LITERALS=(
			'evidencectl new connect-a-source'
			'evidencectl source suggest'
			'chmod -R a-w bundle && chmod 444 runtime.yaml'
			'evidencectl fixtures run --project .'
			'2 passed, 0 failed (12 cases evaluated)'
		)
		SPEC_OUTPUTS=(
			# The page quotes this drafting run verbatim, so pin one line of
			# it: a reworded report fails here instead of leaving the quoted
			# transcript silently stale.
			'Still needs your input (the source block below):'
			'PASS: check'
			'PASS: fixtures/cases.yaml (12 cases)'
			'2 passed, 0 failed (12 cases evaluated)'
		)
		;;
	*)
		printf '%s is not a registered Evidence tutorial\n' "$1" >&2
		exit 2
		;;
	esac
}

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

DRY_RUN=0
ONLY=""
while (($# > 0)); do
	case "$1" in
	--dry-run)
		DRY_RUN=1
		shift
		;;
	--only)
		if (($# < 2)); then
			printf -- '--only needs a tutorial slug\n' >&2
			exit 2
		fi
		ONLY="$2"
		shift 2
		;;
	*)
		printf 'unknown argument: %s (expected --dry-run or --only <slug>)\n' "$1" >&2
		exit 2
		;;
	esac
done

if [[ -n "$ONLY" ]]; then
	# load_spec exits on an unregistered slug, which is the check we want here.
	load_spec "$ONLY"
	EVIDENCE_TUTORIALS=("$ONLY")
fi

WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/evidence-tutorial.XXXXXX")"
cleanup() {
	local exit_code=$?
	set +e
	chmod -R u+w "$WORK_ROOT" 2>/dev/null
	rm -rf "$WORK_ROOT"
	if ((exit_code == 0)); then
		printf 'Evidence tutorial gate: PASS\n'
	else
		printf 'Evidence tutorial gate: FAIL (exit %d)\n' "$exit_code" >&2
	fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

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

SHIM_DIR="$WORK_ROOT/bin"

prepare_toolset() {
	if [[ -z "${EVIDENCE_BIN:-}" || -z "${EVIDENCECTL_BIN:-}" ]]; then
		local profile_dir
		profile_dir="$(resolve_profile_dir)"
		(cd "$REPO_ROOT" && CARGO_TARGET_DIR="$TARGET_DIR" \
			cargo build --locked --profile "$BUILD_PROFILE" \
			-p registry-evidence -p registry-evidencectl)
		EVIDENCE_BIN="$TARGET_DIR/$profile_dir/evidence"
		EVIDENCECTL_BIN="$TARGET_DIR/$profile_dir/evidencectl"
	fi
	local bin
	for bin in "$EVIDENCE_BIN" "$EVIDENCECTL_BIN"; do
		# Absoluteness first: the reader journey runs from its own directory and
		# reaches the binaries through symlinks, so a relative path resolves
		# against the wrong directory and would otherwise surface much later,
		# mid-journey, as "command not found".
		if [[ "$bin" != /* ]]; then
			printf 'toolset binary path must be absolute: %s\n' "$bin" >&2
			exit 1
		fi
		if [[ ! -x "$bin" ]]; then
			printf 'toolset binary not executable: %s\n' "$bin" >&2
			exit 1
		fi
	done

	# The tutorials call the binaries by name, so serve them from a shim dir.
	mkdir -p "$SHIM_DIR"
	ln -s "$EVIDENCE_BIN" "$SHIM_DIR/evidence"
	ln -s "$EVIDENCECTL_BIN" "$SHIM_DIR/evidencectl"
}

# ---------------------------------------------------------------------------
# Journey assembly
# ---------------------------------------------------------------------------

# Emit the sh fences named by a run: step, in order.
emit_run_step() {
	local slug="$1" range="$2" fence_dir="$3"
	local first="${range%%-*}"
	local last="${range##*-}"
	local i fence
	for ((i = first; i <= last; i++)); do
		fence="$(printf '%s/fence-%02d.sh' "$fence_dir" "$i")"
		if [[ ! -f "$fence" ]]; then
			printf 'tutorial spec error in %s: run step names sh fence %d, which does not exist\n' \
				"$slug" "$i" >&2
			exit 2
		fi
		printf '\nprintf "==> %s fence %02d\\n"\n' "$slug" "$i"
		cat "$fence"
	done
}

# Emit a documented before/after fence pair applied to a file the reader edits.
emit_edit_step() {
	local slug="$1" spec="$2"
	local IFS='|'
	# shellcheck disable=SC2206  # deliberate split on the field separator
	local parts=($spec)
	if ((${#parts[@]} != 7)); then
		printf 'tutorial spec error in %s: edit step needs 7 fields, got %d: %s\n' \
			"$slug" "${#parts[@]}" "$spec" >&2
		exit 2
	fi
	printf '\nprintf "==> %s edit %s\\n"\n' "$slug" "${parts[6]}"
	# shellcheck disable=SC2016  # HELPER and TUTORIAL expand in the emitted script
	printf 'node "$HELPER" replace-fence-pair "$TUTORIAL" %q %q %q %q %q %q %q\n' \
		"${parts[0]}" "${parts[1]}" "${parts[2]}" \
		"${parts[3]}" "${parts[4]}" "${parts[5]}" "${parts[6]}"
}

emit_journey() {
	local slug="$1" fence_dir="$2" tutorial_file="$3"
	printf 'set -euo pipefail\n'
	printf 'HELPER=%q\n' "$HELPER"
	printf 'TUTORIAL=%q\n' "$tutorial_file"
	local step
	for step in ${SPEC_STEPS[@]+"${SPEC_STEPS[@]}"}; do
		case "$step" in
		run:*) emit_run_step "$slug" "${step#run:}" "$fence_dir" ;;
		edit:*) emit_edit_step "$slug" "${step#edit:}" ;;
		*)
			printf 'tutorial spec error in %s: unknown step: %s\n' "$slug" "$step" >&2
			exit 2
			;;
		esac
	done
}

# How many sh fences a spec executes, for the summary line.
executed_fence_count() {
	local step range first last total=0
	for step in ${SPEC_STEPS[@]+"${SPEC_STEPS[@]}"}; do
		case "$step" in
		run:*)
			range="${step#run:}"
			first="${range%%-*}"
			last="${range##*-}"
			total=$((total + last - first + 1))
			;;
		esac
	done
	printf '%d' "$total"
}

# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

if ((DRY_RUN == 0)); then
	prepare_toolset
fi

for slug in "${EVIDENCE_TUTORIALS[@]}"; do
	load_spec "$slug"
	tutorial_file="$DOCS_ROOT/$slug.mdx"
	if [[ ! -f "$tutorial_file" ]]; then
		printf 'Evidence tutorial not found: %s\n' "$tutorial_file" >&2
		exit 1
	fi

	# Extract every sh fence, in order, into numbered files.
	fence_dir="$WORK_ROOT/fences/$slug"
	mkdir -p "$fence_dir"
	fence_count="$(awk -v outdir="$fence_dir" '
		/^```sh$/ { infence = 1; count += 1; next }
		infence && /^```$/ { infence = 0; next }
		infence { print > (outdir "/fence-" sprintf("%02d", count) ".sh") }
		END { print count + 0 }
	' "$tutorial_file")"

	if [[ "$fence_count" -ne "$SPEC_FENCES" ]]; then
		printf 'tutorial drift in %s: %s sh fences found, expected %s\n' \
			"$slug" "$fence_count" "$SPEC_FENCES" >&2
		printf 'Update SPEC_FENCES and SPEC_STEPS in %s when the change is intentional.\n' \
			"${BASH_SOURCE[0]}" >&2
		exit 1
	fi

	for literal in ${SPEC_LITERALS[@]+"${SPEC_LITERALS[@]}"}; do
		if ! grep -F -q -- "$literal" "$tutorial_file"; then
			printf 'tutorial drift in %s: required literal missing: %s\n' \
				"$slug" "$literal" >&2
			exit 1
		fi
	done

	printf '%s: %s sh fences, %s executed, %s required literals present\n' \
		"$slug" "$fence_count" "$(executed_fence_count)" "${#SPEC_LITERALS[@]}"

	if ((DRY_RUN)); then
		continue
	fi

	# Replay the journey in one shell so `cd` persists exactly as a reader
	# experiences it, from a reader directory of this tutorial's own.
	reader_dir="$WORK_ROOT/reader/$slug"
	mkdir -p "$reader_dir"
	run_script="$WORK_ROOT/run-$slug.sh"
	emit_journey "$slug" "$fence_dir" "$tutorial_file" >"$run_script"

	run_log="$WORK_ROOT/run-$slug.log"
	if ! (cd "$reader_dir" && PATH="$SHIM_DIR:$PATH" bash "$run_script") 2>&1 |
		tee "$run_log"; then
		printf 'tutorial %s failed; the transcript ends just before this line\n' \
			"$slug" >&2
		exit 1
	fi

	for expected in ${SPEC_OUTPUTS[@]+"${SPEC_OUTPUTS[@]}"}; do
		if ! grep -F -q -- "$expected" "$run_log"; then
			printf 'tutorial output drift in %s: expected "%s" in the transcript\n' \
				"$slug" "$expected" >&2
			exit 1
		fi
	done
done

if ((${#EVIDENCE_TUTORIALS[@]} == 1)); then
	printf 'Checked 1 tutorial.\n'
else
	printf 'Checked %d tutorials.\n' "${#EVIDENCE_TUTORIALS[@]}"
fi
