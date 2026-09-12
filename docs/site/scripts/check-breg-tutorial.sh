#!/usr/bin/env bash
#
# Execute the current Base Registry Engine tutorials from a fresh reader
# directory.
#
# What this gate is for: proving that the commands the BReg tutorials document
# still run, and that a short list of behaviours a successful exit does not
# already prove still holds. A read that still answers, a refusal that still
# refuses, a concurrent write that is still rejected.
#
# What this gate is NOT for: policing what a page says. It pins no fence count,
# no command string and no documented output. Prose, the text around a heading,
# output blocks and command wording are free to change without touching this
# file, and a writer may add or remove a command block under a heading the
# journey already runs with no change here at all. If you find yourself adding
# an array of strings a page must contain, stop: that is the pinning this file
# deliberately does not do.
#
# This gate builds the BReg toolset from the checked-out source unless BREG_BIN,
# BREGCTL_BIN and MINT_BIN select exact candidate or released bytes, then replays
# the registered tutorial's own shell fences from an empty reader directory, the
# way a reader starts after installing the binaries. What CI runs is what a
# reader copies.
#
# Usage:
#   scripts/check-breg-tutorial.sh              replay every registered tutorial
#   scripts/check-breg-tutorial.sh --dry-run    resolve the journeys only
#
# The full run needs Docker, because `bregctl dev`, which the tutorial starts,
# runs PostgreSQL in a container. The dry run needs neither Docker nor a
# compiler, which is what lets it run in the docs checks.
#
# Registering a tutorial means adding its slug to BREG_TUTORIALS and a branch to
# load_spec. Each spec holds two things:
#
#   SPEC_STEPS    the reader journey, in order. Fences are addressed by the
#                 heading they sit under, never by position, so inserting a
#                 command block cannot silently move a step onto the wrong
#                 command.
#                   run:<Heading>              execute every sh fence under
#                                              that heading, in document order
#                   run:<Heading>|<n>          execute the nth sh fence under
#                                              that heading
#                 The |<n> suffix is optional wherever a heading holds a single
#                 sh fence. Skipping is implicit: a fence under no listed
#                 heading is simply not run, and the summary names it so a
#                 reviewer can see the unverified surface.
#
#   SPEC_ASSERTS  behaviours the replay transcript must still show. One test
#                 decides membership: would this regress silently, without any
#                 command exiting non-zero? The documented refusals on these
#                 pages are read with curl --write-out rather than
#                 --fail-with-body, so they exit zero whatever the registry
#                 answers, which is exactly the kind of regression only an
#                 assertion catches. Startup reports and "created" lines fail
#                 that test, because the next command would have failed without
#                 them. Do not grow this back into a transcript pin.
#
# Renaming a heading breaks the steps that name it, by name, in --dry-run. That
# is the trade, and it is a good one: a renamed heading is a structural edit to
# the journey, it fails loudly rather than replaying the wrong command, and it
# is exactly when the journey is worth walking again.
#
# Configuration:
#   BREG_BIN / BREGCTL_BIN / MINT_BIN   run these exact binaries instead of
#                                       building from source
#   BREG_TUTORIAL_CARGO_PROFILE         ci (default) or release
#   BREG_TUTORIAL_DOCS_ROOT             docs content directory override (tests)

set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$SITE_ROOT/../.." && pwd)"
DOCS_ROOT="${BREG_TUTORIAL_DOCS_ROOT:-$SITE_ROOT/src/content/docs}"
BUILD_PROFILE="${BREG_TUTORIAL_CARGO_PROFILE:-ci}"
TARGET_DIR="$REPO_ROOT/target/breg-tutorial-source"

# ---------------------------------------------------------------------------
# Registered tutorials
# ---------------------------------------------------------------------------

# The docs directories this gate is responsible for. BReg and Evidence pages
# share these directories, so membership is decided by what a page runs, not by
# where it sits: see page_runs_breg_commands.
BREG_DOC_SECTIONS=(
	start
	tutorials
)

BREG_TUTORIALS=(
	tutorials/first-breg
)

# Every other page that runs Base Registry Engine commands, and the reason it is
# not replayed here. check_tutorial_coverage below fails by name on a page in
# neither list, so a new BReg tutorial cannot ship unreplayed and unexplained.
EXCLUDED_BREG_TUTORIALS=(
	tutorials/evidence-from-breg                  # native composition uses its own Docker registry; maintained offline verifier plus independent archive-only live reader execution
	tutorials/build-a-breg-production-candidate   # needs a reader-supplied signing key and a production database; product CI builds the candidate
	tutorials/extend-a-registry-with-a-module     # authoring journey with editor steps on the project first-breg generates; replayable, not yet specified as a journey here
	tutorials/derive-a-registry-from-publicschema # derives a project from the embedded PublicSchema snapshot and edits a selection file; replayable, not yet specified as a journey here
	tutorials/query-a-spatial-registry-from-qgis  # needs QGIS on a desktop; product CI runs the spatial quickstart smoke
	tutorials/query-breg-client                   # BReg client journey; depends on the released unified packages, like query-relay-client
	tutorials/review-breg-changes-in-casework     # two-product journey replayed by the Registry Casework tutorial gate, which builds the BReg toolset beside the Casework one
	tutorials/review-registry-changes             # needs psql against the quickstart database and an editor step on change-control configuration; replayable, not yet specified as a journey here
	tutorials/send-registry-events-to-a-webhook   # needs the business demo launcher and its webhook receiver, not the generic quickstart this gate starts
)

in_list() {
	local needle="$1"
	shift
	local item
	for item in "$@"; do
		[[ "$item" == "$needle" ]] && return 0
	done
	return 1
}

# Decide whether a page belongs to this gate: does any of its sh fences invoke
# Base Registry Engine?
#
# The alternative, a hand-kept list of BReg pages, is the gap this check exists
# to close: a page nobody remembered to list would be replayed by nothing and
# explained by nothing. Deriving membership from the commands means a new BReg
# tutorial fails coverage on the commit that adds it.
page_runs_breg_commands() {
	awk '
		in_fence == 0 && /^```sh$/ { in_fence = 1; next }
		in_fence && /^```$/ { in_fence = 0; next }
		in_fence && /(^|[^[:alnum:]_-])(bregctl|breg)([^[:alnum:]_-]|$)/ { found = 1; exit }
		END { exit found ? 0 : 1 }
	' "$1"
}

# Assert that every page running Base Registry Engine commands is either
# registered for replay or named in EXCLUDED_BREG_TUTORIALS with a reason.
check_tutorial_coverage() {
	local file section slug
	local -a unregistered=()
	for slug in "${EXCLUDED_BREG_TUTORIALS[@]}"; do
		if in_list "$slug" "${BREG_TUTORIALS[@]}"; then
			printf 'coverage error in %s: %s is both registered in BREG_TUTORIALS and excluded in EXCLUDED_BREG_TUTORIALS\n' \
				"${BASH_SOURCE[0]}" "$slug" >&2
			exit 2
		fi
		if [[ ! -f "$DOCS_ROOT/$slug.mdx" ]]; then
			printf 'coverage error in %s: %s.mdx in EXCLUDED_BREG_TUTORIALS does not exist under %s\n' \
				"${BASH_SOURCE[0]}" "$slug" "$DOCS_ROOT" >&2
			exit 2
		fi
		if ! page_runs_breg_commands "$DOCS_ROOT/$slug.mdx"; then
			printf 'coverage error in %s: %s.mdx no longer runs Base Registry Engine commands, so its entry in EXCLUDED_BREG_TUTORIALS says nothing; remove it\n' \
				"${BASH_SOURCE[0]}" "$slug" >&2
			exit 2
		fi
	done
	for section in "${BREG_DOC_SECTIONS[@]}"; do
		for file in "$DOCS_ROOT/$section"/*.mdx; do
			[[ -e "$file" ]] || continue
			slug="$section/$(basename "$file" .mdx)"
			page_runs_breg_commands "$file" || continue
			if ! in_list "$slug" "${BREG_TUTORIALS[@]}" && ! in_list "$slug" "${EXCLUDED_BREG_TUTORIALS[@]}"; then
				unregistered+=("$slug")
			fi
		done
	done
	if ((${#unregistered[@]} > 0)); then
		printf 'tutorial coverage gap: the following pages run Base Registry Engine commands and are neither registered in BREG_TUTORIALS nor excluded in EXCLUDED_BREG_TUTORIALS:\n' >&2
		for slug in "${unregistered[@]}"; do
			printf '  %s.mdx\n' "$slug" >&2
		done
		printf 'add each to BREG_TUTORIALS (with a load_spec branch) or to EXCLUDED_BREG_TUTORIALS with a reason, in %s\n' \
			"${BASH_SOURCE[0]}" >&2
		exit 1
	fi
}

check_tutorial_coverage

load_spec() {
	SPEC_STEPS=()
	SPEC_ASSERTS=()

	case "$1" in
	tutorials/first-breg)
		# The page opens with an install one-liner, which this gate replaces
		# with the toolset under test. Everything after it runs in the
		# foreground: `bregctl dev` returns once the registry is ready and
		# leaves its services running, and the page stops them at the end.
		SPEC_STEPS=(
			"run:Create a project"
			"run:Start the registry"
			"run:Get a token"
			"run:Read the registry"
			"run:Create a record"
			"run:Choose which fields to read"
			"run:Update the record"
			"run:Try an invalid record"
			"run:Stop the registry"
		)
		# Every documented refusal on this page is read with curl --write-out
		# and no --fail-with-body, so the fence exits zero whether the registry
		# refuses or answers. A boundary that stopped refusing, an ETag that
		# stopped being enforced or a first read that stopped answering with
		# the envelope would leave the whole journey green. These are the
		# assertions that catch it.
		SPEC_ASSERTS=(
			'"items": []'
			"HTTP 404"
			"HTTP 400"
			'"revisionIdentifier": "2"'
			'"label": "North Quay Engineering Ltd"'
			"HTTP 412"
		)
		;;
	*)
		printf '%s is not a registered Base Registry Engine tutorial in %s\n' \
			"$1" "${BASH_SOURCE[0]}" >&2
		exit 2
		;;
	esac
}

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

DRY_RUN=0
while (($# > 0)); do
	case "$1" in
	--dry-run)
		DRY_RUN=1
		shift
		;;
	*)
		printf 'unknown argument: %s (expected --dry-run)\n' "$1" >&2
		exit 2
		;;
	esac
done

# The registry refuses to initialize a project under a path that traverses a
# symbolic link, and the system temporary directory is one wherever /tmp or
# TMPDIR is itself a link. Resolving the work root once puts the whole reader
# journey on the physical path the registry accepts.
WORK_ROOT="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/breg-tutorial.XXXXXX")" && pwd -P)"
READER_DIR="$WORK_ROOT/reader"
SHIM_DIR="$WORK_ROOT/bin"

# Stop every local development session the replay started, and reclaim its
# container and volume. A journey that fails halfway leaves `bregctl dev`
# running with a database container behind it, and deleting the work root
# alone would orphan that container. Stopping with --remove is idempotent, so
# a journey that already stopped its own session costs nothing here. Returns
# non-zero when a session was left behind, which is what keeps its project
# under the work root for a second attempt.
stop_dev_sessions() {
	local state project status=0
	[[ -d "$READER_DIR" && -x "$SHIM_DIR/bregctl" ]] || return 0
	while IFS= read -r state; do
		project="$(dirname "$(dirname "$(dirname "$state")")")"
		if ! "$SHIM_DIR/bregctl" dev stop "$project" --remove >/dev/null 2>&1; then
			printf 'could not stop the local development session in %s\n' "$project" >&2
			status=1
		fi
	done < <(find "$READER_DIR" -path '*/.breg/dev/state.json' 2>/dev/null)
	return "$status"
}

cleanup() {
	local exit_code=$?
	set +e
	if stop_dev_sessions; then
		chmod -R u+w "$WORK_ROOT" 2>/dev/null
		rm -rf "$WORK_ROOT"
	else
		# `bregctl dev stop --remove` reads the project's own state document, so
		# removing the work root now would strand the container and its volume
		# with nothing left to reclaim them from.
		printf 'keeping %s: rerun the stop above against each project it holds\n' \
			"$WORK_ROOT" >&2
	fi
	if ((exit_code == 0)); then
		printf 'Base Registry Engine tutorial gate: PASS\n'
	else
		printf 'Base Registry Engine tutorial gate: FAIL (exit %d)\n' "$exit_code" >&2
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

prepare_toolset() {
	if [[ -z "${BREG_BIN:-}" || -z "${BREGCTL_BIN:-}" || -z "${MINT_BIN:-}" ]]; then
		local profile_dir
		profile_dir="$(resolve_profile_dir)"
		# The registry binary sits behind the runtime feature, exactly as the
		# release build enables it.
		(cd "$REPO_ROOT" && CARGO_TARGET_DIR="$TARGET_DIR" \
			cargo build --locked --profile "$BUILD_PROFILE" \
			-p registry-breg --features registry-breg/runtime \
			-p registry-bregctl -p registry-mint --bins)
		BREG_BIN="$TARGET_DIR/$profile_dir/breg"
		BREGCTL_BIN="$TARGET_DIR/$profile_dir/bregctl"
		MINT_BIN="$TARGET_DIR/$profile_dir/mint"
	fi
	local bin
	for bin in "$BREG_BIN" "$BREGCTL_BIN" "$MINT_BIN"; do
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

	# The tutorial calls the binaries by name, and `bregctl dev` resolves
	# `breg` and `mint` from PATH, so serve them from a shim dir.
	mkdir -p "$SHIM_DIR"
	ln -s "$BREG_BIN" "$SHIM_DIR/breg"
	ln -s "$BREGCTL_BIN" "$SHIM_DIR/bregctl"
	ln -s "$MINT_BIN" "$SHIM_DIR/mint"
}

# ---------------------------------------------------------------------------
# Journey assembly
# ---------------------------------------------------------------------------

# Resolve a heading address to the sh fence numbers it names, in document order,
# space separated.
#
# An address is a heading, optionally followed by |<occurrence> to name one
# fence under it. Addressing by heading rather than by position is what lets a
# writer add or remove a command block without touching a spec, and it is what
# stops an inserted block from silently moving a later step onto the wrong
# command.
resolve_fences() {
	local slug="$1" address="$2" fence_dir="$3"
	local heading="$address" occurrence=""
	if [[ "$address" == *'|'* ]]; then
		heading="${address%%|*}"
		occurrence="${address##*|}"
		if [[ ! "$occurrence" =~ ^[1-9][0-9]*$ ]]; then
			printf 'tutorial spec error in %s: fence occurrence must be a positive integer: %s\n' \
				"$slug" "$address" >&2
			exit 2
		fi
	fi
	local matched
	matched="$(awk -F '\t' -v want="$heading" -v want_occurrence="$occurrence" '
		$3 != want { next }
		want_occurrence != "" && $2 != want_occurrence + 0 { next }
		{ printf "%s ", $1 }
	' "$fence_dir/index.tsv")"
	matched="${matched% }"
	if [[ -z "$matched" ]]; then
		printf 'tutorial drift in %s: no sh fence answers to "%s"\n' "$slug" "$address" >&2
		printf 'A step names a heading the page no longer carries, or an occurrence under it that no longer exists.\n' >&2
		printf 'Renaming a heading is a structural edit to the journey; walk it again, then name the new heading in %s.\n' \
			"${BASH_SOURCE[0]}" >&2
		printf 'The page currently holds these sh fences:\n' >&2
		awk -F '\t' '{ printf "  fence %s, occurrence %s under \"%s\"\n", $1, $2, $3 }' \
			"$fence_dir/index.tsv" >&2
		exit 1
	fi
	printf '%s\n' "$matched"
}

# Emit the sh fences named by a run: step, in document order.
emit_run_step() {
	local slug="$1" address="$2" fence_dir="$3"
	local matched
	matched="$(resolve_fences "$slug" "$address" "$fence_dir")" || exit $?
	local -a numbers
	read -r -a numbers <<<"$matched"
	local number
	for number in "${numbers[@]}"; do
		printf '\nprintf "==> %s fence %s\\n"\n' "$slug" "$number"
		cat "$fence_dir/fence-$number.sh"
	done
}

emit_journey() {
	local slug="$1" fence_dir="$2"
	printf 'set -euo pipefail\n'
	printf 'trap "exit 130" HUP INT TERM\n'
	local step
	for step in ${SPEC_STEPS[@]+"${SPEC_STEPS[@]}"}; do
		case "$step" in
		run:*) emit_run_step "$slug" "${step#run:}" "$fence_dir" ;;
		*)
			printf 'tutorial spec error in %s: unknown step: %s\n' "$slug" "$step" >&2
			exit 2
			;;
		esac
	done
}

# Resolve every fence-addressing step into EXECUTED_FENCES, in step order.
#
# This runs before the replay and in --dry-run, so a heading a spec names but
# the page no longer carries fails by name in seconds, without a toolchain.
resolve_journey_fences() {
	local slug="$1" fence_dir="$2"
	EXECUTED_FENCES=()
	local step matched number
	local -a numbers
	for step in ${SPEC_STEPS[@]+"${SPEC_STEPS[@]}"}; do
		case "$step" in
		run:*) matched="$(resolve_fences "$slug" "${step#run:}" "$fence_dir")" || exit $? ;;
		*) continue ;;
		esac
		read -r -a numbers <<<"$matched"
		for number in "${numbers[@]}"; do
			if ! in_list "$number" ${EXECUTED_FENCES[@]+"${EXECUTED_FENCES[@]}"}; then
				EXECUTED_FENCES+=("$number")
			fi
		done
	done
}

# Name the sh fences the journey never runs.
#
# This is information for a reviewer, not a rule: an install one-liner that
# reaches the network is documented and unverified, and saying so is more use
# than pinning its text would be.
report_unexecuted_fences() {
	local slug="$1" fence_dir="$2"
	local number occurrence heading first_line
	while IFS=$'\t' read -r number occurrence heading; do
		if in_list "$number" ${EXECUTED_FENCES[@]+"${EXECUTED_FENCES[@]}"}; then
			continue
		fi
		first_line=""
		IFS= read -r first_line <"$fence_dir/fence-$number.sh" || true
		printf '  not executed: fence %s under "%s": %s\n' "$number" "$heading" "$first_line"
	done <"$fence_dir/index.tsv"
}

# Hold the behaviours a successful exit does not already prove.
#
# Read the SPEC_ASSERTS note in the header before adding an entry here. This
# holds outcomes, never the transcript: a page is free to reword everything
# around the line, and the line itself is only here because losing it would
# leave the journey green.
assert_transcript() {
	local slug="$1" run_log="$2"
	local expected
	for expected in ${SPEC_ASSERTS[@]+"${SPEC_ASSERTS[@]}"}; do
		if ! grep -F -q -- "$expected" "$run_log"; then
			printf 'tutorial behaviour drift in %s: the replay ran, but its transcript never showed "%s"\n' \
				"$slug" "$expected" >&2
			printf 'Every command exited zero, so this is the kind of regression only this assertion catches.\n' >&2
			exit 1
		fi
	done
}

# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

if ((DRY_RUN == 0)) && ((${#BREG_TUTORIALS[@]} > 0)); then
	prepare_toolset
fi

for slug in "${BREG_TUTORIALS[@]}"; do
	load_spec "$slug"
	tutorial_file="$DOCS_ROOT/$slug.mdx"
	if [[ ! -f "$tutorial_file" ]]; then
		printf 'Base Registry Engine tutorial not found: %s\n' "$tutorial_file" >&2
		exit 1
	fi

	# Extract every sh fence, in order, into numbered files, and index each one
	# by the heading it sits under and its occurrence there. A level-2 heading
	# opens a section, so a fence under a deeper heading answers to the level-2
	# heading above it, and occurrences are counted per heading.
	fence_dir="$WORK_ROOT/fences/$slug"
	mkdir -p "$fence_dir"
	: >"$fence_dir/index.tsv"
	fence_count="$(awk -v outdir="$fence_dir" -v index_file="$fence_dir/index.tsv" '
		in_fence == 0 && /^##[ \t]+/ {
			heading = $0
			sub(/^##[ \t]+/, "", heading)
			sub(/[ \t]+$/, "", heading)
			next
		}
		in_fence == 0 && /^```[A-Za-z0-9_-]+$/ {
			in_fence = 1
			capture = ($0 == "```sh")
			if (capture) {
				count += 1
				occurrence[heading] += 1
				printf "%02d\t%d\t%s\n", count, occurrence[heading], heading > index_file
			}
			next
		}
		in_fence && /^```$/ { in_fence = 0; capture = 0; next }
		in_fence && capture { print > (outdir "/fence-" sprintf("%02d", count) ".sh") }
		END { print count + 0 }
	' "$tutorial_file")"

	resolve_journey_fences "$slug" "$fence_dir"

	printf '%s: %s sh fences, %s executed\n' \
		"$slug" "$fence_count" "${#EXECUTED_FENCES[@]}"
	report_unexecuted_fences "$slug" "$fence_dir"

	if ((DRY_RUN)); then
		continue
	fi

	# Replay the journey in one shell so variables and `umask` persist exactly
	# as a reader experiences them, from the empty directory the page tells
	# them to open a terminal in.
	reader_dir="$READER_DIR/$(basename "$slug")"
	mkdir -p "$reader_dir"
	run_script="$WORK_ROOT/run-$(basename "$slug").sh"
	emit_journey "$slug" "$fence_dir" >"$run_script"

	run_log="$WORK_ROOT/run-$(basename "$slug").log"
	if ! (
		unset CARGO_TARGET_DIR
		cd "$reader_dir"
		PATH="$SHIM_DIR:$PATH" bash "$run_script"
	) 2>&1 | tee "$run_log"; then
		printf 'tutorial %s failed; the transcript ends just before this line\n' \
			"$slug" >&2
		exit 1
	fi

	assert_transcript "$slug" "$run_log"
done

if ((${#BREG_TUTORIALS[@]} == 1)); then
	printf 'Checked 1 tutorial.\n'
else
	printf 'Checked %d tutorials.\n' "${#BREG_TUTORIALS[@]}"
fi
