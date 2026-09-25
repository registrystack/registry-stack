#!/usr/bin/env bash
#
# Execute the current Registry Messaging tutorials from a fresh reader
# directory.
#
# What this gate is for: proving that the commands the Messaging tutorials
# document still run, and that a short list of behaviours a successful exit
# does not already prove still holds: an accepted submission, an SMS the mock
# provider reports delivered, an email Mailpit received, a session that removes
# its containers when it stops.
#
# What this gate is NOT for: policing what a page says. It pins no fence count,
# no command string and no documented output. Prose, output blocks and command
# wording are free to change without touching this file, and a writer may add
# or remove a command block under a heading the journey already runs with no
# change here at all. If you find yourself adding an array of strings a page
# must contain, stop: that is the pinning this file deliberately does not do.
#
# This gate builds `messagingctl` from the checked-out source unless
# MESSAGINGCTL_BIN selects exact candidate or released bytes, then replays each
# registered tutorial's own shell fences from an empty reader directory, the
# way a reader starts after putting the binary on PATH. What CI runs is what a
# reader copies.
#
# Usage:
#   scripts/check-messaging-tutorial.sh              replay every registered tutorial
#   scripts/check-messaging-tutorial.sh --dry-run    resolve the journeys only
#
# The full run needs Docker because `messagingctl dev` runs PostgreSQL and
# Mailpit in containers. The dry run needs neither Docker nor a compiler, which
# is what lets it run in the docs checks.
#
# Registering a tutorial means adding its slug to MESSAGING_TUTORIALS and a
# branch to load_spec. Each spec holds two things:
#
#   SPEC_STEPS    the reader journey, in order. Fences are addressed by the
#                 heading they sit under, never by position, so inserting a
#                 command block cannot silently move a step onto the wrong
#                 command.
#                   run:<Heading>              execute every sh fence under
#                                              that heading, in document order
#                   run:<Heading>|<n>          execute the nth sh fence under
#                                              that heading
#                   session:<Heading>          start the one single-line sh
#                                              fence under that heading in the
#                                              background, the way a reader
#                                              leaves it running in a first
#                                              terminal, and wait for its
#                                              `ready` line
#                   stop-session               send the session SIGINT, the
#                                              Ctrl-C the page tells a reader
#                                              to press, and wait for it
#                 The |<n> suffix is optional wherever a heading holds a single
#                 sh fence. Skipping is implicit: a fence under no listed
#                 heading is simply not run, and the summary names it so a
#                 reviewer can see the unverified surface.
#
#   SPEC_ASSERTS  behaviours the replay transcript must still show. One test
#                 decides membership: would this regress silently, without any
#                 command exiting non-zero? The submissions on these pages are
#                 read with curl --write-out rather than --fail-with-body, and
#                 the status polls stop after a bounded number of tries rather
#                 than failing, so they exit zero whatever Messaging answers,
#                 which is exactly the kind of regression only an assertion
#                 catches. Do not grow this into a transcript pin.
#
# Renaming a heading breaks the steps that name it, by name, in --dry-run. That
# is the trade: a renamed heading is a structural edit to the journey, it fails
# loudly rather than replaying the wrong command, and it is exactly when the
# journey is worth walking again.
#
# Configuration:
#   MESSAGINGCTL_BIN                           run this exact binary instead
#                                              of building from source
#   MESSAGING_TUTORIAL_CARGO_PROFILE           ci (default) or release
#   MESSAGING_TUTORIAL_READY_SECONDS           how long a session may take to
#                                              report ready (default 600, which
#                                              covers pulling both images)
#   MESSAGING_TUTORIAL_DOCS_ROOT               docs content directory override (tests)
#
# MESSAGINGCTL_DEV_PORT and MESSAGINGCTL_DEV_METRICS_PORT are deliberately not
# set here. The tutorial's own commands pass no port flags, so leaving both
# unset replays the default ports a reader gets. They reach `messagingctl dev`
# through the environment when a caller exports them, which is how a developer
# whose machine already listens on 8107 or 9107 runs this gate; CI exports
# neither.

set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$SITE_ROOT/../.." && pwd)"
DOCS_ROOT="${MESSAGING_TUTORIAL_DOCS_ROOT:-$SITE_ROOT/src/content/docs}"
BUILD_PROFILE="${MESSAGING_TUTORIAL_CARGO_PROFILE:-ci}"
READY_SECONDS="${MESSAGING_TUTORIAL_READY_SECONDS:-600}"
TARGET_DIR="$REPO_ROOT/target/messaging-tutorial-source"
# The label `messagingctl dev` puts on every container a session starts.
OWNER_LABEL='org.registrystack.messagingctl.dev-owner'

# ---------------------------------------------------------------------------
# Registered tutorials
# ---------------------------------------------------------------------------

# The docs directories this gate is responsible for. Messaging shares these
# directories with every other product, so membership is decided by what a
# page runs, not by where it sits: see page_runs_messaging_commands.
MESSAGING_DOC_SECTIONS=(
	start
	tutorials
)

MESSAGING_TUTORIALS=(
	tutorials/first-messaging
)

# Every other page that runs Registry Messaging commands, and the reason it is
# not replayed here. check_tutorial_coverage below fails by name on a page in
# neither list, so a new Messaging tutorial cannot ship unreplayed and
# unexplained. No page needs an entry today.
EXCLUDED_MESSAGING_TUTORIALS=(
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
# Registry Messaging?
#
# A command name is followed by whitespace or the end of the line and preceded
# by neither a path separator nor a word character, so `messaging.yaml`,
# `registry-messagingctl` and `messaging_url` read as the filename, package and
# shell variable they are rather than as an invocation.
page_runs_messaging_commands() {
	awk '
        in_fence == 0 && /^```sh$/ { in_fence = 1; next }
        in_fence && /^```$/ { in_fence = 0; next }
        in_fence && /(^|[^[:alnum:]_.\/-])(messagingctl|messaging)([[:space:]]|$)/ { found = 1; exit }
        END { exit found ? 0 : 1 }
    ' "$1"
}

# Assert that every page running Registry Messaging commands is either
# registered for replay or named in EXCLUDED_MESSAGING_TUTORIALS with a reason.
check_tutorial_coverage() {
	local file section slug
	local -a unregistered=()
	for slug in ${EXCLUDED_MESSAGING_TUTORIALS[@]+"${EXCLUDED_MESSAGING_TUTORIALS[@]}"}; do
		if in_list "$slug" "${MESSAGING_TUTORIALS[@]}"; then
			printf 'coverage error in %s: %s is both registered in MESSAGING_TUTORIALS and excluded in EXCLUDED_MESSAGING_TUTORIALS\n' \
				"${BASH_SOURCE[0]}" "$slug" >&2
			exit 2
		fi
		if [[ ! -f "$DOCS_ROOT/$slug.mdx" ]]; then
			printf 'coverage error in %s: %s.mdx in EXCLUDED_MESSAGING_TUTORIALS does not exist under %s\n' \
				"${BASH_SOURCE[0]}" "$slug" "$DOCS_ROOT" >&2
			exit 2
		fi
		if ! page_runs_messaging_commands "$DOCS_ROOT/$slug.mdx"; then
			printf 'coverage error in %s: %s.mdx no longer runs Registry Messaging commands, so its entry in EXCLUDED_MESSAGING_TUTORIALS says nothing; remove it\n' \
				"${BASH_SOURCE[0]}" "$slug" >&2
			exit 2
		fi
	done
	for section in "${MESSAGING_DOC_SECTIONS[@]}"; do
		for file in "$DOCS_ROOT/$section"/*.mdx; do
			[[ -e "$file" ]] || continue
			slug="$section/$(basename "$file" .mdx)"
			page_runs_messaging_commands "$file" || continue
			if ! in_list "$slug" "${MESSAGING_TUTORIALS[@]}" &&
				! in_list "$slug" ${EXCLUDED_MESSAGING_TUTORIALS[@]+"${EXCLUDED_MESSAGING_TUTORIALS[@]}"}; then
				unregistered+=("$slug")
			fi
		done
	done
	if ((${#unregistered[@]} > 0)); then
		printf 'tutorial coverage gap: the following pages run Registry Messaging commands and are neither registered in MESSAGING_TUTORIALS nor excluded in EXCLUDED_MESSAGING_TUTORIALS:\n' >&2
		for slug in "${unregistered[@]}"; do
			printf '  %s.mdx\n' "$slug" >&2
		done
		printf 'add each to MESSAGING_TUTORIALS (with a load_spec branch) or to EXCLUDED_MESSAGING_TUTORIALS with a reason, in %s\n' \
			"${BASH_SOURCE[0]}" >&2
		exit 1
	fi
}

check_tutorial_coverage

load_spec() {
	SPEC_STEPS=()
	SPEC_ASSERTS=()

	case "$1" in
	tutorials/first-messaging)
		# The page opens with a source build that puts messagingctl on PATH,
		# which this gate replaces with the binary under test. The session
		# runs in a first terminal until Ctrl-C; everything after it runs in
		# a second terminal, which is this journey's own shell.
		SPEC_STEPS=(
			"run:Create a package"
			"session:Start the session"
			"run:Get a token"
			"run:Send an SMS"
			"run:Send an email"
			"stop-session"
		)
		# The submissions use curl --write-out and no --fail-with-body, and
		# the polls give up quietly after ten tries, so the fences exit zero
		# even if Messaging refuses the send or the report never arrives.
		SPEC_ASSERTS=(
			"HTTP 202"
			'"status": "delivered"'
			'"status": "submitted"'
			"Subject: Votre rendez-vous du 01/10/2026"
			"containers are removed"
		)
		;;
	*)
		printf '%s is not a registered Registry Messaging tutorial in %s\n' \
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

# The system temporary directory is a link wherever /tmp or TMPDIR is one.
# Resolving the work root once keeps every path this gate records on the
# physical path the session reports.
WORK_ROOT="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/messaging-tutorial.XXXXXX")" && pwd -P)"
READER_DIR="$WORK_ROOT/reader"
SHIM_DIR="$WORK_ROOT/bin"
SESSION_PID_FILE="$WORK_ROOT/session.pid"

# Stop the development session the replay started, and reclaim its containers
# and volumes. A journey that fails halfway leaves `messagingctl dev` running
# with a PostgreSQL and a Mailpit container behind it, and deleting the work
# root alone would orphan both. The session removes its own containers when
# it stops, so SIGINT comes first; the label sweep then removes whatever a
# killed or crashed session left, by the owner its record names. Both steps
# are idempotent, so a journey that already stopped its session costs nothing
# here.
# Returns non-zero when a container was left behind, which is what keeps its
# session record under the work root for a second attempt.
stop_dev_sessions() {
	local pid record owner container status=0 _
	if [[ -f "$SESSION_PID_FILE" ]]; then
		pid="$(<"$SESSION_PID_FILE")"
		if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
			kill -INT "$pid" 2>/dev/null || true
			for _ in $(seq 1 120); do
				kill -0 "$pid" 2>/dev/null || break
				sleep 0.5
			done
			if kill -0 "$pid" 2>/dev/null; then
				printf 'the development session %s did not stop on SIGINT; killing it\n' "$pid" >&2
				kill -KILL "$pid" 2>/dev/null || true
			fi
		fi
	fi
	[[ -d "$READER_DIR" ]] || return 0
	while IFS= read -r record; do
		if ! owner="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["owner"])' "$record")"; then
			printf 'could not read the session owner from %s\n' "$record" >&2
			status=1
			continue
		fi
		while IFS= read -r container; do
			[[ -n "$container" ]] || continue
			if ! docker rm --force --volumes "$container" >/dev/null; then
				printf 'could not remove container %s of the session in %s\n' "$container" "$record" >&2
				status=1
			fi
		done < <(docker ps --all --quiet --filter "label=$OWNER_LABEL=$owner")
	done < <(find "$READER_DIR" -path '*/.messaging/dev/session.json' 2>/dev/null)
	return "$status"
}

cleanup() {
	local exit_code=$?
	set +e
	if stop_dev_sessions; then
		chmod -R u+w "$WORK_ROOT" 2>/dev/null
		rm -rf "$WORK_ROOT"
	else
		# The session record under the work root names the owner label the
		# containers carry, so removing the work root now would leave them
		# with nothing that says which session they belong to.
		printf 'keeping %s: remove the containers labelled %s by the owner each session.json names\n' \
			"$WORK_ROOT" "$OWNER_LABEL" >&2
	fi
	if ((exit_code == 0)); then
		printf 'Registry Messaging tutorial gate: PASS\n'
	else
		printf 'Registry Messaging tutorial gate: FAIL (exit %d)\n' "$exit_code" >&2
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
	if [[ -z "${MESSAGINGCTL_BIN:-}" ]]; then
		local profile_dir
		profile_dir="$(resolve_profile_dir)"
		# On macOS the FIPS crypto library is a dynamic library a directly
		# executed binary cannot find; the helper records where Cargo built
		# it in REGISTRY_CARGO_RUNTIME_LIBRARY_PATH.
		# shellcheck source=scripts/cargo-runtime-library-path.sh
		. "$REPO_ROOT/scripts/cargo-runtime-library-path.sh"
		CARGO_TARGET_DIR="$TARGET_DIR" \
			registry_cargo_build "$REPO_ROOT" --manifest-path "$REPO_ROOT/Cargo.toml" \
			--locked --profile "$BUILD_PROFILE" -p registry-messagingctl --bins
		MESSAGINGCTL_BIN="$TARGET_DIR/$profile_dir/messagingctl"
	fi
	# Absoluteness first: the reader journey runs from its own directory and
	# reaches the binary through the shim, so a relative path resolves
	# against the wrong directory and would otherwise surface much later,
	# mid-journey, as "command not found".
	if [[ "$MESSAGINGCTL_BIN" != /* ]]; then
		printf 'toolset binary path must be absolute: %s\n' "$MESSAGINGCTL_BIN" >&2
		exit 1
	fi
	if [[ ! -x "$MESSAGINGCTL_BIN" ]]; then
		printf 'toolset binary not executable: %s\n' "$MESSAGINGCTL_BIN" >&2
		exit 1
	fi

	# The tutorial calls the binary by name, so serve it from a shim
	# directory. Where the build recorded a runtime library directory, the
	# shim is a wrapper that sets it: macOS strips DYLD_* variables when it
	# runs a protected executable such as /usr/bin/env, so an inherited value
	# would not survive the journey's own shell.
	mkdir -p "$SHIM_DIR"
	if [[ -n "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}" ]]; then
		printf '#!/bin/sh\nDYLD_FALLBACK_LIBRARY_PATH=%q\nexport DYLD_FALLBACK_LIBRARY_PATH\nexec %q "$@"\n' \
			"$REGISTRY_CARGO_RUNTIME_LIBRARY_PATH" "$MESSAGINGCTL_BIN" >"$SHIM_DIR/messagingctl"
		chmod 755 "$SHIM_DIR/messagingctl"
	else
		ln -s "$MESSAGINGCTL_BIN" "$SHIM_DIR/messagingctl"
	fi
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

# Resolve a session: address to its one fence, and require that fence to be
# a single command line. The gate starts that line in the background, so a
# second line would either run in the foreground ahead of it or be lost; a
# reader, too, starts exactly one command in the first terminal.
resolve_session_fence() {
	local slug="$1" address="$2" fence_dir="$3"
	local matched
	matched="$(resolve_fences "$slug" "$address" "$fence_dir")" || exit $?
	if [[ "$matched" == *' '* ]]; then
		printf 'tutorial spec error in %s: the session heading "%s" holds more than one sh fence (%s); a session starts exactly one command\n' \
			"$slug" "$address" "$matched" >&2
		exit 1
	fi
	local lines
	lines="$(grep -c . "$fence_dir/fence-$matched.sh" || true)"
	if [[ "$lines" != 1 ]]; then
		printf 'tutorial spec error in %s: the session fence under "%s" holds %s command lines; a session starts exactly one command\n' \
			"$slug" "$address" "$lines" >&2
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

# Emit a session: step: start the fence's one command in the background, the
# way a reader leaves it running in a first terminal, record its process id
# for the stop step and the outer cleanup, and wait for its ready report.
emit_session_step() {
	local slug="$1" address="$2" fence_dir="$3"
	local number
	number="$(resolve_session_fence "$slug" "$address" "$fence_dir")" || exit $?
	printf '\nprintf "==> %s fence %s (session, left running)\\n"\n' "$slug" "$number"
	# The redirection is emitted literally; the journey shell expands it.
	# shellcheck disable=SC2016
	printf '%s >"$MESSAGING_TUTORIAL_SESSION_LOG" 2>&1 &\n' "$(cat "$fence_dir/fence-$number.sh")"
	cat <<'EOF'
session_pid=$!
printf '%s\n' "$session_pid" >"$MESSAGING_TUTORIAL_SESSION_PID_FILE"
session_deadline=$((SECONDS + MESSAGING_TUTORIAL_READY_SECONDS))
until grep -q '^ready$' "$MESSAGING_TUTORIAL_SESSION_LOG"; do
	if ! kill -0 "$session_pid" 2>/dev/null; then
		cat "$MESSAGING_TUTORIAL_SESSION_LOG"
		printf 'the session stopped before it reported ready\n' >&2
		exit 1
	fi
	if ((SECONDS >= session_deadline)); then
		cat "$MESSAGING_TUTORIAL_SESSION_LOG"
		printf 'the session did not report ready in %s seconds\n' "$MESSAGING_TUTORIAL_READY_SECONDS" >&2
		exit 1
	fi
	sleep 1
done
cat "$MESSAGING_TUTORIAL_SESSION_LOG"
session_reported="$(wc -l <"$MESSAGING_TUTORIAL_SESSION_LOG")"
EOF
}

# Emit the stop-session step: the Ctrl-C the page tells a reader to press, then
# what the session printed as it stopped.
emit_stop_session_step() {
	local slug="$1"
	printf '\nprintf "==> %s stop the session (Ctrl-C)\\n"\n' "$slug"
	cat <<'EOF'
kill -INT "$session_pid"
wait "$session_pid"
tail -n "+$((session_reported + 1))" "$MESSAGING_TUTORIAL_SESSION_LOG"
EOF
}

emit_journey() {
	local slug="$1" fence_dir="$2"
	printf 'set -euo pipefail\n'
	printf 'trap "exit 130" HUP INT TERM\n'
	local step
	for step in ${SPEC_STEPS[@]+"${SPEC_STEPS[@]}"}; do
		case "$step" in
		run:*) emit_run_step "$slug" "${step#run:}" "$fence_dir" ;;
		session:*) emit_session_step "$slug" "${step#session:}" "$fence_dir" ;;
		stop-session) emit_stop_session_step "$slug" ;;
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
		session:*) matched="$(resolve_session_fence "$slug" "${step#session:}" "$fence_dir")" || exit $? ;;
		stop-session) continue ;;
		*)
			printf 'tutorial spec error in %s: unknown step: %s\n' "$slug" "$step" >&2
			exit 2
			;;
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
# This is information for a reviewer, not a rule: a source build that reaches
# the network is documented and unverified, and saying so is more use than
# pinning its text would be.
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

if ((DRY_RUN == 0)) && ((${#MESSAGING_TUTORIALS[@]} > 0)); then
	prepare_toolset
fi

for slug in "${MESSAGING_TUTORIALS[@]}"; do
	load_spec "$slug"
	tutorial_file="$DOCS_ROOT/$slug.mdx"
	if [[ ! -f "$tutorial_file" ]]; then
		printf 'Registry Messaging tutorial not found: %s\n' "$tutorial_file" >&2
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

	# Replay the journey in one shell so variables persist exactly as a
	# reader's second terminal keeps them, from the empty directory the page
	# tells them to change to.
	reader_dir="$READER_DIR/$(basename "$slug")"
	mkdir -p "$reader_dir"
	run_script="$WORK_ROOT/run-$(basename "$slug").sh"
	emit_journey "$slug" "$fence_dir" >"$run_script"

	run_log="$WORK_ROOT/run-$(basename "$slug").log"
	if ! (
		unset CARGO_TARGET_DIR
		cd "$reader_dir"
		MESSAGING_TUTORIAL_SESSION_LOG="$WORK_ROOT/session-$(basename "$slug").log" \
		MESSAGING_TUTORIAL_SESSION_PID_FILE="$SESSION_PID_FILE" \
		MESSAGING_TUTORIAL_READY_SECONDS="$READY_SECONDS" \
		PATH="$SHIM_DIR:$PATH" bash "$run_script"
	) 2>&1 | tee "$run_log"; then
		printf 'tutorial %s failed; the transcript ends just before this line\n' \
			"$slug" >&2
		exit 1
	fi

	assert_transcript "$slug" "$run_log"
done

if ((${#MESSAGING_TUTORIALS[@]} == 1)); then
	printf 'Checked 1 tutorial.\n'
else
	printf 'Checked %d tutorials.\n' "${#MESSAGING_TUTORIALS[@]}"
fi
