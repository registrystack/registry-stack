#!/usr/bin/env bash
#
# Execute the current Evidence tutorials from a fresh reader directory.
#
# This gate builds the Evidence toolset from the checked-out source unless
# EVIDENCE_BIN, EVIDENCECTL_BIN and MINT_BIN select exact candidate or released
# bytes, then replays each registered tutorial's own shell fences in its own
# reader directory. Every tutorial creates the files it needs from its
# documented commands, so what CI runs is what a reader copies.
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
#   EVIDENCE_BIN / EVIDENCECTL_BIN /      run these exact binaries instead of
#   MINT_BIN                              building from source
#   EVIDENCE_TUTORIAL_CARGO_PROFILE       ci (default) or release
#   EVIDENCE_TUTORIAL_DOCS_ROOT           tutorial directory override (tests)

set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$SITE_ROOT/../.." && pwd)"
# A fence helper written against the replay userland's floor: it locates a
# fence by heading, language and occurrence and applies it to a file, using
# only the shell and coreutils the container carries.
FENCE="$SITE_ROOT/scripts/evidence-tutorial-fence.sh"
DOCS_ROOT="${EVIDENCE_TUTORIAL_DOCS_ROOT:-$SITE_ROOT/src/content/docs/tutorials}"
BUILD_PROFILE="${EVIDENCE_TUTORIAL_CARGO_PROFILE:-ci}"
TARGET_DIR="$REPO_ROOT/target/evidence-tutorial-source"

# ---------------------------------------------------------------------------
# Registered tutorials
# ---------------------------------------------------------------------------

EVIDENCE_TUTORIALS=(
	first-evidence-assertion
	return-a-governed-value
	refuse-unsafe-evidence-requests
	verify-an-assertion-as-a-consumer
)

load_spec() {
	SPEC_FENCES=0
	SPEC_STEPS=()
	SPEC_LITERALS=()
	SPEC_OUTPUTS=()

	case "$1" in
	first-evidence-assertion)
		SPEC_FENCES=12
		SPEC_STEPS=(
			"run:2"
			"save:Start a small registry|python|1|registry.py"
			"background:3"
			"wait-http:http://127.0.0.1:8000/openapi.json"
			"run:4-5"
			"save:Create the Evidence project|yaml|1|questions/adult-status.yaml"
			"save:Create the Evidence project|rhai|1|derivations/adult-status.rhai"
			"run:6-12"
		)
		SPEC_LITERALS=(
			"releases/latest/download/evidencectl-install.sh | bash"
			"evidencectl new adult-status"
			"evidencectl request prepare adult-status"
			"--config .evidence/requests/first-assertion/authorization.curl"
			"evidencectl verify assertion.jws.json"
			"evidencectl audit show --last-operation"
		)
		SPEC_OUTPUTS=(
			"Created an incomplete OpenAPI authoring project in adult-status"
			"Evidence ready at http://127.0.0.1:8080"
			"Prepared request: .evidence/requests/first-assertion/request.json"
			"VERIFIED"
			"Local Evidence stopped"
			"ACCESS AUTHORIZED adult-status age-check requester="
			"DISCLOSURE RELEASED is_adult"
		)
		;;
	return-a-governed-value)
		SPEC_FENCES=9
		SPEC_STEPS=(
			"background:1"
			"wait-http:http://127.0.0.1:8000/openapi.json"
			"run:2"
			"save:Add the age-bracket question|yaml|1|questions/age-bracket.yaml"
			"save:Add the age-bracket question|rhai|1|derivations/age-bracket.rhai"
			"run:3-9"
		)
		SPEC_LITERALS=(
			"type: controlled-category"
			"values: [under-18, 18-to-24, 25-to-64, 65-or-older]"
			"evidencectl request prepare age-bracket"
			"--config .evidence/requests/age-bracket/authorization.curl"
			"evidencectl verify age-bracket.jws.json"
			"evidencectl audit show --last-operation"
		)
		SPEC_OUTPUTS=(
			"Evidence ready at http://127.0.0.1:8080"
			"Prepared request: .evidence/requests/age-bracket/request.json"
			"VERIFIED"
			"Local Evidence stopped"
			"ACCESS AUTHORIZED age-bracket service-path-selection requester="
			"DISCLOSURE RELEASED age_bracket"
		)
		;;
	refuse-unsafe-evidence-requests)
		SPEC_FENCES=11
		SPEC_STEPS=(
			"background:1"
			"wait-http:http://127.0.0.1:8000/openapi.json"
			"run:2-11"
		)
		SPEC_LITERALS=(
			'request["purpose"] = "age-check"'
			"--data-binary @unauthorized-request.json"
			"--write-out 'HTTP %{http_code}\\n'"
			"--data-binary @.evidence/requests/refusal-check/request.json"
			"evidencectl verify tampered-response.jws.json"
			"test ! -e tampered-response.verified.json"
		)
		SPEC_OUTPUTS=(
			"Evidence ready at http://127.0.0.1:8080"
			"Prepared request: .evidence/requests/refusal-check/request.json"
			"HTTP 403"
			"VERIFIED"
			"TAMPER REFUSED"
			"Local Evidence stopped"
		)
		;;
	verify-an-assertion-as-a-consumer)
		SPEC_FENCES=3
		SPEC_STEPS=("run:1-3")
		SPEC_LITERALS=(
			'context["trustedJwks"]'
			'context["verificationPolicy"]'
			"--jws authorized-response.jws.json"
			"--jwks trusted-issuer-keys.json"
			"--policy verification-policy.json"
			'--at "$verified_at"'
		)
		SPEC_OUTPUTS=(
			"authentic: yes"
			"currently-valid: yes"
			'"value": "25-to-64"'
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
	if [[ -z "${EVIDENCE_BIN:-}" || -z "${EVIDENCECTL_BIN:-}" || -z "${MINT_BIN:-}" ]]; then
		local profile_dir
		profile_dir="$(resolve_profile_dir)"
		(cd "$REPO_ROOT" && CARGO_TARGET_DIR="$TARGET_DIR" \
			cargo build --locked --profile "$BUILD_PROFILE" \
			-p registry-evidence -p registry-evidencectl -p registry-mint)
		EVIDENCE_BIN="$TARGET_DIR/$profile_dir/evidence"
		EVIDENCECTL_BIN="$TARGET_DIR/$profile_dir/evidencectl"
		MINT_BIN="$TARGET_DIR/$profile_dir/mint"
	fi
	local bin
	for bin in "$EVIDENCE_BIN" "$EVIDENCECTL_BIN" "$MINT_BIN"; do
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
	ln -s "$MINT_BIN" "$SHIM_DIR/mint"
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
#
# Both fences are read out of the tutorial here, while the journey is being
# assembled, so a pair the tutorial no longer carries fails by name before the
# reader's first command runs.
emit_edit_step() {
	local slug="$1" spec="$2" tutorial_file="$3" edit_dir="$4"
	local IFS='|'
	# shellcheck disable=SC2206  # deliberate split on the field separator
	local parts=($spec)
	if ((${#parts[@]} != 7)); then
		printf 'tutorial spec error in %s: edit step needs 7 fields, got %d: %s\n' \
			"$slug" "${#parts[@]}" "$spec" >&2
		exit 2
	fi
	EDIT_INDEX=$((EDIT_INDEX + 1))
	local before after
	before="$(printf '%s/edit-%02d-before' "$edit_dir" "$EDIT_INDEX")"
	after="$(printf '%s/edit-%02d-after' "$edit_dir" "$EDIT_INDEX")"
	if ! bash "$FENCE" write-fence "$tutorial_file" \
		"${parts[0]}" "${parts[1]}" "${parts[2]}" "$before" ||
		! bash "$FENCE" write-fence "$tutorial_file" \
			"${parts[3]}" "${parts[4]}" "${parts[5]}" "$after"; then
		printf 'tutorial drift in %s: edit step names a fence the tutorial no longer carries: %s\n' \
			"$slug" "$spec" >&2
		exit 1
	fi
	printf '\nprintf "==> %s edit %s\\n"\n' "$slug" "${parts[6]}"
	# shellcheck disable=SC2016  # FENCE expands in the emitted script
	printf 'bash "$FENCE" replace-block %q %q %q\n' "${parts[6]}" "$before" "$after"
}

# Save a documented non-shell fence as the file the reader is instructed to
# create. The maintained Markdown remains the single source of those bytes.
emit_save_step() {
	local slug="$1" spec="$2"
	local IFS='|'
	# shellcheck disable=SC2206  # deliberate split on the field separator
	local parts=($spec)
	if ((${#parts[@]} != 4)); then
		printf 'tutorial spec error in %s: save step needs 4 fields, got %d: %s\n' \
			"$slug" "${#parts[@]}" "$spec" >&2
		exit 2
	fi
	printf '\nprintf "==> %s save %s\\n"\n' "$slug" "${parts[3]}"
	# shellcheck disable=SC2016  # FENCE and TUTORIAL expand in the emitted script
	printf 'bash "$FENCE" write-fence "$TUTORIAL" %q %q %q %q\n' \
		"${parts[0]}" "${parts[1]}" "${parts[2]}" "${parts[3]}"
}

# A tutorial may ask the reader to leave one foreground command running in a
# second terminal. CI runs that exact one-line command in the background and
# retains its PID for cleanup.
emit_background_step() {
	local slug="$1" number="$2" fence_dir="$3"
	local fence
	fence="$(printf '%s/fence-%02d.sh' "$fence_dir" "$number")"
	if [[ ! -f "$fence" ]] || [[ "$(wc -l <"$fence")" -ne 1 ]]; then
		printf 'tutorial spec error in %s: background step needs one sh line at fence %s\n' \
			"$slug" "$number" >&2
		exit 2
	fi
	local command
	IFS= read -r command <"$fence"
	printf '\nprintf "==> %s fence %02d (background)\\n"\n' "$slug" "$number"
	printf '%s &\n' "$command"
	printf 'BACKGROUND_PIDS+=("$!")\n'
}

emit_wait_http_step() {
	local url="$1"
	printf '\nfor attempt in {1..50}; do\n'
	printf '  if curl -fs %q >/dev/null 2>&1; then break; fi\n' "$url"
	printf '  if [[ "$attempt" -eq 50 ]]; then printf "tutorial service did not become ready\\n" >&2; exit 1; fi\n'
	printf '  sleep 0.1\n'
	printf 'done\n'
}

emit_journey() {
	local slug="$1" fence_dir="$2" tutorial_file="$3"
	local edit_dir="$WORK_ROOT/edits/$slug"
	mkdir -p "$edit_dir"
	EDIT_INDEX=0
	printf 'set -euo pipefail\n'
	printf 'FENCE=%q\n' "$FENCE"
	printf 'TUTORIAL=%q\n' "$tutorial_file"
	printf 'BACKGROUND_PIDS=()\n'
	printf 'cleanup_journey() {\n'
	printf '  if [[ -S .evidence/dev/control.sock ]]; then evidencectl dev stop >/dev/null 2>&1 || true; fi\n'
	printf '  local pid\n'
	printf '  for pid in "${BACKGROUND_PIDS[@]}"; do kill "$pid" >/dev/null 2>&1 || true; wait "$pid" >/dev/null 2>&1 || true; done\n'
	printf '}\n'
	printf 'trap cleanup_journey EXIT\n'
	printf 'trap "exit 130" HUP INT TERM\n'
	local step
	for step in ${SPEC_STEPS[@]+"${SPEC_STEPS[@]}"}; do
		case "$step" in
		run:*) emit_run_step "$slug" "${step#run:}" "$fence_dir" ;;
		edit:*) emit_edit_step "$slug" "${step#edit:}" "$tutorial_file" "$edit_dir" ;;
		save:*) emit_save_step "$slug" "${step#save:}" ;;
		background:*) emit_background_step "$slug" "${step#background:}" "$fence_dir" ;;
		wait-http:*) emit_wait_http_step "${step#wait-http:}" ;;
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
		background:*) total=$((total + 1)) ;;
		esac
	done
	printf '%d' "$total"
}

# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

if ((DRY_RUN == 0)) && ((${#EVIDENCE_TUTORIALS[@]} > 0)); then
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
	case "$slug" in
	first-evidence-assertion)
		reader_dir="$WORK_ROOT/reader/evidence-start"
		;;
	return-a-governed-value)
		reader_dir="$WORK_ROOT/reader/evidence-start/first-evidence-assertion"
		;;
	refuse-unsafe-evidence-requests)
		reader_dir="$WORK_ROOT/reader/evidence-start/first-evidence-assertion"
		;;
	verify-an-assertion-as-a-consumer)
		reader_dir="$WORK_ROOT/reader/evidence-start/first-evidence-assertion"
		;;
	*) reader_dir="$WORK_ROOT/reader/$slug" ;;
	esac
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
