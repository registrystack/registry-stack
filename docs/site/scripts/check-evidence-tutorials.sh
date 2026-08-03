#!/usr/bin/env bash
#
# Execute the current Evidence tutorials from a fresh reader directory.
#
# This gate builds the Evidence toolset from the checked-out source unless
# EVIDENCE_BIN and EVIDENCECTL_BIN select exact candidate or released bytes,
# then replays the first-assertion tutorial's own shell fences: scaffold,
# key generation, the immutability freeze, the fixtures run, and cleanup.
# The release-download fences are not executed here; the released-binary form
# of this gate arrives once a release ships the toolset (plan item F3).
#
# Usage:
#   scripts/check-evidence-tutorials.sh            extract, drift-check, execute
#   scripts/check-evidence-tutorials.sh --dry-run  extract and drift-check only
#
# Drift detection:
#   - EXPECTED_SH_FENCES pins how many sh fences the tutorial holds; bump it
#     when you intentionally add or remove a documented command block
#   - RUNNABLE_FROM pins where the on-machine journey starts (the fences
#     before it download a release and are replaced by the built binaries)
#   - REQUIRED_LITERALS pins the commands and outputs the tutorial must keep
#     documenting; the executed fences run verbatim, so a changed command is
#     exercised as written
#
# Configuration:
#   EVIDENCE_BIN / EVIDENCECTL_BIN        run these exact binaries instead of
#                                         building from source
#   EVIDENCE_TUTORIAL_CARGO_PROFILE       ci (default) or release
#   EVIDENCE_TUTORIAL_FILE                tutorial path override (tests only)

set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$SITE_ROOT/../.." && pwd)"
TUTORIAL="${EVIDENCE_TUTORIAL_FILE:-$SITE_ROOT/src/content/docs/tutorials/first-evidence-assertion.mdx}"
BUILD_PROFILE="${EVIDENCE_TUTORIAL_CARGO_PROFILE:-ci}"
TARGET_DIR="$REPO_ROOT/target/evidence-tutorial-source"

EXPECTED_SH_FENCES=8
RUNNABLE_FROM=3
# shellcheck disable=SC2016  # the first entry is literal tutorial text, not an expansion
REQUIRED_LITERALS=(
	'evidencectl-${tag}-install.sh'
	'evidencectl new hello-evidence'
	'evidencectl keygen signing --out-dir secrets --kid scaffold-signing-key-1'
	'chmod -R a-w bundle && chmod 444 runtime.yaml'
	'evidencectl fixtures run --project .'
	'2 passed, 0 failed (12 cases evaluated)'
)

DRY_RUN=0
case "${1:-}" in
'') ;;
--dry-run) DRY_RUN=1 ;;
*)
	printf 'unknown argument: %s (expected --dry-run or nothing)\n' "$1" >&2
	exit 2
	;;
esac

if [[ ! -f "$TUTORIAL" ]]; then
	printf 'Evidence tutorial not found: %s\n' "$TUTORIAL" >&2
	exit 1
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

# Extract every sh fence, in order, into numbered files.
FENCE_DIR="$WORK_ROOT/fences"
mkdir -p "$FENCE_DIR"
fence_count="$(awk -v outdir="$FENCE_DIR" '
	/^```sh$/ { infence = 1; count += 1; next }
	infence && /^```$/ { infence = 0; next }
	infence { print > (outdir "/fence-" sprintf("%02d", count) ".sh") }
	END { print count + 0 }
' "$TUTORIAL")"

if [[ "$fence_count" -ne "$EXPECTED_SH_FENCES" ]]; then
	printf 'tutorial drift: %s sh fences found, expected %s\n' \
		"$fence_count" "$EXPECTED_SH_FENCES" >&2
	printf 'Update EXPECTED_SH_FENCES and RUNNABLE_FROM in %s when the change is intentional.\n' \
		"${BASH_SOURCE[0]}" >&2
	exit 1
fi

for literal in "${REQUIRED_LITERALS[@]}"; do
	if ! grep -F -q -- "$literal" "$TUTORIAL"; then
		printf 'tutorial drift: required literal missing: %s\n' "$literal" >&2
		exit 1
	fi
done

if ((DRY_RUN)); then
	printf 'Extracted %s sh fences; every required literal present.\n' "$fence_count"
	exit 0
fi

# Resolve the toolset under test.
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

if [[ -z "${EVIDENCE_BIN:-}" || -z "${EVIDENCECTL_BIN:-}" ]]; then
	profile_dir="$(resolve_profile_dir)"
	(cd "$REPO_ROOT" && CARGO_TARGET_DIR="$TARGET_DIR" \
		cargo build --locked --profile "$BUILD_PROFILE" \
		-p registry-evidence -p registry-evidencectl)
	EVIDENCE_BIN="$TARGET_DIR/$profile_dir/evidence"
	EVIDENCECTL_BIN="$TARGET_DIR/$profile_dir/evidencectl"
fi
for bin in "$EVIDENCE_BIN" "$EVIDENCECTL_BIN"; do
	# Absoluteness first: the reader journey runs from its own directory and
	# reaches the binaries through symlinks, so a relative path resolves against
	# the wrong directory and would otherwise surface much later, mid-journey,
	# as "command not found".
	if [[ "$bin" != /* ]]; then
		printf 'toolset binary path must be absolute: %s\n' "$bin" >&2
		exit 1
	fi
	if [[ ! -x "$bin" ]]; then
		printf 'toolset binary not executable: %s\n' "$bin" >&2
		exit 1
	fi
done

# The tutorial calls the binaries by name, so serve them from a shim dir.
SHIM_DIR="$WORK_ROOT/bin"
mkdir -p "$SHIM_DIR"
ln -s "$EVIDENCE_BIN" "$SHIM_DIR/evidence"
ln -s "$EVIDENCECTL_BIN" "$SHIM_DIR/evidencectl"

# Replay the on-machine journey: every fence from RUNNABLE_FROM onward, in
# order, in one shell so `cd` persists exactly as a reader experiences it.
READER_DIR="$WORK_ROOT/reader"
mkdir -p "$READER_DIR"
RUN_SCRIPT="$WORK_ROOT/run.sh"
{
	printf 'set -euo pipefail\n'
	for ((i = RUNNABLE_FROM; i <= EXPECTED_SH_FENCES; i++)); do
		printf '\nprintf "==> tutorial fence %02d\\n"\n' "$i"
		cat "$(printf '%s/fence-%02d.sh' "$FENCE_DIR" "$i")"
	done
} >"$RUN_SCRIPT"

RUN_LOG="$WORK_ROOT/run.log"
if ! (cd "$READER_DIR" && PATH="$SHIM_DIR:$PATH" bash "$RUN_SCRIPT") 2>&1 |
	tee "$RUN_LOG"; then
	printf 'tutorial execution failed; the transcript ends just before this line\n' >&2
	exit 1
fi

for expected in \
	'PASS: check' \
	'PASS: fixtures/cases.yaml (12 cases)' \
	'2 passed, 0 failed (12 cases evaluated)'; do
	if ! grep -F -q -- "$expected" "$RUN_LOG"; then
		printf 'tutorial output drift: expected "%s" in the fixtures run output\n' \
			"$expected" >&2
		exit 1
	fi
done
