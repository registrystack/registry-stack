#!/usr/bin/env bash
#
# check-tutorial.sh
#
# Verify that src/content/docs/tutorials/first-run-with-registry-lab.mdx still
# matches reality by extracting its shell commands from the "## Steps" section
# and executing them, in order, against a sibling registry-lab checkout.
#
# Usage:
#   scripts/check-tutorial.sh              extract + execute (needs Docker)
#   scripts/check-tutorial.sh --dry-run    extract + print only (no Docker)
#
# Configuration:
#   REGISTRY_LAB_PATH   path to the registry-lab checkout.
#                       Default: <repo-root>/../registry-lab
#
# Exit codes:
#   0   success
#   1   tutorial drift, missing prerequisite, or step failure
#   2   bad CLI argument
#
# Drift detection:
#   - the script asserts EXPECTED_STEP_COUNT commands were extracted; bump this
#     constant when you intentionally add or remove a tutorial step
#   - the script runs whatever commands appear in the tutorial verbatim, so a
#     command change in the docs causes the runner to exercise the new command
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUTORIAL="$REPO_ROOT/src/content/docs/tutorials/first-run-with-registry-lab.mdx"
EXPECTED_STEP_COUNT=7

DRY_RUN=0
for arg in "$@"; do
	case "$arg" in
	--dry-run) DRY_RUN=1 ;;
	-h | --help)
		sed -n '3,21p' "$0"
		exit 0
		;;
	*)
		printf 'unknown argument: %s\n' "$arg" >&2
		exit 2
		;;
	esac
done

if [[ ! -f "$TUTORIAL" ]]; then
	printf 'tutorial not found: %s\n' "$TUTORIAL" >&2
	exit 1
fi

# Extract shell commands from the "## Steps" section. The fences are indented
# under list items (4 spaces), so we strip leading whitespace from each content
# line. Empty lines inside a fence are skipped.
COMMANDS=()
while IFS= read -r line; do
	COMMANDS+=("$line")
done < <(
	awk '
        /^## / {
            in_steps = ($0 ~ /^## Steps[[:space:]]*$/)
            in_fence = 0
            next
        }
        !in_steps { next }
        /^[[:space:]]*```sh[[:space:]]*$/ {
            in_fence = 1
            next
        }
        /^[[:space:]]*```[[:space:]]*$/ && in_fence {
            in_fence = 0
            next
        }
        in_fence {
            sub(/^[[:space:]]+/, "")
            if ($0 != "") print
        }
    ' "$TUTORIAL"
)

if ((${#COMMANDS[@]} != EXPECTED_STEP_COUNT)); then
	printf 'tutorial drift: expected %d shell commands in Steps section, extracted %d:\n' \
		"$EXPECTED_STEP_COUNT" "${#COMMANDS[@]}" >&2
	for cmd in "${COMMANDS[@]}"; do
		printf '  %s\n' "$cmd" >&2
	done
	printf 'if this change was intentional, update EXPECTED_STEP_COUNT in %s\n' \
		"${BASH_SOURCE[0]}" >&2
	exit 1
fi

printf 'extracted %d commands from tutorial:\n' "${#COMMANDS[@]}"
for i in "${!COMMANDS[@]}"; do
	printf '  step %d: %s\n' "$((i + 1))" "${COMMANDS[$i]}"
done

if ((DRY_RUN)); then
	printf 'dry-run: extraction OK, skipping execution\n'
	exit 0
fi

LAB_DIR="${REGISTRY_LAB_PATH:-$REPO_ROOT/../registry-lab}"

if [[ ! -d "$LAB_DIR" ]]; then
	printf 'registry-lab checkout not found at: %s\n' "$LAB_DIR" >&2
	printf 'set REGISTRY_LAB_PATH or check out the repo at the expected path\n' >&2
	exit 1
fi
LAB_DIR="$(cd "$LAB_DIR" && pwd)"

for tool in docker uv python3 openssl; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		printf 'required tool not on PATH: %s\n' "$tool" >&2
		exit 1
	fi
done

LOG_DIR="$REPO_ROOT/dist-check"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/tutorial-$(date -u +%Y%m%dT%H%M%SZ).log"
printf 'lab: %s\n' "$LAB_DIR"
printf 'log: %s\n' "$LOG_FILE"

cleanup() {
	local exit_code=$?
	printf '\n--- cleanup: docker compose down -v ---\n' | tee -a "$LOG_FILE"
	(cd "$LAB_DIR" && docker compose -f compose.yaml down -v) >>"$LOG_FILE" 2>&1 || true
	if ((exit_code == 0)); then
		printf 'tutorial check: PASS (log: %s)\n' "$LOG_FILE"
	else
		printf 'tutorial check: FAIL at exit code %d (log: %s)\n' "$exit_code" "$LOG_FILE" >&2
	fi
}
trap cleanup EXIT

cd "$LAB_DIR"

for i in "${!COMMANDS[@]}"; do
	cmd="${COMMANDS[$i]}"
	step=$((i + 1))
	printf '\n=== step %d: %s ===\n' "$step" "$cmd" | tee -a "$LOG_FILE"
	if ! bash -c "$cmd" >>"$LOG_FILE" 2>&1; then
		printf 'step %d failed: %s\n' "$step" "$cmd" >&2
		printf 'last 50 lines of log:\n' >&2
		tail -n 50 "$LOG_FILE" >&2
		exit 1
	fi
done

# Step 7 (demo-client) writes artifacts under output/. Assert at least one file.
if [[ ! -d "$LAB_DIR/output" ]] ||
	! find "$LAB_DIR/output" -mindepth 1 -type f -print -quit | grep -q .; then
	printf 'expected demo-client to write artifacts under %s/output/\n' "$LAB_DIR" >&2
	exit 1
fi
printf '\ndemo-client artifacts present under %s/output/\n' "$LAB_DIR"
