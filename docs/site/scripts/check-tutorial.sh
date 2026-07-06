#!/usr/bin/env bash
#
# check-tutorial.sh
#
# Verify that src/content/docs/tutorials/first-run-with-registry-lab.mdx still
# matches reality by extracting its shell commands from the "## Steps" and
# "## Verify" sections and executing them, in order, against a sibling
# registry-lab checkout.
#
# Also drift-checks the registryctl tutorials (publish-spreadsheet,
# verify-claim-registry-api) by extracting every `sh`
# fence and asserting the command-line count. Those tutorials are
# execution-verified manually (they need registryctl and a workstation); the
# count assertion makes silent command additions or removals fail CI.
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
#   - the script asserts EXPECTED_STEP_COUNT / EXPECTED_VERIFY_COUNT commands
#     were extracted from the matching sections; bump these constants when you
#     intentionally add or remove a documented command
#   - after compose comes up, the script asserts every entry in
#     EXPECTED_SERVICES is in `running` state; bump the array when you
#     intentionally add or remove a long-running service
#   - the script runs whatever commands appear in the tutorial verbatim, so a
#     command change in the docs causes the runner to exercise the new command
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUTORIAL="$REPO_ROOT/src/content/docs/tutorials/first-run-with-registry-lab.mdx"
EXPECTED_STEP_COUNT=5
EXPECTED_VERIFY_COUNT=4
EXPECTED_DEMO_ARTIFACTS=3
EXPECTED_SERVICES=(
	civil-registry-relay
	social-protection-registry-relay
	health-registry-relay
	postgres
	zitadel
	civil-notary
	social-protection-notary
	shared-eligibility-notary
	openfn-mock-registry
	openfn-civil-sidecar
	openfn-civil-notary
	static-metadata-publisher
)

DRY_RUN=0
for arg in "$@"; do
	case "$arg" in
	--dry-run) DRY_RUN=1 ;;
	-h | --help)
		sed -n '3,31p' "$0"
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

# Extract shell commands from a named "## <Section>" section of the tutorial.
# Fences may be indented under list items; strip leading whitespace and skip
# empty lines within a fence.
extract_section_commands() {
	local section="$1"
	awk -v target="$section" '
        /^## / {
            in_section = ($0 ~ ("^## " target "[[:space:]]*$"))
            in_fence = 0
            next
        }
        !in_section { next }
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
}

STEPS=()
while IFS= read -r line; do
	STEPS+=("$line")
done < <(extract_section_commands "Steps")

VERIFY=()
while IFS= read -r line; do
	VERIFY+=("$line")
done < <(extract_section_commands "Verify")

if ((${#STEPS[@]} != EXPECTED_STEP_COUNT)); then
	printf 'tutorial drift: expected %d shell commands in Steps section, extracted %d:\n' \
		"$EXPECTED_STEP_COUNT" "${#STEPS[@]}" >&2
	for cmd in "${STEPS[@]}"; do
		printf '  %s\n' "$cmd" >&2
	done
	printf 'if this change was intentional, update EXPECTED_STEP_COUNT in %s\n' \
		"${BASH_SOURCE[0]}" >&2
	exit 1
fi

if ((${#VERIFY[@]} != EXPECTED_VERIFY_COUNT)); then
	printf 'tutorial drift: expected %d shell commands in Verify section, extracted %d:\n' \
		"$EXPECTED_VERIFY_COUNT" "${#VERIFY[@]}" >&2
	for cmd in "${VERIFY[@]}"; do
		printf '  %s\n' "$cmd" >&2
	done
	printf 'if this change was intentional, update EXPECTED_VERIFY_COUNT in %s\n' \
		"${BASH_SOURCE[0]}" >&2
	exit 1
fi

printf 'extracted %d Steps commands from tutorial:\n' "${#STEPS[@]}"
for i in "${!STEPS[@]}"; do
	printf '  step %d: %s\n' "$((i + 1))" "${STEPS[$i]}"
done
printf 'extracted %d Verify commands from tutorial:\n' "${#VERIFY[@]}"
for i in "${!VERIFY[@]}"; do
	printf '  verify %d: %s\n' "$((i + 1))" "${VERIFY[$i]}"
done

# Drift check for the registryctl tutorials: count non-empty command lines
# inside `sh` fences. Bump the expected count when you intentionally add or
# remove a documented command.
REGISTRYCTL_TUTORIALS=(
	"publish-spreadsheet-secured-registry-api:36"
	"verify-claim-registry-api:69"
)

count_sh_command_lines() {
	awk '
        /^[[:space:]]*```sh[[:space:]]*$/ { in_fence = 1; next }
        /^[[:space:]]*```[[:space:]]*$/ && in_fence { in_fence = 0; next }
        in_fence {
            sub(/^[[:space:]]+/, "")
            if ($0 != "") count++
        }
        END { print count + 0 }
    ' "$1"
}

for entry in "${REGISTRYCTL_TUTORIALS[@]}"; do
	name="${entry%:*}"
	expected="${entry##*:}"
	page="$REPO_ROOT/src/content/docs/tutorials/$name.mdx"
	if [[ ! -f "$page" ]]; then
		printf 'tutorial not found: %s\n' "$page" >&2
		exit 1
	fi
	actual="$(count_sh_command_lines "$page")"
	if [[ "$actual" != "$expected" ]]; then
		printf 'tutorial drift: %s.mdx has %s sh command lines, expected %s\n' \
			"$name" "$actual" "$expected" >&2
		printf 'if this change was intentional, update REGISTRYCTL_TUTORIALS in %s\n' \
			"${BASH_SOURCE[0]}" >&2
		exit 1
	fi
	printf 'registryctl tutorial %s: %s sh command lines (expected %s)\n' \
		"$name" "$actual" "$expected"
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

for tool in just docker uv python3 openssl; do
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

run_command() {
	local label="$1"
	local cmd="$2"
	printf '\n=== %s: %s ===\n' "$label" "$cmd" | tee -a "$LOG_FILE"
	if ! bash -c "$cmd" >>"$LOG_FILE" 2>&1; then
		printf '%s failed: %s\n' "$label" "$cmd" >&2
		printf 'last 50 lines of log:\n' >&2
		tail -n 50 "$LOG_FILE" >&2
		exit 1
	fi
}

for i in "${!STEPS[@]}"; do
	run_command "step $((i + 1))" "${STEPS[$i]}"
done

# After all Steps, the topology should be up. Assert every long-running service
# (everything except the profile-gated demo-client) is in `running` state.
printf '\n--- assert services running ---\n' | tee -a "$LOG_FILE"
running_services="$(docker compose -f compose.yaml ps --services --filter status=running)"
printf 'running services:\n%s\n' "$running_services" >>"$LOG_FILE"
missing=()
for svc in "${EXPECTED_SERVICES[@]}"; do
	if ! grep -qx "$svc" <<<"$running_services"; then
		missing+=("$svc")
	fi
done
if ((${#missing[@]} > 0)); then
	printf 'expected services not running:\n' >&2
	for svc in "${missing[@]}"; do
		printf '  %s\n' "$svc" >&2
	done
	printf 'docker compose ps:\n' >&2
	docker compose -f compose.yaml ps >&2 || true
	exit 1
fi
printf 'all %d expected services running\n' "${#EXPECTED_SERVICES[@]}"

for i in "${!VERIFY[@]}"; do
	run_command "verify $((i + 1))" "${VERIFY[$i]}"
done

# Step 7 (demo-client) writes artifacts under output/. Assert at least
# EXPECTED_DEMO_ARTIFACTS files are present.
artifact_count=0
if [[ -d "$LAB_DIR/output" ]]; then
	artifact_count="$(find "$LAB_DIR/output" -mindepth 1 -type f | wc -l | tr -d ' ')"
fi
if ((artifact_count < EXPECTED_DEMO_ARTIFACTS)); then
	printf 'expected at least %d artifacts under %s/output/, found %d\n' \
		"$EXPECTED_DEMO_ARTIFACTS" "$LAB_DIR" "$artifact_count" >&2
	exit 1
fi
printf '\ndemo-client artifacts present under %s/output/ (%d files)\n' \
	"$LAB_DIR" "$artifact_count"
