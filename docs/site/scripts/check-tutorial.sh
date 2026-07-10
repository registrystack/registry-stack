#!/usr/bin/env bash
#
# check-tutorial.sh
#
# Verify that src/content/docs/tutorials/first-run-with-solmara-lab.mdx still
# matches reality by extracting its shell commands from the "## Steps" and
# "## Verify" sections and executing them, in order, against a Solmara Lab
# checkout.
#
# Also applies the cheap drift pre-gate to the registryctl tutorials
# (publish-spreadsheet, verify-claim-registry-api) by extracting every `sh`
# fence and asserting the command-line count. The dedicated source-under-test
# runner in check-registryctl-tutorials.sh executes those commands in CI; this
# count assertion fails before that more expensive container build starts.
#
# Usage:
#   scripts/check-tutorial.sh              extract + execute (needs Docker)
#   scripts/check-tutorial.sh --dry-run    extract + print only (no Docker)
#
# CI policy:
#   npm run check calls check:tutorial:dry-run, which guarantees extraction and
#   drift detection only. check:tutorial executes the Solmara tutorial manually.
#   The registryctl-tutorials CI job executes the registryctl tutorials through
#   check-registryctl-tutorials.sh after this cheaper command-count pre-gate.
#
# Configuration:
#   SOLMARA_LAB_PATH   path to an existing Solmara Lab checkout.
#                      Default: clone https://github.com/registrystack/solmara-lab
#                      at SOLMARA_LAB_REF into a temporary directory.
#                      REGISTRY_LAB_PATH is accepted as a deprecated alias.
#   SOLMARA_LAB_REF    commit to clone when SOLMARA_LAB_PATH is unset.
#                      This pins the check's own reproducibility; the
#                      tutorial itself tells readers to clone `main`.
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
TUTORIAL="$REPO_ROOT/src/content/docs/tutorials/first-run-with-solmara-lab.mdx"
EXPECTED_STEP_COUNT=3
EXPECTED_VERIFY_COUNT=4
EXPECTED_DEMO_ARTIFACTS=3
EXPECTED_SERVICES=(
	cra-civil-relay
	nia-population-relay
	sro-social-relay
	programme-mis-relay
	sipf-pensions-relay
	nagdi-agriculture-relay
	child-benefit-notary
	pension-notary
	nagdi-notary
	citizen-notary
	static-metadata
	portal
	home
	scenario-runner
	postgres
	redis
)

DRY_RUN=0
for arg in "$@"; do
	case "$arg" in
	--dry-run) DRY_RUN=1 ;;
	-h | --help)
		sed -n '3,37p' "$0"
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
	"publish-spreadsheet-secured-registry-api:39"
	"verify-claim-registry-api:71"
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
	printf 'dry-run: extraction and drift checks passed; Solmara execution skipped\n'
	exit 0
fi

SOLMARA_LAB_REF="${SOLMARA_LAB_REF:-3698ea8690b3a170cb72fd1a27780d85b91b1583}"
# REGISTRY_LAB_PATH is a deprecated alias kept for callers that have not
# migrated their environment yet; SOLMARA_LAB_PATH takes precedence.
SOLMARA_LAB_PATH="${SOLMARA_LAB_PATH:-${REGISTRY_LAB_PATH:-}}"

CLONE_DIR=""
if [[ -n "$SOLMARA_LAB_PATH" ]]; then
	if [[ ! -d "$SOLMARA_LAB_PATH" ]]; then
		printf 'solmara-lab checkout not found at: %s\n' "$SOLMARA_LAB_PATH" >&2
		exit 1
	fi
	LAB_DIR="$(cd "$SOLMARA_LAB_PATH" && pwd)"
else
	CLONE_DIR="$(mktemp -d)"
	printf 'SOLMARA_LAB_PATH not set; cloning solmara-lab@%s into %s\n' \
		"$SOLMARA_LAB_REF" "$CLONE_DIR"
	git clone --quiet https://github.com/registrystack/solmara-lab "$CLONE_DIR"
	git -C "$CLONE_DIR" checkout --quiet "$SOLMARA_LAB_REF"
	LAB_DIR="$CLONE_DIR"
	# The lab derives a per-checkout Compose project name, but pin one anyway
	# so a temporary clone can never join another checkout's project.
	COMPOSE_PROJECT_NAME="solmara-tutorial-check-$$"
	export COMPOSE_PROJECT_NAME
	# The tutorial's "Get the repository" section requires just setup before
	# the Steps; a fresh clone must exercise that documented path too.
	printf 'running just setup in the fresh clone\n'
	(cd "$CLONE_DIR" && just setup)
fi

for tool in just docker uv pnpm python3 openssl git; do
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
	# Clone mode owns its stack outright, so remove the volumes too; for a
	# caller-supplied checkout, stop containers but never touch its volumes.
	if [[ -n "$CLONE_DIR" ]]; then
		printf '\n--- cleanup: just reset ---\n' | tee -a "$LOG_FILE"
		(cd "$LAB_DIR" && just reset) >>"$LOG_FILE" 2>&1 || true
	else
		printf '\n--- cleanup: just down ---\n' | tee -a "$LOG_FILE"
		(cd "$LAB_DIR" && just down) >>"$LOG_FILE" 2>&1 || true
	fi
	if [[ -n "$CLONE_DIR" ]]; then
		rm -rf "$CLONE_DIR"
	fi
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

# After all Steps, the topology should be up. Assert every long-running
# service (everything except the one-shot volume-permissions init job) is in
# `running` state.
printf '\n--- assert services running ---\n' | tee -a "$LOG_FILE"
running_services="$(docker compose --env-file versions.env --env-file .env -f compose.yaml ps --services --filter status=running)"
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
	docker compose --env-file versions.env --env-file .env -f compose.yaml ps >&2 || true
	exit 1
fi
printf 'all %d expected services running\n' "${#EXPECTED_SERVICES[@]}"

for i in "${!VERIFY[@]}"; do
	run_command "verify $((i + 1))" "${VERIFY[$i]}"
done

# Step 3 (just smoke) writes artifacts under output/smoke/. Assert at least
# EXPECTED_DEMO_ARTIFACTS files are present.
artifact_count=0
if [[ -d "$LAB_DIR/output/smoke" ]]; then
	artifact_count="$(find "$LAB_DIR/output/smoke" -mindepth 1 -type f | wc -l | tr -d ' ')"
fi
if ((artifact_count < EXPECTED_DEMO_ARTIFACTS)); then
	printf 'expected at least %d artifacts under %s/output/smoke/, found %d\n' \
		"$EXPECTED_DEMO_ARTIFACTS" "$LAB_DIR" "$artifact_count" >&2
	exit 1
fi
printf '\nsmoke artifacts present under %s/output/smoke/ (%d files)\n' \
	"$LAB_DIR" "$artifact_count"
