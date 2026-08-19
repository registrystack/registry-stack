#!/usr/bin/env bash
#
# check-tutorial.sh
#
# Historical checker for the unpublished Solmara Lab tutorial. The tutorial
# documents the former Evidence Gateway-over-Relay topology. Keep the executable
# path for archaeology against its pinned lab source.
#
# Usage:
#   scripts/check-tutorial.sh              extract + execute (needs Docker)
#   scripts/check-tutorial.sh --dry-run    extract + print only (no Docker)
#
# CI policy:
#   npm run check runs only this checker's dry-run extraction and drift checks.
#   check:tutorial executes the archived Solmara workflow manually when asked.
#
# Configuration:
#   SOLMARA_LAB_PATH   path to an existing Solmara Lab checkout.
#                      Default: clone https://github.com/registrystack/solmara-lab
#                      at SOLMARA_LAB_REF into a temporary directory.
#   SOLMARA_LAB_REF    commit to clone when SOLMARA_LAB_PATH is unset.
#                      This pins the check's own reproducibility; the
#                      tutorial itself tells readers to clone `main`.
#   REGISTRY_STACK_SOURCE_DIR
#                      clean Registry Stack checkout the lab builds the
#                      Evidence and Mint images from, a documented tutorial
#                      prerequisite until a release publishes them.
#                      Default: this repository.
#
# Exit codes:
#   0   success
#   1   tutorial drift, missing prerequisite, or step failure
#   2   bad CLI argument
#
# Drift detection:
#   - the script reports the commands it extracted from each section rather
#     than pinning how many there are, so adding or removing a documented
#     command needs no change here. It fails only when a section yields none,
#     which means the heading it reads was renamed and the runner would
#     otherwise pass by doing nothing
#   - after compose comes up, the script asserts every entry in
#     EXPECTED_SERVICES is in `running` state and that EXPECTED_RUNNING_TOTAL
#     services are running in all; bump both when you intentionally add or
#     remove a long-running service
#   - the script runs whatever commands appear in the tutorial verbatim, so a
#     command change in the docs causes the runner to exercise the new command
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUTORIAL="${SOLMARA_TUTORIAL_PAGE:-$REPO_ROOT/src/content/docs/tutorials/first-run-with-solmara-lab.mdx}"
EXPECTED_DEMO_ARTIFACTS=3
# Every service the tutorial names or gives a host port. The topology holds far
# more; EXPECTED_RUNNING_TOTAL below covers the rest as a count, because the
# page states one.
EXPECTED_SERVICES=(
	cra-civil-relay
	nia-population-relay
	sro-social-relay
	programme-mis-relay
	sipf-pensions-relay
	nagdi-agriculture-relay
	child-benefit-federator
	static-metadata
	portal
	home
	scenario-runner
	postgres
	evidence-gateway
	mint
	cra-records-relay
	cra-records-workload-agent
	evidence
)
EXPECTED_RUNNING_TOTAL=41

DRY_RUN=0
for arg in "$@"; do
	case "$arg" in
	--dry-run) DRY_RUN=1 ;;
	-h | --help)
		sed -n '3,45p' "$0"
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

# The counts are reported below, not pinned: a writer may add or remove a
# documented command without touching this file, and the runner simply runs
# what the page now says. Empty is the one count that is drift, because it
# means the heading this reads was renamed and every later step would pass by
# running nothing at all.
require_commands() {
	local section="$1" extracted="$2"
	if ((extracted == 0)); then
		printf 'tutorial drift: no shell commands under its "%s" heading\n' "$section" >&2
		printf 'The section was renamed or removed, so this runner would execute nothing and still pass.\n' >&2
		printf 'Point %s at the heading the page carries now.\n' "${BASH_SOURCE[0]}" >&2
		exit 1
	fi
}

require_commands Steps "${#STEPS[@]}"
require_commands Verify "${#VERIFY[@]}"

printf 'extracted %d Steps commands from tutorial:\n' "${#STEPS[@]}"
for i in "${!STEPS[@]}"; do
	printf '  step %d: %s\n' "$((i + 1))" "${STEPS[$i]}"
done
printf 'extracted %d Verify commands from tutorial:\n' "${#VERIFY[@]}"
for i in "${!VERIFY[@]}"; do
	printf '  verify %d: %s\n' "$((i + 1))" "${VERIFY[$i]}"
done

if ((DRY_RUN)); then
	printf 'dry-run: extraction and drift checks passed; Solmara execution skipped\n'
	exit 0
fi

SOLMARA_LAB_REF="${SOLMARA_LAB_REF:-3698ea8690b3a170cb72fd1a27780d85b91b1583}"
SOLMARA_LAB_PATH="${SOLMARA_LAB_PATH:-}"

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

# The tutorial's Steps run the Evidence overlay. A lab checkout that predates it
# would fail several commands in without saying why.
if [[ ! -f "$LAB_DIR/compose.evidence.yaml" ]]; then
	printf 'solmara-lab checkout has no compose.evidence.yaml: %s\n' "$LAB_DIR" >&2
	printf 'the tutorial runs the Evidence overlay; advance SOLMARA_LAB_REF in %s\n' \
		"${BASH_SOURCE[0]}" >&2
	exit 1
fi

# No Registry Stack release ships the Evidence or Mint binaries, so the lab
# builds both images from a checkout the operator names, and refuses a dirty
# one. This is a documented tutorial prerequisite until a release publishes
# them; default it to the repository this script lives in.
REGISTRY_STACK_SOURCE_DIR="${REGISTRY_STACK_SOURCE_DIR:-$(cd "$REPO_ROOT/../.." && pwd)}"
export REGISTRY_STACK_SOURCE_DIR
if [[ -n "$(git -C "$REGISTRY_STACK_SOURCE_DIR" status --porcelain 2>&1)" ]]; then
	printf 'REGISTRY_STACK_SOURCE_DIR is not a clean git checkout: %s\n' \
		"$REGISTRY_STACK_SOURCE_DIR" >&2
	printf 'point it at a clean checkout or git worktree carrying crates/registry-evidence\n' >&2
	exit 1
fi

# Step 1 rotates every local credential, including the Postgres password, so a
# data volume left by an earlier run no longer matches it and the stack cannot
# bootstrap. Clone mode always starts empty. A caller-supplied checkout has to be
# reset by its owner, because cleanup below never deletes their volumes.
if [[ -z "$CLONE_DIR" ]]; then
	lab_project="$(cd "$LAB_DIR" && python3 scripts/compose_project_name.py)"
	if docker volume ls --format '{{.Name}}' | grep -q "^${lab_project}_"; then
		printf 'solmara-lab checkout still holds volumes from an earlier run: %s\n' \
			"$lab_project" >&2
		printf 'step 1 rotates the Postgres password; run just reset-evidence in %s first\n' \
			"$LAB_DIR" >&2
		exit 1
	fi
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
		printf '\n--- cleanup: just reset-evidence ---\n' | tee -a "$LOG_FILE"
		(cd "$LAB_DIR" && just reset-evidence) >>"$LOG_FILE" 2>&1 || true
	else
		printf '\n--- cleanup: just down-evidence ---\n' | tee -a "$LOG_FILE"
		(cd "$LAB_DIR" && just down-evidence) >>"$LOG_FILE" 2>&1 || true
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

# After all Steps, the topology should be up. Assert every service the tutorial
# names is in `running` state, and that the total matches the count the page
# states (everything except the one-shot bootstrap and secret-root jobs).
printf '\n--- assert services running ---\n' | tee -a "$LOG_FILE"
running_services="$(docker compose --env-file versions.env --env-file .env -f compose.yaml -f compose.evidence.yaml ps --services --filter status=running)"
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
	docker compose --env-file versions.env --env-file .env -f compose.yaml -f compose.evidence.yaml ps >&2 || true
	exit 1
fi
running_total="$(grep -c . <<<"$running_services")"
if ((running_total != EXPECTED_RUNNING_TOTAL)); then
	printf 'tutorial drift: %d services running, the tutorial states %d\n' \
		"$running_total" "$EXPECTED_RUNNING_TOTAL" >&2
	printf 'if this change was intentional, update EXPECTED_RUNNING_TOTAL in %s and the count on the page\n' \
		"${BASH_SOURCE[0]}" >&2
	exit 1
fi
printf 'all %d named services running, %d in total\n' \
	"${#EXPECTED_SERVICES[@]}" "$running_total"

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
