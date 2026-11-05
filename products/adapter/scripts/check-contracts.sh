#!/usr/bin/env bash
set -euo pipefail

: "${CARGO_TARGET_DIR:?Set CARGO_TARGET_DIR to an external worktree Cargo target.}"

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$repo_root"

# shellcheck source=products/adapter/scripts/contract-lane-cache.sh
source "$repo_root/products/adapter/scripts/contract-lane-cache.sh"
python3 -m unittest discover -s products/adapter/scripts -p 'test_contract_lane_cache.py'
python3 -m unittest discover -s products/adapter/scripts -p 'test_effective_contract_example.py'
node --test "$repo_root"/products/adapter/examples/govstack-wg-demo/test_*.mjs

# The dependency-direction gate runs first, before any cargo build: its
# unittest, then the check against the resolved graph and the engine
# module's imports. Both are cheap and a violation should not wait on a
# cold compile.
python3 -m unittest discover -s products/adapter/scripts -p 'test_dependency_direction.py'
python3 products/adapter/scripts/check_dependency_direction.py
python3 -m unittest discover -s products/adapter/scripts -p 'test_test_connector_native.py'

# The verification floor: format over the workspace, then clippy and tests
# over the adapter crates. Cargo runs in the caller's explicit worktree
# target, so an omitted target cannot fill the source volume before the
# example generator rejects it. PATH keeps cargo reachable when it is not on
# the caller's PATH.
PATH="$HOME/.cargo/bin:$PATH" cargo fmt --all --check
clear_completed_adapter_lane
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --locked -p registry-adapter -p registry-adapter-core -p registry-adapter-engine -p registry-adapter-job -p registry-adapterctl --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter -p registry-adapter-core -p registry-adapter-engine -p registry-adapter-job -p registry-adapterctl --no-fail-fast
# The BReg connector is default-off. Compile every connector target with its
# feature and execute its scripted suites here; the real-runtime scenarios
# remain isolated under test-connector-native.py because they provision BReg
# and PostgreSQL explicitly.
clear_completed_adapter_lane
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --locked -p registry-adapter-connectors --features breg --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-connectors --features breg --no-fail-fast
# The signed Coordinator event connector is its own default-off feature: its
# admission matrix, retry byte identity, and signature checks run here, not
# only behind the job host.
clear_completed_adapter_lane
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --locked -p registry-adapter-connectors --features coordinator-event --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-connectors --features coordinator-event --lib
# The live verifier's HTTPS policy is proven against a deterministic local
# private-CA server. Keep this feature build after the default suite so the
# default adapterctl binary used by the product checks remains the production
# build; the PostgreSQL gate builds its own feature binary serially later.
PATH="$HOME/.cargo/bin:$PATH" cargo test -p registry-adapterctl --locked --features tls-test --test verify
# The governed-ingestion job sources (CONCEPT 17): each default-off
# feature gate holds its own clippy and test lane, so a gate can never
# rot behind the default build. The first lane builds registry-adapter and
# registry-adapter-engine on their own: the combined run above links
# registry-adapterctl, which turns both gates on, so only this lane runs the
# suites that hold a build without them to its refusals.
clear_completed_adapter_lane
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --locked -p registry-adapter -p registry-adapter-engine --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter -p registry-adapter-engine
clear_completed_adapter_lane
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --locked -p registry-adapter -p registry-adapter-engine --features registry-adapter/job-file,registry-adapter-engine/job-file --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter -p registry-adapter-engine --features registry-adapter/job-file,registry-adapter-engine/job-file
clear_completed_adapter_lane
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --locked -p registry-adapter -p registry-adapter-engine --features registry-adapter/job-postgres,registry-adapter-engine/job-postgres --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter -p registry-adapter-engine --features registry-adapter/job-postgres,registry-adapter-engine/job-postgres
clear_completed_adapter_lane
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --locked -p registry-adapter -p registry-adapter-engine --features registry-adapter/job-file,registry-adapter/job-postgres,registry-adapter-engine/job-file,registry-adapter-engine/job-postgres --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter -p registry-adapter-engine --features registry-adapter/job-file,registry-adapter/job-postgres,registry-adapter-engine/job-file,registry-adapter-engine/job-postgres

# SFTP uses an in-process loopback SSH fixture here. Its real CLI and item-store
# acceptance runs in test-job-postgres.sh with a disposable PostgreSQL database.
clear_completed_adapter_lane
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --locked -p registry-adapter-engine -p registry-adapter-job --features registry-adapter-job/job-sftp --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-engine -p registry-adapter-job --features registry-adapter-job/job-sftp

# The broker host remains default-off. Keep its production feature graph and
# in-process seams here; broker transport and durable settlement run serially
# with the service fixtures in test-job-postgres.sh.
clear_completed_adapter_lane
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --locked -p registry-adapter-engine -p registry-adapter-job --features registry-adapter-job/job-rabbitmq --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-engine -p registry-adapter-job --features registry-adapter-job/job-rabbitmq
PATH="$HOME/.cargo/bin:$PATH" cargo check --locked -p registry-adapter-job --features job-sftp,job-rabbitmq

# Hook ingress is separate from facade admission and default-off. Exercise its
# real local HTTP boundary and trigger coalescing; the CLI/store acceptance is
# mandatory in test-job-postgres.sh.
clear_completed_adapter_lane
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --locked -p registry-adapter-job --features job-hook --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-job --features job-hook --lib

# Each job destination is a default-off host feature with its own clippy and
# unit-test lane; the PostgreSQL-backed destination suites run in
# test-job-postgres.sh.
clear_completed_adapter_lane
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --locked -p registry-adapter-job --features direct-breg --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-job --features direct-breg --lib
clear_completed_adapter_lane
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --locked -p registry-adapter-job --features signed-coordinator-event --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-job --features signed-coordinator-event --lib

# The generated schemas are held to their generator (CFG-SCHEMA-2), and the
# adapter formats are held to the configuration-format convention
# (CFG-SCHEMA-1) with the platform lint that CI also runs.
PATH="$HOME/.cargo/bin:$PATH" cargo run --locked -p registry-adapterctl -- schemas --check --output-dir products/adapter/schemas
products/adapter/scripts/generate-effective-contract-example.sh --check
uv run --no-project --with PyYAML==6.0.2 python products/platform/scripts/check-config-conventions.py

# The Camel port table (CONCEPT.md 8.10) is held to the code: every
# delivered row maps to named core tests and every accepted key has a row;
# later-increment rows report pending and never fail.
python3 products/adapter/scripts/check-port-table.py

# The example and corpus checks run the real adapterctl binary. It comes
# from, most explicit first:
#   1. the --bin-dir option,
#   2. the ADAPTERCTL_BIN environment variable, run exactly as named,
#   3. a build under the exported CARGO_TARGET_DIR,
# and the script refuses otherwise. A repo-local target/ directory is
# never used: a stale binary there once checked green against the wrong
# reader, which passed the corpus silently.
bin_dir=''
adapterctl_bin=''
previous=''
for argument in "$@"; do
  case "$argument" in
  --bin-dir=*) bin_dir="${argument#--bin-dir=}" ;;
  *)
    if [[ "$previous" == '--bin-dir' ]]; then
      bin_dir="$argument"
    fi
    ;;
  esac
  previous="$argument"
done

if [[ -n "$bin_dir" ]]; then
  adapterctl_bin="${bin_dir}/adapterctl"
elif [[ -n "${ADAPTERCTL_BIN:-}" ]]; then
  if [[ ! -x "${ADAPTERCTL_BIN}" ]]; then
    printf 'check-contracts: ADAPTERCTL_BIN names no executable: %s\n' "${ADAPTERCTL_BIN}" >&2
    printf 'Set ADAPTERCTL_BIN to the adapterctl binary, pass --bin-dir, or export CARGO_TARGET_DIR.\n' >&2
    exit 2
  fi
  # Run exactly the named binary: reducing it to its directory would
  # silently run a different adapterctl from the same directory. The
  # directory is kept only for the aws-lc-fips artifact lookup below.
  adapterctl_bin="${ADAPTERCTL_BIN}"
  bin_dir="$(cd "$(dirname "${ADAPTERCTL_BIN}")" && pwd -P)"
elif [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  command -v cargo >/dev/null 2>&1 || {
    printf 'check-contracts: CARGO_TARGET_DIR is set but cargo is not on PATH.\n' >&2
    exit 2
  }
  cargo build --locked -p registry-adapterctl --manifest-path "${repo_root}/Cargo.toml" --target-dir "${CARGO_TARGET_DIR}"
  bin_dir="${CARGO_TARGET_DIR}/debug"
  adapterctl_bin="${bin_dir}/adapterctl"
else
  printf 'check-contracts: no adapterctl binary found.\n' >&2
  printf 'Set ADAPTERCTL_BIN to the adapterctl binary, pass --bin-dir, or export CARGO_TARGET_DIR; the repository target/ directory is never used.\n' >&2
  exit 2
fi

if [[ ! -x "${adapterctl_bin}" ]]; then
  printf 'check-contracts: no adapterctl binary at %s.\n' "${adapterctl_bin}" >&2
  printf 'Set ADAPTERCTL_BIN to the adapterctl binary, pass --bin-dir, or export CARGO_TARGET_DIR.\n' >&2
  exit 2
fi

# A debug build that links aws-lc-fips-sys dynamically on macOS needs its
# library at each adapterctl launch. Keep the directory in the same
# non-DYLD carrier the conformance wrapper uses, and put it on the DYLD
# search for the direct child executions below.
if [[ -z "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}" ]]; then
  for artifacts in "${bin_dir}"/build/aws-lc-fips-sys-*/out/build/artifacts; do
    if [[ -d "$artifacts" ]]; then
      REGISTRY_CARGO_RUNTIME_LIBRARY_PATH="$(cd "$artifacts" && pwd -P)"
      export REGISTRY_CARGO_RUNTIME_LIBRARY_PATH
      break
    fi
  done
fi
if [[ -n "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}" ]]; then
  DYLD_FALLBACK_LIBRARY_PATH="${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH}${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
  export DYLD_FALLBACK_LIBRARY_PATH
fi

# The example is held to the exact command the configuration-format
# conformance registers for the adapter formats (products/platform/
# config-formats.yaml, `check:`): the project, its pinned profile and
# pack, and the shared fixture set.
fixture_flags=()
for fixture in products/adapter/fixtures/dhis2-tracker/*.yaml; do
  fixture_flags+=(--fixtures "$fixture")
done
"$adapterctl_bin" check products/adapter/examples/dhis2-tracker/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml \
  "${fixture_flags[@]}" >/dev/null
printf 'Example check passed\n'

# The same contract executes offline through the real route engine and
# exact intercepted transcript. Simulated writes do not claim PostgreSQL
# durability; the database suite establishes that independently.
"$adapterctl_bin" fixtures replay products/adapter/examples/dhis2-tracker/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml \
  "${fixture_flags[@]}" >/dev/null
printf 'Example fixture replay passed\n'

# Built-in Consultation projects own only source bindings, transformations and
# schemas. Their standard protocol comes from Rust, so no --profile is supplied.
for example in dhis2-consultation opencrvs-consultation; do
  project_dir="products/adapter/examples/${example}"
  case "$example" in
  dhis2-consultation) pack="products/adapter/packs/dhis2-tracker/pack.yaml" ;;
  opencrvs-consultation) pack="products/adapter/packs/opencrvs-events/pack.yaml" ;;
  esac
  consultation_flags=()
  for fixture in "${project_dir}"/fixtures/*.yaml; do
    if [[ ! -f "$fixture" ]]; then
      printf 'Consultation example has no fixture: %s\n' "$example" >&2
      exit 2
    fi
    consultation_flags+=(--fixtures "$fixture")
  done
  "$adapterctl_bin" check "${project_dir}/project.yaml" --pack "$pack" "${consultation_flags[@]}" >/dev/null
  "$adapterctl_bin" compile --check "${project_dir}/project.yaml" --pack "$pack" >/dev/null
  "$adapterctl_bin" fixtures replay "${project_dir}/project.yaml" --pack "$pack" "${consultation_flags[@]}" >/dev/null
  printf 'Built-in Consultation check, compile and replay passed: %s\n' "$example"
done

# The unified BReg-backed GovStack example owns its domain schema and mappings.
# Native source mutation and recovery run in the PostgreSQL gate.
breg_govstack=products/adapter/examples/breg-govstack
"$adapterctl_bin" check "$breg_govstack/project.yaml" \
  --pack products/adapter/packs/breg-records/pack.yaml >/dev/null
"$adapterctl_bin" compile --check "$breg_govstack/project.yaml" \
  --pack products/adapter/packs/breg-records/pack.yaml >/dev/null
printf 'BReg GovStack example check and compile passed\n'

# The OpenCRVS birth example is held to the same two commands. Its fixtures
# are hand-derived from the reviewed Evidence reference and marked documented
# (each file says so): none is a captured exchange, so this proves the
# contract shape, not the live upstream.
ocrvs_flags=()
for fixture in products/adapter/fixtures/opencrvs-events/*.yaml; do
  ocrvs_flags+=(--fixtures "$fixture")
done
"$adapterctl_bin" check products/adapter/examples/opencrvs-events/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/packs/opencrvs-events/pack.yaml \
  "${ocrvs_flags[@]}" >/dev/null
printf 'OpenCRVS example check passed\n'
"$adapterctl_bin" fixtures replay products/adapter/examples/opencrvs-events/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/packs/opencrvs-events/pack.yaml \
  "${ocrvs_flags[@]}" >/dev/null
printf 'OpenCRVS example fixture replay passed\n'

# The facade recovery example is held to the three commands its README and
# the product README's "Try an example" give, runtime example included.
recovery=products/adapter/examples/facade-recovery
"$adapterctl_bin" check "$recovery/project.yaml" \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack "$recovery/pack.yaml" \
  --runtime "$recovery/runtime.example.yaml" >/dev/null
recovery_contract=$(mktemp)
"$adapterctl_bin" compile "$recovery/project.yaml" \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack "$recovery/pack.yaml" \
  --output "$recovery_contract" >/dev/null
rm -f "$recovery_contract"
"$adapterctl_bin" fixtures replay "$recovery/project.yaml" \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack "$recovery/pack.yaml" \
  --fixtures "$recovery/fixture.yaml" >/dev/null
printf 'Facade recovery example check, compile and replay passed\n'

# Each source-shape fixture holds the concrete contract its project compiles
# to (`generated/openapi.json` beside the project) and at least one fixture
# that the actual runtime interpreter replays offline. `compile --check` and
# `fixtures replay` refuse on drift or an unserved transcript, so the source
# shapes cannot rot behind reader, core, document, or route-engine changes. A
# source shape that carries no `profile.yaml` beside its project binds the
# maintained profile its project pins by id, under
# `products/adapter/profiles/<id>/`, the same profile its documented check
# command names; a project that pins no id, one with no maintained profile,
# or one with no discovered fixture refuses loudly rather than being skipped.
source_shapes=0
shape_fixtures=0
for project in products/adapter/fixtures/source-shapes/*/project.yaml; do
  directory="${project%/*}"
  if [[ -f "${directory}/profile.yaml" ]]; then
    profile="${directory}/profile.yaml"
  else
    profile_id="$(awk '/^profile:$/ { pinned = 1; next } pinned && /^  id:/ { sub(/^  id:[[:space:]]*/, ""); print; exit } pinned && /^[^ ]/ { exit }' "${project}")"
    if [[ -z "${profile_id}" ]]; then
      printf 'check-contracts: %s pins no profile id.\n' "${project}" >&2
      exit 2
    fi
    profile="products/adapter/profiles/${profile_id}/profile.yaml"
  fi
  fixture_paths=("${directory}"/fixtures/*.yaml)
  if [[ ! -f "${fixture_paths[0]}" ]]; then
    printf 'check-contracts: %s has no fixture under %s/fixtures/.\n' "${project}" "${directory}" >&2
    exit 2
  fi
  shape_fixture_flags=()
  for fixture in "${fixture_paths[@]}"; do
    shape_fixture_flags+=(--fixtures "${fixture}")
    shape_fixtures=$((shape_fixtures + 1))
  done
  "$adapterctl_bin" compile --check "$project" --profile "$profile" >/dev/null
  "$adapterctl_bin" fixtures replay "$project" \
    --profile "$profile" \
    "${shape_fixture_flags[@]}" >/dev/null
  source_shapes=$((source_shapes + 1))
done
printf 'Source-shape contracts and fixture replays hold (%d source shapes, %d fixtures)\n' \
  "$source_shapes" "$shape_fixtures"

# The governed-ingestion example jobs compile offline over the same
# compile the page run uses, through the exact command the
# configuration-format conformance registers for the job format. The
# example credentials are synthetic stand-ins for the check, and the
# profile and project sit beside the job, the bundle layout the job
# format's example carries.
export KOBO_USERNAME=check-contracts KOBO_PASSWORD=check-contracts
export ODK_EMAIL=check-contracts ODK_PASSWORD=check-contracts
"$adapterctl_bin" job check products/adapter/packs/kobotoolbox/pack.yaml \
  products/adapter/examples/kobotoolbox-job/job.yaml \
  --runtime products/adapter/examples/kobotoolbox-job/job-runtime.example.yaml \
  --profile products/adapter/examples/kobotoolbox-job/profile.yaml \
  --project products/adapter/examples/kobotoolbox-job/project.yaml >/dev/null
# The host validates exact hook binding coverage and resolves the hook
# credentials the way a loop start does, without opening the listener. The
# gate stands in synthetic owner-only secret files under a throwaway
# file-provider root, beside a copy of the example runtime that names it.
hook_check_root=$(mktemp -d "${CARGO_TARGET_DIR}/check-contracts-hook.XXXXXX")
cleanup_hook_check() {
  rm -f -- "$hook_check_root/secrets/kobo-hook-username" \
    "$hook_check_root/secrets/kobo-hook-password" "$hook_check_root/runtime.yaml"
  rmdir -- "$hook_check_root/secrets" "$hook_check_root"
}
trap cleanup_hook_check EXIT
mkdir -m 0700 "$hook_check_root/secrets"
for hook_secret in kobo-hook-username kobo-hook-password; do
  (umask 077 && printf 'check-contracts' >"$hook_check_root/secrets/$hook_secret")
done
sed "s|root: /run/secrets/adapter-job|root: $hook_check_root/secrets|" \
  products/adapter/examples/kobotoolbox-job/job-runtime.hook.example.yaml \
  >"$hook_check_root/runtime.yaml"
if ! grep -q "root: $hook_check_root/secrets" "$hook_check_root/runtime.yaml"; then
  printf 'The hook example runtime no longer names /run/secrets/adapter-job; update this gate.\n' >&2
  exit 1
fi
PATH="$HOME/.cargo/bin:$PATH" cargo run --locked -p registry-adapter-job \
  --features job-hook,direct-breg --bin adapter-job -- check \
  products/adapter/examples/kobotoolbox-job/job.hook.yaml \
  --pack products/adapter/packs/kobotoolbox/pack.yaml \
  --runtime "$hook_check_root/runtime.yaml" \
  --profile products/adapter/examples/kobotoolbox-job/profile.yaml \
  --project products/adapter/examples/kobotoolbox-job/project.yaml >/dev/null
# The signed Coordinator event example needs the destination feature in the host
# that reads it.
PATH="$HOME/.cargo/bin:$PATH" cargo run --locked -p registry-adapter-job \
  --features signed-coordinator-event --bin adapter-job -- check \
  products/adapter/examples/kobotoolbox-job/job.coordinator.yaml \
  --pack products/adapter/packs/kobotoolbox/pack.yaml \
  --runtime products/adapter/examples/kobotoolbox-job/job-runtime.coordinator.example.yaml \
  --profile products/adapter/examples/kobotoolbox-job/profile.yaml \
  --project products/adapter/examples/kobotoolbox-job/project.yaml >/dev/null
"$adapterctl_bin" job check products/adapter/packs/odk-central/pack.yaml \
  products/adapter/examples/odk-central-job/job.yaml \
  --runtime products/adapter/examples/odk-central-job/job-runtime.example.yaml \
  --profile products/adapter/examples/odk-central-job/profile.yaml \
  --project products/adapter/examples/odk-central-job/project.yaml >/dev/null
# The PostgreSQL view example compiles offline with the job-postgres source and
# the BReg destination. Its credentials are references the check does not
# resolve, and it opens no database connection.
"$adapterctl_bin" job check products/adapter/examples/postgres-source/pack.yaml \
  products/adapter/examples/postgres-source/job.yaml \
  --runtime products/adapter/examples/postgres-source/job-runtime.example.yaml \
  --profile products/adapter/examples/postgres-source/profile.yaml \
  --project products/adapter/examples/postgres-source/project.yaml >/dev/null
printf 'Job example checks passed\n'

# The bad-authoring corpus: every discovered bad/ member refuses with its
# own code (plus, transitionally, a co-fired partner code that is another
# member's expectation; see the runner and the corpus README), and the
# base/ control passes with zero findings. The runner self-tests its
# decision logic before it spends an adapterctl run.
python3 products/adapter/scripts/check-corpus.py "$adapterctl_bin"

printf 'Adapter product contracts passed\n'
