#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
product_dir=$(cd -- "$loadtest_dir/.." && pwd)
repository_root=$(cd -- "$product_dir/../.." && pwd)
support="$loadtest_dir/support/loadenv.py"
run_dir="$loadtest_dir/.run"
fixture="$product_dir/acceptance/business-establishments"

usage() {
  printf '%s\n' 'usage: products/breg/loadtest/up.sh [--debug]' >&2
  exit 2
}

# Capacity figures from an unoptimized build are not representative, so the
# runtime is built with the release profile unless --debug asks for a faster
# build to iterate on the harness itself.
build_profile=release
case "$#:${1-}" in
  0:) ;;
  1:--debug) build_profile=debug ;;
  *) usage ;;
esac
for command in cargo docker python3; do
  command -v "$command" >/dev/null 2>&1 || {
    printf '%s\n' "$command is required for the Base Registry Engine load-test environment." >&2
    exit 2
  }
done
umask 077
if [[ -L "$run_dir" || -e "$run_dir" ]]; then
  if [[ -L "$run_dir" || ! -d "$run_dir" || -L "$run_dir/.launcher-owned" || ! -f "$run_dir/.launcher-owned" ]] ||
    [[ "$(<"$run_dir/.launcher-owned")" != registry-stack-breg-loadtest-v2 ]] ||
    ! python3 -c 'import json, sys; report = json.load(open(sys.argv[1])); sys.exit(not (report.get("status") == "stopped" and report.get("cleaned") is True))' "$run_dir/stop-report.json" 2>/dev/null; then
    printf '%s\n' "load-test state path already exists: $run_dir. Stop its owned dev run with down.sh before starting again." >&2
    exit 2
  fi
  archive=$(mktemp -d "$loadtest_dir/.run-archive.XXXXXXXX")
  mv -- "$run_dir" "$archive/"
  printf 'Previous load-test evidence: %s/.run\n' "$archive"
fi

mkdir -m 700 "$run_dir"
printf '%s\n' 'registry-stack-breg-loadtest-v2' >"$run_dir/.launcher-owned"

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0

# shellcheck source-path=SCRIPTDIR source=../../../scripts/cargo-runtime-library-path.sh
. "$repository_root/scripts/cargo-runtime-library-path.sh"
cargo_profile_arguments=()
if [[ "$build_profile" == release ]]; then cargo_profile_arguments=(--release); fi
printf '%s\n' "== Building Base Registry Engine and bregctl ($build_profile profile)"
registry_cargo_build "$repository_root" --manifest-path "$repository_root/Cargo.toml" --locked \
  "${cargo_profile_arguments[@]}" \
  -p registry-breg --features registry-breg/runtime \
  -p registry-bregctl --bins \
  -p registry-rstack >/dev/null
rstack="$repository_root/target/$build_profile/rstack"
# A source build resolves the sibling tools through these overrides, on every
# rstack dev call.
export RSTACK_BREG_BIN="$repository_root/target/$build_profile/breg"
export RSTACK_BREGCTL_BIN="$repository_root/target/$build_profile/bregctl"
export RSTACK_DEV_STATE_DIR="$run_dir/state"
unset RSTACK_DEV_DATABASE_URL RSTACK_DEV_DATABASE_CA
bregctl="$RSTACK_BREGCTL_BIN"
rstack_args=(--install-root "$repository_root/target/$build_profile" --format json)
rstack_dev() {
  "$rstack" "${rstack_args[@]}" dev "$@"
}
run_id=""

cleanup_failed_start() {
  local status=$?
  if [[ "$status" -ne 0 && -n "$run_id" ]]; then
    printf '%s\n' 'Load-test startup failed; stopping only the run this script started.' >&2
    if ! rstack_dev stop "$run_id" --clean >/dev/null; then
      printf 'Automatic cleanup failed. Run RSTACK_DEV_STATE_DIR=%q ' "$RSTACK_DEV_STATE_DIR" >&2
      printf '%q ' "$rstack" "${rstack_args[@]}" dev stop "$run_id" --clean >&2
      printf '\n' >&2
    fi
  fi
  exit "$status"
}
trap cleanup_failed_start EXIT

printf '%s\n' '== Preparing the local business-establishments project'
python3 "$support" local-project --fixture "$fixture" --project "$run_dir/project"
"$bregctl" --format json check "$run_dir/project" >"$run_dir/check-report.json"

printf '%s\n' '== Starting the BReg development run'
# A failed run keeps its logs, so a start that exits non-zero is still stopped
# once its run id is known.
rstack_dev start "$run_dir/project" >"$run_dir/dev-report.json" || {
  run_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("run_id",""))' "$run_dir/dev-report.json" 2>/dev/null || true)
  exit 1
}
run_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$run_dir/dev-report.json")
python3 "$support" environment \
  --root "$run_dir" \
  --dev-report "$run_dir/dev-report.json" \
  --rstack "$rstack" \
  --build-profile "$build_profile" \
  --runtime-library-path "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH-}"
breg_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["products"]["breg"])' "$run_dir/dev-report.json")

printf '\n%s\n' 'Base Registry Engine load-test environment is ready.'
printf '  Base Registry Engine:  %s\n' "$breg_url"
printf '  Identity provider:     the rstack dev run issuer\n'
printf '  Database:              managed PostgreSQL container of run %s\n' "$run_id"
printf '  BReg build profile:    %s\n' "$build_profile"
printf '  BReg pool max size:    4 (the rstack dev default)\n'
printf '  Environment:           %s\n' "$run_dir/env.json"
printf '  Seed next:             products/breg/loadtest/seed.py --count 100000\n'
printf '  Then run:              products/breg/loadtest/run.sh --profile steady\n'
printf '  Tear down with:        products/breg/loadtest/down.sh\n'
trap - EXIT
