#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
product_dir=$(cd -- "$loadtest_dir/.." && pwd)
repository_root=$(cd -- "$product_dir/../.." && pwd)
support="$loadtest_dir/support/loadenv.py"
run_dir="$loadtest_dir/.run"
example="$product_dir/examples/standalone-decision"

usage() {
  printf '%s\n' 'usage: products/casework/loadtest/up.sh [--debug]' >&2
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
    printf '%s\n' "$command is required for the Registry Casework load-test environment." >&2
    exit 2
  }
done
if [[ -L "$run_dir" || -e "$run_dir" ]]; then
  printf '%s\n' "load-test state path already exists: $run_dir. Preserve it, or move it aside after stopping its owned dev run." >&2
  exit 2
fi

umask 077
mkdir -m 700 "$run_dir" "$run_dir/state"
printf '%s\n' 'registry-stack-casework-loadtest-v2' >"$run_dir/.launcher-owned"

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0

# shellcheck source-path=SCRIPTDIR source=../../../scripts/cargo-runtime-library-path.sh
. "$repository_root/scripts/cargo-runtime-library-path.sh"
cargo_profile_arguments=()
if [[ "$build_profile" == release ]]; then cargo_profile_arguments=(--release); fi
printf '%s\n' "== Building Registry Casework, caseworkctl, and rstack ($build_profile profile)"
registry_cargo_build "$repository_root" --manifest-path "$repository_root/Cargo.toml" --locked \
  "${cargo_profile_arguments[@]}" \
  -p registry-casework --bin casework \
  -p registry-caseworkctl --bin caseworkctl \
  -p registry-rstack --bin rstack >/dev/null
export RSTACK_CASEWORK_BIN="$repository_root/target/$build_profile/casework"
export RSTACK_CASEWORKCTL_BIN="$repository_root/target/$build_profile/caseworkctl"
rstack="$repository_root/target/$build_profile/rstack"
# rstack dev keeps each run's private state, including its credentials, here.
export RSTACK_DEV_STATE_DIR="$run_dir/state"

run_id=""
cleanup_failed_start() {
  local status=$?
  if [[ "$status" -ne 0 && -n "$run_id" ]]; then
    printf '%s\n' 'Load-test startup failed; stopping only the run this launcher started.' >&2
    "$rstack" dev stop "$run_id" >/dev/null 2>&1 ||
      printf '%s\n' "Automatic owned-run cleanup failed; run: RSTACK_DEV_STATE_DIR=$run_dir/state $rstack dev stop $run_id" >&2
  fi
  exit "$status"
}
trap cleanup_failed_start EXIT

printf '%s\n' '== Preparing the local standalone-decision project'
python3 "$support" local-project --example "$example" --project "$run_dir/project"
"$rstack" --format json dev check "$run_dir/project" >"$run_dir/check-report.json"

printf '%s\n' '== Starting the rstack dev run'
"$rstack" --format json dev start --ttl 8h "$run_dir/project" >"$run_dir/start-report.json"
run_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$run_dir/start-report.json")
python3 "$support" environment \
  --root "$run_dir" \
  --start-report "$run_dir/start-report.json" \
  --rstack "$rstack" \
  --build-profile "$build_profile" \
  --runtime-library-path "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH-}"
casework_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["casework_url"])' "$run_dir/env.json")

printf '\n%s\n' 'Registry Casework load-test environment is ready.'
printf '  Registry Casework:     %s\n' "$casework_url"
printf '  Token signing:         throwaway local key held by rstack dev run %s\n' "$run_id"
printf '  Database:              managed PostgreSQL container owned by that run\n'
printf '  Casework build:        %s\n' "$build_profile"
printf '  Casework pool max:     32 (fixed in the runtime)\n'
printf '  Environment:           %s\n' "$run_dir/env.json"
printf '  Seed next:             products/casework/loadtest/seed.py --count 2000\n'
printf '  Then run:              products/casework/loadtest/run.sh --profile smoke\n'
printf '  Tear down with:        products/casework/loadtest/down.sh\n'
trap - EXIT
