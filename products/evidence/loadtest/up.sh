#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
product_dir=$(cd -- "$loadtest_dir/.." && pwd -P)
repository_root=$(cd -- "$product_dir/../.." && pwd -P)
support="$loadtest_dir/support/loadenv.py"
run_dir="$loadtest_dir/.run"
tracked="$loadtest_dir/project"
canonical_project="$product_dir/examples/standalone"

usage() {
  printf '%s\n' 'usage: products/evidence/loadtest/up.sh [--debug]' >&2
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
# `rstack dev` runs at most 256 test people, and each load client is one person.
load_clients="${LOAD_CLIENTS:-128}"
if [[ ! "$load_clients" =~ ^[0-9]+$ ]] || ((load_clients < 1 || load_clients > 256)); then
  printf '%s\n' 'LOAD_CLIENTS must be an integer between 1 and 256.' >&2
  exit 2
fi
required_commands=(cargo python3)
# The launcher proves it owns the source mock by its working directory, which
# only Linux exposes under /proc; elsewhere lsof reads it.
if [[ "$(uname -s)" != Linux ]]; then required_commands+=(lsof); fi
for command in "${required_commands[@]}"; do
  command -v "$command" >/dev/null 2>&1 || {
    printf '%s\n' "$command is required for the Evidence load-test environment." >&2
    exit 2
  }
done
if [[ -L "$run_dir" || -e "$run_dir" ]]; then
  printf '%s\n' "load-test state path already exists: $run_dir. Preserve it, or move it aside after running down.sh." >&2
  exit 2
fi

umask 077
mkdir -m 700 "$run_dir"
printf '%s\n' 'registry-stack-evidence-loadtest-v1' >"$run_dir/.launcher-owned"

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0

# shellcheck source-path=SCRIPTDIR source=../../../scripts/cargo-runtime-library-path.sh
. "$repository_root/scripts/cargo-runtime-library-path.sh"
cargo_profile_arguments=()
if [[ "$build_profile" == release ]]; then cargo_profile_arguments=(--release); fi
printf '%s\n' "== Building Evidence, evidencectl and rstack ($build_profile profile)"
registry_cargo_build "$repository_root" --manifest-path "$repository_root/Cargo.toml" --locked \
  "${cargo_profile_arguments[@]}" \
  -p registry-evidence -p registry-evidencectl -p registry-rstack --bins >/dev/null
rstack="$repository_root/target/$build_profile/rstack"
evidencectl="$repository_root/target/$build_profile/evidencectl"
# A source build resolves the sibling tools through these overrides, on every
# rstack dev call.
export RSTACK_EVIDENCE_BIN="$repository_root/target/$build_profile/evidence"
export RSTACK_EVIDENCECTL_BIN="$evidencectl"
export RSTACK_DEV_STATE_DIR="$run_dir/state"
rstack_dev() {
  "$rstack" --install-root "$repository_root/target/$build_profile" --format json dev "$@"
}
project="$run_dir/project"
run_id=""
mock_pid=""

stop_owned_mock() {
  if [[ -n "$mock_pid" ]]; then
    kill "$mock_pid" 2>/dev/null || true
    wait "$mock_pid" 2>/dev/null || true
    mock_pid=""
  fi
}

cleanup_failed_start() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    if [[ -n "$run_id" ]]; then
      printf '%s\n' 'Load-test startup failed; stopping only the run this script started.' >&2
      rstack_dev stop "$run_id" >/dev/null 2>&1 ||
        printf '%s\n' "Automatic cleanup failed; run: rstack dev stop $run_id" >&2
    fi
    if [[ -n "$mock_pid" ]]; then
      printf '%s\n' 'Stopping the source mock this launcher started.' >&2
      stop_owned_mock
    fi
  fi
  exit "$status"
}
trap cleanup_failed_start EXIT

mock_port=$(python3 "$support" port)

printf '%s\n' '== Preparing the synthetic adult-status project'
python3 "$support" openapi --template "$tracked/source.openapi.yaml" --port "$mock_port" --out "$run_dir/source.openapi.yaml"
python3 "$support" local-project \
  --tracked "$canonical_project" \
  --project "$project" \
  --pool "$run_dir/pool" \
  --source-openapi "$run_dir/source.openapi.yaml" \
  --mock-port "$mock_port" \
  --clients "$load_clients"
{
  "$evidencectl" keygen signing \
    --output-dir "$project/.generated/secrets"
  "$evidencectl" keygen secret \
    --output "$project/.generated/secrets/audit-hmac-key"
  "$evidencectl" keygen secret \
    --output "$project/.generated/secrets/subject-binding-hmac-key"
  "$evidencectl" keygen token \
    --output "$project/.generated/secrets/synthetic-source-token"
} >"$run_dir/keygen.log"
"$evidencectl" --format json check "$project" \
  --target "$project/local-target.yaml" >"$run_dir/check-report.json"
"$evidencectl" source mock check "$project" >"$run_dir/mock-check.log"

# Each load client is a distinct principal, so the per-principal limit of the
# local target applies to each one separately. The clients are the people of
# the generated run plan, fixed for the life of the run.
printf '%s\n' "== Starting the synthetic source mock on 127.0.0.1:$mock_port"
# The materialized plan path is project-relative and resolved against the
# working directory, so the mock runs inside the project. The subshell ignores
# SIGHUP and execs the mock, so the recorded PID is the mock itself. It avoids
# nohup: macOS strips DYLD_* from protected system binaries such as
# /usr/bin/nohup, and evidencectl needs the recorded runtime library path.
(
  trap '' HUP
  cd -- "$project"
  exec "$evidencectl" source mock serve --config mocks/source.yaml \
    --http-addr "127.0.0.1:$mock_port" </dev/null >"$run_dir/mock.log" 2>&1
) &
mock_pid=$!
printf '%s\n' "$mock_pid" >"$run_dir/mock.pid"
for _ in $(seq 1 60); do
  if [[ "$(<"$run_dir/mock.log")" == *'Source mock ready:'* ]]; then break; fi
  if ! kill -0 "$mock_pid" 2>/dev/null; then
    printf '%s\n' "The source mock exited during startup; see $run_dir/mock.log." >&2
    mock_pid=""
    exit 1
  fi
  sleep 0.5
done
if [[ "$(<"$run_dir/mock.log")" != *'Source mock ready:'* ]]; then
  printf '%s\n' "The source mock did not report ready within 30 seconds; see $run_dir/mock.log." >&2
  exit 1
fi

printf '%s\n' '== Starting the Evidence development run'
# A failed run keeps its logs, so a start that exits non-zero is still stopped
# once its run id is known.
rstack_dev start "$project" >"$run_dir/dev-report.json" || {
  run_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("run_id",""))' "$run_dir/dev-report.json" 2>/dev/null || true)
  exit 1
}
run_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$run_dir/dev-report.json")
python3 "$support" environment \
  --root "$run_dir" \
  --run-report "$run_dir/dev-report.json" \
  --rstack "$rstack" \
  --evidencectl "$evidencectl" \
  --build-profile "$build_profile" \
  --runtime-library-path "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH-}" \
  --mock-pid "$mock_pid" \
  --mock-port "$mock_port" \
  --clients "$load_clients"
evidence_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["products"]["evidence"])' "$run_dir/dev-report.json")

printf '\n%s\n' 'Evidence load-test environment is ready.'
printf '  Evidence:               %s\n' "$evidence_url"
printf '  Identity provider:      the rstack dev run issuer (run %s)\n' "$run_id"
printf '  Source mock:            evidencectl source mock on 127.0.0.1:%s (pid %s)\n' "$mock_port" "$mock_pid"
printf '  Evidence build profile: %s\n' "$build_profile"
printf '  Load clients:           %s (each limited to 60 requests per minute)\n' "$load_clients"
printf '  Environment:            %s\n' "$run_dir/env.json"
printf '  Then run:               products/evidence/loadtest/run.sh --profile smoke\n'
printf '  Tear down with:         products/evidence/loadtest/down.sh\n'
trap - EXIT
