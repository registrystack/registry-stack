#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
product_dir=$(cd -- "$loadtest_dir/.." && pwd -P)
repository_root=$(cd -- "$product_dir/../.." && pwd -P)
support="$loadtest_dir/support/loadenv.py"
run_dir="$loadtest_dir/.run"
tracked="$loadtest_dir/project"

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
load_clients="${LOAD_CLIENTS:-128}"
if [[ ! "$load_clients" =~ ^[0-9]+$ ]] || ((load_clients < 1 || load_clients > 256)); then
  printf '%s\n' 'LOAD_CLIENTS must be an integer between 1 and 256.' >&2
  exit 2
fi
required_commands=(cargo docker python3)
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
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

# shellcheck source-path=SCRIPTDIR source=../../../scripts/cargo-runtime-library-path.sh
. "$repository_root/scripts/cargo-runtime-library-path.sh"
cargo_profile_arguments=()
if [[ "$build_profile" == release ]]; then cargo_profile_arguments=(--release); fi
printf '%s\n' "== Building Evidence and evidencectl ($build_profile profile)"
registry_cargo_build "$repository_root" --manifest-path "$repository_root/Cargo.toml" --locked \
  "${cargo_profile_arguments[@]}" \
  -p registry-evidence -p registry-evidencectl --bins >/dev/null
evidence_bin="$repository_root/target/$build_profile/evidence"
evidencectl="$repository_root/target/$build_profile/evidencectl"
project="$run_dir/project"
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
    if [[ -f "$project/.evidence/dev/state.json" ]]; then
      printf '%s\n' 'Load-test startup failed; stopping only the project-owned dev session.' >&2
      "$evidencectl" --format json dev stop "$project" >/dev/null 2>&1 || :
      "$evidencectl" --format json dev clean --project "$project" >/dev/null 2>&1 ||
        printf '%s\n' "Automatic owned-session cleanup did not complete; inspect $project/.evidence." >&2
    fi
    if [[ -n "$mock_pid" ]]; then
      printf '%s\n' 'Stopping the source mock this launcher started.' >&2
      stop_owned_mock
    fi
  fi
  exit "$status"
}
trap cleanup_failed_start EXIT

read -r mock_port evidence_port issuer_port < <(python3 "$support" ports)

printf '%s\n' '== Preparing the synthetic adult-status project'
python3 "$support" openapi --template "$tracked/source.openapi.yaml" --port "$mock_port" --out "$run_dir/source.openapi.yaml"
"$evidencectl" init "$project" --openapi "$run_dir/source.openapi.yaml" --profile local >"$run_dir/init.log"
python3 "$support" local-project --tracked "$tracked" --project "$project" --pool "$run_dir/pool"
"$evidencectl" --format json check "$project" >"$run_dir/check-report.json"
"$evidencectl" source mock check --project "$project" >"$run_dir/mock-check.log"

# Each load client is a distinct principal, so the per-principal limit of the
# stock development bundle applies to each one separately. Clients must exist
# before dev start because the compiled bundle fixes the authority profiles.
printf '%s\n' "== Registering $load_clients synthetic load clients"
(
  # evidencectl creates access/ with mode 0755 through the process umask and
  # then requires exactly 0755, so these commands need the stock umask. The
  # project stays inside the owner-only .run directory, and the client keys
  # are still written owner-only by evidencectl itself.
  umask 022
  cd -- "$project"
  "$evidencectl" access policy add loadtest --question adult-status >/dev/null
  while IFS= read -r client; do
    "$evidencectl" access client add "$client" --policy loadtest --generate-local-key >/dev/null
  done < <(python3 "$support" clients --count "$load_clients")
)

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

printf '%s\n' '== Starting the stock evidencectl development lifecycle'
"$evidencectl" --format json dev start \
  --evidence-bin "$evidence_bin" \
  --docker-bin "$(command -v docker)" \
  --evidence-port "$evidence_port" \
  --issuer-port "$issuer_port" \
  "$project" >"$run_dir/dev-report.json"
python3 "$support" environment \
  --root "$run_dir" \
  --dev-report "$run_dir/dev-report.json" \
  --evidencectl "$evidencectl" \
  --build-profile "$build_profile" \
  --runtime-library-path "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH-}" \
  --mock-pid "$mock_pid" \
  --mock-port "$mock_port" \
  --clients "$load_clients"

printf '\n%s\n' 'Evidence load-test environment is ready.'
printf '  Evidence:               http://127.0.0.1:%s\n' "$evidence_port"
printf '  Identity provider:      stock evidencectl dev issuer on 127.0.0.1:%s\n' "$issuer_port"
printf '  Source mock:            evidencectl source mock on 127.0.0.1:%s (pid %s)\n' "$mock_port" "$mock_pid"
printf '  Evidence build profile: %s\n' "$build_profile"
printf '  Load clients:           %s (each limited to 60 requests per minute)\n' "$load_clients"
printf '  Environment:            %s\n' "$run_dir/env.json"
printf '  Then run:               products/evidence/loadtest/run.sh --profile smoke\n'
printf '  Tear down with:         products/evidence/loadtest/down.sh\n'
trap - EXIT
