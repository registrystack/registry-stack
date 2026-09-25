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
  printf '%s\n' "load-test state path already exists: $run_dir. Preserve it, or move it aside after stopping its owned dev session." >&2
  exit 2
fi

umask 077
mkdir -m 700 "$run_dir"
printf '%s\n' 'registry-stack-casework-loadtest-v1' >"$run_dir/.launcher-owned"

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

# shellcheck source-path=SCRIPTDIR source=../../../scripts/cargo-runtime-library-path.sh
. "$repository_root/scripts/cargo-runtime-library-path.sh"
cargo_profile_arguments=()
if [[ "$build_profile" == release ]]; then cargo_profile_arguments=(--release); fi
printf '%s\n' "== Building Registry Casework and caseworkctl ($build_profile profile)"
registry_cargo_build "$repository_root" --manifest-path "$repository_root/Cargo.toml" --locked \
  "${cargo_profile_arguments[@]}" \
  -p registry-casework --bin casework \
  -p registry-caseworkctl --bin caseworkctl >/dev/null
casework="$repository_root/target/$build_profile/casework"
caseworkctl="$repository_root/target/$build_profile/caseworkctl"

cleanup_failed_start() {
  local status=$?
  if [[ "$status" -ne 0 && -d "$run_dir/project/.casework/dev" ]]; then
    printf '%s\n' 'Load-test startup failed; stopping only the project-owned dev session.' >&2
    "$caseworkctl" dev stop --remove --docker-bin "$(command -v docker)" "$run_dir/project" >/dev/null 2>&1 ||
      printf '%s\n' "Automatic owned-session cleanup failed; inspect $run_dir/project/.casework/dev." >&2
  fi
  exit "$status"
}
trap cleanup_failed_start EXIT

read -r database_port issuer_port casework_port < <(python3 "$support" ports)
printf '%s\n' '== Preparing the local standalone-decision project'
producer_subject=$(python3 "$support" producer-subject --caseworkctl "$caseworkctl")
python3 "$support" local-project \
  --example "$example" \
  --project "$run_dir/project" \
  --issuer-port "$issuer_port" \
  --producer-subject "$producer_subject"
"$caseworkctl" --format json check "$run_dir/project" >"$run_dir/check-report.json"

printf '%s\n' '== Starting the stock retained Casework development lifecycle'
"$caseworkctl" --format json dev start \
  --casework-bin "$casework" \
  --docker-bin "$(command -v docker)" \
  --database-port "$database_port" \
  --issuer-port "$issuer_port" \
  --casework-port "$casework_port" \
  "$run_dir/project" >"$run_dir/dev-report.json"
python3 "$support" environment \
  --root "$run_dir" \
  --dev-report "$run_dir/dev-report.json" \
  --caseworkctl "$caseworkctl" \
  --build-profile "$build_profile" \
  --runtime-library-path "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH-}"

printf '\n%s\n' 'Registry Casework load-test environment is ready.'
printf '  Registry Casework:     http://127.0.0.1:%s\n' "$casework_port"
printf '  Token issuer:          stock local issuer through caseworkctl dev on 127.0.0.1:%s\n' "$issuer_port"
printf '  Database:              owned caseworkctl dev PostgreSQL on 127.0.0.1:%s\n' "$database_port"
printf '  Casework build:        %s\n' "$build_profile"
printf '  Casework pool max:     32 (fixed in the runtime)\n'
printf '  Environment:           %s\n' "$run_dir/env.json"
printf '  Seed next:             products/casework/loadtest/seed.py --count 2000\n'
printf '  Then run:              products/casework/loadtest/run.sh --profile smoke\n'
printf '  Tear down with:        products/casework/loadtest/down.sh\n'
trap - EXIT
