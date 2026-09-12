#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
product_dir=$(cd -- "$loadtest_dir/.." && pwd)
repository_root=$(cd -- "$product_dir/../.." && pwd)
support="$loadtest_dir/support/loadenv.py"
run_dir="$loadtest_dir/.run"
fixture="$product_dir/acceptance/business-establishments"

if [[ $# -ne 0 ]]; then
  printf '%s\n' 'usage: products/breg/loadtest/up.sh' >&2
  exit 2
fi
for command in cargo docker python3; do
  command -v "$command" >/dev/null 2>&1 || {
    printf '%s\n' "$command is required for the Base Registry Engine load-test environment." >&2
    exit 2
  }
done
if [[ -L "$run_dir" || -e "$run_dir" ]]; then
  printf '%s\n' "load-test state path already exists: $run_dir. Preserve it, or move it aside after stopping its owned dev session." >&2
  exit 2
fi

umask 077
mkdir -m 700 "$run_dir"
printf '%s\n' 'registry-stack-breg-loadtest-v2' >"$run_dir/.launcher-owned"

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"

printf '%s\n' '== Building Base Registry Engine and bregctl'
cargo build --manifest-path "$repository_root/Cargo.toml" --locked \
  -p registry-breg --features registry-breg/runtime \
  -p registry-bregctl --bins >/dev/null
breg="$repository_root/target/debug/breg"
bregctl="$repository_root/target/debug/bregctl"

cleanup_failed_start() {
  local status=$?
  if [[ "$status" -ne 0 && -d "$run_dir/project/.breg/dev" ]]; then
    printf '%s\n' 'Load-test startup failed; stopping only the project-owned dev session.' >&2
    "$bregctl" dev stop --remove --docker-bin "$(command -v docker)" "$run_dir/project" >/dev/null 2>&1 ||
      printf '%s\n' "Automatic owned-session cleanup failed; inspect $run_dir/project/.breg/dev." >&2
  fi
  exit "$status"
}
trap cleanup_failed_start EXIT

printf '%s\n' '== Preparing the local business-establishments project'
python3 "$support" local-project --fixture "$fixture" --project "$run_dir/project"
"$bregctl" --format json check "$run_dir/project" >"$run_dir/check-report.json"

read -r database_port issuer_port breg_port < <(python3 "$support" ports)
printf '%s\n' '== Starting the stock retained BReg development lifecycle'
"$bregctl" --format json dev start \
  --breg-bin "$breg" \
  --docker-bin "$(command -v docker)" \
  --database-port "$database_port" \
  --issuer-port "$issuer_port" \
  --breg-port "$breg_port" \
  "$run_dir/project" >"$run_dir/dev-report.json"
python3 "$support" environment \
  --root "$run_dir" \
  --dev-report "$run_dir/dev-report.json" \
  --bregctl "$bregctl"

printf '\n%s\n' 'Base Registry Engine load-test environment is ready.'
printf '  Base Registry Engine:  http://127.0.0.1:%s\n' "$breg_port"
printf '  Identity provider:     stock ThunderID 1.0.1 through bregctl dev\n'
printf '  Database:              owned bregctl dev PostgreSQL on 127.0.0.1:%s\n' "$database_port"
printf '  BReg pool max size:    4 (the stock development lifecycle default)\n'
printf '  Environment:           %s\n' "$run_dir/env.json"
printf '  Seed next:             products/breg/loadtest/seed.py --count 100000\n'
printf '  Then run:              products/breg/loadtest/run.sh --profile steady\n'
printf '  Tear down with:        products/breg/loadtest/down.sh\n'
trap - EXIT
