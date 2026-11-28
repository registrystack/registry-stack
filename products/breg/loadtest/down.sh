#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$loadtest_dir/../../.." && pwd)
run_dir="$loadtest_dir/.run"
marker="$run_dir/.launcher-owned"

if [[ $# -ne 0 ]]; then
  printf '%s\n' 'usage: products/breg/loadtest/down.sh' >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'docker is required to stop the owned rstack dev run.' >&2
  exit 2
fi
if [[ -L "$run_dir" || ! -d "$run_dir" || ! -f "$marker" ]] ||
  [[ "$(<"$marker")" != registry-stack-breg-loadtest-v2 ]]; then
  printf '%s\n' 'No owned Base Registry Engine load-test state was found; refusing teardown.' >&2
  exit 2
fi
if [[ -L "$run_dir/project" || ! -d "$run_dir/project" || ! -f "$run_dir/env.json" ]]; then
  printf '%s\n' 'Owned load-test state is incomplete; refusing teardown.' >&2
  exit 2
fi

environment_fields=$(python3 "$loadtest_dir/support/loadenv.py" describe --root "$run_dir" --repository "$repository_root") || exit 2
read -r _ rstack run_id state_dir runtime_library_path <<<"$environment_fields"
if [[ -n "$runtime_library_path" ]]; then
  export DYLD_FALLBACK_LIBRARY_PATH="$runtime_library_path${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
fi

build_dir=$(dirname -- "$rstack")
export RSTACK_DEV_STATE_DIR="$state_dir" RSTACK_BREG_BIN="$build_dir/breg" RSTACK_BREGCTL_BIN="$build_dir/bregctl"
# Clean the database even if the run already stopped.
"$rstack" --install-root "$build_dir" --format json dev stop "$run_id" --clean >"$run_dir/stop-report.json"
printf '%s\n' 'Load-test services and their managed database were removed through rstack dev.'
printf '%s\n' "Evidence and synthetic seeds remain at $run_dir. The next start archives that directory."
