#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$loadtest_dir/../../.." && pwd)
run_dir="$loadtest_dir/.run"
marker="$run_dir/.launcher-owned"

if [[ $# -ne 0 ]]; then
  printf '%s\n' 'usage: products/casework/loadtest/down.sh' >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'docker is required to stop the owned caseworkctl development session.' >&2
  exit 2
fi
if [[ -L "$run_dir" || ! -d "$run_dir" || ! -f "$marker" ]] ||
  [[ "$(<"$marker")" != registry-stack-casework-loadtest-v1 ]]; then
  printf '%s\n' 'No owned Registry Casework load-test state was found; refusing teardown.' >&2
  exit 2
fi
if [[ -L "$run_dir/project" || ! -d "$run_dir/project" || ! -f "$run_dir/env.json" ]]; then
  printf '%s\n' 'Owned load-test state is incomplete; refusing teardown.' >&2
  exit 2
fi

environment_fields=$(python3 "$loadtest_dir/support/loadenv.py" describe --root "$run_dir" --repository "$repository_root") || exit 2
read -r _ caseworkctl _ runtime_library_path <<<"$environment_fields"
if [[ -n "$runtime_library_path" ]]; then
  export DYLD_FALLBACK_LIBRARY_PATH="$runtime_library_path${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
fi

"$caseworkctl" --format json dev stop --remove --docker-bin "$(command -v docker)" "$run_dir/project" >"$run_dir/stop-report.json"
printf '%s\n' 'Load-test services and their owned database were removed through caseworkctl dev.'
printf '%s\n' "Evidence and synthetic seeds remain at $run_dir; move that directory aside before another start."
