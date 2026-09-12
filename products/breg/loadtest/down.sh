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
  printf '%s\n' 'docker is required to stop the owned bregctl development session.' >&2
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

bregctl=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["bregctl"])' "$run_dir/env.json")
if [[ "$bregctl" != "$repository_root/target/debug/bregctl" || ! -x "$bregctl" ]]; then
  printf '%s\n' 'The bregctl recorded by this environment is unavailable; preserve state and restore the matching build.' >&2
  exit 2
fi

"$bregctl" --format json dev stop --remove --docker-bin "$(command -v docker)" "$run_dir/project" >"$run_dir/stop-report.json"
printf '%s\n' 'Load-test services and their owned database were removed through bregctl dev.'
printf '%s\n' "Evidence and synthetic seeds remain at $run_dir; move that directory aside before another start."
