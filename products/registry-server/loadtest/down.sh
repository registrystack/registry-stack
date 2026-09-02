#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
run_dir="$loadtest_dir/.run"

if [[ ! -f "$run_dir/env.json" ]]; then
  printf '%s\n' "No recorded load-test environment at $run_dir/env.json." >&2
  exit 2
fi

container=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["database"]["container"])' "$run_dir/env.json")

if [[ -f "$run_dir/server.pid" ]]; then
  kill "$(cat "$run_dir/server.pid")" >/dev/null 2>&1 || true
fi
if [[ -f "$run_dir/mint.pid" ]]; then
  kill "$(cat "$run_dir/mint.pid")" >/dev/null 2>&1 || true
fi
docker rm -f "$container" >/dev/null 2>&1 || true
rm -f "$run_dir/server.pid" "$run_dir/mint.pid" "$run_dir/env.json"
printf '%s\n' 'Load-test environment stopped. The .run directory was kept for logs and seeds; up.sh clears it on the next start.'
