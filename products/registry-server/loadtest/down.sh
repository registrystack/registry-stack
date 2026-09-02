#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
run_dir="$loadtest_dir/.run"

if [[ ! -f "$run_dir/env.json" ]]; then
  printf '%s\n' "No recorded load-test environment at $run_dir/env.json." >&2
  exit 2
fi

container=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["database"]["container"])' "$run_dir/env.json")
if [[ ! "$container" =~ ^registry-server-loadtest-[0-9]+-[0-9]+$ ]]; then
  printf '%s\n' 'Recorded container name is not a Registry Server load-test target; refusing teardown.' >&2
  exit 2
fi

validated_pid() {
  local pid_file="$1"
  local expected_config="$2"
  local label="$3"
  if [[ ! -f "$pid_file" ]]; then
    return 0
  fi
  local pid
  pid=$(<"$pid_file")
  if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "Recorded $label PID is invalid; refusing teardown." >&2
    return 2
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    return 0
  fi
  local command
  command=$(ps -ww -p "$pid" -o command= 2>/dev/null || true)
  if [[ "$command" != *"$expected_config"* ]]; then
    printf '%s\n' "Recorded $label PID now belongs to another process; refusing teardown." >&2
    return 2
  fi
  printf '%s\n' "$pid"
}

server_pid=$(validated_pid "$run_dir/server.pid" "$run_dir/runtime.yaml" 'Registry Server') || exit $?
mint_pid=$(validated_pid "$run_dir/mint.pid" "$run_dir/mint/mint.yaml" 'Registry Mint') || exit $?

if [[ -n "$server_pid" ]]; then
  kill "$server_pid" >/dev/null 2>&1 || true
fi
if [[ -n "$mint_pid" ]]; then
  kill "$mint_pid" >/dev/null 2>&1 || true
fi
docker rm -f "$container" >/dev/null 2>&1 || true
rm -f "$run_dir/server.pid" "$run_dir/mint.pid" "$run_dir/env.json"
printf '%s\n' 'Load-test environment stopped. The .run directory was kept for logs and seeds; up.sh clears it on the next start.'
