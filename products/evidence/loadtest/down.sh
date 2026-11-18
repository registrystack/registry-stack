#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository_root=$(cd -- "$loadtest_dir/../../.." && pwd -P)
run_dir="$loadtest_dir/.run"
marker="$run_dir/.launcher-owned"
support="$loadtest_dir/support/loadenv.py"

if [[ $# -ne 0 ]]; then
  printf '%s\n' 'usage: products/evidence/loadtest/down.sh' >&2
  exit 2
fi
if [[ -L "$run_dir" || ! -d "$run_dir" || ! -f "$marker" ]] ||
  [[ "$(<"$marker")" != registry-stack-evidence-loadtest-v1 ]]; then
  printf '%s\n' 'No owned Evidence load-test state was found; refusing teardown.' >&2
  exit 2
fi
if [[ -L "$run_dir/project" || ! -d "$run_dir/project" || ! -f "$run_dir/env.json" ]]; then
  printf '%s\n' 'Owned load-test state is incomplete; refusing teardown.' >&2
  exit 2
fi

environment_fields=$(python3 "$support" describe --root "$run_dir" --repository "$repository_root") || exit 2
read -r _ rstack run_id state_dir _ runtime_library_path <<<"$environment_fields"
if [[ -n "$runtime_library_path" ]]; then
  export DYLD_FALLBACK_LIBRARY_PATH="$runtime_library_path${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
fi

build_dir=$(dirname -- "$rstack")
export RSTACK_DEV_STATE_DIR="$state_dir" RSTACK_EVIDENCE_BIN="$build_dir/evidence" RSTACK_EVIDENCECTL_BIN="$build_dir/evidencectl"
status=0
"$rstack" --install-root "$build_dir" --format json dev stop "$run_id" >"$run_dir/stop-report.json" || {
  printf '%s\n' "rstack dev stop did not confirm a clean stop; the run may already be stopped. Check: rstack dev status $run_id" >&2
  status=1
}

# Only a process that still runs the exact command this launcher started is
# signalled, so a reused PID never reaches an unrelated process.
mock_status=0
mock_pid=$(python3 "$support" mock-pid --root "$run_dir" 2>/dev/null) || mock_status=$?
if [[ "$mock_status" -eq 0 ]]; then
  kill "$mock_pid"
  for _ in $(seq 1 20); do
    kill -0 "$mock_pid" 2>/dev/null || break
    sleep 0.25
  done
  if kill -0 "$mock_pid" 2>/dev/null; then
    printf '%s\n' "The source mock (pid $mock_pid) did not exit after SIGTERM." >&2
    status=1
  else
    printf '%s\n' 'The owned source mock was stopped.'
  fi
elif [[ "$mock_status" -eq 3 ]]; then
  printf '%s\n' 'The owned source mock is no longer running.'
else
  printf '%s\n' 'Could not validate the recorded source mock; it was not signalled.' >&2
  status=1
fi

if [[ "$status" -eq 0 ]]; then
  printf '%s\n' 'Load-test services were removed through rstack dev, and the source mock was stopped.'
fi
printf '%s\n' "Evidence and the synthetic subject pool remain at $run_dir; move that directory aside before another start."
exit "$status"
