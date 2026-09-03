#!/usr/bin/env bash
set -euo pipefail

quickstart_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
product_dir=$(cd -- "$quickstart_dir/.." && pwd)

bash -n "$quickstart_dir/run.sh"
bash -n "$quickstart_dir/query.sh"
python3 -m py_compile "$quickstart_dir/support/quickstart.py"
python3 "$quickstart_dir/support/quickstart.py" self-test --quickstart-dir "$quickstart_dir"

# Extracts the setup and wait regions a launcher marks with
# "# supervision-signal-handling: <region> begin/end" comments, then drives
# the real code through both an operator SIGINT and a genuine crash without
# starting Docker, Mint, or BReg: the region is spliced into a harness
# script that stands in placeholder "sleep" processes for mint_pid/breg_pid.
check_supervision_signal_handling() {
  local launcher="$1"
  local label="$2"
  local preamble="${3:-}"

  local setup_block wait_block
  setup_block=$(sed -n '/^# supervision-signal-handling: setup begin$/,/^# supervision-signal-handling: setup end$/p' "$launcher")
  wait_block=$(sed -n '/^# supervision-signal-handling: wait begin$/,/^# supervision-signal-handling: wait end$/p' "$launcher")
  if [[ -z "$setup_block" ]]; then
    printf 'FAIL: %s is missing the supervision-signal-handling setup markers\n' "$label" >&2
    exit 1
  fi
  if [[ -z "$wait_block" ]]; then
    printf 'FAIL: %s is missing the supervision-signal-handling wait markers\n' "$label" >&2
    exit 1
  fi

  local stub_bin harness_dir run_dir
  stub_bin=$(mktemp -d)
  harness_dir=$(mktemp -d)
  run_dir="$harness_dir/run"
  mkdir -p "$run_dir"
  cat >"$stub_bin/docker" <<'DOCKER_STUB'
#!/usr/bin/env bash
exit 1
DOCKER_STUB
  chmod +x "$stub_bin/docker"

  # Operator stop: SIGINT must shut the placeholder services down and exit 0.
  local operator_script="$harness_dir/operator-stop.sh"
  {
    printf '#!/usr/bin/env bash\n'
    printf 'set -euo pipefail\n'
    printf 'run_dir=%q\n' "$run_dir"
    [[ -n "$preamble" ]] && printf '%s\n' "$preamble"
    printf '%s\n' "$setup_block"
    printf 'sleep 100 &\n'
    printf 'mint_pid=$!\n'
    printf 'printf %%s "$mint_pid" >%q\n' "$harness_dir/mint.pid"
    printf 'sleep 100 &\n'
    printf 'breg_pid=$!\n'
    printf 'printf %%s "$breg_pid" >%q\n' "$harness_dir/breg.pid"
    printf '%s\n' "$wait_block"
  } >"$operator_script"
  chmod +x "$operator_script"

  local operator_stderr="$harness_dir/operator-stop.stderr"
  # Job control keeps the background process from inheriting SIGINT as
  # ignored, which is bash's default for asynchronous commands and would
  # otherwise make the trap below untestable from this non-interactive script.
  set -m
  PATH="$stub_bin:$PATH" bash "$operator_script" >/dev/null 2>"$operator_stderr" &
  local harness_pid=$!
  set +m
  sleep 0.3
  kill -INT "$harness_pid"
  local status=0
  wait "$harness_pid" || status=$?
  if [[ "$status" -ne 0 ]]; then
    printf 'FAIL: %s did not exit 0 on SIGINT (exit %s)\n' "$label" "$status" >&2
    cat "$operator_stderr" >&2
    exit 1
  fi
  if grep -q 'stopped unexpectedly' "$operator_stderr"; then
    printf 'FAIL: %s reported an unexpected stop on operator SIGINT\n' "$label" >&2
    exit 1
  fi
  local mint_child breg_child
  mint_child=$(cat "$harness_dir/mint.pid")
  breg_child=$(cat "$harness_dir/breg.pid")
  if kill -0 "$mint_child" >/dev/null 2>&1 || kill -0 "$breg_child" >/dev/null 2>&1; then
    printf 'FAIL: %s left a placeholder service running after SIGINT\n' "$label" >&2
    exit 1
  fi

  # Genuine crash: the supervision loop must still exit 1 and report it.
  local crash_script="$harness_dir/crash.sh"
  {
    printf '#!/usr/bin/env bash\n'
    printf 'set -euo pipefail\n'
    printf 'run_dir=%q\n' "$run_dir"
    [[ -n "$preamble" ]] && printf '%s\n' "$preamble"
    printf '%s\n' "$setup_block"
    printf 'sleep 100 &\n'
    printf 'mint_pid=$!\n'
    printf 'sleep 100 &\n'
    printf 'breg_pid=$!\n'
    printf 'kill "$breg_pid"\n'
    printf 'wait "$breg_pid" 2>/dev/null || true\n'
    printf '%s\n' "$wait_block"
  } >"$crash_script"
  chmod +x "$crash_script"

  local crash_stderr="$harness_dir/crash.stderr"
  status=0
  PATH="$stub_bin:$PATH" bash "$crash_script" >/dev/null 2>"$crash_stderr" || status=$?
  if [[ "$status" -ne 1 ]]; then
    printf 'FAIL: %s did not exit 1 on a genuine crash (exit %s)\n' "$label" "$status" >&2
    cat "$crash_stderr" >&2
    exit 1
  fi
  if ! grep -q 'stopped unexpectedly' "$crash_stderr"; then
    printf 'FAIL: %s did not report the crash\n' "$label" >&2
    exit 1
  fi

  rm -rf "$stub_bin" "$harness_dir"
}

check_supervision_signal_handling "$quickstart_dir/run.sh" "quickstart run.sh"
check_supervision_signal_handling "$product_dir/demo/run.sh" "demo run.sh" 'webhook=false'

# Proves --installed mode fails before Docker, cargo, or any other setup work
# when breg, bregctl, or mint are missing from PATH. The stub PATH holds a
# real dirname, since the launchers use it to locate their own directory
# before any preflight check runs, plus stub docker, openssl, python3, and uv
# commands that exit non-zero if ever invoked. A pass here proves the
# reported failure comes from the missing installed binaries, not from a
# stub standing in for a tool the preflight also needs.
check_installed_missing_binaries() {
  local launcher="$1"
  local label="$2"

  local stub_bin real_dirname bash_bin
  stub_bin=$(mktemp -d)
  real_dirname=$(command -v dirname)
  bash_bin=$(command -v bash)
  ln -s "$real_dirname" "$stub_bin/dirname"
  for tool in docker openssl python3 uv; do
    cat >"$stub_bin/$tool" <<STUB
#!/usr/bin/env bash
printf '%s\n' "$tool must not run in this test" >&2
exit 1
STUB
    chmod +x "$stub_bin/$tool"
  done

  local stderr_file status
  stderr_file=$(mktemp)
  status=0
  PATH="$stub_bin" "$bash_bin" "$launcher" --installed >/dev/null 2>"$stderr_file" || status=$?
  if [[ "$status" -eq 0 ]]; then
    printf 'FAIL: %s --installed did not fail with breg, bregctl, and mint absent from PATH\n' "$label" >&2
    exit 1
  fi
  if ! grep -q 'breg' "$stderr_file"; then
    printf 'FAIL: %s --installed did not name the missing breg binary\n' "$label" >&2
    cat "$stderr_file" >&2
    exit 1
  fi
  if ! grep -q 'breg-install.sh' "$stderr_file"; then
    printf 'FAIL: %s --installed did not point to breg-install.sh\n' "$label" >&2
    cat "$stderr_file" >&2
    exit 1
  fi
  if grep -q 'must not run in this test' "$stderr_file"; then
    printf 'FAIL: %s --installed invoked a stubbed preflight command before failing\n' "$label" >&2
    cat "$stderr_file" >&2
    exit 1
  fi

  rm -rf "$stub_bin"
  rm -f "$stderr_file"
}

check_installed_missing_binaries "$quickstart_dir/run.sh" "quickstart run.sh"
check_installed_missing_binaries "$product_dir/demo/run.sh" "demo run.sh"

printf '%s\n' 'Base Registry Engine generic quickstart self-test passed'
