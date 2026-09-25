#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$loadtest_dir/../../.." && pwd)
run_dir="$loadtest_dir/.run"
evidence="$repository_root/scripts/loadtest/evidence.py"
dbstats="$loadtest_dir/dbstats.sh"
seed_dir="$run_dir/seed"

usage() {
  printf '%s\n' "usage: products/casework/loadtest/run.sh --profile smoke|steady|burst [--ops N] [--duration 2m] [extra k6 args]" >&2
  exit 2
}

profile=""
pass_through=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      [[ $# -ge 2 ]] || usage
      profile="$2"
      shift 2
      ;;
    --ops)
      [[ $# -ge 2 ]] || usage
      export OPS="$2"
      shift 2
      ;;
    --duration)
      [[ $# -ge 2 ]] || usage
      export DURATION="$2"
      shift 2
      ;;
    --http-debug|--http-debug=*|--system-tags|--system-tags=*)
      printf '%s\n' "$1 is disabled because it can expose credentials, cursors, or record identifiers." >&2
      exit 2
      ;;
    --no-thresholds|--no-thresholds=*)
      printf '%s\n' "$1 is disabled because a run without thresholds has no verdict." >&2
      exit 2
      ;;
    *)
      pass_through+=("$1")
      shift
      ;;
  esac
done
[[ -n "$profile" ]] || usage
if [[ -n "${K6_HTTP_DEBUG:-}" || -n "${K6_SYSTEM_TAGS:-}" ]]; then
  printf '%s\n' 'K6_HTTP_DEBUG and K6_SYSTEM_TAGS overrides are disabled for evidence safety.' >&2
  exit 2
fi
if [[ -n "${K6_NO_THRESHOLDS:-}" ]]; then
  printf '%s\n' 'K6_NO_THRESHOLDS is disabled because a run without thresholds has no verdict.' >&2
  exit 2
fi
case "$profile" in
  smoke|steady|burst) ;;
  *)
    printf '%s\n' "unknown profile '$profile'" >&2
    usage
    ;;
esac
script="$loadtest_dir/profiles/$profile.js"

if ! command -v k6 >/dev/null 2>&1; then
  printf '%s\n' 'k6 is required (brew install k6). See products/casework/loadtest/README.md.' >&2
  exit 2
fi
if [[ ! -f "$run_dir/env.json" ]]; then
  printf '%s\n' "no load-test environment at $run_dir/env.json; run up.sh first" >&2
  exit 2
fi
for seed_file in read-tasks.txt flow-tasks.txt flow-offset seed-summary.json; do
  if [[ ! -f "$seed_dir/$seed_file" ]]; then
    printf '%s\n' "no complete seed evidence at $seed_dir; run seed.py first" >&2
    exit 2
  fi
done

environment_fields=$(python3 "$loadtest_dir/support/loadenv.py" describe --root "$run_dir" --repository "$repository_root") || exit 2
read -r casework_url caseworkctl project runtime_library_path <<<"$environment_fields"
if [[ -n "$runtime_library_path" ]]; then
  export DYLD_FALLBACK_LIBRARY_PATH="$runtime_library_path${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
fi

duration_seconds() {
  python3 - "$1" <<'PY'
import re,sys
value=sys.argv[1]
parts=list(re.finditer(r'([0-9]+(?:[.][0-9]+)?)(ms|s|m|h)',value))
if not parts or ''.join(part.group(0) for part in parts)!=value:
    raise SystemExit(2)
scale={'ms':0.001,'s':1,'m':60,'h':3600}
print(sum(float(part.group(1))*scale[part.group(2)] for part in parts))
PY
}

require_token_window() {
  local label="$1"
  shift
  local total=0 seconds value
  for value in "$@"; do
    seconds=$(duration_seconds "$value") || {
      printf '%s\n' "$label contains an invalid k6 duration: $value" >&2
      exit 2
    }
    total=$(python3 -c 'import sys; print(float(sys.argv[1])+float(sys.argv[2]))' "$total" "$seconds")
  done
  python3 -c 'import sys; raise SystemExit(0 if float(sys.argv[1]) <= 240 else 1)' "$total" || {
    printf '%s\n' "$label must finish within 4 minutes so one fresh caseworkctl dev token remains valid." >&2
    exit 2
  }
}

require_integer_rate() {
  local label="$1" value="$2" minimum="$3"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || ((10#$value < minimum)); then
    printf '%s\n' "$label must be a whole number of operations per second, at least $minimum" >&2
    exit 2
  fi
}

stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
export CASEWORK_URL="$casework_url"
export READ_TASKS_FILE="$seed_dir/read-tasks.txt"
export FOLLOW_CURSOR="${FOLLOW_CURSOR:-1}"
export RANDOM_SEED="${RANDOM_SEED:-20260902}"
export RUN_NONCE="$stamp"
unset FLOW_TASKS_FILE FLOW_OFFSET

umask 077
mkdir -p "$run_dir/results" "$run_dir/canaries"
db_pid=""
sampler_status=0
last_run_status=0
flow_canaries=""

# A sampler still running is stopped here and exits with 143 (TERM). One that
# already exited stopped sampling early, and its status fails the run. The
# function itself always succeeds, so it stays safe as the exit trap.
stop_samplers() {
  if [[ -n "$db_pid" ]]; then
    local code=0
    if kill -0 "$db_pid" 2>/dev/null; then
      kill "$db_pid" 2>/dev/null || true
      wait "$db_pid" 2>/dev/null || code=$?
      if [[ "$code" -eq 143 ]]; then code=0; fi
    else
      wait "$db_pid" 2>/dev/null || code=$?
    fi
    db_pid=""
    sampler_status="$code"
  fi
}
trap stop_samplers EXIT INT TERM

# Decision flows consume the flow pool in order, one entry per iteration. The
# offset advances by the scenario's upper bound before k6 starts, so an
# interrupted run never hands an already-decided task to a later run.
reserve_flow_pool() {
  local flow_ops="$1" duration="$2"
  local offset total planned seconds
  offset=$(<"$seed_dir/flow-offset")
  total=$(wc -l <"$seed_dir/flow-tasks.txt" | tr -d ' ')
  if [[ ! "$offset" =~ ^[0-9]+$ ]]; then
    printf '%s\n' 'flow-offset is not a whole number; the seed state is damaged.' >&2
    exit 2
  fi
  seconds=$(duration_seconds "$duration")
  planned=$(python3 -c 'import math,sys; print(math.ceil(float(sys.argv[1])*float(sys.argv[2]))+int(sys.argv[1]))' "$flow_ops" "$seconds")
  if ((offset + planned > total)); then
    printf '%s\n' "the flow pool has $((total - offset)) unused tasks but this run may decide $planned; start a fresh environment with a larger seed." >&2
    exit 2
  fi
  export FLOW_TASKS_FILE="$seed_dir/flow-tasks.txt" FLOW_OFFSET="$offset"
  printf '%s\n' "$((offset + planned))" >"$seed_dir/flow-offset"
  # assert-safe reads canaries from the first lines of each pool it is given;
  # this slice makes the entries this run touches part of that check.
  flow_canaries="$run_dir/canaries/$stamp-flow.txt"
  sed -n "$((offset + 1)),$((offset + 20))p" "$seed_dir/flow-tasks.txt" >"$flow_canaries"
}

fresh_header() {
  python3 "$loadtest_dir/support/loadenv.py" header \
    --caseworkctl "$caseworkctl" --project "$project" --client "$1"
}

run_one() {
  local result_dir="$1"
  local manifest_profile="$2"
  local profile_script="$3"
  shift 3
  local manifest_parameters=()
  local parameter
  for parameter in "$@"; do
    manifest_parameters+=(--parameter "$parameter")
  done

  mkdir -m 700 "$result_dir"
  python3 "$evidence" manifest \
    --out "$result_dir/manifest.json" \
    --repository "$repository_root" \
    --environment "$run_dir/env.json" \
    --seed-summary "$seed_dir/seed-summary.json" \
    --product casework \
    --profile "$manifest_profile" \
    "${manifest_parameters[@]}"

  "$dbstats" snapshot >"$result_dir/db-before.json"
  export K6_SUMMARY_PATH="$result_dir/k6-summary.json"

  STAFF_HEADER_FILE=$(fresh_header loadtest-staff)
  PRODUCER_HEADER_FILE=$(fresh_header loadtest-producer)
  export STAFF_HEADER_FILE PRODUCER_HEADER_FILE

  "$dbstats" sample 1 >"$result_dir/db-waits.jsonl" &
  db_pid=$!

  printf '\n%s\n' "== k6 profile: $manifest_profile"
  local k6_status=0
  k6 run --out "json=$result_dir/k6-samples.json" "${pass_through[@]}" "$profile_script" || k6_status=$?
  local status="$k6_status"
  stop_samplers
  if [[ "$sampler_status" -ne 0 ]]; then
    printf '%s\n' "The database wait sampler failed with status $sampler_status; its samples are incomplete." >&2
    status=1
  fi
  "$dbstats" snapshot >"$result_dir/db-after.json"

  local pool_arguments=(--seed-pool "$seed_dir/read-tasks.txt" --seed-pool "$seed_dir/flow-tasks.txt")
  if [[ -n "$flow_canaries" ]]; then pool_arguments+=(--seed-pool "$flow_canaries"); fi
  python3 "$evidence" assert-safe \
    --artifact-dir "$result_dir" \
    --samples "$result_dir/k6-samples.json" \
    --secret-file "$STAFF_HEADER_FILE" \
    --secret-file "$PRODUCER_HEADER_FILE" \
    "${pool_arguments[@]}" \
    --out "$result_dir/safety.json" || status=1

  if [[ -f "$result_dir/k6-summary.json" ]]; then
    python3 "$evidence" summarize \
      --manifest "$result_dir/manifest.json" \
      --k6-summary "$result_dir/k6-summary.json" \
      --samples "$result_dir/k6-samples.json" \
      --db-after "$result_dir/db-after.json" \
      --db-waits "$result_dir/db-waits.jsonl" \
      --db-sampler-exit-code "$sampler_status" \
      --safety "$result_dir/safety.json" \
      --k6-exit-code "$k6_status" \
      --out "$result_dir/result.json" || status=1
  else
    printf '%s\n' 'k6 did not produce its summary artifact.' >&2
    status=1
  fi

  local completion=passed
  if [[ "$status" -ne 0 ]]; then completion=failed; fi
  python3 "$evidence" finish \
    --path "$result_dir/manifest.json" \
    --status "$completion" \
    --exit-code "$status" \
    --k6-exit-code "$k6_status"

  printf '%s\n' "Evidence: $result_dir"
  last_run_status="$status"
  return 0
}

result_dir="$run_dir/results/$stamp-$profile"
case "$profile" in
  smoke)
    # The lifecycle always follows the inbox continuation to find its task.
    run_one "$result_dir" smoke "$script" "followCursor=1" "randomSeed=$RANDOM_SEED"
    ;;
  steady)
    export OPS="${OPS:-20}" DURATION="${DURATION:-2m}"
    require_integer_rate OPS "$OPS" 2
    require_token_window DURATION "$DURATION"
    default_flow_ops=$(python3 -c 'import math,sys; print(max(1, math.floor(int(sys.argv[1])/10+0.5)))' "$OPS")
    export FLOW_OPS="${FLOW_OPS:-$default_flow_ops}"
    require_integer_rate FLOW_OPS "$FLOW_OPS" 1
    if ((10#$FLOW_OPS >= 10#$OPS)); then
      printf '%s\n' 'FLOW_OPS must be below OPS so the inbox mix still runs' >&2
      exit 2
    fi
    reserve_flow_pool "$FLOW_OPS" "$DURATION"
    run_one "$result_dir" steady "$script" \
      "offeredOps=$OPS" "flowOps=$FLOW_OPS" "duration=$DURATION" "followCursor=$FOLLOW_CURSOR" "randomSeed=$RANDOM_SEED"
    ;;
  burst)
    export OPS="${OPS:-20}" PEAK_OPS="${PEAK_OPS:-100}"
    export BASELINE_DURATION="${BASELINE_DURATION:-30s}" RAMP_DURATION="${RAMP_DURATION:-15s}"
    export PEAK_DURATION="${PEAK_DURATION:-30s}" RECOVERY_DURATION="${RECOVERY_DURATION:-90s}"
    require_integer_rate OPS "$OPS" 1
    require_integer_rate PEAK_OPS "$PEAK_OPS" 2
    require_token_window 'burst phase schedule' "$BASELINE_DURATION" "$RAMP_DURATION" "$PEAK_DURATION" "$RAMP_DURATION" "$RECOVERY_DURATION"
    run_one "$result_dir" burst "$script" \
      "baselineOps=$OPS" "peakOps=$PEAK_OPS" "baselineDuration=$BASELINE_DURATION" \
      "rampDuration=$RAMP_DURATION" "peakDuration=$PEAK_DURATION" \
      "recoveryDuration=$RECOVERY_DURATION" "followCursor=$FOLLOW_CURSOR" "randomSeed=$RANDOM_SEED"
    ;;
esac
exit "$last_run_status"
