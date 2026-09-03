#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$loadtest_dir/../../.." && pwd)
run_dir="$loadtest_dir/.run"
evidence="$loadtest_dir/support/evidence.py"
dbstats="$loadtest_dir/dbstats.sh"

usage() {
  printf '%s\n' "usage: products/breg/loadtest/run.sh --profile steady|sweep|burst|herd|token-soak|cursor-smoke [--ops N] [--duration 10m] [extra k6 args]" >&2
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
    --tps)
      printf '%s\n' '--tps was renamed to --ops because one workload iteration can issue multiple HTTP requests.' >&2
      exit 2
      ;;
    --http-debug|--http-debug=*|--system-tags|--system-tags=*)
      printf '%s\n' "$1 is disabled because it can expose credentials, cursors, or record identifiers." >&2
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
script="$loadtest_dir/profiles/$profile.js"
[[ -f "$script" ]] || {
  printf '%s\n' "unknown profile '$profile'" >&2
  usage
}

if ! command -v k6 >/dev/null 2>&1; then
  printf '%s\n' 'k6 is required (brew install k6). See products/breg/loadtest/README.md.' >&2
  exit 2
fi
if [[ ! -f "$run_dir/env.json" ]]; then
  printf '%s\n' "no load-test environment at $run_dir/env.json; run up.sh first" >&2
  exit 2
fi
if [[ ! -f "$run_dir/seed/establishment-ids.txt" || ! -f "$run_dir/seed/seed-summary.json" ]]; then
  printf '%s\n' "no complete seed evidence at $run_dir/seed; run seed.py first" >&2
  exit 2
fi

read -r breg_url metrics_url token_url driver_client_id < <(python3 - "$run_dir/env.json" <<'PY'
import json
import sys

environment = json.load(open(sys.argv[1], encoding="utf-8"))
print(environment["breg_url"], environment["metrics_url"], environment["token_url"], environment["driver_client_id"])
PY
)

export BREG_URL="$breg_url"
export METRICS_URL="$metrics_url"
export TOKEN_URL="$token_url"
export CLIENT_ID="$driver_client_id"
CLIENT_SECRET="$(<"$run_dir/secrets/driver-client-secret")"
export CLIENT_SECRET
export ESTABLISHMENT_IDS_FILE="$run_dir/seed/establishment-ids.txt"
export FOLLOW_CURSOR="${FOLLOW_CURSOR:-1}"
export RANDOM_SEED="${RANDOM_SEED:-20260902}"

umask 077
mkdir -p "$run_dir/results"
stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
metrics_pid=""
db_pid=""
last_run_status=0

stop_samplers() {
  if [[ -n "$metrics_pid" ]]; then
    kill "$metrics_pid" 2>/dev/null || true
    wait "$metrics_pid" 2>/dev/null || true
    metrics_pid=""
  fi
  if [[ -n "$db_pid" ]]; then
    kill "$db_pid" 2>/dev/null || true
    wait "$db_pid" 2>/dev/null || true
    db_pid=""
  fi
}
trap stop_samplers EXIT INT TERM

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
    --seed-summary "$run_dir/seed/seed-summary.json" \
    --profile "$manifest_profile" \
    "${manifest_parameters[@]}"

  "$dbstats" reset
  "$dbstats" snapshot >"$result_dir/db-before.json"
  export K6_SUMMARY_PATH="$result_dir/k6-summary.json"

  python3 "$evidence" sample-metrics \
    --url "$metrics_url" \
    --out "$result_dir/telemetry.jsonl" \
    --server-pid "$run_dir/breg.pid" \
    --mint-pid "$run_dir/mint.pid" &
  metrics_pid=$!
  "$dbstats" sample 1 >"$result_dir/db-waits.jsonl" &
  db_pid=$!

  printf '\n%s\n' "== k6 profile: $manifest_profile"
  local k6_status=0
  k6 run --out "json=$result_dir/k6-samples.json" "${pass_through[@]}" "$profile_script" || k6_status=$?
  local status="$k6_status"
  stop_samplers
  "$dbstats" snapshot >"$result_dir/db-after.json"

  local secret_arguments=()
  local secret_path
  for secret_path in \
    "$run_dir/secrets/"* \
    "$run_dir/keys/mint/"* \
    "$run_dir/keys/operator/"* \
    "$run_dir/tls/"*.key; do
    if [[ -f "$secret_path" ]]; then
      secret_arguments+=(--secret-file "$secret_path")
    fi
  done
  python3 "$evidence" assert-safe \
    --artifact-dir "$result_dir" \
    --samples "$result_dir/k6-samples.json" \
    "${secret_arguments[@]}" \
    --seed-pool "$run_dir/seed/establishment-ids.txt" \
    --seed-pool "$run_dir/seed/business-ids.txt" \
    --out "$result_dir/safety.json" || status=1

  if [[ -f "$result_dir/k6-summary.json" ]]; then
    python3 "$evidence" summarize \
      --manifest "$result_dir/manifest.json" \
      --k6-summary "$result_dir/k6-summary.json" \
      --samples "$result_dir/k6-samples.json" \
      --telemetry "$result_dir/telemetry.jsonl" \
      --db-after "$result_dir/db-after.json" \
      --db-waits "$result_dir/db-waits.jsonl" \
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

if [[ "$profile" == sweep ]]; then
  rates="${RATES:-50,75,100,125,150}"
  hold="${HOLD:-2m}"
  warmup_ops="${WARMUP_OPS:-50}"
  warmup_duration="${WARMUP_DURATION:-2m}"
  if [[ ! "$warmup_ops" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    printf '%s\n' 'WARMUP_OPS must be a positive number' >&2
    exit 2
  fi
  IFS=',' read -r -a sweep_rates <<<"$rates"
  for rate in "${sweep_rates[@]}"; do
    if [[ ! "$rate" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
      printf '%s\n' "invalid held rate in RATES: $rate" >&2
      exit 2
    fi
  done

  sweep_root="$run_dir/results/$stamp-sweep"
  mkdir -m 700 "$sweep_root"
  printf '%s\n' "== read-only warmup: $warmup_ops ops/s for $warmup_duration (excluded from evidence)"
  export OPS="$warmup_ops" DURATION="$warmup_duration" K6_SUMMARY_PATH=""
  k6 run --quiet --no-thresholds --summary-mode disabled "${pass_through[@]}" "$script"

  overall_status=0
  for rate in "${sweep_rates[@]}"; do
    export OPS="$rate" DURATION="$hold"
    run_one \
      "$sweep_root/rate-$rate" sweep "$script" \
      "rateOps=$rate" "duration=$hold" "warmupOps=$warmup_ops" \
      "warmupDuration=$warmup_duration" "followCursor=$FOLLOW_CURSOR" "randomSeed=$RANDOM_SEED"
    if [[ "$last_run_status" -ne 0 ]]; then
      overall_status=1
    fi
  done
  python3 "$evidence" aggregate-sweep --root "$sweep_root" --out "$sweep_root/sweep-result.json"
  printf '%s\n' "Sweep evidence: $sweep_root"
  exit "$overall_status"
fi

result_dir="$run_dir/results/$stamp-$profile"
case "$profile" in
  steady)
    export OPS="${OPS:-50}" DURATION="${DURATION:-10m}"
    run_one "$result_dir" steady "$script" \
      "offeredOps=$OPS" "duration=$DURATION" "followCursor=$FOLLOW_CURSOR" "randomSeed=$RANDOM_SEED"
    ;;
  burst)
    export OPS="${OPS:-50}" PEAK_OPS="${PEAK_OPS:-250}"
    export BASELINE_DURATION="${BASELINE_DURATION:-2m}" RAMP_DURATION="${RAMP_DURATION:-30s}"
    export PEAK_DURATION="${PEAK_DURATION:-30s}" RECOVERY_DURATION="${RECOVERY_DURATION:-3m}"
    run_one "$result_dir" burst "$script" \
      "baselineOps=$OPS" "peakOps=$PEAK_OPS" "baselineDuration=$BASELINE_DURATION" \
      "rampDuration=$RAMP_DURATION" "peakDuration=$PEAK_DURATION" \
      "recoveryDuration=$RECOVERY_DURATION" "followCursor=$FOLLOW_CURSOR" "randomSeed=$RANDOM_SEED"
    ;;
  herd)
    export VUS="${VUS:-200}" DURATION="${DURATION:-30s}"
    run_one "$result_dir" herd "$script" "vus=$VUS" "duration=$DURATION"
    ;;
  token-soak)
    export VUS="${VUS:-200}" DURATION="${DURATION:-1m}"
    run_one "$result_dir" token-soak "$script" "vus=$VUS" "duration=$DURATION"
    ;;
  cursor-smoke)
    export FOLLOW_CURSOR=1
    run_one "$result_dir" cursor-smoke "$script" "followCursor=1" "randomSeed=$RANDOM_SEED"
    ;;
  *) usage ;;
esac
exit "$last_run_status"
