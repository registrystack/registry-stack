#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository_root=$(cd -- "$loadtest_dir/../../.." && pwd -P)
run_dir="$loadtest_dir/.run"
support="$loadtest_dir/support/loadenv.py"
evidence="$repository_root/scripts/loadtest/evidence.py"

usage() {
  printf '%s\n' "usage: products/evidence/loadtest/run.sh --profile smoke|steady|burst|limiter [--ops N] [--duration 2m] [extra k6 args]" >&2
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
    --http-debug | --http-debug=* | --system-tags | --system-tags=*)
      printf '%s\n' "$1 is disabled because it can expose credentials, nonces, or subject identifiers." >&2
      exit 2
      ;;
    --no-thresholds | --no-thresholds=*)
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
  smoke | steady | burst | limiter) ;;
  *)
    printf '%s\n' "unknown profile '$profile'" >&2
    usage
    ;;
esac
script="$loadtest_dir/profiles/$profile.js"

if ! command -v k6 >/dev/null 2>&1; then
  printf '%s\n' 'k6 is required (brew install k6). See products/evidence/loadtest/README.md.' >&2
  exit 2
fi
if [[ ! -f "$run_dir/env.json" ]]; then
  printf '%s\n' "no load-test environment at $run_dir/env.json; run up.sh first" >&2
  exit 2
fi
for pool_file in subjects.txt absent.txt pool-summary.json; do
  if [[ ! -f "$run_dir/pool/$pool_file" ]]; then
    printf '%s\n' "no complete subject pool at $run_dir/pool; run up.sh first" >&2
    exit 2
  fi
done

environment_fields=$(python3 "$support" describe --root "$run_dir" --repository "$repository_root") || exit 2
read -r evidence_url _ _ load_clients runtime_library_path <<<"$environment_fields"
if [[ -n "$runtime_library_path" ]]; then
  export DYLD_FALLBACK_LIBRARY_PATH="$runtime_library_path${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
fi
python3 "$support" mock-pid --root "$run_dir" >/dev/null || {
  printf '%s\n' 'The owned source mock is not running; run down.sh, move .run aside, and start again.' >&2
  exit 2
}

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
    printf '%s\n' "$label must finish within 4 minutes so one fresh evidencectl dev token per client remains valid." >&2
    exit 2
  }
}

# Round-robin spreading gives each load client rate/clients requests per
# second against a stock refill of one per second. Keep a tenth in reserve for
# arrival jitter so the harness never measures its own client-side limit.
require_client_headroom() {
  local label="$1" rate="$2"
  if [[ ! "$rate" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    printf '%s\n' "$label must be a positive number" >&2
    exit 2
  fi
  python3 -c 'import sys; raise SystemExit(0 if float(sys.argv[1]) <= 0.9*int(sys.argv[2]) else 1)' "$rate" "$load_clients" || {
    printf '%s\n' "$label=$rate exceeds 90% of the $load_clients load clients' combined stock limit; restart with a larger LOAD_CLIENTS (see README)." >&2
    exit 2
  }
}

export EVIDENCE_URL="$evidence_url"
export SUBJECTS_FILE="$run_dir/pool/subjects.txt"
export ABSENT_FILE="$run_dir/pool/absent.txt"
REQUIREMENT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["requirement"])' "$run_dir/env.json")
SELECTOR_PROFILE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["selector_profile"])' "$run_dir/env.json")
PURPOSE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["purpose"])' "$run_dir/env.json")
export REQUIREMENT SELECTOR_PROFILE PURPOSE
export RANDOM_SEED="${RANDOM_SEED:-20260925}"

umask 077
mkdir -p "$run_dir/results"
stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
last_run_status=0

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
    --seed-summary "$run_dir/pool/pool-summary.json" \
    --product evidence \
    --profile "$manifest_profile" \
    "${manifest_parameters[@]}"

  export K6_SUMMARY_PATH="$result_dir/k6-summary.json"
  printf '%s\n' "== Fetching fresh tokens for $load_clients load clients"
  HEADER_FILES_LIST=$(python3 "$support" headers --root "$run_dir" --repository "$repository_root")
  export HEADER_FILES_LIST
  local secret_arguments=()
  local header_file
  while IFS= read -r header_file; do
    secret_arguments+=(--secret-file "$header_file")
  done <"$HEADER_FILES_LIST"

  printf '\n%s\n' "== k6 profile: $manifest_profile"
  local k6_status=0
  k6 run --out "json=$result_dir/k6-samples.json" "${pass_through[@]}" "$profile_script" || k6_status=$?
  local status="$k6_status"

  python3 "$evidence" assert-safe \
    --artifact-dir "$result_dir" \
    --samples "$result_dir/k6-samples.json" \
    "${secret_arguments[@]}" \
    --seed-pool "$run_dir/pool/subjects.txt" \
    --seed-pool "$run_dir/pool/absent.txt" \
    --out "$result_dir/safety.json" || status=1

  if [[ -f "$result_dir/k6-summary.json" ]]; then
    python3 "$evidence" summarize \
      --manifest "$result_dir/manifest.json" \
      --k6-summary "$result_dir/k6-summary.json" \
      --samples "$result_dir/k6-samples.json" \
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
    run_one "$result_dir" smoke "$script" "randomSeed=$RANDOM_SEED"
    ;;
  steady)
    export OPS="${OPS:-20}" DURATION="${DURATION:-2m}"
    require_token_window DURATION "$DURATION"
    require_client_headroom OPS "$OPS"
    run_one "$result_dir" steady "$script" \
      "offeredOps=$OPS" "duration=$DURATION" "randomSeed=$RANDOM_SEED"
    ;;
  burst)
    export OPS="${OPS:-20}" PEAK_OPS="${PEAK_OPS:-100}"
    export BASELINE_DURATION="${BASELINE_DURATION:-30s}" RAMP_DURATION="${RAMP_DURATION:-15s}"
    export PEAK_DURATION="${PEAK_DURATION:-30s}" RECOVERY_DURATION="${RECOVERY_DURATION:-90s}"
    require_token_window 'burst phase schedule' "$BASELINE_DURATION" "$RAMP_DURATION" "$PEAK_DURATION" "$RAMP_DURATION" "$RECOVERY_DURATION"
    require_client_headroom OPS "$OPS"
    require_client_headroom PEAK_OPS "$PEAK_OPS"
    run_one "$result_dir" burst "$script" \
      "baselineOps=$OPS" "peakOps=$PEAK_OPS" "baselineDuration=$BASELINE_DURATION" \
      "rampDuration=$RAMP_DURATION" "peakDuration=$PEAK_DURATION" \
      "recoveryDuration=$RECOVERY_DURATION" "randomSeed=$RANDOM_SEED"
    ;;
  limiter)
    run_one "$result_dir" limiter "$script" "randomSeed=$RANDOM_SEED"
    ;;
esac
exit "$last_run_status"
