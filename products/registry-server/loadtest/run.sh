#!/usr/bin/env bash
set -euo pipefail

loadtest_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
run_dir="$loadtest_dir/.run"

usage() {
  printf '%s\n' "usage: products/registry-server/loadtest/run.sh --profile steady|sweep|burst|herd [--tps N] [--duration 10m] [extra k6 args]" >&2
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
    --tps)
      [[ $# -ge 2 ]] || usage
      export TPS="$2"
      shift 2
      ;;
    --duration)
      [[ $# -ge 2 ]] || usage
      export DURATION="$2"
      shift 2
      ;;
    *)
      pass_through+=("$1")
      shift
      ;;
  esac
done
[[ -n "$profile" ]] || usage
script="$loadtest_dir/profiles/$profile.js"
[[ -f "$script" ]] || {
  printf '%s\n' "unknown profile '$profile'; expected steady, sweep, burst, or herd" >&2
  exit 2
}

if ! command -v k6 >/dev/null 2>&1; then
  printf '%s\n' 'k6 is required (brew install k6). See products/registry-server/loadtest/README.md.' >&2
  exit 2
fi
if [[ ! -f "$run_dir/env.json" ]]; then
  printf '%s\n' "no load-test environment at $run_dir/env.json; run up.sh first" >&2
  exit 2
fi
if [[ ! -f "$run_dir/seed/establishment-ids.txt" ]]; then
  printf '%s\n' "no seed pool at $run_dir/seed; run seed.py first" >&2
  exit 2
fi

read -r server_url metrics_url token_url driver_client_id < <(python3 - "$run_dir/env.json" <<'PY'
import json
import sys

environment = json.load(open(sys.argv[1], encoding="utf-8"))
print(environment["server_url"], environment["metrics_url"], environment["token_url"], environment["driver_client_id"])
PY
)

export SERVER_URL="$server_url"
export METRICS_URL="$metrics_url"
export TOKEN_URL="$token_url"
export CLIENT_ID="$driver_client_id"
export CLIENT_SECRET="$(cat "$run_dir/secrets/driver-client-secret")"
export ESTABLISHMENT_IDS_FILE="$run_dir/seed/establishment-ids.txt"
export FOLLOW_CURSOR="${FOLLOW_CURSOR:-1}"

mkdir -p "$run_dir/logs"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
python3 "$loadtest_dir/support/loadenv.py" scrape --url "$metrics_url" --out "$run_dir/logs/metrics-before-$profile-$stamp.txt"

printf '%s\n' "== k6 profile: $profile"
status=0
k6 run "${pass_through[@]}" "$script" || status=$?

python3 "$loadtest_dir/support/loadenv.py" scrape --url "$metrics_url" --out "$run_dir/logs/metrics-after-$profile-$stamp.txt"
printf '%s\n' "Metrics scrapes saved under $run_dir/logs (before/after $stamp)."
printf '%s\n' "DB-side sampling: products/registry-server/loadtest/dbstats.sh"
exit "$status"
