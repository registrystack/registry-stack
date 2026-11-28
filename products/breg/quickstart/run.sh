#!/usr/bin/env bash
set -euo pipefail
quickstart_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$quickstart_dir/../../.." && pwd)
run_dir="$quickstart_dir/.run"
support="$quickstart_dir/support/quickstart.py"
spatial=false; smoke=false; installed=false
for arg in "$@"; do case "$arg" in --spatial) spatial=true;; --smoke) smoke=true;; --installed) installed=true;; *) echo 'usage: products/breg/quickstart/run.sh [--installed] [--spatial] [--smoke]' >&2; exit 2;; esac; done
if [[ -L "$run_dir" || -e "$run_dir" ]]; then
  printf '%s\n' "quickstart state path already exists: $run_dir. Run rstack dev stop RUN_ID --clean with RSTACK_DEV_STATE_DIR=$run_dir/state, then remove it." >&2
  exit 2
fi
for cmd in docker python3; do command -v "$cmd" >/dev/null || { echo "$cmd is required." >&2; exit 2; }; done
if [[ "$installed" == true ]]; then
  rstack=$(command -v rstack) || { echo 'rstack is required in --installed mode.' >&2; exit 2; }
  command -v breg >/dev/null || { echo 'breg is required in --installed mode.' >&2; exit 2; }
  bregctl=$(command -v bregctl) || { echo 'bregctl is required in --installed mode.' >&2; exit 2; }
  rstack_args=()
else
  command -v cargo >/dev/null || { echo 'cargo is required.' >&2; exit 2; }
  export RUSTC_WRAPPER=
  export CARGO_INCREMENTAL=0
  source "$repository_root/scripts/cargo-runtime-library-path.sh"
  registry_cargo_build "$repository_root" --manifest-path "$repository_root/Cargo.toml" --locked -p registry-breg --features registry-breg/runtime -p registry-bregctl -p registry-rstack --bins >/dev/null
  cargo_target_dir="${CARGO_TARGET_DIR:-$repository_root/target}"
  if [[ "$cargo_target_dir" != /* ]]; then
    cargo_target_dir="$repository_root/$cargo_target_dir"
  fi
  rstack="$cargo_target_dir/debug/rstack"; bregctl="$cargo_target_dir/debug/bregctl"
  export RSTACK_BREGCTL_BIN="$bregctl" RSTACK_BREG_BIN="$cargo_target_dir/debug/breg"
  # A source run uses no managed installation: the two variables above name the products.
  rstack_args=(--install-root "$run_dir/install")
fi
umask 077
mkdir -m 700 "$run_dir" "$run_dir/headers" "$run_dir/state"
printf '%s\n' 'registry-stack-breg-quickstart-v1' >"$run_dir/.launcher-owned"
export RSTACK_DEV_STATE_DIR="$run_dir/state"
if [[ "$spatial" == true ]]; then
  python3 "$support" prepare-spatial-project --fixture "$repository_root/products/breg/acceptance/spatial-service-sites" --project "$run_dir/project"
else
  "$bregctl" --format json init "$run_dir/project" >"$run_dir/init-report.json"
fi
run_id=""
cleanup() {
  local exit_code=$?
  # Clean the managed database before deleting the state that identifies it.
  if [[ -n "$run_id" ]]; then
    if ! "$rstack" "${rstack_args[@]}" dev stop "$run_id" --clean >/dev/null; then
      printf 'Cleanup failed. Retry with RSTACK_DEV_STATE_DIR=%q ' "$RSTACK_DEV_STATE_DIR" >&2
      printf '%q ' "$rstack" "${rstack_args[@]}" dev stop "$run_id" --clean >&2
      printf '\n' >&2
      if [[ "$exit_code" -eq 0 ]]; then exit_code=1; fi
    fi
  fi
  if [[ "$exit_code" -eq 0 ]] && [[ -f "$run_dir/.launcher-owned" ]] && [[ "$(cat "$run_dir/.launcher-owned")" == registry-stack-breg-quickstart-v1 ]]; then
    rm -rf -- "$run_dir"
  fi
  return "$exit_code"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# A failed scenario still leaves a live run, so the run ID is read before the exit status is judged.
start_status=0
"$rstack" "${rstack_args[@]}" --format json dev start "$run_dir/project" >"$run_dir/dev-report.json" || start_status=$?
run_id=$(python3 "$support" run-id --report "$run_dir/dev-report.json")
if [[ "$start_status" -ne 0 ]]; then
  python3 "$support" ready --report "$run_dir/dev-report.json" >/dev/null || true
  exit 1
fi
breg_origin=$(python3 "$support" ready --report "$run_dir/dev-report.json")
printf '%s\n' "$breg_origin" >"$run_dir/breg-origin"
person_header() {
  local person=$1 name=$2
  "$rstack" "${rstack_args[@]}" --format json dev token "$run_id" --as "$person" >"$run_dir/$name-token-report.json"
  python3 "$support" copy-header --report "$run_dir/$name-token-report.json" --to "$run_dir/headers/$name.header"
}
client=editor
[[ "$spatial" == true ]] && client=operator
person="$client"; person_header "$person" "$client"
if [[ "$spatial" == true ]]; then
  person=installation-map-reader; person_header "$person" installation-map-reader
  python3 "$support" spatial-smoke --root "$run_dir" --seed "$repository_root/products/breg/acceptance/spatial-service-sites/fixtures/seed-service-sites.jsonl"
else
  person=foreign-editor; person_header "$person" foreign-editor
  id=$(python3 "$support" request --root "$run_dir" --action create --name 'Quickstart contact' --email contact@example.test)
  python3 "$support" request --root "$run_dir" --action get --record-id "$id" >/dev/null
  python3 "$support" request --root "$run_dir" --action refusal --record-id "$id"
  echo "  Contact ID: $id"
fi
echo 'Base Registry Engine quickstart is ready.'
echo "  Base Registry Engine: $breg_origin"
echo "  Client header: $run_dir/headers/$client.header"
[[ "$smoke" == true ]] && exit 0
while :; do sleep 1; done
