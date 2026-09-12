#!/usr/bin/env bash
set -euo pipefail
quickstart_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$quickstart_dir/../../.." && pwd)
run_dir="$quickstart_dir/.run"
support="$quickstart_dir/support/quickstart.py"
spatial=false; smoke=false; installed=false
for arg in "$@"; do case "$arg" in --spatial) spatial=true;; --smoke) smoke=true;; --installed) installed=true;; *) echo 'usage: products/breg/quickstart/run.sh [--installed] [--spatial] [--smoke]' >&2; exit 2;; esac; done
if [[ -L "$run_dir" || -e "$run_dir" ]]; then
  printf '%s\n' "quickstart state path already exists: $run_dir. Stop its owned dev session before removing it." >&2
  exit 2
fi
for cmd in docker python3; do command -v "$cmd" >/dev/null || { echo "$cmd is required." >&2; exit 2; }; done
if [[ "$installed" == true ]]; then
  breg=$(command -v breg) || { echo 'breg is required in --installed mode.' >&2; exit 2; }
  bregctl=$(command -v bregctl) || { echo 'bregctl is required in --installed mode.' >&2; exit 2; }
else
  command -v cargo >/dev/null || { echo 'cargo is required.' >&2; exit 2; }
  export RUSTC_WRAPPER=
  export CARGO_INCREMENTAL=0
  cargo build --manifest-path "$repository_root/Cargo.toml" --locked -p registry-breg --features registry-breg/runtime -p registry-bregctl --bins >/dev/null
  breg="$repository_root/target/debug/breg"; bregctl="$repository_root/target/debug/bregctl"
fi
umask 077
mkdir -m 700 "$run_dir" "$run_dir/headers"
printf '%s\n' 'registry-stack-breg-quickstart-v1' >"$run_dir/.launcher-owned"
read -r database_port issuer_port breg_port < <(python3 "$support" ports)
if [[ "$spatial" == true ]]; then
  python3 "$support" prepare-spatial-project --fixture "$repository_root/products/breg/acceptance/spatial-service-sites" --project "$run_dir/project"
else
  "$bregctl" --format json init "$run_dir/project" >"$run_dir/init-report.json"
fi
cleanup() {
  local exit_code=$?
  local remove=()
  [[ "$exit_code" -eq 0 ]] && remove=(--remove)
  "$bregctl" dev stop "${remove[@]}" --docker-bin "$(command -v docker)" "$run_dir/project" >/dev/null 2>&1 || true
  if [[ "$exit_code" -eq 0 ]] && [[ -f "$run_dir/.launcher-owned" ]] && [[ "$(cat "$run_dir/.launcher-owned")" == registry-stack-breg-quickstart-v1 ]]; then
    rm -rf -- "$run_dir"
  fi
  return "$exit_code"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if ! "$bregctl" --format json dev start --breg-bin "$breg" --docker-bin "$(command -v docker)" \
  --breg-port "$breg_port" --issuer-port "$issuer_port" --database-port "$database_port" \
  "$run_dir/project" >"$run_dir/dev-report.json"; then
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["diagnostics"][0]["message"], file=sys.stderr)' "$run_dir/dev-report.json"
  exit 1
fi
printf 'http://127.0.0.1:%s\n' "$breg_port" >"$run_dir/breg-origin"
client=operator
"$bregctl" --format json dev token "$client" "$run_dir/project" >"$run_dir/token-report.json"
python3 - "$run_dir/token-report.json" "$run_dir/headers/operator.header" <<'PY'
import json,os,shutil,sys
source=json.load(open(sys.argv[1]))['headerFile']; shutil.copyfile(source,sys.argv[2]); os.chmod(sys.argv[2],0o600)
PY
if [[ "$spatial" == true ]]; then
  "$bregctl" --format json dev token installation-map-reader "$run_dir/project" >"$run_dir/map-token-report.json"
  python3 - "$run_dir/map-token-report.json" "$run_dir/headers/installation-map-reader.header" <<'PY'
import json,os,shutil,sys
source=json.load(open(sys.argv[1]))['headerFile']; shutil.copyfile(source,sys.argv[2]); os.chmod(sys.argv[2],0o600)
PY
  python3 "$support" spatial-smoke --root "$run_dir" --seed "$repository_root/products/breg/acceptance/spatial-service-sites/fixtures/qgis-service-sites.jsonl"
else
  id=$(python3 "$support" request --root "$run_dir" --action create --code QS-001 --label 'Quickstart record')
  python3 "$support" request --root "$run_dir" --action get --record-id "$id" >/dev/null
fi
echo 'Base Registry Engine quickstart is ready.'
echo "  Base Registry Engine: http://127.0.0.1:$breg_port"
echo "  Operator header: $run_dir/headers/operator.header"
[[ "$smoke" == true ]] && exit 0
while :; do sleep 1; done
