#!/usr/bin/env bash
set -euo pipefail
demo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$demo_dir/../../.." && pwd)
run_dir="$demo_dir/.run"
support="$demo_dir/support/demo.py"
fixture=business-establishments
smoke=false
installed=false
webhook=false
state_dir=''
handoff=''
usage() {
  printf '%s\n' 'usage: products/breg/demo/run.sh [--installed] [--smoke] [--webhook] [--fixture business-establishments|household|asset-site|asset-change-request|facility|inspection] [--state-dir PATH] [--handoff PATH]' >&2
  exit 2
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --installed) installed=true; shift ;;
    --smoke) smoke=true; shift ;;
    --webhook) webhook=true; shift ;;
    --fixture)
      [[ $# -ge 2 ]] || usage
      fixture="$2"
      shift 2
      ;;
    --state-dir)
      [[ $# -ge 2 ]] || usage
      state_dir="$2"
      shift 2
      ;;
    --handoff)
      [[ $# -ge 2 ]] || usage
      handoff="$2"
      shift 2
      ;;
    --token-lifetime-seconds)
      printf '%s\n' '--token-lifetime-seconds was retired; the stock development issuer owns its bounded token lifetime.' >&2
      exit 2
      ;;
    *) usage ;;
  esac
done
case "$fixture" in
  business-establishments|household|asset-site|asset-change-request|facility|inspection) ;;
  *) usage ;;
esac
[[ -z "$state_dir" ]] || run_dir="$state_dir"
if [[ -L "$run_dir" || -e "$run_dir" ]]; then
  printf '%s\n' "demo state path already exists: $run_dir. Stop its owned dev session before removing it." >&2
  exit 2
fi
for command in docker python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf '%s\n' "$command is required." >&2
    exit 2
  fi
done
if [[ "$installed" == true ]]; then
  breg=$(command -v breg) || { printf '%s\n' 'breg is required in --installed mode.' >&2; exit 2; }
  bregctl=$(command -v bregctl) || { printf '%s\n' 'bregctl is required in --installed mode.' >&2; exit 2; }
else
  export RUSTC_WRAPPER=
  export CARGO_INCREMENTAL=0
  cargo build --manifest-path "$root/Cargo.toml" --locked \
    -p registry-breg --features registry-breg/runtime \
    -p registry-bregctl --bins >/dev/null
  breg="$root/target/debug/breg"
  bregctl="$root/target/debug/bregctl"
fi
umask 077
mkdir -m 700 "$run_dir" "$run_dir/headers" "$run_dir/secrets"
printf '%s\n' 'registry-stack-breg-demo-v1' >"$run_dir/.launcher-owned"
case "$fixture" in
  household) fixture_source=publicschema-household ;;
  asset-site) fixture_source=asset-site-placement ;;
  asset-change-request) fixture_source=asset-site-placement-change-requests ;;
  *) fixture_source="$fixture" ;;
esac
fixture_dir="$root/products/breg/acceptance/$fixture_source"
prepare=(python3 "$support" prepare-dev --root "$run_dir" --fixture "$fixture_dir" --fixture-kind "$fixture")
if [[ "$webhook" == true ]]; then
  prepare+=(--webhook)
fi
"${prepare[@]}"
if [[ "$webhook" == true ]]; then
  "$bregctl" --format json explain model "$run_dir/project" >"$run_dir/webhook-model-report.json"
  python3 "$support" bind-webhook-module \
    --root "$run_dir" \
    --report "$run_dir/webhook-model-report.json"
fi
read -r database_port issuer_port breg_port < <(python3 "$support" ports)
cleanup() {
  local exit_code=$?
  local remove=()
  [[ "$exit_code" -eq 0 ]] && remove=(--remove)
  "$bregctl" dev stop "${remove[@]}" --docker-bin "$(command -v docker)" "$run_dir/project" >/dev/null 2>&1 || true
  if [[ "$exit_code" -eq 0 ]] && [[ -f "$run_dir/.launcher-owned" ]] && [[ "$(cat "$run_dir/.launcher-owned")" == registry-stack-breg-demo-v1 ]]; then
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
python3 - "$run_dir/project/dev-clients.yaml" <<'PY' >"$run_dir/client-map"
import json, sys
for client in json.load(open(sys.argv[1], encoding='utf-8'))['clients']:
    print(client['id'], client['accessProfiles'][0])
PY
while read -r client profile; do
  "$bregctl" --format json dev token "$client" "$run_dir/project" >"$run_dir/$client-token-report.json"
  token_name=$(python3 - "$fixture" "$profile" "$client" <<'PY'
import sys
fixture, profile, client = sys.argv[1:]
variants = {
    'business-demo-no-purpose': 'no-purpose',
    'household-demo-no-purpose': 'no-purpose',
    'asset-site-demo-planner-no-purpose': 'planner-no-purpose',
    'facility-demo-south-operator': 'south-operator',
    'inspection-demo-no-purpose': 'no-purpose',
}
names = {
    ('business-establishments', 'business-operator'): 'operator',
    ('business-establishments', 'business-viewer'): 'viewer',
    ('household', 'household-operator'): 'operator',
    ('household', 'household-viewer'): 'viewer',
    ('asset-site', 'asset-operator'): 'operator',
    ('asset-site', 'site-planner'): 'planner',
    ('asset-change-request', 'asset-operator'): 'operator',
    ('asset-change-request', 'site-planner'): 'planner',
    ('asset-change-request', 'correction-submitter'): 'submitter',
    ('asset-change-request', 'correction-reviewer'): 'reviewer',
    ('asset-change-request', 'correction-supervisor'): 'supervisor',
    ('asset-change-request', 'correction-applier'): 'applier',
    ('facility', 'facility-operator'): 'operator',
    ('inspection', 'inspection-inspector'): 'operator',
}
print(variants.get(client, names[(fixture, profile)]))
PY
)
  python3 - "$run_dir/$client-token-report.json" "$run_dir/headers/$token_name.header" "$run_dir/secrets/$token_name-token" <<'PY'
import json, os, shutil, sys
src = json.load(open(sys.argv[1], encoding='utf-8'))['headerFile']
shutil.copyfile(src, sys.argv[2])
os.chmod(sys.argv[2], 0o600)
line = open(src, encoding='ascii').read().strip()
with open(sys.argv[3], 'w', encoding='ascii') as output:
    output.write(line.removeprefix('Authorization: Bearer '))
os.chmod(sys.argv[3], 0o600)
PY
done <"$run_dir/client-map"
python3 "$support" seed --root "$run_dir" --fixture-kind "$fixture"
[[ -z "$handoff" ]] || python3 "$support" handoff --root "$run_dir" --fixture-kind "$fixture" --out "$handoff"
python3 "$support" query --root "$run_dir" --fixture-kind "$fixture" --suite all >/dev/null
[[ "$webhook" == true ]] && "$bregctl" --format json dev events "$run_dir/project" >"$run_dir/webhook-events.json"
printf '%s\n' 'Base Registry Engine demo is ready.'
printf '  Base Registry Engine: http://127.0.0.1:%s\n' "$breg_port"
printf '  Client headers: %s\n' "$run_dir/headers"
if [[ "$smoke" == true ]]; then
  exit 0
fi
while :; do sleep 1; done
