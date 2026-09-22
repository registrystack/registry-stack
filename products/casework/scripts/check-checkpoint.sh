#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
caseworkctl_bin=${CASEWORKCTL_BIN:-"$repo_root/target/debug/caseworkctl"}

cd "$repo_root"
python3 products/casework/scripts/generate_openapi.py --check
python3 products/casework/scripts/generate_cli_schemas.py --check
python3 products/casework/scripts/check_dependency_direction.py
python3 -m unittest discover -s products/casework/scripts -p 'test_*.py'

if [ ! -x "$caseworkctl_bin" ]; then
  echo "build caseworkctl first or set CASEWORKCTL_BIN" >&2
  exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/casework-checkpoint.XXXXXX")
cleanup() {
  case "$work" in
    "${TMPDIR:-/tmp}"/casework-checkpoint.*) rm -rf -- "$work" ;;
    *) exit 1 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

"$caseworkctl_bin" init "$work/project" --template professional-review >/dev/null
"$caseworkctl_bin" check "$work/project" >/dev/null
"$caseworkctl_bin" test "$work/project" >/dev/null
"$caseworkctl_bin" init "$work/standalone" --template standalone-decision >/dev/null
"$caseworkctl_bin" check "$work/standalone" >/dev/null
"$caseworkctl_bin" test "$work/standalone" >/dev/null
multistage="$repo_root/products/casework/examples/multi-stage-routing-clocks"
"$caseworkctl_bin" check "$multistage" >/dev/null
"$caseworkctl_bin" explain "$multistage" >/dev/null
"$caseworkctl_bin" simulate "$multistage" \
  --fixture "$multistage/simulations/friday-review.yaml" >/dev/null
"$caseworkctl_bin" simulate "$multistage" \
  --fixture "$multistage/simulations/resubmitted-response.yaml" >/dev/null
"$caseworkctl_bin" test "$multistage" >/dev/null
"$caseworkctl_bin" --format json package "$multistage" \
  --output "$work/multistage-package" >"$work/multistage-package.json"
"$caseworkctl_bin" --format json package "$multistage" --dry-run \
  >"$work/multistage-dry-run.json"
python3 - "$work/multistage-package.json" "$work/multistage-dry-run.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    packaged = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    dry_run = json.load(handle)

if dry_run["dryRun"] is not True:
    sys.exit("dry-run report must set dryRun: true")
if "output" in dry_run:
    sys.exit("dry-run report must omit output")
if packaged["dryRun"] is not False:
    sys.exit("written package report must set dryRun: false")
if dry_run["policyDigest"] != packaged["policyDigest"]:
    sys.exit(
        "dry-run policyDigest %r does not match the written package's %r"
        % (dry_run["policyDigest"], packaged["policyDigest"])
    )
if dry_run["files"] != packaged["files"]:
    sys.exit("dry-run files do not match the written package's files")
PY
echo "Casework product contracts and offline authoring journey passed."
