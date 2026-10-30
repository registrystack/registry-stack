#!/bin/sh
set -eu
# Offline adopter proof. Database and native producer journeys have separate gates.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
. "$repo_root/scripts/cargo-runtime-library-path.sh"
cd "$repo_root"
python3 products/casework/scripts/check_dependency_direction.py
python3 products/casework/scripts/check_database_test_isolation.py
python3 -m unittest discover -s products/casework/scripts -p 'test_*.py'
products/casework/scripts/check-schemas.sh
if [ -z "${CASEWORKCTL_BIN:-}" ]; then
  registry_cargo_build "$repo_root" --locked --offline -j2 -p registry-caseworkctl
  target_directory=$(cargo metadata --locked --offline --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
  caseworkctl_bin="$target_directory/debug/caseworkctl"
else
  caseworkctl_bin=$CASEWORKCTL_BIN
fi
if [ ! -x "$caseworkctl_bin" ]; then
  echo "CASEWORKCTL_BIN must name an executable candidate" >&2
  exit 2
fi
# The provider-add authoring proof drives the matching public BReg CLI.
if [ -z "${BREGCTL_BIN:-}" ]; then
  registry_cargo_build "$repo_root" --locked --offline -j2 -p registry-bregctl
  target_directory=$(cargo metadata --locked --offline --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
  BREGCTL_BIN="$target_directory/debug/bregctl"
fi
CASEWORKCTL_BIN=$caseworkctl_bin
export BREGCTL_BIN CASEWORKCTL_BIN
cargo test --locked --offline -j2 -p registry-caseworkctl --test provider_add
work=$(mktemp -d "${TMPDIR:-/tmp}/casework-checkpoint.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM
"$caseworkctl_bin" init "$work/standalone" --template standalone-decision >/dev/null
for pattern in single-reviewer-approval two-peer-approval technical-check-then-authorization; do
  "$caseworkctl_bin" init "$work/$pattern" --template "$pattern" >/dev/null
  "$caseworkctl_bin" --format json check "$work/$pattern" >"$work/check.json"
  "$caseworkctl_bin" --format json explain "$work/$pattern" >"$work/explain.json"
  "$caseworkctl_bin" --format json test "$work/$pattern" >"$work/test.json"
  "$caseworkctl_bin" --format json package "$work/$pattern" --dry-run >"$work/dry-run.json"
done
for project in "$work/standalone" "$repo_root/products/casework/examples/standalone-decision" "$repo_root/products/casework/examples/canonical-review" "$repo_root/products/casework/examples/multi-stage-routing-clocks"; do
  "$caseworkctl_bin" --format json check "$project" >"$work/check.json"
  "$caseworkctl_bin" --format json explain "$project" >"$work/explain.json"
  "$caseworkctl_bin" --format json test "$project" >"$work/test.json"
  "$caseworkctl_bin" --format json types "$project" --output "$work/types" >"$work/types.json"
done
"$caseworkctl_bin" --format json explain "$repo_root/products/casework/examples/multi-stage-routing-clocks" >"$work/advanced-explain.json"
python3 - "$work/advanced-explain.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
policies = report["reviewPolicies"]
if report["ok"] is not True or len(policies) != 1:
    sys.exit("the regional review policy did not compile")
policy = policies[0]
if [stage["id"] for stage in policy["stages"]] != ["technical", "signoff"]:
    sys.exit("the two review stages changed")
if policy["routingFields"] != ["region"] or policy["routing"][0]["queue"] != "northern-review":
    sys.exit("the regional routing contract changed")
if sorted(policy["clocks"]) != ["response-budget", "review-deadline"]:
    sys.exit("the pinned response and deadline clocks changed")
PY
"$caseworkctl_bin" --format json package "$work/standalone" --output "$work/package" >"$work/package.json"
"$caseworkctl_bin" --format json package "$work/standalone" --dry-run >"$work/dry-run.json"
python3 - "$work/package.json" "$work/dry-run.json" <<'PY'
import json
import sys
packaged, dry_run = [json.load(open(path, encoding="utf-8")) for path in sys.argv[1:]]
for report in (packaged, dry_run):
    if report["ok"] is not True or report["command"] != "package":
        sys.exit("package did not return its typed success report")
if dry_run["dryRun"] is not True or "output" in dry_run:
    sys.exit("dry-run must report its mode without an output path")
if dry_run["packageDigest"] != packaged["packageDigest"]:
    sys.exit("dry-run and written package digests differ")
actual = sorted(path.relative_to(root).as_posix() for root in [__import__("pathlib").Path(packaged["output"])] for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
if actual != sorted(dry_run["files"]):
    sys.exit("dry-run file closure differs from the written package")
PY
printf '%s\n' 'Casework offline policy, inspection, types, package and schema checkpoint passed.'
