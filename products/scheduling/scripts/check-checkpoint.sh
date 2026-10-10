#!/bin/sh
set -eu

# shellcheck disable=SC1007  # the space after CDPATH= is the POSIX empty-assignment idiom the sibling products use
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
prepare_schedulingctl_runtime=0
if [ -z "${SCHEDULINGCTL_BIN:-}" ]; then
  schedulingctl_bin="$repo_root/target/debug/schedulingctl"
  prepare_schedulingctl_runtime=1
else
  schedulingctl_bin=$SCHEDULINGCTL_BIN
fi
. "$repo_root/scripts/cargo-runtime-library-path.sh"

cd "$repo_root"
python3 products/scheduling/scripts/generate_openapi.py --check
python3 products/scheduling/scripts/check_dependency_direction.py
python3 products/scheduling/scripts/check_database_test_isolation.py
python3 -m unittest discover -s products/scheduling/scripts -p 'test_*.py'
python3 products/scheduling/scripts/validate_contracts.py

# The committed configuration schemas are reproduced by their generators,
# never hand-edited; the drift tests run only under the schema feature, so
# the checkpoint runs them too.
products/scheduling/scripts/check-schemas.sh

if [ ! -x "$schedulingctl_bin" ]; then
  echo "build schedulingctl first or set SCHEDULINGCTL_BIN" >&2
  exit 2
fi
if [ "$prepare_schedulingctl_runtime" -eq 1 ]; then
  registry_prepare_cargo_runtime "$repo_root" --locked -p registry-schedulingctl
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/scheduling-checkpoint.XXXXXX")
cleanup() {
  case "$work" in
    "${TMPDIR:-/tmp}"/scheduling-checkpoint.*) rm -rf -- "$work" ;;
    *) exit 1 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for template in standalone-exact-time standalone-arrival-window; do
  "$schedulingctl_bin" init "$work/$template" --template "$template" >/dev/null
  "$schedulingctl_bin" check "$work/$template" >/dev/null
  "$schedulingctl_bin" test "$work/$template" >/dev/null
  "$schedulingctl_bin" explain "$work/$template" >/dev/null
done

# The journeys must answer what they claim to answer, not merely exit 0.
check_output=$("$schedulingctl_bin" check "$work/standalone-exact-time")
echo "$check_output" | grep -q '^Authoring check passed.$'
echo "$check_output" | grep -q '^0 errors, 0 warnings in 5 files$'
test_output=$("$schedulingctl_bin" test "$work/standalone-exact-time")
echo "$test_output" | grep -q '^Offline synthetic fixtures passed.$'
echo "$test_output" | grep -q '^proofBoundary: offline_synthetic$'

# A refused value is an error at its position: check exits 1 and names the
# file, line, and pointer on stderr, and the JSON envelope is a domain
# refusal. A broken fixture proof is never green. sed writes beside the file
# and mv replaces it, because sed -i spells differ between the development
# hosts and CI.
broken="$work/broken"
"$schedulingctl_bin" init "$broken" --template standalone-exact-time >/dev/null
sed 's/ttlMinutes: [0-9][0-9]*/ttlMinutes: 0/' \
  "$broken/scheduling.yaml" >"$broken/scheduling.yaml.next"
mv "$broken/scheduling.yaml.next" "$broken/scheduling.yaml"
status=0
refusal=$("$schedulingctl_bin" check "$broken" 2>&1 >/dev/null) || status=$?
if [ "$status" -ne 1 ]; then
  echo "check exited $status on an out-of-range value instead of 1" >&2
  exit 1
fi
echo "$refusal" | grep -q '^error\[config.out-of-range\] .*/scheduling.yaml:[0-9]*:[0-9]* /holdPolicy/ttlMinutes$'
status=0
"$schedulingctl_bin" check "$broken" --format json >"$work/refusal.json" 2>/dev/null || status=$?
if [ "$status" -ne 1 ]; then
  echo "check --format json exited $status on an out-of-range value instead of 1" >&2
  exit 1
fi
python3 - "$work/refusal.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
assert report["ok"] is False, report["status"]
assert report["status"] == "domain-refusal", report["status"]
assert [d["path"] for d in report["diagnostics"]] == ["/holdPolicy/ttlMinutes"]
PY
sed 's/offering: registry-update-30/offering: no-such-offering/' \
  "$broken/fixtures/counter-stations.yaml" >"$broken/fixtures/counter-stations.yaml.next"
mv "$broken/fixtures/counter-stations.yaml.next" "$broken/fixtures/counter-stations.yaml"
if "$schedulingctl_bin" test "$broken" >/dev/null 2>&1; then
  echo 'test accepted a fixture naming an offering the policy does not publish' >&2
  exit 1
fi

# The banded units table is reachable from the authoring journey, not only
# from the core's unit tests: swapping the arrival template's per-recipient
# record for a banded table must still check clean, and must change explain's
# window projection, which proves the records swap was read.
banded="$work/banded"
"$schedulingctl_bin" init "$banded" --template standalone-arrival-window >/dev/null
plain_explain=$("$schedulingctl_bin" explain "$banded")
python3 - "$banded/records.yaml" <<'PY'
import sys
from pathlib import Path

import yaml

path = Path(sys.argv[1])
document = yaml.safe_load(path.read_text(encoding="utf-8"))
for window in document["windows"]:
    window["unitsPolicy"] = {
        "type": "banded-table",
        "input": "service-recipient-count",
        "bands": [
            {"upTo": 2, "units": 1, "because": "One unit for one or two recipients."},
            {"upTo": 3, "units": 2, "because": "Two units for three recipients."},
        ],
        "aboveHighestBand": {"type": "refuse"},
        "because": "Household size decides the serving slots.",
    }
path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
PY
"$schedulingctl_bin" check "$banded" >/dev/null
banded_explain=$("$schedulingctl_bin" explain "$banded")
if [ "$plain_explain" = "$banded_explain" ]; then
  echo 'the banded units table did not change the window records explain read' >&2
  exit 1
fi

# The package journey on a fresh project: the shared package the runtime
# verifies, planned and then written to the same digest.
"$schedulingctl_bin" init "$work/package-project" --template standalone-exact-time >/dev/null
planned=$("$schedulingctl_bin" package "$work/package-project" --dry-run --format json |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["packageDigest"])')
written=$("$schedulingctl_bin" package "$work/package-project" --output "$work/package" --format json |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["packageDigest"])')
if [ "$planned" != "$written" ]; then
  echo "the planned package digest $planned differs from the written $written" >&2
  exit 1
fi
if [ ! -f "$work/package/SHA256SUMS" ] || [ ! -f "$work/package/scheduling.yaml" ]; then
  echo 'schedulingctl package wrote no SHA256SUMS or scheduling.yaml' >&2
  exit 1
fi
sums_digest="sha256:$(python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$work/package/SHA256SUMS")"
if [ "$written" != "$sums_digest" ]; then
  echo "the package digest $written is not the SHA-256 digest of SHA256SUMS" >&2
  exit 1
fi
if [ -e "$work/package/scheduling.package.json" ]; then
  echo 'schedulingctl package wrote the retired scheduling.package.json' >&2
  exit 1
fi

# The committed examples are the starter templates' output, so neither can
# drift from what an adopter initializes, including its live records document.
for template in standalone-exact-time standalone-arrival-window; do
  example="$repo_root/products/scheduling/examples/$template"
  "$schedulingctl_bin" init "$work/example-$template" --template "$template" >/dev/null
  diff -r "$work/example-$template" "$example" >/dev/null
  "$schedulingctl_bin" check "$example" >/dev/null
  "$schedulingctl_bin" test "$example" >/dev/null
done

echo "Scheduling product contracts and offline authoring journey passed."
