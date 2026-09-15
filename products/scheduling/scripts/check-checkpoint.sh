#!/bin/sh
set -eu

# shellcheck disable=SC1007  # the space after CDPATH= is the POSIX empty-assignment idiom the sibling products use
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
schedulingctl_bin=${SCHEDULINGCTL_BIN:-"$repo_root/target/debug/schedulingctl"}

cd "$repo_root"
python3 products/scheduling/scripts/generate_openapi.py --check
python3 products/scheduling/scripts/check_dependency_direction.py
python3 products/scheduling/scripts/check_database_test_isolation.py
python3 -m unittest discover -s products/scheduling/scripts -p 'test_*.py'
python3 products/scheduling/scripts/validate_contracts.py

# The committed runtime configuration schema is reproduced by its generator,
# never hand-edited; the drift test runs only under the schema feature, so
# the checkpoint is the gate that runs it.
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked --quiet -p registry-scheduling --features schema

if [ ! -x "$schedulingctl_bin" ]; then
  echo "build schedulingctl first or set SCHEDULINGCTL_BIN" >&2
  exit 2
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
echo "$check_output" | grep -q '^status: complete'
test_output=$("$schedulingctl_bin" test "$work/standalone-exact-time")
echo "$test_output" | grep -q '^Offline synthetic fixtures passed.$'
echo "$test_output" | grep -q '^proofBoundary: offline_synthetic$'

# A project that carries findings reports them: check exits 0 with findings
# by default, refuses under --deny-findings, and a broken fixture proof is
# never green. sed writes beside the file and mv replaces it, because sed -i
# spells differ between the development hosts and CI.
broken="$work/broken"
"$schedulingctl_bin" init "$broken" --template standalone-exact-time >/dev/null
sed 's/ttlMinutes: [0-9][0-9]*/ttlMinutes: 0/' \
  "$broken/scheduling.yaml" >"$broken/scheduling.yaml.next"
mv "$broken/scheduling.yaml.next" "$broken/scheduling.yaml"
findings=$("$schedulingctl_bin" check "$broken")
echo "$findings" | grep -q '^status: incomplete$'
echo "$findings" | grep -q '^finding '
if "$schedulingctl_bin" check "$broken" --deny-findings >/dev/null 2>&1; then
  echo 'check --deny-findings accepted a finding-carrying project' >&2
  exit 1
fi
sed 's/offering: registry-update-30/offering: no-such-offering/' \
  "$broken/fixtures/counter-stations.yaml" >"$broken/fixtures/counter-stations.yaml.next"
mv "$broken/fixtures/counter-stations.yaml.next" "$broken/fixtures/counter-stations.yaml"
if "$schedulingctl_bin" test "$broken" >/dev/null 2>&1; then
  echo 'test accepted a fixture naming an offering the policy does not publish' >&2
  exit 1
fi

# The banded units table is reachable from the authoring journey, not only
# from the core's unit tests: swapping the arrival template's per-recipient
# policy for a banded table must still check clean, and must change the
# policy digest, which proves the swap took and was read.
banded="$work/banded"
"$schedulingctl_bin" init "$banded" --template standalone-arrival-window >/dev/null
plain_digest=$("$schedulingctl_bin" check "$banded" | grep -o '"policyDigest":"[^"]*"')
python3 - "$banded/scheduling.yaml" <<'PY'
import sys
from pathlib import Path

import yaml

path = Path(sys.argv[1])
document = yaml.safe_load(path.read_text(encoding="utf-8"))
for window in document["windows"]:
    window["unitsPolicy"] = {
        "kind": "bandedTable",
        "input": "serviceRecipientCount",
        "bands": [
            {"upTo": 2, "units": 1, "because": "One unit for one or two recipients."},
            {"upTo": 3, "units": 2, "because": "Two units for three recipients."},
        ],
        "aboveHighestBand": {"policy": "refuse"},
        "because": "Household size decides the serving slots.",
    }
path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
PY
banded_digest=$("$schedulingctl_bin" check "$banded" | grep -o '"policyDigest":"[^"]*"')
if [ "$plain_digest" = "$banded_digest" ]; then
  echo 'the banded units table did not change the policy the check read' >&2
  exit 1
fi

# The package journey on a fresh project: the manifest the runtime verifies.
"$schedulingctl_bin" init "$work/package" --template standalone-exact-time >/dev/null
"$schedulingctl_bin" package "$work/package" >/dev/null

# The committed example is the starter template's output, so it can never
# drift from what an adopter initializes.
example="$repo_root/products/scheduling/examples/standalone-exact-time"
"$schedulingctl_bin" init "$work/example" --template standalone-exact-time >/dev/null
diff -r "$work/example" "$example" >/dev/null
"$schedulingctl_bin" check "$example" >/dev/null
"$schedulingctl_bin" test "$example" >/dev/null

echo "Scheduling product contracts and offline authoring journey passed."
