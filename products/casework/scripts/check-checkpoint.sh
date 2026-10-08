#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
prepare_caseworkctl_runtime=0
if [ -z "${CASEWORKCTL_BIN:-}" ]; then
  caseworkctl_bin="$repo_root/target/debug/caseworkctl"
  prepare_caseworkctl_runtime=1
else
  caseworkctl_bin=$CASEWORKCTL_BIN
fi
prepare_bregctl_runtime=0
if [ -z "${BREGCTL_BIN:-}" ]; then
  bregctl_bin="$repo_root/target/debug/bregctl"
  prepare_bregctl_runtime=1
else
  bregctl_bin=$BREGCTL_BIN
fi
. "$repo_root/scripts/cargo-runtime-library-path.sh"

cd "$repo_root"
python3 products/casework/scripts/generate_openapi.py --check
python3 products/casework/scripts/generate_cli_schemas.py --check
python3 products/casework/scripts/check_dependency_direction.py
python3 products/casework/scripts/check_database_test_isolation.py
python3 -m unittest discover -s products/casework/scripts -p 'test_*.py'
products/casework/scripts/check-schemas.sh

if [ ! -x "$caseworkctl_bin" ]; then
  echo "build caseworkctl first or set CASEWORKCTL_BIN" >&2
  exit 2
fi
if [ ! -x "$bregctl_bin" ]; then
  echo "build bregctl first or set BREGCTL_BIN" >&2
  exit 2
fi
if [ "$prepare_caseworkctl_runtime" -eq 1 ] || [ "$prepare_bregctl_runtime" -eq 1 ]; then
  registry_prepare_cargo_runtime "$repo_root" --locked -p registry-caseworkctl -p registry-bregctl
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
if dry_run["packageDigest"] != packaged["packageDigest"]:
    sys.exit(
        "dry-run packageDigest %r does not match the written package's %r"
        % (dry_run["packageDigest"], packaged["packageDigest"])
    )
if dry_run["files"] != packaged["files"]:
    sys.exit("dry-run files do not match the written package's files")
PY

# A two-entity BReg pairing: `source add` must give each paired request
# entity its own lifecycle hook (`casework-lifecycle-v1-<entity>`), since BReg
# hook identifiers are unique across a registry. If both entities shared one
# bare hook id, the pairing regresses and applying it leaves a registry
# `bregctl check` refuses with `breg.event.id-registry-duplicate`.
source_add_registry="$work/source-add-registry"
mkdir -p "$source_add_registry"
cp "$repo_root/products/breg/starters/public-organizations/core/registry.yaml" \
  "$source_add_registry/registry.yaml"
source_add_registry=$(CDPATH= cd -- "$source_add_registry" && pwd -P)
source_add_project="$work/source-add-casework"
mkdir -p "$source_add_project"
cp "$repo_root/products/casework/fixtures/source-add-public-organizations/casework.yaml" \
  "$source_add_project/casework.yaml"
"$caseworkctl_bin" source add "$source_add_registry" \
  --project "$source_add_project" --source-id public-organizations --apply \
  --bregctl-bin "$bregctl_bin" >/dev/null
"$bregctl_bin" check "$source_add_registry" >/dev/null

# A registry that carries the bare `casework-lifecycle-v1` hook on one request
# entity is paired like any other. `source add` leaves that authored hook as
# written and writes the entity's own hook beside it, and the result is a
# registry `bregctl check` accepts.
bare_hook_registry="$work/bare-hook-registry"
mkdir -p "$bare_hook_registry"
sed 's/id: casework-lifecycle-v1-name-correction$/id: casework-lifecycle-v1/' \
  "$source_add_registry/registry.yaml" >"$bare_hook_registry/registry.yaml"
bare_hook_registry=$(CDPATH= cd -- "$bare_hook_registry" && pwd -P)
if ! grep -q 'id: casework-lifecycle-v1$' "$bare_hook_registry/registry.yaml"; then
  echo "the bare lifecycle hook was not written into the registry under test" >&2
  exit 1
fi
"$bregctl_bin" check "$bare_hook_registry" >/dev/null
bare_hook_project="$work/bare-hook-casework"
mkdir -p "$bare_hook_project"
cp "$repo_root/products/casework/fixtures/source-add-public-organizations/casework.yaml" \
  "$bare_hook_project/casework.yaml"
"$caseworkctl_bin" source add "$bare_hook_registry" \
  --project "$bare_hook_project" --source-id public-organizations --apply \
  --bregctl-bin "$bregctl_bin" >/dev/null
for hook in casework-lifecycle-v1 casework-lifecycle-v1-name-correction; do
  if ! grep -q "id: $hook\$" "$bare_hook_registry/registry.yaml"; then
    echo "source add left no $hook hook beside the bare lifecycle hook" >&2
    exit 1
  fi
done
"$bregctl_bin" check "$bare_hook_registry" >/dev/null

# The pin `source add` just wrote is the public-organizations registry
# revision. A BReg package built from another registry rederives a different
# one, so `check --against-breg-package` must refuse the pin as stale and name
# the repin, through the real bregctl of this release.
set +e
"$caseworkctl_bin" --format json check "$source_add_project" \
  --against-breg-package "$repo_root/crates/registry-breg/tests/fixtures/person-registration-rhai-package" \
  --bregctl-bin "$bregctl_bin" >"$work/stale-pin.json"
stale_pin_exit=$?
set -e
if [ "$stale_pin_exit" -ne 1 ]; then
  echo "check --against-breg-package exited $stale_pin_exit for a stale pin, expected 1" >&2
  exit 1
fi
python3 - "$work/stale-pin.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
diagnostic = report["diagnostics"][0]
if report["ok"] is not False or diagnostic["code"] != "casework.source-revision.stale":
    sys.exit(f"stale pin was not refused as stale: {report}")
if "caseworkctl source add BREG_PROJECT" not in diagnostic["suggestedAction"]:
    sys.exit(f"stale pin refusal names no repin: {diagnostic}")
PY

echo "Casework product contracts and offline authoring journey passed."
