#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
# shellcheck source-path=SCRIPTDIR/../../..
# shellcheck source=scripts/cargo-runtime-library-path.sh
. "$repo_root/scripts/cargo-runtime-library-path.sh"

cd "$repo_root"
python3 products/documents/scripts/check_dependency_direction.py
python3 products/documents/scripts/check_database_test_isolation.py
python3 -m unittest discover -s products/documents/scripts -p 'test_*.py'
python3 products/documents/scripts/validate_contracts.py

# The committed configuration schemas and OpenAPI document are reproduced by
# their generators, never hand-edited; the drift test runs only under the
# schema feature, so the checkpoint is the gate that runs it.
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked --quiet -p registry-documents --features schema

if [[ -n "${DOCUMENTSCTL_BIN:-}" ]]; then
  documentsctl_bin=$DOCUMENTSCTL_BIN
else
  registry_cargo_build "$repo_root" --locked --quiet -p registry-documentsctl
  documentsctl_bin="${CARGO_TARGET_DIR:-$repo_root/target}/debug/documentsctl"
fi
if [[ ! -x "$documentsctl_bin" ]]; then
  printf 'documentsctl is not executable at %s\n' "$documentsctl_bin" >&2
  exit 2
fi

temporary_root=$(CDPATH='' cd -- "${TMPDIR:-/tmp}" && pwd -P)
work=$(mktemp -d "$temporary_root/documents-checkpoint.XXXXXX")
cleanup() {
  case "$work" in
    "$temporary_root"/documents-checkpoint.*) rm -rf -- "$work" ;;
    *) exit 1 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# Write a copy of the starter project and runtime document with one named
# change applied for a refusal case.
starter="$repo_root/products/documents/examples/starter"
variant() {
  local name=$1 change=$2
  mkdir -p "$work/$name/project"
  python3 - "$starter" "$work/$name" "$change" <<'PY'
import sys
from pathlib import Path

import yaml

starter, root, change = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
project = yaml.safe_load((starter / "documents.yaml").read_text(encoding="utf-8"))
runtime = yaml.safe_load((starter / "runtime.example.yaml").read_text(encoding="utf-8"))
if change == "unknown-key":
    runtime["listener"]["port"] = 8116
elif change == "environment-in-credential":
    runtime["database"]["runtimeUrlRef"] = "${DOCUMENTS_RUNTIME_DATABASE_URL}"
elif change == "unrestricted-clients":
    runtime["authentication"]["oidc"]["allowedClients"] = "unrestricted"
elif change == "plaintext-hook":
    hook = runtime["destinations"]["hooks"]["custodian-events"]
    hook["url"] = hook["url"].replace("https://", "http://", 1)
elif change == "verification-disabled":
    runtime["contentVerification"] = {"type": "disabled"}
elif change == "unknown-project-key":
    project["owner"] = "civil-registry"
elif change != "none":
    raise SystemExit(f"unknown change {change}")
(root / "project" / "documents.yaml").write_text(
    yaml.safe_dump(project, sort_keys=False), encoding="utf-8")
(root / "runtime.yaml").write_text(yaml.safe_dump(runtime, sort_keys=False), encoding="utf-8")
PY
}

# The starter project and runtime document check clean together.
variant starter none
report=$("$documentsctl_bin" --format json check --project "$work/starter/project" \
  --runtime-config "$work/starter/runtime.yaml")
python3 - "$report" <<'PY'
import json
import sys

report = json.loads(sys.argv[1])
assert report["ok"] is True, report
assert report["kind"] == "DocumentsCtlReport", report
assert report["filesChecked"] == 2, report
assert report["diagnostics"] == [], report
PY

# Each refusal exits 1 and names the member it refused, at its JSON Pointer,
# under its own code.
expect_refusal() {
  local name=$1 flag=$2 path=$3 code=$4 status=0 report target
  variant "$name" "$name"
  if [[ "$flag" == "--project" ]]; then
    target="$work/$name/project"
  else
    target="$work/$name/runtime.yaml"
  fi
  report=$("$documentsctl_bin" --format json check "$flag" "$target") || status=$?
  if [[ "$status" -ne 1 ]]; then
    printf 'documentsctl check exited %s for %s, expected a refusal\n' "$status" "$name" >&2
    exit 1
  fi
  python3 - "$report" "$path" "$code" "$name" <<'PY'
import json
import sys

report, path, code, name = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
assert report["ok"] is False, report
refused = [(diagnostic["path"], diagnostic["code"]) for diagnostic in report["diagnostics"]]
assert refused == [(path, code)], f"{name}: refused {refused}, expected {(path, code)}"
PY
}

expect_refusal unknown-key --runtime-config /listener/port config.unknown-key
expect_refusal environment-in-credential --runtime-config /database/runtimeUrlRef \
  config.substitution-not-allowed
expect_refusal unrestricted-clients --runtime-config /authentication/oidc/allowedClients \
  documents.runtime.allowed-clients-required
expect_refusal plaintext-hook --runtime-config /destinations/hooks/custodian-events/url \
  documents.runtime.insecure-url
expect_refusal verification-disabled --runtime-config /contentVerification/type \
  documents.runtime.content-verification-disabled
expect_refusal unknown-project-key --project /owner config.unknown-key

# A project directory without documents.yaml is an operational failure, never
# an empty pass.
status=0
"$documentsctl_bin" --format json check --project "$work" >/dev/null || status=$?
if [[ "$status" -ne 3 ]]; then
  printf 'documentsctl check exited %s for a missing project file, expected 3\n' "$status" >&2
  exit 1
fi

printf 'Document Store product contracts and offline configuration checks passed.\n'
