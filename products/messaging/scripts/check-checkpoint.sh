#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
# shellcheck source-path=SCRIPTDIR/../../..
# shellcheck source=scripts/cargo-runtime-library-path.sh
. "$repo_root/scripts/cargo-runtime-library-path.sh"

cd "$repo_root"
python3 products/messaging/scripts/check_dependency_direction.py
python3 products/messaging/scripts/check_database_test_isolation.py
python3 -m unittest discover -s products/messaging/scripts -p 'test_*.py'
python3 products/messaging/scripts/validate_contracts.py

# The committed runtime configuration schema and OpenAPI document are
# reproduced by their generators, never hand-edited; the drift test runs only
# under the schema feature, so the checkpoint is the gate that runs it.
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --locked --quiet -p registry-messaging --features schema

if [[ -n "${MESSAGINGCTL_BIN:-}" ]]; then
  messagingctl_bin=$MESSAGINGCTL_BIN
else
  registry_cargo_build "$repo_root" --locked --quiet -p registry-messagingctl
  messagingctl_bin="${CARGO_TARGET_DIR:-$repo_root/target}/debug/messagingctl"
fi
if [[ ! -x "$messagingctl_bin" ]]; then
  printf 'messagingctl is not executable at %s\n' "$messagingctl_bin" >&2
  exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/messaging-checkpoint.XXXXXX")
cleanup() {
  case "$work" in
    "${TMPDIR:-/tmp}"/messaging-checkpoint.*) rm -rf -- "$work" ;;
    *) exit 1 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# Rewrite a copy of the starter runtime document: point its operated paths at
# the work directory, then apply one named change for a refusal case.
starter="$repo_root/products/messaging/examples/starter"
variant() {
  local name=$1 change=$2
  mkdir -p "$work/$name/package"
  cp "$starter/messaging.yaml" "$work/$name/package/messaging.yaml"
  cp -R "$starter/templates" "$work/$name/package/templates"
  python3 - "$starter/runtime.example.yaml" "$work/$name" "$change" <<'PY'
import sys
from pathlib import Path

import yaml

source, root, change = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
document = yaml.safe_load(source.read_text(encoding="utf-8"))
document["package"]["root"] = str(root / "package")
document["secretProviders"]["file"]["root"] = str(root / "secrets")
document["audit"]["path"] = str(root / "audit.ndjson")
if change == "unknown-key":
    document["listener"]["port"] = 8107
elif change == "environment-in-credential":
    document["database"]["runtimeUrlRef"] = "${MESSAGING_RUNTIME_DATABASE_URL}"
elif change == "metrics-on-public-socket":
    document["metricsListener"]["bind"] = document["listener"]["bind"]
elif change == "pinned-digest":
    document["package"]["expectedDigest"] = "sha256:" + "0" * 64
elif change == "unadmitted-client":
    document["authentication"]["oidc"]["allowedClients"] = ["case-system"]
elif change != "none":
    raise SystemExit(f"unknown change {change}")
(root / "runtime.yaml").write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
PY
}

# The starter checks clean and reports what it would serve.
variant starter none
report=$("$messagingctl_bin" --format json check --runtime-config "$work/starter/runtime.yaml")
python3 - "$report" <<'PY'
import json
import sys

report = json.loads(sys.argv[1])
assert report["ok"] is True, report
assert report["listener"] == "127.0.0.1:8107", report
assert report["metricsListener"] == "127.0.0.1:9107", report
assert [profile["id"] for profile in report["accessProfiles"]] == ["case-notices", "operations"], report
assert [(t["id"], t["version"]) for t in report["templates"]] == [
    ("appointment-reminder", "1"),
    ("appointment-reminder-sms", "1"),
], report
assert report["packageDigest"].startswith("sha256:"), report
PY
starter_digest=$(python3 -c 'import json, sys; print(json.loads(sys.argv[1])["packageDigest"])' "$report")

# init writes exactly the published starter, and its package has the same
# digest the runtime configuration above reported.
"$messagingctl_bin" --format json init "$work/init" >/dev/null
diff -r "$starter" "$work/init"
report=$("$messagingctl_bin" --format json check --package "$work/init")
python3 - "$report" "$starter_digest" <<'PY'
import json
import sys

report, digest = json.loads(sys.argv[1]), sys.argv[2]
assert report["ok"] is True, report
assert report["packageDigest"] == digest, report
PY

# Pinning the digest the check reported is accepted.
python3 - "$work/starter/runtime.yaml" "$starter_digest" <<'PY'
import sys
from pathlib import Path

import yaml

path, digest = Path(sys.argv[1]), sys.argv[2]
document = yaml.safe_load(path.read_text(encoding="utf-8"))
document["package"]["expectedDigest"] = digest
path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
PY
"$messagingctl_bin" --format json check --runtime-config "$work/starter/runtime.yaml" >/dev/null

# preview renders the sample offline, byte-stable across runs, and refuses a
# locale the template does not declare with its problem code.
sms_sample="$starter/templates/appointment-reminder-sms/1/sample.json"
"$messagingctl_bin" --format json preview --package "$work/init" \
  appointment-reminder-sms 1 --locale en --data "$sms_sample" >"$work/preview-1.json"
"$messagingctl_bin" --format json preview --runtime-config "$work/starter/runtime.yaml" \
  appointment-reminder-sms 1 --locale en --data "$sms_sample" >"$work/preview-2.json"
cmp "$work/preview-1.json" "$work/preview-2.json"
python3 - "$work/preview-1.json" "$starter_digest" <<'PY'
import json
import sys
from pathlib import Path

preview, digest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")), sys.argv[2]
assert preview["template"] == {"id": "appointment-reminder-sms", "version": "1"}, preview
assert preview["packageDigest"] == digest, preview
assert preview["channel"] == "sms", preview
assert "Ada Lovelace" in preview["parts"]["text"], preview
assert preview["sms"]["segments"] == 1, preview
PY
status=0
report=$("$messagingctl_bin" --format json preview --package "$work/init" \
  appointment-reminder 1 --locale de --data "$sms_sample") || status=$?
if [[ "$status" -ne 1 ]]; then
  printf 'messagingctl preview exited %s for an undeclared locale, expected 1\n' "$status" >&2
  exit 1
fi
python3 - "$report" <<'PY'
import json
import sys

report = json.loads(sys.argv[1])
assert report["diagnostics"][0]["code"] == "template.locale-unavailable", report
PY

# Each refusal exits 1 and names the member it refused.
expect_refusal() {
  local name=$1 path=$2 status=0 report
  variant "$name" "$name"
  report=$("$messagingctl_bin" --format json check --runtime-config "$work/$name/runtime.yaml") || status=$?
  if [[ "$status" -ne 1 ]]; then
    printf 'messagingctl check exited %s for %s, expected a refusal\n' "$status" "$name" >&2
    exit 1
  fi
  python3 - "$report" "$path" "$name" <<'PY'
import json
import sys

report, path, name = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3]
assert report["ok"] is False, report
paths = [diagnostic["path"] for diagnostic in report["diagnostics"]]
assert paths == [path], f"{name}: refused {paths}, expected {path}"
PY
}

expect_refusal unknown-key listener.port
expect_refusal environment-in-credential database.runtimeUrlRef
expect_refusal metrics-on-public-socket metricsListener.bind
expect_refusal pinned-digest package.expectedDigest
expect_refusal unadmitted-client authentication.oidc.allowedClients

printf 'Messaging product contracts and offline configuration checks passed.\n'
