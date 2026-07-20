#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SPEC_PATH="openapi/registry-notary.openapi.json"
BASE_REF="${1:-${OPENAPI_CONTRACT_BASE_REF:-}}"
WORK_DIR="target/openapi-contract"
GENERATED="$WORK_DIR/generated.openapi.json"
BASELINE="$WORK_DIR/base.openapi.json"
RAW_BREAKING_DIFF="$WORK_DIR/breaking.singleline.txt"
BREAKING_IGNORE="openapi/oasdiff-1.0-err-ignore.txt"
# Exact git blob for the Notary 1.0 contract on main before beta-14 promotion.
# The release-only exception below must never apply after that contract baseline
# advances, even when BASE_REF also contains unrelated commits.
OPENAPI_1_0_BASELINE_BLOB="083a894a853c1791f2ba87f5ecee259e687eab70"

mkdir -p "$WORK_DIR"

cargo run -q -p registry-notary -- openapi > "$GENERATED"

python3 - "$SPEC_PATH" "$GENERATED" <<'PY'
import json
import sys
from pathlib import Path

committed = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
generated = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
if committed != generated:
    raise SystemExit("generated OpenAPI differs from committed baseline")
PY

if [[ -z "$BASE_REF" ]]; then
    echo "OPENAPI_CONTRACT_BASE_REF not set; skipped breaking-change diff"
    exit 0
fi

if ! command -v oasdiff >/dev/null 2>&1; then
    echo "oasdiff is required when OPENAPI_CONTRACT_BASE_REF is set" >&2
    exit 1
fi

if ! git rev-parse --verify "$BASE_REF^{commit}" >/dev/null 2>&1; then
    echo "OpenAPI contract base ref '$BASE_REF' is not available" >&2
    exit 1
fi

# git's <rev>:<path> object syntax resolves <path> relative to the repo
# root, not the current working directory. Compute the repo-root-relative
# form of SPEC_PATH and verify it points at the same file before trusting
# git's answer for whether that path exists at BASE_REF: a wrong
# computation must fail loudly here, not be read as "genuinely absent at
# the base ref" later.
REPO_PREFIX="$(git rev-parse --show-prefix)"
REPO_ROOT="$(git rev-parse --show-toplevel)"
SPEC_PATH_FROM_ROOT="${REPO_PREFIX}${SPEC_PATH}"
if [[ ! "$REPO_ROOT/$SPEC_PATH_FROM_ROOT" -ef "$SPEC_PATH" ]]; then
    echo "failed to resolve repo-root-relative path for '$SPEC_PATH' (got '$SPEC_PATH_FROM_ROOT'); refusing to run base-ref comparison" >&2
    exit 1
fi

if ! git cat-file -e "$BASE_REF:$SPEC_PATH_FROM_ROOT" 2>/dev/null; then
    echo "OpenAPI spec did not exist at '$BASE_REF'; skipped breaking-change diff"
    exit 0
fi

git show "$BASE_REF:$SPEC_PATH_FROM_ROOT" > "$BASELINE"

BASELINE_BLOB="$(git rev-parse "$BASE_REF:$SPEC_PATH_FROM_ROOT")"
if [[ "$BASELINE_BLOB" != "$OPENAPI_1_0_BASELINE_BLOB" ]]; then
    oasdiff breaking --fail-on ERR "$BASELINE" "$GENERATED"
    exit 0
fi

# Keep the one-time 1.0 exception exact and self-expiring. An added allowlist
# line fails this check, and an accepted line that disappears from the raw diff
# also fails so the exception cannot silently survive a baseline advance.
oasdiff breaking --format singleline "$BASELINE" "$GENERATED" > "$RAW_BREAKING_DIFF"
python3 - "$BREAKING_IGNORE" "$RAW_BREAKING_DIFF" <<'PY'
import sys
from pathlib import Path

expected = {
    "GET /oid4vci/credential-offer api path removed without deprecation",
    "POST /oid4vci/nonce api path removed without deprecation",
    "GET /.well-known/openid-credential-issuer removed the optional property `nonce_endpoint` from the response with the `200` status",
    "POST /oid4vci/credential removed the optional property `c_nonce` from the response with the `200` status",
    "POST /oid4vci/credential removed the optional property `c_nonce_expires_in` from the response with the `200` status",
}

ignore_path = Path(sys.argv[1])
raw_path = Path(sys.argv[2])
allowed = {
    line.strip()
    for line in ignore_path.read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.lstrip().startswith("#")
}
if allowed != expected:
    missing = sorted(expected - allowed)
    extra = sorted(allowed - expected)
    raise SystemExit(
        f"Notary OpenAPI 1.0 allowlist is not exact; missing={missing}, extra={extra}"
    )

observed = set()
for raw_line in raw_path.read_text(encoding="utf-8").splitlines():
    marker = "in API "
    if marker not in raw_line:
        continue
    change = raw_line.split(marker, 1)[1]
    if " [" in change:
        change = change.rsplit(" [", 1)[0]
    observed.add(change.strip().removesuffix(".").rstrip())

if observed != allowed:
    missing = sorted(allowed - observed)
    extra = sorted(observed - allowed)
    raise SystemExit(
        f"Notary OpenAPI 1.0 raw diff is not exactly allowlisted; "
        f"missing={missing}, extra={extra}"
    )
PY

oasdiff breaking --fail-on ERR --err-ignore "$BREAKING_IGNORE" \
    --warn-ignore "$BREAKING_IGNORE" \
    "$BASELINE" "$GENERATED"
