#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SPEC_PATH="openapi/registry-relay.openapi.json"
REFERENCE_CONFIG="openapi/registry-relay.reference.yaml"
BASE_REF="${1:-${OPENAPI_CONTRACT_BASE_REF:-}}"
WORK_DIR="target/openapi-contract"
GENERATED="$WORK_DIR/generated.openapi.json"
BASELINE="$WORK_DIR/base.openapi.json"

mkdir -p "$WORK_DIR"

cargo run -q --all-features -- openapi --config "$REFERENCE_CONFIG" > "$GENERATED"

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

if ! git cat-file -e "$BASE_REF:$SPEC_PATH" 2>/dev/null; then
    echo "OpenAPI spec did not exist at '$BASE_REF'; skipped breaking-change diff"
    exit 0
fi

if ! git cat-file -e "$BASE_REF:$REFERENCE_CONFIG" 2>/dev/null; then
    echo "OpenAPI reference config did not exist at '$BASE_REF'; skipped bootstrap breaking-change diff"
    exit 0
fi

git show "$BASE_REF:$SPEC_PATH" > "$BASELINE"
# Accepted one-time diffs live in the ignore file; see its header comment.
oasdiff breaking --fail-on ERR --err-ignore openapi/oasdiff-err-ignore.txt "$BASELINE" "$SPEC_PATH"
