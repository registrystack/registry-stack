#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_PATH="openapi/registry-notary.openapi.json"
BASE_REF="${1:-${OPENAPI_CONTRACT_BASE_REF:-}}"
WORK_DIR="$ROOT/target/openapi-contract"
GENERATED="$WORK_DIR/generated.openapi.json"
BASELINE="$WORK_DIR/base.openapi.json"

mkdir -p "$WORK_DIR"

cargo run -q -p registry-notary-bin -- openapi > "$GENERATED"

python3 - "$ROOT/$SPEC_PATH" "$GENERATED" <<'PY'
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

git -C "$ROOT" show "$BASE_REF:$SPEC_PATH" > "$BASELINE"
oasdiff breaking --fail-on ERR "$BASELINE" "$GENERATED"
