#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_PATH="openapi/registry-relay.openapi.json"
REFERENCE_CONFIG="openapi/registry-relay.reference.yaml"
BASE_REF="${1:-${OPENAPI_CONTRACT_BASE_REF:-}}"
WORK_DIR="$ROOT/target/openapi-contract"
GENERATED="$WORK_DIR/generated.openapi.json"
BASELINE="$WORK_DIR/base.openapi.json"

mkdir -p "$WORK_DIR"

cargo run -q --all-features -- openapi --config "$REFERENCE_CONFIG" > "$GENERATED"

python3 - "$GENERATED" <<'PY'
import json
import sys
from pathlib import Path

json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
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
oasdiff breaking --fail-on ERR "$BASELINE" "$ROOT/$SPEC_PATH"
