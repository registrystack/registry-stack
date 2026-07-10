#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SPEC_PATH="openapi/registry-notary.openapi.json"
BASE_REF="${1:-${OPENAPI_CONTRACT_BASE_REF:-}}"
WORK_DIR="target/openapi-contract"
GENERATED="$WORK_DIR/generated.openapi.json"
BASELINE="$WORK_DIR/base.openapi.json"

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
oasdiff breaking --fail-on ERR "$BASELINE" "$GENERATED"
