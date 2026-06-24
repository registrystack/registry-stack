#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATTERN='registry\.validation\.report\.v1|schema:\s*registry\.validation|checks\[\]\.(product_report|findings)|YAML parsed successfully|auth\.oidc\.(jwks_uri|allowed_typ|leeway_seconds)'
PATHS=(
  "$ROOT/README.md"
  "$ROOT/src/content/docs"
  "$ROOT/src/data"
  "$ROOT/scripts"
)

status=0
if command -v rg >/dev/null 2>&1; then
  rg -n --glob '!scripts/check-stale-config-vocabulary.sh' "$PATTERN" "${PATHS[@]}" || status=$?
else
  grep -RInE --exclude='check-stale-config-vocabulary.sh' "$PATTERN" "${PATHS[@]}" || status=$?
fi

if [[ "$status" -eq 0 ]]; then
  echo "stale config vocabulary found" >&2
  exit 1
elif [[ "$status" -ne 1 ]]; then
  echo "stale config vocabulary search failed with exit code $status" >&2
  exit "$status"
fi
