#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATHS=()

for path in "$ROOT/README.md" "$ROOT/src" "$ROOT/tests"; do
  if [[ -e "$path" ]]; then
    PATHS+=("$path")
  fi
done

if rg -n \
  "registry\\.validation\\.report\\.v1|schema:\\s*registry\\.validation|checks\\[\\]\\.(product_report|findings)|YAML parsed successfully|auth\\.oidc\\.(jwks_uri|allowed_typ|leeway_seconds)" \
  "${PATHS[@]}"; then
  echo "stale config vocabulary found" >&2
  exit 1
fi
