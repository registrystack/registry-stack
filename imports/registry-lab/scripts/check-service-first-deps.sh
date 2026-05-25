#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"

resolve_dir() {
  local raw="$1"
  local candidate
  if [[ "${raw}" = /* ]]; then
    candidate="${raw}"
  else
    candidate="${demo_dir}/${raw}"
  fi
  python3 - "${candidate}" <<'PY'
import sys
from pathlib import Path

print(Path(sys.argv[1]).expanduser().resolve(strict=False))
PY
}

diagnose_missing() {
  local name="$1"
  local env_var="$2"
  local raw="$3"
  local resolved="$4"
  local expected="$5"
  cat >&2 <<EOF
Missing ${name} checkout required for the service-first discovery path.
  looked at: ${resolved}
  configured by: ${env_var:-default sibling checkout}
  current value: ${raw}
  expected: ${expected}

Fix:
  export ${env_var}=/absolute/path/to/${name}
or place ${name} next to registry-lab at:
  ${demo_dir}/../${name}
EOF
}

manifest_path() {
  local raw="${REGISTRY_MANIFEST_REPO:-../registry-manifest}"
  local resolved
  resolved="$(resolve_dir "${raw}")"
  if [[ ! -f "${resolved}/Cargo.toml" ]] || ! grep -R --include 'Cargo.toml' 'name = "registry-manifest-cli"' "${resolved}" >/dev/null 2>&1; then
    diagnose_missing "registry-manifest" "REGISTRY_MANIFEST_REPO" "${raw}" "${resolved}" \
      "Cargo.toml containing the registry-manifest-cli package"
    return 1
  fi
  printf '%s\n' "${resolved}"
}

atlas_path() {
  local raw="${REGISTRY_ATLAS_SOURCE_DIR:-../registry-atlas}"
  local resolved
  resolved="$(resolve_dir "${raw}")"
  if [[ ! -f "${resolved}/Cargo.toml" ]] || [[ ! -d "${resolved}/crates/semantic-asset-discovery-core" ]] || [[ ! -d "${resolved}/crates/semantic-asset-discovery-cli" ]]; then
    diagnose_missing "registry-atlas" "REGISTRY_ATLAS_SOURCE_DIR" "${raw}" "${resolved}" \
      "Cargo.toml plus crates/semantic-asset-discovery-core and crates/semantic-asset-discovery-cli"
    return 1
  fi
  printf '%s\n' "${resolved}"
}

usage() {
  cat >&2 <<'EOF'
usage: scripts/check-service-first-deps.sh manifest|atlas|all|manifest-path|atlas-path

Checks the sibling repositories needed by the service-first discovery demo.
REGISTRY_MANIFEST_REPO and REGISTRY_ATLAS_SOURCE_DIR override the defaults.
EOF
}

case "${1:-all}" in
  manifest)
    manifest_path >/dev/null
    ;;
  atlas)
    atlas_path >/dev/null
    ;;
  all)
    manifest_path >/dev/null
    atlas_path >/dev/null
    ;;
  manifest-path)
    manifest_path
    ;;
  atlas-path)
    atlas_path
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 2
    ;;
esac
