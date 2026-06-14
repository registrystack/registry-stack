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
  configured by: ${env_var:-default vendored checkout}
  current value: ${raw}
  expected: ${expected}

Fix:
  run: just setup
or run: git submodule update --init --recursive
or set:
  export ${env_var}=/absolute/path/to/${name}
EOF
}

manifest_path() {
  local raw="${REGISTRY_MANIFEST_REPO:-./vendor/registry-manifest}"
  local resolved
  resolved="$(resolve_dir "${raw}")"
  if [[ ! -f "${resolved}/Cargo.toml" ]] || ! grep -R --include 'Cargo.toml' 'name = "registry-manifest-cli"' "${resolved}" >/dev/null 2>&1; then
    diagnose_missing "registry-manifest" "REGISTRY_MANIFEST_REPO" "${raw}" "${resolved}" \
      "Cargo.toml containing the registry-manifest-cli package"
    return 1
  fi
  printf '%s\n' "${resolved}"
}

usage() {
  cat >&2 <<'EOF'
usage: scripts/check-service-first-deps.sh manifest|all|manifest-path

Checks the sibling repositories needed by the service-first discovery demo.
REGISTRY_MANIFEST_REPO overrides the default.
EOF
}

case "${1:-all}" in
  manifest)
    manifest_path >/dev/null
    ;;
  all)
    manifest_path >/dev/null
    ;;
  manifest-path)
    manifest_path
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 2
    ;;
esac
