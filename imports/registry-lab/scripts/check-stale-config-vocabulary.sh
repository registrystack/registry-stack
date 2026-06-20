#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

if ! command -v rg >/dev/null 2>&1; then
  printf 'Error: ripgrep (rg) is required but not installed.\n' >&2
  exit 1
fi

failures=0

check_absent() {
  local pattern="$1"
  shift
  local -a paths=("$@")
  if rg -n --glob '!output/**' --glob '!vendor/**' --glob '!scripts/check-stale-config-vocabulary.sh' "${pattern}" "${paths[@]}"; then
    failures=$((failures + 1))
  fi
}

check_absent 'registry\.validation\.report\.v1' config scripts docs README.md justfile
check_absent 'allowed_typ:' config scripts docs README.md
check_absent '^[[:space:]]+leeway_seconds:' config scripts docs README.md

if [[ "${failures}" -ne 0 ]]; then
  printf 'stale config vocabulary check failed with %s violation set(s)\n' "${failures}" >&2
  exit 1
fi

printf 'stale config vocabulary check passed\n'
