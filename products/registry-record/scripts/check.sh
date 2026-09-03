#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "${repo_root}"

python3 -m unittest discover \
  --start-directory products/registry-record/scripts \
  --pattern 'test_*.py'
echo "Registry Record profile artifacts and fixtures conform."
