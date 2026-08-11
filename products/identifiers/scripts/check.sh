#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT

cd "${repo_root}"
python3 -m unittest discover \
  --start-directory products/identifiers/scripts \
  --pattern 'test_*.py'
products/identifiers/scripts/generate.py \
  --output "${temporary}/catalog.v1.json"
cmp products/identifiers/generated/catalog.v1.json \
  "${temporary}/catalog.v1.json"
echo "Registry Stack identifier catalog is complete and reproducible."
