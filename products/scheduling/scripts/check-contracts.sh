#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python3 "$script_dir/validate_contracts.py"
python3 -m unittest \
  "$script_dir/test_validate_contracts.py"

echo "Scheduling product contracts passed"
