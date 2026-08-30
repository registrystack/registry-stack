#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python3 "$script_dir/validate_product.py"
python3 "$script_dir/check_source_neutrality.py"
"$script_dir/check-generated.sh"
python3 -m unittest \
  "$script_dir/test_validate_product.py" \
  "$script_dir/test_check_source_neutrality.py" \
  "$script_dir/test_generated_gates.py" \
  "$script_dir/test_quickstart.py" \
  "$script_dir/../demo/support/test_demo.py"

echo "Registry Server product contracts passed"
