#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python3 "$SCRIPT_DIR/validate_product.py"
python3 "$SCRIPT_DIR/validate-sdmx-profile.py"
bash "$SCRIPT_DIR/check-source-neutrality.sh"
bash "$SCRIPT_DIR/check-client-contract.sh"
python3 -m unittest \
  "$SCRIPT_DIR/test_validate_product.py" \
  "$SCRIPT_DIR/test_adopter_workflow_openapi.py" \
  "$SCRIPT_DIR/test_validate_sdmx_profile.py"
bash "$SCRIPT_DIR/check-configs.sh"

echo "relay-v2 product contracts passed"
