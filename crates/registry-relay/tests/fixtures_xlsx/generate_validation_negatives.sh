#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Generate the FC-R3 full-workbook validation fixtures.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export REGISTRY_RELAY_XLSX_FIXTURE_DIR="$SCRIPT_DIR"

python3 - <<'PYEOF'
import os
from openpyxl import Workbook

out = os.environ["REGISTRY_RELAY_XLSX_FIXTURE_DIR"]

wb = Workbook()
ws = wb.active
ws.title = "Projects"
ws.append(["project_id", "district_code", "sector", "status", "calculated"])
ws.append(["PW-001", "D-01", "roads", "active", "=1+1"])
wb.save(os.path.join(out, "formula_outside_projection.xlsx"))

wb = Workbook()
ws = wb.active
ws.title = "Projects"
ws.append(["project_id", "district_code", "sector", "status"])
for index in range(1002):
    project_index = 1000 if index == 1001 else index
    ws.append(
        [
            f"PW-{project_index:04}",
            f"D-{project_index % 10:02}",
            "roads",
            "active",
        ]
    )
wb.save(os.path.join(out, "duplicate_primary_key_after_1000.xlsx"))
PYEOF
