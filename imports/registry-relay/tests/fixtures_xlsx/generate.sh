#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Generate XLSX test fixtures for XlsxFormat integration tests.
#
# Requires Python 3 + openpyxl. Install with:
#   uv venv .venv && source .venv/bin/activate && uv pip install openpyxl
# or just:
#   pip install openpyxl
#
# Run from the repository root or from this directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python3 - <<'PYEOF'
import os, sys
from datetime import date, datetime

try:
    import openpyxl
    from openpyxl import Workbook
except ImportError:
    print("openpyxl is not installed. Run: pip install openpyxl", file=sys.stderr)
    sys.exit(1)

out = os.path.dirname(os.path.abspath(__file__))

# ── simple.xlsx ──────────────────────────────────────────────────────────────
# Sheet "data", header at row 1, 5 data rows.
# Columns: id (int), name (str), amount (float), active (bool), joined (date).
wb = Workbook()
ws = wb.active
ws.title = "data"
ws.append(["id", "name", "amount", "active", "joined"])
rows = [
    (1, "Alice",  1250.50, True,  date(2020, 1, 15)),
    (2, "Bob",    890.00,  False, date(2021, 6, 1)),
    (3, "Carol",  3420.75, True,  date(2019, 11, 30)),
    (4, "David",  210.00,  True,  date(2022, 3, 8)),
    (5, "Eve",    5000.00, False, date(2018, 7, 22)),
]
for r in rows:
    ws.append(list(r))
# Format the date column so calamine parses it as DateTime.
for row_cells in ws.iter_rows(min_row=2, max_row=6, min_col=5, max_col=5):
    for cell in row_cells:
        cell.number_format = "YYYY-MM-DD"
wb.save(os.path.join(out, "simple.xlsx"))
print("wrote simple.xlsx")

# ── two_sheets.xlsx ──────────────────────────────────────────────────────────
# Sheets: "summary" (metadata only) and "details" (actual data).
wb = Workbook()
ws1 = wb.active
ws1.title = "summary"
ws1.append(["Generated", "2026-05-15"])
ws1.append(["Source", "test fixture"])

ws2 = wb.create_sheet("details")
ws2.append(["country", "population"])
ws2.append(["France", 68_000_000])
ws2.append(["Germany", 84_000_000])
ws2.append(["Italy", 60_000_000])
wb.save(os.path.join(out, "two_sheets.xlsx"))
print("wrote two_sheets.xlsx")

# ── with_data_range.xlsx ─────────────────────────────────────────────────────
# Rows 1-4 are human-readable metadata; header is row 5; data rows 6-10.
# data_range hint: A5:E10, header_row: 5
wb = Workbook()
ws = wb.active
ws.title = "Sheet1"
ws["A1"] = "Report Title"
ws["A2"] = "Version: 1.0"
ws["A3"] = "Date: 2026-05-15"
ws["A4"] = ""  # blank separator
ws.append(["id", "name", "amount", "active", "joined"])  # row 5
data_rows = [
    (10, "Frank",  100.0, True,  date(2023, 1, 1)),
    (11, "Grace",  200.0, False, date(2023, 2, 2)),
    (12, "Heidi",  300.0, True,  date(2023, 3, 3)),
    (13, "Ivan",   400.0, False, date(2023, 4, 4)),
    (14, "Judy",   500.0, True,  date(2023, 5, 5)),
]
for r in data_rows:
    ws.append(list(r))
for row_cells in ws.iter_rows(min_row=6, max_row=10, min_col=5, max_col=5):
    for cell in row_cells:
        cell.number_format = "YYYY-MM-DD"
wb.save(os.path.join(out, "with_data_range.xlsx"))
print("wrote with_data_range.xlsx")

# ── mistyped_date.xlsx ───────────────────────────────────────────────────────
# Column "joined" declared as date, but row 3 contains a free-form string.
wb = Workbook()
ws = wb.active
ws.title = "data"
ws.append(["id", "name", "joined"])
ws.append([1, "Alice", date(2020, 1, 15)])
ws.append([2, "Bob",   "not-a-date"])  # bad value
ws.append([3, "Carol", date(2019, 3, 5)])
for row_cells in ws.iter_rows(min_row=2, max_row=2, min_col=3, max_col=3):
    for cell in row_cells:
        cell.number_format = "YYYY-MM-DD"
for row_cells in ws.iter_rows(min_row=4, max_row=4, min_col=3, max_col=3):
    for cell in row_cells:
        cell.number_format = "YYYY-MM-DD"
wb.save(os.path.join(out, "mistyped_date.xlsx"))
print("wrote mistyped_date.xlsx")

print("All fixtures written to", out)
PYEOF
