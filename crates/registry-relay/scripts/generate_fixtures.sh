#!/usr/bin/env bash
set -euo pipefail

# Generate synthetic test fixtures for Wave 1 Track 7
# All data is PII-free and reproducible from a fixed seed

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FIXTURES_DIR="$PROJECT_ROOT/fixtures"

# Create fixtures directory if needed
mkdir -p "$FIXTURES_DIR"

FIXTURES_DIR="$FIXTURES_DIR" uv run --with openpyxl --with pyarrow --with pandas python3 <<'PYTHON_EOF'
import csv
import random
import string
import os
from datetime import datetime, timedelta
from pathlib import Path

# Fixed seed for reproducibility
random.seed(42)

# Output paths
fixtures_dir = Path(os.environ['FIXTURES_DIR'])
xlsx_path = fixtures_dir / "social_registry.xlsx"
example_xlsx_path = fixtures_dir / "example_social_registry.xlsx"
csv_path = fixtures_dir / "social_registry.csv"
parquet_path = fixtures_dir / "social_registry.parquet"
malformed_csv_path = fixtures_dir / "malformed_csv_truncated.csv"
xlsx_mismatch_path = fixtures_dir / "xlsx_type_mismatch.xlsx"
parquet_mismatch_path = fixtures_dir / "parquet_schema_mismatch.parquet"

# Schema definition
COLUMNS = [
    "beneficiary_id",
    "household_size",
    "municipality_code",
    "program",
    "amount_eur",
    "joined_date",
    "last_updated"
]

PROGRAMS = ["family_allowance", "housing_support", "food_subsidy"]
MUNICIPALITY_CODES = [f"AA{i:03d}" for i in range(1, 21)]

# Generate base data (~1000 rows)
def generate_data(rows=1000):
    data = []
    beneficiary_ids = set()
    base_date = datetime(2018, 1, 1)
    end_date = datetime(2026, 4, 30)
    days_range = (end_date - base_date).days

    for _ in range(rows):
        # Unique beneficiary_id in range 1000-2000
        while True:
            bid = random.randint(1000, 2000)
            if bid not in beneficiary_ids:
                beneficiary_ids.add(bid)
                break

        household_size = random.randint(1, 8)
        municipality_code = random.choice(MUNICIPALITY_CODES)
        program = random.choice(PROGRAMS)
        amount_eur = round(random.uniform(100.0, 2500.0), 2)

        # Random date in range
        joined_offset = random.randint(0, days_range)
        joined_date = (base_date + timedelta(days=joined_offset)).strftime("%Y-%m-%d")

        # Last updated ~90% of the time
        if random.random() < 0.9:
            updated_offset = random.randint(0, days_range)
            last_updated = (base_date + timedelta(days=updated_offset)).strftime("%Y-%m-%d")
        else:
            last_updated = None

        data.append({
            "beneficiary_id": bid,
            "household_size": household_size,
            "municipality_code": municipality_code,
            "program": program,
            "amount_eur": amount_eur,
            "joined_date": joined_date,
            "last_updated": last_updated
        })

    return data

# Generate main fixtures
data = generate_data(1000)

# Write CSV
with open(csv_path, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(data)

# Write XLSX with two sheets: metadata and data
import openpyxl
from openpyxl.utils import get_column_letter

wb = openpyxl.Workbook()
wb.remove(wb.active)

# Metadata sheet
metadata_sheet = wb.create_sheet("metadata")
metadata_sheet['A1'] = "Dataset"
metadata_sheet['B1'] = "social_registry"
metadata_sheet['A2'] = "Resource"
metadata_sheet['B2'] = "beneficiaries"
metadata_sheet['A3'] = "Rows"
metadata_sheet['B3'] = len(data)
metadata_sheet['A4'] = "Generated"
metadata_sheet['B4'] = "2026-01-01T00:00:00"

# Data sheet
data_sheet = wb.create_sheet("data")
for i, col in enumerate(COLUMNS, 1):
    data_sheet.cell(1, i, col)

for row_idx, row_data in enumerate(data, 2):
    for col_idx, col in enumerate(COLUMNS, 1):
        value = row_data[col]
        data_sheet.cell(row_idx, col_idx, value)

wb.save(xlsx_path)

# Write entity-shaped XLSX used by config/example.yaml and release smoke.
example_wb = openpyxl.Workbook()
example_wb.remove(example_wb.active)

households_sheet = example_wb.create_sheet("Households")
households_sheet.append(["household_id", "region_code", "enrollment_date"])
regions = ["north", "central", "south"]
for idx in range(1, 13):
    households_sheet.append([
        f"hh-{idx:03d}",
        regions[(idx - 1) % len(regions)],
        (datetime(2025, 1, 1) + timedelta(days=idx)).strftime("%Y-%m-%d"),
    ])

individuals_sheet = example_wb.create_sheet("Individuals")
individuals_sheet.append([
    "individual_id",
    "household_id",
    "municipality_code",
    "payment_amount",
])
municipalities = ["AA001", "AA002", "AA003"]
individual_id = 1
for household_idx in range(1, 13):
    for _member_idx in range(1, 4):
        individuals_sheet.append([
            f"ind-{individual_id:03d}",
            f"hh-{household_idx:03d}",
            municipalities[(household_idx - 1) % len(municipalities)],
            100 + (individual_id * 7),
        ])
        individual_id += 1

example_wb.save(example_xlsx_path)

# Write Parquet via pandas for consistency
import pandas as pd

df = pd.DataFrame(data)
df.to_parquet(parquet_path, index=False)

# Malformed CSV: truncated mid-row a few hundred lines in
with open(malformed_csv_path, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=COLUMNS)
    writer.writeheader()
    for i, row in enumerate(data):
        if i < 300:
            writer.writerow(row)
        elif i == 300:
            # Write partial row to truncate mid-record
            f.write(f"{row['beneficiary_id']},{row['household_size']},{row['municipality_code']},{row['program']},")
            break
        else:
            break

# XLSX with type mismatch: dates as strings in some rows
wb_mismatch = openpyxl.Workbook()
wb_mismatch.remove(wb_mismatch.active)
mismatch_sheet = wb_mismatch.create_sheet("data")

for i, col in enumerate(COLUMNS, 1):
    mismatch_sheet.cell(1, i, col)

for row_idx, row_data in enumerate(data, 2):
    for col_idx, col in enumerate(COLUMNS, 1):
        value = row_data[col]
        # Introduce type mismatches in joined_date column (column F = index 6)
        if col == "joined_date":
            if row_idx == 3:  # Row 3: "around march 2022"
                value = "around march 2022"
            elif row_idx == 5:  # Row 5: "n/a"
                value = "n/a"
            elif row_idx == 7:  # Row 7: "invalid"
                value = "invalid"
        mismatch_sheet.cell(row_idx, col_idx, value)

wb_mismatch.save(xlsx_mismatch_path)

# Parquet with extra column not in schema
df_extra = df.copy()
df_extra['internal_notes'] = ['test note'] * len(df_extra)
df_extra.to_parquet(parquet_mismatch_path, index=False)

print(f"Generated {len(data)} rows of synthetic data")
print(f"  CSV: {csv_path}")
print(f"  XLSX: {xlsx_path}")
print(f"  Entity example XLSX: {example_xlsx_path}")
print(f"  Parquet: {parquet_path}")
print(f"  Malformed CSV: {malformed_csv_path}")
print(f"  XLSX type mismatch: {xlsx_mismatch_path}")
print(f"  Parquet schema mismatch: {parquet_mismatch_path}")

PYTHON_EOF
