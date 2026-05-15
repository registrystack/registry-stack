# Test Fixtures

This directory contains synthetic, PII-free test data for Wave 1 integration tests.

## Generated Fixtures

All fixtures are deterministically regenerated from a fixed seed (seed=42) by `scripts/generate_fixtures.sh`. They are committed to the repository for test stability and fast CI.

### Primary Dataset: social_registry

Three representations of the same 1000-row dataset, all with identical content:

- **social_registry.csv** (58 KB)
  CSV format with header row. Used by Track 2 (CSV format tests) and Wave 0 format-decoupling tests.

- **social_registry.xlsx** (48 KB)
  XLSX with two sheets:
  - `metadata`: summary info (dataset name, resource name, row count, generation timestamp)
  - `data`: the 1000 data rows with headers
  Used by Track 3 (XLSX format tests) and integration tests.

- **social_registry.parquet** (28 KB)
  Arrow Parquet file. Used by Track 4 (Parquet format tests) and as the reference format for binary comparison.

### Schema

All three formats represent the same 7 columns:

| Column | Type | Notes |
|--------|------|-------|
| `beneficiary_id` | Integer | Unique, 1000–2000 |
| `household_size` | Integer | 1–8 |
| `municipality_code` | String (5 chars) | From fixed set: AA001–AA020 |
| `program` | String | One of: family_allowance, housing_support, food_subsidy |
| `amount_eur` | Number | 100.0–2500.0, two decimals |
| `joined_date` | Date | YYYY-MM-DD, 2018-01-01 to 2026-04-30 |
| `last_updated` | Timestamp | YYYY-MM-DD, nullable (~10% null) |

### Malformed & Mismatched Fixtures

Test data for error and validation paths:

- **malformed_csv_truncated.csv** (17 KB)
  CSV file that starts with a valid header and ~300 well-formed rows, then truncates mid-record (incomplete final row). Used by Track 2 (malformed CSV test).

- **xlsx_type_mismatch.xlsx** (47 KB)
  XLSX matching the schema shape but with `joined_date` column containing non-date strings in rows 3, 5, and 7 ("around march 2022", "n/a", "invalid"). Used by Track 5 (schema validation test for date parsing).

- **parquet_schema_mismatch.parquet** (29 KB)
  Parquet with the standard 7 columns plus an extra column `internal_notes` (String) not declared in the schema. Used by Track 5 (strict-extra-column test).

## Generation

### Regenerate

```bash
./scripts/generate_fixtures.sh
```

The script:
1. Creates a temporary Python venv
2. Installs openpyxl, pyarrow, pandas
3. Runs an inline Python generator with seed=42
4. Produces all six fixture files atomically

Output is idempotent: re-running produces byte-for-byte identical files (verified with MD5).

### Reproducibility

The Python random seed is hardcoded to 42. Regeneration always produces the same data. This ensures:
- CI stability (no flaky tests from data variance)
- Easy comparison across test runs
- Deterministic test coverage

## Verification Commands

```bash
# CSV: first three rows
head -3 fixtures/social_registry.csv

# XLSX: sheet names and row count
python3 -c "import openpyxl; wb=openpyxl.load_workbook('fixtures/social_registry.xlsx'); print(f'Sheets: {wb.sheetnames}, Data rows: {wb[\"data\"].max_row - 1}')"

# Parquet: schema and row count
python3 -c "import pyarrow.parquet as pq; t=pq.read_table('fixtures/social_registry.parquet'); print(f'Schema: {t.schema.names}\\nRows: {t.num_rows}')"

# Malformed CSV: should end mid-row
tail -1 fixtures/malformed_csv_truncated.csv

# XLSX mismatch: check joined_date strings
python3 -c "import openpyxl; wb=openpyxl.load_workbook('fixtures/xlsx_type_mismatch.xlsx'); ws=wb['data']; print([ws[f'F{i}'].value for i in range(3, 8)])"

# Parquet mismatch: extra column present
python3 -c "import pyarrow.parquet as pq; t=pq.read_table('fixtures/parquet_schema_mismatch.parquet'); print(f'Columns: {t.schema.names}')"
```

## Track Dependencies

- **Track 2 (CSV format)**: uses `social_registry.csv` (well-formed) and `malformed_csv_truncated.csv` (malformed)
- **Track 3 (XLSX format)**: uses `social_registry.xlsx` and `xlsx_type_mismatch.xlsx`
- **Track 4 (Parquet format)**: uses `social_registry.parquet` and `parquet_schema_mismatch.parquet`
- **Track 5 (Schema validation)**: uses all mismatched fixtures to test the §4 rule table
- **Track 6 (Integration)**: uses the three primary fixtures for end-to-end ingest + registration tests
