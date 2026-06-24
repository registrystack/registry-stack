# XLSX Test Fixtures

Fixtures for `tests/format_xlsx.rs` (`XlsxFormat`).

## Regenerating

Requires Python 3 with `openpyxl` installed:

```sh
pip install openpyxl   # or: uv pip install openpyxl
bash tests/fixtures_xlsx/generate.sh
```

## Fixture Descriptions

| File | Sheet(s) | Header row | Data rows | Notes |
|---|---|---|---|---|
| `simple.xlsx` | `data` | 1 | 5 | Five columns: `id` (int), `name` (str), `amount` (float), `active` (bool), `joined` (date). |
| `two_sheets.xlsx` | `summary`, `details` | 1 | 3 in `details` | `summary` has metadata; `details` has country/population. Tests named-sheet selection. |
| `with_data_range.xlsx` | `Sheet1` | 5 | 5 (rows 6–10) | Rows 1–4 are human-readable metadata. Tests `data_range: "A5:E10"` + `header_row: 5`. |
| `mistyped_date.xlsx` | `data` | 1 | 3 | Column `joined` declared as Date, but row 2 contains `"not-a-date"`. Tests parse error handling. |

## Columns in `simple.xlsx` / `with_data_range.xlsx`

| Name | Type | Notes |
|---|---|---|
| `id` | Integer | 1-indexed sequence |
| `name` | String | Person names |
| `amount` | Float | Monetary amounts |
| `active` | Boolean | True/False |
| `joined` | Date | Excel date serial (formatted as `YYYY-MM-DD`) |
