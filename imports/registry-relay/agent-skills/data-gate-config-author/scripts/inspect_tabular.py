#!/usr/bin/env python3
"""Inspect CSV, XLSX, or Parquet files for data_gate config drafting.

Outputs JSON with sheet/table names, headers, inferred lightweight types,
null counts, and a small redacted sample. Dependencies are optional:

- CSV uses the Python standard library.
- XLSX uses openpyxl if installed.
- Parquet uses pyarrow first, then duckdb if installed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SENSITIVE_RE = re.compile(
    r"(name|email|phone|mobile|address|ssn|national|passport|birth|dob|note|comment)",
    re.IGNORECASE,
)


def normalize_header(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    text = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower()
    if not text:
        return "column"
    if text[0].isdigit():
        return f"col_{text}"
    return text


def redact(header: str, value: Any, show_samples: bool) -> Any:
    if value is None:
        return None
    text = str(value)
    if not text:
        return ""
    if not show_samples or SENSITIVE_RE.search(header):
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        return f"<redacted:{digest}>"
    if len(text) > 80:
        return text[:77] + "..."
    return text


def infer_type(values: list[Any]) -> str:
    non_empty = [v for v in values if v not in (None, "")]
    if not non_empty:
        return "string"

    bools = {"true", "false", "yes", "no", "0", "1"}
    if all(str(v).strip().lower() in bools for v in non_empty):
        return "boolean"

    if all(re.fullmatch(r"-?\d+", str(v).strip()) for v in non_empty):
        return "integer"

    if all(re.fullmatch(r"-?\d+(\.\d+)?", str(v).strip()) for v in non_empty):
        return "number"

    date_like = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}")
    if all(date_like.fullmatch(str(v).strip()) for v in non_empty):
        return "date"

    return "string"


def summarize_table(
    name: str, headers: list[str], rows: list[list[Any]], show_samples: bool
) -> dict[str, Any]:
    normalized = [normalize_header(h) for h in headers]
    duplicates = [item for item, count in Counter(normalized).items() if count > 1]
    columns = []
    for idx, header in enumerate(normalized):
        values = [row[idx] if idx < len(row) else None for row in rows]
        non_empty = sum(1 for v in values if v not in (None, ""))
        columns.append(
            {
                "name": header,
                "original_name": "" if idx >= len(headers) or headers[idx] is None else str(headers[idx]),
                "inferred_type": infer_type(values),
                "nullable": non_empty < len(values),
                "sample": [redact(header, v, show_samples) for v in values[:3]],
            }
        )

    sample_rows = []
    for row in rows[:3]:
        sample_rows.append(
            {
                normalized[idx]: redact(
                    normalized[idx], row[idx] if idx < len(row) else None, show_samples
                )
                for idx in range(len(normalized))
            }
        )

    return {
        "name": name,
        "row_count_sampled": len(rows),
        "columns": columns,
        "duplicate_normalized_headers": duplicates,
        "sample_rows": sample_rows,
    }


def inspect_csv(path: Path, sample_size: int, show_samples: bool) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    sample = raw[:8192]
    dialect = csv.Sniffer().sniff(sample)
    reader = csv.reader(raw.splitlines(), dialect)
    headers = next(reader)
    rows = []
    for _, row in zip(range(sample_size), reader):
        rows.append(row)
    result = summarize_table(path.stem, headers, rows, show_samples)
    result["format"] = "csv"
    result["delimiter"] = dialect.delimiter
    return {"path": str(path), "tables": [result]}


def inspect_xlsx(path: Path, sample_size: int, show_samples: bool) -> dict[str, Any]:
    try:
        import openpyxl  # type: ignore
    except ImportError as exc:
        raise SystemExit("openpyxl is required to inspect XLSX files") from exc

    workbook = openpyxl.load_workbook(path, read_only=True, data_only=True)
    tables = []
    for sheet in workbook.worksheets:
        rows_iter = sheet.iter_rows(values_only=True)
        headers = None
        for row in rows_iter:
            if row and any(cell not in (None, "") for cell in row):
                headers = list(row)
                break
        if headers is None:
            tables.append({"name": sheet.title, "empty": True})
            continue
        rows = []
        for _, row in zip(range(sample_size), rows_iter):
            rows.append(list(row))
        table = summarize_table(sheet.title, headers, rows, show_samples)
        table["format"] = "xlsx"
        table["sheet"] = sheet.title
        tables.append(table)
    return {"path": str(path), "tables": tables}


def inspect_parquet(path: Path, sample_size: int, show_samples: bool) -> dict[str, Any]:
    try:
        import pyarrow.parquet as pq  # type: ignore

        pf = pq.ParquetFile(path)
        schema = pf.schema_arrow
        batch = next(pf.iter_batches(batch_size=sample_size), None)
        rows = [] if batch is None else batch.to_pylist()
        headers = [field.name for field in schema]
        matrix = [[row.get(header) for header in headers] for row in rows]
        table = summarize_table(path.stem, headers, matrix, show_samples)
        table["format"] = "parquet"
        table["parquet_schema"] = [
            {"name": field.name, "physical_type": str(field.type), "nullable": field.nullable}
            for field in schema
        ]
        return {"path": str(path), "tables": [table]}
    except ImportError:
        pass

    try:
        import duckdb  # type: ignore

        con = duckdb.connect()
        description = con.execute(f"DESCRIBE SELECT * FROM read_parquet('{path}')").fetchall()
        headers = [row[0] for row in description]
        rows = con.execute(f"SELECT * FROM read_parquet('{path}') LIMIT {sample_size}").fetchall()
        table = summarize_table(path.stem, headers, [list(row) for row in rows], show_samples)
        table["format"] = "parquet"
        table["parquet_schema"] = [
            {"name": row[0], "physical_type": row[1], "nullable": str(row[2]).upper() != "NO"}
            for row in description
        ]
        return {"path": str(path), "tables": [table]}
    except ImportError as exc:
        raise SystemExit("pyarrow or duckdb is required to inspect Parquet files") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--sample-size", type=int, default=50)
    parser.add_argument(
        "--show-samples",
        action="store_true",
        help="show non-sensitive sample values; default redacts all non-empty values",
    )
    args = parser.parse_args()

    path = Path(args.path).expanduser()
    suffix = path.suffix.lower()
    if suffix == ".csv":
        result = inspect_csv(path, args.sample_size, args.show_samples)
    elif suffix in {".xlsx", ".xlsm"}:
        result = inspect_xlsx(path, args.sample_size, args.show_samples)
    elif suffix == ".parquet":
        result = inspect_parquet(path, args.sample_size, args.show_samples)
    else:
        raise SystemExit(f"unsupported file extension: {suffix}")

    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
