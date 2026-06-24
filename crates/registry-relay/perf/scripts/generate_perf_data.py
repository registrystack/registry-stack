#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pyarrow",
#   "numpy",
# ]
# ///
"""
Deterministic synthetic fixture generator for Registry Relay performance testing.

Fixed seed 42. Re-running produces identical row content. Outputs Parquet and
CSV files plus a manifest.json summarising every generated file.

Usage:
    uv run perf/scripts/generate_perf_data.py --profile medium
    uv run perf/scripts/generate_perf_data.py --profile all --include-5m
    uv run perf/scripts/generate_perf_data.py --profile large --out-dir /tmp/perf
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.csv as pa_csv
import pyarrow.parquet as pq

SEED = 42
GENERATOR_VERSION = 1

# ---- schema constants -------------------------------------------------------

REGION_CODES = [f"R{i:03d}" for i in range(1, 21)]  # R001 .. R020
CATEGORIES = ["clinic", "hospital", "pharmacy"]


# ---- data generation --------------------------------------------------------

def make_rng(seed: int = SEED) -> np.random.Generator:
    return np.random.default_rng(seed)


def build_base_table(rng: np.random.Generator, n: int) -> pa.Table:
    """Generate the core narrow schema (7 columns) for n rows."""
    ids = pa.array([f"fac-{i:06d}" for i in range(n)], type=pa.string())
    region_idx = rng.integers(0, len(REGION_CODES), size=n)
    region_codes = pa.array([REGION_CODES[i] for i in region_idx], type=pa.string())
    capacity = pa.array(rng.integers(10, 500, size=n), type=pa.int32())
    occupancy = pa.array(rng.integers(0, 500, size=n), type=pa.int32())

    # Dates: last_updated between 2020-01-01 and 2025-12-31
    epoch = datetime(2020, 1, 1).toordinal()
    end_epoch = datetime(2025, 12, 31).toordinal()
    last_updated_days = rng.integers(epoch, end_epoch, size=n)
    last_updated = pa.array(
        [datetime.fromordinal(int(d)).strftime("%Y-%m-%d") for d in last_updated_days],
        type=pa.string(),
    )

    # operating_since: 2000-01-01 .. 2019-12-31
    op_epoch = datetime(2000, 1, 1).toordinal()
    op_end_epoch = datetime(2019, 12, 31).toordinal()
    op_days = rng.integers(op_epoch, op_end_epoch, size=n)
    operating_since = pa.array(
        [datetime.fromordinal(int(d)).strftime("%Y-%m-%d") for d in op_days],
        type=pa.string(),
    )

    cat_idx = rng.integers(0, len(CATEGORIES), size=n)
    category = pa.array([CATEGORIES[i] for i in cat_idx], type=pa.string())

    return pa.table(
        {
            "id": ids,
            "region_code": region_codes,
            "capacity": capacity,
            "occupancy": occupancy,
            "last_updated": last_updated,
            "operating_since": operating_since,
            "category": category,
        }
    )


def build_wide_table(rng: np.random.Generator, n: int, extra_cols: int = 95) -> pa.Table:
    """Core 7 columns + extra_cols numeric/string filler columns (total >= 100)."""
    base = build_base_table(rng, n)
    extra_arrays = {}
    for i in range(extra_cols):
        if i % 3 == 0:
            # string filler
            letters = rng.integers(0, 26, size=(n, 4))
            vals = pa.array(
                ["".join(chr(ord("a") + int(c)) for c in row) for row in letters],
                type=pa.string(),
            )
        else:
            vals = pa.array(rng.integers(0, 10_000, size=n), type=pa.int32())
        extra_arrays[f"extra_{i:03d}"] = vals
    return pa.table({**{c: base.column(c) for c in base.schema.names}, **extra_arrays})


def build_strings_table(rng: np.random.Generator, n: int, str_cols: int = 43) -> pa.Table:
    """Core 7 columns + str_cols string columns of varied lengths."""
    base = build_base_table(rng, n)
    extra_arrays = {}
    lengths = [4, 8, 12, 20, 32, 64]
    for i in range(str_cols):
        length = lengths[i % len(lengths)]
        letters = rng.integers(0, 26, size=(n, length))
        vals = pa.array(
            ["".join(chr(ord("a") + int(c)) for c in row) for row in letters],
            type=pa.string(),
        )
        extra_arrays[f"str_{i:03d}"] = vals
    return pa.table({**{c: base.column(c) for c in base.schema.names}, **extra_arrays})


# ---- fixture writing --------------------------------------------------------

def write_parquet(table: pa.Table, path: Path) -> None:
    pq.write_table(table, path, write_statistics=True, compression="snappy")


def write_csv(table: pa.Table, path: Path) -> None:
    pa_csv.write_csv(table, path)


def file_info(path: Path, table: pa.Table, fixture_type: str) -> dict:
    schema = [
        {"name": field.name, "type": str(field.type)}
        for field in table.schema
    ]
    return {
        "path": str(path),
        "format": fixture_type,
        "row_count": table.num_rows,
        "column_count": table.num_columns,
        "file_size_bytes": path.stat().st_size,
        "schema": schema,
        "generator_version": GENERATOR_VERSION,
        "seed": SEED,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---- profile definitions ----------------------------------------------------

def fixtures_for_profile(profile: str, include_5m: bool) -> list[str]:
    """Return the list of fixture keys to generate for the given profile."""
    small = ["1k"]
    medium = ["1k", "10k", "100k", "100k.csv"]
    large = ["1k", "10k", "100k", "1m", "wide_100k", "strings_100k", "100k.csv"]
    all_fixtures = list(large)
    if include_5m:
        all_fixtures.append("5m")
    mapping = {
        "small": small,
        "medium": medium,
        "large": large,
        "all": all_fixtures,
    }
    return mapping[profile]


FIXTURE_ROW_COUNTS = {
    "1k": 1_000,
    "10k": 10_000,
    "100k": 100_000,
    "100k.csv": 100_000,
    "1m": 1_000_000,
    "5m": 5_000_000,
    "wide_100k": 100_000,
    "strings_100k": 100_000,
}


# ---- main -------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic perf fixtures for Registry Relay.")
    parser.add_argument(
        "--profile",
        choices=["small", "medium", "large", "all"],
        default="all",
        help="Which fixture set to generate (default: all).",
    )
    parser.add_argument(
        "--include-5m",
        action="store_true",
        help="Also generate the optional 5M-row parquet (requires ~8 GB RAM).",
    )
    parser.add_argument(
        "--out-dir",
        default="perf/fixtures/generated/",
        help="Output directory (default: perf/fixtures/generated/).",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    fixture_keys = fixtures_for_profile(args.profile, args.include_5m)

    # Pre-generate all tables so each fixture draws from a fresh deterministic
    # slice of the RNG state. We generate the largest table for each schema
    # type once, then slice it for smaller fixtures.
    print(f"Generating fixtures: {fixture_keys}")

    # Build the base tables we need.
    max_base_rows = max(
        FIXTURE_ROW_COUNTS[k] for k in fixture_keys if k not in ("wide_100k", "strings_100k")
    ) if any(k not in ("wide_100k", "strings_100k") for k in fixture_keys) else 1_000

    print(f"Building base table ({max_base_rows:,} rows)...")
    # Use a fresh RNG for each table type so order-of-profile doesn't change hashes.
    base_rng = make_rng(SEED)
    base_large = build_base_table(base_rng, max_base_rows)

    wide_table = None
    strings_table = None

    manifest_entries = []

    for key in fixture_keys:
        n = FIXTURE_ROW_COUNTS[key]

        if key == "wide_100k":
            if wide_table is None:
                print("Building wide table (100k rows, 102 columns)...")
                wide_rng = make_rng(SEED + 1)
                wide_table = build_wide_table(wide_rng, n)
            table = wide_table
            path = out_dir / "clinic_capacity_wide_100k.parquet"
            print(f"Writing {path} ...")
            write_parquet(table, path)
            manifest_entries.append(file_info(path, table, "parquet"))

        elif key == "strings_100k":
            if strings_table is None:
                print("Building strings table (100k rows, 50 columns)...")
                str_rng = make_rng(SEED + 2)
                strings_table = build_strings_table(str_rng, n)
            table = strings_table
            path = out_dir / "clinic_capacity_strings_100k.parquet"
            print(f"Writing {path} ...")
            write_parquet(table, path)
            manifest_entries.append(file_info(path, table, "parquet"))

        elif key == "100k.csv":
            table = base_large.slice(0, n) if n <= base_large.num_rows else build_base_table(make_rng(SEED), n)
            path = out_dir / "clinic_capacity_100k.csv"
            print(f"Writing {path} ...")
            write_csv(table, path)
            manifest_entries.append(file_info(path, table, "csv"))

        else:
            # Standard parquet files: 1k, 10k, 100k, 1m, 5m
            if n <= base_large.num_rows:
                table = base_large.slice(0, n)
            else:
                # Need more rows than base_large; build fresh.
                print(f"Building {n:,}-row base table...")
                extra_rng = make_rng(SEED + n)
                table = build_base_table(extra_rng, n)
            row_label = key.replace("k", "k").replace("m", "m")
            path = out_dir / f"clinic_capacity_{row_label}.parquet"
            print(f"Writing {path} ...")
            write_parquet(table, path)
            manifest_entries.append(file_info(path, table, "parquet"))

    # Write manifest
    manifest_path = out_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(
            {
                "generator_version": GENERATOR_VERSION,
                "seed": SEED,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "fixtures": manifest_entries,
            },
            f,
            indent=2,
        )
    print(f"\nManifest written: {manifest_path}")

    # Summary table
    print(f"\n{'File':<50} {'Rows':>10} {'Cols':>6} {'Size':>12}")
    print("-" * 82)
    for entry in manifest_entries:
        size_mb = entry["file_size_bytes"] / (1024 * 1024)
        print(
            f"{entry['path']:<50} {entry['row_count']:>10,} {entry['column_count']:>6} {size_mb:>10.1f}MB"
        )


if __name__ == "__main__":
    main()
