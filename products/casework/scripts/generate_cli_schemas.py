#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate command report contracts directly from the owning Rust DTOs."""
from __future__ import annotations
import argparse
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "products/casework/contracts/cli"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="casework-reports-") as directory:
        generated = Path(directory)
        subprocess.run(["cargo", "run", "--locked", "--offline", "-q", "-j2", "-p", "registry-caseworkctl", "--features", "schema", "--example", "report-schemas", "--", "--output", str(generated)], cwd=ROOT, check=True)
        expected = {path.name: path.read_bytes() for path in generated.glob("*.schema.json")}
        actual = {path.name: path.read_bytes() for path in OUTPUT.glob("*.schema.json")}
        if arguments.check:
            if expected != actual:
                raise SystemExit("Casework report schemas differ; run generate_cli_schemas.py")
        else:
            OUTPUT.mkdir(parents=True, exist_ok=True)
            for name in actual.keys() - expected.keys():
                (OUTPUT / name).unlink()
            for name, contents in expected.items():
                (OUTPUT / name).write_bytes(contents)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
