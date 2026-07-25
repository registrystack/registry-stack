#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reject drift between the two product-owned advisory checker copies."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NOTARY_CHECKER = ROOT / "products/notary/scripts/check_advisory_baselines.py"
RELAY_CHECKER = ROOT / "crates/registry-relay/scripts/check_advisory_baselines.py"


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def check_identical(left: Path, right: Path) -> str | None:
    try:
        left_bytes = left.read_bytes()
        right_bytes = right.read_bytes()
    except OSError as exc:
        return f"cannot read advisory checker copy: {exc}"
    if left_bytes != right_bytes:
        return (
            "advisory checker copies differ: "
            f"{display_path(left)} != {display_path(right)}"
        )
    return None


def main() -> int:
    error = check_identical(NOTARY_CHECKER, RELAY_CHECKER)
    if error:
        print(error, file=sys.stderr)
        return 1
    print("advisory checker copies are byte-identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
