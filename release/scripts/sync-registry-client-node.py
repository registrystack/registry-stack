#!/usr/bin/env python3
"""Materialize the unified Node client facades from their owning bindings."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "crates" / "registry-stack-client-node"
PRODUCTS = {
    "discovery": ROOT / "crates" / "registry-discovery-client-node",
    "evidence": ROOT / "crates" / "registry-evidence-client-node",
    "relay": ROOT / "crates" / "registry-relay-client-node",
    "breg": ROOT / "crates" / "registry-breg-client-node",
}


def expected_files() -> dict[Path, bytes]:
    files: dict[Path, bytes] = {}
    license_text = (ROOT / "LICENSE").read_bytes()
    for destination in (
        TARGET,
        TARGET / "npm" / "darwin-arm64",
        TARGET / "npm" / "linux-arm64-gnu",
        TARGET / "npm" / "linux-x64-gnu",
        ROOT / "crates" / "registry-breg-client-node",
        ROOT / "crates" / "registry-breg-client-py",
        ROOT / "crates" / "registry-stack-client-py",
    ):
        files[destination / "LICENSE"] = license_text
    for product, source in PRODUCTS.items():
        destination = TARGET / product
        files[destination / "client.js"] = (source / "client.js").read_bytes()
        files[destination / "client.d.ts"] = (source / "client.d.ts").read_bytes()
        files[destination / "index.d.ts"] = (source / "index.d.ts").read_bytes()
        files[destination / "index.js"] = (
            "'use strict';\n\n"
            f"module.exports = require('../native').load('{product}');\n"
        ).encode()
    return files


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    mismatches = []
    for path, expected in expected_files().items():
        if args.check:
            if not path.is_file() or path.read_bytes() != expected:
                mismatches.append(path.relative_to(ROOT))
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(expected)
    if mismatches:
        for path in mismatches:
            print(f"generated Registry client facade is stale: {path}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
