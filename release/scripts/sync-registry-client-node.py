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
    "casework": ROOT / "crates" / "registry-casework-client-node",
}
# napi-rs platform package name to the Rust target triple it carries, following the
# convention swc, rolldown, and oxc use for their own platform package READMEs.
PLATFORM_TRIPLES = {
    "darwin-arm64": "aarch64-apple-darwin",
    "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
    "linux-x64-gnu": "x86_64-unknown-linux-gnu",
}
PLATFORM_README = """# `@registrystack/client-{platform}`

This is the **{triple}** native binary package for
[`@registrystack/client`](https://www.npmjs.com/package/@registrystack/client).
It is installed automatically as an optional dependency of that package at the
same version. Do not depend on it directly. See
https://github.com/registrystack/registry-stack for details.
"""


def expected_files() -> dict[Path, bytes]:
    files: dict[Path, bytes] = {}
    license_text = (ROOT / "LICENSE").read_bytes()
    for destination in (
        TARGET,
        TARGET / "npm" / "darwin-arm64",
        TARGET / "npm" / "linux-arm64-gnu",
        TARGET / "npm" / "linux-x64-gnu",
        ROOT / "crates" / "registry-breg-client-node",
        ROOT / "crates" / "registry-casework-client-node",
        ROOT / "crates" / "registry-breg-client-py",
        ROOT / "crates" / "registry-casework-client-py",
        ROOT / "crates" / "registry-stack-client-py",
    ):
        files[destination / "LICENSE"] = license_text
    # The root TARGET README is authored by hand; only the platform packages, which
    # npm always includes a README.md for regardless of `files`, get one generated.
    for platform, triple in PLATFORM_TRIPLES.items():
        files[TARGET / "npm" / platform / "README.md"] = PLATFORM_README.format(
            platform=platform, triple=triple
        ).encode()
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
