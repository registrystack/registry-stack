#!/usr/bin/env python3
"""Generate or check shared package sum files for committed Evidence bundles."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[3]
EVIDENCE_ROOT = REPOSITORY / "products" / "evidence"
EXTRA_PACKAGES = (
    REPOSITORY
    / "products"
    / "breg"
    / "acceptance"
    / "farmer-landholding-evidence"
    / "evidence"
    / "provider",
)


def package_roots() -> list[Path]:
    roots = {path.parent for path in EVIDENCE_ROOT.rglob("evidence.yaml")}
    roots.update(path for path in EXTRA_PACKAGES if (path / "evidence.yaml").is_file())
    return sorted(roots)


def rendered_sum(root: Path) -> bytes:
    lines = []
    for path in sorted(path for path in root.rglob("*") if path.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative == "SHA256SUMS":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {relative}\n")
    return "".join(lines).encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    drift = []
    for root in package_roots():
        output = root / "SHA256SUMS"
        expected = rendered_sum(root)
        if args.write:
            output.write_bytes(expected)
        elif not output.is_file() or output.read_bytes() != expected:
            drift.append(root.relative_to(REPOSITORY).as_posix())
    if drift:
        for root in drift:
            print(f"Evidence package sum file is stale: {root}")
        print("Run products/evidence/scripts/generate-package-sums.py --write")
        return 1
    print(f"Evidence package sum files reproduce exactly ({len(package_roots())} packages).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
