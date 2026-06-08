from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
K6_DIR = ROOT / "perf" / "k6"
REMOTE_IMPORT_RE = re.compile(
    r"""\b(?:import|export)\b\s*(?:[^'"]+\bfrom\s*)?['"]https?://|\bimport\s*\(\s*['"]https?://"""
)


def test_k6_scripts_do_not_import_remote_code() -> None:
    offenders: list[str] = []
    for path in sorted(K6_DIR.rglob("*.js")):
        rel = path.relative_to(ROOT)
        if REMOTE_IMPORT_RE.search(path.read_text(encoding="utf-8")):
            offenders.append(str(rel))

    assert offenders == [], (
        "k6 scripts must not import remote executable helper code at runtime: "
        + ", ".join(offenders)
    )
