#!/usr/bin/env python3
"""Verify the k6 perf helpers keep their threshold gate active."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMON_JS = ROOT / "perf" / "k6" / "lib" / "common.js"


def main() -> int:
    common_js = COMMON_JS.read_text(encoding="utf-8")

    if re.search(r"\bREGISTRY_RELAY_NO_THRESHOLD\b", common_js) is None:
        raise SystemExit("REGISTRY_RELAY_NO_THRESHOLD bypass is missing from k6 common.js.")
    if "http_req_duration{expected_status:false}" not in common_js:
        raise SystemExit("k6 latency thresholds are missing from common.js.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
