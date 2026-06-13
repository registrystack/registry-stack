#!/usr/bin/env python3
"""Verify the perf workflow is wired as a k6 threshold gate."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "perf-smoke.yml"
COMMON_JS = ROOT / "perf" / "k6" / "lib" / "common.js"


def active_yaml_lines(text: str) -> str:
    """Return YAML lines that are not whole-line comments.

    Workflow `run:` blocks contain shell, where `#` may appear inside strings
    before active commands. Dropping inline `#...` suffixes can hide active
    threshold bypasses, so only whole-line YAML comments are ignored here.
    """

    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def main() -> int:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    active_workflow = active_yaml_lines(workflow)
    common_js = COMMON_JS.read_text(encoding="utf-8")

    if re.search(r"\bREGISTRY_RELAY_NO_THRESHOLD\b", active_workflow):
        raise SystemExit(
            "perf-smoke.yml must not set REGISTRY_RELAY_NO_THRESHOLD; "
            "CI must enforce latency thresholds."
        )
    if re.search(r"\bREGISTRY_RELAY_NO_THRESHOLD\b", common_js) is None:
        raise SystemExit("REGISTRY_RELAY_NO_THRESHOLD bypass is missing from k6 common.js.")
    if "http_req_duration{expected_status:false}" not in common_js:
        raise SystemExit("k6 latency thresholds are missing from common.js.")
    if "push:" not in active_workflow or "branches: [main]" not in active_workflow:
        raise SystemExit("perf-smoke.yml must run on pushes to main to gate regressions.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
