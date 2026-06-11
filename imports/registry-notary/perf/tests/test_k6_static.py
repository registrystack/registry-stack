from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
K6_DIR = ROOT / "perf" / "k6"
PERF_WORKFLOW = ROOT / ".github" / "workflows" / "perf-smoke.yml"
COMMON_JS = K6_DIR / "lib" / "common.js"
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


def test_perf_workflow_enforces_k6_thresholds() -> None:
    workflow = PERF_WORKFLOW.read_text(encoding="utf-8")
    common_js = COMMON_JS.read_text(encoding="utf-8")

    assert "REGISTRY_NOTARY_NO_THRESHOLD=1" not in workflow
    assert "REGISTRY_NOTARY_NO_THRESHOLD" in common_js
    assert "'http_req_duration{expected_status:false}'" in common_js
