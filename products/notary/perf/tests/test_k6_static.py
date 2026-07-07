from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
K6_DIR = ROOT / "perf" / "k6"
COMMON_JS = K6_DIR / "lib" / "common.js"
PERF_CONFIGS = [
    ROOT / "perf" / "config" / "small.yaml",
    ROOT / "perf" / "config" / "medium.yaml",
]
REMOTE_IMPORT_RE = re.compile(
    r"""\b(?:import|export)\b\s*(?:[^'"]+\bfrom\s*)?['"]https?://|\bimport\s*\(\s*['"]https?://"""
)
PURPOSE_RE = re.compile(r"\bpurpose:\s*['\"]([^'\"]+)['\"]")


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


def test_k6_common_js_declares_thresholds() -> None:
    common_js = COMMON_JS.read_text(encoding="utf-8")

    assert re.search(r"\bREGISTRY_NOTARY_NO_THRESHOLD\b", common_js) is not None
    assert "http_req_duration{expected_status:false}" in common_js


def test_k6_purposes_are_allowed_by_perf_configs() -> None:
    requested_purposes = {
        purpose
        for path in sorted(K6_DIR.glob("*.js"))
        for purpose in PURPOSE_RE.findall(path.read_text(encoding="utf-8"))
    }

    assert requested_purposes, "expected k6 scenarios to declare data-purpose values"
    for config in PERF_CONFIGS:
        config_text = config.read_text(encoding="utf-8")
        missing = [
            purpose
            for purpose in requested_purposes
            if not re.search(rf"^\s*-\s*{re.escape(purpose)}\s*$", config_text, re.MULTILINE)
        ]
        assert missing == [], f"{config.relative_to(ROOT)} missing allowed_purposes: {missing}"
