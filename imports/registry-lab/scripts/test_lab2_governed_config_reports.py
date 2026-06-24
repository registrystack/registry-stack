#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/lab2-governed-config/src/main.rs"


def test_lab2_generator_emits_versioned_config_apply_reports() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    assert "registry.platform.config_apply_report.v1" in source
    assert ".apply-report.json" in source
    assert '"result": "verified"' in source
    assert '"restart_required": bundle.apply_policy == "restart_required"' in source


if __name__ == "__main__":
    test_lab2_generator_emits_versioned_config_apply_reports()
