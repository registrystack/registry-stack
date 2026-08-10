#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compatibility entry point for the release-owned advisory checker."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[3]
    / "release"
    / "scripts"
    / "check-advisory-baselines.py"
)
SPEC = importlib.util.spec_from_file_location("registry_release_advisory_check", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load advisory checker: {SCRIPT}")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)
CHECKER.DEFAULT_BASELINE = Path(__file__).resolve().parents[1] / "security" / "advisory-baseline.json"

for name in dir(CHECKER):
    if not name.startswith("__"):
        globals()[name] = getattr(CHECKER, name)


if __name__ == "__main__":
    CHECKER.main()
