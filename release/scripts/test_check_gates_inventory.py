#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "check-gates-inventory.py"


def load_module():
    spec = importlib.util.spec_from_file_location("check_gates_inventory", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GateInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

    def test_real_ci_workflow_declares_inventory(self) -> None:
        self.assertEqual([], self.module.missing_gates(self.workflow))

    def test_missing_relay_exposure_gate_is_reported(self) -> None:
        text = self.workflow.replace("name: Relay exposure check", "name: Relay exposure")
        self.assertIn("Relay exposure check", self.module.missing_gates(text))


if __name__ == "__main__":
    unittest.main()
