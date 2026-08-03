#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retirement contract for the Notary-only external integration runner."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RetiredIntegrationE2RunnerTest(unittest.TestCase):
    def test_notary_integration_runner_and_packet_are_absent(self) -> None:
        self.assertFalse((ROOT / "release/scripts/integration-e2-runner.py").exists())
        packet = ROOT / "release/conformance/integrations"
        self.assertEqual([], [path for path in packet.rglob("*") if path.is_file()])

    def test_relay_oidc_smoke_remains(self) -> None:
        self.assertTrue((ROOT / "release/scripts/relay-oidc-smoke.py").is_file())

    def test_current_ci_and_gate_inventory_do_not_reference_retired_runner(
        self,
    ) -> None:
        for path in (
            ROOT / ".github/workflows/ci.yml",
            ROOT / "release/scripts/check-gates-inventory.py",
        ):
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("integration-e2", text)
                self.assertNotIn("conformance/integrations", text)


if __name__ == "__main__":
    unittest.main()
