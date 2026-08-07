#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retirement contract for the Notary-only OpenID conformance wrapper."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RetiredOpenIdConformanceRunnerTest(unittest.TestCase):
    def test_notary_oid4vci_wrapper_is_absent(self) -> None:
        self.assertFalse(
            (ROOT / "release/scripts/openid-conformance-runner.py").exists()
        )
        operational_assets = {
            path.name
            for path in (ROOT / "release/conformance/openid").iterdir()
            if path.name != "initial-report.md"
        }
        self.assertEqual(set(), operational_assets)
        self.assertTrue(
            (ROOT / "release/conformance/openid/initial-report.md").is_file()
        )

    def test_relay_oidc_smoke_remains_the_supported_openid_check(self) -> None:
        self.assertTrue((ROOT / "release/scripts/relay-oidc-smoke.py").is_file())
        self.assertTrue((ROOT / "release/conformance/relay-oidc/README.md").is_file())


if __name__ == "__main__":
    unittest.main()
