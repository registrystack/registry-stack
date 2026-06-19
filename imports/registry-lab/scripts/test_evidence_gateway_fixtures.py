#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class EvidenceGatewayFixtureCheckTest(unittest.TestCase):
    def test_governed_evidence_fixtures_validate(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/check-evidence-gateway-fixtures.py"],
            cwd=REPO_ROOT,
            check=True,
            text=True,
            capture_output=True,
        )

        self.assertIn("baseline-dpi/v1", result.stdout)
        self.assertIn("sp-dci/v1", result.stdout)
        self.assertIn("oots-birth-evidence/v1", result.stdout)
        self.assertIn("oots-marriage-evidence/v1", result.stdout)
        self.assertIn("production enforcement profile terms OK", result.stdout)
        self.assertIn("relay metadata binding selectors OK", result.stdout)
        self.assertIn("relay metadata policy hashes OK", result.stdout)
        self.assertIn("manifest metadata shape OK", result.stdout)
        self.assertIn("registry-data freshness projections OK", result.stdout)
        self.assertIn("registry-specific PDP gates OK: absent from ODRL policy constraints", result.stdout)
        self.assertIn("registry:pdp:source_age", result.stdout)
        self.assertIn("freshness source metadata OK", result.stdout)
        self.assertIn("request-supplied freshness keys are forbidden", result.stdout)
        self.assertIn("freshness denial modes OK: missing_timestamp, stale_timestamp", result.stdout)
        self.assertIn("declarative binding contract", result.stdout)
        self.assertIn("live PDP runtime proof is not executed by this checker", result.stdout)
        for code in (
            "pdp.assurance_insufficient",
            "pdp.consent_required",
            "pdp.evidence_stale",
            "pdp.jurisdiction_not_permitted",
            "pdp.legal_basis_required",
            "pdp.purpose_not_permitted",
            "pdp.unsupported_policy_term",
        ):
            self.assertIn(code, result.stdout)


if __name__ == "__main__":
    unittest.main()
