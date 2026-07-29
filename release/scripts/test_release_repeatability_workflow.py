#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "release-repeatability.yml"


class ReleaseRepeatabilityWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_runs_weekly_or_manually_only(self) -> None:
        trigger = self.workflow.split("permissions:", 1)[0]
        self.assertIn("schedule:", trigger)
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("repository_dispatch:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertNotIn("pull_request:", trigger)

    def test_is_not_a_release_publication_or_issue_write_path(self) -> None:
        self.assertNotIn("contents: write", self.workflow)
        self.assertNotIn("issues: write", self.workflow)
        self.assertNotIn("id-token: write", self.workflow)
        self.assertNotIn("gh release upload", self.workflow)
        self.assertNotIn("gh api --method PATCH", self.workflow)

    def test_records_the_30_day_silver_claim_boundary(self) -> None:
        self.assertIn("silver_claim_valid_through", self.workflow)
        self.assertIn("30 * 24 * 60 * 60", self.workflow)
        self.assertIn("retention-days: 30", self.workflow)

    def test_clean_proof_compares_binaries_and_images(self) -> None:
        self.assertIn("Build canonical Linux payload from clean state", self.workflow)
        self.assertIn("cmp \"published/${asset}\"", self.workflow)
        self.assertIn("compare-release-image-layouts.py", self.workflow)


if __name__ == "__main__":
    unittest.main()
