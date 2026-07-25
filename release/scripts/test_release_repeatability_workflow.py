#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "workflows"
    / "release-repeatability.yml"
)


class ReleaseRepeatabilityWorkflowTest(unittest.TestCase):
    def test_attestation_digests_are_anchored_to_trusted_source(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(".workflow.sha == $source_sha", workflow)
        self.assertIn('--signer-digest "${SOURCE_SHA}"', workflow)
        self.assertIn('--source-digest "${SOURCE_SHA}"', workflow)
        self.assertNotIn("workflow_sha=", workflow)
        self.assertNotIn("jq -er '.workflow.sha'", workflow)


if __name__ == "__main__":
    unittest.main()
