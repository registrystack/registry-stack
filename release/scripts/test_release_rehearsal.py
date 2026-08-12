#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release-rehearsal.yml"
SCRIPT = ROOT / "release/scripts/rehearse-release"


class ReleaseRehearsalTest(unittest.TestCase):
    def test_workflow_is_manual_read_only_and_ubuntu_bounded(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        document = yaml.safe_load(text)
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertNotIn("pull_request:", trigger)
        self.assertNotIn("schedule:", trigger)
        self.assertEqual({"contents": "read"}, document["permissions"])
        self.assertEqual(["rehearse"], list(document["jobs"]))
        job = document["jobs"]["rehearse"]
        self.assertEqual("ubuntu-24.04", job["runs-on"])
        self.assertLessEqual(job["timeout-minutes"], 15)
        self.assertFalse(any("upload-artifact@" in str(step) for step in job["steps"]))
        rehearsal = job["steps"][-1]
        self.assertEqual("${{ inputs.version }}", rehearsal["env"]["REHEARSAL_VERSION"])
        self.assertEqual(
            "${{ inputs.release_id }}",
            rehearsal["env"]["REHEARSAL_RELEASE_ID"],
        )
        self.assertNotIn("${{ inputs.", rehearsal["run"])

    def test_script_exercises_future_tag_source_archive_and_dev_base_in_order(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        ordered = (
            "git ls-remote --exit-code --tags origin",
            "registry-release prepare",
            "registry-release validate-current",
            "registry-release validate-docsets",
            "check-release-source-model.sh",
            "npm run check:archive-lock",
            "npm run build:archive",
            "npm run archive:snapshot",
            "npm run build:dev",
            "npm run check:production:built",
            "npm run check:archives",
            'final_status="$(git status --short)"',
        )
        positions = [text.index(marker) for marker in ordered]
        self.assertEqual(sorted(positions), positions)
        for forbidden in (
            "git tag -a",
            "git push",
            "gh release",
            "release.yml",
            "crane copy",
        ):
            self.assertNotIn(forbidden, text)

    def test_docs_ci_replaces_root_build_with_dev_base_build(self) -> None:
        package = json.loads(
            (ROOT / "docs/site/package.json").read_text(encoding="utf-8")
        )
        scripts = package["scripts"]
        self.assertIn("DOCS_BASE=/dev/", scripts["build:dev"])
        self.assertIn("--outDir dist/dev", scripts["build:dev"])
        self.assertIn("DOCS_PUBLIC_BASE=/dev/", scripts["check:production:built"])
        self.assertIn("check:links:current", scripts["check:production:built"])
        self.assertEqual(
            "npm run check:source && npm run build:dev && npm run check:production:built",
            scripts["check:production"],
        )
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        docs_job = ci.split("\n  docs:\n", 1)[1].split("\n  docs-required:\n", 1)[0]
        self.assertIn("run: npm run check:production", docs_job)
        self.assertNotIn("run: npm run check\n", docs_job)


if __name__ == "__main__":
    unittest.main()
