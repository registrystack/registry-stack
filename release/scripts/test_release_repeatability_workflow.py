#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "release-repeatability.yml"


class ReleaseRepeatabilityWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def jq_rows(self, expression: str, document: dict[str, object]) -> list[list[str]]:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image-metadata.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            completed = subprocess.run(
                ["jq", "-er", expression, str(path)],
                check=True,
                capture_output=True,
                text=True,
            )
        return [line.split("\t") for line in completed.stdout.splitlines()]

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
        self.assertIn('"evidence-oid4vci": "evidence-oid4vci"', self.workflow)
        self.assertIn('"registry-manifest": "registry-manifest"', self.workflow)
        self.assertIn('"relay": "relay"', self.workflow)
        self.assertIn('"relayctl": "relayctl"', self.workflow)
        self.assertIn(
            'if grep -Fqx -- "${release_manifest}" <<<"${release_assets}"',
            self.workflow,
        )
        self.assertIn("minor == 16 && patch >= 3", self.workflow)
        self.assertIn(
            'echo "${TAG} has neither ${release_manifest} nor ${image_lock}"',
            self.workflow,
        )
        self.assertIn('--pattern "${image_metadata}"', self.workflow)
        self.assertIn(
            "jq -er '.images[] | [.name,.final_ref,.digest] | @tsv'",
            self.workflow,
        )
        self.assertIn("select(.key | startswith(\"registry-\"))", self.workflow)
        self.assertIn(
            'test "$(crane digest "${published_ref}")" = "${index_digest}"',
            self.workflow,
        )
        self.assertIn("compare-release-image-layouts.py", self.workflow)

    def test_v0152_image_lock_fixture_maps_only_registry_images(self) -> None:
        digest = f"sha256:{'1' * 64}"
        rows = self.jq_rows(
            '.images | to_entries[] | select(.key | startswith("registry-")) '
            '| [.key,.value,(.value | split("@")[1])] | @tsv',
            {
                "images": {
                    "postgresql": f"docker.io/library/postgres@{digest}",
                    "registry-notary": f"ghcr.io/registrystack/registry-notary@{digest}",
                    "registry-relay": f"ghcr.io/registrystack/registry-relay@{digest}",
                },
                "release_tag": "v0.15.2",
            },
        )
        self.assertEqual(
            rows,
            [
                ["registry-notary", f"ghcr.io/registrystack/registry-notary@{digest}", digest],
                ["registry-relay", f"ghcr.io/registrystack/registry-relay@{digest}", digest],
            ],
        )

    def test_current_release_manifest_fixture_carries_the_public_digest(self) -> None:
        digest = f"sha256:{'2' * 64}"
        rows = self.jq_rows(
            ".images[] | [.name,.final_ref,.digest] | @tsv",
            {
                "images": [
                    {
                        "name": "relay",
                        "final_ref": "ghcr.io/registrystack/relay:v0.19.0",
                        "digest": digest,
                    }
                ],
                "release": {"tag": "v0.19.0"},
            },
        )
        self.assertEqual(
            rows,
            [["relay", "ghcr.io/registrystack/relay:v0.19.0", digest]],
        )


if __name__ == "__main__":
    unittest.main()
