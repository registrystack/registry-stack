"""Hold the nightly source, publication and recipe trust boundaries."""

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class NightlyWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / ".github/workflows/nightly-release.yml").read_text()
        self.workflow = yaml.safe_load(self.text)
        self.jobs = self.workflow["jobs"]

    def test_only_main_scheduler_or_manual_selection(self):
        trigger = self.workflow.get("on", self.workflow.get(True))
        self.assertEqual(set(trigger), {"schedule", "workflow_dispatch"})
        self.assertIsNone(trigger["workflow_dispatch"])
        self.assertEqual(self.workflow["concurrency"]["cancel-in-progress"], False)
        self.assertIn("nightly_release.py plan", self.text)
        self.assertIn("wait-for-ci", self.text)
        for job in ("linux", "macos", "arm64"):
            self.assertIn("protected-ci", self.jobs[job]["needs"])

    def test_all_platforms_and_scans_precede_attestation(self):
        self.assertEqual(
            set(self.jobs["prepare"]["needs"]),
            {"select", "macos", "arm64", "images", "scan"},
        )
        self.assertEqual(set(self.jobs["attest"]["needs"]), {"select", "prepare"})
        self.assertEqual(
            set(self.jobs["publish"]["needs"]), {"select", "images", "attest"}
        )
        self.assertEqual(
            self.jobs["linux"]["strategy"]["matrix"]["group"],
            ["core", "breg", "casework", "scheduling", "messaging"],
        )
        self.assertEqual(
            self.jobs["macos"]["strategy"]["matrix"]["group"],
            ["core", "breg", "bregctl", "casework", "scheduling"],
        )

    def test_privileges_are_isolated_and_authentication_precedes_promotion(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        writers = {
            name
            for name, job in self.jobs.items()
            if job.get("permissions", {}).get("contents") == "write"
        }
        oidc = {
            name
            for name, job in self.jobs.items()
            if job.get("permissions", {}).get("id-token") == "write"
        }
        self.assertEqual(writers, {"publish"})
        self.assertEqual(oidc, {"attest"})
        self.assertEqual(
            self.jobs["scan"]["permissions"], {"contents": "read", "packages": "write"}
        )
        steps = self.jobs["publish"]["steps"]
        verify = next(
            i
            for i, step in enumerate(steps)
            if "gh attestation verify" in step.get("run", "")
        )
        promote = next(
            i
            for i, step in enumerate(steps)
            if "nightly_release.py publish" in step.get("run", "")
        )
        self.assertLess(verify, promote)
        for binding in (
            "--source-ref refs/heads/main",
            "--source-digest",
            "--signer-digest",
            "--signer-workflow",
            "--deny-self-hosted-runners",
        ):
            self.assertIn(binding, steps[verify]["run"])

    def test_tool_pins_match_numbered_release(self):
        release = yaml.safe_load(
            (ROOT / ".github/workflows/release-candidate.yml").read_text()
        )
        for key in (
            "RELEASE_BUILDER_IMAGE",
            "RELEASE_BUILDX_VERSION",
            "RELEASE_BUILDKIT_IMAGE",
        ):
            self.assertEqual(self.workflow["env"][key], release["env"][key])
        tools = (
            ROOT / "release/scripts/install-nightly-inspection-tools.sh"
        ).read_text()
        for name in ("SYFT", "GRYPE", "CRANE", "ORAS"):
            self.assertIn(release["env"][f"{name}_VERSION"], tools)
            self.assertIn(release["env"][f"{name}_LINUX_AMD64_SHA256"], tools)
        for job in self.jobs.values():
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertFalse(step["with"]["persist-credentials"])

    def test_no_numbered_release_promotion_or_mutable_image_alias(self):
        self.assertNotIn("REGISTRY_RELEASE_TAG:", self.text)
        self.assertNotIn(":nightly", self.text)
        self.assertNotIn("npm publish", self.text)
        self.assertNotIn("pypi", self.text)
        self.assertIn(
            'nightly_release.py check-scan "reports/${name}.grype.json" \\\n'
            '              --baseline "release/security/${name}-advisory-baseline.json"',
            self.text,
        )
        self.assertIn("nightly_release.py smoke", self.text)

    def test_failed_publication_reuses_successful_producer_artifacts(self):
        def download_names(job):
            return [
                step["with"]["name"]
                for step in self.jobs[job]["steps"]
                if step.get("uses", "").startswith("actions/download-artifact@")
            ]

        self.assertEqual(
            download_names("attest"), ["${{ needs.prepare.outputs.public_artifact }}"]
        )
        self.assertEqual(
            download_names("publish"),
            [
                "${{ needs.attest.outputs.public_artifact }}",
                "${{ needs.images.outputs.canonical_artifact }}",
            ],
        )
        self.assertEqual(
            self.jobs["attest"]["outputs"]["public_artifact"],
            "${{ needs.prepare.outputs.public_artifact }}",
        )
        for job, output in (
            ("prepare", "public_artifact"),
            ("images", "canonical_artifact"),
        ):
            self.assertIn("github.run_attempt", self.jobs[job]["outputs"][output])


if __name__ == "__main__":
    unittest.main()
