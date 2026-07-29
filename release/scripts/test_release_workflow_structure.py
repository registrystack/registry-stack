#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def workflow(name: str) -> tuple[str, dict]:
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    return text, yaml.safe_load(text)


class CandidateWorkflowStructureTest(unittest.TestCase):
    def test_has_five_logical_jobs_and_validation_is_first(self) -> None:
        text, document = workflow("release-candidate.yml")
        self.assertEqual(
            list(document["jobs"]),
            [
                "validate",
                "build-canonical",
                "build-platforms",
                "assemble",
                "attest",
            ],
        )
        self.assertNotIn("needs", document["jobs"]["validate"])
        self.assertIn("timeout-minutes: 5", text)

    def test_build_jobs_have_no_publication_or_oidc_permission(self) -> None:
        _, document = workflow("release-candidate.yml")
        for job in ("build-canonical", "build-platforms"):
            permissions = document["jobs"][job]["permissions"]
            self.assertNotEqual(permissions.get("packages"), "write")
            self.assertNotEqual(permissions.get("id-token"), "write")
        self.assertEqual(
            document["jobs"]["assemble"]["permissions"]["packages"], "write"
        )
        self.assertEqual(document["jobs"]["attest"]["permissions"]["id-token"], "write")

    def test_uses_one_compact_candidate_and_no_removed_ceremony(self) -> None:
        text, _ = workflow("release-candidate.yml")
        self.assertIn("release-candidate-manifest.json", text)
        self.assertIn("seal-candidate", text)
        self.assertIn("verify-candidate", text)
        self.assertNotIn("proof_level", text)
        self.assertNotIn("measurement_bootstrap", text)
        self.assertNotIn("storage-budget", text)
        self.assertNotIn("release-candidate-receipt", text)
        self.assertNotIn("release capsule", text.lower())

    def test_candidate_images_are_private_and_layouts_are_built_without_token(self) -> None:
        text, _ = workflow("release-candidate.yml")
        build = text.split("  build-canonical:", 1)[1].split(
            "  build-platforms:", 1
        )[0]
        assemble = text.split("  assemble:", 1)[1].split("  attest:", 1)[0]
        self.assertIn("RELEASE_IMAGE_OCI_LAYOUT", build)
        self.assertNotIn("docker/login-action", build)
        self.assertIn("Verify local image layouts before package credentials", assemble)
        self.assertIn("--jq .visibility", text)
        self.assertIn(")\" = private", text)


class PublicationWorkflowStructureTest(unittest.TestCase):
    def test_has_four_release_phases_plus_permission_sliced_docs_dispatch(
        self,
    ) -> None:
        _, document = workflow("release.yml")
        self.assertEqual(
            list(document["jobs"]),
            [
                "verify",
                "stage-draft",
                "release-provenance",
                "promote-images",
                "publish",
                "dispatch-docs",
            ],
        )
        self.assertIn("uses", document["jobs"]["release-provenance"])
        self.assertEqual(
            document["jobs"]["publish"]["permissions"],
            {"contents": "write"},
        )
        self.assertEqual(
            document["jobs"]["dispatch-docs"]["permissions"],
            {"actions": "write"},
        )

    def test_draft_is_reconciled_before_image_or_release_publication(self) -> None:
        text, _ = workflow("release.yml")
        reconcile = text.index("Reconcile complete draft before first public write")
        image_copy = text.index('crane copy "${candidate_ref}" "${final_ref}"')
        publish = text.index("Publish immutable release")
        self.assertLess(reconcile, image_copy)
        self.assertLess(image_copy, publish)

    def test_uses_compact_tag_binding_and_delays_oidc(self) -> None:
        text, document = workflow("release.yml")
        self.assertIn("verify-tag-binding", text)
        self.assertIn("--trusted-run-metadata promotion/trusted-run.json", text)
        self.assertNotIn("--manifest-sha256 \"${{", text)
        self.assertNotEqual(
            document["jobs"]["verify"]["permissions"].get("id-token"), "write"
        )
        self.assertEqual(
            document["jobs"]["stage-draft"]["permissions"]["id-token"], "write"
        )
        provenance = document["jobs"]["release-provenance"]["uses"]
        self.assertRegex(provenance, r"@[0-9a-f]{40}$")

    def test_exact_nonpublic_draft_can_be_safely_recreated(self) -> None:
        text, _ = workflow("release.yml")
        self.assertIn(
            "Verify every public destination is absent or safely resumable",
            text,
        )
        self.assertIn(
            "Recreate resumable draft and upload exact pre-provenance inventory",
            text,
        )
        self.assertIn(".draft == true", text)
        self.assertIn("gh api --method DELETE", text)
        self.assertGreaterEqual(
            text.count(
                "registry-stack-release-candidate-v2 manifest_sha256:"
            ),
            3,
        )
        self.assertIn(".name == $title", text)
        self.assertIn("contains($marker)", text)

    def test_publishes_one_signature_bundle_and_dispatches_exact_docs(self) -> None:
        text, _ = workflow("release.yml")
        self.assertIn("SHA256SUMS.sigstore.json", text)
        self.assertIn("cosign sign-blob --yes", text)
        self.assertIn('released_tag=${{ needs.verify.outputs.tag }}', text)
        self.assertIn('docs_sha256=${{ needs.verify.outputs.docs_sha256 }}', text)
        self.assertNotIn(".sig\"", text)
        self.assertNotIn(".pem", text)
        self.assertNotIn("release-capsule", text)
        self.assertNotIn("release-telemetry", text)
        self.assertNotIn("extended-proof", text)

    def test_rechecks_expiry_before_registry_login(self) -> None:
        text, _ = workflow("release.yml")
        expiry = text.index("Reverify candidate expiry immediately before registry login")
        login = text.index("Log in for exact candidate promotion")
        copy = text.index('crane copy "${candidate_ref}" "${final_ref}"')
        self.assertLess(expiry, login)
        self.assertLess(login, copy)


class SupportingWorkflowStructureTest(unittest.TestCase):
    def test_canary_has_no_public_write_permission(self) -> None:
        text, document = workflow("release-canary.yml")
        self.assertIn("schedule:", text.split("permissions:", 1)[0])
        self.assertIn("workflow_dispatch:", text.split("permissions:", 1)[0])
        for job in document["jobs"].values():
            permissions = job.get("permissions", {})
            self.assertNotEqual(permissions.get("contents"), "write")
            self.assertNotEqual(permissions.get("packages"), "write")
        self.assertIn("verify-canary", text)
        self.assertIn("macOS release-tool contract", text)
        self.assertIn('name: "registry-notary"', text)
        self.assertIn('name: "registry-relay"', text)
        self.assertIn("security/registry-notary.grype.json", text)
        self.assertIn("security/registry-relay.grype.json", text)
        self.assertIn("trusted-candidate-run.json", text)
        self.assertIn("trusted-canary-run.json", text)
        self.assertIn('event: "repository_dispatch"', text)
        self.assertIn('path: ".github/workflows/release-candidate.yml"', text)

    def test_scorecard_is_schedule_or_manual_only(self) -> None:
        text, _ = workflow("scorecard.yml")
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("schedule:", trigger)
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertNotIn("pull_request:", trigger)
        self.assertNotIn("branch_protection_rule:", trigger)

    def test_capsule_backfill_has_no_active_workflow(self) -> None:
        self.assertFalse((WORKFLOWS / "release-capsule-backfill.yml").exists())

    def test_v2_helper_flags_used_by_workflow_are_supported(self) -> None:
        helper = ROOT / "release" / "scripts" / "release_candidate.py"
        for command, required in (
            (
                "verify-candidate",
                ("--manifest", "--bundle", "--bundle-root", "--promotion"),
            ),
            (
                "verify-tag-binding",
                (
                    "--message",
                    "--manifest",
                    "--bundle",
                    "--bundle-root",
                    "--trusted-run-metadata",
                ),
            ),
            ("verify-canary", ("--metadata", "--workflow-revision")),
        ):
            result = subprocess.run(
                ["python3", str(helper), command, "--help"],
                check=True,
                capture_output=True,
                text=True,
            )
            for flag in required:
                self.assertIn(flag, result.stdout)


if __name__ == "__main__":
    unittest.main()
