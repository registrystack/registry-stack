#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
LATEST_RELEASE_HELPER = (
    ROOT / "release" / "scripts" / "verify_latest_published_release.py"
)


def workflow(name: str) -> tuple[str, dict]:
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    return text, yaml.safe_load(text)


def verify_latest_release_fixture(
    metadata: object,
    expected_tag: str,
) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "latest-release.json"
        path.write_text(json.dumps(metadata), encoding="utf-8")
        return subprocess.run(
            [
                "python3",
                str(LATEST_RELEASE_HELPER),
                "--metadata",
                str(path),
                "--expected-tag",
                expected_tag,
            ],
            check=False,
            capture_output=True,
            text=True,
        )


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

    def test_candidate_source_is_the_exact_canaried_workflow_revision(self) -> None:
        text, document = workflow("release-candidate.yml")
        validation = next(
            step["run"]
            for step in document["jobs"]["validate"]["steps"]
            if step.get("name")
            == "Validate request, source, CI, canary, and destinations"
        )
        self.assertIn(
            '[[ "${REQUEST_SOURCE_SHA}" != "${workflow_revision}" ]]',
            validation,
        )
        self.assertIn(
            "source_sha must equal the canaried workflow revision",
            validation,
        )
        self.assertIn(
            '--source-sha "${{ needs.validate.outputs.source_sha }}"',
            text,
        )

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

    def test_tag_lookup_accepts_only_git_explicit_absence_status(self) -> None:
        _, document = workflow("release-candidate.yml")
        validation = next(
            step["run"]
            for step in document["jobs"]["validate"]["steps"]
            if step.get("name")
            == "Validate request, source, CI, canary, and destinations"
        )
        self.assertIn("git ls-remote --exit-code --tags", validation)
        self.assertIn("tag_lookup_status=$?", validation)
        self.assertIn('[[ "${tag_lookup_status}" -ne 2 ]]', validation)
        self.assertIn("cannot prove tag ${tag} is absent", validation)


class PublicationWorkflowStructureTest(unittest.TestCase):
    def test_has_final_runtime_gate_before_provenance_and_publication(
        self,
    ) -> None:
        _, document = workflow("release.yml")
        self.assertEqual(
            list(document["jobs"]),
            [
                "verify",
                "stage-draft",
                "promote-images",
                "finalize-assets",
                "release-provenance",
                "publish",
                "dispatch-docs",
            ],
        )
        self.assertIn("uses", document["jobs"]["release-provenance"])
        self.assertEqual(
            document["jobs"]["publish"]["permissions"],
            {"actions": "read", "contents": "write"},
        )
        self.assertEqual(
            document["jobs"]["dispatch-docs"]["permissions"],
            {"actions": "write"},
        )

    def test_draft_is_reconciled_before_image_or_release_publication(self) -> None:
        text, _ = workflow("release.yml")
        reconcile = text.index(
            "Reconcile exact staged draft before first public image write"
        )
        image_copy = text.index('crane copy "${candidate_ref}" "${final_ref}"')
        runtime = text.index("Generate signed 1.x lock and run the clean released runtime")
        publish = text.index("Publish immutable release")
        self.assertLess(reconcile, image_copy)
        self.assertLess(image_copy, runtime)
        self.assertLess(runtime, publish)

    def test_uses_compact_tag_binding_and_delays_oidc(self) -> None:
        text, document = workflow("release.yml")
        self.assertIn("verify-tag-binding", text)
        self.assertIn("--trusted-run-metadata promotion/trusted-run.json", text)
        self.assertNotIn("--manifest-sha256 \"${{", text)
        self.assertNotEqual(
            document["jobs"]["verify"]["permissions"].get("id-token"), "write"
        )
        self.assertNotIn("id-token", document["jobs"]["stage-draft"]["permissions"])
        self.assertEqual(
            document["jobs"]["finalize-assets"]["permissions"]["id-token"], "write"
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
            "Recreate resumable draft and upload exact staged inventory",
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
        self.assertIn("first-country-release-form.tar.gz", text)
        self.assertIn("registry-release-lock.v1.json", text)
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

    def test_candidate_tag_and_final_lock_use_one_exact_source_revision(self) -> None:
        text, _ = workflow("release.yml")
        candidate, _ = workflow("release-candidate.yml")
        self.assertIn(
            '--source-sha "${{ needs.verify.outputs.workflow_revision }}"',
            text,
        )
        self.assertIn(
            'test "${workflow_revision}" = "${{ steps.identity.outputs.source_sha }}"',
            text,
        )
        self.assertIn(
            '--manifest-source-ref "${{ needs.verify.outputs.workflow_revision }}"',
            text,
        )
        self.assertIn(
            '--tag-target "${{ needs.verify.outputs.source_sha }}"',
            text,
        )
        self.assertIn(
            '--manifest-source-ref "${{ needs.validate.outputs.source_sha }}"',
            candidate,
        )
        self.assertIn(
            '--tag-target "${{ needs.validate.outputs.source_sha }}"',
            candidate,
        )

    def test_major_gate_never_adds_an_unsigned_installer_bypass(self) -> None:
        release, _ = workflow("release.yml")
        candidate, _ = workflow("release-candidate.yml")
        self.assertIn("if ((major >= 1)); then", release)
        self.assertIn("if ((major >= 1)); then", candidate)
        self.assertNotIn("REGISTRYCTL_RELEASE_LOCK_BYPASS", release)
        self.assertNotIn("REGISTRYCTL_RELEASE_LOCK_BYPASS", candidate)


class SupportingWorkflowStructureTest(unittest.TestCase):
    def test_docs_deploy_rechecks_latest_release_at_last_boundary(self) -> None:
        text, document = workflow("docs-pages.yml")
        endpoint = 'gh api "repos/${GITHUB_REPOSITORY}/releases/latest"'
        helper = "release/scripts/verify_latest_published_release.py"
        self.assertEqual(text.count(endpoint), 2)
        self.assertEqual(text.count(f"python3 {helper}"), 2)
        deploy_steps = document["jobs"]["deploy"]["steps"]
        recheck = next(
            index
            for index, step in enumerate(deploy_steps)
            if step.get("name")
            == "Recheck latest published release immediately before deployment"
        )
        deployment = next(
            index
            for index, step in enumerate(deploy_steps)
            if step.get("name") == "Deploy to GitHub Pages"
        )
        self.assertEqual(recheck + 1, deployment)

    def test_latest_release_fixture_rejects_stale_or_nonpublished_dispatches(
        self,
    ) -> None:
        release = {
            "tag_name": "v1.4.0",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-07-29T10:00:00Z",
        }
        self.assertEqual(
            verify_latest_release_fixture(release, "v1.4.0").returncode,
            0,
        )
        stale = verify_latest_release_fixture(release, "v1.3.0")
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("is stale", stale.stderr)
        for field in ("draft", "prerelease"):
            with self.subTest(field=field):
                invalid = dict(release)
                invalid[field] = True
                result = verify_latest_release_fixture(invalid, "v1.4.0")
                self.assertNotEqual(result.returncode, 0)

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
