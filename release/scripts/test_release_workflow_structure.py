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
LATEST_RELEASE_HELPER = ROOT / "release/scripts/verify_latest_published_release.py"


def workflow(name: str) -> tuple[str, dict]:
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    return text, yaml.safe_load(text)


def step_run(document: dict, job: str, name: str) -> str:
    return next(
        step["run"]
        for step in document["jobs"][job]["steps"]
        if step.get("name") == name
    )


def verify_latest_release_fixture(metadata: dict, expected_tag: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary_directory:
        metadata_path = Path(temporary_directory) / "release.json"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        return subprocess.run(
            [
                "python3",
                str(LATEST_RELEASE_HELPER),
                "--metadata",
                str(metadata_path),
                "--expected-tag",
                expected_tag,
            ],
            capture_output=True,
            text=True,
            check=False,
        )


class CandidateWorkflowStructureTest(unittest.TestCase):
    def test_keeps_one_candidate_pipeline_with_narrow_permissions(self) -> None:
        _, document = workflow("release-candidate.yml")
        self.assertEqual(
            list(document["jobs"]),
            ["validate", "build-canonical", "build-platforms", "assemble", "attest"],
        )
        for job in ("build-canonical", "build-platforms"):
            permissions = document["jobs"][job]["permissions"]
            self.assertNotEqual(permissions.get("packages"), "write")
            self.assertNotEqual(permissions.get("id-token"), "write")
        self.assertEqual(
            document["jobs"]["assemble"]["permissions"]["packages"], "write"
        )
        self.assertEqual(document["jobs"]["attest"]["permissions"]["id-token"], "write")

    def test_validates_exact_main_source_ci_and_unused_destinations(self) -> None:
        text, document = workflow("release-candidate.yml")
        validation = step_run(
            document,
            "validate",
            "Validate request, source, CI, and destinations",
        )
        self.assertIn('[[ "${REQUEST_SOURCE_SHA}" != "${workflow_revision}" ]]', validation)
        self.assertIn("refs/remotes/origin/main", validation)
        self.assertIn("actions/workflows/ci.yml/runs", validation)
        self.assertIn("git ls-remote --exit-code --tags", validation)
        self.assertIn("require-image-tag-absent", validation)
        self.assertNotIn("select-canary", validation)
        self.assertNotIn("canary", validation.lower())
        self.assertIn(
            '--source-sha "${{ needs.validate.outputs.source_sha }}"',
            text,
        )

    def test_builds_once_scans_exact_images_and_attests_the_candidate(self) -> None:
        text, _ = workflow("release-candidate.yml")
        self.assertIn("Build canonical Linux payload once", text)
        self.assertIn("Build private candidate image layouts once", text)
        self.assertIn("Verify and scan exact candidate images", text)
        self.assertIn("release-candidate-manifest.json", text)
        self.assertIn("Seal compact candidate manifest and bundle", text)
        self.assertIn("Reverify all bytes before requesting OIDC", text)
        self.assertIn("Attest manifest and bundle after re-verification", text)

    def test_reuses_cache_with_seven_day_validity_and_storage_margin(self) -> None:
        text, document = workflow("release-candidate.yml")
        cache = next(
            step
            for step in document["jobs"]["build-canonical"]["steps"]
            if step.get("name") == "Restore reusable Cargo cache"
        )
        self.assertIn("registry-stack-release-${{ runner.os }}-", cache["with"]["restore-keys"])
        self.assertIn('created_at} + 7 days', text)
        final_upload = next(
            step
            for step in document["jobs"]["assemble"]["steps"]
            if step.get("name") == "Upload one candidate manifest and bundle"
        )
        self.assertEqual(final_upload["with"]["retention-days"], 8)
        self.assertNotIn("Rehearse forced 1.x release-lock runtime contract", text)

    def test_only_pre_oidc_reverification_accepts_the_current_run(self) -> None:
        text, document = workflow("release-candidate.yml")
        reverify = step_run(
            document,
            "attest",
            "Reverify all bytes before requesting OIDC",
        )
        self.assertEqual(text.count("--allow-current-run-in-progress"), 1)
        self.assertIn("--allow-current-run-in-progress", reverify)


class PublicationWorkflowStructureTest(unittest.TestCase):
    def test_is_a_manual_main_workflow_with_six_recoverable_jobs(self) -> None:
        text, document = workflow("release.yml")
        self.assertIn("workflow_dispatch:", text.split("permissions:", 1)[0])
        self.assertNotIn("push:", text.split("permissions:", 1)[0])
        self.assertIn("${{ inputs.tag }}", text)
        self.assertIn('"${GITHUB_REF}" != refs/heads/main', text)
        self.assertEqual(
            list(document["jobs"]),
            [
                "verify",
                "stage-draft",
                "promote-images",
                "finalize-assets",
                "publish",
                "dispatch-docs",
            ],
        )
        self.assertEqual(
            document["jobs"]["promote-images"]["permissions"],
            {"actions": "read", "contents": "read", "packages": "write"},
        )
        self.assertEqual(
            document["jobs"]["dispatch-docs"]["permissions"],
            {"actions": "write"},
        )

    def test_binds_an_annotated_tag_to_exact_candidate_and_main_revisions(self) -> None:
        text, document = workflow("release.yml")
        identity = next(
            step
            for step in document["jobs"]["verify"]["steps"]
            if step.get("name") == "Resolve exact tag identity"
        )
        self.assertEqual(identity["env"]["RELEASE_TAG"], "${{ inputs.tag }}")
        self.assertNotIn("${{ inputs.tag }}", identity["run"])
        self.assertIn('"${tag%%.*}" != v0', identity["run"])
        self.assertIn('git cat-file -t "refs/tags/${tag}"', text)
        self.assertIn("git merge-base --is-ancestor", text)
        self.assertIn("promotion_revision", text)
        self.assertIn("verify-tag-binding", text)
        self.assertIn("--trusted-run-metadata promotion/trusted-run.json", text)
        self.assertNotIn("select-canary", text)

    def test_checks_out_the_protected_workflow_before_running_repo_scripts(self) -> None:
        _, document = workflow("release.yml")
        for job_name, job in document["jobs"].items():
            script_indexes = [
                index
                for index, step in enumerate(job.get("steps", []))
                if "release/scripts/" in step.get("run", "")
            ]
            if not script_indexes:
                continue
            checkout_indexes = [
                index
                for index, step in enumerate(job["steps"])
                if step.get("uses", "").startswith("actions/checkout@")
            ]
            self.assertTrue(checkout_indexes, job_name)
            self.assertLess(min(checkout_indexes), min(script_indexes), job_name)

    def test_reconciles_only_absent_or_exact_public_image_tags(self) -> None:
        _, document = workflow("release.yml")
        promotion = step_run(
            document,
            "promote-images",
            "Reconcile exact image digests",
        )
        self.assertIn("reconcile-image-tag", promotion)
        self.assertIn('--expected-digest "${digest}"', promotion)
        self.assertIn('if [[ "${state}" == absent ]]', promotion)
        self.assertIn('crane copy "${candidate_ref}" "${final_ref}"', promotion)
        self.assertIn('test "$(crane digest "${final_ref}")" = "${digest}"', promotion)
        self.assertNotIn("require-image-tag-absent", promotion)

    def test_preserves_exact_draft_binding_without_overwriting_assets(self) -> None:
        text, document = workflow("release.yml")
        self.assertIn("Reconcile bound draft and upload exact staged inventory", text)
        self.assertIn("registry-stack-release-candidate-v2 manifest_sha256:", text)
        self.assertIn(".draft == true", text)
        self.assertIn(".prerelease == false", text)
        self.assertNotIn("--prerelease", text)
        self.assertNotIn("--clobber", text)
        tagged_checkout = next(
            step
            for step in document["jobs"]["stage-draft"]["steps"]
            if step.get("name") == "Checkout exact tagged product source"
        )
        self.assertEqual(
            tagged_checkout["with"]["ref"],
            "${{ needs.verify.outputs.source_sha }}",
        )
        stage = step_run(
            document,
            "stage-draft",
            "Reconcile bound draft and upload exact staged inventory",
        )
        self.assertIn(
            'cp "product-source/release/notes/${tag}.md"',
            stage,
        )

    def test_recovers_only_the_closed_final_asset_roster(self) -> None:
        _, document = workflow("release.yml")
        stage = step_run(
            document,
            "stage-draft",
            "Reconcile bound draft and upload exact staged inventory",
        )
        promote = step_run(
            document,
            "promote-images",
            "Reconcile exact staged draft before first public image write",
        )
        finalize = step_run(
            document,
            "finalize-assets",
            "Clean retryable final additions and reverify exact staged assets",
        )
        retryable_names = (
            '"registryctl-${tag}-image-lock.json"',
            "SHA256SUMS",
            '"registry-stack-${tag}-SHA256SUMS.sigstore.json"',
        )
        retryable_roster = stage[
            stage.index("printf '%s\\n'") : stage.index(
                "> contract/retryable-final-assets"
            )
        ]
        roster_lines = {
            line.strip().removesuffix("\\").strip()
            for line in retryable_roster.splitlines()[1:]
            if line.strip() and not line.lstrip().startswith("}")
        }
        self.assertEqual(roster_lines, set(retryable_names))
        for name in retryable_names:
            self.assertNotIn(name, finalize)
        self.assertLess(
            stage.index('"${RUNNER_TEMP}/staged-draft.json" >/dev/null'),
            stage.index("> contract/retryable-final-assets"),
        )
        self.assertIn("cat contract/expected-staged-assets", stage)
        self.assertIn("cat contract/retryable-final-assets", stage)
        self.assertIn("contract/allowed-staged-assets", stage)
        self.assertIn("[[ -s contract/unexpected-staged-assets ]]", stage)
        self.assertLess(
            promote.index("contract/draft-release.json >/dev/null"),
            promote.index("comm -23"),
        )
        self.assertIn("contract/observed-assets", promote)
        self.assertIn("contract/retryable-final-assets", promote)
        self.assertIn("diff -u contract/expected-assets contract/actual-assets", promote)
        self.assertLess(
            finalize.index("require_bound_draft\n"),
            finalize.index("cat contract/retryable-final-assets"),
        )
        self.assertLess(
            finalize.index("require_bound_draft\n"),
            finalize.index("gh api --method DELETE"),
        )

    def test_rechecks_candidate_immediately_before_public_image_access(self) -> None:
        text, document = workflow("release.yml")
        expiry = text.index(
            "Recheck candidate expiry immediately before registry login"
        )
        login = text.index("Log in for exact candidate promotion", expiry)
        copy = text.index('crane copy "${candidate_ref}" "${final_ref}"', login)
        self.assertLess(expiry, login)
        self.assertLess(login, copy)
        expiry_run = step_run(
            document,
            "promote-images",
            "Recheck candidate expiry immediately before registry login",
        )
        self.assertIn(".validity.expires_at", expiry_run)
        self.assertNotIn("verify-candidate", expiry_run)

    def test_signs_one_checksum_closure_without_beta_only_ceremony(self) -> None:
        text, _ = workflow("release.yml")
        self.assertIn("SHA256SUMS.sigstore.json", text)
        self.assertIn("cosign sign-blob --yes", text)
        self.assertIn(
            ".github/workflows/release.yml@refs/heads/main",
            text,
        )
        self.assertNotIn("release-provenance", text)
        self.assertNotIn("slsa-framework/slsa-github-generator", text)
        self.assertNotIn("Generate signed 1.x lock", text)
        self.assertNotIn("registry-release-lock.v1.json", text)

    def test_publishes_exact_assets_then_dispatches_exact_docs(self) -> None:
        text, _ = workflow("release.yml")
        self.assertIn("Recheck complete signed release and exact public images", text)
        self.assertIn("Publish immutable release", text)
        self.assertIn("-F draft=false", text)
        self.assertIn("-F prerelease=false", text)
        self.assertIn('released_tag=${{ needs.verify.outputs.tag }}', text)
        self.assertIn('docs_sha256=${{ needs.verify.outputs.docs_sha256 }}', text)
        self.assertLess(
            text.index("Publish immutable release"),
            text.index("Dispatch authenticated docs promotion"),
        )


class SupportingWorkflowStructureTest(unittest.TestCase):
    def test_operator_docs_match_the_latest_non_prerelease_contract(self) -> None:
        operations = (ROOT / "release/OPERATIONS.md").read_text(encoding="utf-8")
        verify = (ROOT / "release/VERIFY.md").read_text(encoding="utf-8")
        self.assertIn("public, non-prerelease GitHub Release", operations)
        self.assertNotIn("marked as a prerelease", operations)
        self.assertIn(".isPrerelease == false", verify)
        self.assertNotIn(".isPrerelease == true", verify)

    def test_docs_deploy_rechecks_latest_published_release(self) -> None:
        text, document = workflow("docs-pages.yml")
        latest_endpoint = 'gh api "repos/${GITHUB_REPOSITORY}/releases/latest"'
        helper = "release/scripts/verify_latest_published_release.py"
        self.assertEqual(text.count(latest_endpoint), 2)
        self.assertEqual(text.count(f"python3 {helper}"), 2)
        self.assertIn(".prerelease==false", text)
        self.assertIn(
            ".github/workflows/release.yml@refs/heads/main",
            text,
        )
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

    def test_canary_is_async_and_has_no_public_write_permission(self) -> None:
        text, document = workflow("release-canary.yml")
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("schedule:", trigger)
        self.assertIn("workflow_dispatch:", trigger)
        for job in document["jobs"].values():
            permissions = job.get("permissions", {})
            self.assertNotEqual(permissions.get("contents"), "write")
            self.assertNotEqual(permissions.get("packages"), "write")

    def test_scorecard_is_schedule_or_manual_only(self) -> None:
        text, _ = workflow("scorecard.yml")
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("schedule:", trigger)
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertNotIn("pull_request:", trigger)


if __name__ == "__main__":
    unittest.main()
