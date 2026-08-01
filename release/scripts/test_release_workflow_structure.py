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

    def test_only_internal_pre_oidc_reverification_accepts_current_run(self) -> None:
        text, document = workflow("release-candidate.yml")
        reverify = next(
            step
            for step in document["jobs"]["attest"]["steps"]
            if step.get("name") == "Reverify all bytes before requesting OIDC"
        )

        self.assertEqual(text.count("--allow-current-run-in-progress"), 1)
        self.assertIn("--allow-current-run-in-progress", reverify["run"])
        self.assertNotIn(
            "--allow-current-run-in-progress",
            workflow("release.yml")[0],
        )

    def test_canonical_build_timeout_covers_uncached_follow_on_work(self) -> None:
        _, document = workflow("release-candidate.yml")
        self.assertGreaterEqual(
            document["jobs"]["build-canonical"]["timeout-minutes"], 90
        )

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
        self.assertIn("release_candidate.py select-canary", validation)
        self.assertNotIn("| {\n", validation)

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

    def test_candidate_oras_publisher_is_directly_checksum_pinned(self) -> None:
        text, document = workflow("release-candidate.yml")
        assemble = document["jobs"]["assemble"]
        install = next(
            step
            for step in assemble["steps"]
            if step.get("name") == "Install pinned candidate inspection tools"
        )

        self.assertNotIn("oras-project/setup-oras", text)
        self.assertEqual(document["env"]["ORAS_VERSION"], "v1.3.2")
        self.assertEqual(
            document["env"]["ORAS_LINUX_AMD64_SHA256"],
            "9229ccc6d17bb282039ad4a69abb16dcb887a5bce567c075d731d9b3c7ad8eaf",
        )
        self.assertIn(
            "https://github.com/oras-project/oras/releases/download/"
            "${STEP_ORAS_VERSION}/oras_${oras_version}_linux_amd64.tar.gz",
            install["run"],
        )
        self.assertIn(
            'echo "${STEP_ORAS_SHA256}  ${RUNNER_TEMP}/tools/oras.tar.gz" \\\n'
            "  | sha256sum --check --strict",
            install["run"],
        )

        verify = text.index(
            "Verify local image layouts before package credentials are used"
        )
        publish = text.index("oras cp --from-oci-layout")
        scan = text.index("Verify and scan exact candidate images")
        self.assertLess(verify, publish)
        self.assertLess(publish, scan)

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

    def test_forces_the_v1_runtime_contract_before_the_candidate_is_sealed(
        self,
    ) -> None:
        text, _ = workflow("release-candidate.yml")
        rehearsal = text.index(
            "Rehearse forced 1.x release-lock runtime contract"
        )
        seal = text.index("Seal compact candidate manifest and bundle")
        self.assertLess(rehearsal, seal)
        self.assertIn(
            "release/scripts/check-runtime-contract-parity.sh",
            text[rehearsal:seal],
        )


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
        self.assertIn(
            "their exact identities do not exist before tagging",
            workflow("release-candidate.yml")[0],
        )

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

    def test_exact_nonpublic_draft_can_be_safely_reconciled(self) -> None:
        text, _ = workflow("release.yml")
        staging = text.split("  stage-draft:", 1)[1].split(
            "  promote-images:", 1
        )[0]
        self.assertIn(
            "Verify public images are absent and any draft is bound",
            text,
        )
        self.assertIn(
            "Reconcile bound draft and upload exact staged inventory",
            text,
        )
        self.assertIn(".draft == true", text)
        self.assertNotIn("gh api --method DELETE", staging)
        self.assertGreaterEqual(
            text.count(
                "registry-stack-release-candidate-v2 manifest_sha256:"
            ),
            3,
        )
        self.assertIn(".name == $title", text)
        self.assertIn("contains($marker)", text)

    def test_public_image_promotion_is_fail_closed_and_burns_the_version(
        self,
    ) -> None:
        candidate, _ = workflow("release-candidate.yml")
        release, document = workflow("release.yml")
        combined = candidate + release
        self.assertEqual(
            combined.count("release_workflow_guard.py http-status"),
            3,
        )
        self.assertNotIn("awk '/^HTTP", combined)
        self.assertNotIn("sed -E 's#^ghcr", combined)
        self.assertNotIn("image-tag-state", combined)
        self.assertNotIn("--expected-digest", combined)
        self.assertEqual(combined.count("gh api --paginate --slurp"), 3)
        self.assertEqual(combined.count("require-image-tag-absent"), 3)
        promotion = next(
            step["run"]
            for step in document["jobs"]["promote-images"]["steps"]
            if step.get("name") == "Burn version on first exact digest promotion"
        )
        self.assertIn("public-image-destination", promotion)
        self.assertIn("require-image-tag-absent", promotion)
        absence = promotion.index("require-image-tag-absent")
        copy = promotion.index('crane copy "${candidate_ref}" "${final_ref}"')
        self.assertLess(absence, copy)
        self.assertNotIn("--expected-digest", promotion)
        self.assertNotIn("state=", promotion)
        self.assertIn("irreversible version burn", promotion)
        self.assertIn(
            'test "$(crane digest "${final_ref}")" = "${digest}"',
            promotion,
        )
        verify = next(
            step["run"]
            for step in document["jobs"]["verify"]["steps"]
            if step.get("name")
            == "Verify public images are absent and any draft is bound"
        )
        self.assertIn(
            "require-image-tag-absent",
            verify,
        )
        self.assertNotIn("--expected-digest", verify)

    def test_every_final_release_mutation_requires_the_exact_bound_draft(
        self,
    ) -> None:
        _, document = workflow("release.yml")
        finalize_steps = document["jobs"]["finalize-assets"]["steps"]
        cleanup = next(
            step["run"]
            for step in finalize_steps
            if step.get("name")
            == "Clean retryable final additions and reverify exact staged assets"
        )
        cleanup_loop = cleanup.index(
            "while IFS= read -r name; do"
        )
        cleanup_guard = cleanup.index("require_bound_draft", cleanup_loop)
        cleanup_delete = cleanup.index("gh api --method DELETE", cleanup_guard)
        self.assertLess(cleanup_guard, cleanup_delete)
        self.assertIn(".draft == true", cleanup)

        final_upload = next(
            step["run"]
            for step in finalize_steps
            if step.get("name")
            == "Sign and upload the complete pre-provenance asset closure"
        )
        upload_guard = final_upload.index(
            "contract/final-upload-release.json"
        )
        upload = final_upload.index(
            'gh release upload "${tag}" "${additions[@]}"'
        )
        self.assertLess(upload_guard, upload)
        self.assertIn(".draft == true", final_upload[upload_guard:upload])

        provenance = document["jobs"]["release-provenance"]
        self.assertEqual(provenance["permissions"]["contents"], "read")
        self.assertFalse(provenance["with"]["upload-assets"])
        self.assertNotIn("upload-tag-name", provenance["with"])

        publish_steps = document["jobs"]["publish"]["steps"]
        self.assertTrue(
            any(
                step.get("name")
                == "Download exact tag-bound release provenance"
                for step in publish_steps
            )
        )
        provenance_upload = next(
            step
            for step in publish_steps
            if step.get("name")
            == "Upload provenance to the exact bound draft"
        )
        self.assertEqual(
            provenance_upload["if"],
            "steps.release_state.outputs.release_state == 'draft'",
        )
        provenance_upload = provenance_upload["run"]
        guard_invocations = [
            index
            for index, line in enumerate(provenance_upload.splitlines())
            if line.strip() == "require_bound_draft"
        ]
        self.assertEqual(len(guard_invocations), 2)
        provenance_delete = provenance_upload.index("gh api --method DELETE")
        provenance_write = provenance_upload.index(
            'gh release upload "${tag}" "provenance/${provenance}"'
        )
        first_guard = provenance_upload.index(
            "\nrequire_bound_draft\n"
        )
        second_guard = provenance_upload.index(
            "\nrequire_bound_draft\n",
            first_guard + 1,
        )
        self.assertLess(first_guard, provenance_delete)
        self.assertLess(provenance_delete, second_guard)
        self.assertLess(second_guard, provenance_write)
        self.assertIn(".draft == true", provenance_upload)

        signed_recheck = next(
            step["run"]
            for step in publish_steps
            if step.get("name")
            == "Recheck complete signed release and exact public images"
        )
        self.assertIn('$release_state == "draft"', signed_recheck)
        self.assertIn('$release_state == "published"', signed_recheck)
        self.assertIn(".draft == true", signed_recheck)
        self.assertIn(".draft == false", signed_recheck)
        self.assertIn("needs.verify.outputs.docs_sha256", signed_recheck)
        self.assertNotIn('(.draft | type) == "boolean"', signed_recheck)

        publication = next(
            step["run"]
            for step in publish_steps
            if step.get("name") == "Publish immutable release"
        )
        state = publication.index("publish-state.json")
        draft = publication.index(".draft == true", state)
        patch = publication.index("gh api --method PATCH", draft)
        self.assertLess(state, draft)
        self.assertLess(draft, patch)
        self.assertIn(
            'if [[ "${EXPECTED_RELEASE_STATE}" == draft ]]; then',
            publication,
        )
        self.assertIn('$release_state == "published"', publication)
        self.assertNotIn('(.draft | type) == "boolean"', publication)

    def test_published_retry_is_exact_and_read_only(self) -> None:
        _, document = workflow("release.yml")
        publish_steps = document["jobs"]["publish"]["steps"]
        classification_index, classification = next(
            (index, step)
            for index, step in enumerate(publish_steps)
            if step.get("name")
            == "Classify exact bound draft or published release"
        )
        provenance_index = next(
            index
            for index, step in enumerate(publish_steps)
            if step.get("name")
            == "Upload provenance to the exact bound draft"
        )
        self.assertLess(classification_index, provenance_index)
        self.assertEqual(classification["id"], "release_state")
        classifier = classification["run"]
        self.assertIn('["draft", (.id | tostring)]', classifier)
        self.assertIn('["published", (.id | tostring)]', classifier)
        self.assertIn(".published_at == null", classifier)
        self.assertIn('.published_at | type == "string"', classifier)
        self.assertIn(".name == $title", classifier)
        self.assertIn("contains($marker)", classifier)

        publication = next(
            step["run"]
            for step in publish_steps
            if step.get("name")
            == "Publish immutable release"
        )
        state_validation, remainder = publication.split(
            'if [[ "${EXPECTED_RELEASE_STATE}" == draft ]]; then',
            1,
        )
        draft_branch, final_validation = remainder.split(
            "\nfi\n",
            1,
        )
        self.assertIn('$release_state == "draft"', state_validation)
        self.assertIn('$release_state == "published"', state_validation)
        self.assertIn(".draft == false", state_validation)
        self.assertIn("contains($marker)", state_validation)
        self.assertIn("gh api --method PATCH", draft_branch)
        self.assertNotIn("gh release upload", draft_branch)
        self.assertNotIn("gh api --method DELETE", draft_branch)
        self.assertNotIn('crane copy "${candidate_ref}" "${final_ref}"', draft_branch)
        self.assertIn("published-release.json", final_validation)
        for mutation in (
            "gh release upload",
            "gh api --method DELETE",
            "gh api --method PATCH",
            'crane copy "${candidate_ref}" "${final_ref}"',
        ):
            with self.subTest(mutation=mutation):
                self.assertNotIn(mutation, state_validation)
                self.assertNotIn(mutation, final_validation)

        for step in publish_steps:
            if step.get("name") == "Publish immutable release":
                continue
            if step.get("if") == (
                "steps.release_state.outputs.release_state == 'draft'"
            ):
                continue
            run = step.get("run", "")
            for mutation in (
                "gh release upload",
                "gh api --method DELETE",
                "gh api --method PATCH",
                'crane copy "${candidate_ref}" "${final_ref}"',
            ):
                with self.subTest(step=step.get("name"), mutation=mutation):
                    self.assertNotIn(mutation, run)

    def test_canary_selection_uses_the_complete_shared_schema(self) -> None:
        candidate, _ = workflow("release-candidate.yml")
        release, _ = workflow("release.yml")
        combined = candidate + release
        self.assertEqual(combined.count("release_candidate.py select-canary"), 2)
        for field in ("id", "run_attempt", "event"):
            self.assertIn(f'"{field}": value.get("{field}")', (
                ROOT / "release/scripts/release_candidate.py"
            ).read_text(encoding="utf-8"))

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
        trusted_candidate = text.split(
            "> canary/trusted-candidate-run.json", 1
        )[0].rsplit("jq -n", 1)[1]
        self.assertIn('status: "completed"', trusted_candidate)
        self.assertIn('conclusion: "success"', trusted_candidate)

    def test_canary_seals_complete_security_evidence(self) -> None:
        _, document = workflow("release-canary.yml")
        exercise = next(
            step["run"]
            for step in document["jobs"]["control-plane"]["steps"]
            if step.get("name")
            == "Exercise dispatch, candidate, advisory, draft, and docs contracts"
        )
        for required_member_pattern in (
            "images/postgresql.digest",
            "image-sbom/${name}.spdx.json",
            "image-sbom/postgresql.spdx.json",
            "syft/${name}.syft.json",
            "grype/${name}.grype.json",
            "grype/grype-db-status.json",
            "advisory-verdict.json",
        ):
            self.assertIn(required_member_pattern, exercise)
        for image in ("registry-notary", "registry-relay", "postgresql"):
            self.assertIn(f"write_image_reports {image}", exercise)
        self.assertIn("registry-stack-${tag}-security-evidence.tar.gz", exercise)
        self.assertIn('kind: "security-evidence"', exercise)
        self.assertLess(
            exercise.index("registry-stack-${tag}-security-evidence.tar.gz"),
            exercise.index("release_candidate.py seal-candidate"),
        )

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
                (
                    "--manifest",
                    "--bundle",
                    "--bundle-root",
                    "--promotion",
                    "--allow-current-run-in-progress",
                ),
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
            (
                "select-canary",
                ("--metadata", "--workflow-revision", "--output"),
            ),
        ):
            result = subprocess.run(
                ["python3", str(helper), command, "--help"],
                check=True,
                capture_output=True,
                text=True,
            )
            for flag in required:
                self.assertIn(flag, result.stdout)
            if command == "verify-tag-binding":
                self.assertNotIn(
                    "--allow-current-run-in-progress",
                    result.stdout,
                )


if __name__ == "__main__":
    unittest.main()
