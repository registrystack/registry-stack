#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "check-gates-inventory.py"


def extract_top_level_block(workflow: str, name: str) -> str:
    lines = workflow.splitlines()
    start = lines.index(f"{name}:")
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index] and not lines[index].startswith(" ")
        ),
        len(lines),
    )
    return "\n".join(lines[start:end]).rstrip()


def load_module():
    spec = importlib.util.spec_from_file_location("check_gates_inventory", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GateInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.classifier = (ROOT / ".github" / "scripts" / "ci_changes.py").read_text(
            encoding="utf-8"
        )
        self.gitleaks_config = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
        parsed_gitleaks = tomllib.loads(self.gitleaks_config)
        self.gitleaks_paths = {
            path
            for allowlist in parsed_gitleaks["allowlists"]
            for path in allowlist.get("paths", [])
        }

    def test_real_ci_workflow_declares_inventory(self) -> None:
        self.assertEqual([], self.module.missing_gates(self.workflow))

    def test_real_release_security_workflows_preserve_policy(self) -> None:
        policy_texts = self.module.policy_file_texts(
            ROOT,
            self.module.RELEASE_SECURITY_POLICY_PATHS,
        )
        self.assertEqual(
            [],
            self.module.workflow_policy_violations(
                policy_texts,
                required=self.module.REQUIRED_RELEASE_SECURITY_GATES,
                ordered=self.module.ORDERED_RELEASE_SECURITY_GATES,
                forbidden=self.module.FORBIDDEN_RELEASE_SECURITY_GATES,
            ),
        )
        self.assertEqual(
            [],
            self.module.candidate_build_isolation_violations(
                policy_texts[".github/workflows/release-candidate.yml"]
            ),
        )
        self.assertEqual(
            [],
            self.module.candidate_attestation_isolation_violations(
                policy_texts[".github/workflows/release-candidate.yml"]
            ),
        )
        self.assertEqual(
            [],
            self.module.artifact_retention_violations(
                policy_texts[".github/workflows/release-candidate.yml"]
            ),
        )
        self.assertEqual(
            [],
            self.module.promotion_rebuild_violations(
                policy_texts[".github/workflows/release.yml"]
            ),
        )
        self.assertEqual(
            [],
            self.module.promotion_first_write_barrier_violations(
                policy_texts[".github/workflows/release.yml"]
            ),
        )
        self.assertEqual(
            [],
            self.module.release_draft_mutation_barrier_violations(
                policy_texts[".github/workflows/release.yml"]
            ),
        )

    def test_each_release_security_marker_is_fail_closed(self) -> None:
        policy_texts = self.module.policy_file_texts(
            ROOT,
            self.module.RELEASE_SECURITY_POLICY_PATHS,
        )
        for gate, path, snippets in self.module.REQUIRED_RELEASE_SECURITY_GATES:
            for index, snippet in enumerate(snippets):
                with self.subTest(gate=gate, snippet=snippet):
                    mutated = dict(policy_texts)
                    mutated[path] = mutated[path].replace(
                        snippet,
                        f"removed-security-marker-{index}",
                    )
                    self.assertIn(
                        gate,
                        self.module.workflow_policy_violations(
                            mutated,
                            required=self.module.REQUIRED_RELEASE_SECURITY_GATES,
                        ),
                    )

    def test_each_forbidden_release_security_marker_is_rejected(self) -> None:
        policy_texts = self.module.policy_file_texts(
            ROOT,
            self.module.RELEASE_SECURITY_POLICY_PATHS,
        )
        for gate, path, snippets in self.module.FORBIDDEN_RELEASE_SECURITY_GATES:
            for snippet in snippets:
                with self.subTest(gate=gate, snippet=snippet):
                    mutated = dict(policy_texts)
                    mutated[path] += f"\n{snippet}\n"
                    self.assertIn(
                        gate,
                        self.module.workflow_policy_violations(
                            mutated,
                            forbidden=self.module.FORBIDDEN_RELEASE_SECURITY_GATES,
                        ),
                    )

    def test_ci_concurrency_is_pr_scoped_and_only_cancels_pull_requests(self) -> None:
        self.assertEqual(
            "\n".join(
                (
                    "concurrency:",
                    "  group: ci-${{ github.event_name == 'pull_request' && format('pr-{0}', github.event.pull_request.number) || format('run-{0}', github.run_id) }}",
                    "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
                )
            ),
            extract_top_level_block(self.workflow, "concurrency"),
        )

    def test_ci_classifier_and_its_tests_are_wired(self) -> None:
        self.assertIn(
            "python3 .github/scripts/ci_changes.py",
            self.workflow,
        )
        self.assertIn(
            "run: python3 .github/scripts/test_ci_changes.py",
            self.workflow,
        )

    def test_workflow_policy_requires_every_marker_in_the_named_workflow(self) -> None:
        required = (
            ("candidate trigger", "candidate.yml", ("repository_dispatch:", "trusted")),
        )
        self.assertEqual(
            [],
            self.module.workflow_policy_violations(
                {"candidate.yml": "repository_dispatch:\ntrusted"},
                required=required,
            ),
        )
        self.assertEqual(
            ["candidate trigger"],
            self.module.workflow_policy_violations(
                {"other.yml": "repository_dispatch:\ntrusted"},
                required=required,
            ),
        )
        self.assertEqual(
            ["candidate trigger"],
            self.module.workflow_policy_violations(
                {"candidate.yml": "repository_dispatch:"},
                required=required,
            ),
        )

    def test_workflow_policy_requires_the_whole_barrier_before_publication(
        self,
    ) -> None:
        ordered = (
            ("verification barrier", "release.yml", "verify candidate", "publish"),
        )
        self.assertEqual(
            [],
            self.module.workflow_policy_violations(
                {"release.yml": "verify candidate\npublish"},
                ordered=ordered,
            ),
        )
        self.assertEqual(
            ["verification barrier"],
            self.module.workflow_policy_violations(
                {"release.yml": "verify candidate\npublish\nverify candidate"},
                ordered=ordered,
            ),
        )
        self.assertEqual(
            ["verification barrier"],
            self.module.workflow_policy_violations(
                {"release.yml": "publish\nverify candidate"},
                ordered=ordered,
            ),
        )

    def test_workflow_policy_rejects_forbidden_markers_fail_closed(self) -> None:
        forbidden = (("no ref writes", "release.yml", ("git push", "git update-ref")),)
        self.assertEqual(
            [],
            self.module.workflow_policy_violations(
                {"release.yml": "gh release create"},
                forbidden=forbidden,
            ),
        )
        self.assertEqual(
            ["no ref writes"],
            self.module.workflow_policy_violations(
                {"release.yml": "git push origin tag"},
                forbidden=forbidden,
            ),
        )
        self.assertEqual(
            ["no ref writes"],
            self.module.workflow_policy_violations(
                {},
                forbidden=forbidden,
            ),
        )

    def test_candidate_build_isolation_rejects_duplicate_or_reused_builds(self) -> None:
        workflow = self.module.policy_file_texts(
            ROOT,
            self.module.RELEASE_SECURITY_POLICY_PATHS,
        )[".github/workflows/release-candidate.yml"]
        build_b = self.module.yaml_job_block(workflow, "build-b")
        self.assertIsNone(build_b)
        duplicate = workflow.replace(
            "  build-platforms:",
            "  build-b:\n"
            "    name: Duplicate canonical build\n"
            "    needs: validate\n"
            "\n"
            "  build-platforms:",
        )
        reused = workflow.replace(
            "      - name: Build canonical Linux payload once",
            "      - name: Unsafe reuse\n"
            "        uses: actions/download-artifact@fake\n"
            "\n"
            "      - name: Build canonical Linux payload once",
            1,
        )
        for mutated in (duplicate, reused):
            self.assertEqual(
                ["Candidate build job isolation"],
                self.module.candidate_build_isolation_violations(mutated),
            )

    def test_candidate_verification_cannot_gain_oidc_or_attestation_writes(
        self,
    ) -> None:
        workflow = self.module.policy_file_texts(
            ROOT,
            self.module.RELEASE_SECURITY_POLICY_PATHS,
        )[".github/workflows/release-candidate.yml"]
        for marker in ("      id-token: write\n", "      attestations: write\n"):
            with self.subTest(marker=marker.strip()):
                mutated = workflow.replace(
                    "      packages: write\n",
                    f"      packages: write\n{marker}",
                    1,
                )
                self.assertEqual(
                    ["Candidate verification and attestation permission isolation"],
                    self.module.candidate_attestation_isolation_violations(mutated),
                )

    def test_candidate_attestation_must_consume_prior_verified_bundle(self) -> None:
        workflow = self.module.policy_file_texts(
            ROOT,
            self.module.RELEASE_SECURITY_POLICY_PATHS,
        )[".github/workflows/release-candidate.yml"]
        for marker in (
            "name: Upload one candidate manifest and bundle",
            "name: Download compact candidate",
            "name: Reverify all bytes before requesting OIDC",
        ):
            with self.subTest(marker=marker):
                mutated = workflow.replace(marker, "removed-attestation-barrier")
                self.assertEqual(
                    ["Candidate verification and attestation permission isolation"],
                    self.module.candidate_attestation_isolation_violations(mutated),
                )

    def test_candidate_artifact_contains_only_manifest_and_bundle(self) -> None:
        workflow = self.module.policy_file_texts(
            ROOT,
            self.module.RELEASE_SECURITY_POLICY_PATHS,
        )[".github/workflows/release-candidate.yml"]
        assemble = self.module.yaml_job_block(workflow, "assemble")
        self.assertIsNotNone(assemble)
        assert assemble is not None
        upload = next(
            block
            for block in self.module.yaml_step_blocks(assemble)
            if "name: Upload one candidate manifest and bundle" in block
        )
        self.assertIn("candidate/release-candidate-manifest.json", upload)
        self.assertIn(
            "candidate/registry-stack-${{ needs.validate.outputs.tag }}-candidate.tar.gz",
            upload,
        )
        self.assertNotIn("candidate-receipt", upload)

    def test_candidate_artifacts_use_scoped_retention(self) -> None:
        workflow = self.module.policy_file_texts(
            ROOT,
            self.module.RELEASE_SECURITY_POLICY_PATHS,
        )[".github/workflows/release-candidate.yml"]
        mutated = workflow.replace("retention-days: 7", "retention-days: 8", 1)
        self.assertEqual(
            ["Candidate artifact retention"],
            self.module.artifact_retention_violations(mutated),
        )
        mutated = workflow.replace("retention-days: 2", "retention-days: 8", 1)
        self.assertEqual(
            ["Candidate artifact retention"],
            self.module.artifact_retention_violations(mutated),
        )

    def test_promotion_rejects_any_product_rebuild_invocation(self) -> None:
        workflow = self.module.policy_file_texts(
            ROOT,
            self.module.RELEASE_SECURITY_POLICY_PATHS,
        )[".github/workflows/release.yml"]
        for command in (
            "release/scripts/build-release-binaries.sh 0.14.0",
            "release/scripts/build-release-image.sh registry-notary",
        ):
            with self.subTest(command=command):
                mutated = f"{workflow}\n      - name: Rebuild\n        run: {command}\n"
                self.assertEqual(
                    ["Promotion consumes candidate bytes without rebuilding"],
                    self.module.promotion_rebuild_violations(mutated),
                )

    def test_promotion_rechecks_every_destination_before_first_write(self) -> None:
        workflow = self.module.policy_file_texts(
            ROOT,
            self.module.RELEASE_SECURITY_POLICY_PATHS,
        )[".github/workflows/release.yml"]
        publish = self.module.yaml_job_block(workflow, "promote-images")
        self.assertIsNotNone(publish)
        for marker in (
            "name: Reconcile exact staged draft before first public image write",
            "name: Reconcile exact image digests",
            "reconcile-image-tag",
            '--expected-digest "${digest}"',
            'if [[ "${state}" == absent ]]; then',
            'test "${state}" = present',
            'test "$(crane digest "${final_ref}")" = "${digest}"',
        ):
            with self.subTest(marker=marker):
                mutated_publish = publish.replace(marker, "removed-prewrite-proof", 1)
                mutated = workflow.replace(publish, mutated_publish)
                self.assertEqual(
                    ["Promotion first-write destination barrier"],
                    self.module.promotion_first_write_barrier_violations(mutated),
                )

    def test_final_release_mutations_reject_an_early_publication_race(
        self,
    ) -> None:
        workflow = self.module.policy_file_texts(
            ROOT,
            self.module.RELEASE_SECURITY_POLICY_PATHS,
        )[".github/workflows/release.yml"]
        for marker in (
            "name: Clean retryable final additions and reverify exact staged assets",
            "contract/final-upload-release.json",
            "name: Sign and upload the checksum closure",
            "name: Classify exact bound draft or published release",
            "name: Recheck complete signed release and exact public images",
            "name: Publish immutable release",
        ):
            with self.subTest(marker=marker):
                mutated = workflow.replace(marker, "removed-draft-barrier", 1)
                self.assertEqual(
                    ["Final release mutations require the bound draft"],
                    self.module.release_draft_mutation_barrier_violations(
                        mutated
                    ),
                )
        for step_name in (
            "Clean retryable final additions and reverify exact staged assets",
            "Sign and upload the checksum closure",
            "Classify exact bound draft or published release",
            "Recheck complete signed release and exact public images",
            "Publish immutable release",
        ):
            with self.subTest(early_publication=step_name):
                step = next(
                    block
                    for block in self.module.yaml_step_blocks(workflow)
                    if f"name: {step_name}" in block
                )
                mutated_step = step.replace(
                    ".draft == true",
                    ".draft == false",
                    1,
                )
                mutated = workflow.replace(step, mutated_step, 1)
                self.assertEqual(
                    ["Final release mutations require the bound draft"],
                    self.module.release_draft_mutation_barrier_violations(
                        mutated
                    ),
                )

    def test_real_repository_has_no_tracked_nested_workflows(self) -> None:
        self.assertEqual(
            [],
            self.module.nested_workflow_paths(self.module.tracked_paths(ROOT)),
        )

    def test_every_release_unit_test_is_wired_into_root_ci(self) -> None:
        self.assertEqual(
            [],
            self.module.unwired_release_unit_tests(
                self.workflow,
                self.module.release_unit_test_paths(ROOT),
            ),
        )

    def test_unwired_release_unit_test_is_reported(self) -> None:
        self.assertEqual(
            ["release/scripts/test_new_release_gate.py"],
            self.module.unwired_release_unit_tests(
                self.workflow,
                [
                    "release/scripts/test_registry_release.py",
                    "release/scripts/test_new_release_gate.py",
                ],
            ),
        )

    def test_root_workflows_are_allowed(self) -> None:
        self.assertEqual(
            [],
            self.module.nested_workflow_paths(
                [
                    ".github/workflows/ci.yml",
                    ".github/workflows/release.yml",
                ]
            ),
        )

    def test_nested_workflow_is_reported(self) -> None:
        self.assertEqual(
            ["products/example/.github/workflows/ci.yml"],
            self.module.nested_workflow_paths(
                [
                    ".github/workflows/ci.yml",
                    "products/example/.github/workflows/ci.yml",
                ]
            ),
        )

    def test_missing_relay_exposure_gate_is_reported(self) -> None:
        text = self.workflow.replace(
            "name: Relay exposure check", "name: Relay exposure"
        )
        self.assertIn("Relay exposure check", self.module.missing_gates(text))

    def test_missing_debian13_image_contract_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 release/scripts/check-debian13-images.py",
            "run: true",
        )
        self.assertIn("Debian 13 image contract", self.module.missing_gates(text))

    def test_missing_pull_request_concurrency_group_is_reported(self) -> None:
        text = self.workflow.replace(
            "format('pr-{0}', github.event.pull_request.number)",
            "format('ref-{0}', github.ref)",
        )
        self.assertIn("Pull request concurrency group", self.module.missing_gates(text))

    def test_missing_pull_request_only_cancellation_is_reported(self) -> None:
        text = self.workflow.replace(
            "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
            "cancel-in-progress: true",
        )
        self.assertIn(
            "Pull request concurrency cancellation", self.module.missing_gates(text)
        )

    def test_missing_release_planning_command_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 -m unittest release/scripts/test_registry_release_plans.py",
            "run: true",
        )
        self.assertIn("Release planning command tests", self.module.missing_gates(text))

    def test_missing_release_candidate_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 -m unittest release/scripts/test_release_candidate.py",
            "run: true",
        )
        self.assertIn(
            "Release candidate receipt and promotion verifier tests",
            self.module.missing_gates(text),
        )

    def test_missing_new_release_security_tests_are_reported(self) -> None:
        tests = (
            (
                "release/scripts/test_select_release_proof_level.py",
                "Release proof-level selection tests",
            ),
            (
                "release/scripts/test_check_release_storage.py",
                "Release storage preflight tests",
            ),
            (
                "release/scripts/test_cleanup_release_candidates.py",
                "Release candidate cleanup tests",
            ),
            (
                "release/scripts/test_release_repeatability_workflow.py",
                "Release repeatability workflow tests",
            ),
        )
        for path, gate in tests:
            with self.subTest(path=path):
                text = self.workflow.replace(path, path.replace("test_", "skip_"))
                self.assertIn(gate, self.module.missing_gates(text))

    def test_missing_release_image_oci_checker_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 -m unittest release/scripts/test_check_release_image_oci_labels.py",
            "run: true",
        )
        self.assertIn(
            "Release image OCI label checker tests", self.module.missing_gates(text)
        )

    def test_missing_executable_release_image_oci_smoke_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: release/scripts/smoke-release-image-oci-labels.sh",
            "run: true",
        )
        self.assertIn(
            "Executable release image OCI label smoke", self.module.missing_gates(text)
        )

    def test_missing_release_workflow_classification_is_reported(self) -> None:
        workflows = (
            (
                ".github/workflows/release.yml",
                "Release workflow change classification",
            ),
            (
                ".github/workflows/release-candidate.yml",
                "Release candidate workflow change classification",
            ),
            (
                ".github/workflows/release-repeatability.yml",
                "Release repeatability workflow change classification",
            ),
            (
                ".github/workflows/release-candidate-cleanup.yml",
                "Release candidate cleanup workflow change classification",
            ),
        )
        for path, gate in workflows:
            with self.subTest(path=path):
                classifier = self.classifier.replace(
                    f'"{path}",',
                    f'"{path}.disabled",',
                )
                self.assertIn(
                    gate,
                    self.module.missing_gates(self.workflow, classifier),
                )

    def test_missing_actionlint_gate_is_reported(self) -> None:
        text = self.workflow.replace(
            '"${RUNNER_TEMP}/bin/actionlint"',
            '"${RUNNER_TEMP}/bin/actionlint-disabled"',
        )
        self.assertIn("actionlint workflow lint", self.module.missing_gates(text))

    def test_missing_actionlint_pin_or_checksum_is_reported(self) -> None:
        for snippet, replacement, gate in (
            (
                'ACTIONLINT_VERSION: "1.7.7"',
                'ACTIONLINT_VERSION: "latest"',
                "actionlint version pin",
            ),
            (
                'ACTIONLINT_LINUX_X64_SHA256: "023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757"',
                'ACTIONLINT_LINUX_X64_SHA256: "unverified"',
                "actionlint archive checksum",
            ),
        ):
            with self.subTest(gate=gate):
                text = self.workflow.replace(snippet, replacement)
                self.assertIn(gate, self.module.missing_gates(text))

    def test_missing_advisory_checker_identity_gate_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 release/scripts/check_advisory_checker_copies.py",
            "run: true",
        )
        self.assertIn(
            "Advisory checker byte identity",
            self.module.missing_gates(text),
        )

    def test_missing_advisory_checker_identity_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 -m unittest release/scripts/test_check_advisory_checker_copies.py",
            "run: true",
        )
        self.assertIn(
            "Advisory checker identity guard tests",
            self.module.missing_gates(text),
        )

    def test_missing_advisory_checker_tests_are_reported(self) -> None:
        for path, gate in (
            (
                "products/notary/tests/advisory_baseline_check_test.py",
                "Notary advisory checker tests",
            ),
            (
                "crates/registry-relay/tests/advisory_baseline_check_test.py",
                "Relay advisory checker tests",
            ),
        ):
            with self.subTest(path=path):
                text = self.workflow.replace(
                    path,
                    path.replace(
                        "advisory_baseline_check_test.py",
                        "disabled_advisory_test.py",
                    ),
                )
                self.assertIn(gate, self.module.missing_gates(text))

    def test_missing_relay_all_features_shard_is_reported(self) -> None:
        classifier = self.classifier.replace(
            '"all_features": shard_name == "relay"',
            '"all_features": False',
        )
        self.assertIn(
            "Relay all-features shard",
            self.module.missing_gates(self.workflow, classifier),
        )

    def test_missing_config_report_platform_path_is_reported(self) -> None:
        classifier = self.classifier.replace(
            '"crates/registry-config-report/*",',
            '"crates/removed-config-report/*",',
        )
        self.assertIn(
            "Config report platform path",
            self.module.missing_gates(self.workflow, classifier),
        )

    def test_missing_affected_package_test_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 .github/scripts/run_cargo_packages.py test",
            "run: python3 .github/scripts/run_cargo_packages.py skip-tests",
        )
        self.assertIn("Affected package tests", self.module.missing_gates(text))

    def test_missing_config_report_platform_clippy_is_reported(self) -> None:
        text = self.workflow.replace(
            "cargo clippy --locked -p registry-config-report -p 'registry-platform-*' --all-targets --all-features -- -D warnings",
            "cargo clippy --locked -p 'registry-platform-*' --all-targets --all-features -- -D warnings",
        )
        self.assertIn("Platform all-features clippy", self.module.missing_gates(text))

    def test_missing_platform_coverage_threshold_is_reported(self) -> None:
        text = self.workflow.replace("--fail-under-lines 80", "--summary-only")
        self.assertIn("Platform coverage threshold", self.module.missing_gates(text))

    def test_missing_config_report_platform_coverage_is_reported(self) -> None:
        text = self.workflow.replace(
            "cargo llvm-cov --locked\n          -p registry-config-report\n          -p 'registry-platform-*'",
            "cargo llvm-cov --locked\n          -p 'registry-platform-*'",
        )
        self.assertIn(
            "Config report platform coverage", self.module.missing_gates(text)
        )

    def test_missing_secret_scan_redaction_is_reported(self) -> None:
        text = self.workflow.replace("--redact", "--verbose")
        self.assertIn("Gitleaks redaction", self.module.missing_gates(text))

    def test_root_secret_scan_names_all_synthetic_platform_jwt_fixtures(self) -> None:
        for fixture_path in (
            r"^products/platform/fuzz/corpus/oid4vci_request_and_proof/credential_request\.json$",
            r"^products/platform/fuzz/corpus/oid4vci_request_and_proof/valid-proof-jwt$",
            r"^products/platform/fuzz/corpus/sdjwt_holder_proof/holder_proof\.jwt$",
            r"^products/platform/fuzz/corpus/sdjwt_holder_proof/valid-holder-proof-jwt$",
        ):
            with self.subTest(fixture_path=fixture_path):
                self.assertIn(fixture_path, self.gitleaks_paths)

    def test_root_secret_scan_does_not_keep_pre_monorepo_fuzz_paths(self) -> None:
        self.assertFalse(any(path.startswith("^fuzz/") for path in self.gitleaks_paths))

    def test_root_secret_scan_excludes_only_named_generated_ignored_trees(self) -> None:
        generated_trees = (
            (
                r"^docs/site/\.repo-docs-cache/",
                "docs/site/.repo-docs-cache/generated.txt",
            ),
            (
                r"^editors/vscode/\.vscode-test/",
                "editors/vscode/.vscode-test/generated.txt",
            ),
        )
        for allowlist_path, generated_probe in generated_trees:
            with self.subTest(generated_probe=generated_probe):
                self.assertIn(allowlist_path, self.gitleaks_paths)
                ignored = subprocess.run(
                    ["git", "check-ignore", "--quiet", generated_probe],
                    cwd=ROOT,
                    check=False,
                )
                self.assertEqual(0, ignored.returncode)

    def test_missing_platform_fuzz_bound_is_reported(self) -> None:
        text = self.workflow.replace("-max_total_time=60", "-runs=0")
        self.assertIn("Platform fuzz bounded runtime", self.module.missing_gates(text))

    def test_missing_registryctl_tutorial_execution_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: npm run check:tutorial:registryctl",
            "run: npm run execute-registryctl-tutorial",
        )
        self.assertIn(
            "Registryctl tutorial source execution", self.module.missing_gates(text)
        )

    def test_missing_manifest_profile_validation_is_reported(self) -> None:
        text = self.workflow.replace(
            "cargo run --locked --profile ci -p registry-manifest-cli -- validate-profiles profiles",
            "cargo run --locked --profile ci -p registry-manifest-cli -- skip-profile-validation",
        )
        self.assertIn("Manifest profile validation", self.module.missing_gates(text))

    def test_missing_release_docset_validation_is_reported(self) -> None:
        text = self.workflow.replace(
            "release/scripts/registry-release validate-docsets",
            "release/scripts/registry-release skip-docsets",
        )
        self.assertIn("Release docset validation", self.module.missing_gates(text))

    def test_missing_openid_conformance_runner_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "python3 -m unittest release/scripts/test_openid_conformance_runner.py",
            "python3 release/scripts/openid-conformance-runner.py list",
        )
        self.assertIn(
            "OpenID conformance runner tests", self.module.missing_gates(text)
        )

    def test_missing_external_integration_runner_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "python3 -m unittest release/scripts/test_integration_e2_runner.py",
            "python3 release/scripts/integration-e2-runner.py dry-run",
        )
        self.assertIn(
            "External integration evidence runner tests",
            self.module.missing_gates(text),
        )

    def test_release_tool_runs_conformance_candidate_binding_tests(self) -> None:
        release_tool = self.workflow[
            self.workflow.index("  release-tool:\n") : self.workflow.index(
                "  release-tool-required:\n"
            )
        ]
        self.assertIn(
            "run: python3 -m unittest release/scripts/test_conformance_candidate.py",
            release_tool,
        )

    def test_missing_first_country_release_form_runner_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "python3 -m unittest release/scripts/test_first_country_release_form.py",
            "python3 release/scripts/first-country-release-form.py --help",
        )
        self.assertIn(
            "First-country release-form runner tests",
            self.module.missing_gates(text),
        )

    def test_missing_external_integration_packet_validation_is_reported(self) -> None:
        text = self.workflow.replace(
            "python3 release/scripts/integration-e2-runner.py validate",
            "python3 release/scripts/integration-e2-runner.py plan",
        )
        self.assertIn(
            "External integration evidence packet",
            self.module.missing_gates(text),
        )

    def test_missing_relay_oidc_smoke_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "python3 -m unittest release/scripts/test_relay_oidc_smoke.py",
            "python3 release/scripts/relay-oidc-smoke.py plan",
        )
        self.assertIn("Relay OIDC smoke tests", self.module.missing_gates(text))

    def test_missing_relay_oidc_offline_validation_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 release/scripts/relay-oidc-smoke.py validate",
            "run: python3 release/scripts/relay-oidc-smoke.py skip-validation",
        )
        self.assertIn(
            "Relay OIDC smoke offline validation", self.module.missing_gates(text)
        )

    def test_missing_stable_surface_gate_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 release/scripts/check-stable-surface-compatibility.py",
            "run: python3 release/scripts/skip-stable-surface-compatibility.py",
        )
        self.assertIn("Stable surface compatibility", self.module.missing_gates(text))

    def test_missing_relay_openapi_stability_filter_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 -m unittest release/scripts/test_filter_relay_openapi_stability.py",
            "run: python3 -m unittest release/scripts/skip_filter_relay_openapi_stability.py",
        )
        self.assertIn(
            "Relay OpenAPI stability filter tests", self.module.missing_gates(text)
        )

    def test_missing_openapi_base_reference_is_reported(self) -> None:
        text = self.workflow.replace(
            "OPENAPI_CONTRACT_BASE_REF: ${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || github.event.before }}",
            "OPENAPI_CONTRACT_BASE_REF: disabled",
        )
        self.assertIn("OpenAPI base-reference input", self.module.missing_gates(text))

    def test_missing_upgrade_exercise_record_discovery_is_reported(self) -> None:
        text = self.workflow.replace(
            "python3 release/scripts/validate-upgrade-exercise.py",
            "python3 release/scripts/validate-upgrade-exercise.py --skip-discovery",
        )
        self.assertIn(
            "Upgrade exercise record discovery", self.module.missing_gates(text)
        )

    def test_missing_product_input_lifecycle_validator_tests_are_reported(
        self,
    ) -> None:
        text = self.workflow.replace(
            "python3 -m unittest release/scripts/test_validate_product_input_lifecycle.py",
            "python3 -m unittest release/scripts/skip_validate_product_input_lifecycle.py",
        )
        self.assertIn(
            "Product-input lifecycle validator tests",
            self.module.missing_gates(text),
        )

    def test_missing_product_input_lifecycle_record_discovery_is_reported(
        self,
    ) -> None:
        text = self.workflow.replace(
            "--candidate-asset-root target/candidate-release-assets",
            "--candidate-asset-root target/unauthenticated-assets",
            1,
        )
        self.assertIn(
            "Product-input lifecycle record discovery",
            self.module.missing_gates(text),
        )

    def test_missing_first_country_acceptance_validator_tests_are_reported(
        self,
    ) -> None:
        text = self.workflow.replace(
            "python3 -m unittest release/scripts/test_validate_first_country_acceptance.py",
            "python3 -m unittest release/scripts/skip_validate_first_country_acceptance.py",
        )
        self.assertIn(
            "First-country acceptance validator tests",
            self.module.missing_gates(text),
        )

    def test_missing_first_country_acceptance_source_packet_is_reported(
        self,
    ) -> None:
        text = self.workflow.replace(
            "python3 release/scripts/validate-first-country-acceptance.py check-packet",
            "python3 release/scripts/validate-first-country-acceptance.py skip-packet",
        )
        self.assertIn(
            "First-country acceptance source packet",
            self.module.missing_gates(text),
        )

    def test_missing_upgrade_exercise_asset_preparation_is_reported(self) -> None:
        text = self.workflow.replace(
            "python3 release/scripts/prepare-upgrade-exercise-assets.py",
            "python3 release/scripts/skip-upgrade-exercise-assets.py",
        )
        self.assertIn(
            "Candidate evidence asset preparation",
            self.module.missing_gates(text),
        )

    def test_product_input_candidates_enable_cosign_installation(self) -> None:
        text = self.workflow.replace(
            "if: steps.candidate-assets.outputs.has_candidates == 'true'",
            "if: steps.upgrade-assets.outputs.has_candidates == 'true'",
            1,
        )
        self.assertIn(
            "Candidate evidence Cosign installation",
            self.module.missing_gates(text),
        )

    def test_product_input_candidates_enable_slsa_verifier_installation(
        self,
    ) -> None:
        marker = "if: steps.candidate-assets.outputs.has_candidates == 'true'"
        first = self.workflow.index(marker)
        second = self.workflow.index(marker, first + len(marker))
        text = self.workflow[:second] + self.workflow[second:].replace(
            marker,
            "if: steps.upgrade-assets.outputs.has_candidates == 'true'",
            1,
        )
        self.assertIn(
            "Candidate evidence SLSA verifier installation",
            self.module.missing_gates(text),
        )

    def test_missing_upgrade_exercise_asset_root_is_reported(self) -> None:
        text = self.workflow.replace(
            "--candidate-asset-root target/candidate-release-assets",
            "--candidate-asset-root target/unauthenticated-assets",
        )
        self.assertIn(
            "Upgrade exercise record discovery", self.module.missing_gates(text)
        )

    def test_missing_product_input_lifecycle_asset_preparation_is_reported(
        self,
    ) -> None:
        text = self.workflow.replace(
            "--product-input-records release/exercises/product-input-lifecycle",
            "--product-input-records release/exercises/removed-lifecycle",
        )
        self.assertIn(
            "Candidate evidence asset preparation",
            self.module.missing_gates(text),
        )

    def test_missing_stable_error_registry_path_filter_is_reported(self) -> None:
        classifier = self.classifier.replace(
            '"docs/site/src/content/docs/reference/errors.mdx",',
            '"docs/site/src/content/docs/reference/removed-errors.mdx",',
        )
        self.assertIn(
            "Stable error registry path filter",
            self.module.missing_gates(self.workflow, classifier),
        )

    def test_missing_relay_support_roster_path_filter_is_reported(self) -> None:
        classifier = self.classifier.replace(
            '"docs/site/src/data/relay-support.yaml",',
            '"docs/site/src/data/removed-relay-support.yaml",',
        )
        self.assertIn(
            "Relay support roster path filter",
            self.module.missing_gates(self.workflow, classifier),
        )

    def test_missing_registryctl_tutorial_path_filter_is_reported(self) -> None:
        text = self.workflow.replace(
            "registryctl_tutorial: ${{ steps.filter.outputs.registryctl_tutorial }}",
            "registryctl_tutorial_disabled: ${{ steps.filter.outputs.registryctl_tutorial }}",
        )
        self.assertIn(
            "Registryctl tutorial path filter", self.module.missing_gates(text)
        )


if __name__ == "__main__":
    unittest.main()
