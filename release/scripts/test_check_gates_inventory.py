#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import tomllib
import unittest
from pathlib import Path

import yaml


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
        self.nightly_security = (
            ROOT / ".github" / "workflows" / "nightly-security.yml"
        ).read_text(encoding="utf-8")
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
            self.module.security_workflow_classification_violations(
                self.module.RELEASE_SECURITY_POLICY_PATHS,
                self.module.classifier_security_workflow_gates(),
            ),
        )
        self.assertEqual(
            [],
            self.module.nightly_security_sweep_violations(
                policy_texts[".github/workflows/nightly-security.yml"]
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

    def test_security_workflow_classifier_inventory_cannot_drift(self) -> None:
        required = self.module.REQUIRED_SECURITY_WORKFLOW_SELECTIONS
        for workflow in sorted(required):
            with self.subTest(missing_classifier_workflow=workflow):
                mutated = dict(required)
                mutated.pop(workflow)
                self.assertEqual(
                    ["Security workflow policy classification inventory"],
                    self.module.security_workflow_classification_violations(
                        self.module.RELEASE_SECURITY_POLICY_PATHS,
                        mutated,
                    ),
                )
            with self.subTest(missing_policy_workflow=workflow):
                policy_paths = tuple(
                    path
                    for path in self.module.RELEASE_SECURITY_POLICY_PATHS
                    if path != workflow
                )
                self.assertEqual(
                    ["Security workflow policy classification inventory"],
                    self.module.security_workflow_classification_violations(
                        policy_paths,
                        required,
                    ),
                )

    def test_nightly_security_sweep_covers_every_declared_fuzz_target(self) -> None:
        fuzz_manifests = {
            "platform-fuzz": ROOT / "products" / "platform" / "fuzz" / "Cargo.toml",
            "manifest-fuzz": ROOT / "products" / "manifest" / "fuzz" / "Cargo.toml",
        }
        for job_id, manifest in fuzz_manifests.items():
            with self.subTest(job_id=job_id):
                parsed = tomllib.loads(manifest.read_text(encoding="utf-8"))
                declared_targets = tuple(entry["name"] for entry in parsed["bin"])
                self.assertEqual(
                    self.module.REQUIRED_NIGHTLY_FUZZ_TARGETS[job_id],
                    declared_targets,
                )
        self.assertEqual(
            [],
            self.module.nightly_security_sweep_violations(self.nightly_security),
        )

    def test_nightly_security_sweep_cannot_be_path_suppressed_or_partial(self) -> None:
        gate = ["Nightly security sweep completeness"]
        mutations = {
            "changed-path job": self.nightly_security.replace(
                "jobs:\n",
                "jobs:\n"
                "  changes:\n"
                "    name: Changed security surfaces\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps: []\n\n",
                1,
            ),
            "conditional assurance": self.nightly_security.replace(
                "  assurance:\n",
                "  assurance:\n    if: needs.changes.outputs.run == 'true'\n",
                1,
            ),
            "dependent platform fuzz": self.nightly_security.replace(
                "  platform-fuzz:\n",
                "  platform-fuzz:\n    needs: changes\n",
                1,
            ),
            "cached sweep state": self.nightly_security.replace(
                "jobs:\n",
                "jobs:\n  # .nightly-security-state/last-success-sha\n",
                1,
            ),
        }
        for job_targets in self.module.REQUIRED_NIGHTLY_FUZZ_TARGETS.values():
            for target in job_targets:
                mutations[f"missing fuzz target {target}"] = (
                    self.nightly_security.replace(target, f"removed_{target}", 1)
                )
        for mutation, workflow in mutations.items():
            with self.subTest(mutation=mutation):
                self.assertEqual(
                    gate,
                    self.module.nightly_security_sweep_violations(workflow),
                )
        self.assertEqual(
            gate,
            self.module.nightly_security_sweep_violations(None),
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

    def test_only_protected_main_push_coverage_can_receive_oidc_permission(
        self,
    ) -> None:
        self.assertEqual(
            [],
            self.module.platform_coverage_oidc_isolation_violations(self.workflow),
        )
        protected_push = (
            "if: github.event_name == 'push' && github.ref == 'refs/heads/main'"
        )
        upload_if = (
            f"{protected_push} && needs.changes.outputs.platform == 'true'"
        )
        mutations = (
            (
                "    steps:\n      - name: Checkout",
                "    permissions:\n      contents: read\n      id-token: write\n"
                "    steps:\n      - name: Checkout",
            ),
            (
                upload_if,
                "if: needs.changes.outputs.platform == 'true'",
            ),
            (
                upload_if,
                "if: github.event_name != 'pull_request' && needs.changes.outputs.platform == 'true'",
            ),
            (
                upload_if,
                "if: github.ref == 'refs/heads/main' && needs.changes.outputs.platform == 'true'",
            ),
            (
                upload_if,
                "if: github.event_name == 'push' && needs.changes.outputs.platform == 'true'",
            ),
            (
                protected_push,
                "if: github.event_name != 'pull_request'",
            ),
            (
                protected_push,
                "if: github.ref == 'refs/heads/main'",
            ),
            (
                protected_push,
                "if: github.event_name == 'push'",
            ),
            (
                "      - name: Download platform coverage",
                "      - name: Execute repository code\n        run: cargo test\n\n"
                "      - name: Download platform coverage",
            ),
            (
                "    steps:\n      - name: Download platform coverage",
                "    steps:\n"
                "      - uses: ./.github/actions/untrusted\n"
                "      - name: Download platform coverage",
            ),
            (
                "permissions:\n  contents: read",
                "permissions: write-all",
            ),
            (
                "      id-token: write\n    steps:",
                "      id-token: write\n      issues: write\n    steps:",
            ),
            (
                "      - platform-coverage-upload\n",
                "",
            ),
        )
        for before, after in mutations:
            with self.subTest(before=before):
                mutated = self.workflow.replace(before, after, 1)
                self.assertEqual(
                    ["Platform coverage OIDC permission isolation"],
                    self.module.platform_coverage_oidc_isolation_violations(mutated),
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
        mutated = workflow.replace("retention-days: 8", "retention-days: 7", 1)
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

    def test_missing_relay_v2_product_gates_are_reported(self) -> None:
        for snippet, replacement, gate in (
            (
                "relay-v2-contracts:",
                "relay-v2-disabled:",
                "Relay V2 product contract gate",
            ),
            (
                "run: products/relay-v2/scripts/check-contracts.sh",
                "run: true # Relay V2 contracts disabled",
                "Relay V2 contract consistency",
            ),
            (
                "run: products/relay-v2/scripts/test-http.sh",
                "run: true # Relay V2 HTTP disabled",
                "Relay V2 coequal HTTP journeys",
            ),
        ):
            with self.subTest(gate=gate):
                text = self.workflow.replace(snippet, replacement)
                self.assertIn(gate, self.module.missing_gates(text))

    def test_missing_relay_client_contract_gates_are_reported(self) -> None:
        for snippet, replacement, gate in (
            (
                "relay-client-contracts:",
                "relay-client-disabled:",
                "Relay client contract gate",
            ),
            (
                "run: products/relay-v2/scripts/check-client-contract.sh",
                "run: true # Relay client contracts disabled",
                "Relay client contract consistency",
            ),
            (
                "run: products/relay-v2/scripts/check-source-neutrality.sh",
                "run: true # Relay client neutrality disabled",
                "Relay client source neutrality",
            ),
        ):
            with self.subTest(gate=gate):
                text = self.workflow.replace(snippet, replacement)
                self.assertIn(gate, self.module.missing_gates(text))

    def test_missing_registry_server_product_gates_are_reported(self) -> None:
        for snippet, replacement, gate in (
            (
                "registry-server-contracts:",
                "registry-server-disabled:",
                "Registry Server product contract gate",
            ),
            (
                "run: products/registry-server/scripts/check-contracts.sh",
                "run: true # Registry Server contracts disabled",
                "Registry Server contract consistency",
            ),
            (
                "run: products/registry-server/scripts/test-postgres.sh",
                "run: true # Registry Server PostgreSQL disabled",
                "Registry Server PostgreSQL journeys",
            ),
            (
                "run: products/registry-server/scripts/test-adopter-workflow.sh",
                "run: true # Registry Server adopter workflow disabled",
                "Registry Server adopter workflow",
            ),
            (
                "postgis/postgis@sha256:01a6a70e41e6c4467c8f55f6063555ed72db2d6662cd0d571040d42eadaeb6f6",
                "postgis/postgis",
                "Registry Server PostgreSQL 17 / PostGIS 3.5 image pin",
            ),
        ):
            with self.subTest(gate=gate):
                text = self.workflow.replace(snippet, replacement, 1)
                self.assertIn(gate, self.module.missing_gates(text))

    def test_linux_node_release_proof_is_two_runner_read_only_and_aggregated(
        self,
    ) -> None:
        document = yaml.safe_load(self.workflow)
        job = document["jobs"]["release-linux-node-clients"]
        self.assertEqual(
            "needs.changes.outputs.release_linux_node_clients == 'true'",
            job["if"],
        )
        self.assertEqual({"contents": "read"}, job["permissions"])
        self.assertEqual("1.95.0", job["env"]["RUSTUP_TOOLCHAIN"])
        self.assertEqual(
            {
                (
                    "ubuntu-24.04",
                    "x86_64-unknown-linux-gnu",
                    "linux-x64-gnu",
                ),
                (
                    "ubuntu-24.04-arm",
                    "aarch64-unknown-linux-gnu",
                    "linux-arm64-gnu",
                ),
            },
            {
                (entry["runner"], entry["target"], entry["napi_platform"])
                for entry in job["strategy"]["matrix"]["include"]
            },
        )
        setup_node = next(
            step for step in job["steps"] if step.get("name") == "Setup Node"
        )
        self.assertEqual("22.20.0", setup_node["with"]["node-version"])
        install = next(
            step["run"]
            for step in job["steps"]
            if step.get("name") == "Install pinned Linux client build tools"
        )
        self.assertIn("rustup toolchain install 1.95.0 --profile minimal", install)
        self.assertIn("--require-hashes --only-binary=:all:", install)
        self.assertIn("release/requirements/maturin-1.9.6.txt", install)
        proof = next(
            step["run"]
            for step in job["steps"]
            if step.get("name") == "Prove production Linux Node client recipe"
        )
        self.assertIn("for client in discovery evidence relay", proof)
        self.assertIn("release/scripts/build-linux-node-client", proof)
        self.assertIn('--target "${{ matrix.target }}"', proof)
        self.assertIn('--napi-platform "${{ matrix.napi_platform }}"', proof)
        self.assertIn('--zig-python "${RUNNER_TEMP}/maturin/bin/python"', proof)
        self.assertIn("smoke-${client}-client-package.js", proof)
        self.assertIn('(cd "${smoke}" && node "smoke-${client}-client-package.js")', proof)
        self.assertNotIn("napi build", proof)
        self.assertNotIn("npm pack", proof)
        self.assertNotIn("docker run", proof)
        self.assertFalse(any("upload-artifact@" in str(step) for step in job["steps"]))
        self.assertNotIn("contents: write", str(job))
        for forbidden in ("npm publish", "gh release", "docker push"):
            self.assertNotIn(forbidden, str(job))
        self.assertIn(
            "release-linux-node-clients",
            document["jobs"]["ci-result"]["needs"],
        )

    def test_missing_linux_node_release_proof_gates_are_reported(self) -> None:
        mutations = (
            (
                "release_linux_node_clients: ${{ steps.filter.outputs.release_linux_node_clients }}",
                "release_linux_node_clients: false",
                "Release Linux Node client path filter",
            ),
            (
                "release-linux-node-clients:\n    name: Release Linux Node clients",
                "release-linux-node-clients:\n    name: Disabled Linux Node clients",
                "Release Linux Node client proof job",
            ),
            (
                "release/scripts/build-linux-node-client \\",
                "release/scripts/disabled-linux-node-client \\",
                "Release Linux Node client helper invocation",
            ),
            (
                '--requirement "${GITHUB_WORKSPACE}/release/requirements/maturin-1.9.6.txt"',
                '--requirement "${GITHUB_WORKSPACE}/release/requirements/unpinned.txt"',
                "Release Linux Node client pinned tools",
            ),
            (
                "      - release-linux-node-clients",
                "      - disabled-linux-node-clients",
                "Release Linux Node client CI aggregate",
            ),
        )
        for snippet, replacement, gate in mutations:
            with self.subTest(gate=gate):
                text = self.workflow.replace(snippet, replacement, 1)
                self.assertIn(gate, self.module.missing_gates(text))

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
            "Release candidate manifest and promotion verifier tests",
            self.module.missing_gates(text),
        )

    def test_missing_release_image_oci_label_checks_are_reported(self) -> None:
        tests = (
            (
                "release/scripts/test_check_release_image_oci_labels.py",
                "Release image OCI label checker tests",
            ),
            (
                "release/scripts/smoke-release-image-oci-labels.sh",
                "Release image OCI label smoke",
            ),
        )
        for path, gate in tests:
            with self.subTest(path=path):
                text = self.workflow.replace(path, "release/scripts/disabled-gate")
                self.assertIn(gate, self.module.missing_gates(text))

    def test_missing_container_runtime_preflight_tests_are_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 -m unittest docker/test_runtime_preflight.py",
            "run: true",
        )
        self.assertIn(
            "Container runtime preflight tests",
            self.module.missing_gates(text),
        )

    def test_missing_new_release_security_tests_are_reported(self) -> None:
        tests = (
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
            (
                "release/scripts/test_release_rehearsal.py",
                "Release rehearsal workflow tests",
            ),
            (
                "release/scripts/test_build_linux_node_client.py",
                "Linux Node client release build helper tests",
            ),
            (
                "release/scripts/test_zig_glibc_compiler.py",
                "Zig glibc compiler wrapper tests",
            ),
            (
                "release/scripts/test_verify_public_release.py",
                "Public release verifier tests",
            ),
        )
        for path, gate in tests:
            with self.subTest(path=path):
                text = self.workflow.replace(path, path.replace("test_", "skip_"))
                self.assertIn(gate, self.module.missing_gates(text))



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




    def test_missing_affected_package_test_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: python3 .github/scripts/run_cargo_packages.py test",
            "run: python3 .github/scripts/run_cargo_packages.py skip-tests",
        )
        self.assertIn("Affected package tests", self.module.missing_gates(text))


    def test_missing_platform_coverage_threshold_is_reported(self) -> None:
        text = self.workflow.replace("--fail-under-lines 80", "--summary-only")
        self.assertIn("Platform coverage threshold", self.module.missing_gates(text))


    def test_missing_secret_scan_redaction_is_reported(self) -> None:
        text = self.workflow.replace("--redact", "--verbose")
        self.assertIn("Gitleaks redaction", self.module.missing_gates(text))

    def test_root_secret_scan_names_all_synthetic_platform_jwt_fixtures(self) -> None:
        for fixture_path in (
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

    def test_missing_production_shaped_docs_build_check_is_reported(self) -> None:
        text = self.workflow.replace(
            "run: npm run check:production",
            "run: npm run verify",
        )
        self.assertIn(
            "Production-shaped docs build check",
            self.module.missing_gates(text),
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

    def test_release_manifest_validation_uses_only_the_maintained_manifest(self) -> None:
        command = (
            "release/scripts/registry-release validate-current"
        )
        self.assertIn(command, self.workflow)
        self.assertNotIn(
            "for manifest in release/manifests/registry-stack-*.yaml",
            self.workflow,
        )

        text = self.workflow.replace(command, "release/scripts/registry-release skip")
        self.assertIn("Release manifest validation", self.module.missing_gates(text))



















    def test_missing_stable_error_registry_path_filter_is_reported(self) -> None:
        classifier = self.classifier.replace(
            '"docs/site/src/content/docs/reference/errors.mdx",',
            '"docs/site/src/content/docs/reference/removed-errors.mdx",',
        )
        self.assertIn(
            "Stable error registry path filter",
            self.module.missing_gates(self.workflow, classifier),
        )

    def test_missing_relay_v2_product_document_path_filter_is_reported(self) -> None:
        classifier = self.classifier.replace(
            '"products/relay-v2/CONCEPT.md",',
            '"products/relay-v2/removed-CONCEPT.md",',
        )
        self.assertIn(
            "Relay V2 product document path filter",
            self.module.missing_gates(self.workflow, classifier),
        )


if __name__ == "__main__":
    unittest.main()
