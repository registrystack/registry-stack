#!/usr/bin/env python3

from __future__ import annotations

import fnmatch
import json
import re
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from ci_changes import (
    AUTHORING_REFERENCE_CONTRACT_SOURCES,
    AUTHORING_REFERENCE_INPUTS,
    RELEASE_SECURITY_WORKFLOWS,
    SHARDS,
    Workspace,
    authoring_reference_inputs,
    classify,
    validate_authoring_reference_routing,
)
from run_cargo_packages import command_args, package_args


class CiChangesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        metadata = subprocess.run(
            ("cargo", "metadata", "--locked", "--format-version", "1"),
            check=True,
            capture_output=True,
            text=True,
        )
        cls.workspace = Workspace(json.loads(metadata.stdout))

    def test_shards_cover_every_workspace_package_once(self) -> None:
        assigned = [package for packages in SHARDS.values() for package in packages]
        self.assertCountEqual(assigned, self.workspace.package_names)
        self.assertEqual(len(assigned), len(set(assigned)))

    def test_example_pr_runs_only_affected_rust_shards(self) -> None:
        outputs = classify(
            self.workspace,
            (
                ".github/workflows/release.yml",
                "crates/registry-relay/docs/configuration.md",
                "crates/registry-relay/src/state_plane/runtime.rs",
                "crates/registryctl/src/project_authoring/project.rs",
                "release/scripts/test_registry_release.py",
            ),
        )
        shard_names = {entry["name"] for entry in outputs["rust_matrix"]["include"]}
        self.assertEqual(shard_names, {"relay", "registryctl"})
        self.assertTrue(outputs["release_tool"])
        self.assertTrue(outputs["release_source_proof"])
        self.assertTrue(outputs["registryctl_tutorial"])
        self.assertFalse(outputs["platform"])

    def test_reverse_dependencies_are_included(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-platform-crypto/src/lib.rs",),
        )
        self.assertIn("registry-platform-crypto", outputs["rust_packages"])
        self.assertIn("registry-relay", outputs["rust_packages"])
        self.assertIn("registry-notary", outputs["rust_packages"])
        self.assertTrue(outputs["registryctl_tutorial"])

    def test_ci_workflow_change_runs_the_complete_matrix(self) -> None:
        outputs = classify(self.workspace, (".github/workflows/ci.yml",))
        self.assertCountEqual(outputs["rust_packages"], self.workspace.package_names)
        self.assertTrue(outputs["docs"])
        self.assertTrue(outputs["docs_archives"])
        self.assertTrue(outputs["editors"])

    def test_docs_only_change_skips_rust(self) -> None:
        outputs = classify(
            self.workspace,
            ("docs/site/src/content/docs/reference/glossary.mdx",),
        )
        self.assertFalse(outputs["rust"])
        self.assertEqual(outputs["rust_matrix"], {"include": []})
        self.assertTrue(outputs["docs"])
        self.assertFalse(outputs["docs_archives"])

    def test_archive_content_is_immutable_during_routine_docs_changes(self) -> None:
        current_content = classify(
            self.workspace,
            ("docs/site/src/content/docs/reference/glossary.mdx",),
        )
        archive_lock = classify(
            self.workspace,
            ("docs/site/src/data/archive-lock.yaml",),
        )
        archive_assembler = classify(
            self.workspace,
            ("docs/site/scripts/assemble-archives.mjs",),
        )
        self.assertFalse(current_content["docs_archives"])
        self.assertTrue(archive_lock["docs_archives"])
        self.assertTrue(archive_assembler["docs_archives"])

    def test_archive_dependent_scripts_select_archive_verification(self) -> None:
        for path in (
            ".github/scripts/ci_changes.py",
            "docs/site/scripts/check-built-links.mjs",
            "docs/site/scripts/check-seo.mjs",
            "docs/site/scripts/docsets.mjs",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["docs_archives"])

    def test_run_all_does_not_rebuild_immutable_archives_without_changed_paths(self) -> None:
        outputs = classify(self.workspace, (), run_all=True)
        self.assertTrue(outputs["docs"])
        self.assertFalse(outputs["docs_archives"])

    def test_run_all_keeps_archive_sensitive_changed_paths(self) -> None:
        outputs = classify(
            self.workspace,
            ("docs/site/scripts/archive-bundle.mjs",),
            run_all=True,
        )
        self.assertTrue(outputs["docs"])
        self.assertTrue(outputs["docs_archives"])

    def test_authoring_reference_inputs_run_docs(self) -> None:
        for _, path in AUTHORING_REFERENCE_INPUTS:
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["docs"])

    def test_authoring_reference_input_samples_must_exist_as_files(self) -> None:
        manifest_path = Path("docs/site/scripts/authoring-reference-sources.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        missing_sample = (
            "crates/registryctl/schemas/project-authoring/missing.schema.json"
        )
        self.assertTrue(
            fnmatch.fnmatchcase(
                missing_sample,
                manifest["ci_inputs"][0]["pattern"],
            )
        )
        self.assertFalse(Path(missing_sample).is_file())
        manifest["ci_inputs"][0]["sample"] = missing_sample

        with tempfile.TemporaryDirectory() as temp_directory:
            planted_manifest = Path(temp_directory) / manifest_path.name
            planted_manifest.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "samples must name existing repository files",
            ):
                authoring_reference_inputs(planted_manifest)

    def test_authoring_reference_source_contract_has_independent_ci_coverage(self) -> None:
        self.assertEqual(
            AUTHORING_REFERENCE_CONTRACT_SOURCES,
            (
                "crates/registryctl/schemas/project-authoring/project.schema.json",
                "crates/registryctl/schemas/project-authoring/environment.schema.json",
                "crates/registryctl/schemas/project-authoring/integration.schema.json",
                "crates/registryctl/schemas/project-authoring/fixture.schema.json",
                "crates/registryctl/schemas/project-authoring/entity.schema.json",
                "schemas/registry-relay.config.schema.json",
                "schemas/registry-notary.config.schema.json",
                "crates/registryctl/schemas/project-authoring/parity-coverage.json",
                "crates/registryctl/schemas/project-authoring/documentation-intent.json",
                "crates/registry-relay/config/documentation-intent.json",
                "crates/registry-notary-core/config/documentation-intent.json",
            ),
        )
        validate_authoring_reference_routing(
            AUTHORING_REFERENCE_CONTRACT_SOURCES,
            AUTHORING_REFERENCE_INPUTS,
        )
        without_project_authoring_schemas = tuple(
            item
            for item in AUTHORING_REFERENCE_INPUTS
            if item[0] != "crates/registryctl/schemas/project-authoring/**"
        )
        with self.assertRaisesRegex(
            ValueError,
            "do not route source-contract paths",
        ):
            validate_authoring_reference_routing(
                AUTHORING_REFERENCE_CONTRACT_SOURCES,
                without_project_authoring_schemas,
            )

    def test_docs_pages_is_exact_dispatch_only(self) -> None:
        workflow = Path(".github/workflows/docs-pages.yml").read_text(encoding="utf-8")
        trigger_block = workflow.split("\npermissions:", 1)[0].rstrip()
        self.assertEqual(
            trigger_block,
            """name: Deploy RegistryStack Docs

on:
  workflow_dispatch:
    inputs:
      released_tag:
        description: Exact public Registry Stack release tag
        required: true
        type: string
      docs_sha256:
        description: SHA-256 of the released documentation archive
        required: true
        type: string
""".rstrip(),
        )

    def test_public_project_authoring_modules_run_docs(self) -> None:
        project_authoring = Path("crates/registryctl/src/project_authoring.rs").read_text(
            encoding="utf-8"
        )
        public_modules = re.findall(
            r"^pub use ([a-z][a-z0-9_]*)::\*;$",
            project_authoring,
            flags=re.MULTILINE,
        )
        self.assertTrue(public_modules)

        for module in public_modules:
            source = f"crates/registryctl/src/project_authoring/{module}.rs"
            with self.subTest(source=source):
                self.assertTrue(classify(self.workspace, (source,))["docs"])
        self.assertFalse(
            classify(
                self.workspace,
                ("crates/registryctl/src/project_authoring/project.rs",),
            )["docs"],
            "implementation-only project.rs should not rebuild docs",
        )

    def test_diagnostic_reference_inputs_run_docs(self) -> None:
        inputs = (
            "crates/registry-notary-server/src/standalone/activation.rs",
            "crates/registry-platform-ops/src/lib.rs",
            "crates/registry-relay/src/consultation/**",
            "crates/registry-relay/src/process_startup.rs",
            "crates/registryctl/schemas/project-reports/**",
            "crates/registryctl/src/project_authoring/diagnostic_reference.rs",
            "crates/registryctl/src/project_authoring/diagnostics.rs",
            "crates/registryctl/src/project_authoring/fixture_diagnostics.rs",
            "crates/registryctl/src/project_authoring/preflight.rs",
            "crates/registryctl/tests/fixtures/project-reports/**",
        )
        for path in inputs:
            with self.subTest(path=path):
                classifier_path = path.replace("**", "service.rs")
                self.assertTrue(classify(self.workspace, (classifier_path,))["docs"])

    def test_first_country_docs_and_journey_routing_matrix(self) -> None:
        cases = (
            (
                "crates/registryctl/assets/project-starters/bounded-http/registry-stack.yaml",
                {
                    "docs": True,
                    "project_authoring": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registryctl/tests/fixtures/project-authoring/opencrvs/registry-stack.yaml",
                {
                    "docs": True,
                    "project_authoring": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registryctl/tests/fixtures/project-authoring-journeys.yaml",
                {
                    "docs": True,
                    "project_authoring": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registryctl/src/templates/notary_addon/registry-stack.yaml",
                {
                    "docs": True,
                    "project_authoring": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registryctl/schemas/project-reports/registry.project.explanation.v1.schema.json",
                {
                    "docs": True,
                    "project_authoring": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registryctl/tests/fixtures/project-reports/registry.project.explanation.v1.json",
                {
                    "docs": True,
                    "project_authoring": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registryctl/src/project_authoring/report_contract.rs",
                {
                    "docs": True,
                    "project_authoring": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registryctl/src/project_authoring/output.rs",
                {
                    "docs": True,
                    "project_authoring": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registryctl/src/main.rs",
                {
                    "docs": True,
                    "project_authoring": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registry-relay/src/api/openapi.rs",
                {
                    "docs": True,
                    "relay_contracts": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registry-relay/src/server.rs",
                {
                    "docs": True,
                    "relay_contracts": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registry-relay/src/main.rs",
                {
                    "docs": True,
                    "relay_contracts": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registry-relay/src/config/loader.rs",
                {
                    "docs": True,
                    "relay_contracts": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registry-notary-server/src/standalone/activation.rs",
                {
                    "docs": True,
                    "notary_contracts": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registry-notary/src/config_loader.rs",
                {
                    "docs": False,
                    "notary_contracts": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registry-notary-core/src/config/root.rs",
                {
                    "docs": True,
                    "notary_contracts": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registry-notary-server/src/runtime/evaluation.rs",
                {
                    "docs": False,
                    "notary_contracts": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registry-platform-ops/src/lib.rs",
                {
                    "docs": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registry-relay/src/consultation/service.rs",
                {
                    "docs": True,
                    "relay_contracts": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registry-relay/src/process_startup.rs",
                {
                    "docs": True,
                    "relay_contracts": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registryctl/src/project_authoring/diagnostic_reference.rs",
                {
                    "docs": True,
                    "project_authoring": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "docs/site/src/components/JourneyGateMatrix.astro",
                {
                    "docs": True,
                    "rust": False,
                    "registryctl_tutorial": False,
                },
            ),
            (
                "docs/site/src/content/docs/journeys/verify-instance-openapi.mdx",
                {
                    "docs": True,
                    "rust": False,
                    "registryctl_tutorial": False,
                },
            ),
            (
                "docs/site/src/content/docs/reference/diagnostics/operator.mdx",
                {
                    "docs": True,
                    "rust": False,
                    "registryctl_tutorial": False,
                },
            ),
        )

        for path, expected in cases:
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                for output, value in expected.items():
                    self.assertEqual(outputs[output], value, output)

    def test_tutorial_package_dependencies_route_the_source_journey(self) -> None:
        cases = (
            (
                "crates/registry-relay/src/state_plane/runtime.rs",
                {
                    "docs": False,
                    "relay_contracts": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "crates/registry-platform-crypto/src/lib.rs",
                {"docs": False, "registryctl_tutorial": True},
            ),
            (
                "crates/registryctl/src/project_authoring/project.rs",
                {
                    "docs": False,
                    "project_authoring": True,
                    "registryctl_tutorial": True,
                },
            ),
            (
                "README.md",
                {"docs": False, "rust": False, "registryctl_tutorial": False},
            ),
            (
                "crates/registry-notary-client/src/lib.rs",
                {
                    "docs": False,
                    "notary_contracts": True,
                    "registryctl_tutorial": True,
                },
            ),
        )

        for path, expected in cases:
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                for output, value in expected.items():
                    self.assertEqual(outputs[output], value, output)

    def test_current_reader_journey_inputs_route_the_source_journey(self) -> None:
        inputs = (
            "docs/site/public/examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh",
            "docs/site/public/examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh.sha256",
            "docs/site/public/examples/registryctl/opencrvs-events-api-overlay-v1.sh",
            "docs/site/public/examples/registryctl/opencrvs-events-api-overlay-v1.sh.sha256",
            "docs/site/src/content/docs/configure/oauth-client-credentials.mdx",
            "docs/site/src/content/docs/operate/approve-initial-baseline.mdx",
            "docs/site/src/content/docs/tutorials/author-registry-project.mdx",
            "docs/site/src/content/docs/tutorials/configure-project-script-adapter.mdx",
            "docs/site/src/content/docs/tutorials/verify-opencrvs-claims.mdx",
        )

        for path in inputs:
            with self.subTest(path=path):
                self.assertTrue(
                    classify(self.workspace, (path,))["registryctl_tutorial"]
                )

        for deleted_path in (
            "docs/site/src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx",
            "docs/site/src/content/docs/tutorials/verify-claim-registry-api.mdx",
        ):
            with self.subTest(deleted_path=deleted_path):
                self.assertFalse(
                    classify(self.workspace, (deleted_path,))["registryctl_tutorial"]
                )

    def test_first_country_generation_inputs_run_docs(self) -> None:
        inputs = (
            "crates/registryctl/assets/project-starters/**",
            "crates/registryctl/src/main.rs",
            "crates/registryctl/src/project_authoring/output.rs",
            "crates/registryctl/src/project_authoring/report_contract.rs",
            "crates/registryctl/src/templates/**",
            "crates/registryctl/tests/fixtures/project-authoring-journeys.yaml",
            "crates/registryctl/tests/fixtures/project-authoring/**",
            "crates/registry-relay/src/api/openapi.rs",
            "crates/registry-relay/src/main.rs",
            "crates/registry-relay/src/server.rs",
        )

        for path in inputs:
            with self.subTest(path=path):
                classifier_path = path.replace("**", "example.yaml")
                self.assertTrue(classify(self.workspace, (classifier_path,))["docs"])

    def test_docs_job_fetches_ignored_openapi_inputs_before_script_tests(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        docs_job = workflow.split("\n  docs:\n", 1)[1].split("\n  docs-required:\n", 1)[0]
        fetch = "run: node scripts/fetch-openapi.mjs"
        test_scripts = "run: npm test"

        self.assertIn(fetch, docs_job)
        self.assertLess(docs_job.index(fetch), docs_job.index(test_scripts))

    def test_other_workflow_changes_do_not_select_the_full_matrix(self) -> None:
        for workflow in sorted(RELEASE_SECURITY_WORKFLOWS):
            with self.subTest(workflow=workflow):
                outputs = classify(
                    self.workspace,
                    (workflow,),
                )
                self.assertFalse(outputs["rust"])
                self.assertTrue(outputs["release_tool"])
                self.assertTrue(outputs["release_source_proof"])
                self.assertFalse(outputs["docs"])

    def test_unrelated_workflow_does_not_select_release_checks(self) -> None:
        outputs = classify(
            self.workspace,
            (".github/workflows/docs-pages.yml",),
        )
        self.assertFalse(outputs["release_tool"])
        self.assertFalse(outputs["release_source_proof"])

    def test_nightly_notary_fuzz_inventory_matches_declared_targets(self) -> None:
        workflow = Path(".github/workflows/nightly-security.yml").read_text(
            encoding="utf-8"
        )
        target_block = re.search(
            r"name: Run notary fuzz smoke.*?for target in \\\n"
            r"(?P<targets>.*?)\n\s*do",
            workflow,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(target_block)
        configured = re.findall(
            r"^\s+([a-z][a-z0-9_]*)",
            target_block["targets"],
            re.MULTILINE,
        )

        manifest = tomllib.loads(
            Path("products/notary/fuzz/Cargo.toml").read_text(encoding="utf-8")
        )
        declared = [target["name"] for target in manifest["bin"]]
        self.assertCountEqual(configured, declared)


class RunCargoPackagesTest(unittest.TestCase):
    def test_builds_a_direct_cargo_argument_vector(self) -> None:
        packages = package_args('["registry-relay","registryctl"]')
        self.assertEqual(
            command_args("test", packages, True),
            [
                "cargo",
                "test",
                "--locked",
                "--profile",
                "ci",
                "-p",
                "registry-relay",
                "-p",
                "registryctl",
                "--all-features",
            ],
        )

    def test_rejects_shell_syntax_in_package_names(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid Cargo package name"):
            package_args('["registry-relay; id"]')


if __name__ == "__main__":
    unittest.main()
