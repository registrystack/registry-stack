#!/usr/bin/env python3

from __future__ import annotations

import fnmatch
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from ci_changes import (
    EVIDENCE_AUTHORING_GUIDE_IMPLEMENTATION_INPUTS,
    EVIDENCE_TUTORIAL_INPUTS,
    IDENTIFIER_CATALOG_INPUTS,
    RELEASE_SECURITY_WORKFLOWS,
    SHARDS,
    Workspace,
    classify,
)
from run_cargo_packages import command_args, package_args

# products/evidence/scripts is not a package, so reaching its key-path
# checker needs this path on sys.path, the same way that script's own test
# reaches it.
sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "products/evidence/scripts")
)
from evidence_config_key_paths import CONTRACTS as KEY_PATH_CONTRACTS


# The path the authoring-form routing tests classify. It names a file inside
# registry-evidence-authoring, so the classifier seeds that package alone and
# everything else in the result arrives through the dependency closure.
AUTHORING_FORM_CHANGE = ("crates/registry-evidence-authoring/src/lib.rs",)

# The docs generator that turns each Evidence configuration schema into a
# published page, and the directory the authoring-form schemas are committed to.
EVIDENCE_CONFIGURATION_GENERATOR = Path(
    "docs/site/scripts/generate-evidence-configuration.mjs"
)
AUTHORING_SCHEMA_DIRECTORY = Path("crates/registry-evidencectl/schemas/authoring")


def published_evidence_configuration_schemas() -> set[str]:
    """The schema paths the docs generator's own contract list names."""

    generator = EVIDENCE_CONFIGURATION_GENERATOR.read_text(encoding="utf-8")
    return set(re.findall(r"^\s+file: '([^']+)',$", generator, re.MULTILINE))


def evidence_configuration_generator_contracts() -> dict[str, dict[str, str]]:
    """Every CONTRACTS entry the docs generator declares, keyed by id.

    Each entry's `reference` field names a module-level `..._REFERENCE`
    constant rather than carrying the path as a literal, the same indirection
    `test_every_published_evidence_schema_and_reference_runs_docs` resolves
    below, so this reads those constants first and substitutes them in.
    """

    generator = EVIDENCE_CONFIGURATION_GENERATOR.read_text(encoding="utf-8")
    references = dict(
        re.findall(r"^const (\w+_REFERENCE) =\s*'([^']+)';$", generator, re.MULTILINE)
    )
    entries = re.findall(
        r"\{\s*"
        r"id: '([^']+)',\s*"
        r"file: '([^']+)',\s*"
        r"title: '[^']*',\s*"
        r"marker: '([^']+)',\s*"
        r"status: '[^']*',\s*"
        r"reference: (\w+),\s*"
        r"\},",
        generator,
    )
    return {
        contract_id: {
            "file": file,
            "marker": marker,
            "reference": references[reference_name],
        }
        for contract_id, file, marker, reference_name in entries
    }


def normal_dependency_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Rebuild cargo metadata keeping only the edges a package links against.

    Cargo reports normal, build and dev dependencies in one list per package
    and tells them apart with a `kind` of null, "build" or "dev". The
    classifier keeps all three on purpose, because a dev-dependency edge is
    still a reason to run the dependent's tests. That makes its closure the
    wrong witness for a claim about what a shipped binary contains: it cannot
    see the difference between a crate an editor session compiles in and a
    crate only a test harness pulls in. A test that has to prove the stronger
    claim classifies against this reduced workspace as well, so a link moved
    out of `[dependencies]` fails it however many test-only edges survive.
    """

    packages = [
        {
            **package,
            "dependencies": [
                dependency
                for dependency in package["dependencies"]
                if dependency.get("kind") is None
            ],
        }
        for package in metadata["packages"]
    ]
    return {**metadata, "packages": packages}


def dev_only_dependency_metadata(
    metadata: dict[str, Any], *, consumer: str, dependency: str
) -> dict[str, Any]:
    """Rebuild cargo metadata with one link demoted to a test-only edge.

    This is the severing a routing claim about linked code has to survive: the
    consumer stops compiling the dependency in and keeps depending on it from
    its tests alone. Raising when there is no normal edge to demote keeps the
    fixture honest, because a mutation that quietly does nothing would let the
    test it feeds pass without exercising anything.
    """

    demoted = 0
    packages: list[dict[str, Any]] = []
    for package in metadata["packages"]:
        if package["name"] != consumer:
            packages.append(package)
            continue
        dependencies: list[dict[str, Any]] = []
        for entry in package["dependencies"]:
            if entry["name"] == dependency and entry.get("kind") is None:
                demoted += 1
                dependencies.append({**entry, "kind": "dev"})
            else:
                dependencies.append(entry)
        packages.append({**package, "dependencies": dependencies})

    if demoted == 0:
        raise ValueError(
            f"{consumer} has no normal dependency on {dependency} to demote"
        )
    return {**metadata, "packages": packages}


class CiRetirementTest(unittest.TestCase):
    def test_current_ci_surfaces_do_not_reference_retired_notary(self) -> None:
        current_ci_surfaces = (
            Path(".github/dependabot.yml"),
            Path(".github/scripts/ci_changes.py"),
            Path(".github/workflows/ci.yml"),
            Path(".github/workflows/nightly-rust-coverage.yml"),
            Path(".github/workflows/nightly-security.yml"),
        )
        for path in current_ci_surfaces:
            with self.subTest(path=path):
                self.assertNotRegex(path.read_text(encoding="utf-8"), r"(?i)notary")

        self.assertFalse(
            Path(".github/workflows/notary-postgres-conformance.yml").exists()
        )


class PlatformRetirementTest(unittest.TestCase):
    def test_orphan_platform_crates_and_oid4vci_fuzz_surface_are_absent(self) -> None:
        retired_crates = (
            "registry-platform-cache",
            "registry-platform-oid4vci",
            "registry-platform-replay",
            "registry-platform-sts",
        )
        for crate in retired_crates:
            with self.subTest(crate=crate):
                self.assertNotIn(crate, SHARDS["platform"])
                self.assertFalse(Path("crates", crate).exists())

        self.assertIn("registry-platform-pdp", SHARDS["platform"])
        self.assertIn("registry-platform-sqlite", SHARDS["platform"])
        self.assertIn("registry-platform-testing", SHARDS["platform"])
        self.assertFalse(
            Path(
                "products/platform/fuzz/fuzz_targets/oid4vci_request_and_proof.rs"
            ).exists()
        )
        self.assertFalse(
            Path("products/platform/fuzz/corpus/oid4vci_request_and_proof").exists()
        )


class CiChangesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        metadata = subprocess.run(
            ("cargo", "metadata", "--locked", "--format-version", "1"),
            check=True,
            capture_output=True,
            text=True,
        )
        # Kept beside the workspace so a test can classify against a reduced or
        # deliberately broken copy of the same dependency graph.
        cls.metadata = json.loads(metadata.stdout)
        cls.workspace = Workspace(cls.metadata)

    def test_shards_cover_every_workspace_package_once(self) -> None:
        assigned = [package for packages in SHARDS.values() for package in packages]
        self.assertCountEqual(assigned, self.workspace.package_names)
        self.assertEqual(len(assigned), len(set(assigned)))

    def test_relay_v2_paths_select_the_editor_and_reverse_dependents(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-relay-v2/src/compiler.rs",),
        )
        self.assertIn("registry-relay-v2", outputs["rust_packages"])
        self.assertIn("registry-relayctl", outputs["rust_packages"])
        self.assertTrue(outputs["relay_v2_contracts"])
        self.assertFalse(outputs["relay_contracts"])
        self.assertTrue(outputs["editors"])
        for package in [
            "registry-language-server",
            "registry-relayctl",
            "registryctl",
            "registry-evidencectl",
        ]:
            self.assertIn(package, outputs["rust_packages"])

    def test_every_identifier_source_selects_the_catalog_gate(self) -> None:
        for pattern in IDENTIFIER_CATALOG_INPUTS:
            sample = pattern.replace("**", "sample").replace("*", "sample")
            with self.subTest(pattern=pattern):
                self.assertTrue(classify(self.workspace, (sample,))["identifiers"])

    def test_identifier_exporters_and_indirect_inputs_select_the_catalog_gate(
        self,
    ) -> None:
        for path in (
            "crates/registry-relay-v2/examples/audit-event-schema.rs",
            "crates/registry-relay-v2/examples/problem-catalog.rs",
            "crates/registry-relay-v2/src/artifacts.rs",
            "crates/registry-relay-v2/src/audit.rs",
            "crates/registry-relay-v2/src/problem.rs",
        ):
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["identifiers"])

    def test_ci_always_checks_repository_identifier_reference_closure(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn(
            "products/identifiers/scripts/generate.py --check-references",
            workflow,
        )

    def test_identifier_tooling_does_not_force_the_rust_matrix(self) -> None:
        outputs = classify(
            self.workspace,
            ("products/identifiers/scripts/generate.py",),
        )
        self.assertTrue(outputs["identifiers"])
        self.assertFalse(outputs["rust"])

    def test_relay_v2_product_material_selects_runtime_and_tooling(self) -> None:
        outputs = classify(
            self.workspace,
            ("products/relay-v2/contracts/security-invariant-matrix.yaml",),
        )
        self.assertEqual(
            set(outputs["rust_packages"]),
            {
                "registry-relay-v2",
                "registry-language-server",
                "registry-relayctl",
                "registryctl",
                "registry-evidencectl",
            },
        )
        self.assertTrue(outputs["relay_v2_contracts"])
        self.assertTrue(outputs["editors"])

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
        self.assertFalse(outputs["platform"])

    def test_evidence_tutorial_inputs_cover_every_registered_tutorial(self) -> None:
        # The gate's registry is the source of truth for which tutorials exist.
        # A tutorial missing here would not trigger the job that replays it, so
        # it could break without any pull request noticing.
        gate = (
            Path(__file__).resolve().parents[2]
            / "docs/site/scripts/check-evidence-tutorials.sh"
        )
        registry = re.search(
            r"^EVIDENCE_TUTORIALS=\((.*?)^\)", gate.read_text(), re.DOTALL | re.MULTILINE
        )
        if registry is None:
            self.fail("the gate must declare EVIDENCE_TUTORIALS")
        slugs = registry.group(1).split()
        self.assertTrue(slugs, "the gate must register at least one tutorial")
        for slug in slugs:
            with self.subTest(slug=slug):
                self.assertIn(
                    f"docs/site/src/content/docs/tutorials/{slug}.mdx",
                    EVIDENCE_TUTORIAL_INPUTS,
                )

    def test_evidence_tutorial_inputs_cover_every_helper_the_gate_invokes(self) -> None:
        # Same reasoning as the tutorial registry above, one layer down. The gate
        # delegates to sibling scripts, and a change to one of those changes what
        # every tutorial replay does. A helper missing here routes the change
        # past the job that would have caught it.
        gate = (
            Path(__file__).resolve().parents[2]
            / "docs/site/scripts/check-evidence-tutorials.sh"
        )
        helpers = set(
            re.findall(r"scripts/([A-Za-z0-9._-]+\.(?:sh|mjs))", gate.read_text())
        )
        self.assertTrue(helpers, "the gate must invoke at least one helper")
        for helper in sorted(helpers):
            with self.subTest(helper=helper):
                self.assertIn(f"docs/site/scripts/{helper}", EVIDENCE_TUTORIAL_INPUTS)

    def test_evidence_tutorial_routing(self) -> None:
        infrastructure = (
            "docs/site/scripts/check-evidence-tutorials.sh",
            "docs/site/scripts/check-evidence-tutorials.test.mjs",
            "docs/site/src/content/docs/tutorials/first-evidence-assertion.mdx",
            "docs/site/package.json",
        )
        for path in infrastructure:
            with self.subTest(path=path):
                self.assertTrue(
                    classify(self.workspace, (path,))["evidence_tutorial"]
                )
        self.assertTrue(
            classify(self.workspace, ("crates/registry-evidence/src/runtime.rs",))[
                "evidence_tutorial"
            ]
        )
        self.assertTrue(
            classify(self.workspace, ("crates/registry-evidencectl/src/scaffold.rs",))[
                "evidence_tutorial"
            ]
        )
        # The gate runs `mint` too, so a Mint change that breaks the served
        # tutorial has to reach the job that replays it.
        self.assertTrue(
            classify(self.workspace, ("crates/registry-mint/src/lib.rs",))[
                "evidence_tutorial"
            ]
        )
        self.assertTrue(
            classify(
                self.workspace,
                ("crates/registry-evidence-oid4vci/src/service.rs",),
            )["evidence_tutorial"]
        )
        self.assertFalse(
            classify(
                self.workspace,
                (
                    "docs/site/src/content/docs/tutorials/"
                    "publish-governed-sqlite-registry.mdx",
                ),
            )["evidence_tutorial"]
        )

    def test_reverse_dependencies_are_included(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-platform-crypto/src/lib.rs",),
        )
        self.assertIn("registry-platform-crypto", outputs["rust_packages"])
        self.assertIn("registry-relay", outputs["rust_packages"])

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

    def test_evidence_code_and_product_contracts_select_its_shards_and_drift_gate(self) -> None:
        # A path inside the runtime crate seeds that crate alone. registry-mint
        # dev-depends on registry-evidence so its compatibility test proves
        # Evidence accepts a minted token. Changing Evidence must therefore run
        # the mint shard too.
        outputs = classify(self.workspace, ("crates/registry-evidence/src/source.rs",))
        self.assertTrue(outputs["evidence_contracts"])
        self.assertIn("registry-evidence", outputs["rust_packages"])
        self.assertEqual(
            {entry["name"] for entry in outputs["rust_matrix"]["include"]},
            {"evidence", "mint"},
        )

        # A products/evidence path belongs to no crate directory, so it seeds
        # every Evidence package and its closure runs wider than the runtime
        # crate's. registry-language-server reads the authoring model and
        # The language server reads the authoring form, so a change reaches the
        # editor tooling that has to keep agreeing with it. registryctl remains
        # a compile-time reverse dependent even though it is not a supported
        # editor launcher. A product contract cannot say in advance which
        # package it constrains, so the closure reaches every dependent shard.
        for path in (
            "products/evidence/contracts/source-contract.yaml",
            "products/evidence/reference/request-adapter/ADAPTER-API.md",
            "products/evidence/reference/request-adapter/deployment-projects/dhis2-adult-status/bundle/fixtures/cases.yaml",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["evidence_contracts"])
                self.assertIn("registry-evidence", outputs["rust_packages"])
                self.assertEqual(
                    {entry["name"] for entry in outputs["rust_matrix"]["include"]},
                    {
                        "evidence",
                        "mint",
                        "relay-v2",
                        "developer-tools",
                        "registryctl",
                    },
                )

    def test_an_authoring_form_change_runs_the_editor_tooling_that_reads_it(self) -> None:
        # registry-language-server links registry-evidence-authoring to index
        # an adopter's Evidence documents, and evidencectl and relayctl are its
        # supported CLI hosts. registryctl remains a compile-time reverse
        # dependent. A change to the authoring form can therefore break an
        # editor session or dependent build without touching a host, so the
        # closure has to carry it into their shards.
        outputs = classify(self.workspace, AUTHORING_FORM_CHANGE)
        self.assertTrue(outputs["evidence_contracts"])
        self.assertEqual(
            {entry["name"] for entry in outputs["rust_matrix"]["include"]},
            {"evidence", "relay-v2", "developer-tools", "registryctl"},
        )
        self.assertIn("registry-language-server", outputs["rust_packages"])
        self.assertIn("registryctl", outputs["rust_packages"])

        # The language server also dev-depends on the authoring form, for the
        # testing feature its own suite drives, and the classifier's closure
        # reads every dependency table alike. The assertions above therefore
        # hold on that test-only edge by itself, which is a weaker fact than
        # the one this test is named for: a test-only edge puts nothing inside
        # an adopter's editor. Repeating the closure over normal edges alone
        # ties the shards to the link the editor actually compiles against.
        strict = classify(
            Workspace(normal_dependency_metadata(self.metadata)),
            AUTHORING_FORM_CHANGE,
        )
        self.assertEqual(
            {entry["name"] for entry in strict["rust_matrix"]["include"]},
            {"evidence", "relay-v2", "developer-tools", "registryctl"},
        )
        self.assertIn("registry-language-server", strict["rust_packages"])
        self.assertIn("registryctl", strict["rust_packages"])

    def test_editor_integration_routing_follows_language_server_dependency_closure(
        self,
    ) -> None:
        for path in (
            "crates/registry-evidence-authoring/src/lib.rs",
            "crates/registry-language-server/src/lib.rs",
        ):
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["editors"])

        self.assertFalse(
            classify(
                self.workspace,
                ("crates/registry-evidence-client/src/lib.rs",),
            )["editors"]
        )

    def test_a_relay_v2_contract_change_runs_its_compiler_editor_and_host_cli(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-relay-v2/src/contract.rs",),
        )

        self.assertTrue(outputs["relay_v2_contracts"])
        self.assertTrue(outputs["editors"])
        self.assertIn("registry-language-server", outputs["rust_packages"])
        self.assertIn("registry-relayctl", outputs["rust_packages"])

        strict = classify(
            Workspace(normal_dependency_metadata(self.metadata)),
            ("crates/registry-relay-v2/src/contract.rs",),
        )
        self.assertTrue(strict["editors"])
        self.assertIn("registry-language-server", strict["rust_packages"])
        self.assertIn("registry-relayctl", strict["rust_packages"])

    def test_a_test_only_editor_edge_does_not_satisfy_the_authoring_routing(
        self,
    ) -> None:
        # The check above is only worth its name if it can tell the two edges
        # apart, so hold it against the workspace where it must not hold: the
        # language server keeps the test-only dependency and loses the one it
        # compiles against. Both halves matter here. The kind-blind closure
        # still reaches every editor shard, which is the reason the routing
        # claim cannot rest on it, and the normal-edge closure stops at the
        # authoring form's own shard, which is the power the routing claim
        # borrows from it.
        mutated = dev_only_dependency_metadata(
            self.metadata,
            consumer="registry-language-server",
            dependency="registry-evidence-authoring",
        )

        blind = classify(Workspace(mutated), AUTHORING_FORM_CHANGE)
        self.assertIn("registry-language-server", blind["rust_packages"])
        self.assertIn("registryctl", blind["rust_packages"])

        strict = classify(
            Workspace(normal_dependency_metadata(mutated)),
            AUTHORING_FORM_CHANGE,
        )
        self.assertNotIn("registry-language-server", strict["rust_packages"])
        self.assertNotIn("registryctl", strict["rust_packages"])
        self.assertEqual(
            {entry["name"] for entry in strict["rust_matrix"]["include"]},
            {"evidence"},
        )

    def test_the_mutation_fixture_refuses_to_demote_an_absent_link(self) -> None:
        # The fixture above proves nothing if it silently demotes nothing, so
        # a link that was never normal has to raise rather than hand back an
        # unchanged workspace. registryctl reaches the authoring form through
        # the language server and declares no dependency on it of its own.
        with self.assertRaisesRegex(ValueError, "no normal dependency"):
            dev_only_dependency_metadata(
                self.metadata,
                consumer="registryctl",
                dependency="registry-evidence-authoring",
            )

    def test_binding_only_change_runs_contracts_but_not_the_tutorial_job(self) -> None:
        # A Node-binding-only change has no bearing on any tutorial's shell
        # commands or fixtures, so it must not replay them; but the binding's
        # own source neutrality still needs the contracts gate to run.
        outputs = classify(
            self.workspace,
            ("crates/registry-evidence-client-node/src/lib.rs",),
        )
        self.assertFalse(outputs["evidence_tutorial"])
        self.assertTrue(outputs["evidence_contracts"])
        self.assertTrue(outputs["client_bindings"])
        self.assertEqual(
            {entry["name"] for entry in outputs["rust_matrix"]["include"]},
            {"evidence"},
        )

    def test_oid4vci_change_runs_rust_contracts_and_its_registered_tutorial(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-evidence-oid4vci/src/lib.rs",),
        )
        self.assertIn("registry-evidence-oid4vci", outputs["rust_packages"])
        self.assertTrue(outputs["evidence_contracts"])
        self.assertTrue(outputs["evidence_tutorial"])
        self.assertEqual(
            {entry["name"] for entry in outputs["rust_matrix"]["include"]},
            {"evidence"},
        )

    def test_the_python_binding_and_its_sdk_replay_the_tutorial_that_imports_them(
        self,
    ) -> None:
        # `request-evidence-from-an-application` builds the Python binding and
        # asks for an assertion through it, so the binding, the SDK beneath it
        # and the verifier beneath that are all tutorial source under test.
        # Leaving any of them out is how a client that cannot authenticate
        # against an evidencectl deployment reached a published tutorial.
        for path in (
            "crates/registry-evidence-client-py/src/convert.rs",
            "crates/registry-evidence-client/src/private_key_jwt.rs",
            "crates/registry-evidence-verifier/src/lib.rs",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["evidence_tutorial"])

    def test_python_binding_only_change_runs_its_own_job_and_the_tutorial(
        self,
    ) -> None:
        # The tutorial reaches the binding through one journey. The npm suite,
        # the type-drift check and the Python unittest suite are what cover the
        # rest of its API, so earning a tutorial trigger must not cost a binding
        # its own job.
        outputs = classify(
            self.workspace,
            ("crates/registry-evidence-client-py/src/lib.rs",),
        )
        self.assertTrue(outputs["client_bindings"])
        self.assertTrue(outputs["evidence_tutorial"])

    def test_an_sdk_or_verifier_change_also_runs_the_binding_job(self) -> None:
        # Both bindings are Cargo path-dependents of the SDK and the verifier,
        # so either can change the native surface or the error envelope the
        # packages wrap. Selecting the job from changed paths alone would skip
        # the npm suite, the type-drift check, and the Python unittest suite for
        # exactly the changes most able to break them.
        for path in (
            "crates/registry-evidence-client/src/client.rs",
            "crates/registry-evidence-verifier/src/lib.rs",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["client_bindings"])
                self.assertIn(
                    "registry-evidence-client-node", outputs["rust_packages"]
                )
                self.assertIn("registry-evidence-client-py", outputs["rust_packages"])

    def test_current_contract_gates_replace_the_retired_notary_gate(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("\n  evidence-contracts:\n", workflow)
        self.assertIn("products/evidence/scripts/check-contracts.sh", workflow)
        self.assertIn(
            "products/evidence/scripts/check-source-neutrality.sh", workflow
        )
        self.assertIn("\n  relay-contracts:\n", workflow)
        self.assertIn("name: Relay OpenAPI contract", workflow)
        self.assertNotIn("\n  notary-contracts:\n", workflow)
        self.assertNotIn("notary_contracts", workflow)

        rust_result = workflow.split("\n  rust-result:\n", 1)[1].split(
            "\n  project-authoring-determinism:\n", 1
        )[0]
        self.assertIn("\n      - evidence-contracts\n", rust_result)
        self.assertIn("\n      - relay-contracts\n", rust_result)
        self.assertNotIn("\n      - notary-contracts\n", rust_result)

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
            "docs/site/scripts/check-built-links.mjs",
            "docs/site/scripts/check-seo.mjs",
            "docs/site/scripts/docsets.mjs",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["docs_archives"])

    def test_release_or_classifier_changes_skip_historical_archive_rebuilds(
        self,
    ) -> None:
        for path in (
            ".github/scripts/ci_changes.py",
            ".github/workflows/docs-pages.yml",
            ".github/workflows/release.yml",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertFalse(outputs["docs_archives"])

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

    def test_ops_posture_source_runs_docs(self) -> None:
        # Relay V2 generates no docs-site artifact from crate source, so the one
        # crate a published page still reads is registry-platform-ops: the
        # operational posture page states what that module enforces.
        self.assertTrue(
            classify(self.workspace, ("crates/registry-platform-ops/src/lib.rs",))[
                "docs"
            ]
        )

    def test_evidence_contract_change_runs_docs_and_evidence_contracts(self) -> None:
        """The docs Evidence configuration page is generated from these files."""
        for path in (
            "products/evidence/contracts/bundle.schema.yaml",
            "products/evidence/contracts/runtime.schema.yaml",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["docs"])
                self.assertTrue(outputs["evidence_contracts"])

    def test_evidence_authoring_schema_change_runs_docs(self) -> None:
        """The same page publishes the authoring form beside the frozen ones."""
        for path in (
            "crates/registry-evidencectl/schemas/authoring/question.schema.json",
            "crates/registry-evidencectl/schemas/authoring/project-marker.schema.json",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["docs"])
                self.assertTrue(outputs["evidence_contracts"])

    def test_evidence_configuration_reference_change_runs_docs(self) -> None:
        """Docs tests read the reference that explains each published schema."""
        for path in (
            "products/evidence/reference/authoring-projects/CONFIG.md",
            "products/evidence/reference/request-adapter/deployment-projects/CONFIG.md",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["docs"])
                self.assertTrue(outputs["evidence_contracts"])

    def test_evidence_authoring_guide_implementation_changes_run_docs(self) -> None:
        """Implementation behind the published guide cannot change unnoticed."""
        for pattern, sample in EVIDENCE_AUTHORING_GUIDE_IMPLEMENTATION_INPUTS:
            with self.subTest(pattern=pattern):
                self.assertTrue(Path(sample).is_file())
                self.assertTrue(fnmatch.fnmatchcase(sample, pattern))
                self.assertTrue(classify(self.workspace, (sample,))["docs"])

    def test_unrelated_evidence_client_source_does_not_run_docs(self) -> None:
        """The guide routes owning modules, not every Evidence implementation."""
        outputs = classify(
            self.workspace,
            ("crates/registry-evidence-client/src/lib.rs",),
        )
        self.assertFalse(outputs["docs"])

    def test_every_published_evidence_schema_and_reference_runs_docs(self) -> None:
        """Whatever the generator publishes, a change to it rebuilds the docs."""
        generator = EVIDENCE_CONFIGURATION_GENERATOR.read_text(encoding="utf-8")
        published = published_evidence_configuration_schemas()
        references = set(
            re.findall(
                r"^const \w+_REFERENCE =\s*'([^']+)';$", generator, re.MULTILINE
            )
        )
        self.assertTrue(published)
        self.assertTrue(references)

        for path in sorted(published | references):
            with self.subTest(path=path):
                self.assertTrue(Path(path).is_file())
                self.assertTrue(classify(self.workspace, (path,))["docs"])

    def test_every_committed_authoring_schema_is_published(self) -> None:
        """A schema committed here that no page publishes documents nothing.

        The routing test above reads the generator's contract list, so it can
        only prove that what the list names reaches docs CI. It cannot see a
        schema committed under this directory that the list leaves out, and
        nothing else can either: `check-authoring-schema.sh` diffs the
        generator's output against this directory, so a third generated file
        diffs clean, and both key-path tools walk their own contract lists
        rather than the directory. Reading the directory is what makes the
        omission visible, and reading it is also why this test cannot itself
        grow the stale list it exists to catch.
        """
        committed = {
            path.as_posix()
            for path in AUTHORING_SCHEMA_DIRECTORY.rglob("*.json")
            if path.is_file()
        }
        self.assertTrue(committed)
        prefix = f"{AUTHORING_SCHEMA_DIRECTORY.as_posix()}/"
        self.assertEqual(
            committed,
            {
                path
                for path in published_evidence_configuration_schemas()
                if path.startswith(prefix)
            },
            "every committed authoring schema needs an entry in CONTRACTS in "
            f"{EVIDENCE_CONFIGURATION_GENERATOR}, in the CONTRACTS dict in "
            "products/evidence/scripts/evidence_config_key_paths.py, and a "
            "key-path block in the reference those two name",
        )

    def test_docs_and_key_path_contracts_agree(self) -> None:
        """The generator's CONTRACTS list and the python CONTRACTS dict must match.

        The test above only reads the docs generator's list, so a schema the
        generator names but the python dict leaves out, or names under a
        different marker or reference, would still leave that test green while
        `check-config-key-paths.sh --write` has nothing to generate or diff for
        it. This is what proves the two lists actually agree, rather than
        assuming it.
        """
        generator_contracts = evidence_configuration_generator_contracts()
        self.assertTrue(generator_contracts)
        self.assertEqual(set(generator_contracts), set(KEY_PATH_CONTRACTS))
        for contract_id, entry in generator_contracts.items():
            with self.subTest(contract_id=contract_id):
                key_path_contract = KEY_PATH_CONTRACTS[contract_id]
                self.assertEqual(entry["file"], key_path_contract.schema)
                self.assertEqual(entry["marker"], key_path_contract.marker)
                self.assertEqual(entry["reference"], key_path_contract.reference)

    def test_relay_docs_routing_matrix(self) -> None:
        # Relay V2 publishes two product documents and no generated artifact, so
        # the docs trigger follows those documents rather than crate source.
        # Every crate below still selects its own Rust work; what it must not do
        # is rebuild the site.
        cases = (
            (
                "products/relay-v2/CONCEPT.md",
                {"docs": True, "relay_v2_contracts": True},
            ),
            (
                "products/relay-v2/STANDARDS-ALIGNMENT.md",
                {"docs": True, "relay_v2_contracts": True},
            ),
            (
                "products/relay-v2/contracts/package-layout.yaml",
                {"docs": False, "relay_v2_contracts": True},
            ),
            (
                # ops-posture-spec.test.mjs reads this file to prove the
                # published RS-OP-POSTURE claims still match the runtime, so it
                # is a docs input as well as a contract input.
                "crates/registry-relay-v2/src/server.rs",
                {"docs": True, "relay_v2_contracts": True},
            ),
            (
                # A Relay V2 source no docs test reads stays out of the docs job.
                "crates/registry-relay-v2/src/api.rs",
                {"docs": False, "relay_v2_contracts": True},
            ),
            (
                "crates/registry-relayctl/src/main.rs",
                {"docs": False, "relay_v2_contracts": True},
            ),
            (
                "crates/registry-relay/src/server.rs",
                {"docs": False, "relay_contracts": True},
            ),
            (
                "crates/registryctl/src/project_authoring/output.rs",
                {"docs": False, "project_authoring": True},
            ),
            (
                "docs/site/src/data/repo-docs.yaml",
                {"docs": True, "docs_archives": True, "rust": False},
            ),
            (
                "docs/site/src/content/docs/reference/relayctl.mdx",
                {"docs": True, "rust": False},
            ),
            ("README.md", {"docs": False, "rust": False}),
        )

        for path, expected in cases:
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                for output, value in expected.items():
                    self.assertEqual(outputs[output], value, output)

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
