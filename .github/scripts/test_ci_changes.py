#!/usr/bin/env python3

from __future__ import annotations

import fnmatch
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml

from ci_changes import (
    BREG_CONTRACTS_LANES,
    BREG_TUTORIAL_INPUTS,
    CASEWORK_TUTORIAL_INPUTS,
    CLI_REFERENCE_INPUTS,
    DISCOVERY_PROVIDER_IMPLEMENTATION_INPUTS,
    DISCOVERY_PROVIDER_INPUTS,
    DISCOVERY_TUTORIAL_INPUTS,
    EVIDENCE_AUTHORING_GUIDE_IMPLEMENTATION_INPUTS,
    EVIDENCE_TUTORIAL_INPUTS,
    IDENTIFIER_CATALOG_INPUTS,
    REGISTRY_RECORD_CROSS_PRODUCT_INPUTS,
    BREG_PACKAGES,
    CASEWORK_PACKAGES,
    MESSAGING_PACKAGES,
    MESSAGING_TUTORIAL_INPUTS,
    STACK_CLIENT_PACKAGES,
    CONFIG_CHECK_PACKAGES,
    CONFIG_CONFORMANCE_INPUTS,
    CONFIG_CONFORMANCE_PACKAGES,
    SECURITY_WORKFLOW_GATES,
    SHARDS,
    LockChange,
    Workspace,
    classify,
    config_format_inputs,
    lock_change,
    matches,
    repo_docs_sources,
)
from run_cargo_packages import command_args, package_args
from ci_event_routing import select_event, selection_outputs

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


def config_conformance_runner() -> Any:
    """The configuration conformance corpus runner, loaded as a module."""

    script = Path("products/platform/scripts/run-config-conformance.py")
    spec = importlib.util.spec_from_file_location("run_config_conformance", script)
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = runner
    spec.loader.exec_module(runner)
    return runner


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
    classifier schedules a direct dev-dependent's tests without propagating
    through it, while this reduced workspace proves claims about code a
    shipped binary actually links. A link moved out of `[dependencies]` must
    therefore fail the stronger routing claim even if test-only edges remain.
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

        self.assertNotIn("registry-platform-pdp", SHARDS["platform"])
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
            ("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"),
            check=True,
            capture_output=True,
            text=True,
        )
        # Kept beside the workspace so a test can classify against a reduced or
        # deliberately broken copy of the same dependency graph.
        cls.metadata = json.loads(metadata.stdout)
        cls.workspace = Workspace(cls.metadata)
        workflow = yaml.safe_load(Path(".github/workflows/ci.yml").read_text())
        cls.workflow_jobs = workflow["jobs"]

    @staticmethod
    def normalized_needs(job: dict[str, Any]) -> tuple[str, ...]:
        needs = job.get("needs", ())
        return (needs,) if isinstance(needs, str) else tuple(needs)

    @staticmethod
    def static_matrix_slots(job: dict[str, Any]) -> int:
        matrix = job.get("strategy", {}).get("matrix")
        if matrix is None:
            return 1
        if not isinstance(matrix, dict):
            raise AssertionError("directly eligible jobs must use a static matrix")
        if "include" in matrix:
            return len(matrix["include"])

        # A classifier-selected axis counts at its widest selection.
        dynamic_axes = {
            "${{ fromJSON(needs.changes.outputs.breg_contracts_lanes) }}": len(
                BREG_CONTRACTS_LANES
            ),
        }
        slots = 1
        for name, values in matrix.items():
            if name == "exclude":
                continue
            if isinstance(values, str):
                slots *= dynamic_axes[values]
            elif isinstance(values, list):
                slots *= len(values)
        return slots

    def test_critical_ci_work_remains_directly_eligible_after_classification(
        self,
    ) -> None:
        expected = {
            "platform-quality",
            "platform-hygiene",
            "rust-policy",
            "evidence-contracts",
            "discovery-contracts",
            "breg-contracts",
            "breg-wasm",
            "evidence-tutorials",
            "docs",
            "client-bindings",
            "release-linux-node-clients",
        }
        direct = {
            name
            for name, job in self.workflow_jobs.items()
            if self.normalized_needs(job) == ("changes",)
        }

        self.assertEqual(expected, direct)
        slots = sum(self.static_matrix_slots(self.workflow_jobs[name]) for name in direct)
        self.assertLessEqual(slots, 15)
        self.assertEqual(14, slots)

    def test_deferred_ci_work_keeps_its_selector_and_explicit_status_guard(
        self,
    ) -> None:
        selectors = {
            "casework-postgres": "needs.changes.outputs.casework_postgres == 'true'",
            "scheduling-postgres": (
                "needs.changes.outputs.scheduling_postgres == 'true'"
            ),
            "scheduling-contracts": (
                "needs.changes.outputs.scheduling_contracts == 'true'"
            ),
            "messaging-postgres": (
                "needs.changes.outputs.messaging_postgres == 'true'"
            ),
            "messaging-contracts": (
                "needs.changes.outputs.messaging_contracts == 'true'"
            ),
            "messaging-smtp": (
                "needs.changes.outputs.messaging_postgres == 'true'"
            ),
            "platform-fuzz": "needs.changes.outputs.platform_assurance == 'true'",
            "evidence-fuzz": "needs.changes.outputs.evidence_assurance == 'true'",
            "platform-coverage": (
                "needs.changes.outputs.platform_coverage == 'true'"
            ),
            "rust-quality": "needs.changes.outputs.rust == 'true'",
            "rust-tests": "needs.changes.outputs.rust == 'true'",
            "identifiers": "needs.changes.outputs.identifiers == 'true'",
            "release-tool": "needs.changes.outputs.release_tool == 'true'",
            "release-source-proof": (
                "needs.changes.outputs.release_source_proof == 'true'"
            ),
            "breg-tutorial": "needs.changes.outputs.breg_tutorial == 'true'",
            "casework-tutorial": (
                "needs.changes.outputs.casework_tutorial == 'true'"
            ),
            "messaging-tutorial": (
                "needs.changes.outputs.messaging_tutorial == 'true'"
            ),
            "breg-evidence-composition": (
                "needs.changes.outputs.breg_evidence_composition == 'true'"
            ),
            "docs-archives": "needs.changes.outputs.docs_archives == 'true'",
            "editor-extensions": "needs.changes.outputs.editors == 'true'",
            "config-conformance": (
                "needs.changes.outputs.config_conformance == 'true'"
            ),
        }
        deferred = {
            name
            for name, job in self.workflow_jobs.items()
            if self.normalized_needs(job) == ("changes", "rust-policy")
        }
        self.assertEqual(set(selectors), deferred)

        # An explicit status-check function bypasses GitHub's implicit
        # success() dependency guard. Requiring a successful classifier keeps
        # its failure closed, while !cancelled() lets originally selected work
        # run after a failed or skipped policy dependency unless the workflow
        # was cancelled.
        for name, selector in selectors.items():
            with self.subTest(job=name):
                self.assertEqual(
                    "${{ !cancelled() && needs.changes.result == 'success' && "
                    f"{selector} }}}}",
                    self.workflow_jobs[name]["if"],
                )

    def test_event_tiers_reach_the_workflow(self) -> None:
        workflow = yaml.safe_load(Path(".github/workflows/ci.yml").read_text())
        # PyYAML reads the bare `on` key as a boolean.
        pull_request = workflow[True]["pull_request"]
        # Adding the ci:full label has to start a run of its own.
        self.assertEqual(
            ["opened", "synchronize", "reopened", "labeled"], pull_request["types"]
        )
        outputs = self.workflow_jobs["changes"]["outputs"]
        for name in (
            "platform_coverage",
            "breg_integration",
            "breg_contracts_lanes",
            "full_sweep",
        ):
            with self.subTest(output=name):
                self.assertEqual(
                    f"${{{{ steps.filter.outputs.{name} }}}}", outputs[name]
                )

        breg = self.workflow_jobs["breg-contracts"]
        self.assertEqual(
            "${{ fromJSON(needs.changes.outputs.breg_contracts_lanes) }}",
            breg["strategy"]["matrix"]["lane"],
        )
        self.assertEqual(
            "needs.changes.outputs.breg_integration == 'true'",
            self.workflow_jobs["breg-wasm"]["if"],
        )
        self.assertEqual(
            "github.event_name == 'push' && github.ref == 'refs/heads/main' && "
            "needs.changes.outputs.platform_coverage == 'true'",
            self.workflow_jobs["platform-coverage-upload"]["if"],
        )

        review_examples = next(
            step
            for step in self.workflow_jobs["casework-tutorial"]["steps"]
            if step.get("name") == "Verify BReg, payment, and standalone review examples"
        )
        self.assertEqual("needs.changes.outputs.full_sweep == 'true'", review_examples["if"])

    def test_ci_scheduling_graph_retains_every_job_and_aggregate_dependency(
        self,
    ) -> None:
        expected_jobs = {
            "changes",
            "secrets",
            "platform-quality",
            "platform-coverage",
            "platform-coverage-upload",
            "platform-hygiene",
            "platform-fuzz",
            "evidence-fuzz",
            "rust-policy",
            "rust-quality",
            "rust-tests",
            "evidence-contracts",
            "discovery-contracts",
            "breg-contracts",
            "breg-wasm",
            "identifiers",
            "config-conformance",
            "rust-result",
            "casework-postgres",
            "scheduling-contracts",
            "scheduling-postgres",
            "messaging-contracts",
            "messaging-postgres",
            "messaging-smtp",
            "release-tool",
            "release-tool-required",
            "release-source-proof",
            "release-source-proof-required",
            "evidence-tutorials",
            "breg-tutorial",
            "casework-tutorial",
            "messaging-tutorial",
            "breg-evidence-composition",
            "evidence-anchors",
            "docs",
            "docs-required",
            "docs-archives",
            "editor-extensions",
            "client-bindings",
            "release-linux-node-clients",
            "ci-result",
        }
        self.assertEqual(expected_jobs, set(self.workflow_jobs))

        aggregate_needs = {
            "rust-result": (
                "changes",
                "rust-policy",
                "rust-quality",
                "rust-tests",
                "discovery-contracts",
                "evidence-contracts",
                "breg-contracts",
                "breg-wasm",
                "identifiers",
                "casework-postgres",
                "scheduling-postgres",
                "scheduling-contracts",
                "messaging-postgres",
                "messaging-contracts",
                "messaging-smtp",
                "config-conformance",
            ),
            "release-tool-required": ("changes", "release-tool"),
            "release-source-proof-required": ("changes", "release-source-proof"),
            "docs-required": ("changes", "docs", "docs-archives"),
            "ci-result": (
                "changes",
                "secrets",
                "platform-quality",
                "platform-hygiene",
                "platform-fuzz",
                "rust-policy",
                "rust-quality",
                "rust-tests",
                "discovery-contracts",
                "evidence-contracts",
                "evidence-fuzz",
                "breg-contracts",
                "breg-wasm",
                "identifiers",
                "casework-postgres",
                "scheduling-postgres",
                "scheduling-contracts",
                "messaging-postgres",
                "messaging-contracts",
                "messaging-smtp",
                "config-conformance",
                "release-tool",
                "release-source-proof",
                "evidence-tutorials",
                "breg-tutorial",
                "casework-tutorial",
                "messaging-tutorial",
                "breg-evidence-composition",
                "evidence-anchors",
                "docs",
                "editor-extensions",
                "client-bindings",
                "release-linux-node-clients",
            ),
        }
        for name, expected in aggregate_needs.items():
            with self.subTest(aggregate=name):
                self.assertEqual(expected, self.normalized_needs(self.workflow_jobs[name]))

    def test_final_aggregate_flattens_rust_results_with_equivalent_outcomes(
        self,
    ) -> None:
        rust_job = self.workflow_jobs["rust-result"]
        final_job = self.workflow_jobs["ci-result"]
        rust_needs = set(self.normalized_needs(rust_job))
        final_needs = set(self.normalized_needs(final_job))

        self.assertEqual("Rust workspace", rust_job["name"])
        self.assertEqual("CI result", final_job["name"])
        self.assertEqual("always()", rust_job["if"])
        self.assertEqual("always()", final_job["if"])
        self.assertNotIn("rust-result", final_needs)
        previous_final_needs = {
            "changes",
            "secrets",
            "platform-quality",
            "platform-hygiene",
            "platform-fuzz",
            "evidence-fuzz",
            "rust-result",
            "release-tool",
            "release-source-proof",
            "evidence-tutorials",
            "breg-tutorial",
            "casework-tutorial",
            "messaging-tutorial",
            "breg-evidence-composition",
            "evidence-anchors",
            "docs",
            "editor-extensions",
            "client-bindings",
            "release-linux-node-clients",
        }
        self.assertEqual(
            final_needs,
            previous_final_needs.difference({"rust-result"}).union(rust_needs),
        )
        self.assertEqual(33, len(final_needs))
        # Platform line coverage publishes from main and the nightly sweep;
        # it does not hold the merge queue.
        self.assertNotIn("platform-coverage", final_needs)
        self.assertNotIn("platform-coverage-upload", final_needs)

        def embedded_python(job: dict[str, Any]) -> str:
            run = job["steps"][0]["run"]
            prefix = "python3 - <<'PY'\n"
            self.assertTrue(run.startswith(prefix))
            return run.removeprefix(prefix).rsplit("\nPY", 1)[0]

        rust_script = embedded_python(rust_job)
        final_script = embedded_python(final_job)

        def run_aggregate(script: str, variable: str, results: dict[str, str]) -> int:
            completed = subprocess.run(
                (sys.executable, "-c", script),
                env={
                    variable: json.dumps(
                        {name: {"result": result} for name, result in results.items()}
                    )
                },
                check=False,
                capture_output=True,
                text=True,
            )
            return completed.returncode

        for raw_job in sorted(rust_needs):
            for raw_result, accepted in (
                ("success", True),
                ("skipped", True),
                ("failure", False),
                ("cancelled", False),
            ):
                with self.subTest(raw_job=raw_job, raw_result=raw_result):
                    rust_results = {name: "success" for name in rust_needs}
                    rust_results[raw_job] = raw_result
                    final_results = {name: "success" for name in final_needs}
                    final_results.update(rust_results)

                    rust_status = run_aggregate(
                        rust_script,
                        "RUST_JOB_RESULTS",
                        rust_results,
                    )
                    final_status = run_aggregate(
                        final_script,
                        "CI_JOB_RESULTS",
                        final_results,
                    )
                    expected_status = 0 if accepted else 1
                    self.assertEqual(expected_status, rust_status)
                    self.assertEqual(rust_status, final_status)

    def test_config_conformance_inputs_select_the_conformance_gate(self) -> None:
        for path in (
            "crates/registry-breg-mcp/src/config.rs",
            "crates/registry-breg-review/src/config.rs",
            "crates/registry-platform-config/src/blocks.rs",
            "crates/registry-messaging/src/config.rs",
            "products/messaging/generated/runtime/runtime.schema.json",
            "crates/registry-breg/src/runtime_config.rs",
            "crates/registry-render/src/manifest.rs",
            "crates/registry-discovery/src/startup.rs",
            "crates/registry-evidence/src/config.rs",
            "crates/registry-casework/src/config.rs",
            "crates/registry-scheduling/src/config.rs",
            "products/platform/generated/runtime-config-blocks.schema.json",
            "products/platform/scripts/check-config-conformance.py",
            "products/breg/generated/runtime/runtime.schema.json",
            "products/breg/generated/mcp-runtime/mcp-runtime.schema.json",
            "products/breg/generated/review-runtime/review-runtime.schema.json",
            "products/casework/generated/runtime/runtime.schema.json",
            "products/scheduling/generated/runtime/runtime.schema.json",
        ):
            with self.subTest(path=path):
                self.assertTrue(
                    classify(self.workspace, (path,))["config_conformance"]
                )
        self.assertFalse(
            classify(self.workspace, ("docs/site/src/content/docs/index.mdx",))[
                "config_conformance"
            ]
        )

    def test_config_conventions_inputs_select_the_conformance_gate(self) -> None:
        for path in (
            "products/platform/config-formats.yaml",
            "products/platform/config-conventions-exceptions.yaml",
            "products/platform/CONFIG-CONVENTIONS.md",
            "products/platform/scripts/check-config-conventions.py",
            "products/platform/scripts/test_check_config_conventions.py",
            "editors/configure.py",
            # A schema nobody registered yet must reach the lint, which
            # refuses it until it is registered or declared out of scope.
            "products/render/generated/bundle/bundle.schema.json",
            "products/casework/contracts/cli/NewReport.schema.json",
            "products/evidence/contracts/new.schema.yaml",
            "products/discovery/schemas/new.schema.json",
            "crates/registry-render/schemas/new.schema.json",
            # Reader crates outside the runtime conformance rows.
            "crates/registry-bregctl/src/lib.rs",
            "crates/registry-manifest-cli/src/main.rs",
            "crates/registry-thunderid-tooling/src/lib.rs",
        ):
            with self.subTest(path=path):
                self.assertTrue(
                    classify(self.workspace, (path,))["config_conformance"]
                )

    def test_every_registered_configuration_format_input_is_routed(self) -> None:
        """config-formats.yaml names the files and reader crates the
        conventions lint reads; a change to any of them runs the lint. The
        classifier reads them by line, so this holds the result equal to a
        full YAML parse."""
        root = Path(__file__).resolve().parents[2]
        registry = yaml.safe_load(
            (root / "products/platform/config-formats.yaml").read_text(encoding="utf-8")
        )
        keys = {"path", "file", "example", "driftCheck", "differentialTest"}
        paths: set[str] = set()
        crates: set[str] = set()

        def collect(node: Any, key: str | None = None) -> None:
            if isinstance(node, dict):
                for name, value in node.items():
                    collect(value, name)
            elif isinstance(node, list):
                for value in node:
                    collect(value, key)
            elif isinstance(node, str) and key in keys and node != "none":
                paths.add(node)
            elif isinstance(node, str) and key == "crate":
                crates.add(node)

        collect(registry)
        self.assertIn("products/breg/examples/minimal/registry.yaml", paths)
        self.assertIn("registry-bregctl", crates)
        self.assertEqual(config_format_inputs(root), (frozenset(paths), frozenset(crates)))
        self.assertLessEqual(crates, set(self.workspace.package_names))
        for path in sorted(paths):
            with self.subTest(path=path):
                self.assertTrue((root / path).is_file())
                self.assertTrue(
                    classify(self.workspace, (path,))["config_conformance"]
                )

    def test_every_config_conformance_row_is_routed(self) -> None:
        script = Path("products/platform/scripts/check-config-conformance.py")
        spec = importlib.util.spec_from_file_location("config_conformance", script)
        assert spec is not None and spec.loader is not None
        gate = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = gate
        spec.loader.exec_module(gate)
        packages = {
            Path(source).parts[1]
            for row in gate.ROWS
            for source in row.loader_sources
        }
        self.assertLessEqual(packages, CONFIG_CONFORMANCE_PACKAGES)
        self.assertIn("registry-platform-config", CONFIG_CONFORMANCE_PACKAGES)
        schemas = {
            entry.path for row in gate.ROWS for entry in row.hand_schemas
        } | {
            row.runtime_schema
            for row in gate.ROWS
            if isinstance(row.runtime_schema, str)
        }
        for path in sorted(schemas):
            with self.subTest(path=path):
                self.assertTrue(
                    classify(self.workspace, (path,))["config_conformance"]
                )
        digest_tests = {
            row.digest_mismatch.path for row in gate.ROWS
            if isinstance(row.digest_mismatch, gate.TestRef)
        }
        for path in sorted(digest_tests):
            with self.subTest(path=path):
                self.assertTrue(
                    classify(self.workspace, (path,))["config_conformance"]
                )

    def test_config_conformance_corpus_inputs_select_the_conformance_gate_by_name(
        self,
    ) -> None:
        """The corpus, its harness, and its runner select the gate by name,
        not only through the platform packages a products/platform path seeds."""
        paths = [
            path.as_posix()
            for path in sorted(Path("products/platform/conformance").rglob("*"))
            if path.is_file()
        ] + [
            "products/platform/scripts/run-config-conformance.py",
            "products/platform/scripts/run-config-conformance.sh",
            "products/platform/scripts/test_run_config_conformance.py",
            "products/platform/scripts/test_check_config_conformance.py",
        ]
        self.assertIn("products/platform/conformance/yaml/formats.yaml", paths)
        self.assertIn("products/platform/conformance/yaml/expected-failures.yaml", paths)
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(matches(path, *CONFIG_CONFORMANCE_INPUTS))
                self.assertTrue(
                    classify(self.workspace, (path,))["config_conformance"]
                )

    def test_config_check_packages_build_the_programs_the_corpus_runs(self) -> None:
        """The corpus runner executes the registered check command of every
        format it reaches, the commands its harness prepares with, and the
        init commands its harness starts projects with. The packages whose
        binaries those are: the job builds them, and a change to any of them,
        or to anything they link, runs the job."""
        runner = config_conformance_runner()
        reached, _ = runner.partition_formats(
            runner.load_registry(Path(runner.REGISTRY))
        )
        harness = runner.load_harness(Path(runner.CORPUS) / "formats.yaml")
        commands = [str(fmt.check) for fmt in reached] + [
            command for entry in harness.values() for command in entry.get("prepare", ())
        ] + [entry["init"]["command"] for entry in harness.values() if "init" in entry]
        programs = {shlex.split(command)[0] for command in commands}
        binaries = {
            target["name"]: package["name"]
            for package in self.metadata["packages"]
            for target in package["targets"]
            if "bin" in target["kind"]
        }
        self.assertIn("messagingctl", programs)
        self.assertIn("registry-render", programs)
        self.assertLessEqual(programs, set(binaries))
        self.assertEqual({binaries[program] for program in programs}, CONFIG_CHECK_PACKAGES)
        steps = {
            step.get("name"): step
            for step in self.workflow_jobs["config-conformance"]["steps"]
        }
        build = steps["Build configuration check commands"]["run"].split()
        self.assertEqual(
            {build[index + 1] for index, word in enumerate(build) if word == "-p"},
            CONFIG_CHECK_PACKAGES,
        )
        for package in sorted(CONFIG_CHECK_PACKAGES):
            path = f"{self.workspace.roots[package]}/src/main.rs"
            with self.subTest(path=path):
                self.assertTrue(
                    classify(self.workspace, (path,))["config_conformance"]
                )

    def test_every_config_conformance_staged_project_is_routed(self) -> None:
        """The corpus runner stages a copy of each reached example's directory,
        or of the project and copies its harness names, so a change anywhere in
        one can change a result."""
        runner = config_conformance_runner()
        reached, _ = runner.partition_formats(
            runner.load_registry(Path(runner.REGISTRY))
        )
        harness = runner.load_harness(Path(runner.CORPUS) / "formats.yaml")
        sources = {
            entry.get("project", Path(str(fmt.example)).parent.as_posix())
            for fmt in reached
            for entry in (harness.get(fmt.id, {}),)
        } | {
            copy["from"]
            for entry in harness.values()
            for copy in (entry.get("copies") or {}).values()
        }
        self.assertIn("crates/registry-evidencectl/templates/sqlite-extract", sources)
        for source in sorted(sources):
            path = source if Path(source).is_file() else f"{source}/conformance-probe.yaml"
            with self.subTest(path=path):
                self.assertTrue(
                    classify(self.workspace, (path,))["config_conformance"]
                )

    def test_final_aggregate_refuses_a_selected_integration_job_that_skipped(
        self,
    ) -> None:
        # Review skips the heavy integration tier by design, so a skip passes
        # only where the classifier did not select the job; in the merge
        # queue a selected job has to succeed.
        final_job = self.workflow_jobs["ci-result"]
        run = final_job["steps"][0]["run"]
        script = run.removeprefix("python3 - <<'PY'\n").rsplit("\nPY", 1)[0]
        needs = self.normalized_needs(final_job)
        heavy = {
            "breg-contracts": "breg_contracts",
            "breg-wasm": "breg_integration",
            "casework-postgres": "casework_postgres",
            "scheduling-postgres": "scheduling_postgres",
            "evidence-tutorials": "evidence_tutorial",
            "breg-tutorial": "breg_tutorial",
            "casework-tutorial": "casework_tutorial",
            "breg-evidence-composition": "breg_evidence_composition",
        }

        def status(job: str, selected: str, result: str) -> int:
            results = {name: {"result": "success"} for name in needs}
            results["changes"]["outputs"] = {heavy[job]: selected}
            results[job]["result"] = result
            return subprocess.run(
                (sys.executable, "-c", script),
                env={"CI_JOB_RESULTS": json.dumps(results)},
                check=False,
                capture_output=True,
                text=True,
            ).returncode

        for job in heavy:
            for selected, result, expected in (
                ("false", "skipped", 0),
                ("true", "success", 0),
                ("true", "skipped", 1),
                ("true", "failure", 1),
                ("false", "failure", 1),
            ):
                with self.subTest(job=job, selected=selected, result=result):
                    self.assertEqual(expected, status(job, selected, result))

    def test_shards_cover_every_workspace_package_once(self) -> None:
        assigned = [package for packages in SHARDS.values() for package in packages]
        self.assertCountEqual(assigned, self.workspace.package_names)
        self.assertEqual(len(assigned), len(set(assigned)))

    def test_discovery_product_material_selects_the_complete_product_gate(self) -> None:
        outputs = classify(
            self.workspace,
            ("products/discovery/contracts/security-invariant-matrix.yaml",),
        )
        for package in SHARDS["discovery"]:
            self.assertIn(package, outputs["rust_packages"])
        # The product contract governs the shared provider-publication profile,
        # so its reverse-dependency closure must exercise the Evidence publisher
        # and its owning tooling as well as the Discovery crates themselves.
        self.assertIn("registry-evidence", outputs["rust_packages"])
        self.assertTrue(outputs["discovery_contracts"])
        self.assertEqual(
            {entry["name"] for entry in outputs["rust_matrix"]["include"]},
            {
                "casework",
                "developer-tools",
                "discovery",
                "evidence",
                "stack-client",
            },
        )

    def test_discovery_profile_changes_select_reverse_dependents_and_contracts(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-discovery-profile/src/lib.rs",),
        )
        self.assertIn("registry-discovery-profile", outputs["rust_packages"])
        self.assertIn("registry-discovery", outputs["rust_packages"])
        self.assertIn("registry-discoveryctl", outputs["rust_packages"])
        self.assertTrue(outputs["discovery_contracts"])

    def test_every_provider_publication_implementation_path_selects_discovery_contracts(
        self,
    ) -> None:
        self.assertEqual(
            set(DISCOVERY_PROVIDER_IMPLEMENTATION_INPUTS),
            {
                "crates/registry-evidence/src/bundle.rs",
                "crates/registry-evidence/src/cli.rs",
                "crates/registry-evidence/src/config.rs",
                "crates/registry-evidence/src/contracts.rs",
                "crates/registry-evidence/src/discovery.rs",
                "crates/registry-evidence/src/main.rs",
                "crates/registry-evidence/src/runtime_tests.rs",
                "crates/registry-evidence/src/server.rs",
                "crates/registry-evidencectl/src/authoring.rs",
                "crates/registry-evidencectl/src/build.rs",
                "crates/registry-evidencectl/src/fixtures.rs",
                "crates/registry-evidencectl/tests/production_build.rs",
            },
        )
        for path in DISCOVERY_PROVIDER_IMPLEMENTATION_INPUTS:
            with self.subTest(path=path):
                self.assertTrue(Path(path).is_file())
                self.assertTrue(classify(self.workspace, (path,))["discovery_contracts"])

    def test_every_provider_publication_product_input_selects_discovery_contracts(
        self,
    ) -> None:
        product_patterns = set(DISCOVERY_PROVIDER_INPUTS).difference(
            DISCOVERY_PROVIDER_IMPLEMENTATION_INPUTS
        )
        self.assertTrue(product_patterns)
        for pattern in product_patterns:
            matches = sorted(Path().glob(pattern))
            with self.subTest(pattern=pattern):
                self.assertTrue(matches, f"provider input pattern matches nothing: {pattern}")
            for path in matches:
                with self.subTest(pattern=pattern, path=path):
                    self.assertTrue(
                        classify(self.workspace, (path.as_posix(),))[
                            "discovery_contracts"
                        ]
                    )

    def test_every_discovery_tutorial_input_replays_the_product_gate(self) -> None:
        for path in DISCOVERY_TUTORIAL_INPUTS:
            if path.endswith("/**"):
                continue
            with self.subTest(path=path):
                self.assertTrue(Path(path).is_file())
                self.assertTrue(classify(self.workspace, (path,))["discovery_contracts"])

    def test_discovery_tutorial_routing(self) -> None:
        infrastructure = (
            "docs/site/scripts/run-tutorial.mjs",
            "docs/site/scripts/tutorial-runner/toolsets.mjs",
            "docs/site/src/content/docs/tutorials/publish-and-consume-discovery-index.mdx",
            "docs/site/package.json",
            "products/discovery/tutorial/publication_server.py",
            "products/discovery/tutorial/project/origins.yaml",
            "products/discovery/fixtures/descriptions/evidence.jsonld",
        )
        for path in infrastructure:
            with self.subTest(path=path):
                self.assertTrue(
                    classify(self.workspace, (path,))["discovery_contracts"]
                )

    def test_discovery_tutorial_inputs_cover_every_replayed_tutorial(self) -> None:
        docs = Path(__file__).resolve().parents[2] / "docs/site/src/content/docs"
        slugs = []
        for section in ("start", "tutorials"):
            for page in sorted((docs / section).glob("*.mdx")):
                frontmatter = yaml.safe_load(page.read_text().split("---\n")[1])
                declaration = frontmatter.get("tutorial_test") or {}
                if declaration.get("toolset") == "discovery" and "skip" not in declaration:
                    slugs.append(f"{section}/{page.stem}")
        self.assertIn("tutorials/publish-and-consume-discovery-index", slugs)
        for slug in slugs:
            with self.subTest(slug=slug):
                page = f"docs/site/src/content/docs/{slug}.mdx"
                self.assertTrue(
                    any(
                        fnmatch.fnmatchcase(page, pattern)
                        for pattern in DISCOVERY_TUTORIAL_INPUTS
                    )
                )

    def test_every_identifier_source_selects_the_catalog_gate(self) -> None:
        for pattern in IDENTIFIER_CATALOG_INPUTS:
            sample = pattern.replace("**", "sample").replace("*", "sample")
            with self.subTest(pattern=pattern):
                self.assertTrue(classify(self.workspace, (sample,))["identifiers"])

    def test_registry_record_cross_product_inputs_select_the_breg_gate(self) -> None:
        for path in (
            "products/registry-record/profile/registry-record-v1.md",
            "products/registry-record/schema/registry-record-v1.schema.json",
            "products/registry-record/context/registry-record-v1.jsonld",
            "products/registry-record/fixtures/cross-product/semantic-gold.json",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["identifiers"])
                self.assertTrue(outputs["breg_contracts"])
                self.assertFalse(outputs["rust"])
                self.assertEqual([], outputs["rust_matrix"]["include"])

    def test_cross_product_registry_record_patterns_are_narrow_and_live(self) -> None:
        self.assertEqual(
            REGISTRY_RECORD_CROSS_PRODUCT_INPUTS,
            (
                "products/registry-record/schema/**",
                "products/registry-record/context/**",
                "products/registry-record/profile/**",
                "products/registry-record/fixtures/cross-product/**",
            ),
        )
        for pattern in REGISTRY_RECORD_CROSS_PRODUCT_INPUTS:
            with self.subTest(pattern=pattern):
                self.assertTrue(list(Path().glob(pattern)))

    def test_registry_record_tooling_and_ordinary_fixtures_stay_profile_only(
        self,
    ) -> None:
        for path in (
            "products/registry-record/fixtures/positive/single.json",
            "products/registry-record/scripts/test_contract.py",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["identifiers"])
                self.assertFalse(outputs["rust"])

    def test_identifier_exporters_and_indirect_inputs_select_the_catalog_gate(
        self,
    ) -> None:
        for path in (
            "crates/registry-evidence/examples/problem-catalog.rs",
            "crates/registry-evidence/src/problem.rs",
            "crates/registry-scheduling-core/examples/problem-catalog.rs",
            "crates/registry-breg/src/schema.rs",
            "crates/registry-manifest-core/src/lib.rs",
        ):
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["identifiers"])

    def test_ci_always_checks_repository_identifier_reference_closure(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn(
            "products/identifiers/scripts/generate.py --check-references",
            workflow,
        )
        self.assertIn("products/registry-record/scripts/check.sh", workflow)

    def test_identifier_tooling_does_not_force_the_rust_matrix(self) -> None:
        outputs = classify(
            self.workspace,
            ("products/identifiers/scripts/generate.py",),
        )
        self.assertTrue(outputs["identifiers"])
        self.assertFalse(outputs["rust"])

    def test_casework_product_and_core_select_the_checkpoint_crates(self) -> None:
        product = classify(self.workspace, ("products/casework/README.md",))
        self.assertEqual(set(product["rust_packages"]) & CASEWORK_PACKAGES, set(CASEWORK_PACKAGES))
        selected = {row["name"] for row in product["rust_matrix"]["include"]}
        self.assertIn("casework", selected)
        self.assertTrue(product["casework_postgres"])
        core = classify(self.workspace, ("crates/registry-casework-core/src/adapter.rs",))
        shared_review_packages = {"registry-review-client", "registry-review-protocol"}
        self.assertLessEqual(
            CASEWORK_PACKAGES - shared_review_packages,
            set(core["rust_packages"]),
        )
        self.assertTrue(core["casework_postgres"])
        python = classify(
            self.workspace,
            ("crates/registry-casework-client-py/src/lib.rs",),
        )
        self.assertIn("registry-casework-client-py", python["rust_packages"])
        self.assertTrue(python["casework_postgres"])

    def test_messaging_product_and_core_select_the_checkpoint_crates(self) -> None:
        product = classify(self.workspace, ("products/messaging/README.md",))
        self.assertLessEqual(set(MESSAGING_PACKAGES), set(product["rust_packages"]))
        selected = {row["name"] for row in product["rust_matrix"]["include"]}
        self.assertIn("messaging", selected)
        self.assertTrue(product["messaging_contracts"])
        self.assertTrue(product["messaging_postgres"])
        core = classify(self.workspace, ("crates/registry-messaging-core/src/access.rs",))
        self.assertLessEqual(set(MESSAGING_PACKAGES), set(core["rust_packages"]))
        self.assertTrue(core["messaging_contracts"])
        self.assertTrue(core["messaging_postgres"])
        unrelated = classify(self.workspace, ("crates/registry-scheduling/src/lib.rs",))
        self.assertFalse(unrelated["messaging_contracts"])
        self.assertFalse(unrelated["messaging_postgres"])

    def test_shared_review_protocol_selects_casework_and_breg_consumers(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-review-protocol/src/lib.rs",),
        )
        selected = set(outputs["rust_packages"])
        self.assertIn("registry-review-protocol", selected)
        self.assertIn("registry-review-client", selected)
        self.assertIn("registry-casework-core", selected)
        self.assertIn("registry-casework", selected)
        self.assertIn("registry-breg", selected)
        self.assertTrue(outputs["casework_postgres"])
        self.assertTrue(outputs["breg_contracts"])

    def test_breg_paths_select_its_shard_and_product_gate(self) -> None:
        for path in (
            "crates/registry-breg/src/compiler.rs",
            "crates/registry-bregctl/src/main.rs",
            "products/breg/contracts/definition-of-done.yaml",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["breg_contracts"])
                self.assertTrue(
                    set(outputs["rust_packages"]) & BREG_PACKAGES
                )

        # The review page's real-registry journey runs in the PostgreSQL lane
        # of the product gate, so a change to the page selects that gate.
        review_outputs = classify(
            self.workspace, ("crates/registry-breg-review/src/pages.rs",)
        )
        self.assertTrue(review_outputs["breg_contracts"])
        self.assertIn("registry-breg-review", review_outputs["rust_packages"])

        product_outputs = classify(
            self.workspace,
            ("products/breg/contracts/definition-of-done.yaml",),
        )
        self.assertEqual(
            set(BREG_PACKAGES),
            set(product_outputs["rust_packages"]) & BREG_PACKAGES,
        )

    def test_evidence_runtime_changes_select_real_breg_composition_without_a_runtime_dependency(self) -> None:
        outputs = classify(self.workspace, ("crates/registry-evidence/src/source.rs",))
        self.assertTrue(outputs["breg_contracts"])
        self.assertNotIn("registry-breg", outputs["rust_packages"])

    def test_evidence_client_and_verifier_changes_select_breg_postgres_proof(self) -> None:
        for package in ("registry-evidence-client", "registry-evidence-verifier"):
            with self.subTest(package=package):
                outputs = classify(self.workspace, (f"crates/{package}/src/lib.rs",))
                self.assertTrue(outputs["breg_contracts"])
                self.assertIn("registry-breg", outputs["rust_packages"])

    def test_starter_inputs_run_compiler_and_native_example_tests(self) -> None:
        for path in (
            "products/breg/starters/public-organizations/core/registry.yaml",
            "products/breg/starters/agricultural-holdings/core/tests/journeys.yaml",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["breg_contracts"])
                self.assertTrue(outputs["breg_tutorial"])
                self.assertLessEqual(
                    {"registry-breg", "registry-bregctl", "registry-linkml"},
                    set(outputs["rust_packages"]),
                )

    def test_manifest_core_changes_select_breg_through_linked_code(
        self,
    ) -> None:
        manifest_change = ("crates/registry-manifest-core/src/lib.rs",)
        outputs = classify(self.workspace, manifest_change)

        self.assertTrue(outputs["breg_contracts"])
        self.assertIn("registry-breg", outputs["rust_packages"])
        self.assertIn("registry-manifest-core", outputs["rust_packages"])

    def test_evidence_tutorial_inputs_cover_every_replayed_tutorial(self) -> None:
        # Each page's tutorial_test frontmatter is the source of truth for
        # which tutorials the gate replays. A replayed page missing here would
        # not trigger the job that replays it, so it could break without any
        # pull request noticing.
        docs = Path(__file__).resolve().parents[2] / "docs/site/src/content/docs"
        slugs = []
        for section in ("start", "tutorials"):
            for page in sorted((docs / section).glob("*.mdx")):
                frontmatter = yaml.safe_load(page.read_text().split("---\n")[1])
                declaration = frontmatter.get("tutorial_test") or {}
                if declaration.get("toolset") == "evidence" and "skip" not in declaration:
                    slugs.append(f"{section}/{page.stem}")
        self.assertIn("tutorials/first-evidence-assertion", slugs)
        for slug in slugs:
            with self.subTest(slug=slug):
                page = f"docs/site/src/content/docs/{slug}.mdx"
                self.assertTrue(
                    any(
                        fnmatch.fnmatchcase(page, pattern)
                        for pattern in EVIDENCE_TUTORIAL_INPUTS
                    )
                )

    def test_evidence_tutorial_routing(self) -> None:
        infrastructure = (
            "docs/site/scripts/run-tutorial.mjs",
            "docs/site/scripts/tutorial-runner/toolsets.mjs",
            "docs/site/scripts/fixtures/fhir-tutorial-mock.py",
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
        # The gate runs the stock issuer, so an issuer-tooling change that breaks the served
        # tutorial has to reach the job that replays it.
        self.assertTrue(
            classify(self.workspace, ("crates/registry-thunderid-tooling/src/lib.rs",))[
                "evidence_tutorial"
            ]
        )
        self.assertTrue(
            classify(
                self.workspace,
                ("crates/registry-evidence-oid4vci/src/service.rs",),
            )["evidence_tutorial"]
        )
        # The application tutorial imports the assembled client package, so the
        # scripts and the pinned build tool that produce it decide what the
        # replay imports.
        for path in (
            "release/requirements/maturin-1.9.6.txt",
            "release/scripts/assemble-registry-client-packages.py",
            "release/scripts/assemble-registry-client-wheel.py",
            "release/scripts/build-linux-python-client",
            "release/scripts/smoke-registry-client-package.py",
            "release/scripts/zig-glibc-compiler",
        ):
            with self.subTest(path=path):
                self.assertTrue(
                    classify(self.workspace, (path,))["evidence_tutorial"]
                )
        # The assembled package bundles every product's Python binding, so
        # each of them feeds what the replay imports, not only the Evidence
        # binding.
        for path in (
            "crates/registry-breg-client-py/src/lib.rs",
            "crates/registry-casework-client-py/src/lib.rs",
            "crates/registry-discovery-client-py/src/lib.rs",
            "crates/registry-evidence-client-py/src/lib.rs",
            "crates/registry-messaging-client-py/src/lib.rs",
            "crates/registry-scheduling-client-py/src/lib.rs",
        ):
            with self.subTest(path=path):
                self.assertTrue(
                    classify(self.workspace, (path,))["evidence_tutorial"]
                )
        self.assertFalse(
            classify(
                self.workspace,
                (
                    "docs/site/src/content/docs/tutorials/"
                    "publish-and-consume-discovery-index.mdx",
                ),
            )["evidence_tutorial"]
        )

    def test_breg_tutorial_runs_native_example_recovery(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text()
        breg_job = workflow.split("\n  breg-tutorial:\n", 1)[1].split(
            "\n  breg-evidence-composition:\n", 1
        )[0]
        test = (
            "dev::examples::tests::"
            "native_create_recovers_after_process_exit_without_duplicate_records"
        )
        self.assertIn(test, breg_job)
        self.assertIn("-- --ignored --exact", breg_job)
        # A renamed test would otherwise leave the step running zero tests.
        self.assertIn(
            "grep -q 'test result: ok\\. 1 passed' "
            '"${RUNNER_TEMP}/breg-example-recovery.log" || '
            '{ echo "::error::expected exactly one passing test for '
            f'{test.rsplit("::", 1)[1]}"; exit 1; }}',
            breg_job,
        )
        source = (
            Path("crates/registry-bregctl/src/dev/examples.rs").read_text()
        )
        self.assertIn(f"fn {test.rsplit('::', 1)[1]}()", source)

    def test_casework_postgres_runs_task_approval_and_local_session_exactly(
        self,
    ) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text()
        casework_job = workflow.split("\n  casework-postgres:\n", 1)[1].split(
            "\n  scheduling-contracts:\n", 1
        )[0]
        cases = (
            (
                "task_grants::native_exchange_tests::"
                "approved_casework_tasks_reach_evidence_breg_and_scheduling_through_stock_thunderid",
                "casework-task-approval.log",
            ),
            (
                "task_grants::local_session_tests::"
                "source_backed_dev_approves_exchanges_and_revokes_on_stock_issuer",
                "casework-local-session.log",
            ),
        )
        source_dir = Path("crates/registry-casework/src/task_grants")
        for test, log in cases:
            with self.subTest(test=test):
                self.assertIn(test, casework_job)
                # A renamed test would otherwise leave the step running zero
                # tests, and an inexact filter could silently match more than
                # one, so the step names each test exactly and fails unless
                # it reports one pass.
                self.assertRegex(
                    casework_job,
                    rf"-- --ignored --exact \\\s*\n\s*{re.escape(test)} \\",
                )
                self.assertIn(
                    "grep -q 'test result: ok\\. 1 passed' "
                    f'"${{RUNNER_TEMP}}/{log}" || '
                    '{ echo "::error::expected exactly one passing test for '
                    f'{test.rsplit("::", 1)[1]}"; exit 1; }}',
                    casework_job,
                )
                module, name = test.rsplit("::", 2)[1:]
                module_source = (source_dir / f"{module}.rs").read_text()
                self.assertIn(f"fn {name}()", module_source)

    def test_backup_restore_proofs_run_on_every_input_they_exercise(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text()
        breg_job = workflow.split("\n  breg-contracts:\n", 1)[1].split(
            "\n  breg-wasm:\n", 1
        )[0]
        casework_job = workflow.split("\n  casework-postgres:\n", 1)[1].split(
            "\n  scheduling-contracts:\n", 1
        )[0]
        self.assertIn(
            "if: matrix.lane == 'contracts'\n"
            "        env:\n"
            '          BREG_SKIP_BUILD: "1"\n'
            "        run: products/breg/scripts/test-backup-restore.sh",
            breg_job,
        )
        self.assertIn(
            "run: products/casework/scripts/test-backup-restore.sh", casework_job
        )
        # The BReg proof drives bregctl and breg; the Casework proof drives
        # both development supervisors and both runtimes, so a change to
        # either product or to either script selects the job that runs it.
        for path, outputs_required in (
            ("products/breg/scripts/test-backup-restore.sh", ("breg_contracts",)),
            ("crates/registry-breg/src/instance_claim.rs", ("breg_contracts", "casework_postgres")),
            ("crates/registry-bregctl/src/dev/mod.rs", ("breg_contracts", "casework_postgres")),
            ("products/casework/scripts/test-backup-restore.sh", ("casework_postgres",)),
            ("crates/registry-caseworkctl/src/dev/mod.rs", ("casework_postgres",)),
            ("crates/registry-casework/src/activation.rs", ("casework_postgres",)),
        ):
            outputs = classify(self.workspace, (path,))
            for output in outputs_required:
                with self.subTest(path=path, output=output):
                    self.assertTrue(outputs[output])

    def test_platform_coverage_has_the_shared_activation_database(self) -> None:
        step = next(
            step for step in self.workflow_jobs["platform-coverage"]["steps"]
            if step.get("name") == "Enforce platform line coverage"
        )
        self.assertEqual(
            step["env"]["DISPATCH_TEST_DATABASE_URL"],
            step["env"]["ACTIVATION_TEST_DATABASE_URL"],
        )

    def test_nightly_platform_coverage_has_the_pull_request_database(self) -> None:
        # The nightly platform shard runs the same --all-features build as
        # platform-coverage, whose PostgreSQL tests fail rather than skip
        # without their database, so it needs the same service and URLs.
        pull_request = self.workflow_jobs["platform-coverage"]
        nightly = yaml.safe_load(
            Path(".github/workflows/nightly-rust-coverage.yml").read_text()
        )["jobs"]["rust"]
        self.assertEqual(nightly.get("services"), pull_request["services"])

        def database_urls(job: dict[str, Any], step_name: str) -> dict[str, str]:
            step = next(step for step in job["steps"] if step.get("name") == step_name)
            return {
                name: value for name, value in step.get("env", {}).items()
                if name.endswith("_DATABASE_URL")
            }

        expected = database_urls(pull_request, "Enforce platform line coverage")
        self.assertTrue(expected)
        self.assertEqual(database_urls(nightly, "Run shard with coverage"), expected)

    def test_source_client_tutorial_includes_messaging_before_release_admission(self) -> None:
        script = next(
            step["run"] for step in self.workflow_jobs["evidence-tutorials"]["steps"]
            if step.get("name") == "Assemble the client package the application tutorial imports"
        )
        self.assertIn("--include-messaging", script)
        self.assertIn("--python-profile ci", script)

    def test_shared_activation_selects_every_database_consumer_on_pull_requests(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-platform-activation/src/lib.rs",),
            pull_request=True,
        )
        for package in (
            "registry-platform-activation",
            "registry-casework",
            "registry-scheduling",
            "registry-messaging",
        ):
            self.assertIn(package, outputs["rust_packages"])
        for lane in ("casework_postgres", "scheduling_postgres", "messaging_postgres"):
            self.assertTrue(outputs[lane], lane)

    def test_breg_tutorial_inputs_cover_every_replayed_tutorial(self) -> None:
        # Each page's tutorial_test frontmatter is the source of truth for
        # which tutorials the gate replays. A replayed page missing here would
        # not trigger the job that replays it, so it could break without any
        # pull request noticing.
        docs = Path(__file__).resolve().parents[2] / "docs/site/src/content/docs"
        slugs = []
        for section in ("start", "tutorials"):
            for page in sorted((docs / section).glob("*.mdx")):
                frontmatter = yaml.safe_load(page.read_text().split("---\n")[1])
                declaration = frontmatter.get("tutorial_test") or {}
                if declaration.get("toolset") == "breg" and "skip" not in declaration:
                    slugs.append(f"{section}/{page.stem}")
        self.assertIn("tutorials/first-breg", slugs)
        for slug in slugs:
            with self.subTest(slug=slug):
                page = f"docs/site/src/content/docs/{slug}.mdx"
                self.assertTrue(
                    any(
                        fnmatch.fnmatchcase(page, pattern)
                        for pattern in BREG_TUTORIAL_INPUTS
                    )
                )

    def test_breg_tutorial_routing(self) -> None:
        infrastructure = (
            "docs/site/scripts/run-tutorial.mjs",
            "docs/site/scripts/tutorial-runner/gate.mjs",
            "docs/site/src/content/docs/tutorials/first-breg.mdx",
            "docs/site/src/content/docs/tutorials/extend-a-registry-with-a-module.mdx",
            "docs/site/package.json",
            "products/breg/scripts/test-request-attachments.py",
            "products/breg/acceptance/request-attachments/registry.yaml",
        )
        for path in infrastructure:
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["breg_tutorial"])
        # The issuer tooling `bregctl dev` links, and any BReg product
        # material, which selects the BReg packages the replay builds.
        for path in (
            "crates/registry-thunderid-tooling/src/local.rs",
            "products/breg/quickstart/run.sh",
        ):
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["breg_tutorial"])
        self.assertTrue(
            classify(self.workspace, ("crates/registry-breg/src/api/mod.rs",))[
                "breg_tutorial"
            ]
        )
        self.assertTrue(
            classify(self.workspace, ("crates/registry-bregctl/src/main.rs",))[
                "breg_tutorial"
            ]
        )
        # `bregctl dev` mints the operator token the tutorial's first
        # authenticated call carries.
        self.assertTrue(
            classify(self.workspace, ("crates/registry-thunderid-tooling/src/lib.rs",))[
                "breg_tutorial"
            ]
        )
        # An Evidence page shares the tutorials directory and reaches none of
        # the Base Registry Engine replay.
        self.assertFalse(
            classify(
                self.workspace,
                (
                    "docs/site/src/content/docs/tutorials/"
                    "first-evidence-assertion.mdx",
                ),
            )["breg_tutorial"]
        )
        # The replay starts `bregctl dev` and no Evidence binary, and
        # it replays neither composition page. The offline composition proof
        # owns the Evidence toolset and those pages' commands.
        for path in (
            "crates/registry-evidence/src/source.rs",
            "crates/registry-evidencectl/src/source_cli.rs",
            "docs/site/src/content/docs/tutorials/evidence-from-breg.mdx",
            "docs/site/src/content/docs/tutorials/deploy-evidence-from-breg.mdx",
            "docs/site/scripts/generate-breg-evidence-starter.mjs",
        ):
            with self.subTest(path=path):
                self.assertFalse(classify(self.workspace, (path,))["breg_tutorial"])

    def test_casework_tutorial_inputs_cover_every_replayed_tutorial(self) -> None:
        # Each page's tutorial_test frontmatter is the source of truth for
        # which tutorials the gate replays. A replayed page missing here would
        # not trigger the job that replays it, so it could break without any
        # pull request noticing.
        docs = Path(__file__).resolve().parents[2] / "docs/site/src/content/docs"
        slugs = []
        for section in ("start", "tutorials"):
            for page in sorted((docs / section).glob("*.mdx")):
                frontmatter = yaml.safe_load(page.read_text().split("---\n")[1])
                declaration = frontmatter.get("tutorial_test") or {}
                if declaration.get("toolset") == "casework" and "skip" not in declaration:
                    slugs.append(f"{section}/{page.stem}")
        self.assertIn("tutorials/first-casework", slugs)
        for slug in slugs:
            with self.subTest(slug=slug):
                page = f"docs/site/src/content/docs/{slug}.mdx"
                self.assertTrue(
                    any(
                        fnmatch.fnmatchcase(page, pattern)
                        for pattern in CASEWORK_TUTORIAL_INPUTS
                    )
                )

    def test_casework_tutorial_routing(self) -> None:
        infrastructure = (
            "docs/site/scripts/run-tutorial.mjs",
            "docs/site/scripts/tutorial-runner/toolsets.mjs",
            "docs/site/src/content/docs/tutorials/first-casework.mdx",
            "docs/site/package.json",
        )
        for path in infrastructure:
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["casework_tutorial"])
        # The replay builds and runs these three: the runtime the reader calls,
        # the tool that starts and seeds the local session, and stock issuer tooling,
        # which issues every token the reader's calls carry.
        for path in (
            "crates/registry-casework/src/http.rs",
            "crates/registry-caseworkctl/src/dev/mod.rs",
            "crates/registry-thunderid-tooling/src/lib.rs",
            "crates/registry-breg/src/lib.rs",
            "crates/registry-bregctl/src/dev/mod.rs",
        ):
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["casework_tutorial"])
        # The source-neutral core is linked by the runtime, so a change to the
        # transition rules reaches the replay through reverse dependencies.
        self.assertTrue(
            classify(self.workspace, ("crates/registry-casework-core/src/lib.rs",))[
                "casework_tutorial"
            ]
        )
        # Pages that share the tutorials directory and reach none of the
        # Registry Casework replay; the BReg review guide is skipped.
        for path in (
            "docs/site/src/content/docs/tutorials/first-breg.mdx",
            "docs/site/src/content/docs/tutorials/first-evidence-assertion.mdx",
            "docs/site/src/content/docs/tutorials/review-breg-changes-in-casework.mdx",
        ):
            with self.subTest(path=path):
                self.assertFalse(classify(self.workspace, (path,))["casework_tutorial"])

    def test_messaging_tutorial_inputs_cover_every_registered_tutorial(self) -> None:
        # The gate's registry is the source of truth for which tutorials it
        # replays. A tutorial missing here would not trigger the job that
        # replays it, so it could break without any pull request noticing.
        gate = (
            Path(__file__).resolve().parents[2]
            / "docs/site/scripts/check-messaging-tutorial.sh"
        )
        registry = re.search(
            r"^MESSAGING_TUTORIALS=\((.*?)^\)",
            gate.read_text(),
            re.DOTALL | re.MULTILINE,
        )
        if registry is None:
            self.fail("the gate must declare MESSAGING_TUTORIALS")
        slugs = registry.group(1).split()
        self.assertTrue(slugs, "the gate must register at least one tutorial")
        for slug in slugs:
            with self.subTest(slug=slug):
                page = f"docs/site/src/content/docs/{slug}.mdx"
                self.assertTrue(
                    any(
                        fnmatch.fnmatchcase(page, pattern)
                        for pattern in MESSAGING_TUTORIAL_INPUTS
                    )
                )

    def test_messaging_tutorial_routing(self) -> None:
        infrastructure = (
            "docs/site/scripts/check-messaging-tutorial.sh",
            "docs/site/scripts/check-messaging-tutorial.test.mjs",
            "docs/site/src/content/docs/tutorials/first-messaging.mdx",
            "docs/site/package.json",
        )
        for path in infrastructure:
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["messaging_tutorial"])
        # The replay builds and runs messagingctl, which links the runtime in
        # process for its local session.
        for path in (
            "crates/registry-messaging/src/runtime.rs",
            "crates/registry-messagingctl/src/dev/mod.rs",
            "crates/registry-messagingctl/src/starter.rs",
        ):
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["messaging_tutorial"])
        # The source-neutral core is linked by the runtime, so a change to it
        # reaches the replay through reverse dependencies.
        self.assertTrue(
            classify(self.workspace, ("crates/registry-messaging-core/src/lib.rs",))[
                "messaging_tutorial"
            ]
        )
        # Pages that share the tutorials directory and reach none of the
        # Registry Messaging replay.
        for path in (
            "docs/site/src/content/docs/tutorials/first-casework.mdx",
            "docs/site/scripts/check-casework-tutorial.sh",
        ):
            with self.subTest(path=path):
                self.assertFalse(classify(self.workspace, (path,))["messaging_tutorial"])

    def test_breg_evidence_composition_routing(self) -> None:
        # The proof drives bregctl, evidencectl and the Evidence runtime over
        # the reviewed teaching inputs, so a change to any of those three, to a
        # crate they link, or to the inputs themselves must select it.
        for path in (
            "crates/registry-breg/src/evidence_source.rs",
            "crates/registry-bregctl/src/main.rs",
            "crates/registry-evidence/src/source.rs",
            "crates/registry-evidencectl/src/source_cli.rs",
            "crates/registry-evidence-authoring/src/model.rs",
            "products/breg/evidence/registry/registry.yaml",
            "products/breg/evidence/tests/verify-composition.py",
        ):
            with self.subTest(path=path):
                self.assertTrue(
                    classify(self.workspace, (path,))["breg_evidence_composition"]
                )
        # Nothing the proof reads or runs: the pages that narrate the same
        # journey, the archive generator that publishes its inputs, and the
        # driver of the Docker-backed tutorial replay.
        for path in (
            "docs/site/src/content/docs/tutorials/evidence-from-breg.mdx",
            "docs/site/src/content/docs/tutorials/deploy-evidence-from-breg.mdx",
            "docs/site/scripts/generate-breg-evidence-starter.mjs",
            "docs/site/scripts/run-tutorial.mjs",
        ):
            with self.subTest(path=path):
                self.assertFalse(
                    classify(self.workspace, (path,))["breg_evidence_composition"]
                )
        # The same reviewed inputs and the references that explain them are
        # published, so they also rebuild the documentation.
        for path in (
            "products/breg/evidence/starter/fixtures/record-active.yaml",
            "products/evidence/reference/authoring-projects/SOURCE-EXPORT.md",
            "products/evidence/reference/request-adapter/deployment-projects/SOURCE-CREDENTIAL-ROTATION.md",
        ):
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["docs"])

    def test_reverse_dependencies_are_included(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-platform-crypto/src/lib.rs",),
        )
        self.assertIn("registry-platform-crypto", outputs["rust_packages"])

    def test_platform_fuzz_runner_changes_select_platform_gates(self) -> None:
        for path in (
            "products/platform/scripts/run-fuzz-smoke.sh",
            "products/platform/scripts/test_run_fuzz_smoke.py",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["platform"])
                self.assertTrue(outputs["platform_hygiene"])

    def test_shared_reader_changes_select_the_jobs_that_test_it(self) -> None:
        outputs = classify(
            self.workspace, ("crates/registry-platform-yaml/src/structure.rs",)
        )
        platform_shard = next(
            entry
            for entry in outputs["rust_matrix"]["include"]
            if entry["name"] == "platform"
        )
        self.assertIn("registry-platform-yaml", platform_shard["packages"])
        self.assertIn("registry-platform-config", outputs["rust_packages"])
        self.assertTrue(outputs["platform"])
        self.assertTrue(outputs["platform_assurance"])
        self.assertTrue(outputs["config_conformance"])
        for path in (
            "products/platform/fuzz/fuzz_targets/yaml_decode.rs",
            "products/platform/fuzz/fuzz_targets/yaml_reader.rs",
            "products/platform/fuzz/fuzz_targets/yaml_support.rs",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["platform"])
                self.assertTrue(outputs["platform_assurance"])

    def test_dispatch_changes_select_the_job_running_its_postgres_suite(self) -> None:
        # The dispatch core's PostgreSQL suite runs in the Scheduling
        # PostgreSQL job, whose service database it borrows. A dispatch
        # change must schedule that job whether or not a Scheduling crate
        # happens to depend on dispatch.
        for path in (
            "crates/registry-platform-dispatch/src/postgres/dispatcher.rs",
            "crates/registry-platform-dispatch/tests/postgres_dispatch.rs",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertIn("registry-platform-dispatch", outputs["rust_packages"])
                self.assertTrue(outputs["scheduling_postgres"])

    def test_ci_workflow_change_runs_the_complete_matrix(self) -> None:
        outputs = classify(self.workspace, (".github/workflows/ci.yml",))
        self.assertCountEqual(outputs["rust_packages"], self.workspace.package_names)
        self.assertTrue(outputs["docs"])
        # The workflow does not alter archived bytes; the nightly full sweep
        # replays the archive job's own recipe.
        self.assertFalse(outputs["docs_archives"])
        self.assertTrue(outputs["editors"])

    def test_casework_postgres_job_names_existing_integration_test_targets(self) -> None:
        commands = "\n".join(
            str(step.get("run", ""))
            for step in self.workflow_jobs["casework-postgres"]["steps"]
        )
        targets = set(re.findall(r"--test\s+([a-zA-Z0-9_-]+)", commands))
        self.assertTrue(targets)
        for target in targets:
            with self.subTest(target=target):
                self.assertTrue(
                    Path("crates/registry-casework/tests", f"{target}.rs").is_file(),
                    f"casework-postgres invokes missing test target {target}",
                )

    def test_messaging_postgres_job_names_existing_integration_test_targets(
        self,
    ) -> None:
        commands = "\n".join(
            str(step.get("run", ""))
            for step in self.workflow_jobs["messaging-postgres"]["steps"]
        )
        targets = set(re.findall(r"--test\s+([a-zA-Z0-9_-]+)", commands))
        self.assertTrue(targets)
        for target in targets:
            with self.subTest(target=target):
                self.assertTrue(
                    Path("crates/registry-messaging/tests", f"{target}.rs").is_file(),
                    f"messaging-postgres invokes missing test target {target}",
                )

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
        # A runtime change reaches the real Evidence router consumers, including
        # the Casework institutional exchange acceptance through its dev dependency.
        outputs = classify(self.workspace, ("crates/registry-evidence/src/source.rs",))
        self.assertTrue(outputs["evidence_contracts"])
        self.assertIn("registry-evidence", outputs["rust_packages"])
        self.assertEqual(
            {entry["name"] for entry in outputs["rust_matrix"]["include"]},
            {"casework", "developer-tools", "discovery", "evidence"},
        )

        # A products/evidence path belongs to no crate directory, so it seeds
        # every Evidence package and its closure runs wider than the runtime
        # crate's. registry-language-server reads the authoring model and
        # The language server reads the authoring form, so a change reaches the
        # editor tooling that has to keep agreeing with it. A product contract
        # cannot say in advance which
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
                        "breg",
                        "casework",
                        "discovery",
                        "evidence",
                        "developer-tools",
                        "stack-client",
                    },
                )

    def test_an_authoring_form_change_runs_the_editor_tooling_that_reads_it(self) -> None:
        # registry-language-server links registry-evidence-authoring to index
        # an adopter's Evidence documents, and evidencectl is its supported CLI
        # host. A change to the authoring form can therefore break an
        # editor session or dependent build without touching a host, so the
        # closure has to carry it into their shards.
        outputs = classify(self.workspace, AUTHORING_FORM_CHANGE)
        self.assertTrue(outputs["evidence_contracts"])
        self.assertEqual(
            {entry["name"] for entry in outputs["rust_matrix"]["include"]},
            {"evidence", "developer-tools"},
        )
        self.assertIn("registry-language-server", outputs["rust_packages"])

        # The language server also dev-depends on the authoring form for its
        # own test suite. Repeating the closure over normal edges alone ties
        # the editor routing claim to the link the editor actually compiles.
        strict = classify(
            Workspace(normal_dependency_metadata(self.metadata)),
            AUTHORING_FORM_CHANGE,
        )
        self.assertEqual(
            {entry["name"] for entry in strict["rust_matrix"]["include"]},
            {"evidence", "developer-tools"},
        )
        self.assertIn("registry-language-server", strict["rust_packages"])

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

    def test_editor_configuration_follows_its_copied_product_schemas(self) -> None:
        for path in (
            "products/breg/generated/authoring/registry-project.schema.json",
            "products/breg/generated/runtime/runtime.schema.json",
            "products/casework/generated/project/project.schema.json",
            "products/casework/generated/runtime/runtime.schema.json",
            "products/scheduling/generated/runtime/runtime.schema.json",
            "products/scheduling/generated/project/project.schema.json",
            "products/scheduling/generated/records/records.schema.json",
            "products/scheduling/generated/fixture/fixture.schema.json",
            "products/messaging/generated/runtime/runtime.schema.json",
            "products/discovery/schemas/origins.schema.json",
        ):
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["editors"])

    def test_a_casework_schema_change_runs_its_drift_check_on_a_pull_request(
        self,
    ) -> None:
        # The casework test shard carries the schema drift step, so a pull
        # request that touches a committed schema has to select it.
        for path in (
            "products/casework/generated/project/project.schema.json",
            "products/casework/generated/runtime/runtime.schema.json",
            "crates/registry-casework-core/src/config.rs",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,), pull_request=True)
                self.assertIn(
                    "casework",
                    {entry["name"] for entry in outputs["rust_matrix"]["include"]},
                )

    def test_a_test_only_editor_edge_does_not_satisfy_the_authoring_routing(
        self,
    ) -> None:
        # The check above is only worth its name if it can tell the two edges
        # apart, so hold it against the workspace where it must not hold: the
        # language server keeps the test-only dependency and loses the one it
        # compiles against. A dev edge still selects that direct test suite,
        # but cannot create a normal reverse-dependency cascade.
        mutated = dev_only_dependency_metadata(
            self.metadata,
            consumer="registry-language-server",
            dependency="registry-evidence-authoring",
        )

        blind = classify(Workspace(mutated), AUTHORING_FORM_CHANGE)
        self.assertIn("registry-language-server", blind["rust_packages"])
        self.assertNotIn("registryctl", blind["rust_packages"])

        strict = classify(
            Workspace(normal_dependency_metadata(mutated)),
            AUTHORING_FORM_CHANGE,
        )
        self.assertNotIn("registry-language-server", strict["rust_packages"])
        self.assertEqual(
            {entry["name"] for entry in strict["rust_matrix"]["include"]},
            {"developer-tools", "evidence"},
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

    def test_breg_client_change_stays_on_breg_surfaces(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-breg-client/src/lib.rs",),
        )
        self.assertTrue(outputs["breg_contracts"])
        self.assertIn("registry-breg", outputs["rust_packages"])
        # bregctl examples uses the SDK's recoverable write-attempt contract.
        self.assertIn("registry-bregctl", outputs["rust_packages"])
        self.assertEqual(
            {entry["name"] for entry in outputs["rust_matrix"]["include"]},
            {"breg", "casework", "stack-client", "developer-tools"},
        )

    def test_registry_record_change_runs_the_breg_client_and_facade(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-record/src/lib.rs",),
        )
        self.assertTrue(outputs["breg_contracts"])
        self.assertTrue(BREG_PACKAGES & set(outputs["rust_packages"]))
        self.assertLessEqual(STACK_CLIENT_PACKAGES, set(outputs["rust_packages"]))

    def test_casework_authority_changes_replay_the_stock_breg_composition(self) -> None:
        for path in ("crates/registry-casework/src/task_grants.rs", "crates/registry-casework/src/auth.rs", "crates/registry-casework-core/src/task_grant.rs"):
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["breg_contracts"])

    def test_casework_task_approval_journey_runs_wherever_its_inputs_change(
        self,
    ) -> None:
        # The casework-postgres job owns the stock-issuer task approval
        # journey through Evidence, BReg, and Scheduling. It must run on every
        # change that selects the BReg product gate and on every change to the
        # Scheduling runtime whose probe example the journey builds.
        paths = [f"{root}/src/lib.rs" for root in self.workspace.roots.values()]
        paths.extend(
            (
                "products/registry-record/schema/registry-record-v1.schema.json",
                "crates/registry-casework/src/task_grants.rs",
                "crates/registry-casework-core/src/task_grant.rs",
                "crates/registry-thunderid-tooling/src/local.rs",
                "crates/registry-scheduling/examples/scheduling-auth-probe.rs",
                "crates/registry-scheduling-core/src/lib.rs",
            )
        )
        for path in paths:
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                if outputs["breg_contracts"] or (
                    "registry-scheduling" in outputs["rust_packages"]
                ):
                    self.assertTrue(outputs["casework_postgres"])
        scheduling = classify(
            self.workspace,
            ("crates/registry-scheduling/examples/scheduling-auth-probe.rs",),
        )
        self.assertTrue(scheduling["casework_postgres"])

    def test_issuer_tooling_change_runs_the_replacement_journeys(self) -> None:
        outputs = classify(self.workspace, ("crates/registry-thunderid-tooling/src/local.rs",))
        self.assertIn("registry-thunderid-tooling", outputs["rust_packages"])
        self.assertTrue(outputs["evidence_tutorial"])
        self.assertTrue(outputs["breg_tutorial"])
        self.assertTrue(outputs["casework_tutorial"])

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
            {"developer-tools", "evidence"},
        )

    def test_mcp_gateway_change_runs_in_the_breg_shard(self) -> None:
        outputs = classify(
            self.workspace,
            ("crates/registry-breg-mcp/src/gateway.rs",),
        )
        self.assertIn("registry-breg-mcp", outputs["rust_packages"])
        breg = next(
            entry
            for entry in outputs["rust_matrix"]["include"]
            if entry["name"] == "breg"
        )
        self.assertIn("registry-breg-mcp", breg["packages"])
        self.assertTrue(
            classify(self.workspace, ("crates/registry-breg-mcp/src/cli.rs",))["docs"]
        )

    def test_review_page_command_change_runs_docs(self) -> None:
        # `breg-review`'s Clap tree is built in its lib.rs, which the CLI
        # reference renders, so a change there rebuilds the docs.
        outputs = classify(
            self.workspace,
            ("crates/registry-breg-review/src/lib.rs",),
        )
        self.assertTrue(outputs["docs"])
        self.assertIn("registry-breg-review", outputs["rust_packages"])
        self.assertFalse(
            classify(
                self.workspace, ("crates/registry-breg-review/src/pages.rs",)
            )["docs"]
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

    def test_casework_bindings_run_the_native_client_job(self) -> None:
        # The Casework bindings are covered only by the shared native-client
        # job, and the Python one also ships in the assembled package the
        # application tutorial imports.
        for path in (
            "crates/registry-casework-client-node/src/lib.rs",
            "crates/registry-casework-client-py/src/lib.rs",
        ):
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["client_bindings"])
        self.assertTrue(
            classify(
                self.workspace, ("crates/registry-casework-client-py/src/lib.rs",)
            )["evidence_tutorial"]
        )

    def test_messaging_bindings_run_the_native_client_job(self) -> None:
        # The Messaging bindings are covered only by the shared native-client
        # job, and the Python one also ships in the assembled package the
        # application tutorial imports.
        for path in (
            "crates/registry-messaging-client-node/src/lib.rs",
            "crates/registry-messaging-client-py/src/lib.rs",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["client_bindings"])
                self.assertTrue(outputs["messaging_contracts"])
        self.assertTrue(
            classify(
                self.workspace, ("crates/registry-messaging-client-py/src/lib.rs",)
            )["evidence_tutorial"]
        )

    def test_scheduling_bindings_run_the_native_client_job(self) -> None:
        # The Scheduling bindings are covered only by the shared native-client
        # job, and the Python one also ships in the assembled package the
        # application tutorial imports.
        for path in (
            "crates/registry-scheduling-client-node/src/lib.rs",
            "crates/registry-scheduling-client-py/src/lib.rs",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["client_bindings"])
                self.assertTrue(outputs["scheduling_contracts"])
        self.assertTrue(
            classify(
                self.workspace, ("crates/registry-scheduling-client-py/src/lib.rs",)
            )["evidence_tutorial"]
        )

    def test_a_scheduling_client_change_also_runs_the_binding_job(self) -> None:
        # Both bindings are Cargo path-dependents of the Rust client, so a
        # client change can alter the native surface the packages wrap.
        outputs = classify(
            self.workspace, ("crates/registry-scheduling-client/src/lib.rs",)
        )
        self.assertTrue(outputs["client_bindings"])
        self.assertIn("registry-scheduling-client-node", outputs["rust_packages"])
        self.assertIn("registry-scheduling-client-py", outputs["rust_packages"])

    def test_an_sdk_or_verifier_change_also_runs_the_binding_job(self) -> None:
        # Both bindings are Cargo path-dependents of the SDK and the verifier,
        # so either can change the native surface or the error envelope the
        # packages wrap. Selecting the job from changed paths alone would skip
        # the npm suite, the type-drift check, and the Python unittest suite for
        # exactly the changes most able to break them.
        for path in (
            "crates/registry-discovery-client/src/client.rs",
            "crates/registry-evidence-client/src/client.rs",
            "crates/registry-evidence-verifier/src/lib.rs",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["client_bindings"])
                if "registry-discovery-client" in path:
                    self.assertIn(
                        "registry-discovery-client-node", outputs["rust_packages"]
                    )
                    self.assertIn(
                        "registry-discovery-client-py", outputs["rust_packages"]
                    )
                    continue
                self.assertIn(
                    "registry-evidence-client-node", outputs["rust_packages"]
                )
                self.assertIn("registry-evidence-client-py", outputs["rust_packages"])

    def test_current_contract_gates_replace_the_retired_notary_gate(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("\n  discovery-contracts:\n", workflow)
        self.assertIn("products/discovery/scripts/check-contracts.sh", workflow)
        self.assertIn(
            "node docs/site/scripts/run-tutorial.mjs --gate discovery", workflow
        )
        self.assertNotIn("products/discovery/scripts/test-adopter-tutorial.sh", workflow)
        self.assertIn("\n  evidence-contracts:\n", workflow)
        self.assertIn("products/evidence/scripts/check-contracts.sh", workflow)
        self.assertIn(
            "products/evidence/scripts/check-source-neutrality.sh", workflow
        )
        self.assertNotIn("\n  notary-contracts:\n", workflow)
        self.assertNotIn("notary_contracts", workflow)

        self.assertIn("\n  breg-contracts:\n", workflow)
        self.assertIn("name: Base Registry Engine product contracts", workflow)
        self.assertIn(
            "products/breg/scripts/check-contracts.sh", workflow
        )
        self.assertIn(
            "products/breg/scripts/test-postgres.sh", workflow
        )
        self.assertIn(
            "products/breg/scripts/test-adopter-workflow.sh", workflow
        )

        rust_result = workflow.split("\n  rust-result:\n", 1)[1].split(
            "\n  release-tool:\n", 1
        )[0]
        self.assertIn("\n      - discovery-contracts\n", rust_result)
        self.assertIn("\n      - evidence-contracts\n", rust_result)
        self.assertIn("\n      - breg-contracts\n", rust_result)
        self.assertNotIn("\n      - notary-contracts\n", rust_result)

    def test_breg_contracts_pin_postgresql_and_use_the_product_entry_points(
        self,
    ) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        breg_job = workflow.split(
            "\n  breg-contracts:\n", 1
        )[1].split("\n  identifiers:\n", 1)[0]

        self.assertIn(
            "postgis/postgis@sha256:01a6a70e41e6c4467c8f55f6063555ed72db2d6662cd0d571040d42eadaeb6f6",
            breg_job,
        )
        self.assertIn(
            "ports:\n          - 5432/tcp",
            breg_job,
        )
        self.assertIn(
            "DATABASE_PORT: ${{ job.services.postgres.ports['5432'] }}",
            breg_job,
        )
        self.assertIn(
            "BREG_TEST_DATABASE_URL=postgresql://breg:breg_test@localhost:${DATABASE_PORT}/breg",
            breg_job,
        )
        self.assertIn(
            "BREG_TEST_TLS_DATABASE_URL=postgresql://breg:breg_test@localhost:${DATABASE_PORT}/breg",
            breg_job,
        )
        self.assertIn(
            "BREG_TEST_TLS_HOSTNAME_MISMATCH_DATABASE_URL=postgresql://breg:breg_test@127.0.0.1:${DATABASE_PORT}/breg",
            breg_job,
        )
        self.assertIn(
            "POSTGRES_CONTAINER_ID: ${{ job.services.postgres.id }}",
            breg_job,
        )
        self.assertIn(
            "TLS_CA_PEM_PATH: ${{ runner.temp }}/breg-postgres-trusted-ca.pem",
            breg_job,
        )
        self.assertIn(
            "uses: astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7",
            breg_job,
        )
        self.assertIn('version: "0.11.16"', breg_job)
        for entry_point in (
            "products/breg/scripts/check-contracts.sh",
            "products/breg/scripts/check-client-contract.sh",
            "products/breg/scripts/check-mcp-gateway-boundary.sh",
            "products/breg/scripts/check-service-dependencies.sh",
            "products/breg/scripts/test-postgres.sh",
            "products/breg/scripts/test-postgres-tls.sh",
            "products/breg/scripts/test-adopter-workflow.sh",
            "products/breg/scripts/test-backup-restore.sh",
            "products/breg/quickstart/run.sh --smoke",
        ):
            with self.subTest(entry_point=entry_point):
                self.assertIn(entry_point, breg_job)

    def test_discovery_contracts_pins_node_for_the_tutorial_runner(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        discovery_job = workflow.split("\n  discovery-contracts:\n", 1)[1].split(
            "\n  casework-postgres:\n", 1
        )[0]

        self.assertIn(
            "uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
            discovery_job,
        )
        self.assertIn("node-version: 22.12.0", discovery_job)
        self.assertIn("cache: npm", discovery_job)
        self.assertIn(
            "cache-dependency-path: docs/site/package-lock.json\n", discovery_job
        )

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

    def test_full_sweep_selects_all_gates_and_owned_rust_packages(self) -> None:
        outputs = classify(self.workspace, (), full_sweep=True)
        for key, value in outputs.items():
            if isinstance(value, bool):
                with self.subTest(gate=key):
                    self.assertTrue(value)
        self.assertEqual(outputs["rust_packages"], sorted(self.workspace.package_names))
        self.assertEqual(
            {entry["name"]: entry["packages"] for entry in outputs["rust_matrix"]["include"]},
            {name: sorted(packages) for name, packages in SHARDS.items()},
        )

    def test_event_router_changes_select_complete_rust_proof(self) -> None:
        outputs = classify(self.workspace, (".github/scripts/ci_event_routing.py",))
        self.assertEqual(outputs["rust_packages"], sorted(self.workspace.package_names))

    def test_cargo_runtime_helper_changes_select_complete_rust_proof(self) -> None:
        for path in (
            "scripts/cargo-runtime-library-path.sh",
            "scripts/cargo_runtime_library_path.py",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertEqual(
                    outputs["rust_packages"], sorted(self.workspace.package_names)
                )

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

    def test_docs_pages_deploys_main_and_accepts_optional_dispatch(self) -> None:
        workflow = Path(".github/workflows/docs-pages.yml").read_text(encoding="utf-8")
        trigger_block = workflow.split("\npermissions:", 1)[0].rstrip()
        self.assertEqual(
            trigger_block,
            """name: Deploy RegistryStack Docs
run-name: Deploy RegistryStack Docs ${{ inputs.released_tag }} (${{ inputs.request_id }})

on:
  push:
    branches:
      - main
  workflow_dispatch:
    inputs:
      released_tag:
        description: Optional exact public docs-bearing release tag
        required: false
        type: string
      docs_sha256:
        description: Optional SHA-256 of that released documentation archive
        required: false
        type: string
      request_id:
        description: Optional release publication correlation ID
        required: false
        type: string
""".rstrip(),
        )

    def test_cli_reference_inputs_run_docs(self) -> None:
        self.assertEqual(
            {
                pattern
                for pattern, _source in CLI_REFERENCE_INPUTS
                if pattern in {"Cargo.lock", "Cargo.toml"}
            },
            {"Cargo.lock", "Cargo.toml"},
        )
        for _pattern, source in CLI_REFERENCE_INPUTS:
            with self.subTest(source=source):
                self.assertTrue(classify(self.workspace, (source,))["docs"])

    def test_operator_docs_outside_the_site_run_docs(self) -> None:
        """The docs release-pin suite scans docker/README.md directly."""
        outputs = classify(self.workspace, ("docker/README.md",))
        self.assertTrue(outputs["docs"])
        self.assertFalse(outputs["rust"])

    def test_every_repo_docs_source_runs_docs(self) -> None:
        """Each current page the site generates from repo-docs.yaml is scanned
        by the docs suite, so a change to its owning source runs docs."""
        root = Path(__file__).resolve().parents[2]
        manifest = yaml.safe_load(
            (root / "docs/site/src/data/repo-docs.yaml").read_text(encoding="utf-8")
        )
        sources = {
            entry["src"]
            for repo in manifest["repos"].values()
            for entry in repo.get("docs", ())
        }
        self.assertIn("products/evidence/README.md", sources)
        self.assertEqual(repo_docs_sources(root), sources)
        for source in sorted(sources):
            with self.subTest(source=source):
                self.assertTrue(classify(self.workspace, (source,))["docs"])

    def test_casework_command_changes_select_docs_and_product_checks(self) -> None:
        for path in (
            "crates/registry-casework/src/runtime.rs",
            "crates/registry-caseworkctl/src/lib.rs",
            "crates/registry-caseworkctl/src/main.rs",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["docs"])
                self.assertTrue(outputs["casework_postgres"])
                selected = {row["name"] for row in outputs["rust_matrix"]["include"]}
                self.assertIn("casework", selected)

    def test_messaging_command_changes_select_docs_and_product_checks(self) -> None:
        for path in (
            "crates/registry-messaging/src/runtime.rs",
            "crates/registry-messagingctl/src/lib.rs",
            "crates/registry-messagingctl/src/main.rs",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["docs"])
                self.assertTrue(outputs["messaging_postgres"])
                selected = {row["name"] for row in outputs["rust_matrix"]["include"]}
                self.assertIn("messaging", selected)

    def test_docs_rebuild_from_generator_inputs_without_rendered_changes(self) -> None:
        for path in (
            "crates/registry-cli-docs/Cargo.toml",
            "crates/registry-breg/Cargo.toml",
            "crates/registry-cli-docs/examples/catalog.rs",
            "products/evidence/generated/registry-evidence.openapi.json",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["docs"])
                self.assertFalse(outputs["docs_archives"])

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

    def test_server_config_schema_change_runs_docs_and_server_contracts(self) -> None:
        for path in (
            "products/breg/generated/authoring/registry-project.schema.json",
            "products/breg/generated/authoring/registry-module.schema.json",
            "products/breg/generated/runtime/runtime.schema.json",
        ):
            with self.subTest(path=path):
                outputs = classify(self.workspace, (path,))
                self.assertTrue(outputs["docs"])
                self.assertTrue(outputs["breg_contracts"])

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

    def test_evidence_client_schema_change_runs_evidence_contracts(self) -> None:
        """The contracts job reproduces the client schemas from their readers."""
        for path in (
            "crates/registry-evidence-client/src/profile_file.rs",
            "crates/registry-evidence-client/src/schema.rs",
            "products/evidence/generated/client-profile/client-profile.schema.json",
            "products/evidence/generated/client-contracts/client-contracts.schema.json",
        ):
            with self.subTest(path=path):
                self.assertTrue(classify(self.workspace, (path,))["evidence_contracts"])

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

    def test_docs_routing_matrix(self) -> None:
        # The page manifest is a docs and archive input, while a repository
        # document the site does not publish stays out of the docs job.
        cases = (
            (
                "docs/site/src/data/repo-docs.yaml",
                {"docs": True, "docs_archives": True, "rust": False},
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

    def test_every_referenced_changes_output_is_declared_and_emitted(self) -> None:
        """Job conditions read outputs the changes job forwards.

        A condition naming an output the ``changes`` job never declares reads
        the empty string, so the job it guards never runs and nothing says so.
        """

        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        referenced = set(
            re.findall(r"needs\.changes\.outputs\.([A-Za-z_][A-Za-z0-9_]*)", workflow)
        )
        self.assertTrue(referenced)

        outputs_block = workflow.split("\n    outputs:\n", 1)[1].split(
            "\n    steps:\n", 1
        )[0]
        declared = dict(
            re.findall(
                r"^      ([A-Za-z_][A-Za-z0-9_]*): "
                r"\$\{\{ steps\.filter\.outputs\.([A-Za-z_][A-Za-z0-9_]*) \}\}$",
                outputs_block,
                re.MULTILINE,
            )
        )
        emitted = set(selection_outputs(
            self.workspace, select_event(Path.cwd(), "schedule", {}, "")
        ))

        for name in sorted(referenced):
            with self.subTest(output=name):
                self.assertIn(name, declared)
                self.assertEqual(name, declared[name])
                self.assertIn(name, emitted)

    def test_other_workflow_changes_do_not_select_the_full_matrix(self) -> None:
        gate_outputs = {
            "docs",
            "evidence_assurance",
            "platform",
            "release_source_proof",
            "release_tool",
        }
        for workflow, gates in sorted(SECURITY_WORKFLOW_GATES.items()):
            with self.subTest(workflow=workflow):
                outputs = classify(
                    self.workspace,
                    (workflow,),
                )
                self.assertFalse(outputs["rust"])
                for output in gate_outputs:
                    self.assertEqual(output in gates, outputs[output], output)
                self.assertTrue(outputs["release_tool"])
                self.assertFalse(outputs["docs_archives"])

    def test_every_tracked_root_workflow_selects_release_checks(self) -> None:
        workflows = sorted(Path(".github/workflows").glob("*.y*ml"))
        self.assertTrue(workflows)
        for workflow in workflows:
            with self.subTest(workflow=workflow):
                outputs = classify(self.workspace, (workflow.as_posix(),))
                self.assertTrue(outputs["release_tool"])

    def test_third_party_notice_selects_release_packaging_checks(self) -> None:
        outputs = classify(self.workspace, ("THIRD_PARTY_NOTICES",))

        self.assertTrue(outputs["release_tool"])

    def test_unclassified_root_workflow_fails_closed_to_release_checks(self) -> None:
        for workflow in (
            ".github/workflows/dco.yml",
            ".github/workflows/new-privileged.yml",
            ".github/workflows/new-privileged.yaml",
        ):
            with self.subTest(workflow=workflow):
                outputs = classify(self.workspace, (workflow,))
                self.assertTrue(outputs["release_tool"])
                self.assertTrue(outputs["release_source_proof"])
                self.assertTrue(outputs["docs"])
                self.assertTrue(outputs["platform"])
                self.assertTrue(outputs["rust"])

    def test_non_workflow_file_under_workflow_directory_stays_unselected(
        self,
    ) -> None:
        outputs = classify(
            self.workspace,
            (".github/workflows/README.md",),
        )
        self.assertFalse(outputs["release_tool"])

def edit_lock_package(text: str, name: str, **fields: str) -> str:
    """Return the lockfile with one uniquely named package's fields replaced."""

    blocks = text.split("\n[[package]]\n")
    matched = [
        index for index, block in enumerate(blocks)
        if block.startswith(f'name = "{name}"\n')
    ]
    if len(matched) != 1:
        raise AssertionError(f"expected one locked {name}, found {len(matched)}")
    block = blocks[matched[0]]
    for field, value in fields.items():
        block, count = re.subn(
            rf'^{field} = "[^"]*"$', f'{field} = "{value}"', block, flags=re.MULTILINE
        )
        if count != 1:
            raise AssertionError(f"locked {name} has no single {field}")
    blocks[matched[0]] = block
    return "\n[[package]]\n".join(blocks)


def bump_lock_package(text: str, name: str, version: str) -> str:
    """Model a lock-only upgrade: a new version with a new registry checksum."""

    return edit_lock_package(text, name, version=version, checksum="0" * 64)


class LockfileSelectionTest(unittest.TestCase):
    """A Cargo.lock-only change routes through the packages it can reach."""

    @classmethod
    def setUpClass(cls) -> None:
        metadata = subprocess.run(
            ("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"),
            check=True,
            capture_output=True,
            text=True,
        )
        cls.workspace = Workspace(json.loads(metadata.stdout))
        cls.lock = Path("Cargo.lock").read_text(encoding="utf-8")

    def change(self, head: str | None, base: str | None = None) -> LockChange:
        return lock_change(self.lock if base is None else base, head, self.workspace)

    def assert_full(self, outputs: dict[str, Any]) -> None:
        self.assertEqual(outputs["rust_packages"], sorted(self.workspace.package_names))

    def test_lock_only_leaf_bump_selects_only_its_consumers(self) -> None:
        change = self.change(bump_lock_package(self.lock, "pdf-writer", "0.15.1"))
        self.assertEqual(change.members, frozenset({"registry-render"}))
        self.assertFalse(change.native)

        outputs = classify(self.workspace, ("Cargo.lock",), lock_change=change)
        expected = sorted(self.workspace.affected_packages({"registry-render"}))
        self.assertEqual(outputs["rust_packages"], expected)
        self.assertLess(len(expected), len(self.workspace.package_names))
        self.assertFalse(outputs["platform"])
        self.assertFalse(outputs["platform_hygiene"])
        self.assertFalse(outputs["docs_archives"])
        self.assertFalse(outputs["breg_contracts"])
        # The release helper validates workspace versions in the lock, and the
        # release source model binds the exact lock bytes.
        self.assertTrue(outputs["release_tool"])
        self.assertTrue(outputs["release_source_proof"])

    def test_lock_selection_follows_build_and_dev_edges_to_every_consumer(
        self,
    ) -> None:
        # tree-sitter-yaml compiles C, so it is proven by the full sweep; its
        # pure-Rust companion rhai reaches six members through normal edges.
        change = self.change(bump_lock_package(self.lock, "rhai", "1.26.2"))
        self.assertEqual(
            change.members,
            frozenset(
                {
                    "registry-breg",
                    "registry-evidence",
                    "registry-evidence-authoring",
                    "registry-evidencectl",
                    "registry-messaging",
                    "registry-platform-script",
                }
            ),
        )
        outputs = classify(self.workspace, ("Cargo.lock",), lock_change=change)
        self.assertTrue(outputs["platform"])
        self.assertTrue(outputs["breg_contracts"])
        self.assertTrue(outputs["evidence_contracts"])
        self.assertTrue(outputs["messaging_contracts"])

    def test_sys_bump_forces_full(self) -> None:
        change = self.change(bump_lock_package(self.lock, "libsqlite3-sys", "0.38.3"))
        self.assertIsNone(change.members)
        self.assertTrue(change.native)
        self.assertIn("libsqlite3-sys", change.reason)
        self.assert_full(classify(self.workspace, ("Cargo.lock",), lock_change=change))

    def test_links_and_c_compiling_bumps_force_full(self) -> None:
        for name, version in (
            ("ring", "0.17.15"),
            ("aws-lc-rs", "1.18.2"),
            ("tree-sitter-yaml", "0.7.3"),
        ):
            with self.subTest(package=name):
                change = self.change(bump_lock_package(self.lock, name, version))
                self.assertIsNone(change.members)
                self.assertTrue(change.native)
                self.assert_full(
                    classify(self.workspace, ("Cargo.lock",), lock_change=change)
                )

    def test_widely_used_bump_forces_full(self) -> None:
        # Widely used proc-macros and their syntax toolchain reach most of the
        # workspace; so does any other crate past the threshold.
        for name, version in (("itoa", "1.0.19"), ("serde_derive", "9.9.9")):
            with self.subTest(package=name):
                change = self.change(bump_lock_package(self.lock, name, version))
                self.assertIsNone(change.members)
                self.assertFalse(change.native)
                self.assert_full(
                    classify(self.workspace, ("Cargo.lock",), lock_change=change)
                )

    def test_toolchain_and_shared_build_inputs_stay_full(self) -> None:
        change = self.change(bump_lock_package(self.lock, "pdf-writer", "0.15.1"))
        for other in (
            "rust-toolchain.toml",
            "rust-toolchain",
            "Cargo.toml",
            ".cargo/config.toml",
            "clippy.toml",
            "deny.toml",
            "rustfmt.toml",
            ".github/workflows/ci.yml",
        ):
            with self.subTest(path=other):
                self.assert_full(
                    classify(
                        self.workspace, ("Cargo.lock", other), lock_change=change
                    )
                )

    def test_parse_failure_forces_full(self) -> None:
        for head in (
            "[[package]\nname = ",
            "version = 4\n",
            self.lock.replace('\n "bitflags",\n', '\n "no-such-package",\n', 1),
            None,
        ):
            with self.subTest(head=None if head is None else head[:24]):
                change = self.change(head)
                self.assertIsNone(change.members)
                self.assertTrue(change.native)
                self.assertIn("Cargo.lock", change.reason)
                self.assert_full(
                    classify(self.workspace, ("Cargo.lock",), lock_change=change)
                )

    def test_git_source_change_forces_full(self) -> None:
        head = edit_lock_package(
            self.lock,
            "pdf-writer",
            source="git+https://example.invalid/pdf-writer?rev=0#0",
        )
        change = self.change(head)
        self.assertIsNone(change.members)
        self.assertIn("git", change.reason)

    def test_lock_format_change_forces_full(self) -> None:
        change = self.change(self.lock.replace("\nversion = 4\n", "\nversion = 3\n", 1))
        self.assertIsNone(change.members)

    def test_change_reaching_no_member_forces_full(self) -> None:
        orphan = (
            '\n[[package]]\nname = "unreferenced-crate"\nversion = "1.0.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "{"1" * 64}"\n'
        )
        change = self.change(self.lock + orphan)
        self.assertIsNone(change.members)
        self.assertIn("no workspace member", change.reason)

    def test_unchanged_lock_text_forces_full(self) -> None:
        change = self.change(self.lock + "\n")
        self.assertIsNone(change.members)

    def test_lock_without_an_analysis_stays_full(self) -> None:
        self.assert_full(classify(self.workspace, ("Cargo.lock",)))

class EventScopedSelectionTest(unittest.TestCase):
    """Broad assurance and heavy integration wait for the merge queue."""

    @classmethod
    def setUpClass(cls) -> None:
        metadata = subprocess.run(
            ("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"),
            check=True,
            capture_output=True,
            text=True,
        )
        cls.workspace = Workspace(json.loads(metadata.stdout))

    def test_platform_assurance_waits_for_the_merge_queue(self) -> None:
        for path in (
            "crates/registry-platform-crypto/src/lib.rs",
            "products/platform/fuzz/fuzz_targets/sqlite_statement.rs",
            "products/platform/scripts/run-fuzz-smoke.sh",
        ):
            with self.subTest(path=path):
                reviewed = classify(self.workspace, (path,), pull_request=True)
                self.assertTrue(reviewed["platform"])
                self.assertFalse(reviewed["platform_assurance"])
                queued = classify(self.workspace, (path,))
                self.assertTrue(queued["platform"])
                self.assertTrue(queued["platform_assurance"])
        swept = classify(self.workspace, (), pull_request=True, full_sweep=True)
        self.assertTrue(swept["platform_assurance"])
        unrelated = classify(self.workspace, ("README.md",))
        self.assertFalse(unrelated["platform_assurance"])

    def test_platform_coverage_runs_on_main_and_the_full_sweep_only(self) -> None:
        path = ("crates/registry-platform-crypto/src/lib.rs",)
        self.assertFalse(classify(self.workspace, path, pull_request=True)["platform_coverage"])
        self.assertFalse(classify(self.workspace, path)["platform_coverage"])
        self.assertTrue(classify(self.workspace, path, main_push=True)["platform_coverage"])
        self.assertTrue(classify(self.workspace, (), full_sweep=True)["platform_coverage"])
        self.assertFalse(
            classify(self.workspace, ("README.md",), main_push=True)["platform_coverage"]
        )

    def test_heavy_integration_waits_for_the_merge_queue_or_ci_full(self) -> None:
        heavy = (
            "breg_integration",
            "casework_postgres",
            "scheduling_postgres",
            "evidence_tutorial",
            "breg_tutorial",
            "casework_tutorial",
            "breg_evidence_composition",
        )
        # Each heavy selector keeps its own path gate; this change reaches all.
        paths = (
            "crates/registry-breg/src/lib.rs",
            "crates/registry-evidence/src/lib.rs",
            "crates/registry-casework/src/lib.rs",
            "crates/registry-scheduling/src/lib.rs",
        )
        reviewed = classify(self.workspace, paths, pull_request=True)
        for name in heavy:
            with self.subTest(event="pull_request", output=name):
                self.assertFalse(reviewed[name])
        # Review keeps the plain Base Registry Engine contracts lane.
        self.assertTrue(reviewed["breg_contracts"])
        self.assertEqual(["contracts"], reviewed["breg_contracts_lanes"])
        self.assertTrue(reviewed["rust"])

        for event, outputs in (
            ("ci:full", classify(self.workspace, paths, pull_request=True, ci_full=True)),
            ("merge_group", classify(self.workspace, paths)),
            ("full sweep", classify(self.workspace, (), pull_request=True, full_sweep=True)),
        ):
            for name in heavy:
                with self.subTest(event=event, output=name):
                    self.assertTrue(outputs[name])
            self.assertEqual(list(BREG_CONTRACTS_LANES), outputs["breg_contracts_lanes"])

        # Path gating still applies in the merge queue.
        unrelated = classify(self.workspace, ("README.md",))
        for name in heavy:
            with self.subTest(event="unrelated", output=name):
                self.assertFalse(unrelated[name])

    def test_linux_release_recipe_runs_only_in_the_full_sweep(self) -> None:
        for paths in (
            ("release/scripts/build-linux-node-client",),
            ("crates/registry-evidence-client-py/build.rs",),
            ("crates/registry-casework-client-node/src/lib.rs",),
            ("rust-toolchain.toml",),
            (".github/workflows/ci.yml",),
            ("Cargo.lock",),
        ):
            for pull_request in (True, False):
                with self.subTest(paths=paths, pull_request=pull_request):
                    self.assertFalse(
                        classify(self.workspace, paths, pull_request=pull_request)[
                            "release_linux_node_clients"
                        ]
                    )
        self.assertTrue(
            classify(self.workspace, (), full_sweep=True)["release_linux_node_clients"]
        )

    def test_full_sweep_output_names_the_nightly_and_manual_sweep(self) -> None:
        self.assertTrue(classify(self.workspace, (), full_sweep=True)["full_sweep"])
        self.assertFalse(classify(self.workspace, (), run_all=True)["full_sweep"])
        self.assertFalse(
            classify(self.workspace, (".github/workflows/ci.yml",))["full_sweep"]
        )

    def test_archives_ignore_the_workflow_and_cargo_manifests(self) -> None:
        for paths in (
            (".github/workflows/ci.yml",),
            ("Cargo.lock",),
            ("Cargo.toml",),
            ("Cargo.lock", "Cargo.toml", ".github/workflows/ci.yml"),
        ):
            for pull_request in (True, False):
                with self.subTest(paths=paths, pull_request=pull_request):
                    outputs = classify(
                        self.workspace, paths, pull_request=pull_request
                    )
                    self.assertFalse(outputs["docs_archives"])
        self.assertTrue(classify(self.workspace, (), full_sweep=True)["docs_archives"])

    def test_every_archive_recipe_import_selects_archive_verification(self) -> None:
        # The archive-specific commands `check:archives` and
        # `check:archive-lock` run after the current-site build the docs job
        # already proves. Everything they import is an archive input.
        site = Path("docs/site")
        entries = [
            site / "scripts" / name
            for name in (
                "apply-archive-seo.mjs",
                "archive-lock.mjs",
                "assemble-archives.mjs",
                "check-built-links.mjs",
                "check-llms.mjs",
                "check-seo.mjs",
            )
        ]
        imports = re.compile(
            r"""(?:from\s*|import\(\s*|import\s+)['"](\.{1,2}/[^'"]+)['"]"""
        )
        seen: set[Path] = set()
        pending = list(entries)
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            for relative in imports.findall(current.read_text(encoding="utf-8")):
                target = Path(
                    os.path.normpath(current.parent / relative)
                )
                self.assertTrue(target.is_file(), f"{current} imports {target}")
                pending.append(target)
        self.assertGreater(len(seen), len(entries))
        for path in sorted(seen):
            with self.subTest(path=path.as_posix()):
                self.assertTrue(
                    classify(self.workspace, (path.as_posix(),))["docs_archives"]
                )
                # The archive comparison needs the merge queue's base.
                self.assertFalse(
                    classify(
                        self.workspace, (path.as_posix(),), pull_request=True
                    )["docs_archives"]
                )
        # check-llms reads this module's source text rather than importing it.
        self.assertTrue(
            classify(self.workspace, ("docs/site/src/lib/page-markdown.ts",))[
                "docs_archives"
            ]
        )


class RunCargoPackagesTest(unittest.TestCase):
    def test_builds_a_direct_cargo_argument_vector(self) -> None:
        packages = package_args('["registry-relay-v2","registry-evidence"]')
        self.assertEqual(
            command_args("test", packages, True),
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                "registry-relay-v2",
                "-p",
                "registry-evidence",
                "--all-features",
            ],
        )

    def test_rejects_shell_syntax_in_package_names(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid Cargo package name"):
            package_args('["registry-relay-v2; id"]')


class DocsInstallRetryTest(unittest.TestCase):
    """Run the docs install steps that need the Vale download against a stub npm."""

    STEPS = (
        ("ci.yml", "docs"),
        ("ci.yml", "docs-archives"),
        ("docs-pages.yml", "build"),
    )

    def install_calls(self, command: str, refusals: int) -> tuple[int, list[str]]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / "calls"
            calls.touch()
            (root / "npm").write_text(
                "#!/usr/bin/env bash\n"
                f'echo "npm $*" >> "{calls}"\n'
                f'[[ "$(grep -c "^npm" "{calls}")" -gt {refusals} ]]\n'
            )
            (root / "sleep").write_text(
                f'#!/usr/bin/env bash\necho "sleep $*" >> "{calls}"\n'
            )
            for stub in ("npm", "sleep"):
                (root / stub).chmod(0o755)
            completed = subprocess.run(
                ["bash", "-e", "-c", command],
                env={**os.environ, "PATH": f"{root}{os.pathsep}{os.environ['PATH']}"},
                check=False,
            )
            return completed.returncode, calls.read_text().splitlines()

    def test_a_refused_docs_install_is_retried_once_after_a_pause(self) -> None:
        for name, job in self.STEPS:
            workflow = yaml.safe_load(Path(".github/workflows", name).read_text())
            (step,) = (
                step
                for step in workflow["jobs"][job]["steps"]
                if step.get("name") == "Install docs dependencies"
            )
            with self.subTest(workflow=name, job=job):
                self.assertEqual(
                    self.install_calls(step["run"], refusals=0), (0, ["npm ci"])
                )
                self.assertEqual(
                    self.install_calls(step["run"], refusals=1),
                    (0, ["npm ci", "sleep 30", "npm ci"]),
                )
                status, calls = self.install_calls(step["run"], refusals=2)
                self.assertNotEqual(status, 0)
                self.assertEqual(calls, ["npm ci", "sleep 30", "npm ci"])


if __name__ == "__main__":
    unittest.main()
