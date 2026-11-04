#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_dependency_direction.py")
SPEC = importlib.util.spec_from_file_location("adapter_dependency_direction", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

NAMES = {
    "engine": "registry-adapter",
    "shared-engine": "registry-adapter-engine",
    "core": "registry-adapter-core",
    "ctl": "registry-adapterctl",
    "job": "registry-adapter-job",
    "connectors": "registry-adapter-connectors",
    "record": "registry-record",
    "platform": "registry-platform-httputil",
    "platform-testing": "registry-platform-testing",
    "platform-script": "registry-platform-script",
    "serde": "serde",
    "breg": "registry-breg",
    "breg-client": "registry-breg-client",
    "bregctl": "registry-bregctl",
    "breg-mcp": "registry-breg-mcp",
    "scheduling": "registry-scheduling",
    "scheduling-client": "registry-scheduling-client",
    "schedulingctl": "registry-schedulingctl",
    "documents": "registry-documents",
    "documents-client": "registry-documents-client",
    "documentsctl": "registry-documentsctl",
    "coordinator": "registry-coordinator",
    "coordinator-client": "registry-coordinator-client",
    "stack-client": "registry-stack-client",
    "cli-docs": "registry-cli-docs",
    "evidence": "registry-evidence",
    "casework": "registry-casework",
    "evidence-core": "registry-evidence-core",
    "coordinator-core": "registry-coordinator-core",
    "axum-alias": "axum",
    "postgres-alias": "tokio-postgres",
}

INTENDED = {
    "engine": ["shared-engine", "core", "platform", "platform-script", "serde", ("platform-testing", "dev")],
    "shared-engine": ["core", "platform", "platform-script", "serde"],
    "core": ["platform", "serde"],
    "ctl": ["core", ("engine", "dev")],
    "job": ["shared-engine", "core", "connectors", "platform", "serde"],
    # The job's off-by-default direct feature reaches a connector with exactly
    # one product client. The closure check reads it with all features on, so
    # the fixture lists it as a normal edge.
    "connectors": [
        "core",
        "breg-client",
        "serde",
    ],
    "record": ["serde"],
    "platform": ["serde"],
    "platform-testing": ["platform"],
    "platform-script": ["serde"],
    "serde": [],
    "breg": ["record", "platform"],
    "breg-client": ["record", "platform"],
    "bregctl": ["breg"],
    "breg-mcp": ["breg-client", ("breg", "dev")],
    "scheduling": ["platform"],
    "scheduling-client": ["platform"],
    "schedulingctl": ["scheduling"],
    "documents": ["platform"],
    "documents-client": ["platform"],
    "documentsctl": ["documents"],
    "coordinator": ["breg-client", "platform"],
    "coordinator-client": ["platform"],
    "stack-client": ["breg-client", "coordinator-client"],
    "cli-docs": ["engine", "ctl", "job"],
    "evidence": ["shared-engine", "core", "platform"],
    "casework": ["platform"],
    "evidence-core": ["platform"],
    "coordinator-core": ["platform"],
    "axum-alias": ["serde"],
    "postgres-alias": ["serde"],
}


def dependency(entry) -> dict:
    package_id, kind = entry if isinstance(entry, tuple) else (entry, None)
    return {
        "pkg": package_id,
        "name": NAMES[package_id],
        "dep_kinds": [{"kind": kind, "target": None}],
    }


def metadata(**changes: list) -> dict:
    edges = {**INTENDED, **{name.replace("_", "-"): deps for name, deps in changes.items()}}
    packages = [{"id": package_id, "name": name} for package_id, name in NAMES.items()]
    job = next(package for package in packages if package["name"] == "registry-adapter-job")
    job["dependencies"] = [
        {
            "name": "registry-adapter-connectors",
            "optional": True,
            "uses_default_features": False,
        },
    ]
    job["features"] = {
        "default": [],
        "direct-breg": [
            "dep:registry-adapter-connectors",
            "dep:registry-platform-crypto",
            "dep:registry-platform-httputil",
            "registry-adapter-connectors/breg",
        ],
        "native-test-support": [
            "direct-breg",
            "registry-adapter-connectors/native-test-support",
        ],
        "signed-coordinator-event": [
            "dep:registry-adapter-connectors",
            "dep:registry-platform-httputil",
            "registry-adapter-connectors/coordinator-event",
        ],
    }
    connector = next(
        package
        for package in packages
        if package["name"] == "registry-adapter-connectors"
    )
    connector["features"] = {
        "default": [],
        "coordinator-event": [
            "dep:registry-platform-crypto",
            "dep:registry-platform-hooks",
            "dep:registry-platform-httputil",
            "dep:time",
            "dep:tokio",
            "dep:zeroize",
        ],
    }
    return {
        "packages": packages,
        "resolve": {
            "nodes": [
                {"id": package_id, "deps": [dependency(entry) for entry in entries]}
                for package_id, entries in edges.items()
            ]
        },
    }


def failures(**changes: list) -> str:
    return "\n".join(MODULE.violations(metadata(**changes)))


class EngineTests(unittest.TestCase):
    def test_the_extracted_engine_crate_is_an_accepted_engine_boundary(self):
        self.assertEqual(MODULE.violations(metadata()), [])

    def test_the_extracted_engine_cannot_reach_the_facade_host(self):
        found = failures(**{
            "shared-engine": [*INTENDED["shared-engine"], "engine"],
        })
        self.assertIn("registry-adapter-engine reaches package(s)", found)
        self.assertIn("registry-adapter", found)

    def test_the_extracted_engine_refuses_aliased_axum_and_postgres_packages(self):
        for dependency, package in (
            ("axum-alias", "axum"),
            ("postgres-alias", "tokio-postgres"),
        ):
            with self.subTest(dependency=dependency):
                found = failures(**{
                    "shared-engine": [*INTENDED["shared-engine"], dependency],
                })
                self.assertIn(package, found)

    def test_intended_direction_is_accepted(self):
        self.assertEqual(MODULE.violations(metadata()), [])

    def test_an_engine_crate_reaching_a_product_runtime_is_refused(self):
        for engine in ("engine", "shared-engine", "core", "ctl"):
            for product in ("breg", "scheduling", "documents", "coordinator", "evidence", "casework"):
                with self.subTest(engine=engine, product=product):
                    self.assertIn(
                        f"{NAMES[engine]} reaches package(s) outside registry-platform-*",
                        failures(**{engine: [*INTENDED[engine], product]}),
                    )

    def test_an_engine_crate_reaching_a_product_client_is_refused(self):
        for client in ("breg-client", "scheduling-client", "documents-client", "coordinator-client"):
            with self.subTest(client=client):
                self.assertIn(
                    NAMES[client],
                    failures(engine=[*INTENDED["engine"], client]),
                )

    def test_an_engine_crate_reaching_the_connector_crate_is_refused(self):
        for engine in ("engine", "shared-engine", "core", "ctl"):
            with self.subTest(engine=engine):
                self.assertIn(
                    "registry-adapter-connectors",
                    failures(**{engine: [*INTENDED[engine], "connectors"]}),
                )

    def test_an_engine_crate_reaching_adopter_tooling_is_refused(self):
        found = failures(engine=[*INTENDED["engine"], "bregctl", "schedulingctl", "documentsctl"])
        self.assertIn("registry-bregctl", found)
        self.assertIn("registry-schedulingctl", found)
        self.assertIn("registry-documentsctl", found)

    def test_a_dev_dependency_of_an_engine_crate_counts(self):
        self.assertIn(
            "registry-breg-client",
            failures(engine=[*INTENDED["engine"], ("breg-client", "dev")]),
        )

    def test_a_dev_dependency_of_a_reached_platform_crate_is_not_followed(self):
        self.assertEqual(
            MODULE.violations(
                metadata(platform=["serde", ("casework", "dev")])
            ),
            [],
        )

    def test_a_product_runtime_behind_a_client_is_refused(self):
        # A product client that itself reaches a product runtime puts the
        # runtime in the connector's closure; the connector's rule refuses
        # it, exactly as the engine's rule would.
        found = failures(breg_client=["record", "platform", "breg"])
        self.assertIn("registry-breg", found)
        self.assertIn("registry-adapter-connectors reaches", found)

    def test_the_unified_facade_is_refused_everywhere_in_the_adapter(self):
        for crate in ("engine", "shared-engine", "core", "ctl", "connectors"):
            with self.subTest(crate=crate):
                found = failures(**{crate: [*INTENDED[crate], "stack-client"]})
                self.assertIn("registry-stack-client", found)


class ConnectorTests(unittest.TestCase):
    def test_the_connector_reaches_exactly_one_client(self):
        self.assertEqual(
            MODULE.CONNECTOR_CLIENTS,
            {"registry-breg-client"},
        )

    def test_another_product_client_is_refused(self):
        for client in ("scheduling-client", "documents-client"):
            with self.subTest(client=client):
                self.assertIn(
                    NAMES[client],
                    failures(connectors=[*INTENDED["connectors"], client]),
                )

    def test_the_connector_reaching_a_product_runtime_is_refused(self):
        for product in ("breg", "scheduling", "documents"):
            with self.subTest(product=product):
                self.assertIn(
                    NAMES[product],
                    failures(connectors=[*INTENDED["connectors"], product]),
                )

    def test_the_connector_reaching_a_product_client_outside_the_set_is_refused(self):
        self.assertIn(
            "registry-coordinator-client",
            failures(connectors=[*INTENDED["connectors"], "coordinator-client"]),
        )

    def test_the_connector_reaching_another_products_core_crate_is_refused(self):
        for core in ("evidence-core", "coordinator-core"):
            with self.subTest(core=core):
                self.assertIn(
                    NAMES[core],
                    failures(connectors=[*INTENDED["connectors"], core]),
                )

    def test_the_connector_reaching_adopter_tooling_is_refused(self):
        found = failures(connectors=[*INTENDED["connectors"], "bregctl", "documentsctl"])
        self.assertIn("registry-bregctl", found)
        self.assertIn("registry-documentsctl", found)

    def test_the_connector_reaching_the_engine_runtime_is_refused(self):
        found = failures(connectors=[*INTENDED["connectors"], "engine"])
        self.assertIn("registry-adapter-connectors reaches", found)
        self.assertIn("registry-adapter-core, and registry-platform-*: registry-adapter", found)

    def test_the_connector_may_reach_adapter_core(self):
        self.assertIn("core", INTENDED["connectors"])
        self.assertEqual(MODULE.violations(metadata()), [])

    def test_a_connector_test_cannot_link_what_the_connector_may_not(self):
        self.assertIn(
            "registry-casework",
            failures(connectors=[*INTENDED["connectors"], ("casework", "dev")]),
        )


class DependentTests(unittest.TestCase):
    def test_any_outside_crate_depending_on_an_adapter_crate_is_refused(self):
        for outside in ("breg", "coordinator", "evidence", "casework", "stack-client", "breg-mcp"):
            with self.subTest(outside=outside):
                self.assertIn(
                    f"{NAMES[outside]} depends on Adapter package(s) it is not listed for:",
                    failures(**{outside: [*INTENDED[outside], "connectors"]}),
                )

    def test_evidence_cannot_reach_the_facade_host_even_for_tests(self):
        for edge in ("engine", ("engine", "dev")):
            with self.subTest(edge=edge):
                found = failures(evidence=[*INTENDED["evidence"], edge])
                self.assertIn(
                    "registry-evidence depends on Adapter package(s) it is not listed for: "
                    "registry-adapter",
                    found,
                )

    def test_cli_docs_carries_only_the_engine_command_trees(self):
        self.assertEqual(
            MODULE.ALLOWED_DEPENDENTS,
            {
                "registry-cli-docs": frozenset(
                    {
                        "registry-adapter",
                        "registry-adapter-core",
                        "registry-adapter-engine",
                        "registry-adapter-connectors",
                        "registry-adapter-job",
                        "registry-adapterctl",
                    }
                ),
                "registry-evidence": frozenset(
                    {
                        "registry-adapter-core",
                        "registry-adapter-engine",
                    }
                ),
                "registry-casework": frozenset(
                    {
                        "registry-adapter-core",
                        "registry-adapter-engine",
                    }
                ),
                "registry-discovery-client": frozenset(
                    {
                        "registry-adapter-core",
                        "registry-adapter-engine",
                    }
                ),
                "registry-evidence-client": frozenset(
                    {
                        "registry-adapter-core",
                        "registry-adapter-engine",
                    }
                ),
                "registry-evidencectl": frozenset(
                    {
                        "registry-adapter-core",
                        "registry-adapter-engine",
                    }
                ),
            },
        )

    def test_cli_docs_reaching_the_connector_crate_is_refused(self):
        self.assertIn(
            "registry-cli-docs depends on Adapter package(s) it is not listed for: "
            "registry-adapter-connectors",
            failures(**{"cli-docs": [*INTENDED["cli-docs"], "connectors"]}),
        )

    def test_reaching_the_engine_outside_the_cli_reference_is_refused(self):
        found = failures(bregctl=["breg", "ctl"])
        self.assertIn(
            "registry-bregctl depends on Adapter package(s) it is not listed for:",
            found,
        )

    def test_an_unknown_adapter_crate_needs_a_rule(self):
        names = {**NAMES, "adapter-extra": "registry-adapter-extra"}
        document = metadata()
        document["packages"] = [
            {"id": package_id, "name": name} for package_id, name in names.items()
        ]
        document["resolve"]["nodes"].append({"id": "adapter-extra", "deps": []})
        self.assertEqual(
            MODULE.violations(document),
            [
                "registry-adapter-extra is an Adapter crate this gate does not know; "
                "name its rule here"
            ],
        )


class CommandTests(unittest.TestCase):
    def run_gate(self, document: dict) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "metadata.json"
            fixture.write_text(json.dumps(document), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPT), "--metadata", str(fixture)],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_an_accepted_graph_exits_zero(self):
        completed = self.run_gate(metadata())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")

    def test_a_violation_exits_one_and_names_it(self):
        completed = self.run_gate(metadata(engine=[*INTENDED["engine"], "breg-client"]))
        self.assertEqual(completed.returncode, 1)
        self.assertIn("dependency-direction violation: registry-adapter", completed.stderr)

    def test_a_graph_without_a_resolve_exits_two(self):
        completed = self.run_gate({"packages": []})
        self.assertEqual(completed.returncode, 2)
        self.assertIn("did not include a resolved dependency graph", completed.stderr)


class EngineModuleBoundaryTests(unittest.TestCase):
    """The import-level boundary inside the extracted engine crate."""

    def tree(self, files: dict[str, str]) -> Path:
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        base = Path(root.name)
        engine = base / "crates/registry-adapter-engine/src"
        engine.mkdir(parents=True)
        for name, body in files.items():
            (engine / name).parent.mkdir(parents=True, exist_ok=True)
            (engine / name).write_text(body, encoding="utf-8")
        return base

    def test_a_clean_engine_module_passes(self):
        root = self.tree(
            {
                "route.rs": "use crate::exchange::Exchange;\nuse serde_json::Value;\n",
            }
        )
        self.assertEqual(MODULE.module_violations(root), [])

    def test_a_facade_module_name_refuses(self):
        root = self.tree({"route.rs": "use crate::facade::Problems;\n"})
        failures = MODULE.module_violations(root)
        self.assertTrue(any("facade module facade" in item for item in failures))

    def test_a_super_super_facade_name_refuses(self):
        root = self.tree({"sub.rs": "use super::super::serve::Listener;\n"})
        failures = MODULE.module_violations(root)
        self.assertTrue(any("facade module serve" in item for item in failures))

    def test_a_facade_only_dependency_refuses(self):
        root = self.tree({"egress.rs": "use axum::http::StatusCode;\n"})
        failures = MODULE.module_violations(root)
        self.assertTrue(any("facade-only dependency axum" in item for item in failures))

    def test_comments_do_not_refuse(self):
        root = self.tree(
            {
                "processor.rs": (
                    "//! The idempotentConsumer EIP holds the seam's bound "
                    "(section 9);\n"
                    "// the facade journal once carried it.\n"
                    "pub struct Step;\n"
                ),
            }
        )
        self.assertEqual(MODULE.module_violations(root), [])

    def test_a_brace_import_naming_a_facade_module_refuses(self):
        for body in (
            "use crate::{facade, journal};\n",
            "use crate::{exchange, facade::Problems};\n",
            "use crate::{\n    exchange,\n    journal::Entry,\n};\n",
        ):
            with self.subTest(body=body):
                root = self.tree({"route.rs": body})
                self.assertTrue(
                    any("facade module" in item for item in MODULE.module_violations(root))
                )

    def test_a_brace_import_of_engine_modules_passes(self):
        root = self.tree({"route.rs": "use crate::{exchange, route};\n"})
        self.assertEqual(MODULE.module_violations(root), [])

    def test_a_brace_import_names_each_facade_module_it_lists(self):
        root = self.tree({"route.rs": "use crate::{facade, journal};\n"})
        found = "\n".join(MODULE.module_violations(root))
        self.assertIn("facade module facade", found)
        self.assertIn("facade module journal", found)

    def test_super_from_the_engine_root_module_reaches_the_crate_root(self):
        for body in (
            "use super::journal::Entry;\n",
            "use super::{journal, engine_thing};\n",
        ):
            with self.subTest(body=body):
                root = self.tree({"mod.rs": body})
                self.assertTrue(
                    any("facade module" in item for item in MODULE.module_violations(root))
                )

    def test_super_from_a_sibling_file_stays_inside_the_engine(self):
        root = self.tree({"route.rs": "use super::journal_helper::Entry;\nuse super::exchange;\n"})
        self.assertEqual(MODULE.module_violations(root), [])

    def test_super_super_from_a_nested_module_reaches_the_crate_root(self):
        root = self.tree({"sub/mod.rs": "use super::super::serve::Listener;\n"})
        self.assertTrue(
            any("facade module serve" in item for item in MODULE.module_violations(root))
        )

    def test_a_facade_only_dependency_under_an_alias_refuses(self):
        for body in (
            "use tokio_postgres as pg;\n",
            "extern crate axum as web;\n",
            "use tokio_postgres;\n",
            "use ::axum as web;\n",
        ):
            with self.subTest(body=body):
                root = self.tree({"egress.rs": body})
                self.assertTrue(
                    any(
                        "facade-only dependency" in item
                        for item in MODULE.module_violations(root)
                    )
                )

    def test_a_longer_crate_name_sharing_a_facade_dependency_prefix_passes(self):
        root = self.tree({"egress.rs": "use axum_extra_unrelated as other;\n"})
        self.assertEqual(MODULE.module_violations(root), [])

    def test_a_missing_engine_module_names_itself(self):
        with tempfile.TemporaryDirectory() as empty:
            failures = MODULE.module_violations(Path(empty))
            self.assertEqual(len(failures), 1)
            self.assertIn("engine crate boundary is not assembled", failures[0])

    def test_strip_comments_removes_line_and_block_forms(self):
        text = "let a = 1; // crate::facade\n/* crate::serve */ let b = 2;\n"
        stripped = MODULE.strip_comments(text)
        self.assertNotIn("crate::facade", stripped)
        self.assertNotIn("crate::serve", stripped)
        self.assertIn("let a = 1;", stripped)
        self.assertIn("let b = 2;", stripped)

class GovStackProtocolBoundaryTests(unittest.TestCase):
    """Fixed GovStack wire behavior stays in the facade host."""

    def tree(self, files: dict[str, str]) -> Path:
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        base = Path(root.name)
        engine = base / "crates/registry-adapter-engine/src"
        engine.mkdir(parents=True)
        for name, body in files.items():
            path = engine / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return base

    def test_generic_consultation_metadata_and_transform_code_pass(self):
        root = self.tree(
            {
                "load.rs": (
                    "let metadata = project.consultation.as_ref();\n"
                    "fn attach_project_transform() {}\n"
                    "struct ConsultationFacade;\n"
                ),
                "project_transform.rs": (
                    "fn compile_consultation_input_filters() {}\n"
                    "fn consultation_output_schema() {}\n"
                ),
            }
        )
        self.assertEqual(MODULE.govstack_protocol_violations(root), [])

    def test_a_consultation_protocol_module_in_the_engine_refuses(self):
        root = self.tree({"consultation.rs": "pub const PROFILE_ID: &str = \"fixed\";\n"})
        found = "\n".join(MODULE.govstack_protocol_violations(root))
        self.assertIn("protocol module path", found)
        self.assertIn("consultation.rs", found)

    def test_a_govstack_module_path_in_the_engine_refuses(self):
        root = self.tree({"govstack/consultation.rs": "pub struct Protocol;\n"})
        found = "\n".join(MODULE.govstack_protocol_violations(root))
        self.assertIn("protocol module path", found)
        self.assertIn("govstack/consultation.rs", found)

    def test_an_engine_reference_to_the_protocol_module_refuses(self):
        for body in (
            "use crate::consultation::ConsultationCapability;\n",
            "use crate::govstack::consultation;\n",
            "let path = super::super::consultation::CAPABILITIES_PATH;\n",
        ):
            with self.subTest(body=body):
                root = self.tree({"sub/mod.rs": body})
                self.assertTrue(
                    any(
                        "protocol module consultation" in failure
                        or "protocol module govstack" in failure
                        for failure in MODULE.govstack_protocol_violations(root)
                    )
                )

    def test_fixed_wire_types_and_urls_in_the_engine_refuse(self):
        for marker in (
            "ConsultationCapability",
            "CallerCapabilities",
            "CapabilityCollection",
            "CapabilityOperation",
            "CAPABILITIES_PATH",
            "/govstack/registries",
        ):
            with self.subTest(marker=marker):
                root = self.tree({"load.rs": f'let marker = "{marker}";\n'})
                found = "\n".join(MODULE.govstack_protocol_violations(root))
                self.assertIn("fixed GovStack wire marker", found)

    def test_comments_about_the_boundary_pass(self):
        root = self.tree(
            {
                "load.rs": (
                    "//! crate::consultation once owned ConsultationCapability.\n"
                    "// The host mounts /govstack/registries.\n"
                    "pub struct GenericPlan;\n"
                )
            }
        )
        self.assertEqual(MODULE.govstack_protocol_violations(root), [])


class JobHostGraphTests(unittest.TestCase):
    """registry-adapter-job is one of the engine crates."""

    def test_the_direct_breg_edge_is_accepted_only_through_the_job_host(self):
        self.assertEqual(MODULE.violations(metadata()), [])
        self.assertEqual(MODULE.job_feature_violations(metadata()), [])

    def test_the_connector_dependency_must_stay_optional(self):
        document = metadata()
        job = next(
            package
            for package in document["packages"]
            if package["name"] == "registry-adapter-job"
        )
        job["dependencies"][0]["optional"] = False
        self.assertIn("optional normal dependency", "\n".join(
            MODULE.job_feature_violations(document)
        ))

    def test_the_connector_dependency_must_not_take_default_features(self):
        document = metadata()
        job = next(
            package
            for package in document["packages"]
            if package["name"] == "registry-adapter-job"
        )
        job["dependencies"][0]["uses_default_features"] = True
        self.assertIn("default-features = false", "\n".join(
            MODULE.job_feature_violations(document)
        ))

    def test_a_default_off_feature_cannot_become_a_default_feature(self):
        for crate in ("registry-adapter-job", "registry-adapter-connectors"):
            for feature in ("direct-breg", "signed-coordinator-event", "coordinator-event"):
                document = metadata()
                package = next(
                    item for item in document["packages"] if item["name"] == crate
                )
                package["features"]["default"] = [feature]
                self.assertIn(
                    "default-off feature(s) by default",
                    "\n".join(MODULE.job_feature_violations(document)),
                    f"{crate} default [{feature}]",
                )

    def test_the_direct_breg_feature_cannot_gain_another_edge(self):
        document = metadata()
        job = next(
            package
            for package in document["packages"]
            if package["name"] == "registry-adapter-job"
        )
        job["features"]["direct-breg"].append("registry-breg-client")
        self.assertIn("must contain exactly", "\n".join(
            MODULE.job_feature_violations(document)
        ))

    def test_the_signed_event_path_is_platform_only_and_exact(self):
        document = metadata()
        self.assertEqual(MODULE.job_feature_violations(document), [])
        job = next(
            package
            for package in document["packages"]
            if package["name"] == "registry-adapter-job"
        )
        job["features"]["signed-coordinator-event"].append(
            "registry-coordinator-client"
        )
        self.assertIn(
            "signed-coordinator-event must contain exactly",
            "\n".join(MODULE.job_feature_violations(document)),
        )

    def test_the_connector_event_feature_cannot_gain_a_coordinator_package(self):
        document = metadata()
        connector = next(
            package
            for package in document["packages"]
            if package["name"] == "registry-adapter-connectors"
        )
        connector["features"]["coordinator-event"].append(
            "registry-coordinator"
        )
        self.assertIn(
            "coordinator-event must contain exactly",
            "\n".join(MODULE.job_feature_violations(document)),
        )

    def test_the_job_host_cannot_reach_another_product_client(self):
        found = failures(job=[*INTENDED["job"], "coordinator-client"])
        self.assertIn("registry-adapter-job reaches package(s)", found)
        self.assertIn("registry-coordinator-client", found)

    def test_the_job_host_cannot_link_the_breg_client_directly(self):
        found = failures(job=[*INTENDED["job"], "breg-client"])
        self.assertIn("registry-adapter-job reaches package(s)", found)
        self.assertIn("registry-breg-client", found)

    def test_the_job_nonconnector_subtrees_cannot_reach_the_breg_client(self):
        found = failures(platform=[*INTENDED["platform"], "breg-client"])
        self.assertIn("registry-adapter-job reaches package(s)", found)
        self.assertIn("registry-breg-client", found)

    def test_the_job_host_cannot_reach_the_facade_host(self):
        found = failures(job=[*INTENDED["job"], "engine"])
        self.assertIn("registry-adapter-job reaches package(s)", found)
        self.assertIn("registry-adapter", found)

    def test_the_job_host_reaching_the_engine_is_accepted(self):
        edges = {**INTENDED, "job": ["shared-engine", "core", "platform", "serde"]}
        names = {**NAMES, "job": "registry-adapter-job"}
        self.assertEqual(
            MODULE.violations(
                {
                    "packages": [
                        {"id": package_id, "name": name} for package_id, name in names.items()
                    ],
                    "resolve": {
                        "nodes": [
                            {"id": package_id, "deps": [dependency(e) for e in entries]}
                            for package_id, entries in edges.items()
                        ]
                    },
                }
            ),
            [],
        )

    def test_the_job_host_reaching_a_product_refuses(self):
        edges = {**INTENDED, "job": ["shared-engine", "core", "breg"]}
        names = {**NAMES, "job": "registry-adapter-job"}
        failures = MODULE.violations(
            {
                "packages": [
                    {"id": package_id, "name": name} for package_id, name in names.items()
                ],
                "resolve": {
                    "nodes": [
                        {"id": package_id, "deps": [dependency(e) for e in entries]}
                        for package_id, entries in edges.items()
                    ]
                },
            }
        )
        self.assertTrue(
            any("registry-adapter-job reaches package(s)" in item for item in failures)
        )


if __name__ == "__main__":
    unittest.main()
