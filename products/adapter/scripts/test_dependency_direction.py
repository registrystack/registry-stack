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
    "core": "registry-adapter-core",
    "ctl": "registry-adapterctl",
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
}

INTENDED = {
    "engine": ["core", "platform", "platform-script", "serde", ("platform-testing", "dev")],
    "core": ["platform", "serde"],
    "ctl": ["core", ("engine", "dev")],
    # Every product client the connector may reach is optional and
    # feature-gated; the closure check reads them with all features on,
    # so the fixture lists them as normal edges.
    "connectors": [
        "core",
        "breg-client",
        "scheduling-client",
        "documents-client",
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
    "cli-docs": ["engine", "ctl"],
    "evidence": ["platform"],
    "casework": ["platform"],
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
    return {
        "packages": [{"id": package_id, "name": name} for package_id, name in NAMES.items()],
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
    def test_intended_direction_is_accepted(self):
        self.assertEqual(MODULE.violations(metadata()), [])

    def test_an_engine_crate_reaching_a_product_runtime_is_refused(self):
        for engine in ("engine", "core", "ctl"):
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
        for engine in ("engine", "core", "ctl"):
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
                metadata(platform=["serde", ("evidence", "dev")])
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
        for crate in ("engine", "core", "ctl", "connectors"):
            with self.subTest(crate=crate):
                found = failures(**{crate: [*INTENDED[crate], "stack-client"]})
                self.assertIn("registry-stack-client", found)


class ConnectorTests(unittest.TestCase):
    def test_the_connector_reaches_exactly_the_product_clients(self):
        self.assertEqual(
            MODULE.CONNECTOR_CLIENTS,
            {
                "registry-breg-client",
                "registry-scheduling-client",
                "registry-documents-client",
            },
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

    def test_cli_docs_carries_only_the_engine_command_trees(self):
        self.assertEqual(
            MODULE.ALLOWED_DEPENDENTS,
            {"registry-cli-docs": frozenset(
                {"registry-adapter", "registry-adapter-core", "registry-adapterctl"}
            )},
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


if __name__ == "__main__":
    unittest.main()
