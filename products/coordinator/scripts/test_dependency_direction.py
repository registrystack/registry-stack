#!/usr/bin/env python3
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_dependency_direction.py")
SPEC = importlib.util.spec_from_file_location("coordinator_dependency_direction", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

NAMES = {
    "runtime": "registry-coordinator",
    "client": "registry-coordinator-client",
    "client-node": "registry-coordinator-client-node",
    "client-py": "registry-coordinator-client-py",
    "stack-client": "registry-stack-client",
    "cli-docs": "registry-cli-docs",
    "breg": "registry-breg",
    "breg-client": "registry-breg-client",
    "bregctl": "registry-bregctl",
    "breg-mcp": "registry-breg-mcp",
    "casework-client": "registry-casework-client",
    "casework-core": "registry-casework-core",
    "review-client": "registry-review-client",
    "review-protocol": "registry-review-protocol",
    "messaging": "registry-messaging",
    "messaging-client": "registry-messaging-client",
    "messaging-client-node": "registry-messaging-client-node",
    "messaging-core": "registry-messaging-core",
    "scheduling": "registry-scheduling",
    "scheduling-client": "registry-scheduling-client",
    "scheduling-core": "registry-scheduling-core",
    "schedulingctl": "registry-schedulingctl",
    "evidence": "registry-evidence",
    "record": "registry-record",
    "platform": "registry-platform-httputil",
    "platform-testing": "registry-platform-testing",
    "serde": "serde",
}

INTENDED = {
    "runtime": [
        "breg-client",
        "casework-client",
        "messaging-client",
        "messaging-core",
        "scheduling-client",
        "scheduling-core",
        "platform",
        "serde",
        ("platform-testing", "dev"),
    ],
    "client": ["platform", "serde"],
    "client-node": ["client", "serde"],
    "client-py": ["client", "serde"],
    "stack-client": ["client", "breg-client", "messaging-client", "scheduling-client"],
    "cli-docs": ["runtime", "breg", "bregctl", "messaging", "scheduling", "schedulingctl"],
    "breg": ["record", "platform"],
    "breg-client": ["record", "platform"],
    "bregctl": ["breg"],
    "breg-mcp": ["breg-client", ("breg", "dev")],
    "casework-client": ["casework-core", "review-client", "platform"],
    "casework-core": ["serde"],
    "review-client": ["review-protocol", "platform"],
    "review-protocol": ["serde"],
    "messaging": ["messaging-core", "platform"],
    "messaging-client": ["messaging-core", "platform"],
    "messaging-client-node": ["messaging-client"],
    "messaging-core": ["serde"],
    "scheduling": ["scheduling-core", "platform"],
    "scheduling-client": ["scheduling-core", "platform"],
    "scheduling-core": ["serde"],
    "schedulingctl": ["scheduling"],
    "evidence": ["platform"],
    "record": ["serde"],
    "platform": ["serde"],
    "platform-testing": ["platform"],
    "serde": [],
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


class RuntimeTests(unittest.TestCase):
    def test_intended_direction_is_accepted(self):
        self.assertEqual(MODULE.violations(metadata()), [])

    def test_the_runtime_reaching_a_product_runtime_is_refused(self):
        for product in ("breg", "messaging", "scheduling", "evidence"):
            with self.subTest(product=product):
                self.assertIn(
                    f"registry-coordinator reaches package(s) outside product clients, "
                    f"product cores, registry-record and registry-platform-*: "
                    f"{NAMES[product]}",
                    failures(runtime=[*INTENDED["runtime"], product]),
                )

    def test_the_runtime_reaching_adopter_tooling_is_refused(self):
        found = failures(runtime=[*INTENDED["runtime"], "bregctl", "schedulingctl"])
        self.assertIn("registry-bregctl", found)
        self.assertIn("registry-schedulingctl", found)

    def test_the_runtime_reaching_a_supporting_service_or_binding_is_refused(self):
        found = failures(runtime=["breg-mcp", "messaging-client-node"])
        self.assertIn("registry-breg-mcp", found)
        self.assertIn("registry-messaging-client-node", found)

    def test_the_runtime_reaching_the_unified_facade_is_refused(self):
        self.assertIn(
            "registry-stack-client",
            failures(runtime=[*INTENDED["runtime"], "stack-client"]),
        )

    def test_a_product_runtime_behind_a_client_is_refused(self):
        found = failures(breg_client=["record", "platform", "breg"])
        self.assertIn("registry-coordinator reaches", found)
        self.assertIn("registry-breg", found)

    def test_a_dev_dependency_of_the_runtime_counts(self):
        self.assertIn(
            "registry-coordinator reaches package(s) outside product clients, "
            "product cores, registry-record and registry-platform-*: registry-messaging",
            failures(runtime=[*INTENDED["runtime"], ("messaging", "dev")]),
        )

    def test_a_dev_dependency_of_a_reached_client_is_not_followed(self):
        self.assertEqual(
            MODULE.violations(
                metadata(scheduling_client=["scheduling-core", "platform", ("scheduling", "dev")])
            ),
            [],
        )

    def test_a_build_dependency_is_followed(self):
        self.assertIn(
            "registry-evidence",
            failures(scheduling_client=["scheduling-core", "platform", ("evidence", "build")]),
        )

    def test_client_support_is_admitted_only_by_name(self):
        self.assertEqual(
            MODULE.CLIENT_SUPPORT.keys(),
            {"registry-review-protocol"},
        )
        self.assertEqual(MODULE.violations(metadata()), [])


class ClientTests(unittest.TestCase):
    def test_the_client_reaching_the_runtime_is_refused(self):
        refused = [
            failure
            for failure in MODULE.violations(metadata(client=["platform", "runtime"]))
            if failure.startswith("registry-coordinator-client reaches")
        ]
        self.assertEqual(len(refused), 1)
        self.assertIn("registry-coordinator,", refused[0])

    def test_a_binding_reaching_the_runtime_through_its_client_is_refused(self):
        found = failures(client=["platform", "runtime"])
        for binding in ("registry-coordinator-client-node", "registry-coordinator-client-py"):
            self.assertIn(f"{binding} reaches", found)

    def test_the_client_reaching_another_product_client_is_refused(self):
        self.assertIn(
            "registry-coordinator-client reaches package(s) other than the Coordinator "
            "client and registry-platform-*: registry-messaging-client, registry-messaging-core",
            failures(client=["platform", "messaging-client"]),
        )

    def test_an_unknown_coordinator_crate_needs_a_rule(self):
        names = {**NAMES, "coordinator-core": "registry-coordinator-core"}
        document = metadata()
        document["packages"] = [
            {"id": package_id, "name": name} for package_id, name in names.items()
        ]
        document["resolve"]["nodes"].append({"id": "coordinator-core", "deps": []})
        self.assertEqual(
            MODULE.violations(document),
            [
                "registry-coordinator-core is a Coordinator crate this gate does not know; "
                "name its rule here"
            ],
        )


class DependentTests(unittest.TestCase):
    def test_each_product_runtime_reaching_the_coordinator_is_refused(self):
        for product in ("breg", "messaging", "scheduling", "evidence"):
            with self.subTest(product=product):
                self.assertIn(
                    f"{NAMES[product]} depends on Coordinator package(s) it is not listed for: "
                    "registry-coordinator",
                    failures(**{product: [*INTENDED[product], "runtime"]}),
                )

    def test_a_product_client_reaching_the_coordinator_client_is_refused(self):
        self.assertIn(
            "registry-scheduling-client depends on Coordinator package(s) it is not listed "
            "for: registry-coordinator-client",
            failures(scheduling_client=["scheduling-core", "platform", "client"]),
        )

    def test_a_product_test_depending_on_the_coordinator_is_refused(self):
        self.assertIn(
            "registry-breg-mcp depends on Coordinator package(s) it is not listed for: "
            "registry-coordinator",
            failures(breg_mcp=["breg-client", ("runtime", "dev")]),
        )

    def test_reaching_the_coordinator_through_an_allowed_dependent_is_refused(self):
        found = failures(evidence=["platform", "stack-client"], bregctl=["breg", "cli-docs"])
        self.assertIn(
            "registry-evidence depends on Coordinator package(s) it is not listed for: "
            "registry-coordinator-client",
            found,
        )
        self.assertIn(
            "registry-bregctl depends on Coordinator package(s) it is not listed for: "
            "registry-coordinator",
            found,
        )

    def test_the_facade_reaching_the_runtime_is_refused(self):
        self.assertIn(
            "registry-stack-client depends on Coordinator package(s) it is not listed for: "
            "registry-coordinator",
            failures(stack_client=["client", "runtime"]),
        )

    def test_the_allowed_dependents_are_exactly_the_facade_and_the_cli_reference(self):
        self.assertEqual(
            MODULE.ALLOWED_DEPENDENTS,
            {
                "registry-cli-docs": frozenset({"registry-coordinator"}),
                "registry-stack-client": frozenset({"registry-coordinator-client"}),
            },
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
        completed = self.run_gate(metadata(client=["platform", "runtime"]))
        self.assertEqual(completed.returncode, 1)
        self.assertIn("dependency-direction violation: registry-coordinator-client", completed.stderr)

    def test_a_graph_without_a_resolve_exits_two(self):
        completed = self.run_gate({"packages": []})
        self.assertEqual(completed.returncode, 2)
        self.assertIn("did not include a resolved dependency graph", completed.stderr)


if __name__ == "__main__":
    unittest.main()
