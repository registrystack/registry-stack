#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("check_dependency_direction.py")
SPEC = importlib.util.spec_from_file_location("coordinator_dependency_direction", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

NAMES = {
    "coordinator": "registry-coordinator",
    "coordinator-extra": "registry-coordinator-extra",
    "breg-client": "registry-breg-client",
    "casework-client": "registry-casework-client",
    "messaging-client": "registry-messaging-client",
    "messaging-core": "registry-messaging-core",
    "scheduling-client": "registry-scheduling-client",
    "scheduling-core": "registry-scheduling-core",
    "record": "registry-record",
    "casework-core": "registry-casework-core",
    "review-client": "registry-review-client",
    "review-protocol": "registry-review-protocol",
    "platform-oidc": "registry-platform-oidc",
    "platform-yaml": "registry-platform-yaml",
    "cli-docs": "registry-cli-docs",
    "breg": "registry-breg",
    "bregctl": "registry-bregctl",
    "casework": "registry-casework",
    "caseworkctl": "registry-caseworkctl",
    "casework-breg": "registry-casework-breg",
    "messaging": "registry-messaging",
    "messagingctl": "registry-messagingctl",
    "scheduling": "registry-scheduling",
    "schedulingctl": "registry-schedulingctl",
    "evidence": "registry-evidence",
    "evidence-client": "registry-evidence-client",
    "discovery-client": "registry-discovery-client",
    "manifest-core": "registry-manifest-core",
    "stack-client": "registry-stack-client",
    "serde": "serde",
}

# The graph the workspace resolves to, reduced to one crate of each kind.
INTENDED = {
    "coordinator": [
        "breg-client",
        "casework-client",
        "messaging-client",
        "messaging-core",
        "scheduling-client",
        "scheduling-core",
        "platform-oidc",
        "platform-yaml",
        "serde",
    ],
    "breg-client": ["record", "platform-oidc", "serde"],
    "casework-client": ["casework-core", "review-client", "serde"],
    "casework-core": ["review-protocol", "platform-yaml"],
    "review-client": ["review-protocol"],
    "review-protocol": ["serde"],
    "messaging-client": ["messaging-core"],
    "messaging-core": ["platform-yaml"],
    "scheduling-client": ["scheduling-core"],
    "scheduling-core": ["platform-yaml"],
    "record": ["serde"],
    "platform-oidc": ["platform-yaml", "serde"],
    "platform-yaml": ["serde"],
    "cli-docs": ["coordinator", "serde"],
    "serde": [],
}


def metadata(edges: dict[str, list[str]]) -> dict:
    return {
        "packages": [{"id": package_id, "name": name} for package_id, name in NAMES.items()],
        "resolve": {
            "nodes": [
                {
                    "id": package_id,
                    "deps": [
                        {"pkg": dependency, "name": NAMES[dependency]}
                        for dependency in dependencies
                    ],
                }
                for package_id, dependencies in edges.items()
            ]
        },
    }


def intended(**changes: list[str]) -> dict:
    return metadata({**INTENDED, **{key.replace("_", "-"): value for key, value in changes.items()}})


def run_main(graph: dict) -> tuple[int, str, str]:
    with tempfile.TemporaryDirectory() as directory:
        fixture = Path(directory) / "metadata.json"
        fixture.write_text(json.dumps(graph), encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(sys, "argv", [str(SCRIPT), "--metadata", str(fixture)]),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = MODULE.main()
    return status, stdout.getvalue(), stderr.getvalue()


class DependencyDirectionTests(unittest.TestCase):
    def test_the_intended_graph_is_accepted(self):
        self.assertEqual(MODULE.violations(intended()), [])

    def test_every_listed_product_client_crate_may_be_named_directly(self):
        self.assertEqual(
            sorted(MODULE.PRODUCT_CLIENT_CRATES),
            [
                "registry-breg-client",
                "registry-casework-client",
                "registry-messaging-client",
                "registry-messaging-core",
                "registry-scheduling-client",
                "registry-scheduling-core",
            ],
        )
        for crate in ("breg-client", "casework-client", "messaging-client", "scheduling-core"):
            with self.subTest(crate=crate):
                graph = metadata({"coordinator": [crate], crate: []})
                self.assertEqual(MODULE.violations(graph), [])

    def test_a_forbidden_direct_dependency_is_refused(self):
        for crate in (
            "breg",
            "bregctl",
            "casework",
            "caseworkctl",
            "casework-breg",
            "messaging",
            "messagingctl",
            "scheduling",
            "schedulingctl",
            "evidence",
            "evidence-client",
            "discovery-client",
            "manifest-core",
            "stack-client",
            "cli-docs",
        ):
            with self.subTest(crate=crate):
                edges = {**INTENDED, "cli-docs": ["serde"], crate: ["serde"]}
                edges["coordinator"] = [*INTENDED["coordinator"], crate]
                self.assertEqual(
                    MODULE.violations(metadata(edges)),
                    [
                        "registry-coordinator transitively depends on registry crate(s) "
                        f"outside the Coordinator boundary: {NAMES[crate]}"
                    ],
                )

    def test_a_forbidden_dependency_is_refused_anywhere_in_the_forward_closure(self):
        # Through a product client, through a platform crate, and through a
        # crate from outside the workspace.
        for carrier in ("breg-client", "platform-yaml", "serde"):
            with self.subTest(carrier=carrier):
                edges = {**INTENDED, "breg": ["serde"] if carrier != "serde" else []}
                edges[carrier] = [*INTENDED[carrier], "breg"]
                failures = MODULE.violations(metadata(edges))
                self.assertIn(
                    "registry-coordinator transitively depends on registry crate(s) "
                    "outside the Coordinator boundary: registry-breg",
                    failures,
                )

    def test_every_forbidden_crate_reached_is_named_once_in_order(self):
        graph = intended(
            coordinator=[*INTENDED["coordinator"], "scheduling"],
            breg_client=[*INTENDED["breg-client"], "breg"],
            breg=["evidence-client"],
            scheduling=["scheduling-core", "breg"],
            evidence_client=[],
        )
        self.assertEqual(
            MODULE.violations(graph),
            [
                "registry-coordinator transitively depends on registry crate(s) outside the "
                "Coordinator boundary: registry-breg, registry-evidence-client, registry-scheduling"
            ],
        )

    def test_a_crate_a_client_carries_may_not_be_named_directly(self):
        for crate in ("record", "casework-core", "review-client", "review-protocol"):
            with self.subTest(crate=crate):
                graph = intended(coordinator=[*INTENDED["coordinator"], crate])
                self.assertEqual(
                    MODULE.violations(graph),
                    [
                        "registry-coordinator depends directly on crate(s) it may reach only "
                        f"through a product client: {NAMES[crate]}"
                    ],
                )

    def test_every_coordinator_crate_is_held_to_the_boundary(self):
        graph = intended(coordinator_extra=["coordinator", "casework"], casework=["casework-core"])
        self.assertEqual(
            MODULE.violations(graph),
            [
                "registry-coordinator-extra transitively depends on registry crate(s) outside "
                "the Coordinator boundary: registry-casework"
            ],
        )
        self.assertEqual(
            MODULE.violations(intended(coordinator_extra=["coordinator", "platform-oidc"])), []
        )

    def test_a_registry_crate_reaching_the_coordinator_is_refused(self):
        for crate in (
            "breg-client",
            "messaging-core",
            "scheduling-client",
            "platform-yaml",
            "stack-client",
            "breg",
        ):
            with self.subTest(crate=crate):
                edges = dict(INTENDED)
                edges[crate] = [*INTENDED.get(crate, []), "coordinator"]
                failures = MODULE.violations(metadata(edges))
                self.assertIn(
                    f"{NAMES[crate]} transitively depends on Coordinator package(s): "
                    "registry-coordinator",
                    failures,
                )

    def test_only_the_command_reference_generator_may_reach_the_coordinator(self):
        self.assertEqual(sorted(MODULE.ALLOWED_DEPENDENTS), ["registry-cli-docs"])
        graph = intended(stack_client=["cli-docs"])
        self.assertEqual(
            MODULE.violations(graph),
            ["registry-stack-client transitively depends on Coordinator package(s): registry-coordinator"],
        )

    def test_a_graph_without_a_coordinator_crate_is_not_a_pass(self):
        edges = {key: value for key, value in INTENDED.items() if key not in ("coordinator", "cli-docs")}
        graph = metadata(edges)
        graph["packages"] = [
            package for package in graph["packages"] if not package["name"].startswith("registry-coordinator")
        ]
        with self.assertRaises(ValueError):
            MODULE.violations(graph)
        status, stdout, stderr = run_main(graph)
        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertIn("no Coordinator crate", stderr)

    def test_a_graph_without_resolved_dependencies_is_not_a_pass(self):
        graph = intended()
        graph["resolve"] = None
        status, stdout, stderr = run_main(graph)
        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertIn("could not inspect Cargo metadata", stderr)

    def test_the_command_exits_zero_for_the_intended_graph(self):
        status, stdout, stderr = run_main(intended())
        self.assertEqual(status, 0)
        self.assertEqual(stdout, "Coordinator dependency direction holds.\n")
        self.assertEqual(stderr, "")

    def test_the_command_exits_one_and_names_a_forbidden_dependency(self):
        status, stdout, stderr = run_main(
            intended(coordinator=[*INTENDED["coordinator"], "messaging"], messaging=["messaging-core"])
        )
        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(
            stderr,
            "dependency-direction violation: registry-coordinator transitively depends on "
            "registry crate(s) outside the Coordinator boundary: registry-messaging\n",
        )


if __name__ == "__main__":
    unittest.main()
