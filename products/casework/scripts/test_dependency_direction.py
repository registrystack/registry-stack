#!/usr/bin/env python3
import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("check_dependency_direction.py")
SPEC = importlib.util.spec_from_file_location("casework_dependency_direction", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def metadata(edges: dict[str, list[str]]) -> dict:
    names = {
        "core": "registry-casework-core",
        "client": "registry-casework-client",
        "review-protocol": "registry-review-protocol",
        "review-client": "registry-review-client",
        "adapter": "registry-casework-breg",
        "breg": "registry-breg",
        "breg-client": "registry-breg-client",
        "serde": "serde",
    }
    return {
        "packages": [{"id": package_id, "name": name} for package_id, name in names.items()],
        "resolve": {
            "nodes": [
                {
                    "id": package_id,
                    "deps": [{"pkg": dependency, "name": names[dependency]} for dependency in dependencies],
                }
                for package_id, dependencies in edges.items()
            ]
        },
    }


class DependencyDirectionTests(unittest.TestCase):
    def test_intended_adapter_direction_is_accepted(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["core"],
                "review-protocol": ["serde"],
                "review-client": ["review-protocol"],
                "adapter": ["core", "breg-client"],
                "breg": ["serde"],
                "breg-client": ["serde"],
                "serde": [],
            }
        )
        self.assertEqual(MODULE.violations(graph), [])

    def test_transitive_breg_dependency_from_generic_client_is_rejected(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["serde"],
                "review-protocol": ["serde"],
                "review-client": ["review-protocol"],
                "adapter": ["core", "breg-client"],
                "breg": [],
                "breg-client": [],
                "serde": ["breg-client"],
            }
        )
        self.assertIn("registry-casework-client transitively depends", "\n".join(MODULE.violations(graph)))

    def test_transitive_breg_dependency_from_core_is_rejected(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["core"],
                "review-protocol": ["serde"],
                "review-client": ["review-protocol"],
                "adapter": ["core", "breg-client"],
                "breg": [],
                "breg-client": [],
                "serde": ["breg-client"],
            }
        )
        self.assertIn("registry-casework-core transitively depends", "\n".join(MODULE.violations(graph)))

    def test_breg_dependency_on_casework_is_rejected(self):
        graph = metadata(
            {
                "core": [],
                "client": ["core"],
                "review-protocol": [],
                "review-client": ["review-protocol"],
                "adapter": ["core", "breg-client"],
                "breg": ["serde"],
                "breg-client": [],
                "serde": ["core"],
            }
        )
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn("registry-breg transitively depends on Casework", failures)

    def test_product_neutral_review_protocol_may_be_used_by_breg(self):
        graph = metadata(
            {
                "core": ["review-protocol"],
                "client": ["core", "review-client"],
                "review-protocol": ["serde"],
                "review-client": ["review-protocol"],
                "adapter": ["core", "breg-client"],
                "breg": ["review-client"],
                "breg-client": ["serde"],
                "serde": [],
            }
        )
        self.assertEqual(MODULE.violations(graph), [])

    def test_review_protocol_dependency_on_casework_is_rejected(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["core"],
                "review-protocol": ["serde"],
                "review-client": ["review-protocol"],
                "adapter": ["core", "breg-client"],
                "breg": [],
                "breg-client": [],
                "serde": ["core"],
            }
        )
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn("registry-review-protocol transitively depends on Casework", failures)
        self.assertIn("registry-review-client transitively depends on Casework", failures)

    def test_cargo_metadata_resolves_every_feature(self):
        # An edge behind an optional feature is absent from the default graph,
        # so the gate must resolve the graph with every feature enabled.
        empty = '{"packages": [], "resolve": {"nodes": []}}'
        with mock.patch.object(
            MODULE.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, stdout=empty, stderr=""),
        ) as run:
            MODULE.load_metadata(Path("/repository"), None)

        command = run.call_args.args[0]
        self.assertEqual(["cargo", "metadata"], command[:2])
        self.assertIn("--locked", command)
        self.assertIn("--all-features", command)


if __name__ == "__main__":
    unittest.main()
