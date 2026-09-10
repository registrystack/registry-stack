#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_dependency_direction.py")
SPEC = importlib.util.spec_from_file_location("casework_dependency_direction", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def metadata(edges: dict[str, list[str]]) -> dict:
    names = {
        "core": "registry-casework-core",
        "client": "registry-casework-client",
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
                "adapter": ["core", "breg-client"],
                "breg": ["serde"],
                "breg-client": [],
                "serde": ["core"],
            }
        )
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn("registry-breg transitively depends on Casework", failures)


if __name__ == "__main__":
    unittest.main()
