#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_dependency_direction.py")
SPEC = importlib.util.spec_from_file_location("scheduling_dependency_direction", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def metadata(edges: dict[str, list[str]]) -> dict:
    names = {
        "core": "registry-scheduling-core",
        "client": "registry-scheduling-client",
        "runtime": "registry-scheduling",
        "ctl": "registry-schedulingctl",
        "breg-client": "registry-breg-client",
        "casework-core": "registry-casework-core",
        "evidence-client": "registry-evidence-client",
        "platform": "registry-platform-calendar",
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
    def test_intended_direction_is_accepted(self):
        graph = metadata(
            {
                "core": ["platform", "serde"],
                "client": ["core", "serde"],
                "runtime": ["core"],
                "ctl": ["core"],
                "breg-client": [],
                "casework-core": [],
                "evidence-client": [],
                "platform": ["serde"],
                "serde": [],
            }
        )
        self.assertEqual(MODULE.violations(graph), [])

    def test_transitive_product_dependency_from_core_is_rejected(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["core"],
                "runtime": ["core"],
                "ctl": ["core"],
                "breg-client": [],
                "casework-core": [],
                "evidence-client": [],
                "platform": [],
                "serde": ["breg-client"],
            }
        )
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn("registry-scheduling-core transitively depends on other-product", failures)
        self.assertIn("registry-scheduling-client transitively depends on other-product", failures)
        self.assertIn("registry-scheduling transitively depends on other-product", failures)
        self.assertIn("registry-schedulingctl transitively depends on other-product", failures)

    def test_evidence_dependency_from_client_is_rejected(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["evidence-client"],
                "runtime": ["core"],
                "ctl": ["core"],
                "breg-client": [],
                "casework-core": [],
                "evidence-client": [],
                "platform": [],
                "serde": [],
            }
        )
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn(
            "registry-scheduling-client transitively depends on other-product package(s): registry-evidence-client",
            failures,
        )

    def test_core_depending_on_the_runtime_is_rejected(self):
        graph = metadata(
            {
                "core": ["runtime"],
                "client": ["core"],
                "runtime": ["core"],
                "ctl": ["core"],
                "breg-client": [],
                "casework-core": [],
                "evidence-client": [],
                "platform": [],
                "serde": [],
            }
        )
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn(
            "registry-scheduling-core transitively depends on scheduling crate(s): registry-scheduling",
            failures,
        )

    def test_client_depending_on_the_runtime_is_rejected(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["runtime"],
                "runtime": ["core"],
                "ctl": ["core"],
                "breg-client": [],
                "casework-core": [],
                "evidence-client": [],
                "platform": [],
                "serde": [],
            }
        )
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn(
            "registry-scheduling-client transitively depends on runtime crate(s): registry-scheduling",
            failures,
        )

    def test_product_dependency_on_scheduling_is_rejected(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["core"],
                "runtime": ["core"],
                "ctl": ["core"],
                "breg-client": ["client"],
                "casework-core": [],
                "evidence-client": [],
                "platform": [],
                "serde": [],
            }
        )
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn(
            "registry-breg-client transitively depends on Scheduling package(s): registry-scheduling-client",
            failures,
        )


if __name__ == "__main__":
    unittest.main()
