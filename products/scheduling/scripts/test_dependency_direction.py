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
        "client-node": "registry-scheduling-client-node",
        "client-py": "registry-scheduling-client-py",
        "stack-client": "registry-stack-client",
        "coordinator": "registry-coordinator",
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


    def test_bindings_and_the_unified_client_beside_other_products_are_accepted(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["core"],
                "client-node": ["client", "serde"],
                "client-py": ["client", "serde"],
                "stack-client": ["client", "breg-client", "evidence-client"],
                "runtime": ["core"],
                "ctl": ["runtime", "core"],
                "breg-client": [],
                "casework-core": [],
                "evidence-client": [],
                "platform": [],
                "serde": [],
            }
        )
        self.assertEqual(MODULE.violations(graph), [])

    def test_a_binding_reaching_the_runtime_or_tooling_is_rejected(self):
        # The tooling itself depends on the runtime, so reaching it reaches both.
        for binding, name in (
            ("client-node", "registry-scheduling-client-node"),
            ("client-py", "registry-scheduling-client-py"),
        ):
            for runtime, reached in (
                ("runtime", "registry-scheduling"),
                ("ctl", "registry-scheduling, registry-schedulingctl"),
            ):
                with self.subTest(binding=binding, runtime=runtime):
                    graph = metadata(
                        {
                            "core": ["serde"],
                            "client": ["core"],
                            binding: ["client", runtime],
                            "runtime": ["core"],
                            "ctl": ["runtime", "core"],
                            "serde": [],
                        }
                    )
                    failures = "\n".join(MODULE.violations(graph))
                    self.assertIn(
                        f"{name} transitively depends on runtime crate(s): {reached}",
                        failures,
                    )

    def test_a_binding_reaching_another_product_is_rejected(self):
        for binding, name in (
            ("client-node", "registry-scheduling-client-node"),
            ("client-py", "registry-scheduling-client-py"),
        ):
            with self.subTest(binding=binding):
                graph = metadata(
                    {
                        "core": ["serde"],
                        "client": ["core"],
                        binding: ["client", "casework-core"],
                        "casework-core": [],
                        "serde": [],
                    }
                )
                failures = "\n".join(MODULE.violations(graph))
                self.assertIn(
                    f"{name} transitively depends on other-product package(s): "
                    "registry-casework-core",
                    failures,
                )

    def test_the_unified_client_reaching_the_scheduling_runtime_is_rejected(self):
        for runtime, reached in (
            ("runtime", "registry-scheduling"),
            ("ctl", "registry-scheduling, registry-schedulingctl"),
        ):
            with self.subTest(runtime=runtime):
                graph = metadata(
                    {
                        "core": ["serde"],
                        "client": ["core"],
                        "stack-client": ["client", "breg-client", runtime],
                        "runtime": ["core"],
                        "ctl": ["runtime", "core"],
                        "breg-client": [],
                        "serde": [],
                    }
                )
                failures = "\n".join(MODULE.violations(graph))
                self.assertIn(
                    "registry-stack-client transitively depends on Scheduling runtime "
                    f"package(s): {reached}",
                    failures,
                )

    def test_the_coordinator_beside_the_client_and_core_is_accepted(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["core"],
                "coordinator": ["client", "core", "breg-client", "casework-core"],
                "runtime": ["core"],
                "ctl": ["runtime", "core"],
                "breg-client": [],
                "casework-core": [],
                "serde": [],
            }
        )
        self.assertEqual(MODULE.violations(graph), [])

    def test_the_coordinator_reaching_the_scheduling_runtime_is_rejected(self):
        for runtime, reached in (
            ("runtime", "registry-scheduling"),
            ("ctl", "registry-scheduling, registry-schedulingctl"),
        ):
            with self.subTest(runtime=runtime):
                graph = metadata(
                    {
                        "core": ["serde"],
                        "client": ["core"],
                        "coordinator": ["client", runtime],
                        "runtime": ["core"],
                        "ctl": ["runtime", "core"],
                        "serde": [],
                    }
                )
                failures = "\n".join(MODULE.violations(graph))
                self.assertIn(
                    "registry-coordinator transitively depends on Scheduling runtime "
                    f"package(s): {reached}",
                    failures,
                )

    def test_a_scheduling_crate_reaching_the_coordinator_is_rejected(self):
        for crate, name in (
            ("core", "registry-scheduling-core"),
            ("client", "registry-scheduling-client"),
            ("runtime", "registry-scheduling"),
            ("ctl", "registry-schedulingctl"),
        ):
            with self.subTest(crate=crate):
                edges = {
                    "core": ["serde"],
                    "client": ["serde"],
                    "runtime": ["serde"],
                    "ctl": ["serde"],
                    "coordinator": [],
                    "serde": [],
                }
                edges[crate] = ["coordinator"]
                failures = "\n".join(MODULE.violations(metadata(edges)))
                self.assertIn(
                    f"{name} transitively depends on other-product package(s): "
                    "registry-coordinator",
                    failures,
                )


if __name__ == "__main__":
    unittest.main()
