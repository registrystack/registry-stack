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
        "runtime": "registry-scheduling",
        "ctl": "registry-schedulingctl",
        "breg-client": "registry-breg-client",
        "casework-core": "registry-casework-core",
        "evidence-client": "registry-evidence-client",
        "messaging-client": "registry-messaging-client",
        "coordinator": "registry-coordinator",
        "coordinator-client": "registry-coordinator-client",
        "documents-core": "registry-documents-core",
        "discovery": "registry-discovery",
        "discovery-client": "registry-discovery-client",
        "discovery-profile": "registry-discovery-profile",
        "render": "registry-render",
        "review-protocol": "registry-review-protocol",
        "review-client": "registry-review-client",
        "thunderid": "registry-thunderid-tooling",
        "manifest-core": "registry-manifest-core",
        "cli-docs": "registry-cli-docs",
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

    def test_a_document_store_dependency_is_rejected_both_ways(self):
        edges = {
            "core": ["serde"],
            "client": ["documents-core"],
            "runtime": ["core"],
            "ctl": ["core"],
            "documents-core": [],
            "platform": [],
            "serde": [],
        }
        failures = "\n".join(MODULE.violations(metadata(edges)))
        self.assertIn(
            "registry-scheduling-client transitively depends on other-product package(s): registry-documents-core",
            failures,
        )
        edges = {**edges, "client": ["core"], "documents-core": ["client"]}
        failures = "\n".join(MODULE.violations(metadata(edges)))
        self.assertIn(
            "registry-documents-core transitively depends on Scheduling package(s): registry-scheduling-client, registry-scheduling-core",
            failures,
        )

    def test_messaging_dependency_from_core_is_rejected(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["core"],
                "runtime": ["core"],
                "ctl": ["core"],
                "breg-client": [],
                "casework-core": [],
                "evidence-client": [],
                "messaging-client": [],
                "platform": [],
                "serde": ["messaging-client"],
            }
        )
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn(
            "registry-scheduling-core transitively depends on other-product package(s): registry-messaging-client",
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


    def test_messaging_dependency_on_scheduling_is_rejected(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["core"],
                "runtime": ["core"],
                "ctl": ["core"],
                "breg-client": [],
                "casework-core": [],
                "evidence-client": [],
                "messaging-client": ["client"],
                "platform": [],
                "serde": [],
            }
        )
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn(
            "registry-messaging-client transitively depends on Scheduling package(s): registry-scheduling-client",
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

    def test_a_scheduling_crate_reaching_the_coordinator_is_rejected(self):
        for crate, name in (
            ("core", "registry-scheduling-core"),
            ("client", "registry-scheduling-client"),
            ("client-node", "registry-scheduling-client-node"),
            ("client-py", "registry-scheduling-client-py"),
            ("runtime", "registry-scheduling"),
            ("ctl", "registry-schedulingctl"),
        ):
            for coordinator in ("coordinator", "coordinator-client"):
                with self.subTest(crate=crate, coordinator=coordinator):
                    edges = {
                        "core": ["serde"],
                        "client": ["core"],
                        "client-node": ["client"],
                        "client-py": ["client"],
                        "runtime": ["core"],
                        "ctl": ["core"],
                        "coordinator": [],
                        "coordinator-client": [],
                        "serde": [],
                    }
                    edges[crate] = [*edges[crate], coordinator]
                    failures = "\n".join(MODULE.violations(metadata(edges)))
                    self.assertIn(
                        f"{name} transitively depends on other-product package(s): "
                        f"registry-{coordinator}",
                        failures,
                    )

    def test_the_coordinator_may_use_the_scheduling_client_and_core(self):
        graph = metadata(
            {
                "core": ["serde"],
                "client": ["core"],
                "runtime": ["core"],
                "ctl": ["runtime", "core"],
                "coordinator": ["client", "core", "breg-client"],
                "coordinator-client": ["platform"],
                "breg-client": [],
                "platform": [],
                "serde": [],
            }
        )
        self.assertEqual(MODULE.violations(graph), [])

    def test_the_coordinator_reaching_the_scheduling_runtime_is_rejected(self):
        for coordinator, name in (
            ("coordinator", "registry-coordinator"),
            ("coordinator-client", "registry-coordinator-client"),
        ):
            for runtime, reached in (
                ("runtime", "registry-scheduling"),
                ("ctl", "registry-scheduling, registry-schedulingctl"),
            ):
                with self.subTest(coordinator=coordinator, runtime=runtime):
                    graph = metadata(
                        {
                            "core": ["serde"],
                            "client": ["core"],
                            "runtime": ["core"],
                            "ctl": ["runtime", "core"],
                            coordinator: ["client", runtime],
                            "serde": [],
                        }
                    )
                    failures = "\n".join(MODULE.violations(graph))
                    self.assertIn(
                        f"{name} transitively depends on Scheduling runtime package(s): {reached}",
                        failures,
                    )

    def test_discovery_and_render_boundaries_are_checked_in_both_directions(self):
        for product in ("discovery", "discovery-client", "discovery-profile", "render"):
            with self.subTest(product=product):
                edges = {"runtime": ["platform"], "platform": [product]}
                failures = "\n".join(MODULE.violations(metadata(edges)))
                self.assertIn("registry-scheduling transitively depends on other-product", failures)
                edges = {product: ["platform"], "platform": ["runtime"]}
                failures = "\n".join(MODULE.violations(metadata(edges)))
                self.assertIn(f"registry-{product} transitively depends on Scheduling", failures)

    def test_shared_protocols_and_tooling_do_not_become_runtime_products(self):
        edges = {
            "runtime": ["core", "review-protocol"],
            "core": ["platform"],
            "client": ["core", "review-client"],
            "review-client": ["review-protocol"],
            "review-protocol": ["platform"],
            "ctl": ["runtime", "thunderid", "manifest-core"],
            "cli-docs": ["runtime", "ctl"],
        }
        self.assertEqual(MODULE.violations(metadata(edges)), [])

    def test_a_dependency_test_tool_does_not_become_a_product_dependency(self):
        edges = {"runtime": ["platform"], "core": ["platform"], "platform": ["discovery"]}
        graph = metadata(edges)
        node = next(n for n in graph["resolve"]["nodes"] if n["id"] == "platform")
        node["deps"][0]["dep_kinds"] = [{"kind": "dev", "target": None}]
        self.assertEqual(MODULE.violations(graph), [])
        # The same edge in a supported build is still part of the boundary.
        node["deps"][0]["dep_kinds"].append({"kind": "build", "target": None})
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn("registry-scheduling transitively depends on other-product", failures)

    def test_the_products_own_dev_dependencies_still_count(self):
        edges = {"runtime": ["discovery"]}
        graph = metadata(edges)
        node = next(n for n in graph["resolve"]["nodes"] if n["id"] == "runtime")
        node["deps"][0]["dep_kinds"] = [{"kind": "dev", "target": None}]
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn("registry-scheduling transitively depends on other-product", failures)

    def test_test_tooling_may_use_the_public_client(self):
        edges = {"thunderid": ["client"], "client": ["core"], "core": ["platform"]}
        self.assertEqual(MODULE.violations(metadata(edges)), [])


if __name__ == "__main__":
    unittest.main()
