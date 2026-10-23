#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_dependency_direction.py")
SPEC = importlib.util.spec_from_file_location("messaging_dependency_direction", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

NAMES = {
    "core": "registry-messaging-core",
    "client": "registry-messaging-client",
    "client-node": "registry-messaging-client-node",
    "client-py": "registry-messaging-client-py",
    "stack-client": "registry-stack-client",
    "runtime": "registry-messaging",
    "ctl": "registry-messagingctl",
    "breg": "registry-breg",
    "coordinator": "registry-coordinator",
    "coordinator-client": "registry-coordinator-client",
    "documents-core": "registry-documents-core",
    "casework-core": "registry-casework-core",
    "scheduling-core": "registry-scheduling-core",
    "evidence-client": "registry-evidence-client",
    "cli-docs": "registry-cli-docs",
    "discovery": "registry-discovery",
    "discovery-client": "registry-discovery-client",
    "discovery-profile": "registry-discovery-profile",
    "render": "registry-render",
    "review-protocol": "registry-review-protocol",
    "review-client": "registry-review-client",
    "thunderid": "registry-thunderid-tooling",
    "manifest-core": "registry-manifest-core",
    "platform": "registry-platform-httpsec",
    "serde": "serde",
}

INTENDED = {
    "core": ["platform", "serde"],
    "client": ["core", "platform"],
    "client-node": ["client", "serde"],
    "client-py": ["client", "serde"],
    "stack-client": ["client", "evidence-client"],
    "runtime": ["core", "platform"],
    "ctl": ["runtime", "core"],
    "breg": [],
    "coordinator": [],
    "coordinator-client": [],
    "documents-core": [],
    "casework-core": [],
    "scheduling-core": [],
    "evidence-client": [],
    "cli-docs": ["runtime", "ctl", "breg"],
    "platform": ["serde"],
    "serde": [],
}


def metadata(**changes: list[str]) -> dict:
    edges = {**INTENDED, **changes}
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


class DependencyDirectionTests(unittest.TestCase):
    def test_intended_direction_is_accepted(self):
        self.assertEqual(MODULE.violations(metadata()), [])

    def test_a_transitive_product_dependency_reaches_every_messaging_crate(self):
        failures = "\n".join(MODULE.violations(metadata(serde=["breg"])))
        for crate in (
            "registry-messaging-core",
            "registry-messaging-client",
            "registry-messaging-client-node",
            "registry-messaging-client-py",
            "registry-messaging",
            "registry-messagingctl",
        ):
            self.assertIn(f"{crate} transitively depends on other-product", failures)

    def test_each_named_product_is_refused(self):
        for product in (
            "breg",
            "casework-core",
            "coordinator",
            "documents-core",
            "scheduling-core",
            "evidence-client",
        ):
            with self.subTest(product=product):
                failures = "\n".join(MODULE.violations(metadata(client=["core", product])))
                self.assertIn(
                    "registry-messaging-client transitively depends on other-product "
                    f"package(s): {NAMES[product]}",
                    failures,
                )

    def test_core_depending_on_another_messaging_crate_is_rejected(self):
        failures = "\n".join(MODULE.violations(metadata(core=["client"])))
        self.assertIn(
            "registry-messaging-core transitively depends on Messaging crate(s): "
            "registry-messaging-client",
            failures,
        )

    def test_client_depending_on_the_runtime_is_rejected(self):
        failures = "\n".join(MODULE.violations(metadata(client=["core", "runtime"])))
        self.assertIn(
            "registry-messaging-client transitively depends on runtime crate(s): "
            "registry-messaging",
            failures,
        )

    def test_a_binding_reaching_the_runtime_or_tooling_is_rejected(self):
        # The tooling itself depends on the runtime, so reaching it reaches both.
        for binding in ("client-node", "client-py"):
            for runtime, reached in (
                ("runtime", "registry-messaging"),
                ("ctl", "registry-messaging, registry-messagingctl"),
            ):
                with self.subTest(binding=binding, runtime=runtime):
                    failures = "\n".join(
                        MODULE.violations(metadata(**{binding: ["client", runtime]}))
                    )
                    self.assertIn(
                        f"{NAMES[binding]} transitively depends on runtime crate(s): "
                        f"{reached}",
                        failures,
                    )

    def test_a_binding_reaching_the_runtime_through_its_client_is_rejected(self):
        failures = "\n".join(MODULE.violations(metadata(client=["core", "runtime"])))
        for binding in ("client-node", "client-py"):
            self.assertIn(
                f"{NAMES[binding]} transitively depends on runtime crate(s): "
                "registry-messaging",
                failures,
            )

    def test_a_binding_reaching_another_product_is_rejected(self):
        for binding in ("client-node", "client-py"):
            with self.subTest(binding=binding):
                failures = "\n".join(
                    MODULE.violations(metadata(**{binding: ["client", "casework-core"]}))
                )
                self.assertIn(
                    f"{NAMES[binding]} transitively depends on other-product "
                    "package(s): registry-casework-core",
                    failures,
                )

    def test_the_unified_client_reaching_the_messaging_runtime_is_rejected(self):
        for runtime, reached in (
            ("runtime", "registry-messaging"),
            ("ctl", "registry-messaging, registry-messagingctl"),
        ):
            with self.subTest(runtime=runtime):
                failures = "\n".join(
                    MODULE.violations(metadata(**{"stack-client": ["client", runtime]}))
                )
                self.assertIn(
                    "registry-stack-client transitively depends on Messaging runtime "
                    f"package(s): {reached}",
                    failures,
                )

    def test_a_product_reaching_the_messaging_runtime_is_rejected(self):
        for product in ("breg", "coordinator", "scheduling-core", "evidence-client"):
            with self.subTest(product=product):
                failures = "\n".join(MODULE.violations(metadata(**{product: ["client"], "client": ["runtime"]})))
                self.assertIn(
                    f"{NAMES[product]} transitively depends on Messaging runtime package(s): "
                    "registry-messaging",
                    failures,
                )

    def test_coordinator_dev_dependencies_are_part_of_the_boundary(self):
        graph = metadata(coordinator=["runtime"])
        node = next(n for n in graph["resolve"]["nodes"] if n["id"] == "coordinator")
        node["deps"][0]["dep_kinds"] = [{"kind": "dev", "target": None}]
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn("registry-coordinator transitively depends on Messaging runtime package(s): registry-messaging", failures)
        self.assertEqual(MODULE.violations(metadata(coordinator=["client", "core"])), [])

    def test_a_messaging_crate_reaching_any_coordinator_crate_is_refused(self):
        for crate in ("core", "client", "client-node", "client-py", "runtime", "ctl"):
            for coordinator in ("coordinator", "coordinator-client"):
                with self.subTest(crate=crate, coordinator=coordinator):
                    edges = [*INTENDED[crate], coordinator]
                    failures = "\n".join(MODULE.violations(metadata(**{crate: edges})))
                    self.assertIn(
                        f"{NAMES[crate]} transitively depends on other-product "
                        f"package(s): {NAMES[coordinator]}",
                        failures,
                    )

    def test_the_coordinator_client_reaching_the_messaging_runtime_is_refused(self):
        failures = "\n".join(
            MODULE.violations(metadata(**{"coordinator-client": ["runtime"]}))
        )
        self.assertIn(
            "registry-coordinator-client transitively depends on Messaging runtime "
            "package(s): registry-messaging",
            failures,
        )

    def test_a_product_may_use_the_messaging_client(self):
        for product in ("breg", "coordinator", "discovery", "discovery-client", "render"):
            with self.subTest(product=product):
                self.assertEqual(MODULE.violations(metadata(**{product: ["client"]})), [])

    def test_a_graph_without_a_resolve_is_an_error(self):
        with self.assertRaises(ValueError):
            MODULE.violations({"packages": [], "resolve": None})


    def test_discovery_and_render_boundaries_are_checked_in_both_directions(self):
        for product in ("discovery", "discovery-client", "discovery-profile", "render"):
            with self.subTest(product=product):
                edges = {"runtime": ["platform"], "platform": [product]}
                failures = "\n".join(MODULE.violations(metadata(**edges)))
                self.assertIn("registry-messaging transitively depends on other-product", failures)
                edges = {product: ["platform"], "platform": ["runtime"]}
                failures = "\n".join(MODULE.violations(metadata(**edges)))
                self.assertIn(f"registry-{product} transitively depends on Messaging", failures)

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
        self.assertEqual(MODULE.violations(metadata(**edges)), [])

    def test_a_dependency_test_tool_does_not_become_a_product_dependency(self):
        edges = {"runtime": ["platform"], "core": ["platform"], "platform": ["discovery"]}
        graph = metadata(**edges)
        node = next(n for n in graph["resolve"]["nodes"] if n["id"] == "platform")
        node["deps"][0]["dep_kinds"] = [{"kind": "dev", "target": None}]
        self.assertEqual(MODULE.violations(graph), [])
        # The same edge in a supported build is still part of the boundary.
        node["deps"][0]["dep_kinds"].append({"kind": "build", "target": None})
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn("registry-messaging transitively depends on other-product", failures)

    def test_the_products_own_dev_dependencies_still_count(self):
        edges = {"runtime": ["discovery"]}
        graph = metadata(**edges)
        node = next(n for n in graph["resolve"]["nodes"] if n["id"] == "runtime")
        node["deps"][0]["dep_kinds"] = [{"kind": "dev", "target": None}]
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn("registry-messaging transitively depends on other-product", failures)

    def test_test_tooling_may_use_the_public_client(self):
        edges = {"thunderid": ["client"], "client": ["core"], "core": ["platform"]}
        self.assertEqual(MODULE.violations(metadata(**edges)), [])


if __name__ == "__main__":
    unittest.main()
