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
    "runtime": "registry-messaging",
    "ctl": "registry-messagingctl",
    "breg": "registry-breg",
    "casework-core": "registry-casework-core",
    "scheduling-core": "registry-scheduling-core",
    "evidence-client": "registry-evidence-client",
    "relay-client": "registry-relay-client",
    "cli-docs": "registry-cli-docs",
    "platform": "registry-platform-httpsec",
    "serde": "serde",
}

INTENDED = {
    "core": ["platform", "serde"],
    "client": ["core", "platform"],
    "runtime": ["core", "platform"],
    "ctl": ["runtime", "core"],
    "breg": [],
    "casework-core": [],
    "scheduling-core": [],
    "evidence-client": [],
    "relay-client": [],
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
            "registry-messaging",
            "registry-messagingctl",
        ):
            self.assertIn(f"{crate} transitively depends on other-product", failures)

    def test_each_named_product_is_refused(self):
        for product in (
            "breg",
            "casework-core",
            "scheduling-core",
            "evidence-client",
            "relay-client",
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

    def test_a_product_reaching_the_messaging_runtime_is_rejected(self):
        for product in ("breg", "scheduling-core", "relay-client"):
            with self.subTest(product=product):
                failures = "\n".join(MODULE.violations(metadata(**{product: ["client"], "client": ["runtime"]})))
                self.assertIn(
                    f"{NAMES[product]} transitively depends on Messaging runtime package(s): "
                    "registry-messaging",
                    failures,
                )

    def test_a_product_may_use_the_messaging_client(self):
        self.assertEqual(MODULE.violations(metadata(breg=["client"])), [])

    def test_a_graph_without_a_resolve_is_an_error(self):
        with self.assertRaises(ValueError):
            MODULE.violations({"packages": [], "resolve": None})


if __name__ == "__main__":
    unittest.main()
