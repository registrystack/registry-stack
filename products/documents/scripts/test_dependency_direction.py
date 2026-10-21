#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_dependency_direction.py")
SPEC = importlib.util.spec_from_file_location("documents_dependency_direction", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

NAMES = {
    "core": "registry-documents-core",
    "client": "registry-documents-client",
    "stack-client": "registry-stack-client",
    "runtime": "registry-documents",
    "ctl": "registry-documentsctl",
    "breg": "registry-breg",
    "casework-core": "registry-casework-core",
    "coordinator": "registry-coordinator",
    "evidence-client": "registry-evidence-client",
    "messaging-client": "registry-messaging-client",
    "scheduling-core": "registry-scheduling-core",
    "cli-docs": "registry-cli-docs",
    "platform": "registry-platform-httpsec",
    "serde": "serde",
}

INTENDED = {
    "core": ["platform", "serde"],
    "client": ["core", "platform"],
    "stack-client": ["evidence-client"],
    "runtime": ["core", "platform"],
    "ctl": ["runtime", "core"],
    "breg": [],
    "casework-core": [],
    "coordinator": [],
    "evidence-client": [],
    "messaging-client": [],
    "scheduling-core": [],
    "cli-docs": ["runtime", "ctl", "breg"],
    "platform": ["serde"],
    "serde": [],
}

DOCUMENTS_CRATES = ("core", "client", "runtime", "ctl")
OTHER_PRODUCTS = (
    "breg",
    "casework-core",
    "coordinator",
    "evidence-client",
    "messaging-client",
    "scheduling-core",
)


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

    def test_a_transitive_product_dependency_reaches_every_documents_crate(self):
        failures = "\n".join(MODULE.violations(metadata(serde=["breg"])))
        for crate in DOCUMENTS_CRATES:
            self.assertIn(
                f"{NAMES[crate]} transitively depends on other-product", failures
            )

    def test_each_documents_crate_reaching_each_named_product_is_refused(self):
        for crate in DOCUMENTS_CRATES:
            for product in OTHER_PRODUCTS:
                with self.subTest(crate=crate, product=product):
                    edges = [*INTENDED[crate], product]
                    failures = "\n".join(MODULE.violations(metadata(**{crate: edges})))
                    self.assertIn(
                        f"{NAMES[crate]} transitively depends on other-product "
                        f"package(s): {NAMES[product]}",
                        failures,
                    )

    def test_core_depending_on_another_documents_crate_is_rejected(self):
        failures = "\n".join(MODULE.violations(metadata(core=["client"])))
        self.assertIn(
            "registry-documents-core transitively depends on Document Store crate(s): "
            "registry-documents-client",
            failures,
        )

    def test_client_depending_on_the_runtime_or_tooling_is_rejected(self):
        for runtime, reached in (
            ("runtime", "registry-documents"),
            ("ctl", "registry-documents, registry-documentsctl"),
        ):
            with self.subTest(runtime=runtime):
                failures = "\n".join(
                    MODULE.violations(metadata(client=["core", runtime]))
                )
                self.assertIn(
                    "registry-documents-client transitively depends on runtime crate(s): "
                    f"{reached}",
                    failures,
                )

    def test_the_unified_client_reaching_the_documents_runtime_is_rejected(self):
        for runtime, reached in (
            ("runtime", "registry-documents"),
            ("ctl", "registry-documents, registry-documentsctl"),
        ):
            with self.subTest(runtime=runtime):
                failures = "\n".join(
                    MODULE.violations(metadata(**{"stack-client": [runtime]}))
                )
                self.assertIn(
                    "registry-stack-client transitively depends on Document Store runtime "
                    f"package(s): {reached}",
                    failures,
                )

    def test_a_product_reaching_the_documents_runtime_is_rejected(self):
        for product in OTHER_PRODUCTS:
            with self.subTest(product=product):
                failures = "\n".join(
                    MODULE.violations(metadata(**{product: ["client"], "client": ["runtime"]}))
                )
                self.assertIn(
                    f"{NAMES[product]} transitively depends on Document Store runtime "
                    "package(s): registry-documents",
                    failures,
                )

    def test_dev_dependencies_are_part_of_the_boundary(self):
        graph = metadata(coordinator=["runtime"])
        node = next(n for n in graph["resolve"]["nodes"] if n["id"] == "coordinator")
        node["deps"][0]["dep_kinds"] = [{"kind": "dev", "target": None}]
        failures = "\n".join(MODULE.violations(graph))
        self.assertIn(
            "registry-coordinator transitively depends on Document Store runtime "
            "package(s): registry-documents",
            failures,
        )

    def test_a_product_may_use_the_documents_client(self):
        self.assertEqual(MODULE.violations(metadata(breg=["client"])), [])

    def test_tooling_outside_the_products_may_reach_the_runtime(self):
        self.assertEqual(MODULE.violations(metadata(**{"cli-docs": ["runtime", "ctl"]})), [])

    def test_a_graph_without_a_resolve_is_an_error(self):
        with self.assertRaises(ValueError):
            MODULE.violations({"packages": [], "resolve": None})


if __name__ == "__main__":
    unittest.main()
