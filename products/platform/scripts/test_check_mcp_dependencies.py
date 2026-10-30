#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-mcp-dependencies.py")
SPEC = importlib.util.spec_from_file_location("mcp_dependencies", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


NAMES = {
    "edge": "registry-mcp-edge",
    "runtime": "registry-mcp",
    "provider": "registry-breg-mcp",
    "breg-client": "registry-breg-client",
    "casework-client": "registry-casework-client",
    "casework-core": "registry-casework-core",
    "casework-runtime": "registry-casework",
    "casework-tooling": "registry-caseworkctl",
    "example-client": "registry-example-client",
    "platform": "registry-platform-httputil",
    "record": "registry-record",
    "serde": "serde",
}


def metadata(edges: dict[str, list[str | tuple[str, str | None]]]) -> dict:
    packages = set(edges)
    packages.update(
        dependency[0] if isinstance(dependency, tuple) else dependency
        for dependencies in edges.values()
        for dependency in dependencies
    )
    return {
        "packages": [
            {"id": package_id, "name": NAMES[package_id]}
            for package_id in sorted(packages)
        ],
        "resolve": {
            "nodes": [
                {
                    "id": package_id,
                    "deps": [
                        {
                            "pkg": dependency[0]
                            if isinstance(dependency, tuple)
                            else dependency,
                            "dep_kinds": [
                                {
                                    "kind": dependency[1]
                                    if isinstance(dependency, tuple)
                                    else None
                                }
                            ],
                        }
                        for dependency in dependencies
                    ],
                }
                for package_id, dependencies in edges.items()
            ]
        },
    }


def valid_edges() -> dict[str, list[str | tuple[str, str | None]]]:
    return {
        "edge": ["platform", "serde"],
        "runtime": ["edge", "provider", "casework-client"],
        "provider": ["breg-client"],
        "breg-client": ["record"],
        "casework-client": ["casework-core"],
        "casework-core": ["serde"],
        "platform": ["serde"],
        "record": ["serde"],
        "serde": [],
    }


class McpDependencyTests(unittest.TestCase):
    def test_reviewed_runtime_leaves_are_an_explicit_closed_set(self) -> None:
        self.assertEqual(
            MODULE.REVIEWED_BOUNDARIES,
            frozenset({"registry-breg-mcp", "registry-casework-client"}),
        )

    def test_shared_edge_and_runtime_use_only_reviewed_boundaries(self) -> None:
        self.assertEqual(MODULE.violations(metadata(valid_edges())), [])

    def test_shared_edge_cannot_reach_a_product_even_from_its_tests(self) -> None:
        for kind in (None, "build", "dev"):
            with self.subTest(kind=kind):
                edges = valid_edges()
                edges["edge"] = ["platform", ("breg-client", kind)]
                failures = "\n".join(MODULE.violations(metadata(edges)))
                self.assertIn(
                    "registry-mcp-edge depends on product package(s): "
                    "registry-breg-client, registry-record",
                    failures,
                )

    def test_runtime_must_reach_products_through_a_client_or_provider(self) -> None:
        for dependency in ("casework-core", "casework-runtime", "casework-tooling"):
            with self.subTest(dependency=dependency):
                edges = valid_edges()
                edges[dependency] = []
                edges["runtime"] = ["edge", dependency]
                failures = "\n".join(MODULE.violations(metadata(edges)))
                self.assertIn(
                    f"outside a maintained client/provider boundary: {NAMES[dependency]}",
                    failures,
                )

    def test_an_unknown_client_name_is_not_implicitly_trusted(self) -> None:
        edges = valid_edges()
        edges["example-client"] = ["casework-core"]
        edges["runtime"] = ["edge", "provider", "example-client"]
        failures = "\n".join(MODULE.violations(metadata(edges)))
        self.assertIn("registry-example-client", failures)
        self.assertIn("registry-casework-core", failures)

    def test_runtime_build_dependencies_do_not_bypass_the_boundary(self) -> None:
        edges = valid_edges()
        edges["casework-runtime"] = []
        edges["runtime"] = ["edge", ("casework-runtime", "build")]
        self.assertIn(
            "registry-casework",
            "\n".join(MODULE.violations(metadata(edges))),
        )

    def test_runtime_dev_dependencies_may_hold_product_fixtures(self) -> None:
        edges = valid_edges()
        edges["casework-runtime"] = []
        edges["runtime"] = ["edge", ("casework-runtime", "dev")]
        self.assertEqual(MODULE.violations(metadata(edges)), [])

    def test_missing_boundary_package_fails_closed(self) -> None:
        edges = valid_edges()
        del edges["edge"]
        edges["runtime"] = ["provider", "casework-client"]
        self.assertIn(
            "workspace must contain exactly one registry-mcp-edge package",
            MODULE.violations(metadata(edges)),
        )


if __name__ == "__main__":
    unittest.main()
