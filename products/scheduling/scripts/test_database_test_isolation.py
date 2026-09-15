#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_database_test_isolation.py")
SPEC = importlib.util.spec_from_file_location("scheduling_database_test_isolation", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def package(name: str, gated: dict[str, list[str]], dependencies: list[dict]) -> dict:
    return {
        "name": name,
        "targets": [
            {"name": target, "kind": ["test"], "required-features": features}
            for target, features in gated.items()
        ],
        "dependencies": dependencies,
    }


def dependency(name: str, features: list[str], kind: str | None = None) -> dict:
    return {"name": name, "kind": kind, "features": features}


def metadata(packages: list[dict]) -> dict:
    return {"packages": packages}


class DatabaseTestIsolationTests(unittest.TestCase):
    def test_an_opt_in_feature_chain_is_accepted(self):
        graph = metadata(
            [
                package("registry-scheduling", {"postgres_commitments": ["postgres-test"]}, []),
                package(
                    "registry-schedulingctl",
                    {"records_apply_postgres": ["postgres-test"]},
                    [dependency("registry-scheduling", [])],
                ),
            ]
        )
        self.assertEqual(MODULE.violations(graph), [])

    def test_a_dev_dependency_selecting_a_siblings_database_tests_is_rejected(self):
        graph = metadata(
            [
                package("registry-scheduling", {"postgres_commitments": ["postgres-test"]}, []),
                package(
                    "registry-schedulingctl",
                    {"records_apply_postgres": ["postgres-test"]},
                    [dependency("registry-scheduling", ["postgres-test"], kind="dev")],
                ),
            ]
        )
        failures = MODULE.violations(graph)
        self.assertEqual(len(failures), 1)
        self.assertIn("registry-schedulingctl", failures[0])
        self.assertIn("registry-scheduling/postgres-test", failures[0])
        self.assertIn("postgres_commitments", failures[0])

    def test_an_ordinary_dependency_selecting_them_is_rejected_too(self):
        graph = metadata(
            [
                package("registry-scheduling", {"postgres_commitments": ["postgres-test"]}, []),
                package(
                    "registry-schedulingctl",
                    {},
                    [dependency("registry-scheduling", ["postgres-test"])],
                ),
            ]
        )
        self.assertEqual(len(MODULE.violations(graph)), 1)

    def test_a_feature_that_gates_no_test_target_is_not_the_subject(self):
        graph = metadata(
            [
                package("registry-scheduling", {"postgres_commitments": ["postgres-test"]}, []),
                package(
                    "registry-schedulingctl",
                    {},
                    [dependency("registry-scheduling", ["schema"], kind="dev")],
                ),
            ]
        )
        self.assertEqual(MODULE.violations(graph), [])

    def test_a_non_scheduling_dependency_is_left_to_its_own_product(self):
        graph = metadata(
            [
                package("registry-breg", {"postgres_kernel": ["postgres-test"]}, []),
                package(
                    "registry-casework",
                    {},
                    [dependency("registry-breg", ["postgres-test"], kind="dev")],
                ),
            ]
        )
        self.assertEqual(MODULE.violations(graph), [])

    def test_every_gated_target_is_named_once(self):
        graph = metadata(
            [
                package(
                    "registry-scheduling",
                    {"postgres_commitments": ["postgres-test"], "postgres_replay": ["postgres-test"]},
                    [],
                ),
                package(
                    "registry-schedulingctl",
                    {},
                    [dependency("registry-scheduling", ["postgres-test"], kind="dev")],
                ),
            ]
        )
        failures = MODULE.violations(graph)
        self.assertEqual(len(failures), 1)
        self.assertIn("postgres_commitments", failures[0])
        self.assertIn("postgres_replay", failures[0])


if __name__ == "__main__":
    unittest.main()
