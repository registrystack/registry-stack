#!/usr/bin/env python3
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("check_database_test_isolation.py")
SPEC = importlib.util.spec_from_file_location("casework_database_test_isolation", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def metadata(*, forwarded=True, breg_postgres=False):
    feature_values = (
        ["dep:registry-breg", "registry-breg/postgres-test"] if forwarded else []
    )
    return {
        "packages": [
            {
                "id": "casework",
                "name": "registry-casework",
                "features": {"postgres-test": feature_values},
            },
            {"id": "breg", "name": "registry-breg", "features": {"postgres-test": []}},
        ],
        "resolve": {
            "nodes": [
                {"id": "casework", "features": []},
                {"id": "breg", "features": ["postgres-test"] if breg_postgres else []},
            ]
        },
    }


class DatabaseTestIsolationTests(unittest.TestCase):
    def test_default_is_isolated_and_explicit_feature_forwards(self):
        self.assertEqual(MODULE.violations(metadata(), metadata(breg_postgres=True)), [])

    def test_default_resolution_cannot_enable_breg_postgres(self):
        failures = MODULE.violations(
            metadata(breg_postgres=True), metadata(breg_postgres=True)
        )
        self.assertIn("default workspace resolution", failures[0])

    def test_casework_feature_must_forward_breg_feature(self):
        failures = MODULE.violations(
            metadata(forwarded=False), metadata(forwarded=False, breg_postgres=True)
        )
        self.assertIn("must activate its optional BReg dependency", failures[0])

    def test_explicit_feature_must_activate_breg_postgres(self):
        failures = MODULE.violations(metadata(), metadata())
        self.assertIn("does not activate", failures[0])

    def test_metadata_loader_requests_only_the_explicit_feature_when_needed(self):
        with patch.object(MODULE.subprocess, "run") as run:
            run.return_value.stdout = json.dumps(metadata())
            MODULE.load_metadata(Path("."), None, None)
            self.assertNotIn("--features", run.call_args.args[0])
            MODULE.load_metadata(Path("."), "registry-casework/postgres-test", None)
            self.assertEqual(
                run.call_args.args[0][-2:],
                ["--features", "registry-casework/postgres-test"],
            )


if __name__ == "__main__":
    unittest.main()
