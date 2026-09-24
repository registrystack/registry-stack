#!/usr/bin/env python3
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("check_database_test_isolation.py")
SPEC = importlib.util.spec_from_file_location("messaging_database_test_isolation", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def metadata(features=(), required=("postgres-test",), target="postgres_migrate", extra=()):
    targets = [{"name": target, "kind": ["test"], "required-features": list(required)}]
    targets.extend(extra)
    return {
        "packages": [{"id": "runtime", "name": "registry-messaging", "targets": targets}],
        "resolve": {"nodes": [{"id": "runtime", "features": list(features)}]},
    }


class DatabaseTestIsolationTests(unittest.TestCase):
    def test_explicit_opt_in_is_not_enabled_by_default(self):
        self.assertEqual(MODULE.violations(metadata()), [])

    def test_resolved_default_features_cannot_enable_a_database_suite(self):
        self.assertTrue(MODULE.violations(metadata(features=["default", "postgres-test"])))

    def test_a_database_suite_cannot_lose_its_gate(self):
        self.assertTrue(MODULE.violations(metadata(required=[])))

    def test_an_unrelated_feature_cannot_replace_the_database_gate(self):
        self.assertTrue(MODULE.violations(metadata(required=["schema"])))

    def test_an_ordinary_integration_test_does_not_need_a_gate(self):
        graph = metadata(extra=[{"name": "http_boundary", "kind": ["test"], "required-features": []}])
        self.assertEqual(MODULE.violations(graph), [])

    def test_a_declared_suite_without_a_target_is_reported(self):
        failures = MODULE.violations(metadata(target="postgres_renamed"))
        self.assertEqual(
            failures,
            ["registry-messaging/postgres_migrate is a declared database suite with no test target"],
        )

    def test_all_required_features_must_be_enabled(self):
        self.assertEqual(MODULE.violations(metadata(
            features=["postgres-test"], required=["postgres-test", "tooling"],
        )), [])

    def test_missing_resolution_fails_visibly(self):
        graph = metadata()
        graph["resolve"]["nodes"] = []
        self.assertIn("no resolved feature inventory", MODULE.violations(graph)[0])

    def test_metadata_loader_keeps_the_default_resolved_graph(self):
        with patch.object(MODULE.subprocess, "run") as run:
            run.return_value.stdout = json.dumps(metadata())
            MODULE.load_metadata(Path("."), None)
        command = run.call_args.args[0]
        self.assertNotIn("--no-deps", command)
        self.assertNotIn("--all-features", command)
        self.assertNotIn("--no-default-features", command)

    def test_cargo_resolves_defaults_and_transitive_forwarding(self):
        with tempfile.TemporaryDirectory(prefix="messaging-feature-test.") as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "tests").mkdir()
            (root / "src/lib.rs").write_text("", encoding="utf-8")
            (root / "tests/postgres_migrate.rs").write_text("", encoding="utf-8")
            for default, expected in [('[]', False), ('["full"]', True)]:
                (root / "Cargo.toml").write_text(
                    '[package]\nname="registry-messaging"\nversion="0.1.0"\nedition="2021"\n'
                    '[workspace]\n[features]\n'
                    f'default={default}\nfull=["alias"]\nalias=["postgres-test"]\npostgres-test=[]\n'
                    '[[test]]\nname="postgres_migrate"\nrequired-features=["postgres-test"]\n',
                    encoding="utf-8",
                )
                subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, check=True,
                               capture_output=True, text=True)
                self.assertEqual(bool(MODULE.violations(MODULE.load_metadata(root, None))), expected)


if __name__ == "__main__":
    unittest.main()
