#!/usr/bin/env python3
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("check_database_test_isolation.py")
SPEC = importlib.util.spec_from_file_location("documents_database_test_isolation", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def metadata(features=(), required=("postgres-test",), target="postgres_migrate", extra=()):
    targets = [
        {"name": name, "kind": ["test"], "required-features": list(required)}
        for name in (target, "postgres_package")
    ]
    targets.extend(extra)
    return {
        "packages": [{"id": "runtime", "name": "registry-documents", "targets": targets}],
        "resolve": {"nodes": [{"id": "runtime", "features": list(features)}]},
    }


class DatabaseTestIsolationTests(unittest.TestCase):
    def setUp(self):
        # The fixture graphs declare two suites; the maintained inventory is
        # checked against the real workspace by the script itself.
        suites = patch.object(
            MODULE,
            "DATABASE_SUITES",
            {"registry-documents": {"postgres_migrate", "postgres_package"}},
        )
        suites.start()
        self.addCleanup(suites.stop)

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
            ["registry-documents/postgres_migrate is a declared database suite with no test target"],
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
        with tempfile.TemporaryDirectory(prefix="documents-feature-test.") as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "tests").mkdir()
            (root / "src/lib.rs").write_text("", encoding="utf-8")
            for suite in ("postgres_migrate", "postgres_package"):
                (root / f"tests/{suite}.rs").write_text("", encoding="utf-8")
            for default, expected in [('[]', False), ('["full"]', True)]:
                (root / "Cargo.toml").write_text(
                    '[package]\nname="registry-documents"\nversion="0.1.0"\nedition="2021"\n'
                    '[workspace]\n[features]\n'
                    f'default={default}\nfull=["alias"]\nalias=["postgres-test"]\npostgres-test=[]\n'
                    '[[test]]\nname="postgres_migrate"\nrequired-features=["postgres-test"]\n'
                    '[[test]]\nname="postgres_package"\nrequired-features=["postgres-test"]\n',
                    encoding="utf-8",
                )
                subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, check=True,
                               capture_output=True, text=True)
                self.assertEqual(bool(MODULE.violations(MODULE.load_metadata(root, None))), expected)


READ = 'std::env::var("DOCUMENTS_TEST_DATABASE_URL")'


class DatabaseVariableTests(unittest.TestCase):
    """A database suite fails, rather than skips, without its database."""

    def setUp(self):
        suites = patch.object(
            MODULE,
            "DATABASE_SUITES",
            {"registry-documents": {"postgres_migrate", "postgres_package"}},
        )
        suites.start()
        self.addCleanup(suites.stop)
        directory = tempfile.TemporaryDirectory(prefix="documents-suite-source.")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.tests = self.root / "crates/registry-documents/tests"
        (self.tests / "support").mkdir(parents=True)

    def write(self, name, text):
        (self.tests / name).write_text(text, encoding="utf-8")

    def suites(self, migrate="mod support;\n", package="mod support;\n", support=None):
        self.write("support/mod.rs", support if support is not None else f'{READ}\n    .expect("a database");\n')
        self.write("postgres_migrate.rs", migrate)
        self.write("postgres_package.rs", package)
        return MODULE.source_violations(self.root)

    def test_suites_reading_through_an_expecting_support_module_pass(self):
        self.assertEqual(self.suites(), [])

    def test_a_suite_may_read_the_variable_itself(self):
        self.assertEqual(self.suites(package=f'let url = {READ}.expect("x");\n'), [])

    def test_a_read_that_tolerates_absence_is_refused(self):
        for tolerant in (".ok()", ".unwrap_or_default()", ".is_err()"):
            with self.subTest(tolerant):
                failures = self.suites(package=f"let url = {READ}{tolerant};\n")
                self.assertEqual(len(failures), 1)
                self.assertIn("postgres_package:1 reads", failures[0])

    def test_a_matched_read_is_refused(self):
        failures = self.suites(package=f"match {READ} {{ Ok(u) => u, Err(_) => return }};\n")
        self.assertIn("without .expect", failures[0])

    def test_a_tolerant_support_module_is_refused(self):
        failures = self.suites(support=f"{READ}.ok()\n")
        self.assertIn("support/mod.rs:1 reads", failures[0])

    def test_a_suite_that_never_reads_the_variable_is_refused(self):
        self.assertEqual(
            self.suites(migrate="#[test]\nfn nothing() {}\n"),
            ["registry-documents/postgres_migrate never reads DOCUMENTS_TEST_DATABASE_URL"],
        )

    def test_an_ignored_database_test_is_refused(self):
        failures = self.suites(package='mod support;\n#[ignore = "later"]\n#[test]\nfn t() {}\n')
        self.assertEqual(failures, ["registry-documents/postgres_package ignores a database test, so it never runs"])

    def test_a_declared_suite_without_source_is_refused(self):
        self.suites()
        (self.tests / "postgres_package.rs").unlink()
        self.assertIn("has no source", MODULE.source_violations(self.root)[0])



class MaintainedSuiteSourceTests(unittest.TestCase):
    def test_the_maintained_suites_fail_without_their_database(self):
        self.assertEqual(MODULE.source_violations(SCRIPT.resolve().parents[3]), [])


if __name__ == "__main__":
    unittest.main()
