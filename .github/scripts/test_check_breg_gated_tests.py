#!/usr/bin/env python3
"""Regression checks for the feature-gated registry-breg test selection gate."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

import check_breg_gated_tests as gate
from ci_changes import SHARDS


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
SCHEMA_STEP = (
    "run: cargo test --locked -p registry-breg --features runtime,tooling,schema "
    "--lib --test action_evidence_compiler"
)

FEATURES = {
    "default": ["wasm"],
    "postgres-test": ["runtime", "dep:tower"],
    "runtime": [],
    "schema": [],
    "tooling": [],
    "wasm": [],
}

MANIFEST = """
    [package]
    name = "registry-breg"

    [features]
    default = ["wasm"]
    postgres-test = ["runtime", "dep:tower"]
    runtime = []
    schema = []
    tooling = []
    wasm = []

    [[test]]
    name = "fixtures"
    path = "tests/fixtures.rs"
    required-features = ["runtime", "tooling"]
"""

SIBLING_MANIFEST = """
    [package]
    name = "registry-bregctl"

    [features]
    default = ["wasm"]
    schema = ["registry-breg/schema"]
    wasm = ["registry-breg/wasm"]

    [dependencies]
    registry-breg = { workspace = true, features = ["runtime", "tooling"] }
"""

SHARD = ("registry-breg", "registry-bregctl")
SOURCES = (".github/workflows/ci.yml",)


def write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")


def read(command: str) -> gate.Invocation | None:
    return gate.read_invocation(command, "ci", FEATURES)


class CfgTests(unittest.TestCase):
    def test_feature_conditions_follow_all_any_and_not(self) -> None:
        on = frozenset({"runtime", "tooling"})
        self.assertTrue(gate.cfg_holds('feature = "runtime"', on))
        self.assertFalse(gate.cfg_holds('feature = "schema"', on))
        self.assertTrue(gate.cfg_holds('all(feature = "runtime", feature = "tooling")', on))
        self.assertFalse(gate.cfg_holds('all(feature = "runtime", feature = "schema")', on))
        self.assertTrue(gate.cfg_holds('any(feature = "schema", feature = "tooling")', on))
        self.assertTrue(gate.cfg_holds('not(feature = "schema")', on))
        self.assertFalse(gate.cfg_holds('not(all(feature = "runtime", feature = "tooling"))', on))

    def test_test_and_unix_hold_in_every_ci_test_build(self) -> None:
        self.assertTrue(gate.cfg_holds('all(test, feature = "schema", unix)', frozenset({"schema"})))
        self.assertTrue(gate.cfg_holds('any(test, feature = "schema")', frozenset()))

    def test_unknown_predicate_is_refused_instead_of_guessed(self) -> None:
        for expression in ('all(feature = "schema", windows)', 'target_os = "linux"', "all(feature"):
            with self.subTest(expression=expression), self.assertRaises(gate.GateError):
                gate.cfg_holds(expression, frozenset({"schema"}))

    def test_feature_closure_follows_implied_features_and_defaults(self) -> None:
        self.assertEqual(
            gate.feature_closure(FEATURES, {"postgres-test"}, default_features=True),
            frozenset({"default", "postgres-test", "runtime", "wasm"}),
        )
        self.assertEqual(
            gate.feature_closure(FEATURES, {"schema"}, default_features=False),
            frozenset({"schema"}),
        )


class InvocationTests(unittest.TestCase):
    def test_reads_features_and_target_selection(self) -> None:
        invocation = read(
            "run: cargo test --locked -p registry-breg --features runtime,tooling "
            "--lib --test fixtures --test other"
        )
        self.assertIsNotNone(invocation)
        self.assertEqual(
            invocation.features, frozenset({"default", "runtime", "tooling", "wasm"})
        )
        self.assertTrue(invocation.lib)
        self.assertEqual(invocation.tests, frozenset({"fixtures", "other"}))

    def test_no_target_flags_select_the_library_and_every_test_target(self) -> None:
        invocation = read("cargo test --locked -p registry-breg --features registry-breg/schema")
        self.assertIsNotNone(invocation)
        self.assertEqual(invocation.features, frozenset({"default", "schema", "wasm"}))
        self.assertTrue(invocation.lib)
        self.assertIsNone(invocation.tests)

    def test_named_test_targets_leave_the_library_out(self) -> None:
        invocation = read(
            "cargo test --locked -p registry-breg --no-default-features "
            "--features postgres-test --test fixtures -- --include-ignored --test-threads=1"
        )
        self.assertIsNotNone(invocation)
        self.assertEqual(invocation.features, frozenset({"postgres-test", "runtime"}))
        self.assertFalse(invocation.lib)
        self.assertEqual(invocation.tests, frozenset({"fixtures"}))

    def test_partial_or_unreadable_invocations_select_nothing(self) -> None:
        for command in (
            # A test-name filter runs a subset the gate cannot enumerate.
            "cargo test --locked -p registry-breg --features schema --lib schema::tests",
            "cargo test --locked -p registry-breg --test fixtures one_test -- --exact",
            "cargo test --locked -p registry-breg --test fixtures -- --ignored",
            "cargo test --locked -p registry-breg --test fixtures -- --skip slow",
            "cargo test --locked -p registry-breg --no-run",
            'cargo test --locked -p registry-breg --features "$features"',
            "cargo test --locked -p registry-breg --unknown-flag",
            # Another package, alone or beside registry-breg, is not this crate's selection.
            "cargo test --locked -p registry-bregctl --features schema",
            "cargo test --locked -p registry-breg -p registry-bregctl",
            "cargo build --locked -p registry-breg --features runtime",
        ):
            with self.subTest(command=command):
                self.assertIsNone(read(command))

    def test_source_invocations_join_shell_continuations(self) -> None:
        text = textwrap.dedent(
            """
            if [[ "$lane" == all ]]; then
              uv run --no-project cargo test --locked -p registry-breg --features postgres-test \\
                --test fixtures \\
                --test other
            fi
            cargo test --locked -p registry-breg --lib filtered
            """
        )
        invocations, ignored = gate.source_invocations(text, "script.sh", FEATURES)
        self.assertEqual([invocation.tests for invocation in invocations], [frozenset({"fixtures", "other"})])
        self.assertEqual(ignored, 1)

    def test_shard_unifies_features_requested_by_its_other_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "crates/registry-breg/Cargo.toml", MANIFEST)
            write(root, "crates/registry-bregctl/Cargo.toml", SIBLING_MANIFEST)
            invocation = gate.shard_invocation(root, SHARD, FEATURES)
        # `schema` is forwarded only by a feature the shard does not enable.
        self.assertEqual(
            invocation.features, frozenset({"default", "runtime", "tooling", "wasm"})
        )
        self.assertTrue(invocation.lib)
        self.assertIsNone(invocation.tests)


class ScanTests(unittest.TestCase):
    def scan(self, files: dict[str, str]) -> dict[str, gate.GatedTest]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "crates/registry-breg/Cargo.toml", MANIFEST)
            for relative, text in files.items():
                write(root, f"crates/registry-breg/{relative}", text)
            found = gate.gated_tests(root / "crates/registry-breg")
        return {test.key: test for test in found}

    def test_required_features_target_is_gated_as_a_whole(self) -> None:
        found = self.scan({"tests/fixtures.rs": "#[test]\nfn plain() {}\n"})
        self.assertEqual(list(found), ["tests/fixtures.rs"])
        self.assertEqual(found["tests/fixtures.rs"].target, "fixtures")
        self.assertEqual(
            found["tests/fixtures.rs"].conditions,
            ('feature = "runtime"', 'feature = "tooling"'),
        )

    def test_file_level_cfg_gates_an_undeclared_target(self) -> None:
        found = self.scan(
            {
                "tests/postgres_load.rs": """
                    #![cfg(all(feature = "postgres-test", unix))]

                    #[test]
                    fn loads() {}
                """,
                "tests/plain.rs": "#[test]\nfn plain() {}\n",
            }
        )
        self.assertEqual(list(found), ["tests/postgres_load.rs"])
        self.assertEqual(
            found["tests/postgres_load.rs"].conditions,
            ('all(feature = "postgres-test", unix)',),
        )

    def test_cfg_gated_test_functions_carry_every_enclosing_condition(self) -> None:
        found = self.scan(
            {
                "tests/fixtures.rs": """
                    #[cfg(feature = "schema")]
                    #[test]
                    fn schema_only() {}

                    // A comment between attributes does not hide the test.
                    #[cfg(feature = "postgres-test")]
                    #[tokio::test(
                        flavor = "multi_thread",
                        worker_threads = 2
                    )]
                    async fn database_only() {}

                    #[cfg(any(
                        feature = "postgres-test",
                        all(feature = "runtime", feature = "schema")
                    ))]
                    #[test]
                    fn spread_over_lines() {}

                    #[cfg(feature = "schema")]
                    fn helper() {}

                    #[cfg(test)]
                    #[test]
                    fn ungated() {}
                """
            }
        )
        self.assertEqual(
            sorted(found),
            [
                "tests/fixtures.rs",
                "tests/fixtures.rs::database_only",
                "tests/fixtures.rs::schema_only",
                "tests/fixtures.rs::spread_over_lines",
            ],
        )
        self.assertEqual(
            found["tests/fixtures.rs::schema_only"].conditions,
            ('feature = "runtime"', 'feature = "tooling"', 'feature = "schema"'),
        )
        self.assertEqual(
            found["tests/fixtures.rs::spread_over_lines"].conditions[2],
            'any(feature = "postgres-test", all(feature = "runtime", feature = "schema"))',
        )

    def test_cfg_gated_modules_in_the_library_are_gated(self) -> None:
        found = self.scan(
            {
                "src/lib.rs": """
                    #[cfg(feature = "schema")]
                    pub mod schema;

                    #[cfg(test)]
                    mod tests {
                        #[test]
                        fn ungated() {}
                    }
                """,
                "src/postgres/config.rs": """
                    #[cfg(all(test, feature = "postgres-test"))]
                    mod tests {
                        #[test]
                        fn inside() {}
                    }

                    #[cfg(feature = "postgres-test")]
                    #[test]
                    fn debug_hides_secrets() {}
                """,
            }
        )
        self.assertEqual(
            sorted(found),
            [
                "src/lib.rs::mod schema",
                "src/postgres/config.rs::debug_hides_secrets",
                "src/postgres/config.rs::mod tests",
            ],
        )
        self.assertIsNone(found["src/lib.rs::mod schema"].target)
        self.assertEqual(
            found["src/postgres/config.rs::mod tests"].conditions,
            ('all(test, feature = "postgres-test")',),
        )

    def test_cfg_attribute_the_scanner_cannot_read_is_refused(self) -> None:
        text = '#[test]\n#[cfg(feature = "schema")] fn shared_line() {}\n'
        with self.assertRaises(gate.GateError) as raised:
            self.scan({"tests/fixtures.rs": text})
        self.assertIn("tests/fixtures.rs:2", str(raised.exception))


class SelectionTests(unittest.TestCase):
    def repository(self, directory: str, workflow: str, tests: dict[str, str]) -> Path:
        root = Path(directory)
        write(root, "crates/registry-breg/Cargo.toml", MANIFEST)
        write(root, "crates/registry-bregctl/Cargo.toml", SIBLING_MANIFEST)
        write(root, "crates/registry-breg/src/lib.rs", "")
        write(root, ".github/workflows/ci.yml", workflow)
        for relative, text in tests.items():
            write(root, f"crates/registry-breg/{relative}", text)
        return root

    def problems(
        self,
        workflow: str,
        tests: dict[str, str],
        known: dict[str, str] | None = None,
        shard: tuple[str, ...] = SHARD,
    ) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = self.repository(directory, workflow, tests)
            return gate.repository_violations(
                root, sources=SOURCES, shard=shard, known_unselected=known or {}
            )

    def test_shard_selects_what_its_unified_features_enable(self) -> None:
        self.assertEqual(self.problems("", {"tests/fixtures.rs": "#[test]\nfn plain() {}\n"}), [])

    def test_required_features_target_no_invocation_builds_is_refused(self) -> None:
        problems = self.problems(
            "", {"tests/fixtures.rs": "#[test]\nfn plain() {}\n"}, shard=("registry-breg",)
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("tests/fixtures.rs", problems[0])
        self.assertIn('feature = "tooling"', problems[0])

    def test_newly_gated_test_no_invocation_selects_is_refused(self) -> None:
        tests = {
            "tests/fixtures.rs": '#[cfg(feature = "schema")]\n#[test]\nfn schema_only() {}\n'
        }
        problems = self.problems("", tests)
        self.assertEqual(len(problems), 1)
        self.assertIn("tests/fixtures.rs::schema_only", problems[0])

        # Enabling the feature for another target, or selecting the target
        # without the feature, still leaves the test out.
        for workflow in (
            "run: cargo test --locked -p registry-breg --features runtime,tooling,schema --test other\n",
            "run: cargo test --locked -p registry-breg --features runtime,tooling --test fixtures\n",
            "run: cargo test --locked -p registry-breg --features runtime,tooling,schema --lib\n",
        ):
            with self.subTest(workflow=workflow):
                self.assertEqual(len(self.problems(workflow, tests)), 1)

        selecting = (
            "run: cargo test --locked -p registry-breg --features runtime,tooling,schema "
            "--lib --test fixtures\n"
        )
        self.assertEqual(self.problems(selecting, tests), [])

    def test_gated_library_module_needs_a_library_invocation(self) -> None:
        tests = {"src/lib.rs": '#[cfg(feature = "schema")]\nmod schema;\n'}
        named = "run: cargo test --locked -p registry-breg --features schema --test fixtures\n"
        problems = self.problems(named, tests)
        self.assertEqual(len(problems), 1)
        self.assertIn("src/lib.rs::mod schema", problems[0])
        library = "run: cargo test --locked -p registry-breg --features schema --lib\n"
        self.assertEqual(self.problems(library, tests), [])

    def test_unselected_target_is_reported_once_not_per_test(self) -> None:
        tests = {
            "tests/postgres_load.rs": """
                #![cfg(feature = "postgres-test")]

                #[cfg(feature = "schema")]
                #[test]
                fn loads() {}
            """
        }
        problems = self.problems("", tests)
        self.assertEqual(len(problems), 1)
        self.assertIn("tests/postgres_load.rs:", problems[0])

    def test_known_unselected_entries_are_accepted_until_they_go_stale(self) -> None:
        tests = {
            "tests/fixtures.rs": '#[cfg(feature = "postgres-test")]\n#[test]\nfn database_only() {}\n'
        }
        known = {"tests/fixtures.rs::database_only": "no database lane names this target"}
        self.assertEqual(self.problems("", tests, known), [])

        selecting = (
            "run: cargo test --locked -p registry-breg --features postgres-test,tooling "
            "--test fixtures\n"
        )
        stale = self.problems(selecting, tests, known)
        self.assertEqual(len(stale), 1)
        self.assertIn("tests/fixtures.rs::database_only", stale[0])
        self.assertIn("KNOWN_UNSELECTED", stale[0])

        removed = self.problems("", {"tests/fixtures.rs": "#[test]\nfn plain() {}\n"}, known)
        self.assertEqual(len(removed), 1)
        self.assertIn("KNOWN_UNSELECTED", removed[0])


class RepositoryTests(unittest.TestCase):
    def test_every_gated_test_in_the_repository_is_selected_or_recorded(self) -> None:
        self.assertEqual(gate.repository_violations(ROOT), [])

    def test_schema_gated_tests_depend_on_the_schema_step(self) -> None:
        tests = gate.gated_tests(ROOT / "crates" / gate.CRATE)
        invocations, _ = gate.ci_invocations(ROOT)
        without = [
            invocation
            for invocation in invocations
            if not (invocation.lib and "schema" in invocation.features)
        ]
        self.assertLess(len(without), len(invocations))
        problems = "\n".join(gate.violations(tests, without, gate.KNOWN_UNSELECTED))
        for key in (
            "tests/action_evidence_compiler.rs::published_authoring_schema_accepts_farmer_and_rejects_every_other_abi",
            "src/lib.rs::mod schema",
            "src/runtime_config.rs::mod schema_tests",
        ):
            with self.subTest(key=key):
                self.assertIn(key, problems)

    def test_shard_model_names_the_shard_that_owns_the_crate(self) -> None:
        self.assertIn(gate.CRATE, SHARDS["breg"])
        self.assertEqual(gate.shard_packages(SHARDS), SHARDS["breg"])

    def test_workflow_runs_the_gate_its_tests_and_the_schema_step(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("run: python3 .github/scripts/test_check_breg_gated_tests.py", workflow)
        self.assertIn("run: python3 .github/scripts/check_breg_gated_tests.py", workflow)
        self.assertIn(SCHEMA_STEP, workflow)

    def test_every_invocation_source_exists(self) -> None:
        for source in gate.INVOCATION_SOURCES:
            with self.subTest(source=source):
                self.assertTrue((ROOT / source).is_file())


if __name__ == "__main__":
    unittest.main()
