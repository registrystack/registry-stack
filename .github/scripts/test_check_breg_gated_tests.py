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

BINARY_MANIFEST = """
    [package]
    name = "registry-breg"

    [features]
    default = ["wasm"]
    runtime = []
    schema = []
    tooling = []
    wasm = []

    [[bin]]
    name = "breg"
    path = "src/main.rs"
    required-features = ["runtime"]

    [[bin]]
    name = "tool"
    required-features = ["tooling"]
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
GATED_UNIT_TEST = '#[cfg(feature = "schema")]\n#[test]\nfn schema_only() {}\n'


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

    def test_target_predicates_answer_for_the_linux_ci_target(self) -> None:
        on = frozenset({"schema"})
        for expression in (
            "not(windows)",
            'target_os = "linux"',
            'target_family = "unix"',
            'all(feature = "schema", not(target_os = "macos"))',
            'any(windows, feature = "schema")',
        ):
            with self.subTest(expression=expression):
                self.assertTrue(gate.cfg_holds(expression, on))
        for expression in (
            "windows",
            "not(unix)",
            'target_os = "macos"',
            'target_family = "windows"',
            'all(feature = "schema", windows)',
        ):
            with self.subTest(expression=expression):
                self.assertFalse(gate.cfg_holds(expression, on))

    def test_unknown_predicate_is_refused_instead_of_guessed(self) -> None:
        for expression in (
            'all(feature = "schema", debug_assertions)',
            'target_arch = "x86_64"',
            'target_feature = "sse2"',
            'unix = "linux"',
            "all(feature",
        ):
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
        self.assertEqual(invocation.bins, frozenset())

    def test_no_target_flags_select_the_library_and_every_other_target(self) -> None:
        invocation = read("cargo test --locked -p registry-breg --features registry-breg/schema")
        self.assertIsNotNone(invocation)
        self.assertEqual(invocation.features, frozenset({"default", "schema", "wasm"}))
        self.assertTrue(invocation.lib)
        self.assertIsNone(invocation.tests)
        self.assertIsNone(invocation.bins)

    def test_binary_targets_are_selected_by_name_or_all_together(self) -> None:
        named = read("cargo test --locked -p registry-breg --bin breg --bin tool")
        self.assertIsNotNone(named)
        self.assertEqual(named.bins, frozenset({"breg", "tool"}))
        self.assertFalse(named.lib)
        self.assertEqual(named.tests, frozenset())

        every = read("cargo test --locked -p registry-breg --lib --bins --test fixtures")
        self.assertIsNotNone(every)
        self.assertIsNone(every.bins)
        self.assertTrue(every.lib)
        self.assertEqual(every.tests, frozenset({"fixtures"}))

        self.assertIsNone(read("cargo test --locked -p registry-breg --bin"))

    def test_named_test_targets_leave_the_library_out(self) -> None:
        invocation = read(
            "cargo test --locked -p registry-breg --no-default-features "
            "--features postgres-test --test fixtures -- --include-ignored --test-threads=1"
        )
        self.assertIsNotNone(invocation)
        self.assertEqual(invocation.features, frozenset({"postgres-test", "runtime"}))
        self.assertFalse(invocation.lib)
        self.assertEqual(invocation.tests, frozenset({"fixtures"}))
        self.assertEqual(invocation.bins, frozenset())

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

    def test_source_invocations_join_folded_workflow_scalars(self) -> None:
        text = textwrap.dedent(
            """
            steps:
              - name: Folded
                run: >-
                  cargo test --locked -p registry-breg --features schema
                  --test fixtures

              - name: Literal
                run: |
                  cargo test --locked -p registry-breg --lib
                  echo done
            """
        )
        invocations, ignored = gate.source_invocations(text, "ci.yml", FEATURES)
        self.assertEqual(
            [(invocation.lib, invocation.tests) for invocation in invocations],
            [(False, frozenset({"fixtures"})), (True, frozenset())],
        )
        self.assertEqual(ignored, 0)

    def test_optional_dependency_on_the_crate_in_the_shard_is_refused(self) -> None:
        sibling = """
            [package]
            name = "registry-bregctl"

            [dependencies]
            registry-breg = { workspace = true, optional = true, features = ["schema"] }
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "crates/registry-breg/Cargo.toml", MANIFEST)
            write(root, "crates/registry-bregctl/Cargo.toml", sibling)
            with self.assertRaises(gate.GateError) as raised:
                gate.shard_invocation(root, SHARD, FEATURES)
        self.assertIn("registry-bregctl", str(raised.exception))
        self.assertIn("optional", str(raised.exception))

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
        self.assertIsNone(invocation.bins)


class ScanTests(unittest.TestCase):
    def scan(self, files: dict[str, str], manifest: str = MANIFEST) -> dict[str, gate.GatedTest]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "crates/registry-breg/Cargo.toml", manifest)
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
        self.assertIsNone(found["src/lib.rs::mod schema"].binary)
        self.assertEqual(
            found["src/postgres/config.rs::mod tests"].conditions,
            ('all(test, feature = "postgres-test")',),
        )

    def test_discovered_binary_roots_are_binary_targets_not_the_library(self) -> None:
        found = self.scan(
            {
                "src/lib.rs": GATED_UNIT_TEST,
                "src/main.rs": GATED_UNIT_TEST,
                "src/bin/tool.rs": GATED_UNIT_TEST,
                "src/bin/multi/main.rs": GATED_UNIT_TEST,
                "src/bin/multi/support.rs": GATED_UNIT_TEST,
                "src/binary.rs": GATED_UNIT_TEST,
            }
        )
        self.assertEqual(
            {key: test.binary for key, test in found.items()},
            {
                "src/lib.rs::schema_only": None,
                "src/main.rs::schema_only": "registry-breg",
                "src/bin/tool.rs::schema_only": "tool",
                "src/bin/multi/main.rs::schema_only": "multi",
                "src/bin/multi/support.rs::schema_only": "multi",
                "src/binary.rs::schema_only": None,
            },
        )
        for test in found.values():
            with self.subTest(key=test.key):
                self.assertIsNone(test.target)
                self.assertEqual(test.conditions, ('feature = "schema"',))

    def test_declared_binary_targets_carry_their_name_and_required_features(self) -> None:
        found = self.scan(
            {
                "src/main.rs": GATED_UNIT_TEST,
                "src/bin/tool.rs": "#[test]\nfn plain() {}\n",
                "src/bin/other.rs": GATED_UNIT_TEST,
            },
            BINARY_MANIFEST,
        )
        self.assertEqual(
            {key: (test.binary, test.conditions) for key, test in found.items()},
            {
                # A binary target behind `required-features` is gated as a whole.
                "src/main.rs": ("breg", ('feature = "runtime"',)),
                "src/main.rs::schema_only": (
                    "breg",
                    ('feature = "runtime"', 'feature = "schema"'),
                ),
                # A `[[bin]]` without a path claims the discovered file of its name.
                "src/bin/tool.rs": ("tool", ('feature = "tooling"',)),
                "src/bin/other.rs::schema_only": ("other", ('feature = "schema"',)),
            },
        )

    def test_autobins_off_leaves_only_declared_binary_targets(self) -> None:
        manifest = BINARY_MANIFEST.replace(
            'name = "registry-breg"\n', 'name = "registry-breg"\n    autobins = false\n'
        )
        self.assertIn("autobins = false", manifest)
        found = self.scan(
            {
                "src/main.rs": GATED_UNIT_TEST,
                "src/bin/tool.rs": GATED_UNIT_TEST,
                "src/bin/other.rs": GATED_UNIT_TEST,
            },
            manifest,
        )
        self.assertEqual(found["src/main.rs::schema_only"].binary, "breg")
        self.assertEqual(found["src/bin/tool.rs::schema_only"].binary, "tool")
        self.assertIsNone(found["src/bin/other.rs::schema_only"].binary)

    def test_declared_binary_target_without_a_file_is_refused(self) -> None:
        with self.assertRaises(gate.GateError) as raised:
            self.scan({"src/main.rs": GATED_UNIT_TEST}, BINARY_MANIFEST)
        self.assertIn("tool", str(raised.exception))

    def test_declared_binary_target_outside_src_is_refused(self) -> None:
        manifest = """
            [package]
            name = "registry-breg"

            [features]
            schema = []

            [[bin]]
            name = "tool"
            path = "cmd/tool.rs"
            required-features = ["schema"]
        """
        with self.assertRaises(gate.GateError) as raised:
            self.scan({"cmd/tool.rs": "fn main() {}\n"}, manifest)
        self.assertIn("tool", str(raised.exception))
        self.assertIn("cmd/tool.rs", str(raised.exception))

    def test_disabled_test_target_discovery_is_refused(self) -> None:
        manifest = """
            [package]
            name = "registry-breg"
            autotests = false

            [features]
            schema = []
        """
        with self.assertRaises(gate.GateError) as raised:
            self.scan({"tests/plain.rs": GATED_UNIT_TEST}, manifest)
        self.assertIn("autotests", str(raised.exception))

    def test_declared_test_target_the_gate_does_not_read_is_refused(self) -> None:
        manifest = """
            [package]
            name = "registry-breg"

            [features]
            schema = []

            [[test]]
            name = "nested"
            path = "tests/nested/main.rs"
            required-features = ["schema"]
        """
        for files in (
            {"tests/nested/main.rs": "#[test]\nfn plain() {}\n"},
            {"tests/other.rs": "#[test]\nfn plain() {}\n"},
        ):
            with self.subTest(files=sorted(files)):
                with self.assertRaises(gate.GateError) as raised:
                    self.scan(files, manifest)
                self.assertIn("nested", str(raised.exception))
                self.assertIn("tests/nested/main.rs", str(raised.exception))

    def test_blank_lines_and_comments_do_not_end_an_attribute_group(self) -> None:
        found = self.scan(
            {
                "tests/plain.rs": """
                    #[cfg(feature = "schema")]

                    #[test]
                    fn after_a_blank_line() {}

                    #[cfg(feature = "schema")]
                    /// An outer doc comment.
                    //! An inner doc comment.
                    // A plain comment.

                    #[test]
                    /** A block doc comment. */
                    fn after_line_and_block_comments() {}

                    #[cfg(feature = "schema")]
                    /*
                     * A block comment over several lines, /* nested */ once.
                     */
                    #[tokio::test]
                    async fn after_a_nested_block_comment() {}

                    #[cfg(feature = "schema")]

                    /// The blank line and this comment leave the module gated.
                    mod gated {}
                """
            }
        )
        self.assertEqual(
            sorted(found),
            [
                "tests/plain.rs::after_a_blank_line",
                "tests/plain.rs::after_a_nested_block_comment",
                "tests/plain.rs::after_line_and_block_comments",
                "tests/plain.rs::mod gated",
            ],
        )
        for test in found.values():
            with self.subTest(key=test.key):
                self.assertEqual(test.conditions, ('feature = "schema"',))

    def test_every_cfg_in_a_feature_gated_group_is_retained(self) -> None:
        found = self.scan(
            {
                "tests/plain.rs": """
                    #[cfg(feature = "schema")]
                    #[cfg(windows)]
                    #[test]
                    fn windows_only() {}

                    #[cfg(unix)]
                    #[cfg(feature = "schema")]
                    #[test]
                    fn unix_only() {}

                    #[cfg(windows)]
                    #[test]
                    fn names_no_feature() {}
                """,
                "tests/postgres_load.rs": """
                    #![cfg(feature = "postgres-test")]
                    #![cfg(target_os = "macos")]

                    #[cfg(feature = "schema")]
                    #[test]
                    fn loads() {}
                """,
                "tests/unix_only.rs": """
                    #![cfg(unix)]

                    #[cfg(feature = "schema")]
                    #[test]
                    fn runs() {}
                """,
            }
        )
        self.assertEqual(
            {key: test.conditions for key, test in found.items()},
            {
                "tests/plain.rs::windows_only": ('feature = "schema"', "windows"),
                "tests/plain.rs::unix_only": ("unix", 'feature = "schema"'),
                "tests/postgres_load.rs": (
                    'feature = "postgres-test"',
                    'target_os = "macos"',
                ),
                "tests/postgres_load.rs::loads": (
                    'feature = "postgres-test"',
                    'target_os = "macos"',
                    'feature = "schema"',
                ),
                "tests/unix_only.rs::runs": ("unix", 'feature = "schema"'),
            },
        )

    def test_tests_no_feature_set_builds_on_the_ci_target_are_out_of_scope(self) -> None:
        found = self.scan(
            {
                "tests/plain.rs": """
                    #[cfg(feature = "schema")]
                    #[cfg(windows)]
                    #[test]
                    fn windows_only() {}

                    #[cfg(all(feature = "schema", target_os = "macos"))]
                    #[test]
                    fn macos_only() {}

                    #[cfg(feature = "schema")]
                    #[cfg(not(windows))]
                    #[test]
                    fn linux_too() {}

                    #[cfg(any(feature = "schema", windows))]
                    #[test]
                    fn either() {}

                    #[cfg(not(feature = "wasm"))]
                    #[test]
                    fn without_a_feature() {}
                """
            }
        )
        self.assertEqual(
            gate.out_of_scope(found.values(), FEATURES),
            [
                (
                    "tests/plain.rs::windows_only: no feature set satisfies "
                    'feature = "schema" and windows on the Linux CI target'
                ),
                (
                    "tests/plain.rs::macos_only: no feature set satisfies "
                    'all(feature = "schema", target_os = "macos") on the Linux CI target'
                ),
            ],
        )

    def test_conditions_an_implied_feature_contradicts_are_out_of_scope(self) -> None:
        found = self.scan(
            {
                "tests/plain.rs": """
                    #[cfg(all(feature = "postgres-test", not(feature = "runtime")))]
                    #[test]
                    fn never_built() {}

                    #[cfg(all(feature = "runtime", not(feature = "postgres-test")))]
                    #[test]
                    fn runtime_alone() {}
                """
            }
        )
        self.assertEqual(
            gate.out_of_scope(found.values(), FEATURES),
            [
                (
                    "tests/plain.rs::never_built: no feature set satisfies "
                    'all(feature = "postgres-test", not(feature = "runtime")) '
                    "on the Linux CI target"
                ),
            ],
        )

    def test_test_attribute_behind_a_feature_cfg_attr_is_refused(self) -> None:
        for attribute in (
            '#[cfg_attr(feature = "schema", test)]',
            '#[cfg_attr(feature = "schema", allow(dead_code), tokio::test)]',
            '#[cfg_attr(\n    all(feature = "schema", unix),\n    test\n)]',
        ):
            with self.subTest(attribute=attribute):
                with self.assertRaises(gate.GateError) as raised:
                    self.scan({"tests/fixtures.rs": f"{attribute}\nfn conditional() {{}}\n"})
                self.assertIn("tests/fixtures.rs:1", str(raised.exception))
                self.assertIn("cfg_attr", str(raised.exception))

    def test_cfg_behind_a_feature_cfg_attr_is_refused(self) -> None:
        text = (
            '#[cfg(feature = "schema")]\n'
            '#[cfg_attr(feature = "schema", cfg(feature = "tooling"))]\n'
            "#[test]\nfn doubly_gated() {}\n"
        )
        with self.assertRaises(gate.GateError) as raised:
            self.scan({"tests/fixtures.rs": text})
        self.assertIn("tests/fixtures.rs:2", str(raised.exception))
        self.assertIn("cfg_attr", str(raised.exception))

    def test_cfg_attribute_spelled_with_inner_whitespace_is_refused(self) -> None:
        for attribute in (
            '#[ cfg(feature = "schema")]',
            '#[cfg (feature = "schema")]',
            '# [cfg(feature = "schema")]',
            '#![ cfg(feature = "schema")]',
            '#[cfg\n(feature = "schema")]',
            '#[ cfg_attr(feature = "schema", test)]',
        ):
            with self.subTest(attribute=attribute):
                with self.assertRaises(gate.GateError) as raised:
                    self.scan({"tests/fixtures.rs": f"{attribute}\n#[test]\nfn spaced() {{}}\n"})
                self.assertIn("tests/fixtures.rs:1", str(raised.exception))

    def test_cfg_attr_that_adds_no_test_attribute_is_read_past(self) -> None:
        found = self.scan(
            {
                "tests/plain.rs": """
                    #[cfg_attr(feature = "schema", derive(Debug))]
                    struct Plain;

                    #[cfg_attr(all(feature = "schema", test), allow(dead_code))]
                    fn helper() {}

                    #[cfg_attr(unix, test)]
                    fn unix_test() {}

                    #[cfg(feature = "schema")]
                    #[cfg_attr(test, allow(dead_code))]
                    #[test]
                    fn schema_only() {}
                """
            }
        )
        self.assertEqual(sorted(found), ["tests/plain.rs::schema_only"])

    def test_target_left_out_of_the_default_test_set_is_refused(self) -> None:
        base = """
            [package]
            name = "registry-breg"

            [features]
            schema = []
        """
        for target, name in (
            ('[lib]\ntest = false\n', "the library"),
            ('[[bin]]\nname = "breg"\npath = "src/main.rs"\ntest = false\n', "breg"),
            ('[[test]]\nname = "fixtures"\ntest = false\n', "fixtures"),
        ):
            with self.subTest(target=name):
                manifest = textwrap.dedent(base) + "\n" + target
                with self.assertRaises(gate.GateError) as raised:
                    self.scan(
                        {"src/main.rs": GATED_UNIT_TEST, "tests/fixtures.rs": GATED_UNIT_TEST},
                        manifest,
                    )
                self.assertIn(name, str(raised.exception))
                self.assertIn("test = false", str(raised.exception))

    def test_cfg_attribute_the_scanner_cannot_read_is_refused(self) -> None:
        text = '#[test]\n#[cfg(feature = "schema")] fn shared_line() {}\n'
        with self.assertRaises(gate.GateError) as raised:
            self.scan({"tests/fixtures.rs": text})
        self.assertIn("tests/fixtures.rs:2", str(raised.exception))

    def test_block_comment_closing_on_a_line_with_code_is_refused(self) -> None:
        text = '#[cfg(feature = "schema")]\n/* why */ #[test]\nfn shared_line() {}\n'
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

    def test_test_out_of_scope_on_the_ci_target_needs_no_invocation(self) -> None:
        tests = {
            "tests/plain.rs": """
                #[cfg(feature = "schema")]
                #[cfg(windows)]
                #[test]
                fn windows_only() {}

                #[cfg(feature = "schema")]
                #[cfg(not(windows))]
                #[test]
                fn linux_too() {}
            """
        }
        problems = self.problems("", tests)
        self.assertEqual(len(problems), 1)
        self.assertIn("tests/plain.rs::linux_too", problems[0])
        self.assertIn('feature = "schema" and not(windows)', problems[0])

        selecting = "run: cargo test --locked -p registry-breg --features schema --test plain\n"
        self.assertEqual(self.problems(selecting, tests), [])

        # Recording a test the gate does not hold is refused like any stale entry.
        known = {"tests/plain.rs::windows_only": "runs on Windows only"}
        stale = self.problems(selecting, tests, known)
        self.assertEqual(len(stale), 1)
        self.assertIn("tests/plain.rs::windows_only", stale[0])
        self.assertIn("KNOWN_UNSELECTED", stale[0])
        self.assertIn("out of scope", stale[0])

    def test_conditions_an_implied_feature_contradicts_need_no_invocation(self) -> None:
        tests = {
            "tests/plain.rs": """
                #[cfg(all(feature = "postgres-test", not(feature = "runtime")))]
                #[test]
                fn never_built() {}
            """
        }
        self.assertEqual(self.problems("", tests), [])

    def test_unknown_predicate_beside_a_feature_stops_the_gate(self) -> None:
        tests = {
            "tests/plain.rs": """
                #[cfg(feature = "schema")]
                #[cfg(target_arch = "wasm32")]
                #[test]
                fn wasm_only() {}
            """
        }
        selecting = "run: cargo test --locked -p registry-breg --features schema --test plain\n"
        with self.assertRaises(gate.GateError) as raised:
            self.problems(selecting, tests)
        self.assertIn("`target_arch`", str(raised.exception))

    def test_gated_library_module_needs_a_library_invocation(self) -> None:
        tests = {"src/lib.rs": '#[cfg(feature = "schema")]\nmod schema;\n'}
        named = "run: cargo test --locked -p registry-breg --features schema --test fixtures\n"
        problems = self.problems(named, tests)
        self.assertEqual(len(problems), 1)
        self.assertIn("src/lib.rs::mod schema", problems[0])
        library = "run: cargo test --locked -p registry-breg --features schema --lib\n"
        self.assertEqual(self.problems(library, tests), [])

    def test_gated_binary_test_needs_an_invocation_that_builds_the_binary(self) -> None:
        tests = {"src/main.rs": GATED_UNIT_TEST}
        for workflow in (
            # The shard builds the binary without the feature.
            "",
            # `--lib` and `--test` do not build the binary's tests.
            "run: cargo test --locked -p registry-breg --features schema --lib\n",
            "run: cargo test --locked -p registry-breg --features schema --lib --test fixtures\n",
            # Naming another binary, or building this one without the feature,
            # still leaves the test out.
            "run: cargo test --locked -p registry-breg --features schema --bin other\n",
            "run: cargo test --locked -p registry-breg --bins\n",
        ):
            with self.subTest(workflow=workflow):
                problems = self.problems(workflow, tests)
                self.assertEqual(len(problems), 1)
                self.assertIn("src/main.rs::schema_only", problems[0])
                self.assertIn("binary target registry-breg", problems[0])

        for workflow in (
            "run: cargo test --locked -p registry-breg --features schema --bins\n",
            "run: cargo test --locked -p registry-breg --features schema --lib --bin registry-breg\n",
            "run: cargo test --locked -p registry-breg --features schema\n",
        ):
            with self.subTest(workflow=workflow):
                self.assertEqual(self.problems(workflow, tests), [])

    def test_binary_selection_does_not_cover_the_library(self) -> None:
        tests = {"src/lib.rs": '#[cfg(feature = "schema")]\nmod schema;\n'}
        binaries = "run: cargo test --locked -p registry-breg --features schema --bins\n"
        problems = self.problems(binaries, tests)
        self.assertEqual(len(problems), 1)
        self.assertIn("src/lib.rs::mod schema", problems[0])
        self.assertIn("the library", problems[0])

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
        problems = "\n".join(
            gate.violations(
                tests, without, gate.KNOWN_UNSELECTED, gate.feature_table(ROOT / "crates" / gate.CRATE)
            )
        )
        for key in (
            "tests/action_evidence_compiler.rs::published_authoring_schema_accepts_evidence_action_and_rejects_every_other_abi",
            "src/lib.rs::mod schema",
            "src/runtime_config.rs::mod schema_tests",
        ):
            with self.subTest(key=key):
                self.assertIn(key, problems)

    def test_runtime_binary_is_its_own_target_behind_its_required_features(self) -> None:
        tests = {test.key: test for test in gate.gated_tests(ROOT / "crates" / gate.CRATE)}
        binary = tests["src/main.rs"]
        self.assertEqual(binary.binary, "breg")
        self.assertEqual(binary.conditions, ('feature = "runtime"',))
        invocations, _ = gate.ci_invocations(ROOT)
        targeted = [invocation for invocation in invocations if invocation.bins is not None]
        self.assertTrue(targeted)
        self.assertFalse(any(gate.selects(invocation, binary) for invocation in targeted))
        self.assertTrue(any(gate.selects(invocation, binary) for invocation in invocations))

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
