"""Unit tests for the Messaging contracts validator.

The validator is exercised against synthetic trees so a broken contract
shape is caught without touching the real files, the same way the sibling
products test their contract tooling.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.dont_write_bytecode = True
_SCRIPT_PATH = Path(__file__).with_name("validate_contracts.py")
_SPEC = importlib.util.spec_from_file_location("messaging_validate_contracts", _SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
validator = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(validator)

RUST_TEST_FILE = """\
#[test]
fn the_cited_test_exists() {}
"""

PYTHON_TEST_FILE = """\
import unittest


class Tests(unittest.TestCase):
    def the_cited_test_exists(self) -> None:
        pass
"""

RECORDED_IN_FILE = "# Notes\n"


def sec(number: int) -> str:
    return f"MESSAGING-SEC-{number:02d}"


def matrix_row(
    row_id: str = "MESSAGING-SEC-01",
    state: str = "enforced",
    partial_note: str | None = None,
    test_path: str = "crates/x/src/a.rs",
    test_name: str = "the_cited_test_exists",
) -> dict:
    row = {
        "id": row_id,
        "state": state,
        "threat": "A threat.",
        "enforcementPoint": "An enforcement point.",
        "refusal": "A refusal.",
        "negativeTest": {"path": test_path, "name": test_name},
    }
    if partial_note is not None:
        row["partialNote"] = partial_note
    return row


def pending_row(row_id: str, slice_name: str = "S3") -> dict:
    return {
        "id": row_id,
        "state": "pending",
        "plannedSlice": slice_name,
        "threat": "A threat.",
        "enforcementPoint": "An enforcement point.",
        "refusal": "A refusal.",
        "pendingNote": "What the slice will prove.",
    }


def deferred_row(
    row_id: str = "MESSAGING-DEF-01",
    recorded_in: str = "products/messaging/NOTES.md",
) -> dict:
    return {
        "id": row_id,
        "subject": "A subject",
        "reason": "A reason.",
        "compensatingControl": "A control.",
        "recordedIn": recorded_in,
    }


def traceability_entry(
    entry_id: str = "MESSAGING-SEC-01",
    test_path: str = "crates/x/src/a.rs",
    test_name: str = "the_cited_test_exists",
) -> dict:
    return {
        "id": entry_id,
        "tests": [{"path": test_path, "name": test_name}],
    }


def decision_row(
    row_id: str = "MESSAGING-DEC-01",
    test_path: str = "crates/x/src/a.rs",
    test_name: str = "the_cited_test_exists",
) -> dict:
    return {
        "id": row_id,
        "subject": "A subject",
        "decision": "A decision.",
        "reasoning": "Reasoning.",
        "evidence": [{"path": test_path, "name": test_name}],
    }


def happy_tree() -> dict[str, dict]:
    return {
        "security-invariant-matrix.yaml": {
            "apiVersion": "registry.registrystack.org/product-contract/v1",
            "product": "messaging",
            "invariants": [matrix_row()] + [pending_row(sec(number)) for number in range(2, 11)],
            "deferred": [deferred_row()],
        },
        "security-test-traceability.yaml": {
            "contract": "registry.messaging.security-test-traceability/v1",
            "entries": [traceability_entry()],
        },
        "recorded-decisions.yaml": {
            "apiVersion": "registry.registrystack.org/product-contract/v1",
            "product": "messaging",
            "purpose": "A purpose.",
            "decisions": [decision_row()],
        },
    }


class Resolver:
    """A synthetic repository tree backed by files on disk."""

    def __init__(self, files: dict[str, str]) -> None:
        self._directory = tempfile.TemporaryDirectory(prefix="messaging-contracts-test.")
        self.root = Path(self._directory.name)
        for relative, text in files.items():
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")

    def __call__(self, path: str) -> str | None:
        candidate = self.root / path
        if not candidate.is_file():
            return None
        return candidate.read_text(encoding="utf-8")


def validate_tree(tree: dict[str, dict], files: dict[str, str]) -> list[str]:
    resolver = Resolver(files)
    try:
        return validator.validate(
            tree["security-invariant-matrix.yaml"],
            tree["security-test-traceability.yaml"],
            tree["recorded-decisions.yaml"],
            resolver,
        )
    finally:
        resolver._directory.cleanup()


DEFAULT_FILES = {
    "crates/x/src/a.rs": RUST_TEST_FILE,
    "products/messaging/NOTES.md": RECORDED_IN_FILE,
}


def invariant(tree: dict[str, dict], index: int) -> dict:
    return tree["security-invariant-matrix.yaml"]["invariants"][index]


class RunnerValidation(unittest.TestCase):
    def test_python_discovery_rejects_an_ordinary_method(self) -> None:
        with tempfile.TemporaryDirectory(prefix="messaging-python-inventory.") as directory:
            root = Path(directory)
            source = root / "test_fixture.py"
            source.write_text(
                'import unittest\nclass Tests(unittest.TestCase):\n'
                '    def test_selectable(self): raise AssertionError("must not execute")\n'
                '    def ordinary_method(self): pass\n', encoding="utf-8",
            )
            self.assertEqual(validator.runner_violations(root, [
                {"path": source.name, "name": "test_selectable"},
            ]), [])
            failures = validator.runner_violations(root, [
                {"path": source.name, "name": "ordinary_method"},
            ])
            self.assertEqual(len(failures), 1, failures)
            self.assertIn("not selectable", failures[0])

    def test_rust_citation_must_be_listed_by_its_runner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="messaging-runner-test.") as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text(
                '[package]\nname = "citation-fixture"\nversion = "0.1.0"\nedition = "2021"\n'
                '[workspace]\n[features]\nschema = []\n', encoding="utf-8",
            )
            (root / "Cargo.lock").write_text(
                'version = 3\n[[package]]\nname = "citation-fixture"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (root / "src/lib.rs").write_text(
                '#[test]\nfn selectable() { panic!("inventory must not execute tests"); }\n'
                '#[cfg(feature = "schema")]\n#[test]\n'
                'fn gated() { panic!("inventory must not execute tests"); }\n'
                'pub fn ordinary_function() {}\n', encoding="utf-8",
            )
            self.assertEqual(validator.runner_violations(root, [
                {"path": "src/lib.rs", "name": "selectable"},
            ]), [])
            failures = validator.runner_violations(root, [
                {"path": "src/lib.rs", "name": "ordinary_function"},
            ])
            self.assertEqual(len(failures), 1, failures)
            self.assertIn("not selectable", failures[0])
            gated = {"path": "src/lib.rs", "name": "gated"}
            self.assertTrue(validator.runner_violations(root, [gated]))
            gated["features"] = ["schema"]
            self.assertEqual(validator.runner_violations(root, [gated]), [])


class MatrixValidation(unittest.TestCase):
    def test_a_consistent_tree_has_no_violations(self) -> None:
        self.assertEqual(validate_tree(happy_tree(), DEFAULT_FILES), [])

    def test_a_missing_invariant_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-invariant-matrix.yaml"]["invariants"].pop()
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("exactly MESSAGING-SEC-01 to MESSAGING-SEC-10" in violation
                            for violation in violations), violations)

    def test_an_eleventh_invariant_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-invariant-matrix.yaml"]["invariants"].append(pending_row(sec(11)))
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("exactly MESSAGING-SEC-01" in violation
                            for violation in violations), violations)

    def test_an_unknown_state_is_refused(self) -> None:
        tree = happy_tree()
        invariant(tree, 1)["state"] = "planned"
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("state must be" in violation for violation in violations), violations)

    def test_a_pending_invariant_must_name_its_slice_and_note(self) -> None:
        tree = happy_tree()
        del invariant(tree, 1)["plannedSlice"]
        invariant(tree, 2)["plannedSlice"] = "S1"
        del invariant(tree, 3)["pendingNote"]
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertEqual(
            sum("must name its slice" in violation for violation in violations), 2, violations
        )
        self.assertTrue(any("what its slice will prove" in violation
                            for violation in violations), violations)

    def test_a_pending_invariant_cites_no_test(self) -> None:
        tree = happy_tree()
        invariant(tree, 1)["negativeTest"] = {
            "path": "crates/x/src/a.rs", "name": "the_cited_test_exists",
        }
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("pending invariant cites no test" in violation
                            for violation in violations), violations)

    def test_an_earned_invariant_names_no_planned_slice(self) -> None:
        tree = happy_tree()
        invariant(tree, 0)["plannedSlice"] = "S3"
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("only a pending invariant" in violation
                            for violation in violations), violations)

    def test_an_earned_invariant_needs_its_negative_test(self) -> None:
        tree = happy_tree()
        del invariant(tree, 0)["negativeTest"]
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("negativeTest" in violation for violation in violations), violations)

    def test_a_partial_invariant_without_its_note_is_refused(self) -> None:
        tree = happy_tree()
        invariant(tree, 0)["state"] = "partial"
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("partial invariant" in violation for violation in violations),
                        violations)

    def test_a_missing_threat_is_refused_even_when_pending(self) -> None:
        tree = happy_tree()
        invariant(tree, 4)["threat"] = " "
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("threat is required" in violation for violation in violations),
                        violations)

    def test_a_cited_test_the_file_does_not_define_is_refused(self) -> None:
        tree = happy_tree()
        invariant(tree, 0)["negativeTest"]["name"] = "a_test_that_does_not_exist"
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("defines no test function" in violation
                            for violation in violations), violations)

    def test_a_cited_file_that_does_not_exist_is_refused(self) -> None:
        tree = happy_tree()
        invariant(tree, 0)["negativeTest"]["path"] = "crates/x/src/missing.rs"
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("does not exist" in violation for violation in violations),
                        violations)

    def test_an_absolute_or_escaping_path_is_refused(self) -> None:
        for path in ("/etc/passwd.rs", "crates/../../outside.rs"):
            tree = happy_tree()
            invariant(tree, 0)["negativeTest"]["path"] = path
            violations = validate_tree(tree, DEFAULT_FILES)
            self.assertTrue(any("repository-relative" in violation
                                for violation in violations), violations)

    def test_a_deferral_pointing_at_no_file_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-invariant-matrix.yaml"]["deferred"][0]["recordedIn"] = (
            "products/messaging/ABSENT.md"
        )
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("recordedIn file" in violation for violation in violations),
                        violations)

    def test_a_duplicate_invariant_id_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-invariant-matrix.yaml"]["invariants"].insert(1, matrix_row())
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("listed more than once" in violation
                            for violation in violations), violations)


class TraceabilityValidation(unittest.TestCase):
    def test_an_earned_invariant_without_an_entry_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-invariant-matrix.yaml"]["invariants"][1] = matrix_row(row_id=sec(2))
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("MESSAGING-SEC-02 has no entry" in violation
                            for violation in violations), violations)

    def test_an_entry_for_a_pending_invariant_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-test-traceability.yaml"]["entries"].append(
            traceability_entry(entry_id=sec(3))
        )
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("pending invariant" in violation for violation in violations),
                        violations)

    def test_an_entry_matching_no_invariant_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-test-traceability.yaml"]["entries"].append(
            traceability_entry(entry_id="MESSAGING-SEC-42")
        )
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("matches no matrix invariant" in violation
                            for violation in violations), violations)

    def test_a_python_citation_resolves_through_def(self) -> None:
        tree = happy_tree()
        tree["security-test-traceability.yaml"]["entries"][0]["tests"] = [
            {"path": "products/x/test_y.py", "name": "the_cited_test_exists"}
        ]
        files = dict(DEFAULT_FILES)
        files["products/x/test_y.py"] = PYTHON_TEST_FILE
        self.assertEqual(validate_tree(tree, files), [])

    def test_a_citation_in_a_file_of_no_known_kind_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-test-traceability.yaml"]["entries"][0]["tests"] = [
            {"path": "products/x/notes.txt", "name": "the_cited_test_exists"}
        ]
        files = dict(DEFAULT_FILES)
        files["products/x/notes.txt"] = "fn the_cited_test_exists(\n"
        violations = validate_tree(tree, files)
        self.assertTrue(any("neither Rust nor Python" in violation
                            for violation in violations), violations)


class DecisionValidation(unittest.TestCase):
    def test_a_decision_without_evidence_is_refused(self) -> None:
        tree = happy_tree()
        tree["recorded-decisions.yaml"]["decisions"][0]["evidence"] = []
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("evidence test" in violation for violation in violations),
                        violations)

    def test_a_decision_with_dangling_evidence_is_refused(self) -> None:
        tree = happy_tree()
        tree["recorded-decisions.yaml"]["decisions"][0]["evidence"][0]["name"] = "absent"
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("defines no test function" in violation
                            for violation in violations), violations)

    def test_decisions_must_name_the_product(self) -> None:
        tree = happy_tree()
        tree["recorded-decisions.yaml"]["product"] = "scheduling"
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertIn("decisions: product must be messaging", violations)


class CommittedContracts(unittest.TestCase):
    """The committed contract files themselves pass the validator."""

    def test_committed_files_validate(self) -> None:
        contracts_dir = Path(__file__).resolve().parent.parent / "contracts"
        root = contracts_dir.parents[2]

        def resolve(path: str) -> str | None:
            candidate = root / path
            if not candidate.is_file():
                return None
            return candidate.read_text(encoding="utf-8")

        loaded = {}
        for name in (
            "security-invariant-matrix.yaml",
            "security-test-traceability.yaml",
            "recorded-decisions.yaml",
        ):
            with (contracts_dir / name).open(encoding="utf-8") as handle:
                loaded[name] = yaml.safe_load(handle)
        violations = validator.validate(
            loaded["security-invariant-matrix.yaml"],
            loaded["security-test-traceability.yaml"],
            loaded["recorded-decisions.yaml"],
            resolve,
        )
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
