"""Unit tests for the Scheduling contracts validator.

The validator is exercised against synthetic trees so a broken contract
shape is caught without touching the real files, the same way the sibling
products test their contract tooling.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
import tempfile

import yaml

sys.dont_write_bytecode = True
_SCRIPT_PATH = Path(__file__).with_name("validate_contracts.py")
_SPEC = importlib.util.spec_from_file_location("scheduling_validate_contracts", _SCRIPT_PATH)
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


def matrix_row(
    row_id: str = "SCHEDULING-SEC-01",
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


def deferred_row(
    row_id: str = "SCHEDULING-DEF-01",
    recorded_in: str = "products/scheduling/NOTES.md",
) -> dict:
    return {
        "id": row_id,
        "subject": "A subject",
        "reason": "A reason.",
        "compensatingControl": "A control.",
        "recordedIn": recorded_in,
    }


def traceability_entry(
    entry_id: str = "SCHEDULING-SEC-01",
    test_path: str = "crates/x/src/a.rs",
    test_name: str = "the_cited_test_exists",
) -> dict:
    return {
        "id": entry_id,
        "tests": [{"path": test_path, "name": test_name}],
    }


def decision_row(
    row_id: str = "SCHEDULING-DEC-01",
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
            "product": "scheduling",
            "invariants": [matrix_row()],
            "deferred": [deferred_row()],
        },
        "security-test-traceability.yaml": {
            "contract": "registry.scheduling.security-test-traceability/v1",
            "entries": [traceability_entry()],
        },
        "recorded-decisions.yaml": {
            "apiVersion": "registry.registrystack.org/product-contract/v1",
            "purpose": "A purpose.",
            "decisions": [decision_row()],
        },
    }


class Resolver:
    """A synthetic repository tree backed by files on disk."""

    def __init__(self, files: dict[str, str]) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="scheduling-contracts-test."))
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
    return validator.validate(
        tree["security-invariant-matrix.yaml"],
        tree["security-test-traceability.yaml"],
        tree["recorded-decisions.yaml"],
        Resolver(files),
    )


DEFAULT_FILES = {
    "crates/x/src/a.rs": RUST_TEST_FILE,
    "products/scheduling/NOTES.md": RECORDED_IN_FILE,
}


class MatrixValidation(unittest.TestCase):
    def test_a_consistent_tree_has_no_violations(self) -> None:
        self.assertEqual(validate_tree(happy_tree(), DEFAULT_FILES), [])

    def test_a_partial_invariant_without_its_note_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-invariant-matrix.yaml"]["invariants"][0]["state"] = "partial"
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(any("partialNote" in violation or "partial invariant" in violation
                            for violation in violations), violations)

    def test_a_cited_test_the_file_does_not_define_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-invariant-matrix.yaml"]["invariants"][0]["negativeTest"]["name"] = (
            "a_test_that_does_not_exist"
        )
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(
            any("defines no test function" in violation for violation in violations),
            violations,
        )

    def test_a_cited_file_that_does_not_exist_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-invariant-matrix.yaml"]["invariants"][0]["negativeTest"]["path"] = (
            "crates/x/src/missing.rs"
        )
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(
            any("does not exist" in violation for violation in violations), violations
        )

    def test_a_deferral_pointing_at_no_file_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-invariant-matrix.yaml"]["deferred"][0]["recordedIn"] = (
            "products/scheduling/ABSENT.md"
        )
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(
            any("recordedIn file" in violation for violation in violations), violations
        )

    def test_a_duplicate_invariant_id_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-invariant-matrix.yaml"]["invariants"].append(matrix_row())
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(
            any("listed more than once" in violation for violation in violations),
            violations,
        )


class TraceabilityValidation(unittest.TestCase):
    def test_an_invariant_without_an_entry_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-invariant-matrix.yaml"]["invariants"].append(
            matrix_row(row_id="SCHEDULING-SEC-02", test_path="crates/x/src/a.rs")
        )
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(
            any("SCHEDULING-SEC-02 has no entry" in violation for violation in violations),
            violations,
        )

    def test_an_entry_matching_no_invariant_is_refused(self) -> None:
        tree = happy_tree()
        tree["security-test-traceability.yaml"]["entries"].append(
            traceability_entry(entry_id="SCHEDULING-SEC-09")
        )
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(
            any("matches no matrix invariant" in violation for violation in violations),
            violations,
        )

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
        self.assertTrue(
            any("neither Rust nor Python" in violation for violation in violations),
            violations,
        )


class DecisionValidation(unittest.TestCase):
    def test_a_decision_without_evidence_is_refused(self) -> None:
        tree = happy_tree()
        tree["recorded-decisions.yaml"]["decisions"][0]["evidence"] = []
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(
            any("evidence test" in violation for violation in violations), violations
        )

    def test_a_decision_with_dangling_evidence_is_refused(self) -> None:
        tree = happy_tree()
        tree["recorded-decisions.yaml"]["decisions"][0]["evidence"][0]["name"] = "absent"
        violations = validate_tree(tree, DEFAULT_FILES)
        self.assertTrue(
            any("defines no test function" in violation for violation in violations),
            violations,
        )


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
