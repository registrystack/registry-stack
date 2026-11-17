#!/usr/bin/env python3
"""Regression tests for the Adapter Camel port-table evidence gate."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("check-port-table.py")
SPEC = importlib.util.spec_from_file_location("check_port_table", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECK_PORT_TABLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK_PORT_TABLE)


INGESTION_CONCEPTS = (
    "file (job source) [ingestion]",
    "CSV data format [ingestion]",
    "JSONL decoder [ingestion]",
    "SQL (read-only job source) [ingestion]",
    "sftp (job source) [ingestion]",
    "pollEnrich (job only) [ingestion]",
)


class RustTestFunctionTests(unittest.TestCase):
    def test_resolves_shared_engine_facade_and_job_tests_at_their_owning_paths(self) -> None:
        self.assertTrue(
            CHECK_PORT_TABLE.function_exists(
                "engine:src/exchange.rs:headers_are_case_insensitive"
            )
        )
        self.assertTrue(
            CHECK_PORT_TABLE.function_exists(
                "facade:tests/camel_header_filter.rs:only_listed_request_headers_are_sent"
            )
        )
        self.assertTrue(
            CHECK_PORT_TABLE.function_exists(
                "job:src/sftp_source.rs:done_file_gates_partial_file_and_completed_file_is_read_only"
            )
        )

    def test_rejects_a_production_function(self) -> None:
        source = "pub fn send_request() {}\n"

        self.assertFalse(
            CHECK_PORT_TABLE.has_rust_test_function(source, "send_request")
        )

    def test_rejects_an_unattributed_helper_in_a_test_module(self) -> None:
        source = """
#[cfg(test)]
mod tests {
    fn fixture() {}
}
"""

        self.assertFalse(CHECK_PORT_TABLE.has_rust_test_function(source, "fixture"))

    def test_accepts_a_plain_test_function(self) -> None:
        source = """
#[test]
fn route_round_trips() {}
"""

        self.assertTrue(
            CHECK_PORT_TABLE.has_rust_test_function(source, "route_round_trips")
        )

    def test_accepts_a_multiline_tokio_test_attribute_on_an_async_function(self) -> None:
        source = """
#[tokio::test(
    flavor = "multi_thread",
    worker_threads = 2,
)]
async fn retries_once() {}
"""

        self.assertTrue(CHECK_PORT_TABLE.has_rust_test_function(source, "retries_once"))

    def test_does_not_reuse_an_attribute_from_an_earlier_function(self) -> None:
        source = """
#[test]
fn actual_test() {}

fn helper() {}
"""

        self.assertFalse(CHECK_PORT_TABLE.has_rust_test_function(source, "helper"))

    def test_accepts_documentation_between_attribute_and_function(self) -> None:
        source = """
#[tokio::test]
/// The pinned upstream method this case ports.
async fn refuses_redirects() {}
"""
        self.assertTrue(
            CHECK_PORT_TABLE.has_rust_test_function(source, "refuses_redirects")
        )

    def test_documentation_cannot_supply_a_test_attribute(self) -> None:
        source = """
/// An example annotation: #[test]
fn helper() {}
"""
        self.assertFalse(CHECK_PORT_TABLE.has_rust_test_function(source, "helper"))

    def test_ignores_test_attributes_inside_comments(self) -> None:
        source = """
// #[test]
fn commented_out_test() {}
"""

        self.assertFalse(
            CHECK_PORT_TABLE.has_rust_test_function(source, "commented_out_test")
        )


class PortTableDataTests(unittest.TestCase):
    def load(self, text: str):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "table.yaml"
            path.write_text(text, encoding="utf-8")
            return CHECK_PORT_TABLE.load_rows(path)

    def test_the_port_table_is_a_yaml_file_beside_the_script(self) -> None:
        self.assertEqual(
            CHECK_PORT_TABLE.PORT_TABLE,
            SCRIPT.with_name("camel-port-table.yaml"),
        )

    def test_the_table_carries_every_row_with_five_cells(self) -> None:
        rows, problems = CHECK_PORT_TABLE.load_rows(CHECK_PORT_TABLE.PORT_TABLE)
        self.assertEqual(problems, [])
        self.assertEqual(len(rows), 47)
        self.assertTrue(all(len(cells) == 5 for _, cells in rows))
        increments = sorted(int(cells[4]) for _, cells in rows)
        self.assertEqual(
            {inc: increments.count(inc) for inc in set(increments)},
            {0: 5, 1: 32, 2: 1, 3: 1, 4: 8},
        )

    def test_a_missing_file_fails_naming_the_file(self) -> None:
        missing = Path("/nonexistent/camel-port-table.yaml")
        rows, problems = CHECK_PORT_TABLE.load_rows(missing)
        self.assertEqual(rows, [])
        self.assertEqual(len(problems), 1)
        self.assertIn(str(missing), problems[0])

    def test_an_empty_table_fails(self) -> None:
        rows, problems = self.load("rows: []\n")
        self.assertEqual(rows, [])
        self.assertIn("the port table has no rows", problems[0])

    def test_a_row_missing_a_cell_fails_naming_its_row(self) -> None:
        rows, problems = self.load(
            "rows:\n- concept: A\n  reference: r\n  form: f\n  inc: 1\n"
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("row 1", problems[0])
        self.assertIn("table.yaml", problems[0])

    def test_a_row_with_an_unknown_cell_fails(self) -> None:
        _, problems = self.load(
            "rows:\n- concept: A\n  reference: r\n  form: f\n  divergence: d\n"
            "  inc: 1\n  extra: x\n"
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("row 1", problems[0])

    def test_cells_come_back_as_strings_in_column_order(self) -> None:
        rows, problems = self.load(
            "rows:\n- concept: A\n  reference: r\n  form: f\n  divergence: d\n  inc: 3\n"
        )
        self.assertEqual(problems, [])
        self.assertEqual(rows, [(1, ["A", "r", "f", "d", "3"])])


class IngestionPortEvidenceTests(unittest.TestCase):
    def test_pending_ingestion_rows_name_the_reviewed_existing_tests(self) -> None:
        self.assertEqual(CHECK_PORT_TABLE.INCREMENT_DELIVERED, 1)
        rows, problems = CHECK_PORT_TABLE.load_rows(CHECK_PORT_TABLE.PORT_TABLE)
        self.assertEqual(problems, [])
        increments = {cells[0].replace("`", ""): int(cells[4]) for _, cells in rows}

        for concept in INGESTION_CONCEPTS:
            with self.subTest(concept=concept):
                self.assertEqual(increments.get(concept), 4)
                evidence = CHECK_PORT_TABLE.EVIDENCE.get(concept)
                self.assertTrue(evidence)
                self.assertTrue(all(map(CHECK_PORT_TABLE.function_exists, evidence)))

    def test_pending_recorded_evidence_still_rejects_a_broken_reference(self) -> None:
        concept = INGESTION_CONCEPTS[0]
        broken = "engine:src/exchange.rs:not_an_attributed_test"

        with mock.patch.dict(CHECK_PORT_TABLE.EVIDENCE, {concept: [broken]}):
            problems = CHECK_PORT_TABLE.check_evidence(123, concept, 4)

        self.assertEqual(len(problems), 1)
        self.assertIn(broken, problems[0])
        self.assertIn("is not a test function", problems[0])


if __name__ == "__main__":
    unittest.main()
