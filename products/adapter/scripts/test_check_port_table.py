#!/usr/bin/env python3
"""Regression tests for the Adapter Camel port-table evidence gate."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-port-table.py")
SPEC = importlib.util.spec_from_file_location("check_port_table", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECK_PORT_TABLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK_PORT_TABLE)


class RustTestFunctionTests(unittest.TestCase):
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

    def test_ignores_test_attributes_inside_comments(self) -> None:
        source = """
// #[test]
fn commented_out_test() {}
"""

        self.assertFalse(
            CHECK_PORT_TABLE.has_rust_test_function(source, "commented_out_test")
        )


if __name__ == "__main__":
    unittest.main()
