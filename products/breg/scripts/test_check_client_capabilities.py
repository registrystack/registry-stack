# SPDX-License-Identifier: Apache-2.0

import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("client_capabilities", Path(__file__).with_name("check_client_capabilities.py"))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class CapabilityInventoryTests(unittest.TestCase):
    def query_binding_inputs(self):
        root = CHECK.ROOT
        inventory = CHECK.json.loads(CHECK.INVENTORY.read_text())
        rust = "\n".join(path.read_text() for path in (root / "crates/registry-breg-client/src").glob("*.rs"))
        node = (root / "crates/registry-breg-client-node/client.d.ts").read_text()
        python = (root / "crates/registry-breg-client-py/python/registry_breg_client/__init__.pyi").read_text()
        return inventory, rust, node, python

    def test_new_server_operation_requires_an_inventory_decision(self):
        actual = CHECK.enum_variants("pub enum Operation {\n    Get,\n    NewlyServed,\n}", "Operation")
        self.assertEqual(["unaccounted server operation: NewlyServed"], CHECK.require_accounted(actual, {"Get"}, "server operation"))

    def test_query_or_representation_addition_is_not_silently_covered(self):
        self.assertEqual(["unaccounted query: bbox"], CHECK.require_accounted({"$top", "bbox"}, {"$top"}, "query"))
        self.assertEqual(["unaccounted representation: application/geo+json"], CHECK.require_accounted({"application/geo+json"}, {"application/json"}, "representation"))

    def test_missing_owning_enum_fails_instead_of_accepting_an_empty_inventory(self):
        with self.assertRaises(ValueError):
            CHECK.enum_variants("", "Operation")

    def test_read_parser_inventory_distinguishes_accepted_and_refused_names(self):
        source = '''impl QueryBuilder {
    fn apply() {
            "bbox" => {
                self.bbox = Some(parse_bbox(value)?);
            }
            "sql" => {
                return Err(QueryParseError::DisallowedOption);
            }
    }
    fn finish(self) {}
}'''
        self.assertEqual({"bbox"}, CHECK.accepted_read_options(source))

    def test_direct_list_bbox_must_remain_in_the_node_declaration(self):
        inventory, rust, node, python = self.query_binding_inputs()
        without_direct_bbox = node.replace(
            "  bbox?: BoundingBox | null\n", "", 1
        )
        self.assertIn(
            "bbox: missing node query-option declaration ListOptions.bbox",
            CHECK.check_query_option_bindings(inventory, rust, without_direct_bbox, python),
        )

    def test_bbox_is_refused_on_shared_temporal_and_relationship_options(self):
        inventory, rust, node, python = self.query_binding_inputs()
        widened_node = node.replace(
            "export interface CollectionOptions extends RecordProjectionOptions {",
            "export interface CollectionOptions extends RecordProjectionOptions {\n  bbox?: BoundingBox | null",
        )
        widened_python = python.replace(
            "        path_route: str,\n        *,\n        top: int | None = None,",
            "        path_route: str,\n        *,\n        bbox: tuple[str, str, str, str] | None = None,\n        top: int | None = None,",
        )
        errors = CHECK.check_query_option_bindings(
            inventory, rust, widened_node, widened_python
        )
        self.assertIn(
            "bbox: forbidden node query-option declaration CollectionOptions.bbox", errors
        )
        self.assertIn(
            "bbox: forbidden python query-option declaration BaseRegistryClient.list_relationship_records.bbox",
            errors,
        )


if __name__ == "__main__":
    unittest.main()
