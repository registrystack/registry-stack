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
        rust = "\n".join(path.read_text() for path in (root / "crates/registry-breg-client/src").rglob("*.rs"))
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

    def test_native_proposal_queries_require_the_real_public_methods(self):
        inventory, rust, node, python = self.query_binding_inputs()
        without_list = node.replace("listProposals(collection:", "retiredListProposals(collection:")
        errors = CHECK.check_query_option_bindings(inventory, rust, without_list, python)
        self.assertIn("action: missing node query-option declaration BaseRegistryClient.listProposals.queryJson", errors)
        self.assertNotIn("requestHistoryAfterProposalVersion", inventory["queryOptions"])
        self.assertNotIn("proposalVersion", inventory["queryOptions"])

    def test_batch_context_ids_require_real_public_parameters(self):
        inventory, rust, node, python = self.query_binding_inputs()
        self.assertIn("ids", inventory["queryOptions"])
        cases = [
            ("rust", "BaseRegistryClient.read_proposal_review_context_batch.ids", rust.replace(
                "ids: &[&str]", "unbound: &[&str]"), node, python),
            ("node", "BaseRegistryClient.readProposalReviewContextBatch.ids", rust, node.replace(
                "readProposalReviewContextBatch(binding: BRegProposalReviewBinding, ids:",
                "readProposalReviewContextBatch(binding: BRegProposalReviewBinding, unbound:"), python),
            ("python", "BaseRegistryClient.read_proposal_review_context_batch.ids", rust, node, python.replace(
                "read_proposal_review_context_batch(self, binding: BRegProposalReviewBinding, ids:",
                "read_proposal_review_context_batch(self, binding: BRegProposalReviewBinding, unbound:")),
        ]
        for language, target, rust_source, node_types, python_types in cases:
            with self.subTest(language=language):
                self.assertIn(target, inventory["queryOptionBindings"]["ids"][language])
                self.assertIn(
                    f"ids: missing {language} query-option declaration {target}",
                    CHECK.check_query_option_bindings(inventory, rust_source, node_types, python_types),
                )

    def test_attachment_version_uses_the_promoted_proposal_not_a_caller_version(self):
        inventory, rust, node, python = self.query_binding_inputs()
        binding = inventory["queryOptionBindings"]["submissionVersion"]
        self.assertEqual(binding["rust"], ["BaseRegistryClient.download_proposal_attachment.proposal", "BaseRegistryClient.download_proposal_review_document.context"])
        without_proposal = node.replace("downloadProposalAttachment(proposal:", "downloadProposalAttachment(unbound:")
        self.assertIn(
            "submissionVersion: missing node query-option declaration BaseRegistryClient.downloadProposalAttachment.proposal",
            CHECK.check_query_option_bindings(inventory, rust, without_proposal, python),
        )


    def test_review_document_queries_use_bound_context_and_selected_field(self):
        inventory, rust, node, python = self.query_binding_inputs()
        for option in ["effectDigest", "contextSchemaDigest"]:
            self.assertEqual(inventory["queryOptionBindings"][option]["rust"],
                             ["BaseRegistryClient.download_proposal_review_document.context"])
        self.assertEqual(inventory["queryOptionBindings"]["reviewContextField"]["rust"],
                         ["BaseRegistryClient.download_proposal_review_document.field"])
        without_context = node.replace(
            "context: BRegProposalReviewDocument, field: string", "unbound: BRegProposalReviewDocument, field: string")
        errors = CHECK.check_query_option_bindings(inventory, rust, without_context, python)
        self.assertIn("effectDigest: missing node query-option declaration BaseRegistryClient.downloadProposalReviewDocument.context", errors)
        self.assertEqual(CHECK.check_query_option_bindings(inventory, rust, node, python), [])


if __name__ == "__main__":
    unittest.main()
