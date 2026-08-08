#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Evidence configuration key-path parity check."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import evidence_config_key_paths as checker


class KeyPathCollectionTests(unittest.TestCase):
    def test_nested_properties_produce_dotted_paths(self):
        schema = {
            "type": "object",
            "properties": {
                "listener": {
                    "type": "object",
                    "properties": {"port": {"type": "integer"}},
                }
            },
        }
        self.assertEqual(checker.key_paths(schema), {"listener", "listener.port"})

    def test_array_items_produce_a_bracket_segment(self):
        schema = {
            "type": "object",
            "properties": {
                "requirements": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}},
                    },
                }
            },
        }
        self.assertEqual(
            checker.key_paths(schema),
            {"requirements", "requirements[]", "requirements[].id"},
        )

    def test_map_values_produce_a_star_segment(self):
        schema = {
            "type": "object",
            "properties": {
                "sources": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "object",
                        "properties": {"origin": {"type": "string"}},
                    },
                }
            },
        }
        self.assertEqual(
            checker.key_paths(schema),
            {"sources", "sources.*", "sources.*.origin"},
        )

    def test_closed_objects_do_not_produce_a_star_segment(self):
        schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {"version": {"const": 1}},
        }
        self.assertEqual(checker.key_paths(schema), {"version"})

    def test_local_references_are_resolved(self):
        schema = {
            "type": "object",
            "properties": {"path": {"$ref": "#/$defs/absolute-path"}},
            "$defs": {
                "absolute-path": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                }
            },
        }
        self.assertEqual(checker.key_paths(schema), {"path", "path.value"})

    def test_recursive_references_terminate_at_re_entry(self):
        """`adapter-parameter-value` nests into itself; the walk records it once."""
        schema = {
            "type": "object",
            "properties": {"node": {"$ref": "#/$defs/node"}},
            "$defs": {
                "node": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "child": {"$ref": "#/$defs/node"},
                    },
                }
            },
        }
        self.assertEqual(
            checker.key_paths(schema),
            {"node", "node.name", "node.child"},
        )

    def test_combinator_branches_are_unioned(self):
        schema = {
            "type": "object",
            "properties": {
                "signer": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {"privateKeyRef": {"type": "string"}},
                        },
                        {"type": "object", "properties": {"mount": {"type": "string"}}},
                    ]
                }
            },
        }
        self.assertEqual(
            checker.key_paths(schema),
            {"signer", "signer.privateKeyRef", "signer.mount"},
        )

    def test_governance_siblings_are_not_key_paths(self):
        """The frozen contracts carry ownership/startup blocks beside the schema."""
        schema = {
            "type": "object",
            "properties": {"version": {"const": 1}},
            "ownership": {"governed_fields": "prohibited"},
            "startup": {"unknown_keys": "rejected at every level"},
        }
        self.assertEqual(checker.key_paths(schema), {"version"})

    def test_unresolvable_reference_is_an_error(self):
        schema = {"type": "object", "properties": {"a": {"$ref": "#/$defs/missing"}}}
        with self.assertRaises(checker.ContractError):
            checker.key_paths(schema)


class DocumentedBlockTests(unittest.TestCase):
    def block(self, body):
        return (
            "prose before\n"
            "<!-- evidence-runtime-key-paths:start -->\n"
            "```text\n"
            f"{body}"
            "```\n"
            "<!-- evidence-runtime-key-paths:end -->\n"
            "prose after\n"
        )

    def test_block_contents_are_read_as_paths(self):
        text = self.block("listener\nlistener.port\n")
        self.assertEqual(
            checker.documented_key_paths(text, "evidence-runtime-key-paths"),
            {"listener", "listener.port"},
        )

    def test_blank_lines_and_fences_are_ignored(self):
        text = self.block("listener\n\n  listener.port  \n")
        self.assertEqual(
            checker.documented_key_paths(text, "evidence-runtime-key-paths"),
            {"listener", "listener.port"},
        )

    def test_missing_start_marker_is_an_error(self):
        with self.assertRaises(checker.ContractError):
            checker.documented_key_paths("no markers here", "evidence-runtime-key-paths")

    def test_missing_end_marker_is_an_error(self):
        text = "<!-- evidence-runtime-key-paths:start -->\n```text\nlistener\n"
        with self.assertRaises(checker.ContractError):
            checker.documented_key_paths(text, "evidence-runtime-key-paths")

    def test_duplicate_paths_are_an_error(self):
        text = self.block("listener\nlistener\n")
        with self.assertRaises(checker.ContractError):
            checker.documented_key_paths(text, "evidence-runtime-key-paths")

    def test_unsorted_paths_are_an_error(self):
        """A sorted block keeps review diffs minimal and stable."""
        text = self.block("listener.port\nlistener\n")
        with self.assertRaises(checker.ContractError):
            checker.documented_key_paths(text, "evidence-runtime-key-paths")


class RewriteTests(unittest.TestCase):
    def test_rewriting_replaces_the_block_and_keeps_surrounding_prose(self):
        text = (
            "before\n"
            "<!-- evidence-runtime-key-paths:start -->\n"
            "```text\n"
            "stale\n"
            "```\n"
            "<!-- evidence-runtime-key-paths:end -->\n"
            "after\n"
        )
        updated = checker.rewrite_block(
            text, "evidence-runtime-key-paths", {"listener.port", "listener"}
        )
        self.assertIn("before\n", updated)
        self.assertIn("after\n", updated)
        self.assertNotIn("stale", updated)
        self.assertEqual(
            checker.documented_key_paths(updated, "evidence-runtime-key-paths"),
            {"listener", "listener.port"},
        )

    def test_rewriting_is_idempotent(self):
        text = (
            "<!-- evidence-runtime-key-paths:start -->\n"
            "```text\n"
            "```\n"
            "<!-- evidence-runtime-key-paths:end -->\n"
        )
        once = checker.rewrite_block(text, "evidence-runtime-key-paths", {"a", "b"})
        twice = checker.rewrite_block(once, "evidence-runtime-key-paths", {"a", "b"})
        self.assertEqual(once, twice)

    def test_rewriting_without_a_marker_is_an_error(self):
        with self.assertRaises(checker.ContractError):
            checker.rewrite_block("no markers", "evidence-runtime-key-paths", {"a"})


class ParityTests(unittest.TestCase):
    def test_parity_reports_both_directions(self):
        problems = checker.compare(
            schema_paths={"a", "b"},
            documented_paths={"b", "c"},
            label="runtime.schema.yaml",
        )
        joined = "\n".join(problems)
        self.assertIn("a", joined)
        self.assertIn("c", joined)
        self.assertIn("runtime.schema.yaml", joined)

    def test_exact_parity_reports_nothing(self):
        self.assertEqual(
            checker.compare(
                schema_paths={"a"}, documented_paths={"a"}, label="runtime.schema.yaml"
            ),
            [],
        )


class FrozenContractTests(unittest.TestCase):
    """The real contracts must stay in parity with the committed reference."""

    def test_committed_contracts_and_reference_agree(self):
        problems = checker.check_all(checker.repository_root())
        self.assertEqual(problems, [], "\n".join(problems))


if __name__ == "__main__":
    unittest.main()
