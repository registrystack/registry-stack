#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Evidence configuration key-path parity check."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
            label="products/evidence/contracts/runtime.schema.yaml",
            reference="products/evidence/reference/one/CONFIG.md",
        )
        joined = "\n".join(problems)
        self.assertIn("a", joined)
        self.assertIn("c", joined)
        self.assertIn("products/evidence/contracts/runtime.schema.yaml", joined)

    def test_parity_names_the_reference_that_should_carry_the_path(self):
        """More than one reference holds blocks, so a problem must say which."""
        problems = checker.compare(
            schema_paths={"a"},
            documented_paths={"c"},
            label="crates/example/schemas/question.schema.json",
            reference="products/evidence/reference/authoring-projects/CONFIG.md",
        )
        self.assertEqual(len(problems), 2)
        for problem in problems:
            self.assertIn(
                "products/evidence/reference/authoring-projects/CONFIG.md", problem
            )

    def test_exact_parity_reports_nothing(self):
        self.assertEqual(
            checker.compare(
                schema_paths={"a"},
                documented_paths={"a"},
                label="products/evidence/contracts/runtime.schema.yaml",
                reference="products/evidence/reference/one/CONFIG.md",
            ),
            [],
        )


class ContractAddressingTests(unittest.TestCase):
    """Every entry addresses its own schema and its own reference."""

    def test_every_schema_and_reference_path_exists(self):
        root = checker.repository_root()
        for name, contract in checker.CONTRACTS.items():
            with self.subTest(contract=name):
                self.assertTrue((root / contract.schema).is_file(), contract.schema)
                self.assertTrue(
                    (root / contract.reference).is_file(), contract.reference
                )

    def test_every_marker_is_unique(self):
        markers = [contract.marker for contract in checker.CONTRACTS.values()]
        self.assertEqual(len(markers), len(set(markers)))

    def test_the_frozen_contracts_and_the_authoring_schemas_split_references(self):
        """The authoring form is adopter tooling, documented apart from the
        frozen Version 1 grammar rather than beside it."""
        frozen = {
            contract.reference
            for name, contract in checker.CONTRACTS.items()
            if not name.startswith("authoring-")
        }
        authoring = {
            contract.reference
            for name, contract in checker.CONTRACTS.items()
            if name.startswith("authoring-")
        }
        self.assertEqual(len(frozen), 1)
        self.assertEqual(len(authoring), 1)
        self.assertFalse(frozen & authoring)

    def test_references_group_every_contract_under_its_own_file(self):
        grouped = checker.references()
        self.assertEqual(
            sum(len(contracts) for contracts in grouped.values()),
            len(checker.CONTRACTS),
        )
        for reference, contracts in grouped.items():
            for contract in contracts:
                self.assertEqual(contract.reference, reference)


class PerEntryAddressingTests(unittest.TestCase):
    """Schemas outside one directory, documented into more than one reference."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.write(
            "contracts/first.schema.yaml",
            "type: object\nproperties:\n  alpha:\n    type: string\n",
        )
        self.write(
            "elsewhere/second.schema.json",
            '{"type": "object", "properties": {"beta": {"type": "string"}}}\n',
        )
        self.write("one/CONFIG.md", self.reference("first-key-paths"))
        self.write("two/CONFIG.md", self.reference("second-key-paths"))
        self.contracts = {
            "first": checker.Contract(
                schema="contracts/first.schema.yaml",
                reference="one/CONFIG.md",
                marker="first-key-paths",
            ),
            "second": checker.Contract(
                schema="elsewhere/second.schema.json",
                reference="two/CONFIG.md",
                marker="second-key-paths",
            ),
        }

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def reference(self, marker):
        return (
            "prose\n"
            f"<!-- {marker}:start -->\n"
            "```text\n"
            "```\n"
            f"<!-- {marker}:end -->\n"
        )

    def read(self, relative):
        return (self.root / relative).read_text(encoding="utf-8")

    def test_writing_fills_every_reference_from_its_own_schema(self):
        with mock.patch.object(checker, "CONTRACTS", self.contracts):
            self.assertTrue(checker.write_all(self.root))
            self.assertEqual(checker.check_all(self.root), [])
        self.assertIn("alpha", self.read("one/CONFIG.md"))
        self.assertNotIn("beta", self.read("one/CONFIG.md"))
        self.assertIn("beta", self.read("two/CONFIG.md"))
        self.assertNotIn("alpha", self.read("two/CONFIG.md"))

    def test_writing_twice_reports_no_further_change(self):
        with mock.patch.object(checker, "CONTRACTS", self.contracts):
            self.assertTrue(checker.write_all(self.root))
            self.assertFalse(checker.write_all(self.root))

    def test_a_json_schema_is_read_by_the_same_loader(self):
        with mock.patch.object(checker, "CONTRACTS", self.contracts):
            checker.write_all(self.root)
        self.assertIn("beta", self.read("two/CONFIG.md"))

    def test_drift_in_one_reference_names_that_reference_and_its_schema(self):
        self.write("two/CONFIG.md", self.reference("second-key-paths"))
        with mock.patch.object(checker, "CONTRACTS", self.contracts):
            checker.write_all(self.root)
            self.write("two/CONFIG.md", self.reference("second-key-paths"))
            problems = checker.check_all(self.root)
        self.assertEqual(len(problems), 1)
        self.assertIn("elsewhere/second.schema.json", problems[0])
        self.assertIn("two/CONFIG.md", problems[0])
        self.assertIn("beta", problems[0])

    def test_a_missing_marker_names_the_schema_that_wanted_it(self):
        with mock.patch.object(checker, "CONTRACTS", self.contracts):
            checker.write_all(self.root)
            self.write("two/CONFIG.md", "prose with no markers\n")
            problems = checker.check_all(self.root)
        self.assertEqual(len(problems), 1)
        self.assertIn("elsewhere/second.schema.json", problems[0])
        self.assertIn("second-key-paths", problems[0])

    def test_write_all_writes_nothing_when_a_later_reference_is_missing_its_marker(self):
        """`one/CONFIG.md` is stale and would regenerate; `two/CONFIG.md` is
        broken. The break must stop the write before `one/CONFIG.md` is
        touched, not just before `two/CONFIG.md` is."""
        original_one = self.read("one/CONFIG.md")
        self.write("two/CONFIG.md", "prose with no markers\n")
        with mock.patch.object(checker, "CONTRACTS", self.contracts):
            with self.assertRaises(checker.ContractError):
                checker.write_all(self.root)
        self.assertEqual(self.read("one/CONFIG.md"), original_one)
        self.assertNotIn("alpha", original_one)

    def test_write_all_writes_nothing_when_a_later_schema_does_not_parse(self):
        original_one = self.read("one/CONFIG.md")
        original_two = self.read("two/CONFIG.md")
        self.write("elsewhere/second.schema.json", "{not valid json")
        with mock.patch.object(checker, "CONTRACTS", self.contracts):
            with self.assertRaises(checker.ContractError):
                checker.write_all(self.root)
        self.assertEqual(self.read("one/CONFIG.md"), original_one)
        self.assertEqual(self.read("two/CONFIG.md"), original_two)

    def test_write_all_only_writes_the_references_whose_content_changed(self):
        """A second run, after only one schema gains a key, must not touch
        the reference whose block is already current."""
        with mock.patch.object(checker, "CONTRACTS", self.contracts):
            checker.write_all(self.root)
            self.write(
                "contracts/first.schema.yaml",
                "type: object\nproperties:\n  alpha:\n    type: string\n"
                "  gamma:\n    type: string\n",
            )
            written = []
            original_write_text = Path.write_text

            def spy(target, *args, **kwargs):
                written.append(target)
                return original_write_text(target, *args, **kwargs)

            with mock.patch.object(Path, "write_text", spy):
                changed = checker.write_all(self.root)
        self.assertTrue(changed)
        self.assertEqual(written, [self.root / "one/CONFIG.md"])
        self.assertIn("gamma", self.read("one/CONFIG.md"))


class CommittedParityTests(unittest.TestCase):
    """Every committed schema must stay in parity with the reference it feeds."""

    def test_committed_schemas_and_references_agree(self):
        problems = checker.check_all(checker.repository_root())
        self.assertEqual(problems, [], "\n".join(problems))


if __name__ == "__main__":
    unittest.main()
