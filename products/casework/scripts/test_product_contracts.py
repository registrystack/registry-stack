#!/usr/bin/env python3
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MATRIX = ROOT / "products/casework/contracts/security-invariant-matrix.yaml"
TRACE = ROOT / "products/casework/contracts/security-test-traceability.yaml"
STANDALONE_EXAMPLE = (
    ROOT / "products/casework/examples/standalone-decision/casework.yaml"
)
STANDALONE_FIXTURE = (
    ROOT
    / "products/casework/examples/standalone-decision/fixtures/standalone-decision.yaml"
)
BREG_EXAMPLE = ROOT / "products/casework/examples/professional-review/casework.yaml"


def references(text: str) -> set[tuple[str, str]]:
    return set(re.findall(r"(?:path|file): ([^,}]+), name: ([A-Za-z0-9_]+)", text))


class ProductContractTests(unittest.TestCase):
    def test_standalone_example_is_source_free_and_breg_starter_remains(self):
        standalone = STANDALONE_EXAMPLE.read_text(encoding="utf-8")
        fixture = STANDALONE_FIXTURE.read_text(encoding="utf-8")
        breg = BREG_EXAMPLE.read_text(encoding="utf-8")

        self.assertNotRegex(standalone, r"(?m)^sources:")
        self.assertRegex(standalone, r"(?m)^hostedKinds:")
        self.assertRegex(standalone, r"(?m)^\s+role: requester$")
        self.assertRegex(standalone, r"(?m)^\s+kinds: \[decision\]$")
        self.assertRegex(fixture, r"(?m)^hosted:$")
        self.assertRegex(fixture, r"(?m)^\s+outcomes: \[confirmed, rejected\]$")
        self.assertRegex(breg, r"(?m)^sources:")
        self.assertNotRegex(breg, r"(?m)^hostedKinds:")

    def test_security_contracts_are_scoped_and_do_not_claim_execution(self):
        matrix = MATRIX.read_text(encoding="utf-8")
        trace = TRACE.read_text(encoding="utf-8")
        self.assertIn("scope: first-checkpoint", matrix)
        self.assertIn("evidenceStatus: source-mapped-not-executed", matrix)
        self.assertIn("executionStatus: not-recorded", trace)
        self.assertNotIn("executionStatus: passed", matrix + trace)
        matrix_ids = set(re.findall(r"id: (CASEWORK-SEC-[0-9]+)", matrix))
        trace_ids = set(re.findall(r"id: (CASEWORK-SEC-[0-9]+)", trace))
        self.assertEqual(matrix_ids, trace_ids)

    def test_concept_invariant_mapping_is_complete_without_claiming_deferred_work(self):
        matrix = MATRIX.read_text(encoding="utf-8")
        mapped = {
            int(number)
            for values in re.findall(r"invariants: \[([^]]+)\]", matrix)
            for number in values.split(", ")
        }
        deferred = {
            int(number)
            for number in re.findall(
                r"^  - \{number: ([0-9]+), targetWave: post-checkpoint,", matrix, re.M
            )
        }
        self.assertEqual(set(range(1, 19)), mapped | deferred)
        self.assertFalse(mapped & deferred)
        self.assertEqual({2, 11, 12}, deferred)

    def test_every_mapped_test_exists_by_exact_name(self):
        mapped = references(MATRIX.read_text(encoding="utf-8")) | references(
            TRACE.read_text(encoding="utf-8")
        )
        self.assertTrue(mapped)
        for relative, name in sorted(mapped):
            source_path = ROOT / relative
            self.assertTrue(source_path.is_file(), relative)
            source = source_path.read_text(encoding="utf-8")
            self.assertRegex(source, rf"\b(?:async\s+)?(?:fn|def)\s+{re.escape(name)}\b", f"{relative}:{name}")


if __name__ == "__main__":
    unittest.main()
