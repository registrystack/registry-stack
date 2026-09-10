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
MULTISTAGE_EXAMPLE = (
    ROOT / "products/casework/examples/multi-stage-routing-clocks/casework.yaml"
)
MULTISTAGE_SOURCE = (
    ROOT
    / "products/casework/examples/multi-stage-routing-clocks/sources/regional-register.json"
)
MULTISTAGE_RESPONSE_SOURCE = (
    ROOT
    / "products/casework/examples/multi-stage-routing-clocks/sources/response-register.json"
)
MULTISTAGE_SIMULATION = (
    ROOT
    / "products/casework/examples/multi-stage-routing-clocks/simulations/friday-review.yaml"
)
MULTISTAGE_RESPONSE_SIMULATION = (
    ROOT
    / "products/casework/examples/multi-stage-routing-clocks/simulations/resubmitted-response.yaml"
)
MULTISTAGE_HOLIDAYS = (
    ROOT
    / "products/casework/examples/multi-stage-routing-clocks/simulations/holiday-sets/office-holidays-7.yaml"
)


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

    def test_multistage_example_pins_routing_and_both_clock_contracts(self):
        policy = MULTISTAGE_EXAMPLE.read_text(encoding="utf-8")
        source = MULTISTAGE_SOURCE.read_text(encoding="utf-8")
        response_source = MULTISTAGE_RESPONSE_SOURCE.read_text(encoding="utf-8")
        simulation = MULTISTAGE_SIMULATION.read_text(encoding="utf-8")
        response_simulation = MULTISTAGE_RESPONSE_SIMULATION.read_text(
            encoding="utf-8"
        )
        holidays = MULTISTAGE_HOLIDAYS.read_text(encoding="utf-8")

        self.assertIn("projection: [region]", policy)
        self.assertIn("id: northern-requests", policy)
        self.assertIn("scope: subject", policy)
        self.assertIn("scope: activity", policy)
        self.assertIn("after: {workingDays: 5}", policy)
        self.assertIn('"reviewMode": "staged"', source)
        self.assertIn('"id": "authorization"', source)
        self.assertIn('"field": "region"', source)
        self.assertIn('"requestEntity": "response-correction"', response_source)
        self.assertIn('dueAt: "2026-09-14T17:00:00+07:00"', simulation)
        self.assertIn("eligibleReminders: [due-soon]", simulation)
        self.assertIn("remainingMilliseconds: 158400000", response_simulation)
        self.assertIn('dueAt: "2026-09-13T09:00:00+07:00"', response_simulation)
        self.assertIn("revision: 7", holidays)
        self.assertIn("dates: [2026-09-07]", holidays)

    def test_security_contracts_are_scoped_and_do_not_claim_execution(self):
        matrix = MATRIX.read_text(encoding="utf-8")
        trace = TRACE.read_text(encoding="utf-8")
        self.assertIn("scope: first-full-mvp", matrix)
        self.assertIn("scope: first-full-mvp", trace)
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
                r"^  - \{number: ([0-9]+), targetWave: post-mvp,", matrix, re.M
            )
        }
        self.assertEqual(set(range(1, 19)), mapped | deferred)
        self.assertFalse(mapped & deferred)
        self.assertEqual({12}, deferred)

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
