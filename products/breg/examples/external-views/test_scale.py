#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Deterministic checks for the native scale fixture and independent oracle."""

import unittest

from scale_exercise import (
    ABSENT_KEYS, BATCH_KEYS, DENIED_ROOTS, ELIGIBLE_ROOTS, HOLDER_KEYS,
    MATCH_KEYS, PERSON_REQUEST_BUDGET, REFRESH_PAGE_SIZE, ScaleFixture,
    exact_oracle, holding_oracle, native_plans, ordered_oracle, root_id, seed_sql,
)
from synthetic_source import FixtureFault


class ScaleFixtureTests(unittest.TestCase):
    def test_corpus_and_current_pagination_have_a_predeclared_budget(self):
        self.assertEqual(ELIGIBLE_ROOTS, 1_000_000)
        self.assertEqual(DENIED_ROOTS, 100_000)
        self.assertEqual(ABSENT_KEYS, 2_500)
        self.assertEqual(ELIGIBLE_ROOTS // HOLDER_KEYS, 20)
        self.assertEqual((REFRESH_PAGE_SIZE, BATCH_KEYS), (100, 64))
        self.assertEqual(PERSON_REQUEST_BUDGET, 1_100)
        self.assertEqual(len(exact_oracle("Cohort")), len(MATCH_KEYS) * 20)
        self.assertEqual(len(exact_oracle(None)), 50_000)

    def test_oracle_orders_by_source_value_then_immutable_local_id(self):
        ascending = ordered_oracle(roots=500)
        descending = ordered_oracle(descending=True, roots=500)
        self.assertEqual(len(ascending), 500)
        self.assertEqual(len(set(ascending)), 500)
        self.assertEqual(ascending[-25:], descending[-25:])
        self.assertEqual(ascending[-1], root_id(500))
        self.assertNotEqual(ascending[0], descending[0])

    def test_source_enforces_batch_ceiling_and_denied_subject_boundary(self):
        source = ScaleFixture()
        query = {"type": "batch", "fields": ["family-name"], "keys": ["scale-person-000005", "scale-person-000020"]}
        body, no_store = source.acquire("person-batch", query)
        self.assertFalse(no_store)
        self.assertEqual([row["state"] for row in body["records"]], ["found", "confirmed-absent"])
        self.assertEqual(body["records"][0]["properties"]["family-name"], "Cohort")
        with self.assertRaises(FixtureFault):
            source.acquire("person-batch", {**query, "keys": ["scale-denied-000001"]})
        with self.assertRaises(FixtureFault):
            source.acquire("person-batch", {**query, "keys": [f"scale-person-{i:06}" for i in range(1, 66)]})
        self.assertEqual(source.status()["uniquePersonKeys"], 2)
        self.assertEqual(source.status()["deniedSelectors"], 1)

    def test_collection_snapshots_fit_the_pack_and_cover_two_allowed_parents(self):
        source = ScaleFixture()
        for parent in range(1, 3):
            request = {"type": "by-parent", "parentKey": f"scale-business-{parent}", "fields": ["share-count"]}
            counts = []
            snapshots = set()
            while True:
                page, _ = source.acquire("holdings-by-business", request)
                counts.extend(row["properties"]["share-count"] for row in page["items"])
                snapshots.add(page["snapshotId"])
                if page["finished"]:
                    break
                request["cursor"] = page["next"]
            self.assertEqual(counts, holding_oracle(parent))
            self.assertEqual(len(snapshots), 1)
        with self.assertRaises(FixtureFault):
            source.acquire("holdings-by-business", {**request, "parentKey": "scale-business-3"})
        self.assertEqual(source.status()["collections"], {"scale-business-1": 3, "scale-business-2": 3})

    def test_bulk_seed_is_confined_to_owned_tables_and_requires_empty_fixture(self):
        entity = {"table": "breg_e_licence_1", "fields": {"licence-number": "breg_f_number_1",
                  "holder-key": "breg_f_holder_1", "jurisdiction": "breg_f_zone_1"}}
        business = {"table": "breg_e_business_1", "fields": {"licence-number": "breg_f_number_2",
                    "business-key": "breg_f_business_2", "jurisdiction": "breg_f_zone_2"}}
        sql = seed_sql({"entities": {"licence": entity, "licensed-business": business}})
        self.assertIn("generate_series(1, 1100000)", sql)
        self.assertIn("scale fixture tables must be empty", sql)
        self.assertIn("active_activation_id::text", sql)
        self.assertNotIn("registry_external_projection_", sql)

    def test_plans_require_native_coverage_page_and_buffer_evidence(self):
        entry = """[breg-plan] breg_ext_runtime runtime LOG:
Query Text: WITH projection_state AS MATERIALIZED (SELECT 1)
  CTE coverage
  CTE page
  Buffers: shared hit=1
"""
        self.assertEqual(len(native_plans(entry, "breg_ext_runtime", "runtime")), 1)
        self.assertEqual(native_plans(entry.replace("CTE page", "CTE other"), "breg_ext_runtime", "runtime"), [])
        self.assertEqual(native_plans(entry, "breg_ext_other", "runtime"), [])


if __name__ == "__main__":
    unittest.main()
