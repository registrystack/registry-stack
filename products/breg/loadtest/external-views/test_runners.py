#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Deterministic checks for the candidate runner helpers."""

from pathlib import Path
import tempfile
import unittest

import fixture_path  # noqa: F401
from journey import JourneyError
from recovery import operator_report
from run_candidate import URL_FILES, database_urls, stage_project, verify_source_facts
from synthetic_source import runtime_fragment


class RecoveryTests(unittest.TestCase):
    def test_operator_report_reads_the_psql_json_cell(self):
        output = b"""BEGIN
SET
SET
                    jsonb_pretty
----------------------------------------------------
 {                                                 +
     "projection": "holdings-indexed",             +
     "active": false                               +
 }
(1 row)

COMMIT
"""
        self.assertEqual(operator_report(output), {"projection": "holdings-indexed", "active": False})
        for invalid in (output.replace(b"COMMIT", b"ROLLBACK"), b"COMMIT", output + output):
            with self.assertRaisesRegex(JourneyError, "scope report"):
                operator_report(invalid)


class CandidateFixtureTests(unittest.TestCase):
    def test_saved_native_project_is_staged_byte_for_byte_and_requires_all_three_files(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            source = work / "studio"
            (source / "tests").mkdir(parents=True)
            files = {"registry.yaml": b"registry", "dev-clients.yaml": b"clients",
                     "tests/journeys.yaml": b"journeys"}
            for name, data in files.items():
                (source / name).write_bytes(data)
            staged = stage_project(source, work)
            for name, data in files.items():
                self.assertEqual((staged / name).read_bytes(), data)
                self.assertEqual((source / name).read_bytes(), data)
            incomplete = work / "incomplete"
            incomplete.mkdir()
            (incomplete / "registry.yaml").write_bytes(b"registry")
            with self.assertRaises(JourneyError):
                stage_project(incomplete, work)

    def test_source_facts_require_all_projections_and_refuse_connection_details(self):
        bindings = runtime_fragment("http://127.0.0.1:8001", "synthetic", "2030-01-01T00:00:00Z")
        projections = []
        for binding in bindings["externalSources"]:
            person = binding["id"].startswith("person")
            indexed = binding["id"].endswith("-indexed")
            projections.append({
                "id": binding["id"], "mode": "indexed" if indexed else "live",
                "recordType": "person" if person else "holding",
                "authority": "urn:example:population-register" if person else "urn:example:business-register",
                "operation": ("person-batch" if indexed else "person-exact") if person else "holdings-by-business",
                "operationVersion": "1",
                "selectorScheme": "urn:example:person-number" if person else "urn:example:business-number",
                "purpose": "licensing", "scope": "licensing-holders" if person else "licensed-business-holdings",
                "fields": binding["allowedFields"], "connection": "synthetic-licensing",
                "bindingDigest": "sha256:" + "1" * 64, "grantDigest": "sha256:" + "2" * 64,
                "grantValidUntil": "2030-01-01T00:00:00+00:00",
                "cacheTtlSeconds": 300 if indexed else None,
                "maximumRetentionSeconds": 300 if indexed else None,
                "refreshIntervalSeconds": 60 if indexed else None,
            })
        facts = {
            "apiVersion": "id.registrystack.org/formats/breg/external-source-facts/v1alpha1",
            "kind": "BRegExternalSourceFacts", "registryId": "synthetic-licensing",
            "revision": "fixture-revision", "projections": projections,
        }
        verify_source_facts(facts, bindings, 300)
        with self.assertRaises(JourneyError):
            verify_source_facts({**facts, "projections": projections[:-1]}, bindings, 300)
        with self.assertRaises(JourneyError):
            verify_source_facts({**facts, "projections": [{**projections[0], "baseUrl": "private"}, *projections[1:]]},
                                bindings, 300)
        with self.assertRaises(JourneyError):
            verify_source_facts({**facts, "projections": [{**projections[0], "fields": ["other"]}, *projections[1:]]},
                                bindings, 300)

    def test_url_files_must_describe_fresh_split_loopback_databases(self):
        valid = [
            "postgresql://migrator@localhost:6543/breg_ext_rehearsal?sslmode=require",
            "postgresql://server@localhost:6543/breg_ext_rehearsal?sslmode=require",
            "postgresql://migrator@localhost:6543/breg_ext_serving?sslmode=require",
            "postgresql://server@localhost:6543/breg_ext_serving?sslmode=require",
        ]
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            output = root / "output"
            output.mkdir()
            for invalid in (valid[2], valid[3] + "&host=example.test"):
                for name, url in zip(URL_FILES, [*valid[:3], invalid]):
                    (root / name).write_text(url, encoding="ascii")
                with self.assertRaises(JourneyError):
                    database_urls(root, output)
                self.assertEqual(list(output.iterdir()), [])
            for name, url in zip(URL_FILES, valid):
                (root / name).write_text(url, encoding="ascii")
            self.assertEqual(database_urls(root, output), {"migration": "migrator", "runtime": "server"})
            self.assertEqual({path.name for path in output.iterdir()}, set(URL_FILES))


if __name__ == "__main__":
    unittest.main()
