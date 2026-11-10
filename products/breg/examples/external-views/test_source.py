#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from journey import JourneyError
from recovery import operator_report
from run_candidate import URL_FILES, database_urls, stage_project, verify_source_facts
from synthetic_source import Fixture, FixtureFault, handler, runtime_fragment


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


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.source = Fixture()

    def test_person_fields_and_keyed_absence(self):
        result, no_store = self.source.acquire(
            "person-batch",
            {"type": "batch", "keys": ["person-7", "person-9"], "fields": ["family-name"]},
        )
        self.assertFalse(no_store)
        self.assertEqual(result["records"][0]["properties"], {"family-name": "Lee"})
        self.assertEqual(result["records"][1], {"subject": "person-9", "state": "confirmed-absent"})
        with self.assertRaisesRegex(FixtureFault, "outside the approved scope"):
            self.source.acquire(
                "person-exact",
                {"type": "exact", "key": "person-11", "fields": ["family-name"]},
            )

    def test_a_shareholder_can_be_reached_only_through_a_holding(self):
        self.source.control({"action": "add-label-only"})
        rows = []
        request = {"type": "by-parent", "parentKey": "business-1", "fields": ["person-key"]}
        for _ in range(3):
            page, _ = self.source.acquire("holdings-by-business", request)
            rows.extend(page["items"])
            if page["finished"]:
                break
            request["cursor"] = page["next"]
        self.assertTrue(page["finished"])
        keys = {row["properties"]["person-key"] for row in rows}
        self.assertEqual(keys, {"person-7", "person-12", None})
        label, _ = self.source.acquire(
            "person-batch", {"type": "batch", "keys": ["person-12"], "fields": ["family-name"]},
        )
        self.assertEqual(label["records"][0]["properties"], {"family-name": "Solano"})

    def test_company_rows_have_no_person_identifier(self):
        first, _ = self.source.acquire(
            "holdings-by-business",
            {"type": "by-parent", "parentKey": "business-1", "fields": ["person-key", "shareholder-type"]},
        )
        second, _ = self.source.acquire(
            "holdings-by-business",
            {"type": "by-parent", "parentKey": "business-1", "fields": ["person-key", "shareholder-type"],
             "cursor": first["next"]},
        )
        self.assertEqual(first["snapshotId"], second["snapshotId"])
        self.assertEqual(first["items"][0]["properties"]["person-key"], "person-7")
        self.assertEqual(second["items"][0]["properties"], {"person-key": None, "shareholder-type": "business"})
        self.assertTrue(second["finished"])
        self.source.control({"action": "replace-holdings"})
        with self.assertRaisesRegex(FixtureFault, "snapshot changed"):
            self.source.acquire(
                "holdings-by-business",
                {"type": "by-parent", "parentKey": "business-1", "fields": ["shareholder-type"],
                 "cursor": first["next"]},
            )

    def test_a_paused_source_call_holds_the_snapshot_while_new_calls_progress(self):
        request = {"type": "batch", "keys": ["person-7"], "fields": ["family-name"]}
        earlier = []
        self.source.control({"action": "hold-next", "operation": "person-batch"})
        waiter = Thread(target=lambda: earlier.append(self.source.acquire("person-batch", request)))
        waiter.start()
        self.assertTrue(self.source.wait_for_hold(2))
        self.source.control({"action": "rename-holder"})
        later, _ = self.source.acquire("person-batch", request)
        self.source.control({"action": "release"})
        waiter.join(2)
        self.assertFalse(waiter.is_alive())
        self.assertEqual(earlier[0][0]["records"][0]["properties"], {"family-name": "Lee"})
        self.assertEqual(later["records"][0]["properties"], {"family-name": "Ng"})

    def test_no_store_and_interruption_are_separate_controls(self):
        request = {"type": "batch", "keys": ["person-7"], "fields": ["family-name"]}
        self.source.control({"action": "set-no-store", "operation": "person-batch", "enabled": True})
        self.assertTrue(self.source.acquire("person-batch", request)[1])
        self.source.control({"action": "interrupt-collection", "enabled": True})
        parent = {"type": "by-parent", "parentKey": "business-1", "fields": ["share-class"]}
        first, _ = self.source.acquire("holdings-by-business", parent)
        with self.assertRaisesRegex(FixtureFault, "collection interrupted"):
            self.source.acquire("holdings-by-business", {**parent, "cursor": first["next"]})


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


class HttpFixtureTests(unittest.TestCase):
    def test_source_and_control_identities_are_separate(self):
        source_key, control_key = "synthetic-source-key", "synthetic-control-key"
        with ThreadingHTTPServer(("127.0.0.1", 0), handler(Fixture(), source_key, control_key)) as server:
            thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                origin = f"http://127.0.0.1:{server.server_port}"
                client = build_opener(ProxyHandler({}))
                data = json.dumps({"type": "exact", "key": "person-7", "fields": ["family-name"]}).encode()
                with client.open(Request(
                    origin + "/people/exact", data=data, headers={"x-registry-service-key": source_key},
                ), timeout=2) as response:
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    self.assertEqual(json.load(response)["properties"], {"family-name": "Lee"})
                with self.assertRaises(HTTPError) as denied:
                    client.open(Request(origin + "/fixture/status", headers={"x-fixture-control-key": source_key}), timeout=2)
                self.assertEqual(denied.exception.code, 403)
                denied.exception.close()
                with self.assertRaises(HTTPError) as wrong_identity:
                    client.open(Request(
                        origin + "/people/exact", data=data, headers={"x-registry-service-key": control_key},
                    ), timeout=2)
                self.assertEqual(wrong_identity.exception.code, 403)
                wrong_identity.exception.close()
                with client.open(Request(
                    origin + "/fixture/status", headers={"x-fixture-control-key": control_key},
                ), timeout=2) as response:
                    self.assertEqual(json.load(response)["operations"], {"person-exact": 2})
            finally:
                server.shutdown()
                thread.join(2)

    def test_generated_fragment_is_scoped_and_pins_the_maintained_pack(self):
        config = runtime_fragment("http://127.0.0.1:8001", "projection-source-key", "2030-01-01T00:00:00Z")
        bindings = {entry["id"]: entry for entry in config["externalSources"]}
        self.assertEqual(set(bindings), {"person-live", "person-indexed", "holdings-live", "holdings-indexed"})
        self.assertNotIn("retention", bindings["person-live"])
        self.assertIn("retention", bindings["person-indexed"])
        self.assertIn("person-key", bindings["holdings-indexed"]["allowedFields"])
        self.assertNotIn("person-key", bindings["holdings-live"]["allowedFields"])
        self.assertTrue(bindings["person-indexed"]["packDigest"].startswith("sha256:"))
        self.assertEqual(bindings["person-live"]["packDigest"], bindings["holdings-indexed"]["packDigest"])


if __name__ == "__main__":
    unittest.main()
