#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from http.server import ThreadingHTTPServer
import json
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from synthetic_source import Fixture, FixtureFault, handler, runtime_fragment


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
