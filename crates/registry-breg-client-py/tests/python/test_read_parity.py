"""Exercise every operation-specific read through the native Python module."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import BaseRegistryClient  # noqa: E402

RECORD_ID = "00000000-0000-4000-8000-000000000001"
SNAPSHOT = "breg1_00000000-0000-4000-8000-000000000002"
TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
PROFILE_LINK = (
    '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", '
    '</v1/schemas/company>; rel="describedby"'
)


def record_data() -> dict:
    return {
        "recordIdentifier": RECORD_ID,
        "revisionIdentifier": "1",
        "domainData": {"label": "one"},
    }


def metadata() -> dict:
    return {
        "registryIdentifier": "registry",
        "datasetIdentifier": "dataset",
        "entityTypeIdentifier": "company",
    }


def feature() -> dict:
    return {
        "type": "Feature",
        "id": RECORD_ID,
        "geometry": {"type": "Point", "coordinates": [100.25, 13.25]},
        "properties": {"label": "one", "large": 2**63},
        "registry": {"revision": 1},
    }


class ReadParityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests = []
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                requests.append((self.path, self.headers.get("accept")))
                if self.headers.get("accept") == "application/geo+json":
                    if RECORD_ID in self.path:
                        self.respond(feature(), "application/geo+json", False, False)
                    else:
                        cursor = None if "%24skiptoken=" in self.path or "$skiptoken=" in self.path else "geo-next"
                        self.respond(
                            {
                                "type": "FeatureCollection",
                                "features": [feature()],
                                "numberReturned": 1,
                                "registry": {
                                    "pageInfo": {"nextCursor": cursor},
                                    "count": 1,
                                },
                            },
                            "application/geo+json",
                            False,
                            False,
                        )
                    return

                is_collection = any(
                    marker in self.path
                    for marker in (":current", ":as-of", ":snapshot", "/related")
                )
                if is_collection:
                    cursor = None if "%24skiptoken=" in self.path or "$skiptoken=" in self.path else "next"
                    value = {
                        "items": [record_data()],
                        "pageInfo": {"nextCursor": cursor},
                        "meta": metadata(),
                    }
                    if ":snapshot" in self.path:
                        value["snapshot"] = SNAPSHOT
                    self.respond(value, "application/json", True, False)
                    return
                revision_detail = "/revisions/" in self.path
                self.respond(
                    {"data": record_data(), "meta": metadata()},
                    "application/json",
                    True,
                    not revision_detail,
                )

            def respond(
                self,
                value: dict,
                media_type: str,
                link: bool,
                etag: bool,
            ) -> None:
                body = json.dumps(value, separators=(",", ":")).encode()
                self.send_response(200)
                self.send_header("content-type", media_type)
                self.send_header("traceparent", TRACEPARENT)
                if link:
                    self.send_header("link", PROFILE_LINK)
                if etag:
                    self.send_header("etag", '"breg-record-000000000001"')
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = BaseRegistryClient(
            f"http://127.0.0.1:{self.server.server_port}"
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_geojson_bbox_and_typed_continuation(self) -> None:
        single = self.client.get_geojson_record("companies", RECORD_ID)
        self.assertEqual(single["value"]["geometry"]["coordinates"], [100.25, 13.25])
        self.assertEqual(single["value"]["properties"]["large"], 2**63)
        self.assertIsNone(single["etag"])

        first = self.client.list_geojson_records(
            "companies",
            access_profile="map",
            top=1,
            count=True,
            bbox=("100.1", "13.1", "100.2", "13.2"),
        )
        self.assertEqual(first["value"]["numberReturned"], 1)
        self.assertEqual(first["continuation"]["skiptoken"], "geo-next")
        second = self.client.continue_geojson_list(first["continuation"])
        self.assertIsNone(second["continuation"])
        self.assertTrue(any("bbox=100.1%2C13.1%2C100.2%2C13.2" in path for path, _ in self.requests))

    def test_temporal_snapshot_relationship_revision_and_history_reads(self) -> None:
        current = self.client.list_current_records("companies", top=1)
        self.assertIsNone(
            self.client.continue_current_list(current["continuation"])["continuation"]
        )

        as_of = self.client.list_records_as_of(
            "companies", "2026-09-10T00:00:00Z", top=1
        )
        self.assertEqual(as_of["continuation"]["asOf"], "2026-09-10T00:00:00Z")
        self.assertIsNone(
            self.client.continue_as_of_list(as_of["continuation"])["continuation"]
        )

        snapshot = self.client.list_snapshot_records("companies", top=1)
        self.assertEqual(snapshot["snapshot"], SNAPSHOT)
        resumed = self.client.continue_snapshot_list(snapshot["continuation"])
        self.assertEqual(resumed["snapshot"], SNAPSHOT)
        self.assertIsNone(resumed["continuation"])

        related = self.client.list_relationship_records(
            "companies", RECORD_ID, "related", top=1
        )
        self.assertEqual(related["continuation"]["pathRoute"], "related")
        self.assertIsNone(
            self.client.continue_relationship_list(related["continuation"])[
                "continuation"
            ]
        )

        revision = self.client.get_record_revision("companies", RECORD_ID, 1)
        self.assertEqual(json.loads(revision["body"])["data"]["recordIdentifier"], RECORD_ID)
        self.client.get_record(
            "companies",
            RECORD_ID,
            request_history_after_proposal_version=2**32 - 1,
        )
        self.assertTrue(
            any(
                "requestHistoryAfterProposalVersion=4294967295" in path
                for path, _ in self.requests
            )
        )


if __name__ == "__main__":
    unittest.main()
