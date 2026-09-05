"""app-developer-22: a missing resource is its own error kind.

The construction tests in `test_construction.py` cover kinds a client can
raise before any I/O. This file covers the one kind that only exists after a
real exchange: a 404 Base Registry Engine problem response promoted to
`kind == "not_found"` instead of the generic `"problem"` every other refusal
shares. A minimal stdlib `http.server` stands in for Base Registry Engine;
this crate has no shared stub-server helper of its own, so the server is
defined here rather than borrowed from a sibling crate's test tree.
"""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

import registry_breg_client as breg_client  # noqa: E402

BaseRegistryClient = breg_client.BaseRegistryClient
BaseRegistryClientError = breg_client.BaseRegistryClientError

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
MISSING_RECORD_ID = "00000000-0000-4000-8000-000000000001"


class _MissingRecordHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (stdlib handler method name)
        body = json.dumps(
            {
                "type": "urn:breg:problem:resource.not_found",
                "title": "Not Found",
                "status": 404,
                "detail": "The requested resource was not found.",
                "code": "resource.not_found",
                "traceId": TRACE_ID,
            }
        ).encode("utf-8")
        self.send_response(404)
        self.send_header("content-type", "application/problem+json")
        self.send_header("cache-control", "no-store")
        self.send_header("traceparent", TRACEPARENT)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass  # keep test output clean; the response is asserted, not logged


class NotFoundKindTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = HTTPServer(("127.0.0.1", 0), _MissingRecordHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        port = self.server.server_address[1]
        self.client = BaseRegistryClient(f"http://127.0.0.1:{port}/tenant")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_a_missing_record_fails_with_its_own_not_found_kind(self) -> None:
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.get_record("companies", MISSING_RECORD_ID)
        self.assertEqual(raised.exception.kind, "not_found")
        self.assertEqual(raised.exception.status, 404)
        self.assertEqual(raised.exception.code, "resource.not_found")


if __name__ == "__main__":
    unittest.main()
