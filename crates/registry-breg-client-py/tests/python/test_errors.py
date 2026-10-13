"""Public error kinds for known and future Base Registry Engine problems.

The construction tests in `test_construction.py` cover kinds a client can
raise before any I/O. This file covers known and future Problem responses after
a real exchange. A minimal stdlib `http.server` stands in for Base Registry
Engine; this crate has no shared stub-server helper of its own.
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
EXTENDED_UNKNOWN_PROBLEM_ID = "00000000-0000-4000-8000-000000000003"
UNKNOWN_PROBLEM_STATUSES = {
    "00000000-0000-4000-8000-000000000422": 422,
    "00000000-0000-4000-8000-000000000404": 404,
    "00000000-0000-4000-8000-000000000503": 503,
    EXTENDED_UNKNOWN_PROBLEM_ID: 422,
}
MALFORMED_PROBLEM_ID = "00000000-0000-4000-8000-000000000002"


class _ProblemHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (stdlib handler method name)
        record_id = self.path.rsplit("/", maxsplit=1)[-1]
        if record_id == MISSING_RECORD_ID:
            status = 404
            document = {
                "type": "https://id.registrystack.org/problems/registry-breg/resource/not_found",
                "title": "Not Found",
                "status": 404,
                "detail": "The requested resource was not found.",
                "code": "resource.not_found",
                "traceId": TRACE_ID,
            }
        else:
            status = UNKNOWN_PROBLEM_STATUSES.get(record_id, 422)
            document = {
                "type": "https://id.registrystack.org/problems/registry-breg/future/refused",
                "title": "Future refusal",
                "status": 503 if record_id == MALFORMED_PROBLEM_ID else status,
                "detail": "canary response detail",
                "code": "future.refused",
                "traceId": TRACE_ID,
            }
            if record_id == EXTENDED_UNKNOWN_PROBLEM_ID:
                document.update(
                    {
                        "fieldPath": "/input/futureField",
                        "refusalCode": "future-refusal",
                        "reasonCode": "future-reason",
                        "future": {"disposition": "opaque"},
                    }
                )
        body = json.dumps(document).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/problem+json")
        self.send_header("cache-control", "no-store")
        self.send_header("traceparent", TRACEPARENT)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass  # keep test output clean; the response is asserted, not logged


class ProblemKindTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = HTTPServer(("127.0.0.1", 0), _ProblemHandler)
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
        self.assertEqual(raised.exception.kind, "not-found")
        self.assertEqual(raised.exception.status, 404)
        self.assertEqual(raised.exception.code, "resource.not_found")

    def test_unknown_problem_codes_fall_back_to_http_status_semantics(self) -> None:
        for record_id, status in UNKNOWN_PROBLEM_STATUSES.items():
            with self.subTest(status=status):
                with self.assertRaises(BaseRegistryClientError) as raised:
                    self.client.get_record("companies", record_id)
                error = raised.exception
                self.assertEqual(error.kind, "problem")
                self.assertEqual(error.status, status)
                self.assertEqual(error.trace_id, TRACE_ID)
                self.assertIsNone(error.code)
                self.assertIsNone(error.plan_refusal)
                self.assertIsNone(error.refusal_code)
                self.assertIsNone(error.reason_code)
                self.assertIsNone(error.field_path)
                self.assertFalse(hasattr(error, "future"))
                self.assertIs(error.outcome_unknown, status >= 500)
                self.assertNotIn("future.refused", str(error))
                self.assertNotIn("canary response detail", str(error))
                self.assertNotIn("future-refusal", str(error))
                self.assertNotIn("opaque", str(error))

    def test_an_unknown_problem_with_a_mismatched_body_status_fails_closed(self) -> None:
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.get_record("companies", MALFORMED_PROBLEM_ID)
        error = raised.exception
        self.assertEqual(error.kind, "protocol")
        self.assertEqual(error.status, 422)
        self.assertEqual(error.code, "problem")
        self.assertEqual(error.trace_id, TRACE_ID)
        self.assertNotIn("future.refused", str(error))
        self.assertNotIn("canary response detail", str(error))


if __name__ == "__main__":
    unittest.main()
