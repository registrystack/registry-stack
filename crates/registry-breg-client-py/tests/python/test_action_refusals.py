"""An immediate-action refusal reaches the caller with its declared reason.

Base Registry Engine answers 422 `action.refused` with the refusal code the
package declared and its static label. The reason is the whole machine-readable
outcome of that refusal, so it is exposed as `refusal_code`; a document outside
the published bounds must fail closed instead. A minimal stdlib `http.server`
stands in for Base Registry Engine, as in `test_errors.py`.
"""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from bootstrap import ensure_built

ensure_built()

import registry_breg_client as breg_client  # noqa: E402

BaseRegistryClient = breg_client.BaseRegistryClient
BaseRegistryClientError = breg_client.BaseRegistryClientError

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
RECORD_ID = "00000000-0000-4000-8000-000000000001"
# A package declares its own refusal catalogue, so the code and the label both
# stand in for one declared entry rather than for fixed client-side text.
REFUSAL_CODE = "blank-name"
REFUSAL_LABEL = "At least one name part is required."


def refusal(**extra: Any) -> dict[str, Any]:
    document = {
        "type": "https://id.registrystack.org/problems/registry-breg/action/refused",
        "title": "Unprocessable Entity",
        "status": 422,
        "detail": REFUSAL_LABEL,
        "code": "action.refused",
        "traceId": TRACE_ID,
        "refusalCode": REFUSAL_CODE,
    }
    document.update(extra)
    return document


class _ProblemHandler(BaseHTTPRequestHandler):
    document: dict[str, Any] = refusal()

    def do_GET(self) -> None:  # noqa: N802 (stdlib handler method name)
        body = json.dumps(self.document).encode("utf-8")
        self.send_response(self.document["status"])
        self.send_header("content-type", "application/problem+json")
        self.send_header("cache-control", "no-store")
        self.send_header("traceparent", TRACEPARENT)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass  # keep test output clean; the response is asserted, not logged


class ActionRefusalTests(unittest.TestCase):
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

    def answer(self, document: dict[str, Any]) -> BaseRegistryClientError:
        _ProblemHandler.document = document
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.get_record("people", RECORD_ID)
        return raised.exception

    def test_a_declared_refusal_reaches_the_caller_with_its_reason(self) -> None:
        for document in [
            refusal(),
            refusal(fieldPath="/input/givenName"),
            refusal(detail="A declared label.", refusalCode="declared.reason_9"),
        ]:
            with self.subTest(refusal_code=document["refusalCode"]):
                error = self.answer(document)
                self.assertEqual(error.kind, "problem")
                self.assertEqual(error.status, 422)
                self.assertEqual(error.code, "action.refused")
                self.assertEqual(error.refusal_code, document["refusalCode"])
                self.assertEqual(error.trace_id, TRACE_ID)
                self.assertIsNone(error.plan_refusal)

    def test_a_refusal_outside_the_published_bounds_fails_closed(self) -> None:
        silent = refusal()
        del silent["refusalCode"]
        for document in [
            silent,
            refusal(refusalCode=""),
            refusal(refusalCode="r" * 129),
            refusal(refusalCode="blank\u0007name"),
            refusal(fieldPath="/input/given-name"),
            refusal(fieldPath="/evidence/status"),
            refusal(detail="label " * 64),
            {
                "type": "https://id.registrystack.org/problems/registry-breg/mutation/conflict",
                "title": "Conflict",
                "status": 409,
                "detail": "The mutation conflicts with current state.",
                "code": "mutation.conflict",
                "traceId": TRACE_ID,
                "refusalCode": REFUSAL_CODE,
            },
        ]:
            with self.subTest(document=document.get("refusalCode"), path=document.get("fieldPath")):
                error = self.answer(document)
                self.assertEqual(error.kind, "protocol")
                self.assertEqual(error.code, "problem")
                self.assertIsNone(error.refusal_code)


if __name__ == "__main__":
    unittest.main()
