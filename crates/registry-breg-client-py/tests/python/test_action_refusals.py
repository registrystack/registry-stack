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


def guard_failure(**extra: Any) -> dict[str, Any]:
    document = {
        "type": "https://id.registrystack.org/problems/registry-breg/action/guard_failed",
        "title": "Precondition Failed",
        "status": 412,
        "detail": "The action guard was not satisfied.",
        "code": "action.guard_failed",
        "traceId": TRACE_ID,
        "guardReason": "legal_name_unchanged",
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
                self.assertEqual(error.field_path, document.get("fieldPath"))
                self.assertEqual(error.trace_id, TRACE_ID)
                self.assertFalse(hasattr(error, "plan_refusal"))

    def test_a_failed_guard_exposes_only_its_bounded_authored_copy_key(self) -> None:
        for reason in ["a", "legal_name_unchanged", "a" + "b" * 63]:
            with self.subTest(reason=reason):
                error = self.answer(guard_failure(guardReason=reason))
                self.assertEqual(error.kind, "problem")
                self.assertEqual(error.status, 412)
                self.assertEqual(error.code, "action.guard_failed")
                self.assertEqual(error.guard_reason, reason)
                self.assertIsNone(error.refusal_code)
                self.assertIsNone(error.reason_code)
                if len(reason) > 1:
                    self.assertNotIn(reason, str(error))
                    self.assertNotIn(reason, repr(error))
        for document in [
            guard_failure(guardReason=""),
            guard_failure(guardReason="Uppercase"),
            guard_failure(guardReason="has.dot"),
            guard_failure(guardReason="a" + "b" * 64),
            guard_failure(guardReason=None),
            refusal(guardReason="misplaced"),
            guard_failure(refusalCode=REFUSAL_CODE),
            guard_failure(reasonCode="source-data-error"),
        ]:
            with self.subTest(document=document):
                error = self.answer(document)
                self.assertEqual(error.kind, "protocol")
                self.assertIsNone(error.guard_reason)
                self.assertIsNone(error.refusal_code)
                self.assertIsNone(error.reason_code)

    def test_the_typed_idempotency_key_reuse_problem_uses_the_current_wire_code(self) -> None:
        current = self.answer(
            {
                "type": "https://id.registrystack.org/problems/registry-breg/idempotency/key-reused",
                "title": "Conflict",
                "status": 409,
                "detail": "The idempotency key is bound to another request.",
                "code": "idempotency.key-reused",
                "traceId": TRACE_ID,
            }
        )
        self.assertEqual(current.kind, "problem")
        self.assertEqual(current.code, "idempotency.key-reused")
        self.assertEqual(current.status, 409)
        self.assertFalse(current.outcome_unknown)

        retired = self.answer(
            {
                "type": "https://id.registrystack.org/problems/registry-breg/idempotency/conflict",
                "title": "Conflict",
                "status": 409,
                "detail": "The idempotency key is bound to another request.",
                "code": "idempotency.conflict",
                "traceId": TRACE_ID,
            }
        )
        self.assertEqual(retired.kind, "problem")
        self.assertIsNone(retired.code)

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
                self.assertIsNone(error.field_path)

    def test_row_local_constraints_retain_only_bounded_declared_identifiers(self) -> None:
        base = {
            "type": "https://id.registrystack.org/problems/registry-breg/mutation/conflict",
            "title": "Conflict", "status": 409,
            "detail": "The mutation conflicts with current state.",
            "code": "mutation.conflict", "traceId": TRACE_ID,
        }
        constraints = [
            {"recordType": "item", "constraintId": "valid-period", "constraintKind": "compare",
             "left": "valid-from", "right": "valid-to"},
            {"recordType": "item", "constraintId": "quantity-range", "constraintKind": "int-range",
             "field": "quantity"},
            {"recordType": "item", "constraintId": "allowed-status", "constraintKind": "vocabulary",
             "field": "status"},
        ]
        for constraint in constraints:
            error = self.answer({**base, **constraint})
            self.assertEqual(error.kind, "problem")
            self.assertEqual(error.code, "mutation.conflict")
            self.assertFalse(error.outcome_unknown)
            self.assertEqual(error.constraint, constraint)
            self.assertNotIn(constraint["constraintId"], str(error))
            self.assertNotIn(constraint["constraintId"], repr(error))
        self.assertIsNone(self.answer(base).constraint)
        for malformed in [
            {**constraints[0], "right": None},
            {**constraints[0], "constraintKind": "unique"},
            {**constraints[1], "field": "x" * 129},
            {**constraints[2], "field": "value\ncanary"},
        ]:
            error = self.answer({**base, **malformed})
            self.assertEqual(error.kind, "protocol")
            self.assertIsNone(error.constraint)


if __name__ == "__main__":
    unittest.main()
