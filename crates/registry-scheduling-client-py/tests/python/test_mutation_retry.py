"""The bounded same-key resend of a hold, against a scripted service."""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_scheduling_client import SchedulingClient, SchedulingClientError  # noqa: E402

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
PROBLEM_BASE = "https://id.registrystack.org/problems/registry-scheduling/"
HOLD_ID = "0199d0e0-8f2a-7c3b-9d4e-5f6a7b8c9d0e"
KEY = "hold-2026-10-05-0001"
REFERENCE = {"product": "casework", "recordType": "review-task", "identifier": "case:1234"}
ADMISSION = {
    "offering": "registry-update-30",
    "start": "2026-10-05T09:00:00Z",
    "party": {"recipients": 1, "attendees": 1},
    "policyRevision": 3,
    "capabilities": [],
    "prerequisites": [],
    "externalReferences": [REFERENCE],
}
HOLD = {
    "holdId": HOLD_ID,
    "offering": "registry-update-30",
    "start": "2026-10-05T09:00:00Z",
    "end": "2026-10-05T09:30:00Z",
    "resource": "clerk-1",
    "units": 1,
    "expiresAt": "2026-10-05T08:15:00Z",
    "policyRevision": 3,
    "externalReferences": [REFERENCE],
}
CREATED = (201, "application/json", HOLD)


def problem(code: str, status: int, title: str, detail: str) -> tuple[int, str, object]:
    return (
        status,
        "application/problem+json",
        {
            "type": PROBLEM_BASE + code.replace(".", "/"),
            "title": title,
            "status": status,
            "detail": detail,
            "code": code,
            "traceId": TRACE_ID,
        },
    )


UNAVAILABLE = problem(
    "service.unavailable",
    503,
    "Scheduling service unavailable",
    "Scheduling storage is unavailable. Try again after the service recovers.",
)
EXHAUSTED = problem(
    "capacity.exhausted",
    409,
    "Capacity exhausted",
    "The supply is fully committed for the requested interval. Choose another time.",
)


class _Scripted(BaseHTTPRequestHandler):
    """Answer each request with the next scripted answer, in request order."""

    answers: list[tuple[int, str, object]] = []
    observations: list[dict[str, str]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        self.observations.append({
            "path": self.path,
            "idempotency_key": self.headers.get("idempotency-key", ""),
            "body": self.rfile.read(length).decode("utf-8"),
        })
        status, content_type, document = (
            self.answers.pop(0) if self.answers else (418, "application/json", {})
        )
        payload = json.dumps(document).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("traceparent", TRACEPARENT)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


class MutationRetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), _Scripted)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.server.server_address
        cls.base_url = f"http://{host}:{port}/tenant/"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def script(self, *answers: tuple[int, str, object]) -> None:
        _Scripted.answers[:] = list(answers)
        _Scripted.observations.clear()

    def test_a_503_is_resent_once_under_the_same_key_and_succeeds(self) -> None:
        self.script(UNAVAILABLE, CREATED)

        outcome = SchedulingClient(self.base_url).create_hold("one-call-token", KEY, ADMISSION)

        self.assertEqual(outcome, {"kind": "complete", "value": HOLD, "trace_id": TRACE_ID})
        self.assertEqual(len(_Scripted.observations), 2)
        first, resend = _Scripted.observations
        self.assertEqual(first["path"], "/tenant/v1/holds")
        self.assertEqual(first["idempotency_key"], KEY)
        self.assertEqual(resend, first)

    def test_a_ceiling_of_zero_sends_once_and_reports_the_outcome_unknown(self) -> None:
        self.script(UNAVAILABLE, CREATED)
        client = SchedulingClient(self.base_url, max_mutation_retries=0)

        with self.assertRaises(SchedulingClientError) as raised:
            client.create_hold("one-call-token", KEY, ADMISSION)

        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.status, 503)
        self.assertEqual(raised.exception.code, "service.unavailable")
        self.assertIs(raised.exception.outcome_unknown, True)
        self.assertEqual(len(_Scripted.observations), 1)

    def test_a_4xx_refusal_is_never_resent_and_reports_the_outcome_known(self) -> None:
        self.script(EXHAUSTED, CREATED)
        client = SchedulingClient(self.base_url, max_mutation_retries=2)

        with self.assertRaises(SchedulingClientError) as raised:
            client.create_hold("one-call-token", KEY, ADMISSION)

        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.status, 409)
        self.assertIs(raised.exception.outcome_unknown, False)
        self.assertEqual(len(_Scripted.observations), 1)

    def test_a_ceiling_outside_zero_to_two_is_a_configuration_error(self) -> None:
        for retries in (0, 1, 2):
            with self.subTest(retries=retries):
                SchedulingClient(self.base_url, max_mutation_retries=retries)
        for retries in (3, 255, 256, -1, 1.5, "1", True):
            with self.subTest(retries=retries):
                with self.assertRaises(SchedulingClientError) as raised:
                    SchedulingClient(self.base_url, max_mutation_retries=retries)
                self.assertEqual(raised.exception.kind, "configuration")
                self.assertIs(raised.exception.outcome_unknown, False)

    def test_a_request_refused_before_any_exchange_reports_the_outcome_known(self) -> None:
        self.script()
        with self.assertRaises(SchedulingClientError) as raised:
            SchedulingClient(self.base_url).create_hold("one-call-token", "two words", ADMISSION)
        self.assertEqual(raised.exception.kind, "invalid-request")
        self.assertIs(raised.exception.outcome_unknown, False)
        self.assertEqual(_Scripted.observations, [])


if __name__ == "__main__":
    unittest.main()
