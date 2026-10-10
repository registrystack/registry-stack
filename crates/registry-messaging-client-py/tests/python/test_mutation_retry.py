"""The bounded same-key resend of a submission, against a scripted service."""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_messaging_client import MessagingClient, MessagingClientError  # noqa: E402

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
MESSAGE_ID = "0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d"
PROBLEM_BASE = "https://id.registrystack.org/problems/registry-messaging/"
KEY = "reminder-2026-09-25-0001"
SUBMISSION = {
    "senderProfile": "reminders-sms",
    "to": {"phone": "+15550100"},
    "template": {"id": "appointment-reminder", "version": "1"},
    "locale": "en",
    "data": {"time": "10:00"},
}
RECEIPT = (
    202,
    "application/json",
    {
        "id": MESSAGE_ID,
        "status": "queued",
        "links": {
            "self": f"/v1/messages/{MESSAGE_ID}",
            "cancel": f"/v1/messages/{MESSAGE_ID}/cancel",
        },
    },
)


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
    "Messaging service unavailable",
    "Messaging is unavailable. Try again after the service recovers.",
)
KEY_REUSED = problem(
    "idempotency.key-reused",
    409,
    "Idempotency key reused",
    "This idempotency key was used for a different request.",
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
        self.script(UNAVAILABLE, RECEIPT)

        receipt = MessagingClient(self.base_url).submit("one-call-token", KEY, SUBMISSION)

        self.assertEqual(receipt["kind"], "complete")
        self.assertEqual(receipt["value"]["id"], MESSAGE_ID)
        self.assertEqual(len(_Scripted.observations), 2)
        first, resend = _Scripted.observations
        self.assertEqual(first["path"], "/tenant/v1/messages")
        self.assertEqual(first["idempotency_key"], KEY)
        self.assertEqual(resend, first)

    def test_a_ceiling_of_zero_sends_once_and_reports_the_outcome_unknown(self) -> None:
        self.script(UNAVAILABLE, RECEIPT)
        client = MessagingClient(self.base_url, max_mutation_retries=0)

        with self.assertRaises(MessagingClientError) as raised:
            client.submit("one-call-token", KEY, SUBMISSION)

        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.status, 503)
        self.assertEqual(raised.exception.code, "service.unavailable")
        self.assertIs(raised.exception.outcome_unknown, True)
        self.assertEqual(len(_Scripted.observations), 1)

    def test_a_4xx_refusal_is_never_resent_and_reports_the_outcome_known(self) -> None:
        self.script(KEY_REUSED, RECEIPT)
        client = MessagingClient(self.base_url, max_mutation_retries=2)

        with self.assertRaises(MessagingClientError) as raised:
            client.submit("one-call-token", KEY, SUBMISSION)

        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.status, 409)
        self.assertIs(raised.exception.outcome_unknown, False)
        self.assertEqual(len(_Scripted.observations), 1)

    def test_a_ceiling_outside_zero_to_two_is_a_configuration_error(self) -> None:
        for retries in (0, 1, 2):
            with self.subTest(retries=retries):
                MessagingClient(self.base_url, max_mutation_retries=retries)
        for retries in (3, 255, 256, -1, 1.5, "1", True):
            with self.subTest(retries=retries):
                with self.assertRaises(MessagingClientError) as raised:
                    MessagingClient(self.base_url, max_mutation_retries=retries)
                self.assertEqual(raised.exception.kind, "configuration")
                self.assertIs(raised.exception.outcome_unknown, False)

    def test_a_request_refused_before_any_exchange_reports_the_outcome_known(self) -> None:
        self.script()
        with self.assertRaises(MessagingClientError) as raised:
            MessagingClient(self.base_url).submit("one-call-token", "two words", SUBMISSION)
        self.assertEqual(raised.exception.kind, "invalid-request")
        self.assertIs(raised.exception.outcome_unknown, False)
        self.assertEqual(_Scripted.observations, [])


if __name__ == "__main__":
    unittest.main()
