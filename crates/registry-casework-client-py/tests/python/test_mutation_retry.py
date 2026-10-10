"""The bounded same-key resend of an absence, against a scripted service."""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_casework_client import CaseworkClient, CaseworkClientError  # noqa: E402

TRACE_ID = "0123456789abcdef0123456789abcdef"
TRACEPARENT = f"00-{TRACE_ID}-0123456789abcdef-01"
PROBLEM_BASE = "https://id.registrystack.org/problems/registry-casework/"
KEY = "absence-1"
ABSENCE = {
    "person": {"issuer": "https://issuer.example", "subject": "staff-1"},
    "cover": {"issuer": "https://issuer.example", "subject": "staff-2"},
    "from": "2026-10-05T00:00:00Z",
    "until": "2026-10-06T00:00:00Z",
}
RECORD = {**ABSENCE, "absenceId": "00000000-0000-0000-0000-000000000005", "revision": 3}
CREATED = (201, "application/json", RECORD)


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
    "Casework service unavailable",
    "Casework storage is unavailable. Try again after the service recovers.",
)
PRECONDITION_FAILED = problem(
    "precondition.failed",
    412,
    "Precondition failed",
    "The item or directory changed since you loaded it. Reload and try again.",
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
            "if_match": self.headers.get("if-match", ""),
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

        outcome = CaseworkClient(self.base_url).create_absence(
            "one-call-token", "administrator", 2, KEY, ABSENCE
        )

        self.assertEqual(outcome["value"], RECORD)
        self.assertEqual(len(_Scripted.observations), 2)
        first, resend = _Scripted.observations
        self.assertEqual(first["path"], "/tenant/v1/directory/absences")
        self.assertEqual(first["idempotency_key"], KEY)
        self.assertEqual(first["if_match"], '"2"')
        self.assertEqual(resend, first)

    def test_a_ceiling_of_zero_sends_once_and_reports_the_outcome_unknown(self) -> None:
        self.script(UNAVAILABLE, CREATED)
        client = CaseworkClient(self.base_url, max_mutation_retries=0)

        with self.assertRaises(CaseworkClientError) as raised:
            client.create_absence("one-call-token", "administrator", 2, KEY, ABSENCE)

        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.status, 503)
        self.assertEqual(raised.exception.code, "service.unavailable")
        self.assertIs(raised.exception.outcome_unknown, True)
        self.assertEqual(len(_Scripted.observations), 1)

    def test_a_4xx_refusal_is_never_resent_and_reports_the_outcome_known(self) -> None:
        self.script(PRECONDITION_FAILED, CREATED)
        client = CaseworkClient(self.base_url, max_mutation_retries=2)

        with self.assertRaises(CaseworkClientError) as raised:
            client.create_absence("one-call-token", "administrator", 2, KEY, ABSENCE)

        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.status, 412)
        self.assertIs(raised.exception.outcome_unknown, False)
        self.assertEqual(len(_Scripted.observations), 1)

    def test_a_ceiling_outside_zero_to_two_is_a_configuration_error(self) -> None:
        for retries in (0, 1, 2):
            with self.subTest(retries=retries):
                CaseworkClient(self.base_url, max_mutation_retries=retries)
        for retries in (3, 255, 256, -1, 1.5, "1", True):
            with self.subTest(retries=retries):
                with self.assertRaises(CaseworkClientError) as raised:
                    CaseworkClient(self.base_url, max_mutation_retries=retries)
                self.assertEqual(raised.exception.kind, "configuration")
                self.assertIs(raised.exception.outcome_unknown, False)

    def test_a_request_refused_before_any_exchange_reports_the_outcome_known(self) -> None:
        self.script()
        with self.assertRaises(CaseworkClientError) as raised:
            CaseworkClient(self.base_url).create_absence(
                "one-call-token", "administrator", 2, "two words", ABSENCE
            )
        self.assertEqual(raised.exception.kind, "invalid-request")
        self.assertIs(raised.exception.outcome_unknown, False)
        self.assertEqual(_Scripted.observations, [])


if __name__ == "__main__":
    unittest.main()
