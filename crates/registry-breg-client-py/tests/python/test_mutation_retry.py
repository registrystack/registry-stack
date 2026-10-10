"""The bounded same-key resend of a publication, against a scripted service."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import BaseRegistryClient, BaseRegistryClientError  # noqa: E402

TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
KEY = "publish-2026-09-0001"
PUBLISHED = b'{"dataset":"enrolments","version":1}'
TITLES = {409: "Conflict", 500: "Internal Server Error", 503: "Service Unavailable"}


def problem(code: str, status: int, detail: str, **extension: str) -> tuple[int, str, bytes, dict[str, str]]:
    body = json.dumps({
        "type": "https://id.registrystack.org/problems/registry-breg/" + code.replace(".", "/"),
        "title": TITLES[status], "status": status, "detail": detail,
        "code": code, "traceId": TRACE_ID, **extension,
    }, separators=(",", ":")).encode()
    return status, "application/problem+json", body, {}


UNAVAILABLE = problem("service.unavailable", 503, "The Registry mutation service is unavailable.")
VERSION_CONFLICT = problem(
    "statistical_dataset.version_conflict",
    409,
    "The statistical dataset computation was superseded or its package changed.",
)
DOMAIN_VIOLATION = problem(
    "statistical_dataset.domain_violation",
    500,
    "A statistical dataset contains a code outside its declared domain.",
    fieldPath="statisticalDatasets[id=enrolments].dimensions[id=category]",
)
PUBLICATION = (
    201,
    "application/json",
    PUBLISHED,
    {
        "vary": "authorization, accept",
        "repr-digest": f"sha-256=:{base64.b64encode(hashlib.sha256(PUBLISHED).digest()).decode()}:",
    },
)


class _Scripted(BaseHTTPRequestHandler):
    """Answer each request with the next scripted answer, in request order."""

    answers: list[tuple[int, str, bytes, dict[str, str]]] = []
    observations: list[dict[str, str]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        self.observations.append({
            "path": self.path,
            "idempotency_key": self.headers.get("idempotency-key", ""),
            "body": self.rfile.read(length).decode("utf-8"),
        })
        status, content_type, body, headers = (
            self.answers.pop(0) if self.answers else (418, "text/plain", b"", {})
        )
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("traceparent", TRACEPARENT)
        self.send_header("cache-control", "no-store")
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


class MutationRetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), _Scripted)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def script(self, *answers: tuple[int, str, bytes, dict[str, str]]) -> None:
        _Scripted.answers[:] = list(answers)
        _Scripted.observations.clear()

    @staticmethod
    def publish(client: BaseRegistryClient) -> object:
        return client.statistics_publish("enrolments", "2026-09", "final", "publisher", KEY)

    def test_a_503_is_resent_once_under_the_same_key_and_succeeds(self) -> None:
        self.script(UNAVAILABLE, PUBLICATION)

        published = self.publish(BaseRegistryClient(self.base_url))

        self.assertTrue(published["repr_digest"].startswith("sha-256=:"))
        self.assertEqual(len(_Scripted.observations), 2)
        first, resend = _Scripted.observations
        self.assertEqual(first["path"], "/v1/statistics/enrolments/releases/2026-09/versions?accessProfile=publisher")
        self.assertEqual(first["idempotency_key"], KEY)
        self.assertEqual(resend, first)

    def test_a_ceiling_of_zero_sends_once_and_reports_the_outcome_unknown(self) -> None:
        self.script(UNAVAILABLE, PUBLICATION)
        client = BaseRegistryClient(self.base_url, max_mutation_retries=0)

        with self.assertRaises(BaseRegistryClientError) as raised:
            self.publish(client)

        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.status, 503)
        self.assertEqual(raised.exception.code, "service.unavailable")
        self.assertIs(raised.exception.outcome_unknown, True)
        self.assertEqual(len(_Scripted.observations), 1)

    def test_a_refusal_or_a_failure_before_commit_is_never_resent(self) -> None:
        for refusal in (VERSION_CONFLICT, DOMAIN_VIOLATION):
            with self.subTest(status=refusal[0]):
                self.script(refusal, PUBLICATION)
                client = BaseRegistryClient(self.base_url, max_mutation_retries=2)

                with self.assertRaises(BaseRegistryClientError) as raised:
                    self.publish(client)

                self.assertEqual(raised.exception.kind, "problem")
                self.assertEqual(raised.exception.status, refusal[0])
                self.assertIs(raised.exception.outcome_unknown, False)
                self.assertEqual(len(_Scripted.observations), 1)

    def test_a_ceiling_outside_zero_to_two_is_a_configuration_error(self) -> None:
        for retries in (0, 1, 2):
            with self.subTest(retries=retries):
                BaseRegistryClient(self.base_url, max_mutation_retries=retries)
        for retries in (3, 255, 256, -1, 1.5, "1", True):
            with self.subTest(retries=retries):
                with self.assertRaises(BaseRegistryClientError) as raised:
                    BaseRegistryClient(self.base_url, max_mutation_retries=retries)
                self.assertEqual(raised.exception.kind, "configuration")
                self.assertIs(raised.exception.outcome_unknown, False)

    def test_a_request_refused_before_any_exchange_reports_the_outcome_known(self) -> None:
        self.script()
        with self.assertRaises(BaseRegistryClientError) as raised:
            BaseRegistryClient(self.base_url).statistics_publish(
                "enrolments", "2025-99", "final", "publisher", "invalid-period-key"
            )
        self.assertEqual(raised.exception.kind, "invalid-request")
        self.assertIs(raised.exception.outcome_unknown, False)
        self.assertEqual(_Scripted.observations, [])


if __name__ == "__main__":
    unittest.main()
