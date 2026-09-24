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
HIDDEN_ID = "00000000-0000-4000-8000-000000000404"
RACED_ID = "00000000-0000-4000-8000-000000000409"
REUSED_KEY = "reused-key"
PROBLEM_BASE = "https://id.registrystack.org/problems/registry-messaging/"
LINKS = {
    "self": f"/v1/messages/{MESSAGE_ID}",
    "cancel": f"/v1/messages/{MESSAGE_ID}/cancel",
}
SUBMISSION = {
    "senderProfile": "reminders-sms",
    "to": {"phone": "+15550100"},
    "template": {"id": "appointment-reminder", "version": "1"},
    "locale": "en",
    "data": {"time": "10:00"},
    "correlationId": "case-42",
}
VIEW = {
    "id": MESSAGE_ID,
    "status": "delivered",
    "dispatch": "submitted",
    "report": "delivered",
    "reportedAt": "2026-09-25T10:00:02Z",
    "channel": "sms",
    "senderProfile": "reminders-sms",
    "to": {"phone": "+15550100"},
    "template": {"id": "appointment-reminder", "version": "1"},
    "correlationId": "case-42",
    "acceptedAt": "2026-09-25T10:00:00Z",
    "expiresAt": "2026-09-26T10:00:00Z",
    "updatedAt": "2026-09-25T10:00:01Z",
    "attempts": [
        {
            "generation": 1,
            "attempt": 1,
            "outcome": "accepted",
            "startedAt": "2026-09-25T10:00:00Z",
            "finishedAt": "2026-09-25T10:00:01Z",
            "providerReference": True,
        }
    ],
    "links": LINKS,
}
CANCELLED_VIEW = {
    "id": MESSAGE_ID,
    "status": "cancelled",
    "dispatch": "cancelled",
    "report": "none",
    "channel": "sms",
    "senderProfile": "reminders-sms",
    "to": {"phone": "+15550100"},
    "acceptedAt": "2026-09-25T10:00:00Z",
    "expiresAt": "2026-09-26T10:00:00Z",
    "updatedAt": "2026-09-25T10:00:01Z",
    "attempts": [],
    "links": LINKS,
}
PREVIEW_REQUEST = {"locale": "en", "data": {"time": "10:00"}}
PREVIEW = {
    "template": {"id": "appointment-reminder", "version": "1"},
    "locale": "en",
    "channel": "sms",
    "packageDigest": "sha256:" + "0" * 64,
    "parts": {"text": "Your appointment is at 10:00."},
    "sms": {"encoding": "gsm7", "units": 29, "segments": 1},
}
PREVIEW_PATH = "/tenant/v1/templates/appointment-reminder/versions/1/preview"
FRENCH_PREVIEW_PATH = "/tenant/v1/templates/appointment-reminder/versions/2/preview"


class _Handler(BaseHTTPRequestHandler):
    observations: list[dict[str, str]] = []

    def observe(self, body: str = "") -> None:
        self.observations.append({
            "method": self.command,
            "path": self.path,
            "authorization": self.headers.get("authorization", ""),
            "idempotency_key": self.headers.get("idempotency-key", ""),
            "content_type": self.headers.get("content-type", ""),
            "body": body,
        })

    def do_GET(self) -> None:  # noqa: N802
        self.observe()
        if self.path in ("/tenant/health", "/tenant/ready"):
            self.send_response(200)
            self.send_header("traceparent", TRACEPARENT)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        if self.path == f"/tenant/v1/messages/{MESSAGE_ID}":
            self.respond(200, VIEW)
            return
        if self.path == f"/tenant/v1/messages/{HIDDEN_ID}":
            self.respond_problem(
                "message.not-visible",
                404,
                "Message not visible",
                "No message with this identifier is visible to the caller.",
            )
            return
        self.respond_problem("request.not-found", 404, "Route not found", "The requested route does not exist.")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        self.observe(body)
        if self.path == f"/tenant/v1/messages/{MESSAGE_ID}/cancel":
            self.respond(200, CANCELLED_VIEW)
            return
        if self.path == f"/tenant/v1/messages/{RACED_ID}/cancel":
            self.respond_problem(
                "message.dispatch-started",
                409,
                "Message dispatch started",
                "Dispatch already started.",
            )
            return
        if self.path == PREVIEW_PATH:
            self.respond(200, PREVIEW)
            return
        if self.path == FRENCH_PREVIEW_PATH:
            self.respond_problem(
                "template.locale-unavailable",
                422,
                "Template locale unavailable",
                "The template version has no text for this locale.",
            )
            return
        if self.headers.get("idempotency-key") == REUSED_KEY:
            self.respond_problem(
                "idempotency.key-reused",
                409,
                "Idempotency key reused",
                "This idempotency key was used for a different request.",
            )
            return
        self.respond(202, {"id": MESSAGE_ID, "status": "queued", "links": LINKS})

    def respond(self, status: int, document: object) -> None:
        payload = json.dumps(document).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("traceparent", TRACEPARENT)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def respond_problem(self, code: str, status: int, title: str, detail: str) -> None:
        payload = json.dumps({
            "type": PROBLEM_BASE + code.replace(".", "/"),
            "title": title,
            "status": status,
            "detail": detail,
            "code": code,
            "traceId": TRACE_ID,
        }).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/problem+json")
        self.send_header("traceparent", TRACEPARENT)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


class NativeRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.server.server_address
        cls.base_url = f"http://{host}:{port}/tenant/"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self) -> None:
        _Handler.observations.clear()
        self.client = MessagingClient(self.base_url)

    def test_health_and_ready_complete_without_a_value(self) -> None:
        self.assertEqual(
            self.client.health(),
            {"kind": "complete", "value": None, "trace_id": TRACE_ID},
        )
        self.assertEqual(
            self.client.ready(),
            {"kind": "complete", "value": None, "trace_id": TRACE_ID},
        )
        self.assertEqual(
            [observed["path"] for observed in _Handler.observations],
            ["/tenant/health", "/tenant/ready"],
        )
        self.assertEqual(_Handler.observations[0]["authorization"], "")

    def test_submit_carries_the_idempotency_key_and_answers_the_receipt(self) -> None:
        receipt = self.client.submit("one-call-token", "reminder-2026-09-25-0001", SUBMISSION)

        self.assertEqual(receipt["kind"], "complete")
        self.assertEqual(receipt["trace_id"], TRACE_ID)
        self.assertEqual(receipt["value"], {"id": MESSAGE_ID, "status": "queued", "links": LINKS})
        observed = _Handler.observations[-1]
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["path"], "/tenant/v1/messages")
        self.assertEqual(observed["authorization"], "Bearer one-call-token")
        self.assertEqual(observed["idempotency_key"], "reminder-2026-09-25-0001")
        self.assertEqual(observed["content_type"], "application/json")
        self.assertEqual(json.loads(observed["body"]), SUBMISSION)

    def test_submit_refuses_a_key_outside_the_header_grammar_before_io(self) -> None:
        for key in ("", "two words", "café", "line\nbreak", "k" * 129):
            with self.subTest(key=key[:12]):
                with self.assertRaises(MessagingClientError) as raised:
                    self.client.submit("one-call-token", key, SUBMISSION)
                self.assertEqual(raised.exception.kind, "invalid_request")
        self.assertEqual(_Handler.observations, [])

    def test_message_reads_the_view(self) -> None:
        outcome = self.client.message("one-call-token", MESSAGE_ID)

        self.assertEqual(outcome, {"kind": "complete", "value": VIEW, "trace_id": TRACE_ID})
        observed = _Handler.observations[-1]
        self.assertEqual(observed["method"], "GET")
        self.assertEqual(observed["path"], f"/tenant/v1/messages/{MESSAGE_ID}")
        self.assertEqual(observed["authorization"], "Bearer one-call-token")

    def test_message_refuses_a_non_canonical_identifier_before_io(self) -> None:
        with self.assertRaises(MessagingClientError) as raised:
            self.client.message("one-call-token", MESSAGE_ID.upper())
        self.assertEqual(raised.exception.kind, "invalid_request")
        self.assertEqual(_Handler.observations, [])

    def test_reused_idempotency_key_is_the_mapped_problem(self) -> None:
        with self.assertRaises(MessagingClientError) as raised:
            self.client.submit("answered-token-canary", REUSED_KEY, SUBMISSION)

        error = raised.exception
        self.assertEqual(error.kind, "problem")
        self.assertEqual(error.status, 409)
        self.assertEqual(error.code, "idempotency.key-reused")
        self.assertEqual(error.title, "Idempotency key reused")
        self.assertEqual(error.detail, "This idempotency key was used for a different request.")
        self.assertEqual(str(error), error.detail)
        self.assertEqual(error.trace_id, TRACE_ID)
        self.assertIsNone(error.protocol_failure)
        self.assertIsNone(error.transport_kind)
        rendered = "\n".join((str(error), repr(error), repr(vars(error))))
        self.assertNotIn("canary", rendered)

    def test_invisible_message_is_the_mapped_not_visible_problem(self) -> None:
        with self.assertRaises(MessagingClientError) as raised:
            self.client.message("one-call-token", HIDDEN_ID)
        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.status, 404)
        self.assertEqual(raised.exception.code, "message.not-visible")

    def test_cancel_posts_to_the_cancel_route_and_answers_the_cancelled_view(self) -> None:
        outcome = self.client.cancel("one-call-token", MESSAGE_ID)

        self.assertEqual(outcome, {"kind": "complete", "value": CANCELLED_VIEW, "trace_id": TRACE_ID})
        observed = _Handler.observations[-1]
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["path"], f"/tenant/v1/messages/{MESSAGE_ID}/cancel")
        self.assertEqual(observed["authorization"], "Bearer one-call-token")
        self.assertEqual(observed["idempotency_key"], "")
        self.assertEqual(observed["body"], "")

    def test_cancel_refuses_a_non_canonical_identifier_before_io(self) -> None:
        for message_id in ("", "../ready", MESSAGE_ID.upper()):
            with self.subTest(message_id=message_id):
                with self.assertRaises(MessagingClientError) as raised:
                    self.client.cancel("one-call-token", message_id)
                self.assertEqual(raised.exception.kind, "invalid_request")
        self.assertEqual(_Handler.observations, [])

    def test_a_cancellation_that_lost_the_race_is_the_mapped_conflict(self) -> None:
        with self.assertRaises(MessagingClientError) as raised:
            self.client.cancel("answered-token-canary", RACED_ID)

        error = raised.exception
        self.assertEqual(error.kind, "problem")
        self.assertEqual(error.status, 409)
        self.assertEqual(error.code, "message.dispatch-started")
        self.assertEqual(error.trace_id, TRACE_ID)
        rendered = "\n".join((str(error), repr(error), repr(vars(error))))
        self.assertNotIn("canary", rendered)

    def test_preview_posts_the_locale_and_data_and_answers_the_rendered_parts(self) -> None:
        outcome = self.client.preview("one-call-token", "appointment-reminder", "1", PREVIEW_REQUEST)

        self.assertEqual(outcome, {"kind": "complete", "value": PREVIEW, "trace_id": TRACE_ID})
        observed = _Handler.observations[-1]
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["path"], PREVIEW_PATH)
        self.assertEqual(observed["authorization"], "Bearer one-call-token")
        self.assertEqual(observed["content_type"], "application/json")
        self.assertEqual(json.loads(observed["body"]), PREVIEW_REQUEST)

    def test_preview_refuses_a_template_name_outside_the_package_grammar_before_io(self) -> None:
        for template_id, version in (("", "1"), ("../ready", "1"), ("Reminder", "1"), ("reminder", "1/preview")):
            with self.subTest(template_id=template_id, version=version):
                with self.assertRaises(MessagingClientError) as raised:
                    self.client.preview("one-call-token", template_id, version, PREVIEW_REQUEST)
                self.assertEqual(raised.exception.kind, "invalid_request")
        with self.assertRaises(MessagingClientError) as raised:
            self.client.preview("one-call-token", "reminder", "1", {**PREVIEW_REQUEST, "channel": "sms"})
        self.assertEqual(raised.exception.kind, "invalid_request")
        self.assertEqual(_Handler.observations, [])

    def test_a_template_refusal_is_the_mapped_problem(self) -> None:
        with self.assertRaises(MessagingClientError) as raised:
            self.client.preview("one-call-token", "appointment-reminder", "2", PREVIEW_REQUEST)
        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.status, 422)
        self.assertEqual(raised.exception.code, "template.locale-unavailable")

    def test_unreachable_service_is_a_transport_failure(self) -> None:
        probe = HTTPServer(("127.0.0.1", 0), _Handler)
        host, port = probe.server_address
        probe.server_close()
        client = MessagingClient(f"http://{host}:{port}/", connect_timeout_seconds=1.0)
        with self.assertRaises(MessagingClientError) as raised:
            client.health()
        self.assertEqual(raised.exception.kind, "transport")
        self.assertIsInstance(raised.exception.transport_kind, str)


if __name__ == "__main__":
    unittest.main()
