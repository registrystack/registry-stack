from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qsl, urlsplit

from bootstrap import ensure_built

ensure_built()

from registry_scheduling_client import SchedulingClient, SchedulingClientError  # noqa: E402

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
PROBLEM_BASE = "https://id.registrystack.org/problems/registry-scheduling/"
HOLD_ID = "0199d0e0-8f2a-7c3b-9d4e-5f6a7b8c9d0e"
APPOINTMENT_ID = "0199d0e0-8f2a-7c3b-9d4e-5f6a7b8c9d0f"
STALE_ID = "0199d0e0-8f2a-7c3b-9d4e-5f6a7b8c9d10"
UNKNOWN_CODE_ID = "0199d0e0-8f2a-7c3b-9d4e-5f6a7b8c9d11"
REUSED_KEY = "reused-key"
EXHAUSTED_KEY = "exhausted-key"
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
# The Rust client serializes every optional admission member it does not
# skip, so the wire body names the omitted ones as null.
ADMISSION_ON_THE_WIRE = {**ADMISSION, "channel": None, "duplicateKey": None, "windowRevision": None}
SERVICE = {"schedulingId": "scheduling-1", "policyRevision": 3, "policyDigest": "sha256:abc"}
SERVICES = {"items": [{"id": "registry-update", "label": "Registry update"}], "nextCursor": "next-1"}
RESOURCES = {
    "items": [{"resourceId": "clerk-1", "pool": "clerks", "capabilities": ["registry"], "available": True}],
    "nextCursor": None,
}
LOCATIONS = {"items": [{"locationId": "office-1", "timezone": "Africa/Nairobi"}], "nextCursor": None}
OFFERINGS = {
    "items": [{
        "id": "registry-update-30",
        "service": "registry-update",
        "label": "Registry update, 30 minutes",
        "mode": "exact-time",
        "location": "office-1",
        "leadTimeMinutes": 60,
        "horizonDays": 30,
        "cancellationCutoffMinutes": 120,
        "durationMinutes": 30,
        "bufferBeforeMinutes": None,
        "bufferAfterMinutes": 5,
        "startIncrementMinutes": 30,
        "maxRecipients": 1,
        "window": None,
        "reminders": [{"minutesBefore": 1440}],
        "requiresCapabilities": [],
        "prerequisites": [],
    }],
    "nextCursor": None,
}
AVAILABILITY = {
    "items": [
        {"kind": "slot", "start": "2026-10-05T09:00:00Z", "end": "2026-10-05T09:30:00Z", "free": 2},
        {
            "kind": "window",
            "window": "morning",
            "start": "2026-10-05T08:00:00Z",
            "end": "2026-10-05T12:00:00Z",
            "remaining": 7,
            "channelRemaining": None,
        },
    ],
    "nextCursor": "next-1",
}
EXPLANATION = {
    "offering": "registry-update-30",
    "start": "2026-10-05T09:00:00Z",
    "publicCode": "capacity.exhausted",
    "explanation": "Every clerk is booked.",
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
APPOINTMENT = {
    "appointmentId": APPOINTMENT_ID,
    "offering": "registry-update-30",
    "start": "2026-10-05T09:00:00Z",
    "end": "2026-10-05T09:30:00Z",
    "resource": "clerk-1",
    "units": 1,
    "channel": None,
    "revision": 1,
    "state": "confirmed",
    "policyRevision": 3,
    "createdAt": "2026-10-04T08:00:00Z",
    "cancelledAt": None,
    "externalReferences": [REFERENCE],
}
CANCELLED = {**APPOINTMENT, "revision": 2, "state": "cancelled", "cancelledAt": "2026-10-04T09:00:00Z"}
HISTORY = {
    "items": [{
        "eventId": "event-1",
        "kind": "appointment.confirmed",
        "revision": 1,
        "occurredAt": "2026-10-04T08:00:00Z",
        "actor": None,
        "detail": {"channel": None, "units": 1},
    }],
    "nextCursor": None,
}
APPOINTMENTS = {"items": [APPOINTMENT], "nextCursor": None}
ANSWERS = {
    ("GET", "/tenant/v1/scheduling"): SERVICE,
    ("GET", "/tenant/v1/services"): SERVICES,
    ("GET", "/tenant/v1/offerings"): OFFERINGS,
    ("GET", "/tenant/v1/resources"): RESOURCES,
    ("GET", "/tenant/v1/locations"): LOCATIONS,
    ("GET", "/tenant/v1/availability"): AVAILABILITY,
    ("GET", "/tenant/v1/availability/explain"): EXPLANATION,
    ("GET", f"/tenant/v1/appointments/{APPOINTMENT_ID}"): APPOINTMENT,
    ("GET", f"/tenant/v1/appointments/{APPOINTMENT_ID}/history"): HISTORY,
    ("GET", "/tenant/v1/appointments"): APPOINTMENTS,
    ("POST", f"/tenant/v1/appointments/{APPOINTMENT_ID}/reschedule"): APPOINTMENT,
    ("POST", f"/tenant/v1/appointments/{APPOINTMENT_ID}/cancel"): CANCELLED,
}


class _Handler(BaseHTTPRequestHandler):
    observations: list[dict[str, object]] = []

    def observe(self, body: str = "") -> tuple[str, dict[str, str]]:
        parts = urlsplit(self.path)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        self.observations.append({
            "method": self.command,
            "path": parts.path,
            "query": query,
            "authorization": self.headers.get("authorization", ""),
            "idempotency_key": self.headers.get("idempotency-key", ""),
            "content_type": self.headers.get("content-type", ""),
            "body": body,
        })
        return parts.path, query

    def do_GET(self) -> None:  # noqa: N802
        path, _ = self.observe()
        if path == f"/tenant/v1/appointments/{UNKNOWN_CODE_ID}":
            self.respond_problem("capacity.future", 409, "Future", "Future.")
            return
        self.answer("GET", path)

    def do_DELETE(self) -> None:  # noqa: N802
        path, _ = self.observe()
        if path == f"/tenant/v1/holds/{HOLD_ID}":
            self.send_response(204)
            self.send_header("traceparent", TRACEPARENT)
            self.end_headers()
            return
        self.respond_problem(
            "hold.expired",
            410,
            "Hold expired",
            "The hold expired before confirmation. Its capacity is bookable again; start a new request.",
        )

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        path, _ = self.observe(body)
        key = self.headers.get("idempotency-key")
        if key == REUSED_KEY:
            self.respond_problem(
                "idempotency.key-reused",
                409,
                "Idempotency key reused",
                "This idempotency key was used for a different request.",
            )
            return
        if key == EXHAUSTED_KEY:
            self.respond_problem(
                "capacity.exhausted",
                409,
                "Capacity exhausted",
                "The supply is fully committed for the requested interval. Choose another time.",
            )
            return
        if path == f"/tenant/v1/appointments/{STALE_ID}/cancel":
            self.respond_problem(
                "revision.mismatch",
                412,
                "Revision mismatch",
                "The window revision changed before the request committed. Reload the catalogue and try again.",
            )
            return
        if path == "/tenant/v1/holds":
            self.respond(201, HOLD)
            return
        if path == "/tenant/v1/appointments":
            self.respond(201, APPOINTMENT)
            return
        self.answer("POST", path)

    def answer(self, method: str, path: str) -> None:
        document = ANSWERS.get((method, path))
        if document is None:
            self.respond_problem("request.not-found", 404, "Route not found", "The requested route does not exist.")
            return
        self.respond(200, document)

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
        self.client = SchedulingClient(self.base_url)

    def complete(self, value: object) -> dict[str, object]:
        return {"kind": "complete", "value": value, "trace_id": TRACE_ID}

    def assert_refused_before_io(self, *calls) -> None:
        for index, call in enumerate(calls):
            with self.subTest(call=index):
                with self.assertRaises(SchedulingClientError) as raised:
                    call()
                self.assertEqual(raised.exception.kind, "invalid-request")
        self.assertEqual(_Handler.observations, [])

    def test_get_scheduling_answers_the_deployment_with_the_answered_trace(self) -> None:
        self.assertEqual(self.client.get_scheduling("one-call-token"), self.complete(SERVICE))
        observed = _Handler.observations[-1]
        self.assertEqual(observed["method"], "GET")
        self.assertEqual(observed["path"], "/tenant/v1/scheduling")
        self.assertEqual(observed["authorization"], "Bearer one-call-token")

    def test_catalogue_listings_carry_the_caller_cursor(self) -> None:
        self.assertEqual(self.client.list_services("one-call-token"), self.complete(SERVICES))
        self.assertEqual(self.client.list_offerings("one-call-token", "cursor-2"), self.complete(OFFERINGS))
        self.assertEqual(self.client.list_resources("one-call-token", cursor=None), self.complete(RESOURCES))
        self.assertEqual(self.client.list_locations("one-call-token"), self.complete(LOCATIONS))
        self.assertEqual(
            [(observed["path"], observed["query"]) for observed in _Handler.observations],
            [
                ("/tenant/v1/services", {}),
                ("/tenant/v1/offerings", {"cursor": "cursor-2"}),
                ("/tenant/v1/resources", {}),
                ("/tenant/v1/locations", {}),
            ],
        )

    def test_availability_carries_the_offering_interval_and_page_bounds(self) -> None:
        outcome = self.client.availability(
            "one-call-token",
            "registry-update-30",
            start="2026-10-05T08:00:00Z",
            end="2026-10-05T15:00:00+03:00",
            cursor="cursor-1",
            limit=25,
        )

        self.assertEqual(outcome, self.complete(AVAILABILITY))
        self.assertEqual(_Handler.observations[-1]["path"], "/tenant/v1/availability")
        self.assertEqual(_Handler.observations[-1]["query"], {
            "offering": "registry-update-30",
            "start": "2026-10-05T08:00:00Z",
            "end": "2026-10-05T12:00:00Z",
            "cursor": "cursor-1",
            "limit": "25",
        })
        self.client.availability("one-call-token", "registry-update-30")
        self.assertEqual(_Handler.observations[-1]["query"], {"offering": "registry-update-30"})

    def test_availability_refuses_a_selector_instant_or_bound_outside_its_grammar_before_io(self) -> None:
        self.assert_refused_before_io(
            lambda: self.client.availability("one-call-token", "Registry_Update"),
            lambda: self.client.availability("one-call-token", "registry/update"),
            lambda: self.client.availability("one-call-token", "registry-update-30", start="tomorrow"),
            lambda: self.client.availability("one-call-token", "registry-update-30", end="2026-10-05"),
            lambda: self.client.availability("one-call-token", "registry-update-30", cursor=""),
            lambda: self.client.availability("one-call-token", "registry-update-30", limit=0),
            lambda: self.client.availability("one-call-token", "registry-update-30", limit=-1),
            lambda: self.client.availability("one-call-token", "registry-update-30", limit=2**32),
        )

    def test_explain_carries_the_offering_and_start(self) -> None:
        outcome = self.client.explain("one-call-token", "registry-update-30", "2026-10-05T12:00:00+03:00")

        self.assertEqual(outcome, self.complete(EXPLANATION))
        self.assertEqual(_Handler.observations[-1]["path"], "/tenant/v1/availability/explain")
        self.assertEqual(
            _Handler.observations[-1]["query"],
            {"offering": "registry-update-30", "start": "2026-10-05T09:00:00Z"},
        )

    def test_create_hold_carries_the_idempotency_key_and_answers_the_hold(self) -> None:
        outcome = self.client.create_hold("one-call-token", "hold-2026-10-05-0001", ADMISSION)

        self.assertEqual(outcome, self.complete(HOLD))
        observed = _Handler.observations[-1]
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["path"], "/tenant/v1/holds")
        self.assertEqual(observed["authorization"], "Bearer one-call-token")
        self.assertEqual(observed["idempotency_key"], "hold-2026-10-05-0001")
        self.assertEqual(observed["content_type"], "application/json")
        self.assertEqual(json.loads(observed["body"]), ADMISSION_ON_THE_WIRE)

    def test_mutations_refuse_a_key_outside_the_header_grammar_before_io(self) -> None:
        calls = []
        for key in ("", "two words", "café", "line\nbreak", "k" * 129):
            calls.append(lambda key=key: self.client.create_hold("one-call-token", key, ADMISSION))
            calls.append(lambda key=key: self.client.create_appointment("one-call-token", key, {"hold": HOLD_ID}))
            calls.append(lambda key=key: self.client.reschedule_appointment(
                "one-call-token", APPOINTMENT_ID, key, {"observedRevision": 1, "admission": ADMISSION},
            ))
            calls.append(lambda key=key: self.client.cancel_appointment(
                "one-call-token", APPOINTMENT_ID, key, {"observedRevision": 1},
            ))
        self.assert_refused_before_io(*calls)

    def test_release_hold_deletes_the_hold_and_completes_without_a_value(self) -> None:
        self.assertEqual(self.client.release_hold("one-call-token", HOLD_ID), self.complete(None))
        observed = _Handler.observations[-1]
        self.assertEqual(observed["method"], "DELETE")
        self.assertEqual(observed["path"], f"/tenant/v1/holds/{HOLD_ID}")
        self.assertEqual(observed["idempotency_key"], "")

    def test_route_identifiers_stay_one_path_segment(self) -> None:
        calls = []
        for identifier in ("", "../ready", "appt/1", "appt%2F1", "space id", "x" * 129):
            calls.append(lambda identifier=identifier: self.client.release_hold("one-call-token", identifier))
            calls.append(lambda identifier=identifier: self.client.get_appointment("one-call-token", identifier))
            calls.append(lambda identifier=identifier: self.client.appointment_history("one-call-token", identifier))
        self.assert_refused_before_io(*calls)

    def test_create_appointment_confirms_a_hold_or_books_directly(self) -> None:
        self.assertEqual(
            self.client.create_appointment("one-call-token", "confirm-1", {"hold": HOLD_ID}),
            self.complete(APPOINTMENT),
        )
        self.client.create_appointment("one-call-token", "direct-1", {"admission": ADMISSION})
        self.assertEqual(
            [json.loads(observed["body"]) for observed in _Handler.observations],
            [{"hold": HOLD_ID, "admission": None}, {"hold": None, "admission": ADMISSION_ON_THE_WIRE}],
        )
        self.assertEqual(
            [observed["idempotency_key"] for observed in _Handler.observations],
            ["confirm-1", "direct-1"],
        )

    def test_get_appointment_and_history_read_what_the_runtime_serves(self) -> None:
        self.assertEqual(self.client.get_appointment("one-call-token", APPOINTMENT_ID), self.complete(APPOINTMENT))
        self.assertEqual(
            self.client.appointment_history("one-call-token", APPOINTMENT_ID, "cursor-1"),
            self.complete(HISTORY),
        )
        self.assertEqual(
            _Handler.observations[-1]["path"], f"/tenant/v1/appointments/{APPOINTMENT_ID}/history"
        )
        self.assertEqual(_Handler.observations[-1]["query"], {"cursor": "cursor-1"})

    def test_list_appointments_selects_by_external_reference(self) -> None:
        outcome = self.client.list_appointments("one-call-token", REFERENCE, cursor="cursor-1", limit=10)

        self.assertEqual(outcome, self.complete(APPOINTMENTS))
        self.assertEqual(_Handler.observations[-1]["query"], {
            "externalReferenceProduct": "casework",
            "externalReferenceRecordType": "review-task",
            "externalReferenceIdentifier": "case:1234",
            "cursor": "cursor-1",
            "limit": "10",
        })

    def test_list_appointments_refuses_a_reference_or_bound_outside_its_grammar_before_io(self) -> None:
        self.assert_refused_before_io(
            lambda: self.client.list_appointments("one-call-token", {**REFERENCE, "product": "Casework"}),
            lambda: self.client.list_appointments("one-call-token", {**REFERENCE, "identifier": " "}),
            lambda: self.client.list_appointments("one-call-token", {**REFERENCE, "extra": "x"}),
            lambda: self.client.list_appointments("one-call-token", REFERENCE, limit=0),
            lambda: self.client.list_appointments("one-call-token", REFERENCE, cursor="x" * 4097),
        )

    def test_reschedule_and_cancel_carry_the_observed_revision_and_the_caller_key(self) -> None:
        moved = self.client.reschedule_appointment(
            "one-call-token", APPOINTMENT_ID, "move-1", {"observedRevision": 1, "admission": ADMISSION},
        )
        cancelled = self.client.cancel_appointment(
            "one-call-token", APPOINTMENT_ID, "cancel-1", {"observedRevision": 2, "reason": "moved away"},
        )

        self.assertEqual(moved, self.complete(APPOINTMENT))
        self.assertEqual(cancelled, self.complete(CANCELLED))
        self.assertEqual(
            [(o["method"], o["path"], o["idempotency_key"], json.loads(o["body"])) for o in _Handler.observations],
            [
                (
                    "POST",
                    f"/tenant/v1/appointments/{APPOINTMENT_ID}/reschedule",
                    "move-1",
                    {"observedRevision": 1, "admission": ADMISSION_ON_THE_WIRE},
                ),
                (
                    "POST",
                    f"/tenant/v1/appointments/{APPOINTMENT_ID}/cancel",
                    "cancel-1",
                    {"observedRevision": 2, "reason": "moved away"},
                ),
            ],
        )

    def test_reused_idempotency_key_is_the_mapped_problem(self) -> None:
        with self.assertRaises(SchedulingClientError) as raised:
            self.client.create_hold("answered-token-canary", REUSED_KEY, ADMISSION)

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
        self.assertFalse(hasattr(error, "retry_after_seconds"))
        rendered = "\n".join((str(error), repr(error), repr(vars(error))))
        self.assertNotIn("canary", rendered)

    def test_capacity_and_revision_refusals_are_the_mapped_problems(self) -> None:
        with self.assertRaises(SchedulingClientError) as raised:
            self.client.create_appointment("one-call-token", EXHAUSTED_KEY, {"admission": ADMISSION})
        self.assertEqual(raised.exception.code, "capacity.exhausted")
        self.assertEqual(raised.exception.status, 409)
        self.assertEqual(raised.exception.title, "Capacity exhausted")

        with self.assertRaises(SchedulingClientError) as raised:
            self.client.cancel_appointment("one-call-token", STALE_ID, "cancel-1", {"observedRevision": 1})
        self.assertEqual(raised.exception.code, "revision.mismatch")
        self.assertEqual(raised.exception.status, 412)

        with self.assertRaises(SchedulingClientError) as raised:
            self.client.release_hold("one-call-token", "expired-hold")
        self.assertEqual(raised.exception.code, "hold.expired")
        self.assertEqual(raised.exception.status, 410)

    def test_a_code_outside_the_closed_catalogue_is_a_protocol_failure(self) -> None:
        with self.assertRaises(SchedulingClientError) as raised:
            self.client.get_appointment("one-call-token", UNKNOWN_CODE_ID)
        self.assertEqual(raised.exception.kind, "protocol")
        self.assertEqual(raised.exception.status, 409)
        self.assertEqual(raised.exception.protocol_failure, "problem")
        self.assertIsNone(raised.exception.code)

    def test_unreachable_service_is_a_transport_failure(self) -> None:
        probe = HTTPServer(("127.0.0.1", 0), _Handler)
        host, port = probe.server_address
        probe.server_close()
        client = SchedulingClient(f"http://{host}:{port}/", connect_timeout_seconds=1.0)
        with self.assertRaises(SchedulingClientError) as raised:
            client.get_scheduling("one-call-token")
        self.assertEqual(raised.exception.kind, "transport")
        self.assertIsInstance(raised.exception.transport_kind, str)


if __name__ == "__main__":
    unittest.main()
