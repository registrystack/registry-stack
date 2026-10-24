from __future__ import annotations

import json
import threading
import unittest
from unittest.mock import patch
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
    "durationMinutes": 1500,
    "resource": "clerk-2",
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
OPERATIONAL = {
    "items": [{
        "appointmentId": "appointment-1",
        "revision": 2,
        "service": "registry-update",
        "location": "office-1",
        "offering": "registry-update-30",
        "state": "confirmed",
        "displayedStart": "2026-10-05T09:00:00Z",
        "displayedEnd": "2026-10-06T10:00:00Z",
        "resource": "clerk-2",
        "units": 1,
    }],
    "nextCursor": "next",
}
OFFERINGS = {
    "items": [{
        "id": "registry-update-30",
        "service": "registry-update",
        "label": "Registry update, 30 minutes",
        "mode": "exact-time",
        "location": "office-1",
        "pool": "clerks",
        "leadTimeMinutes": 60,
        "horizonDays": 30,
        "cancellationCutoffMinutes": 120,
        "durationMinutes": 30,
        "durationSelection": {"minimumMinutes": 15, "maximumMinutes": 60, "incrementMinutes": 15},
        "openingCoverage": "occupied-interval",
        "allowResourceSelection": True,
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
PREVIEW = {
    "offering": "room", "start": "2026-10-05T09:00:00Z",
    "end": "2026-10-05T10:00:00Z", "capacityAvailable": True,
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
BUSY_REQUEST = {
    "expectedRevision": 0, "observedAt": "2026-10-05T08:00:00Z",
    "freshUntil": "2026-10-05T09:00:00Z", "status": "fresh",
    "coverage": {"start": "2026-10-05T00:00:00Z", "end": "2026-10-06T00:00:00Z", "resources": ["room-a"]},
    "records": [{"externalUid": "event-1", "externalRevision": "v1", "resource": "room-a", "start": "2026-10-05T10:00:00Z", "end": "2026-10-05T11:00:00Z"}],
}
BUSY_COUNTS = {
    "sourceId": "calendar-a", "requestDigest": "sha256:abc",
    "added": 1, "changed": 0, "deleted": 0,
    "retainedOutsideAuthority": 0, "retainedAcrossCoverageBoundary": 0,
    "impacts": {"total": 1, "detailsAvailable": False, "truncated": True},
}
BUSY_PREVIEW = {**BUSY_COUNTS, "expectedRevision": 0, "currentRevision": 0}
BUSY_APPLIED = {**BUSY_COUNTS, "kind": "applied", "revision": 1}

ATTENDANCE_REQUEST = {
    "observedAppointmentRevision": 7, "observedRevision": 0,
    "state": "arrived", "observedAt": "2026-10-05T09:05:00Z",
}
ATTENDANCE = {
    "appointmentId": APPOINTMENT_ID, "appointmentRevision": 7, "revision": 3,
    "state": "arrived", "observedAt": ATTENDANCE_REQUEST["observedAt"],
    "recordedAt": "2026-10-05T09:06:00Z",
}

ANSWERS = {
    ("PUT", f"/tenant/v1/appointments/{APPOINTMENT_ID}/attendance"): ATTENDANCE,
    ("GET", "/tenant/v1/scheduling"): SERVICE,
    ("GET", "/tenant/v1/services"): SERVICES,
    ("GET", "/tenant/v1/offerings"): OFFERINGS,
    ("GET", "/tenant/v1/resources"): RESOURCES,
    ("GET", "/tenant/v1/locations"): LOCATIONS,
    ("GET", "/tenant/v1/operational/appointments"): OPERATIONAL,
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

    def do_PUT(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        path, _ = self.observe(self.rfile.read(length).decode("utf-8"))
        self.answer("PUT", path)

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
        path, query = self.observe(body)
        key = self.headers.get("idempotency-key")
        if path.startswith("/tenant/v1/source-busy/"):
            if query.get("profile") == "failing":
                self.respond_problem("service.unavailable", 503, "Service unavailable", "server-detail-canary")
            else:
                self.respond(200, BUSY_PREVIEW if path.endswith("/preview") else BUSY_APPLIED)
            return
        if path == "/tenant/v1/appointments/receipt":
            failures = {
                "unresolved-key-canary": ("receipt.unresolved", 409, "Original receipt unresolved", "No retained success receipt matches this caller, key, and original request. The original outcome remains unknown; this is not evidence that no effect occurred."),
                "denied-key-canary": ("operation.not-authorized", 403, "Operation not authorized", "server-detail-canary"),
                "unavailable-key-canary": ("service.unavailable", 503, "Service unavailable", "server-detail-canary"),
            }
            failure = failures.get(self.headers.get("idempotency-key"))
            if failure:
                self.respond_problem(*failure)
            else:
                self.respond(200, APPOINTMENT)
            return

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
                "The observed revision is no longer current.",
            )
            return
        if path == "/tenant/v1/holds":
            self.respond(201, HOLD)
            return
        if path == "/tenant/v1/availability/preview":
            self.respond(200, PREVIEW)
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
    def test_attendance_preserves_observed_visit_revision_and_caller_key(self) -> None:
        result = self.client.record_attendance("token", APPOINTMENT_ID, "observation-1", ATTENDANCE_REQUEST)
        self.assertEqual(result["value"], ATTENDANCE)
        self.assertEqual(len(_Handler.observations), 1)
        sent = _Handler.observations[0]
        self.assertEqual(sent["method"], "PUT")
        self.assertEqual(sent["path"], f"/tenant/v1/appointments/{APPOINTMENT_ID}/attendance")
        self.assertEqual(sent["idempotency_key"], "observation-1")
        self.assertEqual(json.loads(sent["body"]), ATTENDANCE_REQUEST)

    def test_attendance_refuses_unknown_fields_invalid_states_and_invalid_revisions_before_io(self) -> None:
        for request in (
            {**ATTENDANCE_REQUEST, "attendees": ["person-1"]},
            {**ATTENDANCE_REQUEST, "state": "withdrawn"},
            {**ATTENDANCE_REQUEST, "observedRevision": -1},
        ):
            with self.subTest(request=request), self.assertRaises(SchedulingClientError) as raised:
                self.client.record_attendance("token", APPOINTMENT_ID, "observation-1", request)
            self.assertEqual(raised.exception.kind, "invalid-request")
        self.assertEqual(_Handler.observations, [])

    def test_appointment_detail_preserves_minimized_attendance(self) -> None:
        with patch.dict(APPOINTMENT, {"revision": 7, "attendance": ATTENDANCE}):
            self.assertEqual(self.client.get_appointment("token", APPOINTMENT_ID)["value"], APPOINTMENT)

    def test_arrival_catalogue_preserves_every_window_an_offering_serves(self) -> None:
        windows = [
            {"id": "day-one", "revision": 1, "start": "2026-10-05T09:00:00Z",
             "end": "2026-10-05T11:00:00Z", "units": 12},
            {"id": "day-two", "revision": 2, "start": "2026-10-12T09:00:00Z",
             "end": "2026-10-12T11:00:00Z", "units": 8},
        ]
        offering = {**OFFERINGS["items"][0], "mode": "arrival-window", "window": None,
                    "windows": windows}
        offering.pop("pool", None)
        page = {"items": [offering], "nextCursor": None}
        with patch.dict(ANSWERS, {("GET", "/tenant/v1/offerings"): page}):
            self.assertEqual(self.client.list_offerings("token")["value"], page)

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
            duration_minutes=1500,
            resource="clerk-2",
        )

        self.assertEqual(outcome, self.complete(AVAILABILITY))
        self.assertEqual(_Handler.observations[-1]["path"], "/tenant/v1/availability")
        self.assertEqual(_Handler.observations[-1]["query"], {
            "offering": "registry-update-30",
            "start": "2026-10-05T08:00:00Z",
            "end": "2026-10-05T12:00:00Z",
            "cursor": "cursor-1",
            "limit": "25",
            "durationMinutes": "1500",
            "resource": "clerk-2",
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
            lambda: self.client.availability("one-call-token", "registry-update-30", duration_minutes=0),
            lambda: self.client.availability("one-call-token", "registry-update-30", duration_minutes=10081),
            lambda: self.client.availability("one-call-token", "registry-update-30", duration_minutes=-1),
            lambda: self.client.availability("one-call-token", "registry-update-30", duration_minutes=1.5),
            lambda: self.client.availability("one-call-token", "registry-update-30", duration_minutes=True),
            lambda: self.client.availability("one-call-token", "registry-update-30", resource="clerk/2"),
        )

    def test_explain_carries_the_offering_and_start(self) -> None:
        outcome = self.client.explain("one-call-token", "registry-update-30", "2026-10-05T12:00:00+03:00")

        self.assertEqual(outcome, self.complete(EXPLANATION))
        self.assertEqual(_Handler.observations[-1]["path"], "/tenant/v1/availability/explain")
        self.assertEqual(
            _Handler.observations[-1]["query"],
            {"offering": "registry-update-30", "start": "2026-10-05T09:00:00Z"},
        )
        self.client.explain(
            "one-call-token",
            "registry-update-30",
            "2026-10-05T12:00:00+03:00",
            duration_minutes=45,
            resource="clerk-2",
        )
        self.assertEqual(
            _Handler.observations[-1]["query"],
            {
                "offering": "registry-update-30",
                "start": "2026-10-05T09:00:00Z",
                "durationMinutes": "45",
                "resource": "clerk-2",
            },
        )

        count = len(_Handler.observations)
        for call in (
            lambda: self.client.explain(
                "one-call-token", "registry-update-30", "2026-10-05T09:00:00Z", duration_minutes=0,
            ),
            lambda: self.client.explain(
                "one-call-token", "registry-update-30", "2026-10-05T09:00:00Z", duration_minutes=10081,
            ),
            lambda: self.client.explain(
                "one-call-token", "registry-update-30", "2026-10-05T09:00:00Z", duration_minutes=-1,
            ),
            lambda: self.client.explain(
                "one-call-token", "registry-update-30", "2026-10-05T09:00:00Z", duration_minutes=1.5,
            ),
            lambda: self.client.explain(
                "one-call-token", "registry-update-30", "2026-10-05T09:00:00Z", duration_minutes=True,
            ),
            lambda: self.client.explain(
                "one-call-token", "registry-update-30", "2026-10-05T09:00:00Z", resource="clerk/2",
            ),
        ):
            with self.assertRaises(SchedulingClientError):
                call()
        self.assertEqual(len(_Handler.observations), count)

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

    def test_resource_hold_preserves_party_references_without_invented_counts(self) -> None:
        request = {**ADMISSION, "manager": "schedulingManager", "partyReferences": [
            {"role": "organization", "reference": REFERENCE},
        ]}
        del request["party"]
        self.assertEqual(self.client.create_hold("synthetic-token", "resource-hold", request), self.complete(HOLD))
        observed = _Handler.observations[-1]
        body = json.loads(observed["body"])
        self.assertEqual(body, {
            **request, "channel": None, "duplicateKey": None, "windowRevision": None,
        })
        self.assertNotIn("party", body)

    def test_capacity_preview_uses_the_closed_physical_shape_without_mutation_key(self) -> None:
        request = {"offering": "room", "start": PREVIEW["start"],
                   "additionalAllocations": [{"offering": "chairs", "units": 30}]}
        self.assertEqual(self.client.preview_availability("synthetic-token", request), self.complete(PREVIEW))
        observed = _Handler.observations[-1]
        self.assertEqual(observed["path"], "/tenant/v1/availability/preview")
        self.assertEqual(json.loads(observed["body"]), request)
        self.assertEqual(observed["idempotency_key"], "")

    def test_capacity_preview_refuses_identity_and_invalid_quantity_before_io(self) -> None:
        request = {"offering": "room", "start": PREVIEW["start"]}
        self.assert_refused_before_io(
            lambda: self.client.preview_availability("synthetic-token", {**request, "manager": "schedulingManager"}),
            lambda: self.client.preview_availability("synthetic-token", {**request, "resourceUnits": 0}),
            lambda: self.client.preview_availability("synthetic-token", {**request, "additionalAllocations": [{"offering": "chairs"}] * 16}),
        )

    def test_source_busy_selects_one_profile_and_preserves_cas_and_minimized_impacts(self) -> None:
        self.assertEqual(self.client.preview_source_busy("synthetic-token", "calendar-main", BUSY_REQUEST), self.complete(BUSY_PREVIEW))
        self.assertEqual(self.client.apply_source_busy("synthetic-token", "calendar-main", BUSY_REQUEST), self.complete(BUSY_APPLIED))
        for observed in _Handler.observations:
            self.assertEqual(observed["query"], {"profile": "calendar-main"})
            self.assertEqual(json.loads(observed["body"]), BUSY_REQUEST)
            self.assertEqual(observed["idempotency_key"], "")
        self.assertEqual([row["path"] for row in _Handler.observations], [
            "/tenant/v1/source-busy/preview", "/tenant/v1/source-busy/apply",
        ])

    def test_source_busy_rejects_private_data_and_invalid_coverage_before_io(self) -> None:
        self.assert_refused_before_io(
            lambda: self.client.preview_source_busy("synthetic-token", "../other", BUSY_REQUEST),
            lambda: self.client.apply_source_busy("synthetic-token", "calendar-main", {**BUSY_REQUEST, "sourceId": "other"}),
            lambda: self.client.apply_source_busy("synthetic-token", "calendar-main", {**BUSY_REQUEST, "records": [{**BUSY_REQUEST["records"][0], "description": "private"}]}),
            lambda: self.client.apply_source_busy("synthetic-token", "calendar-main", {**BUSY_REQUEST, "coverage": {**BUSY_REQUEST["coverage"], "resources": []}}),
            lambda: self.client.apply_source_busy("synthetic-token", "calendar-main", {**BUSY_REQUEST, "records": BUSY_REQUEST["records"] * 4097}),
            lambda: self.client.apply_source_busy("synthetic-token", "calendar-main", {**BUSY_REQUEST, "status": "unavailable"}),
        )

    def test_source_busy_uncertain_apply_is_not_automatically_resent(self) -> None:
        with self.assertRaises(SchedulingClientError) as caught:
            self.client.apply_source_busy("synthetic-token", "failing", BUSY_REQUEST)
        self.assertTrue(caught.exception.outcome_unknown)
        self.assertEqual(len(_Handler.observations), 1)

    def test_counted_bundle_hold_roundtrips_allocation_rows(self) -> None:
        allocations = [{
            "requirement": {"kind": "additional", "index": 0},
            "offering": "chairs", "resource": "chairs-a", "units": 30,
            "occupiedStart": HOLD["start"], "occupiedEnd": HOLD["end"],
        }]
        request = {**ADMISSION, "resourceUnits": 2, "additionalAllocations": [
            {"offering": "chairs", "resource": "chairs-a", "units": 30},
        ]}
        del request["party"]
        with patch.dict(HOLD, {"allocations": allocations, "units": 2}):
            outcome = self.client.create_hold("synthetic-token", "bundle-hold", request)
            self.assertEqual(outcome, self.complete(HOLD))
        self.assertEqual(json.loads(_Handler.observations[-1]["body"]), {
            **request, "channel": None, "duplicateKey": None, "windowRevision": None,
        })

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

    def test_operational_listing_carries_one_role_bounded_query(self) -> None:
        query = {
            "service": "registry-update",
            "location": "office-1",
            "start": "2026-10-05T09:00:00Z",
            "end": "2026-10-07T09:00:00Z",
            "timeBasis": "occupied",
            "offering": "registry-update-30",
            "state": "confirmed",
            "resource": "clerk-2",
            "externalReference": REFERENCE,
            "profile": "desk",
            "cursor": "next",
            "limit": 25,
        }
        self.assertEqual(
            self.client.list_operational_appointments("one-call-token", query),
            self.complete(OPERATIONAL),
        )
        self.assertEqual(_Handler.observations[-1]["query"], {
            "service": "registry-update",
            "location": "office-1",
            "start": "2026-10-05T09:00:00Z",
            "end": "2026-10-07T09:00:00Z",
            "timeBasis": "occupied",
            "offering": "registry-update-30",
            "state": "confirmed",
            "resource": "clerk-2",
            "externalReferenceProduct": "casework",
            "externalReferenceRecordType": "review-task",
            "externalReferenceIdentifier": "case:1234",
            "profile": "desk",
            "cursor": "next",
            "limit": "25",
        })

    def test_operational_listing_refuses_an_invalid_role_query_before_io(self) -> None:
        query = {
            "service": "registry-update",
            "location": "office-1",
            "start": "2026-10-05T09:00:00Z",
            "end": "2026-10-07T09:00:00Z",
            "timeBasis": "occupied",
        }
        self.assert_refused_before_io(
            lambda: self.client.list_operational_appointments(
                "one-call-token", {**query, "resource": "clerk/2"}
            ),
            lambda: self.client.list_operational_appointments(
                "one-call-token", {**query, "end": query["start"]}
            ),
            lambda: self.client.list_operational_appointments(
                "one-call-token", {**query, "limit": 0}
            ),
            lambda: self.client.list_operational_appointments(
                "one-call-token", {**query, "extra": "x"}
            ),
        )

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

    def test_receipt_observation_preserves_the_original_request_key_and_current_token(self) -> None:
        result = self.client.appointment_receipt("current-token", "original-key", {"admission": ADMISSION})
        self.assertEqual(result, {"kind": "complete", "value": APPOINTMENT, "trace_id": TRACE_ID})
        self.assertEqual(len(_Handler.observations), 1)
        observed = _Handler.observations[0]
        self.assertEqual(observed["method"], "POST")
        self.assertEqual(observed["path"], "/tenant/v1/appointments/receipt")
        self.assertEqual(observed["authorization"], "Bearer current-token")
        self.assertEqual(observed["idempotency_key"], "original-key")
        self.assertEqual(json.loads(observed["body"]), {"hold": None, "admission": ADMISSION_ON_THE_WIRE})

    def test_receipt_observation_maps_unresolved_and_refused_without_retry_or_disclosure(self) -> None:
        for key, code, status in [
            ("unresolved-key-canary", "receipt.unresolved", 409),
            ("denied-key-canary", "operation.not-authorized", 403),
            ("unavailable-key-canary", "service.unavailable", 503),
        ]:
            with self.subTest(code=code):
                _Handler.observations.clear()
                with self.assertRaises(SchedulingClientError) as raised:
                    self.client.appointment_receipt("token-canary", key, {"admission": ADMISSION})
                error = raised.exception
                self.assertEqual(error.kind, "problem")
                self.assertEqual(error.code, code)
                self.assertEqual(error.status, status)
                self.assertEqual(error.trace_id, TRACE_ID)
                self.assertEqual(error.outcome_unknown, status >= 500)
                rendered = "\n".join((str(error), repr(error), repr(vars(error))))
                for canary in [key, "token-canary", "server-detail-canary"]:
                    self.assertNotIn(canary, rendered)
                self.assertEqual(len(_Handler.observations), 1)
                self.assertEqual(_Handler.observations[0]["path"], "/tenant/v1/appointments/receipt")

    def test_receipt_observation_refuses_invalid_key_or_request_before_exchange(self) -> None:
        for key, request in [("two words", {"admission": ADMISSION}), ("key", {"admission": ADMISSION, "extra": True})]:
            with self.assertRaises(SchedulingClientError) as raised:
                self.client.appointment_receipt("token", key, request)
            self.assertEqual(raised.exception.kind, "invalid-request")
        self.assertEqual(_Handler.observations, [])


if __name__ == "__main__":
    unittest.main()
