from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from bootstrap import ensure_built

ensure_built()

from registry_casework_client import CaseworkClient, CaseworkClientError  # noqa: E402

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
ITEM_ID = "00000000-0000-4000-8000-000000000001"
CLOCK_OCCURRENCE_ID = "00000000-0000-4000-8000-000000000002"
PREVIEW_ID = "00000000-0000-4000-8000-000000000003"


class _Handler(BaseHTTPRequestHandler):
    observations: list[dict[str, str]] = []

    def do_GET(self) -> None:  # noqa: N802
        self.observations.append({
            "path": self.path,
            "authorization": self.headers.get("authorization", ""),
            "profile": self.headers.get("registry-casework-profile", ""),
            "source_profile": self.headers.get("registry-source-profile", ""),
        })
        if "cursor=expired" in self.path:
            self.respond_problem(
                "cursor.expired",
                "Cursor expired",
                "This cursor has expired. Start again without a cursor and deduplicate entries by eventId.",
            )
            return
        if self.path == f"/tenant/v1/work-items/{ITEM_ID}":
            self.respond({
                "itemId": ITEM_ID,
                "subject": {
                    "sourceId": "source-one",
                    "kind": "case",
                    "id": "case-one",
                },
                "occurrenceKind": "review",
                "binding": {
                    "sourceRevision": "revision-1",
                    "version": "version-1",
                    "generation": "generation-1",
                },
                "bindingReference": "binding-one",
                "state": "claimed",
                "queueId": "review",
                "holder": {
                    "issuer": "https://id.example",
                    "subject": "officer-one",
                },
                "heldSince": "2026-09-11T03:04:05Z",
                "revision": 2,
                "firstObservedAt": "2026-09-11T03:00:00Z",
                "updatedAt": "2026-09-11T03:04:05Z",
                "actions": [],
            })
        elif self.path == f"/tenant/v1/work-items/{ITEM_ID}/clocks":
            self.respond([{
                "clockOccurrenceId": CLOCK_OCCURRENCE_ID,
                "subject": {"sourceId": "source-one", "kind": "case", "id": "case-one"},
                "clockId": "decision-due",
                "state": "running",
                "policyDigest": f"sha256:{'1' * 64}",
                "calculationGeneration": 1,
                "recomputeGeneration": 0,
                "anchorAt": "2026-09-10T00:00:00Z",
                "startedAt": "2026-09-10T00:00:00Z",
                "dueAt": "2026-09-14T00:00:00Z",
                "nextEffect": {
                    "kind": "reminder",
                    "id": "at-risk",
                    "at": "2026-09-12T00:00:00Z",
                },
                "upcomingEffects": [{
                    "kind": "reminder",
                    "id": "at-risk",
                    "at": "2026-09-12T00:00:00Z",
                }, {
                    "kind": "reassign",
                    "id": "escalate",
                    "at": "2026-09-14T00:00:00Z",
                    "because": "Deadline reached",
                    "queueId": "appeals",
                }],
            }])
        elif self.path == "/tenant/v1/directory/holidays/statutory/revisions/7":
            self.respond({
                "holidaySet": "statutory",
                "revision": 7,
                "dates": ["2026-09-11"],
            })
        elif self.path.startswith(f"/tenant/v1/work-items/{ITEM_ID}/history?"):
            self.respond({"items": [], "nextCursor": "next-cursor", "status": "complete"})
        elif self.path.startswith("/tenant/v1/holdings?"):
            self.respond({"items": [], "nextCursor": "next-holdings", "status": "complete"})
        elif self.path.startswith("/tenant/v1/work-items/next?"):
            self.respond({
                "items": [],
                "nextCursor": "resume-next",
                "status": "budget_exhausted",
                "servedQueues": ["review"],
            })
        elif self.path.startswith("/tenant/v1/directory/targets?"):
            self.respond({
                "items": [{
                    "issuer": "https://id.example",
                    "subject": "cover-officer",
                    "displayName": "Cover Officer",
                }],
                "nextCursor": "target-next",
                "status": "complete",
            })
        elif self.path.startswith("/tenant/v1/directory/absences?"):
            self.respond({
                "directoryRevision": 12,
                "items": [],
                "nextCursor": "absence-next",
            })
        elif self.path.startswith("/tenant/v1/work-items"):
            self.respond({
                "items": [],
                "servedQueues": ["appeals", "review"],
                "status": "complete",
            })
        else:
            self.respond({
                "projectId": "fixture",
                "policyVersion": "v1",
                "queues": [],
                "sources": [],
                "hostedKinds": [],
            })

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        body = json.loads(self.rfile.read(length))
        self.observations.append({
            "path": self.path,
            "authorization": self.headers.get("authorization", ""),
            "profile": self.headers.get("registry-casework-profile", ""),
            "source_profile": self.headers.get("registry-source-profile", ""),
            "idempotency_key": self.headers.get("idempotency-key", ""),
            "body": json.dumps(body, sort_keys=True),
        })
        if self.headers.get("idempotency-key") == "expired-create-key":
            self.respond_problem(
                "idempotency.expired",
                "Idempotency window expired",
                "The stored response for this idempotency key has expired. Reconcile the original operation before choosing a new key.",
            )
            return
        if self.path == "/tenant/v1/directory/holidays":
            self.respond(body["document"], status=201)
            return
        if self.path == "/tenant/v1/directory/clocks/recompute/preview":
            self.respond({
                "previewId": PREVIEW_ID,
                "clockId": body["clockId"],
                "holidaySet": body["holidaySet"],
                "holidayRevision": body["holidayRevision"],
                "expiresAt": "2026-09-10T01:00:00Z",
                "changes": [{
                    "clockOccurrenceId": CLOCK_OCCURRENCE_ID,
                    "itemId": ITEM_ID,
                    "expectedCalculationGeneration": 1,
                    "oldDueAt": "2026-09-14T00:00:00Z",
                    "proposedDueAt": "2026-09-15T00:00:00Z",
                }],
            })
            return
        if self.path == "/tenant/v1/directory/clocks/recompute/apply":
            self.respond({
                "previewId": body["previewId"],
                "appliedOccurrences": [CLOCK_OCCURRENCE_ID],
            })
            return
        if self.path.startswith("/tenant/v1/directory/caseload/preview"):
            self.respond({"items": [], "status": "complete"})
            return
        self.respond({
            "itemId": ITEM_ID,
            "requesterReference": body["requesterReference"],
            "kind": body["kind"],
            "version": "v1",
            "display": body["display"],
            "state": "open",
            "revision": 1,
            "kindPolicyDigest": f"sha256:{'0' * 64}",
            "createdAt": "2026-09-10T00:00:00Z",
            "updatedAt": "2026-09-10T00:00:00Z",
        }, status=201)

    def do_PUT(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        body = json.loads(self.rfile.read(length))
        self.observations.append({
            "path": self.path,
            "authorization": self.headers.get("authorization", ""),
            "profile": self.headers.get("registry-casework-profile", ""),
            "source_profile": self.headers.get("registry-source-profile", ""),
            "if_match": self.headers.get("if-match", ""),
            "idempotency_key": self.headers.get("idempotency-key", ""),
            "body": json.dumps(body, sort_keys=True),
        })
        self.respond({
            "revision": 4,
            "teams": [{
                "id": "intake",
                "members": body["staff"],
                "supervisors": body["supervisors"],
                "servedQueues": body["servedQueues"],
                "revision": 4,
            }],
        })

    def respond(
        self,
        value: object,
        status: int = 200,
        media_type: str = "application/json",
    ) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("content-type", media_type)
        self.send_header("cache-control", "no-store")
        self.send_header("traceparent", TRACEPARENT)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def respond_problem(self, code: str, title: str, detail: str) -> None:
        self.respond({
            "type": (
                "https://id.registrystack.org/problems/registry-casework/"
                + code.replace(".", "/")
            ),
            "title": title,
            "status": 410,
            "detail": detail,
            "code": code,
            "traceId": TRACE_ID,
        }, status=410, media_type="application/problem+json")

    def log_message(self, *args: object) -> None:
        pass


class NativeRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        _Handler.observations = []
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        port = self.server.server_address[1]
        self.client = CaseworkClient(f"http://127.0.0.1:{port}/tenant")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_requester_and_staff_calls_preserve_explicit_authority(self) -> None:
        created = self.client.create_hosted_item(
            "requester-token", "requester", "exact-create-key", {
                "kind": "decision",
                "requesterReference": "python-smoke",
                "display": {"summary": "Review"},
            }
        )
        self.assertEqual(created["kind"], "complete")
        self.assertEqual(created["trace_id"], TRACE_ID)
        self.assertEqual(created["value"]["itemId"], ITEM_ID)
        page = self.client.list_work_items(
            "staff-token",
            "staff",
            "source-one",
            {
                "view": "mine",
                "sourceId": "source-one",
                "subjectKind": "resident-record",
                "subjectId": "human-reference-42",
                "limit": 25,
            },
        )
        self.assertEqual(page["value"], {
            "items": [],
            "servedQueues": ["appeals", "review"],
            "status": "complete",
        })
        preview = self.client.preview_caseload_move(
            "supervisor-token",
            "supervisor",
            {
                "from": {"issuer": "issuer", "subject": "person-one"},
                "to": {"issuer": "issuer", "subject": "person-two"},
                "reason": "Coverage transfer",
            },
            {"limit": 25},
            "source-one",
        )
        self.assertEqual(preview["value"], {"items": [], "status": "complete"})

        requester, staff, supervisor = _Handler.observations
        self.assertEqual(requester["authorization"], "Bearer requester-token")
        self.assertEqual(requester["profile"], "requester")
        self.assertEqual(requester["idempotency_key"], "exact-create-key")
        self.assertEqual(requester["source_profile"], "")
        self.assertEqual(staff["authorization"], "Bearer staff-token")
        self.assertEqual(staff["profile"], "staff")
        self.assertEqual(staff["source_profile"], "source-one")
        self.assertEqual(
            parse_qs(urlsplit(staff["path"]).query),
            {
                "view": ["mine"],
                "sort": ["due"],
                "sourceId": ["source-one"],
                "subjectKind": ["resident-record"],
                "subjectId": ["human-reference-42"],
                "limit": ["25"],
            },
        )
        self.assertEqual(supervisor["authorization"], "Bearer supervisor-token")
        self.assertEqual(supervisor["profile"], "supervisor")
        self.assertEqual(supervisor["source_profile"], "source-one")
        self.assertIn('"reason": "Coverage transfer"', supervisor["body"])

    def test_expiry_is_typed_and_never_retried(self) -> None:
        with self.assertRaises(CaseworkClientError) as cursor_error:
            self.client.hosted_terminal_items(
                "requester-token", "requester", {"cursor": "expired"}
            )
        self.assertEqual(cursor_error.exception.kind, "problem")
        self.assertEqual(cursor_error.exception.code, "cursor.expired")
        self.assertEqual(cursor_error.exception.status, 410)
        self.assertEqual(cursor_error.exception.trace_id, TRACE_ID)

        with self.assertRaises(CaseworkClientError) as key_error:
            self.client.create_hosted_item(
                "requester-token",
                "requester",
                "expired-create-key",
                {
                    "kind": "decision",
                    "requesterReference": "python-smoke",
                    "display": {"summary": "Review"},
                },
            )
        self.assertEqual(key_error.exception.kind, "problem")
        self.assertEqual(key_error.exception.code, "idempotency.expired")
        self.assertEqual(key_error.exception.status, 410)
        self.assertEqual(len(_Handler.observations), 2)

    def test_source_history_forwards_page_query_and_returns_continuation(self) -> None:
        page = self.client.work_item_history(
            "staff-token",
            "staff",
            "source-one",
            ITEM_ID,
            {"cursor": "opaque-cursor", "limit": 25},
        )
        self.assertEqual(page["value"]["nextCursor"], "next-cursor")
        self.assertEqual(
            _Handler.observations[0]["path"],
            f"/tenant/v1/work-items/{ITEM_ID}/history?cursor=opaque-cursor&limit=25",
        )
        self.assertEqual(_Handler.observations[0]["source_profile"], "source-one")

    def test_holdings_forwards_page_query_and_returns_continuation(self) -> None:
        page = self.client.holdings(
            "staff-token",
            "staff",
            "source-one",
            {"cursor": "opaque-holdings", "limit": 25},
        )
        self.assertEqual(page["value"]["nextCursor"], "next-holdings")
        self.assertEqual(
            _Handler.observations[0]["path"],
            "/tenant/v1/holdings?cursor=opaque-holdings&limit=25",
        )
        self.assertEqual(_Handler.observations[0]["source_profile"], "source-one")

    def test_next_work_item_preserves_empty_budget_page_and_cursor(self) -> None:
        page = self.client.next_work_item(
            "staff-token",
            "staff",
            "source-one",
            {"queue": "review", "cursor": "opaque-next"},
        )
        self.assertEqual(page["value"], {
            "items": [],
            "nextCursor": "resume-next",
            "status": "budget_exhausted",
            "servedQueues": ["review"],
        })
        self.assertEqual(
            _Handler.observations[0]["path"],
            "/tenant/v1/work-items/next?queue=review&cursor=opaque-next",
        )
        self.assertEqual(_Handler.observations[0]["source_profile"], "source-one")

    def test_native_client_preserves_optional_held_timestamp(self) -> None:
        item = self.client.get_work_item(
            "staff-token", "staff", "source-one", ITEM_ID
        )

        self.assertEqual(item["value"]["heldSince"], "2026-09-11T03:04:05Z")
        self.assertEqual(_Handler.observations[0]["source_profile"], "source-one")

    def test_directory_targets_preserve_exact_query_without_source_authority(self) -> None:
        page = self.client.directory_targets(
            "supervisor-token",
            "supervisor",
            {
                "purpose": "absence_cover",
                "personIssuer": "https://id.example",
                "personSubject": "absent-officer",
                "cursor": "opaque-target-cursor",
                "limit": 25,
            },
        )

        self.assertEqual(page["value"], {
            "items": [{
                "issuer": "https://id.example",
                "subject": "cover-officer",
                "displayName": "Cover Officer",
            }],
            "nextCursor": "target-next",
            "status": "complete",
        })
        observation = _Handler.observations[0]
        self.assertEqual(
            parse_qs(urlsplit(observation["path"]).query),
            {
                "purpose": ["absence_cover"],
                "personIssuer": ["https://id.example"],
                "personSubject": ["absent-officer"],
                "cursor": ["opaque-target-cursor"],
                "limit": ["25"],
            },
        )
        self.assertEqual(observation["profile"], "supervisor")
        self.assertEqual(observation["source_profile"], "")

    def test_absence_list_carries_pagination_after_source_profile(self) -> None:
        absences = self.client.absences(
            "staff-token",
            "staff",
            "source-one",
            {"cursor": "opaque-absence-cursor", "limit": 1000},
        )

        self.assertEqual(absences["value"], {
            "directoryRevision": 12,
            "items": [],
            "nextCursor": "absence-next",
        })
        observation = _Handler.observations[0]
        self.assertEqual(
            parse_qs(urlsplit(observation["path"]).query),
            {"cursor": ["opaque-absence-cursor"], "limit": ["1000"]},
        )
        self.assertEqual(observation["source_profile"], "source-one")

    def test_clock_calls_preserve_source_profile_revision_and_explicit_keys(self) -> None:
        clocks = self.client.work_item_clocks(
            "staff-token", "staff", "source-one", ITEM_ID
        )
        holiday = self.client.holiday_revision(
            "administrator-token", "administrator", "statutory", 7
        )
        created = self.client.create_holiday_revision(
            "administrator-token",
            "administrator",
            "exact-holiday-key",
            {
                "document": {
                    "holidaySet": "statutory",
                    "revision": 8,
                    "dates": ["2026-09-12"],
                }
            },
        )
        preview = self.client.preview_clock_recompute(
            "administrator-token",
            "administrator",
            {
                "clockId": "decision-due",
                "holidaySet": "statutory",
                "holidayRevision": 8,
            },
        )
        applied = self.client.apply_clock_recompute(
            "administrator-token",
            "administrator",
            "exact-recompute-key",
            {"previewId": PREVIEW_ID},
        )

        self.assertEqual(clocks["value"][0]["clockOccurrenceId"], CLOCK_OCCURRENCE_ID)
        self.assertEqual(clocks["value"][0]["nextEffect"]["id"], "at-risk")
        self.assertEqual(
            [effect["id"] for effect in clocks["value"][0]["upcomingEffects"]],
            ["at-risk", "escalate"],
        )
        self.assertEqual(holiday["value"]["revision"], 7)
        self.assertEqual(created["value"]["revision"], 8)
        self.assertEqual(preview["value"]["previewId"], PREVIEW_ID)
        self.assertEqual(applied["value"]["appliedOccurrences"], [CLOCK_OCCURRENCE_ID])

        clock_read, holiday_read, holiday_create, recompute_preview, recompute_apply = (
            _Handler.observations
        )
        self.assertEqual(clock_read["source_profile"], "source-one")
        self.assertEqual(holiday_read["path"], "/tenant/v1/directory/holidays/statutory/revisions/7")
        self.assertEqual(holiday_create["idempotency_key"], "exact-holiday-key")
        self.assertEqual(
            json.loads(holiday_create["body"]),
            {
                "document": {
                    "dates": ["2026-09-12"],
                    "holidaySet": "statutory",
                    "revision": 8,
                }
            },
        )
        self.assertEqual(recompute_preview["idempotency_key"], "")
        self.assertEqual(
            json.loads(recompute_preview["body"]),
            {
                "clockId": "decision-due",
                "holidayRevision": 8,
                "holidaySet": "statutory",
            },
        )
        self.assertEqual(recompute_apply["idempotency_key"], "exact-recompute-key")
        self.assertEqual(json.loads(recompute_apply["body"]), {"previewId": PREVIEW_ID})
        self.assertEqual(len(_Handler.observations), 5)

    def test_directory_team_update_preserves_admin_precondition_and_key(self) -> None:
        request = {
            "staff": [{"issuer": "issuer", "subject": "staff-one", "displayName": "Staff One"}],
            "supervisors": [{"issuer": "issuer", "subject": "supervisor-one"}],
            "servedQueues": ["intake", "review"],
        }
        updated = self.client.update_directory_team(
            "administrator-token",
            "administrator",
            "intake",
            3,
            "exact-team-update-key",
            request,
        )

        self.assertEqual(updated["value"]["revision"], 4)
        self.assertEqual(updated["value"]["teams"][0]["servedQueues"], ["intake", "review"])
        self.assertEqual(updated["value"]["teams"][0]["members"][0]["displayName"], "Staff One")
        self.assertEqual(len(_Handler.observations), 1)
        observation = _Handler.observations[0]
        self.assertEqual(observation["path"], "/tenant/v1/directory/teams/intake")
        self.assertEqual(observation["authorization"], "Bearer administrator-token")
        self.assertEqual(observation["profile"], "administrator")
        self.assertEqual(observation["source_profile"], "")
        self.assertEqual(observation["if_match"], '"3"')
        self.assertEqual(observation["idempotency_key"], "exact-team-update-key")
        self.assertEqual(json.loads(observation["body"]), request)


if __name__ == "__main__":
    unittest.main()
