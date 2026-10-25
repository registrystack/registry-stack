from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from calendar_busy import (
    SCHEDULING_UID_SUFFIX,
    CalendarBusyAdapter,
    CalendarImportError,
    Coverage,
    ReconciliationJournal,
    expand_calendar,
)

NOW = datetime(2026, 10, 23, 0, 0, tzinfo=UTC)
COVERAGE = Coverage(
    datetime(2026, 10, 23, 0, 0, tzinfo=UTC),
    datetime(2026, 11, 20, 0, 0, tzinfo=UTC),
)


def calendar(*events: str) -> bytes:
    return (
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n"
        + "".join(events)
        + "END:VCALENDAR\r\n"
    ).encode()


def event(body: str) -> str:
    return f"BEGIN:VEVENT\r\n{body}END:VEVENT\r\n"


class ExpansionTests(unittest.TestCase):
    def test_timezone_recurrence_exception_and_deletion_are_bounded(self) -> None:
        source = calendar(
            event(
                "UID:weekly-1\r\n"
                "DTSTART;TZID=Europe/Zurich:20261027T090000\r\n"
                "DTEND;TZID=Europe/Zurich:20261027T100000\r\n"
                "RRULE:FREQ=WEEKLY;COUNT=3\r\n"
                "EXDATE;TZID=Europe/Zurich:20261103T090000\r\n"
                "SEQUENCE:4\r\nSUMMARY:Private appointment\r\n"
                "ATTENDEE:mailto:person@example.test\r\n"
            )
        )
        rows = expand_calendar(
            source,
            coverage=COVERAGE,
            resource="staff-a",
            default_timezone="Europe/Zurich",
            trusted_scheduling_uids=set(),
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["start"], "2026-10-27T08:00:00Z")
        self.assertEqual(rows[1]["start"], "2026-11-10T08:00:00Z")
        encoded = str(rows)
        self.assertNotIn("Private appointment", encoded)
        self.assertNotIn("person@example.test", encoded)

    def test_detached_exception_keeps_the_occurrence_identity_when_moved(self) -> None:
        source = calendar(
            event(
                "UID:moved-series\r\nDTSTART:20261024T090000Z\r\n"
                "DTEND:20261024T100000Z\r\nRRULE:FREQ=DAILY;COUNT=2\r\n"
                "SEQUENCE:1\r\n"
            ),
            event(
                "UID:moved-series\r\nRECURRENCE-ID:20261025T090000Z\r\n"
                "DTSTART:20261025T110000Z\r\nDTEND:20261025T120000Z\r\n"
                "SEQUENCE:2\r\n"
            ),
        )
        rows = expand_calendar(
            source,
            coverage=COVERAGE,
            resource="staff-a",
            default_timezone="UTC",
            trusted_scheduling_uids=set(),
        )
        self.assertEqual(
            [row["start"] for row in rows],
            [
                "2026-10-24T09:00:00Z",
                "2026-10-25T11:00:00Z",
            ],
        )
        self.assertEqual(rows[1]["externalUid"], "moved-series#2026-10-25T09:00:00Z")

    def test_cancelled_and_transparent_events_do_not_create_busy_time(self) -> None:
        source = calendar(
            event(
                "UID:cancelled\r\nDTSTART:20261024T090000Z\r\n"
                "DTEND:20261024T100000Z\r\nSTATUS:CANCELLED\r\n"
            ),
            event(
                "UID:free\r\nDTSTART:20261024T110000Z\r\n"
                "DTEND:20261024T120000Z\r\nTRANSP:TRANSPARENT\r\n"
            ),
        )
        self.assertEqual(
            expand_calendar(
                source,
                coverage=COVERAGE,
                resource="staff-a",
                default_timezone="UTC",
                trusted_scheduling_uids=set(),
            ),
            [],
        )

    def test_export_uid_requires_authenticated_provenance_match(self) -> None:
        uid = "11111111-1111-4111-8111-111111111111" + SCHEDULING_UID_SUFFIX
        source = calendar(
            event(
                f"UID:{uid}\r\nDTSTART:20261024T090000Z\r\n"
                "DTEND:20261024T100000Z\r\nSEQUENCE:1\r\n"
            )
        )
        untrusted = expand_calendar(
            source,
            coverage=COVERAGE,
            resource="staff-a",
            default_timezone="UTC",
            trusted_scheduling_uids=set(),
        )
        trusted = expand_calendar(
            source,
            coverage=COVERAGE,
            resource="staff-a",
            default_timezone="UTC",
            trusted_scheduling_uids={uid},
        )
        self.assertEqual(len(untrusted), 1)
        self.assertEqual(trusted, [])

    def test_event_crossing_coverage_is_refused_instead_of_partly_erased(self) -> None:
        source = calendar(
            event("UID:long\r\nDTSTART:20261022T230000Z\r\nDTEND:20261023T010000Z\r\n")
        )
        with self.assertRaisesRegex(CalendarImportError, "coverage boundary"):
            expand_calendar(
                source,
                coverage=COVERAGE,
                resource="staff-a",
                default_timezone="UTC",
                trusted_scheduling_uids=set(),
            )

    def test_occurrence_identity_is_bounded_as_a_whole(self) -> None:
        uid = "u" * 500
        source = calendar(
            event(
                f"UID:{uid}\r\nDTSTART:20261027T090000Z\r\nDTEND:20261027T100000Z\r\n"
            )
        )
        with self.assertRaisesRegex(
            CalendarImportError, "identity is outside its bound"
        ):
            expand_calendar(
                source,
                coverage=COVERAGE,
                resource="staff-a",
                default_timezone="UTC",
                trusted_scheduling_uids=set(),
            )

    def test_expansion_bound_is_checked_before_recurrence_allocation(self) -> None:
        sources = []
        for index in range(130):
            sources.append(
                event(
                    f"UID:daily-{index}\r\nDTSTART:20261024T090000Z\r\n"
                    "DTEND:20261024T100000Z\r\nRRULE:FREQ=DAILY\r\n"
                )
            )
        with self.assertRaisesRegex(CalendarImportError, "4096 occurrences"):
            expand_calendar(
                calendar(*sources),
                coverage=COVERAGE,
                resource="staff-a",
                default_timezone="UTC",
                trusted_scheduling_uids=set(),
            )


class FakeClient:
    def __init__(self) -> None:
        self.revision = 0
        self.applies: list[dict[str, object]] = []
        self.lose_first_apply = False

    def preview_source_busy(self, token, profile, request):
        return {"currentRevision": self.revision, "profile": profile}

    def apply_source_busy(self, token, profile, request):
        self.applies.append(request.copy())
        expected = int(request["expectedRevision"])
        if expected == self.revision:
            self.revision += 1
        elif expected + 1 != self.revision:
            raise AssertionError("unexpected revision")
        result = {"revision": self.revision, "kind": "applied"}
        if self.lose_first_apply:
            self.lose_first_apply = False
            raise ConnectionError("lost response after apply")
        return result


class Provenance:
    def __init__(self, values=()):
        self.values = values

    def exported_uids(self, token, *, resource, coverage):
        return self.values


class AdapterTests(unittest.TestCase):
    def adapter(self, root: Path, client: FakeClient) -> CalendarBusyAdapter:
        return CalendarBusyAdapter(
            client,
            Provenance(),
            ReconciliationJournal(root / "state.sqlite3"),
            profile="staff-calendar",
            resource="staff-a",
            timezone="UTC",
            freshness_seconds=300,
        )

    def test_restart_retries_exact_pending_request_after_lost_ack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = FakeClient()
            client.lose_first_apply = True
            adapter = self.adapter(root, client)
            with self.assertRaises(ConnectionError):
                adapter.reconcile(
                    "token",
                    coverage=COVERAGE,
                    observed_at=NOW,
                    fetch=calendar,
                )
            adapter.close()
            restarted = self.adapter(root, client)
            restarted.reconcile(
                "token", coverage=COVERAGE, observed_at=NOW, fetch=calendar
            )
            restarted.close()
            self.assertEqual(client.applies[0], client.applies[1])
            self.assertEqual(client.revision, 2)

    def test_fresh_until_is_derived_from_the_normalized_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client = FakeClient()
            adapter = self.adapter(Path(directory), client)
            adapter.reconcile(
                "token",
                coverage=COVERAGE,
                observed_at=NOW.replace(microsecond=654321),
                fetch=calendar,
            )
            adapter.close()
            request = client.applies[-1]
            self.assertEqual(request["observedAt"], "2026-10-23T00:00:00Z")
            self.assertEqual(request["freshUntil"], "2026-10-23T00:05:00Z")

    def test_outage_is_applied_as_unavailable_without_deleting_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client = FakeClient()
            adapter = self.adapter(Path(directory), client)
            result = adapter.reconcile(
                "token",
                coverage=COVERAGE,
                observed_at=NOW,
                fetch=lambda: (_ for _ in ()).throw(ConnectionError("feed down")),
            )
            request = client.applies[-1]
            self.assertEqual(request["status"], "unavailable")
            self.assertEqual(request["records"], [])
            self.assertNotIn("freshUntil", request)
            self.assertEqual(result["apply"]["revision"], 1)
            adapter.close()

    def test_revision_mismatch_is_refused_without_rebasing_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client = FakeClient()
            client.revision = 1
            adapter = self.adapter(Path(directory), client)
            with self.assertRaisesRegex(CalendarImportError, "revision changed"):
                adapter.reconcile(
                    "token",
                    coverage=COVERAGE,
                    observed_at=NOW,
                    fetch=calendar,
                )
            self.assertEqual(client.applies, [])
            self.assertEqual(adapter.journal.state("staff-calendar"), (0, None))
            adapter.close()

    def test_fresh_omission_represents_deletion_and_reconnects_after_outage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client = FakeClient()
            adapter = self.adapter(Path(directory), client)
            source = calendar(
                event(
                    "UID:removed-later\r\nDTSTART:20261024T090000Z\r\n"
                    "DTEND:20261024T100000Z\r\nSEQUENCE:1\r\n"
                )
            )
            adapter.reconcile(
                "token", coverage=COVERAGE, observed_at=NOW, fetch=lambda: source
            )
            adapter.reconcile(
                "token",
                coverage=COVERAGE,
                observed_at=NOW,
                fetch=lambda: (_ for _ in ()).throw(ConnectionError("feed down")),
            )
            adapter.reconcile(
                "token", coverage=COVERAGE, observed_at=NOW, fetch=calendar
            )
            self.assertEqual(len(client.applies[0]["records"]), 1)
            self.assertEqual(client.applies[1]["status"], "unavailable")
            self.assertEqual(client.applies[2]["status"], "fresh")
            self.assertEqual(client.applies[2]["records"], [])
            adapter.close()

    def test_journal_corruption_is_visible_before_any_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = ReconciliationJournal(Path(directory) / "state.sqlite3")
            journal.prepare("staff-calendar", 0, {"expectedRevision": 0, "records": []})
            journal.connection.execute(
                "UPDATE source_state SET pending_json='{}' WHERE profile='staff-calendar'"
            )
            journal.connection.commit()
            with self.assertRaisesRegex(CalendarImportError, "digest does not match"):
                journal.state("staff-calendar")
            journal.close()


if __name__ == "__main__":
    unittest.main()
