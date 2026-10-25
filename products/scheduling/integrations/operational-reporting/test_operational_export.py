from __future__ import annotations

import csv
import io
import json
import unittest

from operational_export import ExportError, read_rows, render

QUERY = {
    "service": "room-reservation",
    "location": "community-hall",
    "start": "2026-03-28T23:00:00Z",
    "end": "2026-03-29T22:00:00Z",
    "timeBasis": "occupied",
    "profile": "operations-report",
}


def row(identifier: str, **extra: object) -> dict[str, object]:
    return {
        "appointmentId": identifier,
        "revision": 1,
        "state": "confirmed",
        "service": "room-reservation",
        "location": "community-hall",
        "offering": "meeting-room",
        "displayedStart": "2026-03-29T00:30:00Z",
        "displayedEnd": "2026-03-29T02:30:00Z",
        **extra,
    }


def page(items: list[dict[str, object]], next_cursor: str | None = None) -> dict[str, object]:
    return {"kind": "complete", "value": {"items": items, "nextCursor": next_cursor}}


class FakeClient:
    def __init__(self, *pages: dict[str, object]) -> None:
        self.pages = list(pages)
        self.requests: list[dict[str, object]] = []

    def list_operational_appointments(self, token: str, query: dict[str, object]):
        self.requests.append(query)
        return self.pages.pop(0)


class OperationalExportTest(unittest.TestCase):
    def test_follows_cursors_and_keeps_the_scoped_query(self):
        client = FakeClient(page([row("a")], "c1"), page([row("b")]))
        export = read_rows(client, "token", QUERY, page_size=1)
        self.assertEqual([item["appointmentId"] for item in export["rows"]], ["a", "b"])
        self.assertEqual(export["query"], QUERY)
        self.assertEqual([request.get("cursor") for request in client.requests], [None, "c1"])
        self.assertTrue(all(request["limit"] == 1 for request in client.requests))
        self.assertTrue(all(request["profile"] == "operations-report" for request in client.requests))

    def test_a_repeated_cursor_is_refused(self):
        client = FakeClient(page([row("a")], "c1"), page([row("b")], "c1"))
        with self.assertRaisesRegex(ExportError, "repeated cursor"):
            read_rows(client, "token", QUERY)

    def test_the_page_and_row_bounds_are_refused(self):
        endless = FakeClient(*[page([row(str(i))], f"c{i}") for i in range(5)])
        with self.assertRaisesRegex(ExportError, "page bound"):
            read_rows(endless, "token", QUERY, max_pages=3)
        crowded = FakeClient(page([row("a"), row("b")]))
        with self.assertRaisesRegex(ExportError, "row bound"):
            read_rows(crowded, "token", QUERY, max_rows=1)

    def test_a_page_larger_than_requested_is_refused(self):
        client = FakeClient(page([row("a"), row("b")]))
        with self.assertRaisesRegex(ExportError, "page size"):
            read_rows(client, "token", QUERY, page_size=1)

    def test_an_incomplete_page_is_refused(self):
        client = FakeClient({"kind": "partial", "value": {"items": []}})
        with self.assertRaisesRegex(ExportError, "complete page"):
            read_rows(client, "token", QUERY)

    def test_csv_flattens_one_row_per_logical_booking(self):
        allocations = [
            {"resource": "room-a", "units": 2, "occupiedStart": "s", "occupiedEnd": "e"},
            {"resource": "projector", "units": 1, "occupiedStart": "s", "occupiedEnd": "e"},
        ]
        export = read_rows(
            FakeClient(
                page(
                    [
                        row(
                            "a",
                            allocations=allocations,
                            party={"recipients": 1, "attendees": 3},
                            attendance={"state": "completed"},
                        ),
                        row("b", state="cancelled"),
                    ]
                )
            ),
            "token",
            QUERY,
        )
        parsed = list(csv.DictReader(io.StringIO(render(export, "csv"))))
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["allocations"], "room-a:2:s/e;projector:1:s/e")
        self.assertEqual(parsed[0]["partyAttendees"], "3")
        self.assertEqual(parsed[0]["attendanceState"], "completed")
        self.assertEqual(parsed[1]["state"], "cancelled")
        self.assertEqual(parsed[1]["attendanceState"], "")

    def test_json_keeps_the_collection_window(self):
        export = read_rows(FakeClient(page([row("a")])), "token", QUERY)
        decoded = json.loads(render(export, "json"))
        self.assertIn("startedAt", decoded)
        self.assertIn("completedAt", decoded)
        self.assertEqual(len(decoded["rows"]), 1)

    def test_an_unknown_format_is_refused(self):
        with self.assertRaises(ExportError):
            render({"rows": []}, "xml")


if __name__ == "__main__":
    unittest.main()
