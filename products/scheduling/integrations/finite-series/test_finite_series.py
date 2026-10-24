from __future__ import annotations

import copy
import json
import stat
import tempfile
import threading
import unittest
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from finite_series import (
    Conflict,
    Limits,
    SeriesJournal,
    SeriesProcessor,
    ValidationError,
    expand_weekly,
)

SERIES_ID = "c4207bf4-e7c3-4de4-bb14-36797183b480"
OWNER = "room-reservations-production"


def definition(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "seriesId": SERIES_ID,
        "timezone": "Europe/Zurich",
        "localStart": "2026-10-20T18:00:00",
        "intervalWeeks": 1,
        "count": 4,
        "ambiguousTime": "reject",
        "exclusionDates": ["2026-11-03"],
    }
    value.update(changes)
    return value


def admission(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "offering": "room-evening",
        "start": "1999-01-01T00:00:00Z",
        "durationMinutes": 120,
        "resource": "room-a",
        "policyRevision": 7,
        "capabilities": ["meeting-room"],
        "prerequisites": ["deposit-recorded"],
        "externalReferences": [
            {
                "product": "source-application",
                "recordType": "reservation-request",
                "identifier": "request:42",
            }
        ],
        "additionalAllocations": [
            {"offering": "projectors", "resource": "projector-a", "units": 1},
            {"offering": "chairs", "units": 30},
        ],
    }
    value.update(changes)
    return value


def appointment(occurrence: dict[str, object], revision: int = 1) -> dict[str, object]:
    return {
        "appointmentId": str(uuid.uuid5(uuid.UUID(str(occurrence["occurrenceId"])), "appointment")),
        "offering": "room-evening",
        "start": occurrence["start"],
        "end": "2026-10-20T20:00:00Z",
        "resource": "room-a",
        "units": 1,
        "channel": None,
        "revision": revision,
        "state": "confirmed",
        "policyRevision": 7,
        "createdAt": "2026-10-01T00:00:00Z",
        "cancelledAt": None,
        "externalReferences": [],
    }


class ClientProblem(Exception):
    def __init__(self, code: str, *, outcome_unknown: bool = False) -> None:
        super().__init__(code)
        self.kind = "problem"
        self.code = code
        self.outcome_unknown = outcome_unknown


class FakeSchedulingClient:
    def __init__(self) -> None:
        self.created: dict[str, dict[str, object]] = {}
        self.calls: list[tuple[str, str, dict[str, object]]] = []
        self.conflict_starts: set[str] = set()
        self.lose_response_for: set[str] = set()
        self.unresolved_receipts: set[str] = set()
        self.block_key: str | None = None
        self.entered = threading.Event()
        self.release = threading.Event()

    def create_appointment(
        self, token: str, key: str, request: dict[str, object]
    ) -> dict[str, object]:
        self.calls.append(("create", key, copy.deepcopy(request)))
        if self.block_key == key:
            self.entered.set()
            if not self.release.wait(timeout=3):
                raise AssertionError("test did not release blocked client call")
        start = str(request["admission"]["start"])  # type: ignore[index]
        if start in self.conflict_starts:
            raise ClientProblem("capacity.exhausted")
        existing = self.created.get(key)
        if existing is None:
            occurrence = {
                "occurrenceId": next(
                    ref["identifier"]
                    for ref in request["admission"]["externalReferences"]  # type: ignore[index]
                    if ref["recordType"] == "reservation-occurrence"
                ),
                "start": start,
            }
            existing = appointment(occurrence)
            self.created[key] = existing
        if key in self.lose_response_for:
            self.lose_response_for.remove(key)
            raise ClientProblem("transport.closed", outcome_unknown=True)
        return {"kind": "complete", "value": copy.deepcopy(existing), "trace_id": "trace-create"}

    def appointment_receipt(
        self, token: str, key: str, request: dict[str, object]
    ) -> dict[str, object]:
        self.calls.append(("receipt", key, copy.deepcopy(request)))
        if key in self.unresolved_receipts or key not in self.created:
            raise ClientProblem("receipt.unresolved")
        return {
            "kind": "complete",
            "value": copy.deepcopy(self.created[key]),
            "trace_id": "trace-receipt",
        }

    def reschedule_appointment(
        self,
        token: str,
        appointment_id: str,
        key: str,
        request: dict[str, object],
    ) -> dict[str, object]:
        self.calls.append(("reschedule", key, copy.deepcopy(request)))
        if key in self.lose_response_for:
            self.lose_response_for.remove(key)
            raise ClientProblem("transport.closed", outcome_unknown=True)
        if request["admission"]["start"] in self.conflict_starts:  # type: ignore[index]
            raise ClientProblem("capacity.exhausted")
        value = {
            "appointmentId": appointment_id,
            "revision": int(request["observedRevision"]) + 1,
            "start": request["admission"]["start"],  # type: ignore[index]
            "state": "confirmed",
        }
        return {"kind": "complete", "value": value, "trace_id": "trace-reschedule"}

    def cancel_appointment(
        self,
        token: str,
        appointment_id: str,
        key: str,
        request: dict[str, object],
    ) -> dict[str, object]:
        self.calls.append(("cancel", key, copy.deepcopy(request)))
        if key in self.lose_response_for:
            self.lose_response_for.remove(key)
            raise ClientProblem("transport.closed", outcome_unknown=True)
        value = {
            "appointmentId": appointment_id,
            "revision": int(request["observedRevision"]) + 1,
            "state": "cancelled",
        }
        return {"kind": "complete", "value": value, "trace_id": "trace-cancel"}


class ExpansionTests(unittest.TestCase):
    def test_count_exclusions_and_identity_are_stable(self) -> None:
        first = expand_weekly(definition())
        second = expand_weekly(definition())

        self.assertEqual(first, second)
        self.assertEqual([item["ordinal"] for item in first], [0, 1, 2, 3])
        self.assertEqual([item["excluded"] for item in first], [False, False, True, False])
        self.assertEqual(first[0]["start"], "2026-10-20T16:00:00Z")
        self.assertEqual(first[3]["start"], "2026-11-10T17:00:00Z")
        self.assertEqual(
            first[0]["occurrenceId"],
            str(uuid.uuid5(uuid.UUID(SERIES_ID), "occurrence:0")),
        )

    def test_inclusive_through_date_and_exclusion_must_name_a_candidate(self) -> None:
        expanded = expand_weekly(
            definition(count=None, throughDate="2026-11-03", exclusionDates=[])
        )
        self.assertEqual(len(expanded), 3)
        with self.assertRaisesRegex(ValidationError, "candidate"):
            expand_weekly(definition(exclusionDates=["2026-10-21"]))

    def test_nonexistent_and_ambiguous_wall_times_are_explicit(self) -> None:
        spring = definition(
            localStart="2026-03-29T02:30:00",
            count=1,
            exclusionDates=[],
        )
        with self.assertRaisesRegex(ValidationError, "nonexistent"):
            expand_weekly(spring)

        fold = definition(
            localStart="2026-10-25T02:30:00",
            count=1,
            exclusionDates=[],
        )
        with self.assertRaisesRegex(ValidationError, "ambiguous"):
            expand_weekly(fold)
        earlier = expand_weekly({**fold, "ambiguousTime": "earlier"})
        later = expand_weekly({**fold, "ambiguousTime": "later"})
        self.assertEqual(earlier[0]["start"], "2026-10-25T00:30:00Z")
        self.assertEqual(later[0]["start"], "2026-10-25T01:30:00Z")

    def test_occurrence_horizon_and_aggregate_allocation_bounds(self) -> None:
        with self.assertRaisesRegex(ValidationError, "64"):
            expand_weekly(definition(count=65, exclusionDates=[]))
        with self.assertRaisesRegex(ValidationError, "366"):
            expand_weekly(
                definition(count=54, intervalWeeks=1, exclusionDates=[]),
                Limits(max_occurrences=64, max_horizon_days=366),
            )


class JournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "series.sqlite3"
        self.journal = SeriesJournal(self.database)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_new_journal_is_private_source_state(self) -> None:
        mode = stat.S_IMODE(self.database.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_changed_prepared_request_is_refused_before_dispatch_or_recovery(self) -> None:
        for state in ("prepared", "dispatched"):
            with self.subTest(state=state):
                journal = SeriesJournal(Path(self.temp.name) / f"{state}.sqlite3")
                prepared = journal.prepare_series(
                    definition(count=1, exclusionDates=[]), admission(), owner=OWNER
                )
                operation = prepared["occurrences"][0]["operation"]
                changed = copy.deepcopy(operation["request"])
                changed["admission"]["offering"] = "different-offering"
                with journal._immediate() as connection:
                    connection.execute(
                        "UPDATE operations SET request_json = ?, status = ?",
                        (json.dumps(changed), state),
                    )
                client = FakeSchedulingClient()
                with self.assertRaisesRegex(Conflict, "integrity"):
                    SeriesProcessor(journal, client, credential_profile=OWNER).process(
                        SERIES_ID, token="synthetic-token"
                    )
                self.assertEqual(client.calls, [])
                self.assertEqual(
                    journal.read_series(SERIES_ID)["occurrences"][0]["operation"]["attemptCount"],
                    0,
                )

    def test_preparation_preserves_the_admission_and_derives_aggregate_lines(self) -> None:
        original = admission()
        self.journal.prepare_series(definition(), original, owner=OWNER)
        result = self.journal.read_series(SERIES_ID)

        self.assertEqual(result["revision"], 1)
        active = [item for item in result["occurrences"] if not item["excluded"]]
        self.assertEqual(result["aggregateAllocationLines"], 9)
        sent = active[0]["operation"]["request"]["admission"]
        self.assertEqual(sent["durationMinutes"], 120)
        self.assertEqual(sent["resource"], "room-a")
        self.assertEqual(sent["additionalAllocations"], original["additionalAllocations"])
        self.assertEqual(sent["capabilities"], original["capabilities"])
        self.assertEqual(len(sent["externalReferences"]), 3)
        self.assertNotEqual(sent["start"], original["start"])
        self.assertEqual(original["start"], "1999-01-01T00:00:00Z")

        with self.assertRaisesRegex(ValidationError, "aggregate"):
            self.journal.prepare_series(
                definition(seriesId=str(uuid.uuid4()), count=64, exclusionDates=[]),
                admission(additionalAllocations=[{"offering": f"offering-{i}"} for i in range(4)]),
                owner=OWNER,
                limits=Limits(
                    max_horizon_days=500,
                    max_aggregate_allocation_lines=256,
                ),
            )

    def test_partial_result_records_every_success_conflict_and_exclusion(self) -> None:
        self.journal.prepare_series(definition(), admission(), owner=OWNER)
        client = FakeSchedulingClient()
        rows = self.journal.read_series(SERIES_ID)["occurrences"]
        client.conflict_starts.add(rows[1]["start"])
        processor = SeriesProcessor(self.journal, client, credential_profile=OWNER)

        result = processor.process(SERIES_ID, token="synthetic-token")

        self.assertEqual(result["mode"], "partial")
        self.assertEqual(
            [item["outcome"] for item in result["occurrences"]],
            ["succeeded", "refused", "excluded", "succeeded"],
        )
        self.assertEqual(result["summary"], {"excluded": 1, "refused": 1, "succeeded": 2})

    def test_lost_response_is_recovered_after_restart_with_exact_key_and_body(self) -> None:
        self.journal.prepare_series(
            definition(count=1, exclusionDates=[]), admission(), owner=OWNER
        )
        before = self.journal.read_series(SERIES_ID)["occurrences"][0]["operation"]
        client = FakeSchedulingClient()
        client.lose_response_for.add(before["idempotencyKey"])

        first = SeriesProcessor(self.journal, client, credential_profile=OWNER).process(
            SERIES_ID, token="synthetic-token"
        )
        self.assertEqual(first["occurrences"][0]["outcome"], "unresolved")

        reopened = SeriesJournal(self.database)
        second = SeriesProcessor(reopened, client, credential_profile=OWNER).process(
            SERIES_ID, token="synthetic-token"
        )
        self.assertEqual(second["occurrences"][0]["outcome"], "succeeded")
        create = next(call for call in client.calls if call[0] == "create")
        receipt = next(call for call in client.calls if call[0] == "receipt")
        self.assertEqual(create[1:], receipt[1:])

    def test_unresolved_receipt_never_uses_a_fresh_key(self) -> None:
        self.journal.prepare_series(
            definition(count=1, exclusionDates=[]), admission(), owner=OWNER
        )
        operation = self.journal.read_series(SERIES_ID)["occurrences"][0]["operation"]
        self.journal.mark_dispatched_for_test(operation["operationId"])
        client = FakeSchedulingClient()
        client.unresolved_receipts.add(operation["idempotencyKey"])

        result = SeriesProcessor(self.journal, client, credential_profile=OWNER).process(
            SERIES_ID, token="synthetic-token"
        )
        self.assertEqual(result["occurrences"][0]["outcome"], "unresolved")
        self.assertEqual({call[1] for call in client.calls}, {operation["idempotencyKey"]})
        self.assertEqual([call[0] for call in client.calls], ["receipt"])

    def test_fenced_lease_prevents_immediate_reconcile_while_call_is_in_flight(self) -> None:
        self.journal.prepare_series(
            definition(count=1, exclusionDates=[]), admission(), owner=OWNER
        )
        operation = self.journal.read_series(SERIES_ID)["occurrences"][0]["operation"]
        client = FakeSchedulingClient()
        client.block_key = operation["idempotencyKey"]
        first_processor = SeriesProcessor(self.journal, client, credential_profile=OWNER)
        second_processor = SeriesProcessor(
            SeriesJournal(self.database), client, credential_profile=OWNER
        )
        outcomes: list[object] = []

        first = threading.Thread(
            target=lambda: outcomes.append(first_processor.process(SERIES_ID, token="token"))
        )
        first.start()
        self.assertTrue(client.entered.wait(timeout=2))
        with self.assertRaises(Conflict):
            second_processor.process(SERIES_ID, token="token")
        client.release.set()
        first.join(timeout=3)
        self.assertFalse(first.is_alive())
        self.assertEqual(len([call for call in client.calls if call[0] == "create"]), 1)
        self.assertEqual(outcomes[0]["occurrences"][0]["outcome"], "succeeded")  # type: ignore[index]

    def test_credential_profile_mismatch_does_not_dispatch_or_change_identity(self) -> None:
        self.journal.prepare_series(
            definition(count=1, exclusionDates=[]), admission(), owner=OWNER
        )
        client = FakeSchedulingClient()
        with self.assertRaisesRegex(Conflict, "credential profile"):
            SeriesProcessor(self.journal, client, credential_profile="replacement-profile").process(
                SERIES_ID, token="other-token"
            )
        self.assertEqual(client.calls, [])

    def test_profile_mismatch_during_recovery_remains_unresolved(self) -> None:
        self.journal.prepare_series(
            definition(count=1, exclusionDates=[]), admission(), owner=OWNER
        )
        operation = self.journal.read_series(SERIES_ID)["occurrences"][0]["operation"]
        self.journal.mark_dispatched_for_test(operation["operationId"])
        client = FakeSchedulingClient()

        result = SeriesProcessor(
            self.journal, client, credential_profile="replacement-profile"
        ).process(SERIES_ID, token="other-token")

        self.assertEqual(result["occurrences"][0]["outcome"], "unresolved")
        self.assertEqual(
            result["occurrences"][0]["operation"]["idempotencyKey"],
            operation["idempotencyKey"],
        )
        self.assertEqual(result["ownerProfile"], OWNER)
        self.assertEqual(client.calls, [])

    def test_edit_reschedules_a_series_that_omits_the_ambiguity_policy(self) -> None:
        stored = definition(count=2, exclusionDates=[])
        del stored["ambiguousTime"]
        self.journal.prepare_series(stored, admission(), owner=OWNER)
        client = FakeSchedulingClient()
        processor = SeriesProcessor(self.journal, client, credential_profile=OWNER)
        created = processor.process(SERIES_ID, token="token")
        target = created["occurrences"][1]["occurrenceId"]
        self.journal.prepare_edit(
            SERIES_ID,
            expected_revision=1,
            scope="one",
            target_occurrence_id=target,
            changes={target: {"action": "reschedule", "localStart": "2026-10-28T19:00:00"}},
            now=datetime(2026, 10, 1, tzinfo=UTC),
        )
        prepared = self.journal.read_series(SERIES_ID)["occurrences"]
        reschedule = next(item for item in prepared if item["occurrenceId"] == target)
        self.assertEqual(
            reschedule["operation"]["request"]["admission"]["start"], "2026-10-28T18:00:00Z"
        )

    def test_explicit_edit_diff_uses_revision_and_retains_failed_reschedule(self) -> None:
        self.journal.prepare_series(
            definition(count=3, exclusionDates=[]), admission(), owner=OWNER
        )
        client = FakeSchedulingClient()
        processor = SeriesProcessor(self.journal, client, credential_profile=OWNER)
        created = processor.process(SERIES_ID, token="token")
        ids = [item["occurrenceId"] for item in created["occurrences"]]
        old = created["occurrences"][1]
        changed_start = "2026-11-04T18:00:00"
        client.conflict_starts.add("2026-11-04T17:00:00Z")

        changes = {
            ids[1]: {"action": "reschedule", "localStart": changed_start},
            ids[2]: {"action": "cancel", "reason": "term shortened"},
        }
        edit = self.journal.prepare_edit(
            SERIES_ID,
            expected_revision=1,
            scope="this-and-future",
            target_occurrence_id=ids[1],
            changes=changes,
            now=datetime(2026, 10, 1, tzinfo=UTC),
        )
        self.assertEqual(edit["revision"], 2)
        self.assertEqual(set(edit["diff"]), set(changes))
        prepared = self.journal.read_series(SERIES_ID)["occurrences"]
        reschedule = next(item for item in prepared if item["occurrenceId"] == ids[1])["operation"][
            "request"
        ]["admission"]
        self.assertNotIn("externalReferences", reschedule)
        self.assertEqual(reschedule["durationMinutes"], 120)
        self.assertEqual(reschedule["additionalAllocations"], admission()["additionalAllocations"])
        with self.assertRaisesRegex(Conflict, "revision"):
            self.journal.prepare_edit(
                SERIES_ID,
                expected_revision=1,
                scope="one",
                target_occurrence_id=ids[0],
                changes={ids[0]: {"action": "cancel"}},
                now=datetime(2026, 10, 1, tzinfo=UTC),
            )

        result = processor.process(SERIES_ID, token="token")
        middle = next(item for item in result["occurrences"] if item["occurrenceId"] == ids[1])
        last = next(item for item in result["occurrences"] if item["occurrenceId"] == ids[2])
        self.assertEqual(middle["outcome"], "refused")
        self.assertEqual(middle["appointmentId"], old["appointmentId"])
        self.assertEqual(middle["start"], old["start"])
        self.assertEqual(last["outcome"], "succeeded")
        self.assertEqual(last["appointmentState"], "cancelled")
        history = self.journal.read_history(SERIES_ID)
        self.assertEqual([item["revision"] for item in history], [1, 2])

    def test_edit_cannot_hide_an_unresolved_occurrence_operation(self) -> None:
        self.journal.prepare_series(
            definition(count=1, exclusionDates=[]), admission(), owner=OWNER
        )
        created = SeriesProcessor(
            self.journal, FakeSchedulingClient(), credential_profile=OWNER
        ).process(SERIES_ID, token="token")
        occurrence = created["occurrences"][0]
        occurrence_id = occurrence["occurrenceId"]
        self.journal.prepare_edit(
            SERIES_ID,
            expected_revision=1,
            scope="one",
            target_occurrence_id=occurrence_id,
            changes={occurrence_id: {"action": "cancel"}},
            now=datetime(2026, 10, 1, tzinfo=UTC),
        )
        operation = self.journal.read_series(SERIES_ID)["occurrences"][0]["operation"]
        with self.journal.dispatch_lease(SERIES_ID) as generation:
            self.journal.claim_operation(operation["operationId"], generation)
            self.journal.finish_operation(operation["operationId"], generation, status="unresolved")
        with self.assertRaisesRegex(Conflict, "pending|unresolved"):
            self.journal.prepare_edit(
                SERIES_ID,
                expected_revision=2,
                scope="one",
                target_occurrence_id=occurrence_id,
                changes={
                    occurrence_id: {"action": "reschedule", "localStart": "2026-11-04T18:00:00"}
                },
                now=datetime(2026, 10, 1, tzinfo=UTC),
            )
        current = self.journal.read_series(SERIES_ID)
        self.assertEqual(current["revision"], 2)
        self.assertEqual(current["occurrences"][0]["outcome"], "unresolved")

    def test_failed_lock_file_open_does_not_poison_dispatch(self) -> None:
        self.journal.prepare_series(
            definition(count=1, exclusionDates=[]), admission(), owner=OWNER
        )
        with patch("finite_series.os.open", side_effect=PermissionError("test denial")):
            with self.assertRaises(PermissionError):
                with self.journal.dispatch_lease(SERIES_ID):
                    self.fail("a denied lock file must not grant a lease")
        with self.journal.dispatch_lease(SERIES_ID) as generation:
            self.assertEqual(generation, 1)

    def test_failed_lease_cleanup_still_releases_dispatch_lock(self) -> None:
        self.journal.prepare_series(
            definition(count=1, exclusionDates=[]), admission(), owner=OWNER
        )
        with patch.object(
            self.journal,
            "_immediate",
            side_effect=[self.journal._immediate(), RuntimeError("test storage failure")],
        ):
            with self.assertRaisesRegex(RuntimeError, "storage failure"):
                with self.journal.dispatch_lease(SERIES_ID):
                    pass
        with self.journal.dispatch_lease(SERIES_ID) as generation:
            self.assertEqual(generation, 2)

    def test_past_occurrence_cannot_be_edited(self) -> None:
        self.journal.prepare_series(
            definition(count=1, exclusionDates=[]), admission(), owner=OWNER
        )
        occurrence_id = self.journal.read_series(SERIES_ID)["occurrences"][0]["occurrenceId"]
        with self.assertRaisesRegex(ValidationError, "past"):
            self.journal.prepare_edit(
                SERIES_ID,
                expected_revision=1,
                scope="one",
                target_occurrence_id=occurrence_id,
                changes={occurrence_id: {"action": "cancel"}},
                now=datetime(2026, 10, 21, tzinfo=UTC),
            )

    def test_all_scope_requires_an_explicit_change_for_each_future_occurrence(self) -> None:
        self.journal.prepare_series(
            definition(count=2, exclusionDates=[]), admission(), owner=OWNER
        )
        client = FakeSchedulingClient()
        processor = SeriesProcessor(self.journal, client, credential_profile=OWNER)
        created = processor.process(SERIES_ID, token="token")
        first, second = [item["occurrenceId"] for item in created["occurrences"]]

        with self.assertRaisesRegex(ValidationError, "every occurrence"):
            self.journal.prepare_edit(
                SERIES_ID,
                expected_revision=1,
                scope="all",
                target_occurrence_id=None,
                changes={first: {"action": "cancel"}},
                now=datetime(2026, 10, 1, tzinfo=UTC),
            )

        edit = self.journal.prepare_edit(
            SERIES_ID,
            expected_revision=1,
            scope="all",
            target_occurrence_id=None,
            changes={
                first: {"action": "cancel"},
                second: {"action": "cancel"},
            },
            now=datetime(2026, 10, 1, tzinfo=UTC),
        )
        self.assertEqual(edit["scope"], "all")
        self.assertEqual(set(edit["diff"]), {first, second})


if __name__ == "__main__":
    unittest.main()
