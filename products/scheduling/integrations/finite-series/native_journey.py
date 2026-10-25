#!/usr/bin/env python3
"""Exercise finite series through the installed public Scheduling facade."""

from __future__ import annotations

import argparse
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from registry_client import scheduling

from finite_series import SeriesJournal, SeriesProcessor


class SyntheticLostResponse(Exception):
    code = None
    outcome_unknown = True


class LoseOneCreateResponse:
    """Call the real client, then model a transport loss before its response is used."""

    def __init__(self, client: scheduling.SchedulingClient) -> None:
        self.client = client
        self.lost = False

    def create_appointment(
        self, token: str, idempotency_key: str, request: dict[str, object]
    ) -> dict[str, object]:
        complete = self.client.create_appointment(token, idempotency_key, request)
        if not self.lost:
            self.lost = True
            raise SyntheticLostResponse("synthetic response loss after native success")
        return complete

    def __getattr__(self, name: str) -> object:
        return getattr(self.client, name)


def parse_local(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is not None:
        raise ValueError("--local-start must not contain a UTC offset")
    return parsed


def definition(series_id: str, local_start: datetime, count: int) -> dict[str, object]:
    return {
        "seriesId": series_id,
        "timezone": "Europe/Zurich",
        "localStart": local_start.isoformat(timespec="seconds"),
        "intervalWeeks": 1,
        "count": count,
        "ambiguousTime": "reject",
        "exclusionDates": [],
    }


def admission(*, offering: str, resource: str, policy_revision: int) -> dict[str, object]:
    return {
        "offering": offering,
        "start": "2000-01-01T00:00:00Z",
        "durationMinutes": 120,
        "resource": resource,
        "channel": "public",
        "policyRevision": policy_revision,
        "capabilities": [],
        "prerequisites": [],
        "externalReferences": [],
    }


def require_outcomes(result: dict[str, object], expected: list[str]) -> None:
    actual = [item["outcome"] for item in result["occurrences"]]
    if actual != expected:
        raise AssertionError(f"expected occurrence outcomes {expected!r}, got {actual!r}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--state-directory", required=True, type=Path)
    parser.add_argument("--local-start", required=True)
    parser.add_argument("--offering", default="meeting-room")
    parser.add_argument("--resource", default="room-a")
    parser.add_argument("--policy-revision", required=True, type=int)
    parser.add_argument("--credential-profile", default="native-finite-series")
    args = parser.parse_args()
    token = os.environ.get("REGISTRY_SCHEDULING_TOKEN")
    if not token:
        raise RuntimeError("REGISTRY_SCHEDULING_TOKEN is required")
    if args.state_directory.exists() and any(args.state_directory.iterdir()):
        raise RuntimeError("--state-directory must be empty")
    args.state_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.state_directory.chmod(0o700)

    client = scheduling.SchedulingClient(args.base_url)
    start = parse_local(args.local_start)
    template = admission(
        offering=args.offering,
        resource=args.resource,
        policy_revision=args.policy_revision,
    )

    success_id = str(uuid.uuid4())
    success_journal = SeriesJournal(args.state_directory / "success.sqlite3")
    success_journal.prepare_series(
        definition(success_id, start, 3), template, owner=args.credential_profile
    )
    success = SeriesProcessor(
        success_journal, client, credential_profile=args.credential_profile
    ).process(success_id, token=token)
    require_outcomes(success, ["succeeded", "succeeded", "succeeded"])

    reference = {
        "product": "source-application",
        "recordType": "reservation-series",
        "identifier": success_id,
    }
    listed = client.list_appointments(token, reference, limit=10)
    if len(listed["value"]["items"]) != 3:
        raise AssertionError("series reference did not select all three appointments")

    conflict_id = str(uuid.uuid4())
    conflict_journal = SeriesJournal(args.state_directory / "conflict.sqlite3")
    conflict_journal.prepare_series(
        definition(conflict_id, start, 1), template, owner=args.credential_profile
    )
    conflict = SeriesProcessor(
        conflict_journal, client, credential_profile=args.credential_profile
    ).process(conflict_id, token=token)
    require_outcomes(conflict, ["refused"])

    lost_id = str(uuid.uuid4())
    lost_journal_path = args.state_directory / "lost-response.sqlite3"
    lost_journal = SeriesJournal(lost_journal_path)
    lost_journal.prepare_series(
        definition(lost_id, start + timedelta(days=2), 1),
        template,
        owner=args.credential_profile,
    )
    lost = SeriesProcessor(
        lost_journal,
        LoseOneCreateResponse(client),
        credential_profile=args.credential_profile,
    ).process(lost_id, token=token)
    require_outcomes(lost, ["unresolved"])
    recovered = SeriesProcessor(
        SeriesJournal(lost_journal_path),
        client,
        credential_profile=args.credential_profile,
    ).process(lost_id, token=token)
    require_outcomes(recovered, ["succeeded"])

    occurrences = success["occurrences"]
    first_id = occurrences[0]["occurrenceId"]
    success_journal.prepare_edit(
        success_id,
        expected_revision=1,
        scope="one",
        target_occurrence_id=first_id,
        changes={
            first_id: {
                "action": "reschedule",
                "localStart": (start + timedelta(days=1)).isoformat(timespec="seconds"),
            }
        },
        now=datetime.now(UTC),
    )
    moved = SeriesProcessor(
        success_journal, client, credential_profile=args.credential_profile
    ).process(success_id, token=token)
    require_outcomes(moved, ["succeeded", "succeeded", "succeeded"])

    second_id = occurrences[1]["occurrenceId"]
    third_id = occurrences[2]["occurrenceId"]
    success_journal.prepare_edit(
        success_id,
        expected_revision=2,
        scope="this-and-future",
        target_occurrence_id=second_id,
        changes={
            second_id: {"action": "cancel", "reason": "native journey"},
            third_id: {"action": "cancel", "reason": "native journey"},
        },
        now=datetime.now(UTC),
    )
    cancelled = SeriesProcessor(
        success_journal, client, credential_profile=args.credential_profile
    ).process(success_id, token=token)
    if [item["appointmentState"] for item in cancelled["occurrences"]] != [
        "confirmed",
        "cancelled",
        "cancelled",
    ]:
        raise AssertionError("explicit future cancellation did not preserve current states")

    lost_occurrence_id = recovered["occurrences"][0]["occurrenceId"]
    lost_journal.prepare_edit(
        lost_id,
        expected_revision=1,
        scope="all",
        target_occurrence_id=None,
        changes={lost_occurrence_id: {"action": "cancel", "reason": "native journey"}},
        now=datetime.now(UTC),
    )
    all_cancelled = SeriesProcessor(
        lost_journal, client, credential_profile=args.credential_profile
    ).process(lost_id, token=token)
    if all_cancelled["occurrences"][0]["appointmentState"] != "cancelled":
        raise AssertionError("whole-series cancellation did not reach Scheduling")

    history = client.appointment_history(token, str(cancelled["occurrences"][1]["appointmentId"]))
    if len(history["value"]["items"]) < 2:
        raise AssertionError("Scheduling did not retain create and cancellation history")

    print("native finite-series journey passed")


if __name__ == "__main__":
    main()
