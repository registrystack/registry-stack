#!/usr/bin/env python3
"""Exercise calendar busy reconciliation through the installed public facade."""

from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime
from pathlib import Path
from time import sleep

from registry_client import scheduling

from calendar_busy import (
    SCHEDULING_UID_SUFFIX,
    CalendarBusyAdapter,
    Coverage,
    ReconciliationJournal,
    SchedulingBusyClient,
)


class SyntheticLostResponse(Exception):
    code = None
    outcome_unknown = True


class SchedulingFacadeBusyClient:
    """Expose the adapter protocol over the public facade's Complete envelope."""

    def __init__(self, client: scheduling.SchedulingClient) -> None:
        self.client = client

    def preview_source_busy(self, token, profile, request):
        return self.client.preview_source_busy(token, profile, request)["value"]

    def apply_source_busy(self, token, profile, request):
        return self.client.apply_source_busy(token, profile, request)["value"]


class LoseOneApplyResponse:
    """Call the real client, then model one lost success response."""

    def __init__(self, client: SchedulingBusyClient) -> None:
        self.client = client
        self.lost = False
        self.original: dict[str, object] | None = None

    def apply_source_busy(self, token, profile, request):
        complete = self.client.apply_source_busy(token, profile, request)
        if not self.lost:
            self.lost = True
            self.original = complete
            raise SyntheticLostResponse("synthetic response loss after native success")
        return complete

    def __getattr__(self, name: str) -> object:
        return getattr(self.client, name)


class OperationalExportProvenance:
    """Derive trusted export UIDs from this deployment's authenticated read."""

    def __init__(self, client, *, service: str, location: str, profile: str) -> None:
        self.client = client
        self.service = service
        self.location = location
        self.profile = profile

    def exported_uids(self, token, *, resource, coverage):
        cursor = None
        seen: set[str] = set()
        uids: set[str] = set()
        for _ in range(10):
            query = {
                "service": self.service,
                "location": self.location,
                "start": coverage.start.astimezone(UTC)
                .isoformat()
                .replace("+00:00", "Z"),
                "end": coverage.end.astimezone(UTC).isoformat().replace("+00:00", "Z"),
                "timeBasis": "displayed",
                "resource": resource,
                "profile": self.profile,
                "limit": 50,
            }
            if cursor is not None:
                query["cursor"] = cursor
            response = self.client.list_operational_appointments(token, query)
            value = response["value"]
            for item in value["items"]:
                appointment_id = item["appointmentId"]
                uids.add(appointment_id + SCHEDULING_UID_SUFFIX)
                if len(uids) > 500:
                    raise RuntimeError("trusted export read exceeded 500 appointments")
            next_cursor = value.get("nextCursor")
            if next_cursor is None:
                return uids
            if next_cursor in seen:
                raise RuntimeError("trusted export read returned a cursor loop")
            seen.add(next_cursor)
            cursor = next_cursor
        raise RuntimeError("trusted export read exceeded ten pages")


def aware(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("coverage values must include a UTC offset")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--calendar", required=True, type=Path)
    parser.add_argument("--state-directory", required=True, type=Path)
    parser.add_argument("--source-profile", required=True)
    parser.add_argument("--operational-profile", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--location", required=True)
    parser.add_argument("--resource", required=True)
    parser.add_argument("--timezone", required=True)
    parser.add_argument("--coverage-start", required=True)
    parser.add_argument("--coverage-end", required=True)
    parser.add_argument("--freshness-seconds", type=int, default=300)
    args = parser.parse_args()
    token = os.environ.get("REGISTRY_SCHEDULING_TOKEN")
    if not token:
        raise RuntimeError("REGISTRY_SCHEDULING_TOKEN is required")
    if args.state_directory.exists() and any(args.state_directory.iterdir()):
        raise RuntimeError("--state-directory must be empty")
    args.state_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.state_directory.chmod(0o700)

    facade = scheduling.SchedulingClient(args.base_url)
    client = SchedulingFacadeBusyClient(facade)
    provenance = OperationalExportProvenance(
        facade,
        service=args.service,
        location=args.location,
        profile=args.operational_profile,
    )
    journal_path = args.state_directory / "source-busy.sqlite3"
    coverage = Coverage(aware(args.coverage_start), aware(args.coverage_end))
    observed_at = datetime.now(UTC).replace(microsecond=0)

    lossy_client = LoseOneApplyResponse(client)
    lossy = CalendarBusyAdapter(
        lossy_client,
        provenance,
        ReconciliationJournal(journal_path),
        profile=args.source_profile,
        resource=args.resource,
        timezone=args.timezone,
        freshness_seconds=args.freshness_seconds,
    )
    try:
        lossy.reconcile(
            token,
            coverage=coverage,
            observed_at=observed_at,
            fetch=args.calendar.read_bytes,
        )
    except SyntheticLostResponse as error:
        if error.code is not None or not error.outcome_unknown:
            raise AssertionError(
                "synthetic lost response was not outcome-unknown"
            ) from error
    else:
        raise AssertionError("native journey did not exercise the lost-response path")
    lossy.close()

    recovered_adapter = CalendarBusyAdapter(
        client,
        provenance,
        ReconciliationJournal(journal_path),
        profile=args.source_profile,
        resource=args.resource,
        timezone=args.timezone,
        freshness_seconds=args.freshness_seconds,
    )
    _, pending = recovered_adapter.journal.state(args.source_profile)
    if pending is None:
        raise AssertionError("lost-response request was not journaled")
    replayed = client.apply_source_busy(token, args.source_profile, pending)
    if replayed.get("kind") != "already-applied":
        raise AssertionError(f"exact replay was not recognized: {replayed!r}")
    if lossy_client.original is None:
        raise AssertionError(
            "synthetic lost response did not retain its original outcome"
        )
    original = {
        key: value for key, value in lossy_client.original.items() if key != "kind"
    }
    replay = {key: value for key, value in replayed.items() if key != "kind"}
    if replay != original:
        raise AssertionError(f"exact replay lost its bounded outcome: {replayed!r}")
    recovered_adapter.journal.complete(args.source_profile, int(replayed["revision"]))
    sleep(1)
    recovered = recovered_adapter.reconcile(
        token,
        coverage=coverage,
        observed_at=datetime.now(UTC),
        fetch=args.calendar.read_bytes,
    )
    recovered_adapter.close()
    if recovered["apply"].get("kind") not in {"applied", "already-applied"}:
        raise AssertionError(f"unexpected recovered outcome: {recovered['apply']!r}")
    delayed = dict(pending)
    delayed["expectedRevision"] = int(recovered["apply"]["revision"])
    try:
        client.apply_source_busy(token, args.source_profile, delayed)
    except scheduling.SchedulingClientError as error:
        if (
            error.code != "precondition.failed"
            or error.status != 412
            or error.outcome_unknown
        ):
            raise AssertionError(
                f"unexpected delayed observation refusal: {error}"
            ) from error
    else:
        raise AssertionError("delayed observation replaced a newer source revision")
    print("calendar busy native journey completed")


if __name__ == "__main__":
    main()
