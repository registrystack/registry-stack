"""Bounded RFC 5545 calendar adapter for Scheduling source-busy imports."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Protocol
from zoneinfo import ZoneInfo

import recurring_ical_events
from icalendar import Calendar

MAX_CALENDAR_BYTES = 1 << 20
MAX_EXPANDED_OCCURRENCES = 4096
MAX_COVERAGE_SECONDS = 62 * 24 * 60 * 60
MAX_FRESHNESS_SECONDS = 7 * 24 * 60 * 60
SCHEDULING_UID_SUFFIX = "@appointments.scheduling.registrystack.org"


class CalendarImportError(ValueError):
    """The calendar or reconciliation result is unsafe to apply."""


@dataclass(frozen=True)
class Coverage:
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if (
            self.start.tzinfo is None
            or self.end.tzinfo is None
            or self.start >= self.end
            or (self.end - self.start).total_seconds() > MAX_COVERAGE_SECONDS
        ):
            raise CalendarImportError(
                "coverage must be one positive aware interval within 62 days"
            )


class SchedulingBusyClient(Protocol):
    def preview_source_busy(
        self, token: str, profile: str, request: dict[str, object]
    ) -> dict[str, object]: ...

    def apply_source_busy(
        self, token: str, profile: str, request: dict[str, object]
    ) -> dict[str, object]: ...


class SchedulingProvenanceReader(Protocol):
    """Authenticated same-deployment read used to recognize exported events."""

    def exported_uids(
        self,
        token: str,
        *,
        resource: str,
        coverage: Coverage,
    ) -> Collection[str]: ...


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise CalendarImportError("calendar date-time has no timezone")
    return value.astimezone(UTC).replace(microsecond=0)


def _decoded_time(value: object, default_timezone: ZoneInfo) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=default_timezone)
        return _utc(value)
    if isinstance(value, date):
        return datetime.combine(value, time.min, default_timezone).astimezone(UTC)
    raise CalendarImportError("calendar event has no supported date or date-time")


def _text(component: object, name: str) -> str | None:
    value = component.get(name)  # type: ignore[attr-defined]
    return None if value is None else str(value)


def _occurrence_identity(event: object, start: datetime) -> str:
    uid = _text(event, "UID")
    if (
        uid is None
        or not uid
        or len(uid.encode()) > 512
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in uid)
    ):
        raise CalendarImportError("calendar event UID is missing or outside its bound")
    recurrence = event.get("RECURRENCE-ID")  # type: ignore[attr-defined]
    if recurrence is None:
        occurrence = start.isoformat().replace("+00:00", "Z")
    else:
        decoded = recurrence.dt  # type: ignore[attr-defined]
        occurrence = (
            _decoded_time(decoded, ZoneInfo("UTC")).isoformat().replace("+00:00", "Z")
        )
    identity = f"{uid}#{occurrence}"
    if len(identity.encode()) > 512:
        raise CalendarImportError(
            "calendar event occurrence identity is outside its bound"
        )
    return identity


def _external_revision(event: object) -> str:
    sequence = _text(event, "SEQUENCE") or "0"
    stamp = _text(event, "LAST-MODIFIED") or _text(event, "DTSTAMP") or "unstamped"
    revision = f"sequence:{sequence};stamp:{stamp}"
    if len(revision.encode()) > 256:
        raise CalendarImportError("calendar event revision is outside its bound")
    return revision


def _bounded_recurrence_estimate(calendar: Calendar, coverage: Coverage) -> None:
    """Refuse rules that can expand beyond the cap before allocating the list."""

    days = max(1, int((coverage.end - coverage.start).total_seconds() // 86_400) + 2)
    total = 0
    safe_keys = {
        "FREQ",
        "INTERVAL",
        "COUNT",
        "UNTIL",
        "BYDAY",
        "BYMONTHDAY",
        "BYMONTH",
        "WKST",
    }
    for event in calendar.walk("VEVENT"):
        estimate = 1
        recurrence = event.get("RRULE")
        if recurrence is not None:
            keys = {str(key).upper() for key in recurrence}
            if not keys <= safe_keys:
                raise CalendarImportError(
                    "calendar recurrence rule is outside the bounded subset"
                )
            frequency = str(recurrence.get("FREQ", [""])[0]).upper()
            interval = int(recurrence.get("INTERVAL", [1])[0])
            if interval <= 0 or frequency not in {
                "DAILY",
                "WEEKLY",
                "MONTHLY",
                "YEARLY",
            }:
                raise CalendarImportError(
                    "calendar recurrence frequency is outside the bounded subset"
                )
            if frequency == "DAILY":
                estimate = days // interval + 2
            elif frequency == "WEEKLY":
                estimate = (days // (7 * interval) + 2) * max(
                    1, len(recurrence.get("BYDAY", []))
                )
            elif frequency == "MONTHLY":
                estimate = (days // (28 * interval) + 2) * max(
                    1,
                    len(recurrence.get("BYMONTHDAY", [])),
                    len(recurrence.get("BYDAY", [])),
                )
            else:
                estimate = (
                    (days // (365 * interval) + 2)
                    * max(1, len(recurrence.get("BYMONTH", [])))
                    * max(
                        1,
                        len(recurrence.get("BYMONTHDAY", [])),
                        len(recurrence.get("BYDAY", [])),
                    )
                )
            counts = recurrence.get("COUNT")
            if counts:
                estimate = min(estimate, int(counts[0]))
        rdates = event.get("RDATE")
        if rdates is not None:
            estimate += len(getattr(rdates, "dts", ()))
        total += estimate
        if total > MAX_EXPANDED_OCCURRENCES:
            raise CalendarImportError(
                f"calendar expands beyond {MAX_EXPANDED_OCCURRENCES} occurrences"
            )


def expand_calendar(
    calendar_bytes: bytes,
    *,
    coverage: Coverage,
    resource: str,
    default_timezone: str,
    trusted_scheduling_uids: Collection[str],
) -> list[dict[str, object]]:
    """Expand one bounded calendar snapshot into privacy-minimal busy rows."""

    if not calendar_bytes or len(calendar_bytes) > MAX_CALENDAR_BYTES:
        raise CalendarImportError("calendar input is empty or exceeds one MiB")
    try:
        zone = ZoneInfo(default_timezone)
        calendar = Calendar.from_ical(calendar_bytes)
    except Exception as error:
        raise CalendarImportError("calendar could not be parsed") from error
    _bounded_recurrence_estimate(calendar, coverage)
    try:
        events = recurring_ical_events.of(calendar).between(
            coverage.start, coverage.end
        )
    except Exception as error:
        raise CalendarImportError("calendar could not be expanded") from error
    if len(events) > MAX_EXPANDED_OCCURRENCES:
        raise CalendarImportError(
            f"calendar expands beyond {MAX_EXPANDED_OCCURRENCES} occurrences"
        )
    trusted = set(trusted_scheduling_uids)
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for event in events:
        if (_text(event, "STATUS") or "").upper() == "CANCELLED":
            continue
        if (_text(event, "TRANSP") or "OPAQUE").upper() == "TRANSPARENT":
            continue
        uid = _text(event, "UID")
        if uid is not None and uid.endswith(SCHEDULING_UID_SUFFIX) and uid in trusted:
            continue
        try:
            start = _decoded_time(event.decoded("DTSTART"), zone)
            end = _decoded_time(event.decoded("DTEND"), zone)
        except Exception as error:
            raise CalendarImportError(
                "calendar event must have DTSTART and DTEND"
            ) from error
        if start >= end:
            raise CalendarImportError("calendar event interval is not positive")
        if start < coverage.start.astimezone(UTC) or end > coverage.end.astimezone(UTC):
            raise CalendarImportError(
                "calendar event crosses the authoritative coverage boundary"
            )
        external_uid = _occurrence_identity(event, start)
        if external_uid in seen:
            raise CalendarImportError(
                "calendar expansion repeats one occurrence identity"
            )
        seen.add(external_uid)
        rows.append(
            {
                "externalUid": external_uid,
                "externalRevision": _external_revision(event),
                "resource": resource,
                "start": start.isoformat().replace("+00:00", "Z"),
                "end": end.isoformat().replace("+00:00", "Z"),
            }
        )
    rows.sort(key=lambda row: (str(row["start"]), str(row["externalUid"])))
    return rows


class ReconciliationJournal:
    """Small restart journal for exact lost-ack retries and source revision."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS source_state(
                profile TEXT PRIMARY KEY,
                revision INTEGER NOT NULL,
                pending_json TEXT,
                pending_digest TEXT
            )"""
        )
        self.connection.commit()

    def state(self, profile: str) -> tuple[int, dict[str, object] | None]:
        row = self.connection.execute(
            "SELECT revision,pending_json,pending_digest FROM source_state WHERE profile=?",
            (profile,),
        ).fetchone()
        if row is None:
            return (0, None)
        if row[1] is None:
            return (int(row[0]), None)
        digest = "sha256:" + hashlib.sha256(row[1].encode()).hexdigest()
        if digest != row[2]:
            raise CalendarImportError(
                "source reconciliation journal digest does not match"
            )
        return (int(row[0]), json.loads(row[1]))

    def prepare(self, profile: str, revision: int, request: dict[str, object]) -> None:
        encoded = json.dumps(request, sort_keys=True, separators=(",", ":"))
        digest = "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()
        with self.connection:
            self.connection.execute(
                """INSERT INTO source_state(profile,revision,pending_json,pending_digest)
                   VALUES(?,?,?,?) ON CONFLICT(profile) DO UPDATE SET
                   revision=excluded.revision,pending_json=excluded.pending_json,
                   pending_digest=excluded.pending_digest""",
                (profile, revision, encoded, digest),
            )

    def complete(self, profile: str, revision: int) -> None:
        with self.connection:
            self.connection.execute(
                """INSERT INTO source_state(profile,revision,pending_json,pending_digest)
                   VALUES(?,?,NULL,NULL) ON CONFLICT(profile) DO UPDATE SET
                   revision=excluded.revision,pending_json=NULL,pending_digest=NULL""",
                (profile, revision),
            )

    def close(self) -> None:
        self.connection.close()


class CalendarBusyAdapter:
    def __init__(
        self,
        client: SchedulingBusyClient,
        provenance: SchedulingProvenanceReader,
        journal: ReconciliationJournal,
        *,
        profile: str,
        resource: str,
        timezone: str,
        freshness_seconds: int,
    ) -> None:
        if not 0 < freshness_seconds <= MAX_FRESHNESS_SECONDS:
            raise CalendarImportError("freshness_seconds must be from 1 through 604800")
        self.client = client
        self.provenance = provenance
        self.journal = journal
        self.profile = profile
        self.resource = resource
        self.timezone = timezone
        self.freshness_seconds = freshness_seconds

    def close(self) -> None:
        self.journal.close()

    def reconcile(
        self,
        token: str,
        *,
        coverage: Coverage,
        observed_at: datetime,
        fetch: Callable[[], bytes],
    ) -> dict[str, object]:
        revision, pending = self.journal.state(self.profile)
        if pending is not None:
            result = self.client.apply_source_busy(token, self.profile, pending)
            self.journal.complete(self.profile, int(result["revision"]))
            revision = int(result["revision"])
        # Both timestamps derive from one whole-second observation so that
        # freshUntil never exceeds observedAt plus the configured freshness.
        observation = _utc(observed_at)
        base = {
            "expectedRevision": revision,
            "observedAt": observation.isoformat().replace("+00:00", "Z"),
            "coverage": {
                "start": _utc(coverage.start).isoformat().replace("+00:00", "Z"),
                "end": _utc(coverage.end).isoformat().replace("+00:00", "Z"),
                "resources": [self.resource],
            },
        }
        try:
            content = fetch()
        except (ConnectionError, OSError, TimeoutError):
            request = {
                **base,
                "status": "unavailable",
                "records": [],
            }
        else:
            trusted = self.provenance.exported_uids(
                token, resource=self.resource, coverage=coverage
            )
            records = expand_calendar(
                content,
                coverage=coverage,
                resource=self.resource,
                default_timezone=self.timezone,
                trusted_scheduling_uids=trusted,
            )
            request = {
                **base,
                "status": "fresh",
                "freshUntil": (observation + timedelta(seconds=self.freshness_seconds))
                .isoformat()
                .replace("+00:00", "Z"),
                "records": records,
            }
        preview = self.client.preview_source_busy(token, self.profile, request)
        current = int(preview["currentRevision"])
        if current != revision:
            raise CalendarImportError(
                f"source revision changed from {revision} to {current}; "
                "discard this snapshot and reconcile a fresh observation"
            )
        self.journal.prepare(self.profile, revision, request)
        result = self.client.apply_source_busy(token, self.profile, request)
        self.journal.complete(self.profile, int(result["revision"]))
        return {"preview": preview, "apply": result}
