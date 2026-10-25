"""Source-owned finite reservation series over the public Scheduling client.

This module deliberately owns recurrence and recovery state outside Registry
Scheduling. Scheduling remains the only authority that commits capacity.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import threading
import uuid
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Protocol
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class ValidationError(ValueError):
    """The source series definition is invalid."""


class Conflict(RuntimeError):
    """The requested source transition conflicts with durable state."""


@dataclass(frozen=True)
class Limits:
    """Work bounds for one materialized series.

    Sixty-four occurrences covers a weekly term of more than a year. The
    separate 366-day horizon prevents sparse rules from turning that count
    into multi-year work. The allocation bound permits four requirements per
    full 64-occurrence series while bounding downstream capacity checks.
    """

    max_occurrences: int = 64
    max_horizon_days: int = 366
    max_aggregate_allocation_lines: int = 256


class SchedulingClient(Protocol):
    def create_appointment(
        self, token: str, idempotency_key: str, request: dict[str, object]
    ) -> dict[str, object]: ...

    def appointment_receipt(
        self, token: str, idempotency_key: str, request: dict[str, object]
    ) -> dict[str, object]: ...

    def reschedule_appointment(
        self,
        token: str,
        appointment_id: str,
        idempotency_key: str,
        request: dict[str, object],
    ) -> dict[str, object]: ...

    def cancel_appointment(
        self,
        token: str,
        appointment_id: str,
        idempotency_key: str,
        request: dict[str, object],
    ) -> dict[str, object]: ...


_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_local(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a local ISO 8601 date-time")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValidationError(f"{field} must be a local ISO 8601 date-time") from error
    if parsed.tzinfo is not None:
        raise ValidationError(f"{field} must not contain a UTC offset")
    if parsed.microsecond:
        raise ValidationError(f"{field} must have whole-second precision")
    return parsed


def _resolve_local(local: datetime, zone: ZoneInfo, ambiguity: str) -> datetime:
    candidates: list[datetime] = []
    for fold in (0, 1):
        aware = local.replace(tzinfo=zone, fold=fold)
        instant = aware.astimezone(UTC)
        if instant.astimezone(zone).replace(tzinfo=None) == local:
            candidates.append(instant)
    distinct = sorted(set(candidates))
    if not distinct:
        raise ValidationError(f"local time {local.isoformat()} is nonexistent in {zone.key}")
    if len(distinct) == 1:
        return distinct[0]
    if ambiguity == "reject":
        raise ValidationError(f"local time {local.isoformat()} is ambiguous in {zone.key}")
    if ambiguity == "earlier":
        return distinct[0]
    if ambiguity == "later":
        return distinct[-1]
    raise ValidationError("ambiguousTime must be reject, earlier, or later")


def expand_weekly(
    definition: Mapping[str, object], limits: Limits = Limits()
) -> list[dict[str, object]]:
    """Expand one bounded weekly civil-time rule into explicit UTC instants."""

    try:
        series_uuid = uuid.UUID(str(definition["seriesId"]))
    except (KeyError, ValueError, AttributeError) as error:
        raise ValidationError("seriesId must be a UUID") from error
    timezone_name = definition.get("timezone")
    if not isinstance(timezone_name, str):
        raise ValidationError("timezone must name an IANA time zone")
    try:
        zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as error:
        raise ValidationError("timezone must name an installed IANA time zone") from error
    local_start = _parse_local(definition.get("localStart"), "localStart")
    interval = definition.get("intervalWeeks", 1)
    if not isinstance(interval, int) or isinstance(interval, bool) or not 1 <= interval <= 52:
        raise ValidationError("intervalWeeks must be an integer from 1 through 52")
    ambiguity = definition.get("ambiguousTime", "reject")
    if ambiguity not in {"reject", "earlier", "later"}:
        raise ValidationError("ambiguousTime must be reject, earlier, or later")

    raw_count = definition.get("count")
    raw_through = definition.get("throughDate")
    has_count = raw_count is not None
    has_through = raw_through is not None
    if has_count == has_through:
        raise ValidationError("exactly one of count or throughDate is required")

    candidate_locals: list[datetime] = []
    step = timedelta(weeks=interval)
    if has_count:
        if (
            not isinstance(raw_count, int)
            or isinstance(raw_count, bool)
            or raw_count < 1
            or raw_count > limits.max_occurrences
        ):
            raise ValidationError(
                f"count must be an integer from 1 through {limits.max_occurrences}"
            )
        candidate_locals = [local_start + ordinal * step for ordinal in range(raw_count)]
    else:
        if not isinstance(raw_through, str):
            raise ValidationError("throughDate must be an ISO 8601 date")
        try:
            through = date.fromisoformat(raw_through)
        except ValueError as error:
            raise ValidationError("throughDate must be an ISO 8601 date") from error
        if through < local_start.date():
            raise ValidationError("throughDate must include localStart")
        candidate = local_start
        while candidate.date() <= through:
            candidate_locals.append(candidate)
            if len(candidate_locals) > limits.max_occurrences:
                raise ValidationError(
                    f"series exceeds the maximum of {limits.max_occurrences} occurrences"
                )
            candidate += step

    if (candidate_locals[-1].date() - candidate_locals[0].date()).days > limits.max_horizon_days:
        raise ValidationError(
            f"series exceeds the maximum horizon of {limits.max_horizon_days} days"
        )

    raw_exclusions = definition.get("exclusionDates", [])
    if not isinstance(raw_exclusions, list) or not all(
        isinstance(value, str) for value in raw_exclusions
    ):
        raise ValidationError("exclusionDates must be a list of ISO 8601 dates")
    exclusions: set[date] = set()
    for value in raw_exclusions:
        try:
            parsed = date.fromisoformat(value)
        except ValueError as error:
            raise ValidationError("exclusionDates must contain ISO 8601 dates") from error
        if parsed in exclusions:
            raise ValidationError("exclusionDates must not repeat")
        exclusions.add(parsed)
    candidate_dates = {value.date() for value in candidate_locals}
    if not exclusions.issubset(candidate_dates):
        raise ValidationError("each exclusion date must name a generated candidate")

    expanded: list[dict[str, object]] = []
    for ordinal, local in enumerate(candidate_locals):
        instant = _resolve_local(local, zone, str(ambiguity))
        expanded.append(
            {
                "occurrenceId": str(uuid.uuid5(series_uuid, f"occurrence:{ordinal}")),
                "ordinal": ordinal,
                "localStart": local.isoformat(timespec="seconds"),
                "start": _utc_text(instant),
                "excluded": local.date() in exclusions,
            }
        )
    return expanded


_SCHEMA = """
CREATE TABLE IF NOT EXISTS series (
    series_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL,
    owner_profile TEXT NOT NULL,
    timezone TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    admission_template_json TEXT NOT NULL,
    aggregate_allocation_lines INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS series_revisions (
    series_id TEXT NOT NULL REFERENCES series(series_id),
    revision INTEGER NOT NULL,
    scope TEXT NOT NULL,
    diff_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (series_id, revision)
);
CREATE TABLE IF NOT EXISTS occurrences (
    occurrence_id TEXT PRIMARY KEY,
    series_id TEXT NOT NULL REFERENCES series(series_id),
    ordinal INTEGER NOT NULL,
    local_start TEXT NOT NULL,
    actual_start TEXT NOT NULL,
    excluded INTEGER NOT NULL,
    appointment_id TEXT,
    appointment_revision INTEGER,
    appointment_state TEXT,
    admission_json TEXT NOT NULL,
    UNIQUE (series_id, ordinal)
);
CREATE TABLE IF NOT EXISTS operations (
    operation_id TEXT PRIMARY KEY,
    occurrence_id TEXT NOT NULL REFERENCES occurrences(occurrence_id),
    series_revision INTEGER NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    owner_profile TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    request_json TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    appointment_id TEXT,
    dispatch_generation INTEGER,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    outcome_json TEXT,
    trace_id TEXT,
    problem_code TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (occurrence_id, series_revision)
);
CREATE TABLE IF NOT EXISTS dispatch_leases (
    series_id TEXT PRIMARY KEY REFERENCES series(series_id),
    generation INTEGER NOT NULL,
    holder TEXT,
    acquired_at TEXT
);
"""


class SeriesJournal:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(os.path.abspath(os.fspath(Path(path).expanduser())))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            metadata = self.path.lstat()
        except FileNotFoundError:
            try:
                descriptor = os.open(
                    self.path,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR,
                    0o600,
                )
            except FileExistsError:
                metadata = self.path.lstat()
            else:
                os.close(descriptor)
                metadata = self.path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValidationError("journal path must be a regular file")
        with closing(self._connect()) as connection:
            connection.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _immediate(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def prepare_series(
        self,
        definition: Mapping[str, object],
        admission_template: Mapping[str, object],
        *,
        owner: str,
        limits: Limits = Limits(),
    ) -> dict[str, object]:
        if not owner or len(owner) > 128:
            raise ValidationError("owner credential profile is invalid")
        expanded = expand_weekly(definition, limits)
        admission = copy.deepcopy(dict(admission_template))
        additional = admission.get("additionalAllocations", [])
        if not isinstance(additional, list):
            raise ValidationError("additionalAllocations must be a list when supplied")
        lines_per_occurrence = 1 + len(additional)
        active_count = sum(not bool(item["excluded"]) for item in expanded)
        aggregate = active_count * lines_per_occurrence
        if aggregate > limits.max_aggregate_allocation_lines:
            raise ValidationError(
                f"series aggregate allocation lines exceed {limits.max_aggregate_allocation_lines}"
            )
        references = admission.get("externalReferences", [])
        if not isinstance(references, list):
            raise ValidationError("externalReferences must be a list when supplied")
        for reference in references:
            if not isinstance(reference, dict):
                raise ValidationError("externalReferences must contain objects")
            if reference.get("product") == "source-application" and reference.get("recordType") in {
                "reservation-series",
                "reservation-occurrence",
            }:
                raise ValidationError("series correlation references are recipe-owned")

        series_id = str(uuid.UUID(str(definition["seriesId"])))
        now = _utc_text(datetime.now(UTC))
        with self._immediate() as connection:
            if connection.execute(
                "SELECT 1 FROM series WHERE series_id = ?", (series_id,)
            ).fetchone():
                raise Conflict("series already exists")
            connection.execute(
                "INSERT INTO series VALUES (?, 1, ?, ?, ?, ?, ?, ?)",
                (
                    series_id,
                    owner,
                    str(definition["timezone"]),
                    _canonical(dict(definition)),
                    _canonical(admission),
                    aggregate,
                    now,
                ),
            )
            creation_diff = {
                str(item["occurrenceId"]): "excluded" if item["excluded"] else "create"
                for item in expanded
            }
            connection.execute(
                "INSERT INTO series_revisions VALUES (?, 1, 'all', ?, ?)",
                (series_id, _canonical(creation_diff), now),
            )
            connection.execute(
                "INSERT INTO dispatch_leases VALUES (?, 0, NULL, NULL)", (series_id,)
            )
            for item in expanded:
                occurrence_id = str(item["occurrenceId"])
                occurrence_admission = copy.deepcopy(admission)
                occurrence_admission["start"] = item["start"]
                occurrence_admission["externalReferences"] = [
                    *copy.deepcopy(references),
                    {
                        "product": "source-application",
                        "recordType": "reservation-series",
                        "identifier": series_id,
                    },
                    {
                        "product": "source-application",
                        "recordType": "reservation-occurrence",
                        "identifier": occurrence_id,
                    },
                ]
                connection.execute(
                    "INSERT INTO occurrences VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?)",
                    (
                        occurrence_id,
                        series_id,
                        item["ordinal"],
                        item["localStart"],
                        item["start"],
                        int(bool(item["excluded"])),
                        _canonical(occurrence_admission),
                    ),
                )
                if not item["excluded"]:
                    request = {"admission": occurrence_admission}
                    self._insert_operation(
                        connection,
                        occurrence_id=occurrence_id,
                        series_revision=1,
                        kind="create",
                        owner=owner,
                        request=request,
                        appointment_id=None,
                        now=now,
                    )
        return self.read_series(series_id)

    @staticmethod
    def _insert_operation(
        connection: sqlite3.Connection,
        *,
        occurrence_id: str,
        series_revision: int,
        kind: str,
        owner: str,
        request: Mapping[str, object],
        appointment_id: str | None,
        now: str,
    ) -> None:
        operation_id = str(
            uuid.uuid5(uuid.UUID(occurrence_id), f"revision:{series_revision}:{kind}")
        )
        key = f"series-{occurrence_id}-r{series_revision}-{kind}"
        request_json = _canonical(dict(request))
        digest = hashlib.sha256(request_json.encode()).hexdigest()
        connection.execute(
            """
            INSERT INTO operations (
                operation_id, occurrence_id, series_revision, kind, status,
                owner_profile, idempotency_key, request_json, request_hash,
                appointment_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'prepared', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                operation_id,
                occurrence_id,
                series_revision,
                kind,
                owner,
                key,
                request_json,
                digest,
                appointment_id,
                now,
                now,
            ),
        )

    def prepare_edit(
        self,
        series_id: str,
        *,
        expected_revision: int,
        scope: str,
        target_occurrence_id: str | None,
        changes: Mapping[str, Mapping[str, object]],
        now: datetime,
    ) -> dict[str, object]:
        if now.tzinfo is None:
            raise ValidationError("edit clock must be timezone-aware")
        if scope not in {"one", "this-and-future", "all"}:
            raise ValidationError("scope must be one, this-and-future, or all")
        timestamp = _utc_text(datetime.now(UTC))
        with self._immediate() as connection:
            series = connection.execute(
                "SELECT * FROM series WHERE series_id = ?", (series_id,)
            ).fetchone()
            if series is None:
                raise ValidationError("series does not exist")
            if int(series["revision"]) != expected_revision:
                raise Conflict("series revision changed")
            rows = connection.execute(
                "SELECT * FROM occurrences WHERE series_id = ? ORDER BY ordinal",
                (series_id,),
            ).fetchall()
            by_id = {str(row["occurrence_id"]): row for row in rows}
            target = by_id.get(str(target_occurrence_id)) if target_occurrence_id else None
            if scope in {"one", "this-and-future"} and target is None:
                raise ValidationError("scope requires a series occurrence target")
            future = [
                row
                for row in rows
                if datetime.fromisoformat(str(row["actual_start"]).replace("Z", "+00:00"))
                >= now.astimezone(UTC)
            ]
            if scope == "one":
                if target not in future:
                    raise ValidationError("a past occurrence cannot be edited")
                selected = [target]
            elif scope == "this-and-future":
                if target not in future:
                    raise ValidationError("a past occurrence cannot anchor an edit")
                selected = [row for row in future if row["ordinal"] >= target["ordinal"]]
            else:
                selected = future
            selected_ids = {str(row["occurrence_id"]) for row in selected}
            if set(changes) != selected_ids:
                raise ValidationError("changes must explicitly name every occurrence in scope")

            new_revision = expected_revision + 1
            diff: dict[str, object] = {}
            for row in selected:
                occurrence_id = str(row["occurrence_id"])
                pending = connection.execute(
                    """SELECT 1 FROM operations WHERE occurrence_id = ?
                         AND status IN ('prepared', 'dispatched', 'unresolved') LIMIT 1""",
                    (occurrence_id,),
                ).fetchone()
                if pending is not None:
                    raise Conflict("occurrence has a pending or unresolved operation")
                change = dict(changes[occurrence_id])
                action = change.get("action")
                if action not in {"reschedule", "cancel"}:
                    raise ValidationError("an occurrence change must reschedule or cancel")
                if row["appointment_id"] is None or row["appointment_state"] != "confirmed":
                    raise Conflict("only a confirmed occurrence can be changed")
                observed_revision = int(row["appointment_revision"])
                if action == "cancel":
                    request: dict[str, object] = {"observedRevision": observed_revision}
                    if "reason" in change:
                        request["reason"] = change["reason"]
                else:
                    local = _parse_local(change.get("localStart"), "localStart")
                    zone = ZoneInfo(str(series["timezone"]))
                    definition = json.loads(str(series["definition_json"]))
                    # Stored definitions keep the authored shape, so the
                    # omitted policy defaults as it does on expansion.
                    ambiguity = str(definition.get("ambiguousTime", "reject"))
                    instant = _resolve_local(local, zone, ambiguity)
                    admission = json.loads(str(row["admission_json"]))
                    admission["start"] = _utc_text(instant)
                    # Scheduling keeps the create-time references, party
                    # references, and manager immutable. Its reschedule
                    # contract requires these members to be absent.
                    for member in ("externalReferences", "partyReferences", "manager"):
                        admission.pop(member, None)
                    request = {"observedRevision": observed_revision, "admission": admission}
                    change["resolvedStart"] = admission["start"]
                self._insert_operation(
                    connection,
                    occurrence_id=occurrence_id,
                    series_revision=new_revision,
                    kind=str(action),
                    owner=str(series["owner_profile"]),
                    request=request,
                    appointment_id=str(row["appointment_id"]),
                    now=timestamp,
                )
                diff[occurrence_id] = change
            connection.execute(
                "UPDATE series SET revision = ? WHERE series_id = ? AND revision = ?",
                (new_revision, series_id, expected_revision),
            )
            connection.execute(
                "INSERT INTO series_revisions VALUES (?, ?, ?, ?, ?)",
                (series_id, new_revision, scope, _canonical(diff), timestamp),
            )
        return {"seriesId": series_id, "revision": new_revision, "scope": scope, "diff": diff}

    def read_history(self, series_id: str) -> list[dict[str, object]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM series_revisions WHERE series_id = ? ORDER BY revision",
                (series_id,),
            ).fetchall()
        return [
            {
                "revision": int(row["revision"]),
                "scope": str(row["scope"]),
                "diff": json.loads(str(row["diff_json"])),
                "createdAt": str(row["created_at"]),
            }
            for row in rows
        ]

    def read_series(self, series_id: str) -> dict[str, object]:
        with closing(self._connect()) as connection:
            series = connection.execute(
                "SELECT * FROM series WHERE series_id = ?", (series_id,)
            ).fetchone()
            if series is None:
                raise ValidationError("series does not exist")
            rows = connection.execute(
                """
                SELECT o.*,
                       p.operation_id, p.series_revision, p.kind, p.status,
                       p.owner_profile, p.idempotency_key, p.request_json,
                       p.request_hash, p.outcome_json, p.trace_id,
                       p.problem_code, p.last_error, p.attempt_count
                  FROM occurrences o
             LEFT JOIN operations p ON p.operation_id = (
                       SELECT p2.operation_id FROM operations p2
                        WHERE p2.occurrence_id = o.occurrence_id
                     ORDER BY p2.series_revision DESC LIMIT 1
                  )
                 WHERE o.series_id = ?
              ORDER BY o.ordinal
                """,
                (series_id,),
            ).fetchall()
        occurrences: list[dict[str, object]] = []
        for row in rows:
            operation = None
            if row["operation_id"] is not None:
                status = str(row["status"])
                operation = {
                    "operationId": str(row["operation_id"]),
                    "seriesRevision": int(row["series_revision"]),
                    "kind": str(row["kind"]),
                    "status": status,
                    "ownerProfile": str(row["owner_profile"]),
                    "idempotencyKey": str(row["idempotency_key"]),
                    "request": json.loads(str(row["request_json"])),
                    "requestHash": str(row["request_hash"]),
                    "attemptCount": int(row["attempt_count"]),
                    "problemCode": row["problem_code"],
                    "lastError": row["last_error"],
                }
            if bool(row["excluded"]) and operation is None:
                outcome = "excluded"
            elif row["status"] == "succeeded":
                outcome = "succeeded"
            elif row["status"] == "refused":
                outcome = "refused"
            elif row["status"] in {"dispatched", "unresolved"}:
                outcome = "unresolved"
            else:
                outcome = "pending"
            occurrences.append(
                {
                    "occurrenceId": str(row["occurrence_id"]),
                    "ordinal": int(row["ordinal"]),
                    "localStart": str(row["local_start"]),
                    "start": str(row["actual_start"]),
                    "excluded": bool(row["excluded"]),
                    "appointmentId": row["appointment_id"],
                    "appointmentRevision": row["appointment_revision"],
                    "appointmentState": row["appointment_state"],
                    "outcome": outcome,
                    "operation": operation,
                }
            )
        summary: dict[str, int] = {}
        for item in occurrences:
            outcome = str(item["outcome"])
            summary[outcome] = summary.get(outcome, 0) + 1
        return {
            "seriesId": series_id,
            "revision": int(series["revision"]),
            "mode": "partial",
            "ownerProfile": str(series["owner_profile"]),
            "aggregateAllocationLines": int(series["aggregate_allocation_lines"]),
            "occurrences": occurrences,
            "summary": dict(sorted(summary.items())),
        }

    def mark_dispatched_for_test(self, operation_id: str) -> None:
        with self._immediate() as connection:
            connection.execute(
                """UPDATE operations
                      SET status = 'dispatched', dispatch_generation = 1
                    WHERE operation_id = ?""",
                (operation_id,),
            )

    @contextmanager
    def dispatch_lease(self, series_id: str) -> Iterator[int]:
        lock_path = f"{self.path}.dispatch.lock"
        with _THREAD_LOCKS_GUARD:
            thread_lock = _THREAD_LOCKS.setdefault(lock_path, threading.Lock())
        if not thread_lock.acquire(blocking=False):
            raise Conflict("series dispatch is already in flight")
        with ExitStack() as cleanup:
            cleanup.callback(thread_lock.release)
            descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise Conflict("series dispatch is already in flight") from error
                holder = str(uuid.uuid4())
                with self._immediate() as connection:
                    row = connection.execute(
                        "SELECT generation FROM dispatch_leases WHERE series_id = ?", (series_id,)
                    ).fetchone()
                    if row is None:
                        raise ValidationError("series does not exist")
                    generation = int(row["generation"]) + 1
                    connection.execute(
                        """UPDATE dispatch_leases
                              SET generation = ?, holder = ?, acquired_at = ?
                            WHERE series_id = ?""",
                        (generation, holder, _utc_text(datetime.now(UTC)), series_id),
                    )
                try:
                    yield generation
                finally:
                    with self._immediate() as connection:
                        connection.execute(
                            """UPDATE dispatch_leases
                                  SET holder = NULL, acquired_at = NULL
                                WHERE series_id = ? AND generation = ? AND holder = ?""",
                            (series_id, generation, holder),
                        )
            finally:
                # Closing releases the kernel lock even if journal cleanup fails.
                os.close(descriptor)

    def pending_operations(self, series_id: str) -> list[sqlite3.Row]:
        with closing(self._connect()) as connection:
            return connection.execute(
                """
                SELECT p.* FROM operations p
                  JOIN occurrences o ON o.occurrence_id = p.occurrence_id
                 WHERE o.series_id = ?
                   AND p.status IN ('prepared', 'dispatched', 'unresolved')
              ORDER BY o.ordinal, p.series_revision
                """,
                (series_id,),
            ).fetchall()

    def claim_operation(self, operation_id: str, generation: int) -> str:
        with self._immediate() as connection:
            row = connection.execute(
                "SELECT status FROM operations WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if row is None or row["status"] not in {"prepared", "dispatched", "unresolved"}:
                raise Conflict("operation is no longer recoverable")
            prior = str(row["status"])
            connection.execute(
                """
                UPDATE operations
                   SET status = 'dispatched', dispatch_generation = ?,
                       attempt_count = attempt_count + 1, updated_at = ?
                 WHERE operation_id = ?
                """,
                (generation, _utc_text(datetime.now(UTC)), operation_id),
            )
        return prior

    def finish_operation(
        self,
        operation_id: str,
        generation: int,
        *,
        status: str,
        value: Mapping[str, object] | None = None,
        trace_id: str | None = None,
        problem_code: str | None = None,
        last_error: str | None = None,
    ) -> None:
        if status not in {"succeeded", "refused", "unresolved"}:
            raise ValueError("invalid terminal operation status")
        with self._immediate() as connection:
            operation = connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if (
                operation is None
                or operation["status"] != "dispatched"
                or operation["dispatch_generation"] != generation
            ):
                raise Conflict("stale dispatch completion was fenced")
            connection.execute(
                """
                UPDATE operations
                   SET status = ?, outcome_json = ?, trace_id = ?,
                       problem_code = ?, last_error = ?, updated_at = ?
                 WHERE operation_id = ? AND dispatch_generation = ?
                """,
                (
                    status,
                    _canonical(dict(value)) if value is not None else None,
                    trace_id,
                    problem_code,
                    last_error,
                    _utc_text(datetime.now(UTC)),
                    operation_id,
                    generation,
                ),
            )
            if status != "succeeded" or value is None:
                return
            occurrence_id = str(operation["occurrence_id"])
            kind = str(operation["kind"])
            if kind == "create":
                connection.execute(
                    """
                    UPDATE occurrences
                       SET appointment_id = ?, appointment_revision = ?, appointment_state = ?
                     WHERE occurrence_id = ?
                    """,
                    (
                        value["appointmentId"],
                        value["revision"],
                        value.get("state", "confirmed"),
                        occurrence_id,
                    ),
                )
            elif kind == "reschedule":
                request = json.loads(str(operation["request_json"]))
                rescheduled = request["admission"]
                row = connection.execute(
                    "SELECT admission_json FROM occurrences WHERE occurrence_id = ?",
                    (occurrence_id,),
                ).fetchone()
                if row is None:
                    raise ValidationError("occurrence does not exist")
                admission = json.loads(str(row["admission_json"]))
                admission["start"] = rescheduled["start"]
                connection.execute(
                    """
                    UPDATE occurrences
                       SET local_start = ?, actual_start = ?, admission_json = ?,
                           appointment_revision = ?, appointment_state = ?
                     WHERE occurrence_id = ?
                    """,
                    (
                        datetime.fromisoformat(str(rescheduled["start"]).replace("Z", "+00:00"))
                        .astimezone(ZoneInfo(self._series_timezone(connection, occurrence_id)))
                        .replace(tzinfo=None)
                        .isoformat(timespec="seconds"),
                        rescheduled["start"],
                        _canonical(admission),
                        value["revision"],
                        value.get("state", "confirmed"),
                        occurrence_id,
                    ),
                )
            else:
                connection.execute(
                    """UPDATE occurrences
                          SET appointment_revision = ?, appointment_state = ?
                        WHERE occurrence_id = ?""",
                    (value["revision"], value.get("state", "cancelled"), occurrence_id),
                )

    @staticmethod
    def _series_timezone(connection: sqlite3.Connection, occurrence_id: str) -> str:
        row = connection.execute(
            """
            SELECT s.timezone FROM series s
              JOIN occurrences o ON o.series_id = s.series_id
             WHERE o.occurrence_id = ?
            """,
            (occurrence_id,),
        ).fetchone()
        if row is None:
            raise ValidationError("occurrence does not exist")
        return str(row["timezone"])

    def mark_profile_mismatch(self, series_id: str, expected: str, actual: str) -> bool:
        with self._immediate() as connection:
            rows = connection.execute(
                """
                SELECT p.operation_id, p.status FROM operations p
                  JOIN occurrences o ON o.occurrence_id = p.occurrence_id
                 WHERE o.series_id = ?
                   AND p.status IN ('prepared', 'dispatched', 'unresolved')
                """,
                (series_id,),
            ).fetchall()
            uncertain = [row for row in rows if row["status"] != "prepared"]
            if uncertain:
                for row in uncertain:
                    connection.execute(
                        """UPDATE operations
                              SET status = 'unresolved', last_error = ?
                            WHERE operation_id = ?""",
                        ("credential profile mismatch", row["operation_id"]),
                    )
                return True
        return False


class SeriesProcessor:
    """Dispatch and reconcile journalled commands through the public client."""

    def __init__(
        self,
        journal: SeriesJournal,
        client: SchedulingClient,
        *,
        credential_profile: str,
    ) -> None:
        self.journal = journal
        self.client = client
        self.credential_profile = credential_profile

    def process(self, series_id: str, *, token: str) -> dict[str, object]:
        before = self.journal.read_series(series_id)
        expected_profile = str(before["ownerProfile"])
        if self.credential_profile != expected_profile:
            if self.journal.mark_profile_mismatch(
                series_id, expected_profile, self.credential_profile
            ):
                return self.journal.read_series(series_id)
            raise Conflict("credential profile does not own this series")
        with self.journal.dispatch_lease(series_id) as generation:
            for operation in self.journal.pending_operations(series_id):
                operation_id = str(operation["operation_id"])
                request_json = str(operation["request_json"])
                if hashlib.sha256(request_json.encode()).hexdigest() != operation["request_hash"]:
                    raise Conflict("journal request integrity check failed")
                prior = self.journal.claim_operation(operation_id, generation)
                request = json.loads(request_json)
                kind = str(operation["kind"])
                try:
                    if kind == "create" and prior != "prepared":
                        complete = self.client.appointment_receipt(
                            token, str(operation["idempotency_key"]), request
                        )
                    elif kind == "create":
                        complete = self.client.create_appointment(
                            token, str(operation["idempotency_key"]), request
                        )
                    elif kind == "reschedule":
                        complete = self.client.reschedule_appointment(
                            token,
                            str(operation["appointment_id"]),
                            str(operation["idempotency_key"]),
                            request,
                        )
                    else:
                        complete = self.client.cancel_appointment(
                            token,
                            str(operation["appointment_id"]),
                            str(operation["idempotency_key"]),
                            request,
                        )
                except Exception as error:
                    code = getattr(error, "code", None)
                    unknown = bool(getattr(error, "outcome_unknown", True))
                    recovery = prior != "prepared"
                    unresolved = (
                        unknown
                        or recovery
                        or code
                        in {
                            "receipt.unresolved",
                            "idempotency.expired",
                        }
                    )
                    self.journal.finish_operation(
                        operation_id,
                        generation,
                        status="unresolved" if unresolved else "refused",
                        problem_code=str(code) if code else None,
                        last_error=type(error).__name__,
                    )
                    continue
                value = complete.get("value")
                if not isinstance(value, dict):
                    self.journal.finish_operation(
                        operation_id,
                        generation,
                        status="unresolved",
                        last_error="invalid public client completion",
                    )
                    continue
                self.journal.finish_operation(
                    operation_id,
                    generation,
                    status="succeeded",
                    value=value,
                    trace_id=str(complete.get("trace_id", "")),
                )
        return self.journal.read_series(series_id)


def public_client(base_url: str, **configuration: object) -> SchedulingClient:
    """Construct the maintained public Python facade lazily.

    Keeping the import here lets source-only validation run without a native
    wheel. Production callers still use the unified public package.
    """

    from registry_client import scheduling

    return scheduling.SchedulingClient(base_url, **configuration)
