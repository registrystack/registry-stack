#!/usr/bin/env python3
"""Export bounded operational Scheduling appointment rows as JSON or CSV."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

PAGE_SIZE = 50
MAXIMUM_PAGE_SIZE = 100
MAXIMUM_PAGES = 10
MAXIMUM_ROWS = 500
CSV_COLUMNS = (
    "appointmentId",
    "revision",
    "state",
    "service",
    "location",
    "offering",
    "displayedStart",
    "displayedEnd",
    "occupiedStart",
    "occupiedEnd",
    "partyRecipients",
    "partyAttendees",
    "attendanceState",
    "allocations",
    "externalReferences",
)


class ExportError(ValueError):
    """The operational read returned an unusable or out-of-bounds page."""


class OperationalClient(Protocol):
    def list_operational_appointments(
        self, token: str, query: dict[str, object]
    ) -> dict[str, object]: ...


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_rows(
    client: OperationalClient,
    token: str,
    query: Mapping[str, object],
    *,
    page_size: int = PAGE_SIZE,
    max_pages: int = MAXIMUM_PAGES,
    max_rows: int = MAXIMUM_ROWS,
) -> dict[str, object]:
    """Follow every continuation cursor; fail rather than return a partial export."""

    if not 1 <= page_size <= MAXIMUM_PAGE_SIZE:
        raise ExportError(f"page_size must be from 1 through {MAXIMUM_PAGE_SIZE}")
    started_at = _now()
    rows: list[dict[str, object]] = []
    seen_cursors: set[str] = set()
    cursor: str | None = None
    for _ in range(max_pages):
        request = {**query, "limit": page_size}
        if cursor is not None:
            request["cursor"] = cursor
        response = client.list_operational_appointments(token, request)
        value = response.get("value") if isinstance(response, dict) else None
        if not isinstance(response, dict) or response.get("kind") != "complete":
            raise ExportError("operational client did not return a complete page")
        if not isinstance(value, dict) or not isinstance(value.get("items"), list):
            raise ExportError("operational page must carry a list of items")
        if len(value["items"]) > page_size:
            raise ExportError("operational page exceeded the requested page size")
        for item in value["items"]:
            if not isinstance(item, dict):
                raise ExportError("every operational row must be an object")
            rows.append(item)
        if len(rows) > max_rows:
            raise ExportError(f"operational read exceeded the {max_rows} row bound")
        cursor = value.get("nextCursor")
        if cursor is None:
            return {
                "query": dict(query),
                "startedAt": started_at,
                "completedAt": _now(),
                "rows": rows,
            }
        if not isinstance(cursor, str) or not cursor or cursor in seen_cursors:
            raise ExportError("operational read returned an invalid or repeated cursor")
        seen_cursors.add(cursor)
    raise ExportError(f"operational read exceeded the {max_pages} page bound")


def _flat_row(row: Mapping[str, object]) -> dict[str, object]:
    party = row.get("party") if isinstance(row.get("party"), dict) else {}
    attendance = row.get("attendance") if isinstance(row.get("attendance"), dict) else {}
    allocations = row.get("allocations") or []
    references = row.get("externalReferences") or []
    flat = {column: row.get(column, "") for column in CSV_COLUMNS[:10]}
    flat["partyRecipients"] = party.get("recipients", "")
    flat["partyAttendees"] = party.get("attendees", "")
    flat["attendanceState"] = attendance.get("state", "")
    flat["allocations"] = ";".join(
        f"{item.get('resource', '')}:{item.get('units', '')}:"
        f"{item.get('occupiedStart', '')}/{item.get('occupiedEnd', '')}"
        for item in allocations
    )
    flat["externalReferences"] = ";".join(
        f"{item.get('product', '')}/{item.get('recordType', '')}/{item.get('identifier', '')}"
        for item in references
    )
    return flat


def render(export: Mapping[str, object], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(export, indent=2, sort_keys=True) + "\n"
    if output_format != "csv":
        raise ExportError("format must be json or csv")
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in export["rows"]:  # type: ignore[union-attr]
        writer.writerow(_flat_row(row))
    return buffer.getvalue()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--location", required=True)
    parser.add_argument("--start", required=True, help="RFC 3339 instant, inclusive")
    parser.add_argument("--end", required=True, help="RFC 3339 instant, exclusive")
    parser.add_argument("--profile", required=True, help="runtime profile that scopes the read")
    parser.add_argument("--offering")
    parser.add_argument("--resource")
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    parser.add_argument(
        "--output",
        type=Path,
        help="new file created with mode 0600; refuses to overwrite. Default: standard output",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    token = os.environ.get("REGISTRY_SCHEDULING_TOKEN")
    if not token:
        raise SystemExit("REGISTRY_SCHEDULING_TOKEN is required")
    from registry_client import scheduling

    query: dict[str, object] = {
        "service": args.service,
        "location": args.location,
        "start": args.start,
        "end": args.end,
        "timeBasis": "occupied",
        "profile": args.profile,
    }
    for name in ("offering", "resource"):
        if getattr(args, name):
            query[name] = getattr(args, name)
    try:
        export = read_rows(scheduling.SchedulingClient(args.base_url), token, query)
        text = render(export, args.format)
    except ExportError as error:
        raise SystemExit(str(error)) from error
    if args.output is None:
        sys.stdout.write(text)
        return
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)


if __name__ == "__main__":
    main()
