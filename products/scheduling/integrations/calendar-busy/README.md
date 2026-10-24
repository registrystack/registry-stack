# Calendar busy import

This maintained adapter reconciles a bounded RFC 5545 calendar snapshot into
Scheduling source-owned busy intervals. Scheduling remains the booking
authority. The calendar source can replace only its own facts, for explicitly
configured resources and coverage, and never creates, reschedules, or cancels
an appointment.

The adapter uses `icalendar` and `recurring-ical-events` to parse timezone-aware
events and expand bounded daily, weekly, monthly, and yearly recurrence rules,
exclusions, and detached exceptions. It accepts at most one MiB, 62 days, and
4,096 expanded occurrences. It estimates expansion before allocating the
occurrence list and refuses finer recurrence frequencies and multiplicative
rule parts outside this bounded subset. Cancelled and transparent events do not
create busy time. An event crossing the claimed coverage boundary is refused,
so a partial-window refresh cannot erase or replace the portion outside its
authority.

Only `UID`, `SEQUENCE`, recurrence identity, and the busy interval enter the
source-busy request. Descriptions, summaries, attendees, organizers, locations,
and absence reasons are omitted from payloads and diagnostics.

## Authority and conservative availability

Each configured source profile has one unique source ID and a bounded set of
allowed Scheduling resources. Profiles may share a write scope, but a caller
must select exactly one profile. Every record, covered resource, and deletion
is checked against that profile. Narrowing a profile does not silently erase
retained rows that the source no longer has authority to reconcile.

One source ID is one strictly ordered observation stream. Use separate source
IDs for feeds that can observe and publish independently. Scheduling refuses a
different request whose observation time is not later than the last applied
snapshot, including equal timestamps, so a delayed snapshot cannot replace
newer busy facts. A new revision needs a later observation time even for an
empty snapshot, an outage snapshot, or a disjoint coverage slice. The adapter
also refuses revision drift and requires a fresh read and snapshot instead of
rebasing already observed bytes.

Each snapshot states its exact coverage, observation time, and freshness. A
fresh snapshot replaces only this source's contained rows in the covered
interval. An outage snapshot has status `unavailable`, carries no rows, and
retains existing facts. Expired, unavailable, or uncovered intervals block new
atomic allocations for a configured resource. Existing commitments remain
unchanged. Responses always return the exact affected interval count and say
whether the result is truncated. Interval detail requires the profile's
explicit `impactProjection: commitment-intervals`; the default
`count-only` projection returns no items. Even the detailed projection omits
appointment and hold identifiers, parties, external references, and source
references.

The SQLite journal saves the exact pending request before apply. A restart
retries those same bytes, allowing Scheduling's request digest and revision CAS
to distinguish a lost success response from a competing update. The journal
contains identifiers and time intervals but no bearer token or calendar
content. Protect its directory as operational state. A competing stale request
is an HTTP 412 `revision.mismatch`; the adapter does not treat it as an empty or
successful source snapshot. If an upgraded deployment recognizes the exact
request digest but has no retained original outcome, it returns
`service.unavailable`; treat the mutation result as unknown, not as no effect.

## Scheduling export round trips

An event using Scheduling's export UID suffix is excluded only when its exact
UID is also found through an authenticated operational read from the same
deployment. A suffix match alone is untrusted and remains busy. The native
journey derives this set page-wise, with a ten-page and 500-appointment bound;
there is no manual trusted-UID option.

## Verification

Run the isolated adapter tests from this directory:

```sh
uv sync --frozen
uv run python -m unittest -v test_calendar_busy.py
```

The tests cover timezone conversion, recurrence exclusions, deletions through
snapshot omission, transparent and cancelled events, coverage boundaries,
trusted round trips, outage retention semantics, restart, and exact retry after
a lost apply response.

`native_journey.py` exercises the installed public `registry_client.scheduling`
facade against a running Scheduling deployment. That facade comes from the
built unified Registry Stack wheel, not this adapter's unit-test dependencies.
After building the version-matched product wheels and assembling the unified
wheel with `release/scripts/assemble-registry-client-wheel.py`, install that
local artifact into this project's environment:

```sh
uv sync --frozen
uv pip install --python .venv/bin/python /path/to/registry_stack_client-<version>-<platform>.whl
```

Then run the journey below. It performs an authenticated
same-deployment provenance read, applies a real calendar snapshot, loses the
first success response deliberately, restarts from the journal, and reconciles
the same source again. Inject the token through the normal secret mechanism:

```sh
REGISTRY_SCHEDULING_TOKEN=... uv run python native_journey.py \
  --base-url https://scheduling.example.gov/ \
  --calendar bounded.ics \
  --state-directory /secure/source-busy-run \
  --source-profile staff-calendar \
  --operational-profile calendar-export \
  --service registry-update \
  --location north-counter \
  --resource staff-a \
  --timezone Europe/Zurich \
  --coverage-start 2026-11-01T00:00:00Z \
  --coverage-end 2026-12-01T00:00:00Z
```
