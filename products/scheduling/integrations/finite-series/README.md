# Finite reservation series

This maintained recipe lets a source application reserve a bounded weekly
series through Registry Scheduling's public Python client. The source owns the
recurrence rule, series revisions, occurrence identities, and recovery
journal. Registry Scheduling remains the only capacity authority. Every
create, reschedule, and cancellation goes through its ordinary public API and
capacity transaction.

The recipe implements explicit partial results. It can therefore confirm some
occurrences and refuse others, but its durable result always names every
occurrence. It never presents the series as wholly booked when a subset was
committed.

## Why the source owns the series

An institution's existing durable source application is the preferred owner
when it already has transactions, locking, and recovery operations. This
SQLite journal is a compact reference for an adopter that needs a complete
single-node implementation or a concrete schema to port.

A Base Registry Engine project could store the source's series records, but it
would add registry schema, action, and deployment work while still requiring
the same outbound Scheduling command journal. Registry Coordinator protects
prepared effects and unknown outcomes well, but its maintained workflow model
does not provide dynamic recurrence fan-out. Using it here would add a runtime
without removing the source-side expansion and per-occurrence state. The
SQLite recipe is therefore the smallest complete maintained composition for
this bounded use case. It adds no recurrence engine or second capacity ledger
to Scheduling.

## Bounds and civil-time semantics

A definition contains:

- a UUID `seriesId`;
- an IANA `timezone` and offset-free `localStart`;
- `intervalWeeks`, from 1 through 52;
- exactly one end rule: `count`, or an inclusive local `throughDate`;
- `ambiguousTime`, set to `reject`, `earlier`, or `later`;
- zero or more `exclusionDates`, each of which must name a generated local
  candidate date.

`count` counts weekly candidates before exclusions. An excluded date does not
extend the term. Each candidate receives
`UUIDv5(seriesId, "occurrence:<ordinal>")`, so its identity survives retries,
exclusion, and later time changes. A nonexistent wall time is always refused.
An ambiguous wall time is refused unless the definition explicitly selects
the earlier or later actual instant.

The default maximum is 64 candidates over at most 366 days. Sixty-four covers
a weekly term longer than one year, while the separate horizon prevents a
sparse rule from turning that count into multi-year work. Aggregate capacity
work is limited to 256 allocation lines. The recipe calculates that value from
the actual admission template as one primary allocation plus the length of
`additionalAllocations`, multiplied by non-excluded occurrences. The caller
cannot supply a smaller count. These bounds keep one source operation and its
recovery review manageable; an adopter can choose lower `Limits`.

The full admission template is copied for each occurrence. Only `start` and
the recipe's correlation references are added or replaced. In particular,
`durationMinutes`, `resource`, party data, and future
`additionalAllocations` bundle constraints pass through without being
reconstructed or dropped. Registry Scheduling still validates the complete
admission under the active offering, task grant, and capacity ledger.

On reschedule, the recipe again preserves the complete interval, resource,
party counts, and bundle request but omits `externalReferences`,
`partyReferences`, and `manager`, as Scheduling's public contract requires.
Scheduling retains the appointment's immutable create-time references, party
references, and manager. The journal likewise keeps its original correlated
admission while updating only the successful current start.

## Durable partial results and recovery

`SeriesJournal` uses a source-owned SQLite database with WAL, foreign keys,
full synchronous commits, and `BEGIN IMMEDIATE` revision changes. Each command
stores its exact credential-profile label, idempotency key, canonical request,
request hash, method kind, attempts, and outcome before a summary is returned.
Bearer tokens are never stored.

Before network I/O, a prepared command is committed as `dispatched`. A
process-wide and operating-system file lock prevents another process from
immediately reconciling an in-flight HTTP call. The SQLite lease generation
fences stale completions after a crash. A restart handles a dispatched create
through `appointment_receipt` with the exact original key and body. A missing
or expired receipt remains `unresolved`; it never licenses a new key.
Reschedule and cancel have no separate receipt observer, so recovery sends only
the identical stored mutation under its original key and current authority.
An expired key or unusable response remains unresolved. The recipe does not
infer mutation success from a current appointment read.

The credential-profile label identifies the operator-configured credential
source that may resume the journal. It is not a verified token identity.
Registry Scheduling verifies the bearer token and exact actor on every call.
A different local profile cannot take over prepared work, and a mismatch while
recovering an already dispatched command leaves that outcome unresolved with
its original profile, key, and request intact.

SQLite gives complete durability and concurrency for one mounted journal, but
it is not an active-active database. An application that already has a durable
source store can port the same invariants: compare-and-swap series revisions,
immutable prepared commands, commit-before-dispatch, fenced leases, exact-key
recovery, and per-occurrence outcomes.

Before dispatch or receipt recovery, the processor checks the stored request
against its prepared hash. A mismatch raises an explicit integrity error
without making a client call. This detects inconsistent local journal data;
it does not authenticate a database against someone who can rewrite both
the command and its hash.

## Correlation and disclosure

Each admission retains two opaque references:

```text
source-application / reservation-series / <series UUID>
source-application / reservation-occurrence / <occurrence UUID>
```

They contain no personal data and grant no authority. Supported owner and
operational appointment reads can select or return these references under
their own authorization. An explicitly configured observer projection may
include allowed references under Scheduling's hook disclosure policy.

The default iCalendar exporter deliberately strips external references. This
recipe therefore makes no default calendar-correlation claim. A calendar feed
that needs series correlation requires a separate, explicit disclosure profile
and design.

## Use the public Python facade

Install the unified Registry Stack Python client for the deployment, then use
its public Scheduling namespace:

```python
from registry_client import scheduling

from finite_series import SeriesJournal, SeriesProcessor

client = scheduling.SchedulingClient("https://scheduling.example.gov/")
journal = SeriesJournal("reservation-series.sqlite3")

journal.prepare_series(
    {
        "seriesId": "c4207bf4-e7c3-4de4-bb14-36797183b480",
        "timezone": "Europe/Zurich",
        "localStart": "2026-10-20T18:00:00",
        "intervalWeeks": 1,
        "count": 8,
        "ambiguousTime": "reject",
        "exclusionDates": ["2026-11-03"],
    },
    {
        "offering": "meeting-room",
        "start": "2026-10-20T16:00:00Z",
        "durationMinutes": 120,
        "resource": "room-a",
        "policyRevision": 7,
        "capabilities": [],
        "prerequisites": [],
        "externalReferences": [],
    },
    owner="room-reservations-production",
)

result = SeriesProcessor(
    journal,
    client,
    credential_profile="room-reservations-production",
).process(series_id="c4207bf4-e7c3-4de4-bb14-36797183b480", token=current_token)
```

The application should show `result["occurrences"]` rather than derive a
single success flag. Outcomes are `succeeded`, `refused`, `excluded`,
`unresolved`, or `pending` before dispatch.

## Explicit edits

`prepare_edit` requires the current `expected_revision`. It accepts scope
`one`, `this-and-future`, or `all`, and the caller must provide one explicit
change for every non-past occurrence selected by that scope. A reschedule
names its new local wall time; a cancellation may carry a reason. The journal
records the complete diff before preparing commands.

An occurrence with a prepared, dispatched, or unresolved command cannot accept
another edit. Resolve that command before preparing a replacement so its
unknown outcome cannot be hidden by a newer operation.

Every mutation uses the occurrence's current appointment identifier and
observed Scheduling revision. A stale series revision fails before command
preparation. A Scheduling revision or capacity conflict is retained as that
occurrence's refusal. A failed reschedule leaves the old confirmed appointment
and its history intact. Past occurrences are never edited or erased.

## Verify the recipe

Run the source and recovery tests without building Rust crates:

```sh
uv run --locked --directory products/scheduling/integrations/finite-series \
  python -m unittest -v test_finite_series.py
```

These tests exercise the authored recurrence and journal behavior with a
contract-shaped client double. They do not establish native client packaging,
HTTP behavior, PostgreSQL locking, task-grant authorization, or runtime
capacity enforcement. Those require the separate public-client native journey
against a disposable Scheduling database.

`native_journey.py` is that executable journey. It imports
`registry_client.scheduling`, reads its token only from
`REGISTRY_SCHEDULING_TOKEN`, and accepts the runtime URL, source state
directory, future local start, policy revision, offering, and resource as
arguments. It proves three successful occurrences, a real capacity conflict,
a synthetic lost response reconciled after reopening the journal, one and
future edits, whole-series cancellation, scoped correlation, and retained
Scheduling history. Its state directory must be empty and disposable for each
run; the script retains its SQLite evidence for inspection.

The native journey additionally needs the unified `registry-stack-client`
wheel built for the same deployment version, Python interpreter, and platform.
The recipe's `uv sync` installs only its own dependencies. Set
`REGISTRY_CLIENT_WHEEL` to the absolute path of the matching built or released
wheel; do not substitute an unpublished package version from a package index.
`uv run --with` installs that wheel in the runner environment without changing
the recipe's lock file:

```sh
uv run --locked --directory products/scheduling/integrations/finite-series \
  --with "${REGISTRY_CLIENT_WHEEL:?set the absolute path to the matching unified wheel}" \
  python native_journey.py --help
```

Run against a disposable fixture with the `meeting-room` offering and `room-a`
resource (or supply their argument overrides), after setting a future
`SERIES_LOCAL_START` in Europe/Zurich civil time and an empty state directory:

```sh
uv run --locked --directory products/scheduling/integrations/finite-series \
  --with "${REGISTRY_CLIENT_WHEEL:?set the absolute path to the matching unified wheel}" \
  python native_journey.py \
  --base-url "${SCHEDULING_BASE_URL:?set the fixture runtime URL}" \
  --policy-revision "${SCHEDULING_POLICY_REVISION:?set the current fixture policy revision}" \
  --local-start "${SERIES_LOCAL_START:?set a future local timestamp without an offset}" \
  --state-directory "${SERIES_STATE_DIRECTORY:?set an empty disposable directory}"
```
