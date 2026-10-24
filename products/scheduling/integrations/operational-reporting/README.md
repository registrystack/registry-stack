# Operational appointment export

`operational_export.py` reads Scheduling's operational appointment list
(`GET /v1/operational/appointments`, `timeBasis: occupied`) through the public
`registry_client.scheduling` facade and writes the rows as JSON or CSV. It is
an authorized read adapter: it has no database access, no mutation authority
and no queue, dashboard or warehouse. It computes no measures. Downstream
tools build the daily work list and any counts from the rows, using the
definitions below.

## Run

Use Python 3.13 with the unified Registry Stack Python package installed for
the deployment. Inject the bearer token through the environment, not a
command argument:

```sh
REGISTRY_SCHEDULING_TOKEN=... python3 operational_export.py \
  --base-url https://scheduling.example.gov/ \
  --service room-reservation \
  --location community-hall \
  --start 2026-03-28T23:00:00Z \
  --end 2026-03-29T22:00:00Z \
  --profile operations-report \
  --format csv \
  --output work-list.csv
```

The script requests at most 50 rows per page, follows at most 10 pages and
accepts at most 500 rows. It refuses a repeated cursor, an incomplete page or a
page larger than requested, and it writes nothing until every page has been
read. `--output` creates a new owner-only (`0600`) file and refuses to
overwrite one. The selected runtime profile must authorize the requested
service and location, and it decides which fields are projected; pagination
cannot widen that scope. JSON output keeps the query and the collection start
and end times; CSV holds one row per logical booking, with allocations and
external references joined by `;`.

Run the tests with `python3 -m unittest -v test_operational_export`.

## Definitions

None of these is counted as another.

- **Appointment**: one logical booking. It is one row, however many
  allocations or occurrences it has. `state` is `confirmed` or `cancelled`;
  cancelled rows stay visible and are never counted as confirmed.
- **Occurrence**: a repeat of a booking in the source system, correlated
  through `externalReferences`. It is reported separately from the booking.
- **Offered capacity units**: the quantity of a resource the institution makes
  available over time. Scheduling's operational list does not return it, and
  free availability is already net of claims, so it is not a denominator.
  Take it from the institution's authoritative schedule.
- **Committed units**: the `units` of each allocation over its occupied
  interval. A two-unit allocation occupying 30 minutes is 3,600 unit-seconds.
  Primary and additional bundle lines each count their own resource, units and
  interval.
- **Utilization**: committed unit-seconds divided by offered unit-seconds, for
  one resource over one period, with days split at civil-day boundaries in the
  reporting time zone (a daylight saving day keeps its real length). Without an
  authoritative offered figure the ratio is unavailable; the committed
  numerator stays valid on its own. Do not use a room's maximum occupants as a
  denominator: that counts people, not resource time.
- **Recipients and attendees**: `party.recipients` and `party.attendees` are
  planned party counts. They are people, never stock, and never capacity units.
- **Attendance observation**: when the profile projects `attendance`, the
  appointment's current `arrived`, `completed` or `no-show` observation.
  Count it per booking. It is not a number of people who arrived, and the
  planned `attendees` value never substitutes for it. When the field is not
  projected, attendance is unknown, not zero.
- **Request-only, held and confirmed**: Scheduling lists only confirmed and
  cancelled appointments. Requests and temporary holds live in the source
  workflow, so report them from a separately authorized source and keep them
  apart from confirmed bookings.

## As-of rule, late corrections and limits

- The export is Scheduling's current retained state read page by page between
  `startedAt` and `completedAt`. It is not an atomic snapshot, and a run over
  a past period shows current state for appointments overlapping it, not the
  state at the period end. Name the reporting period and the collection time
  when you publish a figure.
- A correction committed after its page was read is missing from that export.
  Re-run to pick it up; keep the earlier file if audit policy needs the
  supersession trail. If one appointment appears at several revisions,
  downstream tools use the highest `revision`, and the highest attendance
  `revision` within it, so a correction from `arrived` to `completed` counts
  once. A reschedule starts a new visit and does not inherit the earlier
  visit's attendance.
- Scheduling retention can make older appointments, allocations or labels
  unavailable. Treat a missing historical row, allocation, denominator,
  request, hold or attendance value as unknown, never as zero.
- Times are UTC instants. Convert to the institution's IANA time zone only when
  grouping by local date.
- Handling: project only the fields the work list needs, keep exports only as
  long as the operational purpose requires, on an access-controlled encrypted
  filesystem, and avoid shared temporary directories, backups, logs, email and
  analytics tools unless their disclosure and retention are approved.
  Examples and tests use synthetic identifiers only.
