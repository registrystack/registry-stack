# Record responses and historical queries

Successful record HTTP responses now use the shared Registry Record v1 profile.
A single record uses:

```json
{
  "data": {
    "recordIdentifier": "00000000-0000-4000-8000-000000000001",
    "revisionIdentifier": "1",
    "domainData": {"label": "Example"}
  },
  "meta": {
    "registryIdentifier": "example-registry",
    "datasetIdentifier": "example-dataset",
    "entityTypeIdentifier": "example-record"
  }
}
```

Collections use `items`, `pageInfo.nextCursor`, and `meta`. Create, patch, and
tombstone keep the committed `snapshot` as a closed BReg-owned member of the
record in `data`. Revision detail and list responses use the same record and
collection envelopes; revision provenance remains outside `domainData`.
Snapshot queries add their BReg-owned `snapshot`, optional `validAt`, and
optional `count` collection members.

`application/json` never contains `@context`, `@id`, or `@type` profile terms.
`application/ld+json` adds the scalar context
`https://id.registrystack.org/contexts/registry-record/v1`. Successful profiled
responses carry the exact Registry Record profile Link and a relative
`describedby` schema link. Neither link is derived from Host or forwarded
headers. ETags and idempotency request identity include the negotiated response
representation.

Selecting and authorizing a compiled record operation authorizes publication of
its structural registry, primary-dataset, and entity-type identifiers. These
identifiers are not `$select` domain fields and are not gated by the optional
Registry Manifest catalogue publication profile. Concealed requests complete
before record I/O and disclose no profile, schema, context, or link hint.

Lookup still queries at most two rows. Exactly one row returns the shared single
record. Unknown or ungranted selectors, missing verified claims, zero rows, and
multiple rows return the same value-free `lookup.unresolved` problem. Malformed
requests remain `400`; source and audit failures remain `503`. Existing Registry
BReg problem identifiers are unchanged in this release.

Batch mutations, Action receipts, Proposals, and GeoJSON remain
named separate response shapes. Generated and caller-filtered OpenAPI documents
declare each route's exact shape and media-specific closed schema. Operations
that also serve GeoJSON use `x-registry-responseShapes` to assign every media
branch explicitly. Their stable singular `x-registry-responseProfile` marker
governs only the `application/json` and `application/ld+json` branches; the
GeoJSON branch remains the named BReg shape in the media map.

| Route family | Response shape |
| --- | --- |
| Get, lookup, create, patch, tombstone | `RegistryRecordSingleV1` |
| List, relationship traversal | `RegistryRecordCollectionV1` |
| Revision detail | `BRegRevisionRecordV1`, a shared record with closed BReg history metadata |
| Revision list | `BRegRevisionCollectionV1`, a shared collection of revision records |
| Snapshot query | `BRegSnapshotCollectionV1`, a shared collection with snapshot selection metadata |
| Batch mutation | `BRegAtomicBatchMutationResponseV1` |
| Actions and Proposals | Their operation-specific BReg response shapes |
| GeoJSON get and list | `BRegGeoJsonFeatureV1` and `BRegGeoJsonFeatureCollectionV1` |

## Corrections and historical queries

Base Registry Engine retains complete stored-record revisions. A successful mutation
returns a `snapshot` reference for its committed change. Every item in a
successful atomic batch shares that reference. Retrying the same idempotent
request returns the original response and reference.

| Input | Meaning |
| --- | --- |
| `snapshot` | Which committed registry state to reproduce. Omit it to capture the latest committed state once. |
| `validAt` | Optional effective date or UTC timestamp within that recorded state. Omit it to return recorded state without an effective-time filter. |
| `$skiptoken` | Expiring continuation of an already authorized query, including its exact snapshot. |

A snapshot reference is a bookmark, not a credential. Current access rules apply
on every request, including after a package or policy upgrade. Keep the reference
with the input revisions and the consumer's own decision/rule identity when a
later decision must be reproducible. Correcting registry facts does not rewrite
the consumer's earlier decision.

## Configure validity and access

An entity can declare a validity interval without requiring non-overlap:

```yaml
temporal:
  startField: valid-from
  endField: valid-to
```

The start is required. Both fields use the same `date` or `timestamp` type; the
end can be null. Intervals include the start and exclude the end. A non-null end
must be later than the start. To prohibit overlapping intervals for a subject,
add a `temporal-non-overlap` constraint with its `scopeFields` and the same two
boundary fields.

A date interval can name an inclusive last day instead of an exclusive end:

```yaml
temporal:
  startField: valid-from
  lastDayField: valid-through
```

`lastDayField` is a nullable `date` field. A record is in force from its start through the
whole of its last day, so "valid through 31 January" is stored as `2026-01-31`. Declare
exactly one of `endField` and `lastDayField`. `bregctl check` refuses both, or neither, with
`breg.temporal.end-conflict`, and refuses a `lastDayField` on a `timestamp` interval or a
non-date field with `breg.temporal.last-day-type`. A last day earlier than the start is
refused at write. A `temporal-non-overlap` constraint names `lastDayField` in place of the end.
Responses return the stored last day unchanged; BReg never serves a computed exclusive end.

### The registry's time zone

A registry that answers "today" declares an IANA time zone, spelled as in Casework calendars
and Scheduling:

```yaml
project:
  id: licences
  timezone: Asia/Colombo
```

It is required wherever BReg resolves "today":

- the `:current` read of a date-interval Record type, which BReg serves for every such type
  with a list grant;
- an Action requirement's `currentDate` comparison, both when the Action commits and when BReg
  reports whether the Action is available;
- `registry_context.evaluation_date()` in a derived field on a live read;
- the current period of a [statistics](STATISTICS.md) dataset.

`bregctl check` refuses a project that uses any of these without a time zone as
`breg.timezone.required`, naming the route, requirement or field that needs it, and refuses a
name that is not an IANA zone as `breg.timezone.unknown`. A project that uses none of them needs
no time zone. BReg takes today's date as `local_date(now, timezone)` from
`registry-platform-calendar`, the helper Casework calendars and Scheduling use, at every one of
these sites, so one registry has one today, and a registry in Colombo changes date at local
midnight, not at 05:30.

This is a breaking change for 1.0. Earlier releases took today's date in UTC and needed no time
zone, so a project with a date-interval Record type, a `currentDate` requirement, an
`evaluation_date()` field or a statistics dataset fails `bregctl check` after the upgrade until
it adds the `project.timezone` line. The refusal names the line to add. The cost to a builder is
that one line per project; `timezone: UTC` keeps the dates the project had before.

Grant the `snapshot` operation explicitly to an authenticated access profile.
Live `list` access and per-record `revisions` access do not grant snapshot access.
Configure readable, filterable and sortable fields, count permission, purpose
and row restrictions through the usual access profile.

## Read what is in force

A temporal Record type gains two live reads. `:current` returns the records in force now, and
`:as-of` the records in force at `asOf`. Both follow the `validAt` rule by interval type: a
date interval takes a calendar date such as `2026-06-05`, and a timestamp interval takes a UTC
RFC 3339 instant. Any other `asOf` value answers `400 query.invalid` naming `asOf`. On a date
interval, `:current` uses the registry's local date; on a timestamp interval it uses the
current instant. Every `:current` and `:as-of` response echoes the `asOf` it used in collection
`meta`, so a caller can record the date its answer was for.

To tell one record in force from several without paging, read with `$top=2` and no `$count`
or `$orderby`. BReg then returns at most two items, selected after access rules, and the item
count (0, 1 or 2) is the answer; `nextCursor` need not be followed. Coordinator's `breg.read-in-force/v1`
uses this read with an equality filter built from its structured subject.

A list read never turns a missing row boundary into an empty answer. A caller whose
row-boundary claim is missing receives `404 resource.not_found` on the plain list, `:current`
and `:as-of` reads, and a caller whose claim is an empty array receives
`401 authentication.refused`. Only a successful read with zero rows means that nothing
matched. The HTTP read-only and authentication suites hold this rule.

## Query a saved state

For the [household history fixture](acceptance/household-history/README.md), an
authorized consumer sends:

```http
GET /v1/records/memberships:snapshot?accessProfile=eligibility-consumer&snapshot=<saved-reference>&validAt=2026-06-05
```

After reporting a June 1 move from A to B, this returns B. After correcting the
move's effective date to June 15, a newly captured snapshot returns A for June 5.
The original saved reference still returns B, subject to current authorization
and retained history.

Responses contain `items` with `recordIdentifier`, `revisionIdentifier`, and
selected `domainData`, plus collection `meta`, `snapshot`,
`pageInfo.nextCursor`, optional `count`, and `validAt` when supplied.
Use the usual `$select`, `$filter`, `$orderby`, `$top` and `$count` options. Follow
a continuation using only `$skiptoken` and, if needed, `accessProfile`; do not
repeat or override its snapshot, effective time or query options.

Date intervals accept calendar dates such as `2026-06-05`. Timestamp intervals
require a UTC RFC3339 timestamp. Non-temporal entities reject `validAt`.
`recordedAsOf` is not supported. Live `:as-of` reads take `asOf` under the same per-type rule.

Historical queries use stored fields only. They remain usable on an entity
that also defines live derived fields, but cannot select, filter or order by
those derived fields or traverse live relationships. Revision selection precedes
row restrictions, filters and lifecycle checks, so an obsolete matching revision
cannot reappear after a later correction or tombstone.

## Correct related intervals atomically

Use the configured same-entity batch route to patch both affected intervals.
Each patch item carries the record's current `ifMatch` ETag. A batch can include
one optional top-level context:

```json
{
  "kind": "correction",
  "reasonCode": "effective-date-corrected",
  "sourceReferences": ["case-document:correction-001"]
}
```

Place this object in `changeContext` alongside `items`. A correction requires a
nonempty reason code. Context is shared across the batch, with no item-level
override. Bounds are 64 UTF-8 bytes for the code, 4 KiB for `reasonText`, and at
most 16 source references of 256 bytes each. Unknown members are rejected.

Only the compiled temporal exclusion constraints are deferred until the final
batch state. Both interval-edit orders work; final overlap or a stale ETag rolls
back the entire batch. A stale edit returns `412 precondition.failed`. Refetch
the records, review the change and submit a fresh request. Reusing an idempotency
key with different items or context conflicts.

Context is absent from snapshot responses and default revision output. A
`revisions` grant can explicitly allow `provenanceFields` from `kind`,
`reasonCode`, `reasonText` and `sourceReferences`. Shared context is omitted
unless every affected revision is currently visible to that caller.

## Coverage and operating limits

Initial activation installs an empty history baseline. A saved
reference never falls back to current data. Authorized queries return
`503 source.unavailable` when required history, compatible field metadata or a
database execution budget is unavailable. Unauthorized callers retain ordinary
resource concealment. Historical database statements have a two-second budget;
existing HTTP, projection, page, cell and response bounds also apply. One query
can resolve at most 64 originating schema descriptors.

Descriptors retain field interpretation, not old access policy or executable
code. Supported policy-only and unrelated additive upgrades preserve queries
over compatible requested fields. A newly required or incompatible historical
field makes the query unavailable instead of inventing today's default.

Reviewed bounded data migrations append internal `migration` revisions and
commit membership. They do not fabricate user patches or business events.
A transactional data step is a direct reviewed `UPDATE` on one retained entity
table with explicit affected-row bounds. The complete table must fit that bound,
up to 1,000 rows, so before/after capture remains bounded within the transaction.
A chunked backfill is a direct reviewed `UPDATE` of one retained entity per
chunk of at most 1,000 record identifiers; each chunk commits on its own with
one migration commit for the rows it changed, so a resumed backfill never
journals a committed chunk twice and the table size is bounded only by the
step's `maxTotalRows`.
Unsupported data-changing migrations refuse before changing records. Runtime
credentials do not acquire journal UPDATE or DELETE authority.

## Erase retained history

The migration authority can erase one record's retained revisions through a
specified revision number. This is irreversible maintenance, not a runtime API
permission. It does not remove the current record. Apply the institution's
live-data removal policy separately when required.

Prepare an absolute, owner-only JSON file, using permissions `0600` on Unix:

```json
{
  "recordType": "membership-record",
  "recordId": "00000000-0000-4000-8000-000000000001",
  "eraseThroughRevision": 2,
  "operatorReference": "approved-maintenance-001",
  "reason": "approved-retention-request"
}
```

Use the actual entity ID and record ID. Keep this file private, including after
the operation. The command accepts paths so record identifiers and reasons do
not need to appear in process arguments:

```bash
bregctl history erase \
  --runtime-config /absolute/path/runtime.yaml \
  --request-file /absolute/path/erasure.json \
  --acknowledge-irreversible
```

The command refuses without `--acknowledge-irreversible`, before it reads any
file or opens any connection, because erasure cannot be undone and no command
restores the erased revisions.

One transaction erases at most 10,000 retained revisions, scrubs affected shared
correction context and retained outbox payloads, and replaces affected cached
idempotency responses with refusal tombstones. Retrying those mutation keys
cannot replay their old bodies or execute them again. Required schema
descriptors remain retained. The result and keyed audit contain counts, not the
record values or reason text.

Coverage is conservative: snapshots at or after the earliest erased commit
become unavailable, including later snapshots. Erasing baseline data makes all
snapshot coverage unavailable. Earlier complete snapshots may remain usable;
the command never silently re-baselines the registry, and `history rebaseline`
below is the separate command that does it explicitly. Live writes and
separately authorized maintenance remain available.

A successor package remains applicable after an erasure of revisions committed
after the coverage baseline: the apply interlock admits a ready commit head
whose unavailable-after position matches an erasure coverage record that a
standalone erasure committed with its erasure. Erasing baseline data, a
lifecycle erasure, and any gap the database does not record as an erasure
still refuse successors until `history rebaseline` restores coverage.

Operators remain responsible for current records, saved exports, copies already
delivered to external consumers, and backup expiry. Change-request proposals and
application receipts have their own retention policy and maintenance commands;
erasing record history does not erase those separate workflow records. Neither
a hash nor an opaque identifier is automatically anonymous, and a saved
bookmark cannot restore erased bytes.

The executable acceptance journey is
`products/breg/scripts/test-historical-workflow.sh`. It uses signed
packages, certificate-verified PostgreSQL, real authenticated HTTP requests,
restart, an additive upgrade and access revocation. Its temporary credentials
and data are disposable; it is not a production deployment script.

## Restore snapshot coverage

Nothing in the write path widens coverage again, so snapshot reads of current
state stay unavailable after an erasure until the migration authority
re-establishes a covered position. That is the same authority and the same
bounded interlock as the erasure, in its own audited command.

Prepare an absolute, owner-only JSON file carrying the operator reference alone,
using permissions `0600` on Unix:

```json
{
  "operatorReference": "approved-maintenance-002"
}
```

```bash
bregctl history rebaseline \
  --runtime-config /absolute/path/runtime.yaml \
  --request-file /absolute/path/rebaseline.json
```

One transaction proves the retained journal head of every live row still
reproduces that row, installs one baseline commit at the head, and moves the
coverage baseline to it. It resurrects nothing: snapshot references before the
new baseline remain unavailable, because the bytes they named are gone. The
command refuses when coverage is already complete, when the registry is not
ready, when a retained journal head is not indexed by a commit, and when a live
row has no retained journal head that reproduces it. Verification pages through
the live rows to bound memory; there is no total live-row cap. The transaction
holds every Record type table in ACCESS EXCLUSIVE mode, so reads and writes wait
until verification commits. The result and keyed audit contain counts and positions, not record values; the
operator reference is recorded as a keyed hash.
