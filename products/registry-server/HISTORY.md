# Corrections and historical queries

Registry Server retains complete stored-record revisions. A successful mutation
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
boundary fields. The deprecated `temporal.scopeFields` spelling is only a
transition aid and must match an explicit non-overlap constraint.

Grant the `snapshot` operation explicitly to an authenticated access profile.
Live `list` access and per-record `revisions` access do not grant snapshot access.
Configure readable, filterable and sortable fields, count permission, purpose
and row restrictions through the usual access profile.

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

Responses contain `items` with `id`, `revision` and selected `data`, plus
`snapshot`, `pageInfo.nextCursor`, optional `count`, and `validAt` when supplied.
Use the usual `$select`, `$filter`, `$orderby`, `$top` and `$count` options. Follow
a continuation using only `$skiptoken` and, if needed, `accessProfile`; do not
repeat or override its snapshot, effective time or query options.

Date intervals accept calendar dates such as `2026-06-05`. Timestamp intervals
require a UTC RFC3339 timestamp. Non-temporal entities reject `validAt`.
`recordedAsOf` is not supported, and live-query `asOf` keeps its existing meaning.

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

History starts at an exact empty or verified existing-data baseline. A saved
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
The supported data step is a direct reviewed `UPDATE` on one retained entity
table with explicit affected-row bounds. The complete table must fit that bound,
up to 1,000 rows, so before/after capture remains bounded within the transaction.
Establishing an existing-data baseline also has a 1,000-row limit.
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
  "entityId": "membership-record",
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
registry-serverctl history erase \
  --runtime-config /absolute/path/runtime.yaml \
  --request-file /absolute/path/erasure.json
```

One transaction erases at most 10,000 retained revisions, scrubs affected shared
correction context and retained outbox payloads, and replaces affected cached
idempotency responses with refusal tombstones. Retrying those mutation keys
cannot replay their old bodies or execute them again. Required schema
descriptors remain retained. The result and keyed audit contain counts, not the
record values or reason text.

Coverage is conservative: snapshots at or after the earliest erased commit
become unavailable, including later snapshots. Erasing baseline data makes all
snapshot coverage unavailable. Earlier complete snapshots may remain usable;
the command never silently re-baselines the registry. Live writes and separately
authorized maintenance remain available.

Operators remain responsible for current records, saved exports, copies already
delivered to external consumers, and backup expiry. Change-request proposals and
application receipts have their own retention policy and maintenance commands;
erasing record history does not erase those separate workflow records. Neither
a hash nor an opaque identifier is automatically anonymous, and a saved
bookmark cannot restore erased bytes.

The executable acceptance journey is
`products/registry-server/scripts/test-historical-workflow.sh`. It uses signed
packages, certificate-verified PostgreSQL, real authenticated HTTP requests,
restart, an additive upgrade and access revocation. Its temporary credentials
and data are disposable; it is not a production deployment script.
