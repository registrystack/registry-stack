# Breaking HTTP response change: Registry Record profile

Successful record HTTP responses now use the shared Registry Record v1 profile.
The previous single-record shape `{id, revision, data}` and mutation shape
`{id, revision, snapshot, data}` are no longer served. A single record is now:

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

Batch mutations, change-request actions, immediate actions, and GeoJSON remain
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
| Change-request and immediate actions | Their operation-specific BReg response shapes |
| GeoJSON get and list | `BRegGeoJsonFeatureV1` and `BRegGeoJsonFeatureCollectionV1` |

# Breaking authoring change: plural catalogue resources

`manifestProjection.dataset` and `manifestProjection.dataService` were removed.
Projects now declare `registry.canonicalBaseIri`, publisher `id`, one
`publicService`, plural `datasets`, plural `dataServices` with nonempty
`servesDatasets`, optional `distributions`, and one `primaryDataset` on every
entity. Run `bregctl project migrate PROJECT` to review the exact
rewrite, then repeat it with `--write` only after approving the proposed
`<registry-id>-authority` and `<registry-id>-service` identifiers. The migration
preserves an explicit legacy dataset id and otherwise preserves the old
effective fallback to `registry.id`.

# Breaking authoring change: entity hooks

`entities[].events` and `extendEntities[].events` were replaced by
`entities[].hooks` and `extendEntities[].hooks`, which declare the shared
Registry Stack hook shape from `registry-platform-hooks`. A hook adds a
required `phase` and replaces the `webhook` member with a `handler` union
tagged by `kind`. The old member is refused by name at compile time with
`entity.events.removed`, so a project that still authors it fails to compile
rather than silently losing its events.

Before:

```yaml
entities:
  - id: case
    events:
      - id: case-approved-v1
        trigger: patched
        projection: [status]
        webhook:
          destinationId: eligibility-service
```

After:

```yaml
entities:
  - id: case
    hooks:
      - id: case-approved-v1
        phase: after
        trigger: patched
        projection: [status]
        handler:
          kind: url
          destinationId: eligibility-service
```

The rewrite is mechanical: rename the member to `hooks`, add `phase: after` to
every hook, and replace `webhook: {destinationId: X}` with
`handler: {kind: url, destinationId: X}`. `id`, `trigger`, `projection`, and
`when` keep their spelling and meaning. An entity hook runs after the
triggering transaction commits, so the compiler refuses `phase: before`. The
local `rhai` and `wasm` handler kinds the shared declaration also offers run in
the post-commit worker and name a reviewed script or module path instead of a
destination.

Runtime `eventDestinations` keeps its name and its keys, and retained delivery
state keyed on the compiled delivery id survives a package upgrade. The stored
and delivered body is the shared hook envelope rather than the bare
CloudEvents request, and `X-Registry-Signature` covers exactly the envelope
bytes a receiver is sent. A receiver built against the earlier request shape
must verify the new body, and the outbox must be drained before upgrading.
Diagnostic codes still read `event.*`, because they name the operator-facing
concept rather than the authored member.

Because a module's lock digest covers its parsed document, renaming the member
changes every locked digest. Run `bregctl project lock PROJECT` after the
rewrite.

`caseworkctl source add` writes the new shape. A registry connected by an
earlier `caseworkctl` carries the old member and must be rewritten by hand or
reconnected.

Projects maintained outside this repository need the same rewrite. The adopter
demo in [`registrystack/solmara-lab`](https://github.com/registrystack/solmara-lab)
authors the old member and is not updated by this change.

# Breaking authoring change: changeRequest review moves to an external authority

`changeRequest.review.mode` and `changeRequest.review.stages` were removed.
Review authority for a change request is now delegated to an external review
producer through the runtime's `reviewAuthorities` block: author
`review.authority` naming that authority id and `review.policyId` naming the
policy it evaluates. `application` was renamed to `onApproved`;
`application.mode` is now `onApproved.mode`, still `manual` or `automatic`.

Before:

```yaml
changeRequest:
  review:
    stages:
      - id: review
        approvals: 1
        excludeSubmitter: true
  application:
    mode: manual
```

After:

```yaml
changeRequest:
  review:
    authority: casework
    policyId: lot-number-correction
  onApproved:
    mode: manual
```

The `approve_request`, `reject_request`, and `request_revision` profile
operations were removed; a profile now needs only `get` and `apply_request` to
apply a reviewed request. The per-stage `reviewStages` permission targets were
removed from apply profiles in favor of a top-level `applyTargets` list, and
both the submitter and application profiles gained `readableRequestFields` for
the fields the external reviewer needs to read, such as `reason` and
`review_state`.

Add a `reviewAuthorities` entry in runtime configuration for every authority id
a project's `review.authority` names. Each entry requires `endpoint`,
`profile`, `producerId`, and `recoveryDays`, authenticates with either
`privateKeyJwt` or an opaque `tokenRef`, and a completion-notified authority
also sets `completionTokenRef` and `completionRecipient`. `bregctl dev` and
`source add --apply` write this block and the paired Casework producer binding
automatically; see [Review BReg changes in Casework](../../docs/site/src/content/docs/tutorials/review-breg-changes-in-casework.mdx)
for the full authoring and binding shape.

`caseworkctl source add` writes the new shape. A registry still authoring
`review.stages` or `application`, or a profile still granting the three
retired operations, must be rewritten by hand: replace the review stage list
with an authority binding, rename `application` to `onApproved`, remove the
retired operations, and add a `reviewAuthorities` entry for the named
authority.

# Corrections and historical queries

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

Responses contain `items` with `recordIdentifier`, `revisionIdentifier`, and
selected `domainData`, plus collection `meta`, `snapshot`,
`pageInfo.nextCursor`, optional `count`, and `validAt` when supplied.
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
whose unavailable-after position matches a committed terminal erasure audit
record carrying no lifecycle reference. Erasing baseline data, a lifecycle
erasure, a pruned erasure record, and any gap the journal does not record as an
erasure still refuse successors until `history rebaseline` restores coverage.

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
row has no retained journal head that reproduces it. The 1,000-row live bound
that applies to establishing an existing-data baseline applies here too. The
result and keyed audit contain counts and positions, not record values; the
operator reference is recorded as a keyed hash.
