# Domain occurrences

A record type may declare that each of its records states one domain
occurrence: something that happened to one or more subjects, when it happened,
when it took effect, what it rests on, and whether it corrects an earlier
statement. The declaration is a descriptor over fields the record type already
stores. It adds no storage, no route, no grant and no behavior. It lets a
compiler, an explanation, runtime metadata and a client read the same record
shape in one generic way.

A domain occurrence is not a technical event. `bregctl explain events` and
[the event and webhook design](EVENTS-AND-WEBHOOKS.md) describe delivery
notifications about changes; an occurrence is registry data an author models
as a record. The descriptor has no `event` member and the two never read each
other.

## Authoring

`occurrence` is an optional member of a record type, next to `consentRecord`.
Every `field` value is the id of a stored field of the same record type (not a
derived field and not an `apiName`).

```yaml
recordTypes:
- id: entry-registration
  mutationMode: create-only
  fields:
  - {id: entry, type: reference, target: entry, required: true}
  - {id: source-reference, type: string, required: true}
  - {id: effective-at, type: timestamp, required: true}
  - {id: occurred-on, type: date, required: false}
  - {id: summary, type: text, required: false}
  - {id: corrects, type: reference, target: entry-registration, required: false}
  constraints:
  - {id: one-per-source, type: unique, fields: [source-reference]}
  occurrence:
    label: Entry registered
    subjects:
    - {role: entry, field: entry, label: Entry, target: entry}
    summary: summary
    occurredAt: {at: occurred-on}
    effective: {at: effective-at}
    sources:
    - {role: source, field: source-reference, label: Source,
       external: {namespace: "urn:example:synthetic:sources"}}
    correction: {field: corrects, relation: corrects}
    sourceEventId:
      field: source-reference
      namespace: "urn:example:synthetic:sources"
      duplicates: reject
      constraint: one-per-source
```

| Member | Required | Meaning |
|---|---|---|
| `label` | no | Display text for the occurrence. Defaults to the record type display label, then its id. |
| `subjects` | yes, 1 to 16 | What the occurrence is about. Each item maps a `role` to a field. |
| `summary` | no | A `string` or `text` field holding a human description. The descriptor never generates prose. |
| `occurredAt` | no | When it happened: a point or an interval. |
| `effective` | no | When it took effect: a point or a span, kept separate from `occurredAt`. |
| `sources` | no, 0 to 16 | References to what the statement rests on. Same item shape as subjects. |
| `correction` | no | A reference to an earlier occurrence record this one corrects or supersedes. |
| `sourceEventId` | no | An identifier assigned by the originating system, with its namespace and a duplicate policy. |

Subjects and sources share one role namespace. A role starts with a lowercase
letter, contains only lowercase letters, digits, hyphens and underscores, is at
most 64 characters, and is unique across both lists. A role item maps either:

- a `reference` field (a native relationship; optional `target` asserts the
  referenced record type), or
- a `string` or `uuid` field with `external: {namespace: <absolute URI>}`, an
  opaque identifier owned by another system. The registry never resolves it,
  and an external item has no native target.

Recording a source reference is not verification. The registry does not check
that the source exists or supports the statement.

### Time

`occurredAt` and `effective` are either a point or an interval, over `date` or
`timestamp` fields (both bounds of an interval share one type).

| Shape | Members |
|---|---|
| point | `at` |
| interval | `start`, `end`, and for `occurredAt` a `meaning` |

`meaning` is required for an `occurredAt` interval and refused on a point:

- `span`: it lasted from `start` to `end` (end exclusive, as in
  [history](HISTORY.md)). `end` is optional (still open).
- `within`: one occurrence happened at an unknown point between `start` and
  `end`. `end` is required. This is the unknown-precision form, for example
  "agreed between two dates, exact day unknown".

`effective` is span-only: it has no `meaning` member, and its `end` is optional
for an open-ended effect.

These are authored as flat members, with no tag. Where the explanation, the
runtime metadata and the client view serve a time, a `type` member names the
shape (`point` or `interval`) beside that shape's members.

Rules that follow from this:

- A null value in a mapped field means declared but unknown. The compiler does
  not require mapped fields to be `required: true`. An optional field that is
  absent is served as an explicit `null` in record Get and in revision
  `domainData`.
- Date fields stay dates. No midnight instant is ever derived from them.
- The descriptor adds no ordering rule. To require `start` before `end`, or an
  effect not before the occurrence, author a `compare` constraint. A null side
  passes the constraint.
- There is no `recordedAt` member (the parser refuses it with
  `config.unknown-key`). Recorded time is always the creation revision of the
  record, never authored and never a clock fallback; see "Recorded time" below.

### Corrections

`correction.field` is a `reference` to a record type that declares an
occurrence (the same record type is allowed). `relation` is:

- `corrects`: the new record amends an error in the earlier statement.
- `supersedes`: the new record replaces the earlier statement as the current
  interpretation.

Neither changes the earlier record. Which record is current, and who may
record a correction, belongs to the author's Actions, guards and
documentation. A guard that checks the prior target is an ordinary Action
guard; the descriptor does not add one.

### Source event identifier

`sourceEventId` names a field (`string` or `uuid`) that carries the identifier
the originating system assigned. Declare exactly one of `namespace` (an
absolute URI of at most 512 bytes) or `namespaceField` (a `string` or
`vocabulary-code` field). `duplicates` is:

- `reject`: a second record with the same identifier must be refused. The
  descriptor creates no constraint; `constraint` must name an authored `unique`
  constraint over exactly the identifier field (and the namespace field when
  one is declared), with no `when` condition. A violation returns
  `409 mutation.conflict`.
- `allow`: duplicates are permitted; `constraint` is forbidden.

### Validation

All diagnostics are errors. Paths use `recordTypes[id=<record>].occurrence`
as the base, and `[role=<role>]` for role items (the index form `[<n>]` when
the role itself is invalid or duplicated).

| Code | Trigger |
|---|---|
| `breg.occurrence.subjects-empty` | `subjects` is empty |
| `breg.occurrence.roles-too-many` | more than 16 subjects or sources |
| `breg.occurrence.role-invalid` | role is not a lowercase identifier |
| `breg.occurrence.role-duplicate` | a role repeated across subjects and sources |
| `breg.occurrence.field-unknown` | a mapped field is not a stored field of the record type |
| `breg.occurrence.field-type` | field type outside the allowed set below |
| `breg.occurrence.field-reused` | one field mapped by two of subjects, sources, correction and summary |
| `breg.occurrence.reference-target` | `target` differs from the field's reference target |
| `breg.occurrence.external-target` | `target` on an `external` item |
| `breg.occurrence.external-namespace` | namespace is not an absolute URI of at most 512 bytes |
| `breg.occurrence.time-shape` | point and interval members mixed, `end` without `start`, missing or misplaced `meaning`, `within` without `end` |
| `breg.occurrence.interval-type-mismatch` | interval bounds of different types |
| `breg.occurrence.correction-target` | the correction target declares no occurrence |
| `breg.occurrence.source-event-namespace` | both or neither of `namespace` and `namespaceField` |
| `breg.occurrence.source-event-constraint` | policy and constraint disagree, or the constraint is not a matching unique constraint |
| `breg.display-text.invalid` | unsafe characters in a label |
| `config.unknown-key` | an unknown member, for example `recordedAt`, `event` or `meaning` under `effective` |
| `config.unknown-variant` | an unknown `meaning`, `relation` or `duplicates` value |
| `config.missing-key` | `duplicates` missing from `sourceEventId` |

Allowed field types:

| Member | Allowed `type` |
|---|---|
| subject or source without `external` | `reference` |
| subject or source with `external` | `string`, `uuid` |
| `summary` | `string`, `text` |
| `occurredAt`, `effective` | `date`, `timestamp` |
| `correction.field` | `reference` |
| `sourceEventId.field` | `string`, `uuid` |
| `sourceEventId.namespaceField` | `string`, `vocabulary-code` |

Not validated by design: requiredness of mapped fields, interval order,
recorded-versus-effective order, who may correct, and whether the record type
is create-only.

## What the descriptor does not do

The descriptor grants nothing: no read, write, resolution, schedule, retention
exemption or immutability. Reading, writing and executing remain governed by
access profiles, Actions and guards. It is excluded from
`record_definition_revision`, Action `definition_revision` and Proposal
fingerprints, so adding, changing or removing it does not change any execution
identity. It is included in the effective model, so it changes the registry
revision and the package checksum. Package comparison treats it like display
text: no change code and no review gate.

It does not touch storage. The generated DDL for a project is identical with
and without descriptors.

It is separate from the Manifest projection concepts on fields (`concepts`,
`relationshipRole`), which annotate vocabulary for publication, and from
`temporal` and `validTimeRole`, which drive history validity and valid-at
queries. Authors may use all of them on the same fields; none reads the others.

## Explanation

`bregctl explain model` reports the declared descriptor in
`recordTypes[].occurrence` (`null` when undeclared) and the display grouping in
`recordTypes[].grouping` and `actions[].grouping`. The explanation keeps
explicit nulls for undeclared members, and shows the `sourceEventId`
`constraint` that runtime metadata does not serve. These members arrive with
model explanation `v1alpha7`. The version string is part of the document file
name and envelope, so a reader that accepts only an earlier version refuses
the document; there is no partial view. See
[the explanation contract](contracts/explain/README.md).

## Runtime metadata

`GET /v1/registry` carries the descriptor as an `occurrence` member of a record
type, filtered for the caller and profile. `metadataVersion` stays `"2"`; the
member is additive and ignorable.

- No `occurrence` member when the record type declares none.
- `descriptorVersion` (the integer `1`), `label` and `recordedTime` (`{source:
  creation-revision}`) are always present for a declaring, visible record type.
- A subject or source item is omitted when its field is not readable by the
  profile. The lists may become empty.
- `summary`, `correction` and `sourceEventId` are omitted when any field they
  use is unreadable. A `sourceEventId` whose `namespaceField` is unreadable is
  omitted whole.
- `occurredAt` and `effective` are omitted unless every mapped bound is
  readable.
- A native item's or correction's `target` is dropped when that record type is
  not among the caller's visible record types.
- Withheld and undeclared members are omitted, never `null`, so a client cannot
  distinguish them and reports both as unavailable.
- Each emitted field is `{id, apiName, type, target?}`, and every one is
  already in `readableFields`. The served `sourceEventId` carries no
  `constraint`.
- Grouping is not exposed in runtime metadata.

Discovery grants no authority; see [metadata](metadata.md).

## Recorded time

Recorded time is when the registry first accepted the record: `createdAt` of
revision `1` of the record (`mutationKind: create`, no predecessor), read from
its revision history. A client reading it needs revision access under the
selected profile; without it, or when history is absent, recorded time is
unavailable, never guessed from another clock. The registry serves revision
`createdAt` as RFC 3339 text ending in `Z`.

Authored `timestamp` values are stored as instants and served in UTC with a
`+00:00` offset: `2026-10-20T09:30:00+02:00` is read back as
`2026-10-20T07:30:00+00:00`. The authored offset is not preserved by the
registry. The client occurrence view passes the served text through (only
letter case is normalized: uppercase `T` separator and `Z` zone letter) and
never converts a value to another zone.

## Client view

The Rust, Node and Python clients project a record plus its creation revision
into an occurrence view for any declared record type through one reader. The
client guide, [CLIENTS.md](../../crates/CLIENTS.md), documents the clients.
The view is inert data. Its format identifier is
`id.registrystack.org/formats/breg/occurrence-view/v1alpha1`, and its JSON
Schema is
[`OccurrenceView.schema.json`](contracts/occurrence-view/OccurrenceView.schema.json),
which the client tests hold to the projection output.

The view carries these members:

- `contract`, `descriptorVersion` (the integer `1`) and `registryRevision`, the revision
  of the metadata that supplied the descriptor.
- `source`: `recordType`, `recordId` and `revision` of the projected record
  revision.
- `label`, `subjects` and `sources`. Each role lists `role`, an optional
  `label`, `kind` (`native` or `external`), `namespace` for an external role,
  and `value`. A role whose kind this client does not know has no `kind` and no
  `namespace`, and its `value` is `unsupported`.
- `summary`, `occurredAt`, `effective`, `correction` and `sourceEventId`. Each
  is `unavailable` when the descriptor does not declare it. A time names its
  shape in `type`: `point` (`at`) or `interval` (`meaning` `span` or `within`,
  `start`, `end`). A correction names `relation` (`corrects` or `supersedes`) and a
  `reference` value. A source event identifier names `namespace`, `value` and
  `duplicates` (`reject` or `allow`).
- `recordedAt` and `recordedAtSource`. Recorded time is `available` only when
  the caller supplied the creation revision of the projected record; otherwise
  it is `unavailable`. `recordedAtSource` is always `creation-revision`.
- `provenance`: one entry for each distinct item of supplied evidence that
  names this exact record revision. An action receipt entry carries `action`,
  `applicationId` and `effect`. A proposal application entry carries
  `applicationId`, `submissionVersion`, and `appliedAt` (an RFC 3339 instant,
  normalized like every other instant) and `appliedBy` when stated. Evidence
  repeated by the caller yields one entry, in first-seen order.
- `ignoredEvidence`: evidence that does not name this exact record revision,
  with `reason` `revision-mismatch` (same record, other revision) or
  `no-matching-result`. Ignored evidence never contributes provenance.

A value member states what the client could say, never a guess. `available`
carries `type` (`date`, `instant`, `text`, `uuid` or `reference`), `value`, and
for a reference its `target` record type. `declaredUnknown` means the record
holds an explicit null. `unavailable` means the record has no such key.
`unsupported` carries a `detail` naming the type, kind, relation, meaning or
policy the client does not know, so a descriptor that is newer than the client
degrades one member instead of failing the whole view.

The reader refuses with a closed set of error codes, none of which carries a
record value: `not-an-occurrence` (the record type declares no occurrence),
`unsupported-version` (a descriptor version that is a non-negative integer other
than `1`, including `0`), `malformed-descriptor` (a malformed descriptor,
including a `descriptorVersion` that is not a non-negative integer, such as a
string, a fraction or a negative number), `wrong-record-evidence` (evidence or
a creation revision that belongs to another record, or a malformed identifier,
revision or proposal application time), `revision-mismatch`,
`incompatible-metadata` (a record member that contradicts its declared type) and
`invalid-input` (the language-binding arguments are not exact JSON or do not
match the contract).

## Changing a descriptor while work is in flight

- A descriptor-only package activation does not invalidate submitted
  Proposals: the frozen contract fingerprint (`definition_revision`) is
  unchanged, so a waiting Proposal still applies afterwards.
- A saved client Action command is bound to the registry revision it was
  prepared under. After any activation, including a descriptor-only one, the
  client refuses to recover or replay it (the stored bytes and key are
  preserved). Settle uncertain Action commands before activating a
  descriptor-only package.

## Retention and tombstones

Occurrence links are ordinary `reference` fields and follow the existing
reference rules. Only `onDelete: restrict` is supported.

- A create-only record cannot be tombstoned. An occurrence record is normally
  create-only, so it stays as evidence.
- Tombstoning a record that an active record references is refused with a
  value-free conflict. This applies to subjects of a create-only occurrence and
  to a record an active mutable occurrence record points at.
- Tombstoning a mutable record that held a reference releases the restriction
  on its target. The retained link UUID stays in the revision history.
- A reference to an unknown record UUID, such as an unknown `corrects` target, is refused at write time.

Declare a descriptor over a mutable record type only when its fields may
change; the descriptor then describes the current revision, and earlier
statements remain in revision history.

## Display purpose and grouping

Record types and Actions may declare `display.purpose` and `display.group`.
They are presentation only: they never grant, hide, order execution, gate
activation or change Action, Access or Proposal behavior. A missing declaration
gives an ungrouped list with no purpose claim; purpose is never inferred from a
name, route or mutation mode.

```yaml
recordTypes:
- id: entry
  display: {label: Entry, purpose: domain, group: Register}
actions:
- id: seed-demonstration-entries
  display: {label: Seed demonstration entries, purpose: synthetic-seed, group: Demonstration data}
```

`purpose` is optional; `group` is optional display text, and grouping is by
exact string.

| Value | Records | Actions |
|---|---|---|
| `domain` | registry facts the programme exists to keep | changes to those facts |
| `processing` | working records that support processing (notes, review items, intake) | processing steps |
| `technical` | operational or integration records | maintenance or integration Actions |
| `synthetic-seed` | not allowed | Actions that create demonstration or test data |

Validation:

| Code | Trigger |
|---|---|
| `config.unknown-variant` | `purpose` outside the four values |
| `breg.display.purpose-surface` | `synthetic-seed` on a record type |
| `breg.display-text.invalid` | unsafe characters in `group` |
| `config.unknown-key` | `purpose` or `group` on any other display surface (fields, inputs, datasets, review authorities) |

A group with one member is valid, groups may mix purposes, and a record type
and an Action may share a group string. Grouping is excluded from record and
Action definition revisions, migration review revisions and Proposal
fingerprints; it is included in the effective model, so it changes the
registry revision. It is reported by `bregctl explain model` (`v1alpha7`) and
not by runtime metadata.

A consumer shows `grouping: null` as ungrouped with no badge, shows a `group`
without a `purpose` as grouped with no badge, and shows an unrecognized future
`purpose` as unsupported while keeping the item visible. Grouping never hides
an item.

## Actions that record occurrences

Recording an occurrence is an ordinary create-only Action: one or more effects,
an idempotency key, and commit guards. Observed behavior:

- A failed guard returns `412 action.guard_failed`, with `guardReason` when the
  caller may read every guard fact.
- A violated unique source-event constraint returns `409 mutation.conflict`.
- The same idempotency key with a changed body returns `409
  idempotency.key-reused`; the exact same command replays the retained result.
- Two concurrent Actions with the same precondition token commit once: one
  receives `200`, the other `412`. Two concurrent handovers of the same
  external deed commit once: one `200`, one `409`.
