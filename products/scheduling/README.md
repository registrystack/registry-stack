# Registry Scheduling

PostgreSQL 17 or newer is required for package activation and runtime startup.

Registry Scheduling gives a registry a coordinated booking surface: published
openings, exact-time offerings over interchangeable resource pools, published
arrival windows with channel subquotas, holds, and accountable bookings, over
PostgreSQL. The runtime is `crates/registry-scheduling`; the source-neutral
model and evaluators live in `crates/registry-scheduling-core`; adopter
tooling is `crates/registry-schedulingctl` (`schedulingctl`); the bounded Rust
client is `crates/registry-scheduling-client`.

The contract is unreleased and carries no frozen compatibility promise.

## Boundary

Scheduling owns its capacity ledger absolutely. A hold or an appointment is
created, moved, or released only inside the Scheduling runtime's own capacity
transaction, and no other product may write that ledger, directly or through
a shared database. Another product may publish bookable supply for work it
governs, or show an appointment Scheduling holds, without either side gaining
the other's authority: eligibility stays with the source system, and the
authority to commit capacity stays with the task grant Scheduling verifies.

## What Scheduling is not

The product is a capacity ledger over anchored supply, and nothing else. It is
not a source of eligibility: whether a party may hold a service is decided by
the system that owns that rule, and Scheduling has no eligibility route. It is
not a queue: nothing here coordinates source-owned work items, which is
Registry Casework's surface. It is not a calendar product: openings, windows,
and closures are published facts an operator anchors, and Scheduling holds no
personal calendar and no invitation lifecycle. It is not a reminder delivery
product: the runtime records due reminder intents and delivers them to one
operator-configured destination, while the message content, the channel, and
the notification bus stay outside Scheduling.

## Start from an authored project

Create a starter, inspect its effective configuration, and replay its
fixtures:

```sh
schedulingctl init ./scheduling --template standalone-exact-time
schedulingctl check ./scheduling
schedulingctl test ./scheduling
schedulingctl explain ./scheduling
```

Check reads the policy, `records.yaml`, and every fixture, and names each
problem as an error at its file, line, column, and JSON pointer; any error
exits 1, `--deny-warnings` makes a warning refuse too, and `--format json`
writes the same diagnostics in one envelope. Every JSON report names its format
as `apiVersion: id.registrystack.org/formats/scheduling/ctl-report/v1alpha1`
and `kind: SchedulingCtlReport`;
[`examples/formats/ctl-report.json`](examples/formats/ctl-report.json) is the
report check writes for the exact-time example. `--runtime-config FILE` checks
a runtime file offline as well. Test runs the same checks and replays the
project's bounded synthetic fixtures offline; a passing report carries the
`offline-synthetic` proof
boundary and `productionClosure: false`, so it does not establish source
reachability or deployment readiness. Explain publishes what the runtime would
serve: identity, policy digest, offerings, the operator-published windows with
their subquotas, and the hold policy.

`schedulingctl init` writes `runtime.example.yaml` and `records.yaml` beside
the policy. The records document contains every location, resource pool, and
arrival window the selected starter needs. Copy the runtime example to
`runtime.yaml`, set its
absolute paths and secret references, and read
[RUNTIME-CONFIG.md](RUNTIME-CONFIG.md) for every block, field, and default.
Then activate the package, apply the live environment records, and start:

```sh
schedulingctl plan --runtime-config "$PWD/runtime.yaml"
schedulingctl apply --runtime-config "$PWD/runtime.yaml" --operator-reference CHG-1234
schedulingctl records apply --runtime-config "$PWD/runtime.yaml" "$PWD/records.yaml"
scheduling --runtime-config "$PWD/runtime.yaml" serve
```

`plan` reads with the runtime credential and writes nothing: it names the
active and candidate package digests, whether the database identity matches
`identity.databaseId`, the schema versions still to apply, the policy revision
the apply would publish, and `changesPending`. `apply` is the only writer of
the activation ledger. With the migration credential and under one advisory
lock, it applies the pending schema versions, binds the database to the
policy's scheduling id, publishes the policy, grants the runtime role its
access when the two credentials name different roles, and records one ledger
row, all in one transaction. It writes an activation request entry to the
`schedulingctl` sibling of `audit.path` (`audit.schedulingctl.ndjson` beside
`audit.ndjson`) before that transaction and a response entry after it, and applies nothing when the request entry cannot be written.
`--operator-reference` (a change ticket, for instance) is kept only as a keyed
hash, and each `--backup REF` is recorded as given. Applying the package that
is already active refuses with `nothing needs applying` unless a schema
version is pending, the runtime credential is another role than the ledger
recorded, its role mode changed, or a split runtime role lost a grant apply
issues; any other valid package, including an
earlier one, applies as a new row. Each row records the runtime role and the
role mode that role actually holds after the grants: `split` when it cannot
write the ledger, `single` when it can, through a grant, ownership, membership
in the migration role, or a superuser attribute. `status` reads the full
activation history and the role mode the runtime credential holds now.

From v0.36.0 the Scheduling image carries the `schedulingctl` built from the
same source as its `scheduling`, at `/usr/local/bin/schedulingctl`; the
entrypoint stays `scheduling`. To run `plan`, `apply`, or `status` with the
image's exact bytes, override the entrypoint and mount the runtime file, the
package, and the secret root read-only at the absolute paths the runtime file
names, and the audit directory writable, because `apply` writes its entries to
the `schedulingctl` file beside `audit.path`:

```sh
docker run --rm \
  --entrypoint /usr/local/bin/schedulingctl \
  -v /etc/registry-scheduling/runtime.yaml:/etc/registry-scheduling/runtime.yaml:ro \
  -v /etc/registry-scheduling/package:/etc/registry-scheduling/package:ro \
  -v /etc/registry-scheduling/operator-secrets:/etc/registry-scheduling/secrets:ro \
  -v /var/lib/registry-scheduling/audit:/var/lib/registry-scheduling/audit:rw \
  "$SCHEDULING_IMAGE" \
  apply --runtime-config /etc/registry-scheduling/runtime.yaml \
  --operator-reference CHG-1234
```

Replace the arguments after the image with
`plan --runtime-config /etc/registry-scheduling/runtime.yaml` or
`status --runtime-config /etc/registry-scheduling/runtime.yaml` for the other
two commands. The secret root mounted for `apply` holds the migration
credential `database.migrationUrlRef` names; keep it out of the serving
container's. The image runs as UID 65532, and the file secret provider refuses
a file owned by another user. A Kubernetes Job sets
`command: ["/usr/local/bin/schedulingctl"]` and puts the subcommand and its
flags in `args`.

`serve` writes no activation state. It refuses to start when the ledger holds
no row, when the ledger belongs to another `identity.databaseId`, when the
verified package is not the active one, or when `package.expectedDigest` names
another package; each refusal names `schedulingctl plan` then
`schedulingctl apply`. It also refuses when the ledger recorded `split` and the
runtime credential can now write the ledger, naming `schedulingctl apply` to
reissue the grants. With two roles, `plan`, `apply`, and `serve` refuse a
runtime role that owns a Scheduling object, holds TRIGGER on a Scheduling
table, or holds CREATE on the schema, and a trigger attached to a Scheduling
table, naming object-scoped `ALTER ... OWNER TO` corrections then
`schedulingctl apply`, or `REVOKE TRIGGER`, `REVOKE CREATE ON SCHEMA`, or
`DROP TRIGGER` then a rerun of the
refused command. `serve` also refuses a split runtime role missing a grant
apply issues, naming `schedulingctl apply`. A `serve` that finds a schema older than the one its
binary carries refuses at the readiness check rather than serving against it,
so pending schema versions require `schedulingctl apply` before restart.
Before 1.0, a release reads only the state its immediate predecessor wrote, so
upgrade one release at a time; a release that starts a fresh baseline says so
in its release notes and is applied to a new database. Availability cursors last
at most 15 minutes; callers should deduplicate entries by their start when a
policy, records, or runtime change overlaps an in-flight listing.

`records apply` is the one attributable operator write of a deployment's
environment records: the locations with their time zones, the resource pools
and their members, the published arrival windows, and the dated exceptions
such as closures. The policy references that supply by identifier; it does
not embed it. A records replacement locks standing supply and refuses to move,
remove, or reduce a window below its live bookings and holds; the operator
error names the affected window and deficit. It refuses a database no
`schedulingctl apply` has activated, one whose ledger names another
`identity.databaseId`, and one where another package is active. Database
transport security is not configurable in production: the runtime requires
TLS on both connections, and the plaintext escape is a `postgres-test` build
switch documented in [RUNTIME-CONFIG.md](RUNTIME-CONFIG.md).

Individual pool members may add `availability` with dated `openings` and
`closures`, each a bounded list of `{start, end}` instants. Omitted openings
add no opening constraint; `openings: []` publishes no supply. Intersect their
union with the member's static `available` flag and the offering's location
calendar. Overlapping or adjacent openings form continuous supply, closures
win, and every interval is half-open. Supply must cover the complete occupied
interval, including setup and cleanup. Resolve local calendars and ambiguous
or nonexistent local times at the source before sending RFC 3339 instants.
Each list contains at most 256 intervals, each positive and at most 3,650 days.

Recording an absence blocks new admissions, rescheduling into that absence,
and confirmation of an affected hold. Existing bookings and holds are not
cancelled or reassigned. `records apply --format json` includes
`resourceImpacts`: the first 256 affected live resource allocations, their
claim identifiers and occupied intervals, and the exact total from a current
database snapshot after the apply. A reservation can appear once for each
affected resource; a window appears through its own resource reservation,
without counting each booking in it again. Removed resources and stock
reductions below simultaneous commitments are included alongside absences. It
contains no owner identity or absence reason. This is a current impact read,
not a promise that supply stayed unchanged after publication. Operators can
use scoped appointment reads to inspect further bookings and arrange an
authorized reschedule or cancellation; affected holds can be released or
expire normally. Resource catalogue and ordinary availability responses do
not disclose these dated facts or personnel information.

The [`resource-reservations` starter](examples/resource-reservations/README.md)
demonstrates named selection and policy-bounded intervals, including a
25-hour local day and multi-day bookings. Create it with
`schedulingctl init PROJECT --template resource-reservations`. Existing
offerings retain fixed duration and fungible allocation unless they opt in.

The served routes are the published catalogue (service, offering, resource
and location lists), availability with its preview and the separately
authorized explain read, holds, and appointments with their receipt,
reschedule, cancel, history, and attendance routes. The operational
appointment work list, and the source busy preview and apply routes, are served
only under the runtime profiles that grant them. Every call presents a bearer access
token, and the route's explicit authority decides what it must carry; the
published reference is
[Registry Scheduling API](https://docs.registrystack.org/reference/apis/registry-scheduling/).

## Local development

There is no `schedulingctl dev` verb that stands up a runtime instance
directly; this is a tracked exclusion, not an oversight. Local development
runs the demo instead:

```sh
products/scheduling/demo/run.sh
```

which provisions a disposable TLS-enabled PostgreSQL database, a throwaway
signing key and JWKS, activates the package, applies example environment
records, and serves the runtime on loopback (see `products/scheduling/demo/README.md`). A
verb over that same provisioning shape does not fit as a surgical addition:
the shape depends on Docker container lifecycle, TLS certificate generation,
and JWT signing infrastructure the demo carries in
`products/scheduling/demo/support/demo.py`, and a resident process supervisor
over a runtime instance is a project-sized effort on its own, comparable in
scope to `crates/registry-evidencectl/src/dev.rs`.

## Task grants

Reads take a scope. Every commitment takes a task grant whose scheduling
bounds name the offering's service, its location, and the action, and the
runtime matches all three exactly before the capacity transaction opens. The
bounds, the closed action vocabulary, the value limits, and the one fact the
transaction re-reads are documented in
[TASK_GRANTS.md](TASK_GRANTS.md). Scheduling verifies grants; it does not
approve them, and the approval surface stays with the product that holds the
human relationship. The maintained Casework template and stock ThunderID
exchange path is documented there through an actual appointment request.

## Events and observers

The runtime has two outbound integration seams. Reminder dispatch is product
notification work: a commitment mints the reminder intents its offering
declares, each due a fixed number of minutes before the appointment, and a
worker renders every due intent as one
shared hook envelope in canonical JSON, the same envelope an appointment
observer receives, and POSTs it to the configured reminder destination with
`content-type: application/json`. Delivery runs on the
shared dispatch core: each attempt is bounded at five seconds, a transport
failure retries after thirty seconds, doubling to about thirty-two minutes,
a refusal the retry classes do not cover sets the intent aside for the
operator, and the eighth failed attempt sets it aside. A worker that stops
mid-attempt leaves its lease to lapse, and the attempt counts as a failure.
If the destination accepts an event but the runtime cannot record that
outcome, recovery applies the retry schedule and may send the event again.
Successful delivery is therefore not guaranteed.
A cancellation or reschedule cancels the appointment's reminders no attempt
has started on, in the same transaction. Just before each send the runtime
reads, under the attempt's lease, whether the intent still describes the
appointment: a reminder whose appointment was cancelled or moved to a newer
revision is set aside as superseded and never sent, and a lapsed lease
starts no send. The destination
deduplicates on the envelope `id`, the same on every attempt.

Every event carries the same envelope:

| Field | Value |
| --- | --- |
| `id` | the outbox intent's identifier |
| `type` | `org.registrystack.scheduling.` plus the intent's purpose |
| `source` | `urn:registrystack:scheduling:` plus the deployment's `scheduling.id` from the policy |
| `time` | when the intent fell due, RFC 3339 in UTC at millisecond precision |
| `subject` | `recordReference` `/v1/appointments/<id>` and `recordRevision`, the appointment revision the intent was minted for |
| `dataschema` | `urn:registrystack:scheduling:reminder-data:` plus the intent's purpose |
| `data` | the payload the runtime committed |
| `causation` | a root chain: `root` is the event's own `id` and `hop` is `0` |

A reminder can be signed using the optional
`destinations.reminders.hmacSha256KeyRef`. Signed delivery uses the shared
CloudEvents delivery headers and HMAC-SHA-256 signature, binding the request
target, envelope bytes and delivery metadata. `destinations.reminders.url` is
the fallback for every purpose. The optional closed `purposeUrls` block can
select separate `confirmation`, `change`, `cancellation`, and `reminder`
endpoints on that fallback URL's origin. Missing purpose entries keep using the
fallback. The runtime compiles every effective endpoint at startup and signs
the exact selected path, so a proxy cannot reroute a signed event to another
typed receiver. Its event identity and idempotency key stay fixed
across retries; the attempt and delivery time change. Configure the matching
trusted source and key at the receiver. The optional
`destinations.reminders.bearerTokenRef` independently authenticates access to the
destination and can be used with signing. Omitting the signing key preserves
bearer-only delivery. A valid event signature proves origin and integrity; it
does not grant appointment-read or message-send authority.

There are four purposes, so four types: `confirmation` and `change` carry the
committed appointment's identifier, revision, offering, start, end, and the
policy revision it was committed under; `cancellation` carries the
identifier, revision, and reason; `reminder` carries the identifier,
revision, offering, start, and how many minutes before the start it was
minted for.

With no reminder destination configured, the intents stay readable in place:
each is set aside in the outbox as local when it falls due, never pretended
delivered.
Adopting the product does not require wiring a notification bus first.

Appointment observers are governed hooks. A policy may declare `phase: after`
with a URL handler for exactly four triggers:

| Trigger | Allowed projected fields |
| --- | --- |
| `appointment.confirmed` | `appointmentId`, `revision`, `offering`, `start`, `end`, `state`, `policyRevision` |
| `appointment.rescheduled` | `appointmentId`, `revision`, `offering`, `start`, `end`, `state`, `policyRevision` |
| `appointment.cancelled` | `appointmentId`, `revision`, `state` |
| `appointment.attendance-observed` | `appointmentId`, `appointmentRevision`, `attendanceRevision`, `attendanceState`, `observedAt`, `recordedAt`, `policyRevision` |

See [attendance observations](ATTENDANCE.md) for the observation and correction
contract behind the attendance event.

The runtime refuses conditions, principals, Rhai or Wasm handlers, unknown
triggers, and fields outside that table. It captures one canonical event and
its delivery row in the same transaction as the appointment change, then an
after-commit worker POSTs it to the deployment-bound destination. Delivery is
at least once, HMAC-SHA256 signed, retried within fixed product ceilings, and
audited without payload values: each attempt's audit entry is accepted before
the request leaves, or the delivery stays pending and nothing is sent. A
receiver response is observation only: Scheduling deterministically refuses
every proposal and never turns it into a booking, reschedule, or cancellation.

The hook id becomes the event `type`. The source is
`urn:registrystack:scheduling:<scheduling-id>`, the subject record reference is
`/v1/appointments/<appointment-id>`, and `data` contains only the requested
fields. `state` is the public value `confirmed` or `cancelled`; actor identity,
task grants, resource and channel identifiers, duplicate keys, and cancellation
reasons cannot be projected. Retained payloads expire after
`retention.hookPayloadRetentionDays`. Operator replay is not exposed in this slice.
Terminal delivery metadata uses `retention.receiptRetentionDays`: every
delivered outbox intent (confirmation, change, cancellation, reminder), every
reminder cancelled or set aside as superseded, and every completed hook
delivery ages out in bounded retention batches.
Dead-letter metadata ages from the original `dead_lettered_at` timestamp and
requires completed payload expiry and erased payload bytes before removal.
Later payload expiry does not restart the metadata window, so an old dead letter
can disappear as soon as expiry completes. Active,
retryable and uncertain work, spent idempotency keys, and audit records survive
this cleanup. See [retention configuration](RUNTIME-CONFIG.md).

## Phase 1 scope and exclusions

Phase 1 is one booking surface over anchored supply. It excludes, as tracked
exclusions rather than accidents:

- Reassignment: no route moves an appointment to another party, and no
  evaluator takes a substitute recipient.
- Closure routes: closures are environment records the operator applies, and
  no route creates or lifts one.
- Remediation workflows: a refused or expired commitment ends at its problem
  answer, and nothing reopens it.
- Reports: no occupancy, utilization, or waiting-list reporting surface. The
  operational appointment work list is a bounded read, not a report.
- Guest booking: a caller cannot book for an arbitrary other party. Every
  commitment's grant names the caller, and the party a request carries is the
  party the caller commits. The one exception is source-managed assisted
  booking, where a task grant carrying `hold.create-for` and
  `appointment.create-for` lets an actor book while the source manager from
  the signed grant is retained as the appointment's manager (see
  [Task grants](TASK_GRANTS.md#source-managed-assisted-bookings)).

## External record references

The `v1alpha2` HTTP contract adds external references on the existing `/v1`
routes. Upgrade the runtime before sending the new admission field. Existing
admissions may omit it, and existing appointments return an empty set.

An admission may carry `externalReferences`, each a typed opaque tuple of
`product`, `recordType`, and `identifier`. Scheduling stores only that tuple.
It never calls the referenced product, resolves the identifier, or grants any
authority through the link. Identifiers name records only; callers must not put
personal data in a reference.

A hold returns the references it was created with. Confirming that hold copies
the same immutable references to the appointment; a direct booking takes them
from its admission. A reschedule must omit `externalReferences`; rescheduling
and cancellation retain the original set. Exact retries
may reorder the set, but changing a reference under the same idempotency key is
`idempotency.key-reused`.

`GET /v1/appointments` requires `externalReferenceProduct`,
`externalReferenceRecordType`, and `externalReferenceIdentifier`, and accepts
the ordinary `cursor` and `limit` parameters. It returns only appointments
owned by the authenticated caller that carry the exact tuple. Its cursor is
bound to both that caller and tuple, and ownership is rechecked on every page.
The link lets another product find appointments created by its stable service
principal without giving Scheduling access to that product.

An orchestrator that books for another product's record needs
`externalReferences` on every create it makes. The reference is how it learns
an outcome it never received: the listing needs only the read scope, so a
token for the same issuer and subject that carries no task grant finds the
appointment after the grant that booked it has expired. The token that carried
the expired grant cannot do this, because an expired grant refuses the whole
token, read scope included. A hold is not listed; one that is never confirmed
expires and returns its capacity.

Ordinary listing is per principal by design. By default a hold or appointment
is owned by the verified token issuer and subject that booked it, so another
principal sees an empty page even when it serves the same product, and an orchestrator that must
observe its own outcomes books and reads under one principal. An appointment
an orchestrator books for a party is therefore the orchestrator's, not the
party's: an external party reference alone permits no read or change. The
official books for the party, and changes go through the process that booked
it. History and audit carry the keyed pseudonym of that pair instead, derived
with the audit hash key (`audit.hashKeyRef`), and decide nothing: rotating that key leaves
every live claim with its owner. After an appointment ends or is cancelled,
or a hold expires, is released, or is consumed, the configured
`retention.claimOwnerRetentionDays` window bounds the raw pair. It defaults to
seven days and accepts 1 through 365 days. The sweep replaces the pair with an
inert digest; the former owner can no longer list, read, act on, or recover a
receipt for that claim. The claim, its history, and audit stay. The published
[Registry Scheduling API reference](https://docs.registrystack.org/reference/apis/registry-scheduling/)
gives the full recovery rules for an unknown outcome.

## Booking parties and management

An exact-time offering may opt into `partyCounts: optional`. Room and equipment
bookings can then omit `party` without inventing a recipient or attendee.
Omitted policy configuration keeps required counts, as do arrival windows.
Supplied counts are validated and retained independently from capacity units;
a booking that omits `party` under `partyCounts: optional` records no counts.

`partyReferences` can record up to sixteen typed `beneficiary` or `organization`
references to source-owned records. Use opaque identifiers without names or
contact details; these references grant no authority. They are retained through confirmation and rescheduling,
and follow identity retention. Changing the booking's time does not change its
recorded parties or manager.

Assisted booking can explicitly select `manager: schedulingManager`, using a
fixed value from the source grant's signed identity rather than a caller-supplied
person identifier. The actor and manager are then separate. Additional exact
actions, fresh online grant status and the retained source-manager binding
authorize creation, management and current-detail reads. This path grants no
list or history access. See [Task grants](TASK_GRANTS.md#source-managed-assisted-bookings)
for the complete authority and recovery contract.

Operational staff can use a separate bounded appointment work list when runtime
configuration grants an explicit role scope and service/location/resource
profile. Its projection contains only permitted scheduling data, not booking
identity or contact data. See
[Operational appointment read profiles](RUNTIME-CONFIG.md#operational-appointment-read-profiles).

## Arrival windows and channel subquotas

A published window carries a total unit budget and, optionally, subquotas
keyed by booking channel. A subquota is a per-channel ceiling, not a reserved
floor: the evaluator checks the named channel's allocation against its
subquota, then checks the request against the window's published total, so an
unclaimed subquota stays available to the window's other channels up to that
total. A channel the policy declares but gives no subquota draws from the
total alone, and a request naming an undeclared channel is refused.

A records window may also list `resources`, each naming an exact-time
requirement offering at the window's location with `partyCounts: optional`
that sells the window's whole span, an optional resource, and physical units.
The window reserves them once for its whole span through a parent claim in
the allocation ledger, so the reservation conflicts with exact-time bookings
and other windows that need the same resource, and `records apply` refuses a
window whose resource is unavailable, busy, or not freshly covered by a
configured busy source. `records apply` and a policy publication both refuse
a requirement the deployed policy cannot reserve that way with
`mismatched-reference`.
A window whose record is unchanged keeps what it holds across later records
applies and policy publications; a later absence of its resource shows in
`resourceImpacts` instead. Bookings in the window consume only the window's
units.

Nothing in the current grammar reserves capacity for a channel. Reserved
floors are an open Phase 2 product question: they change what "the last unit"
means for a walk-in, and they are not a bug to fix here.

## Product material and gates

This folder holds the product's own contracts, examples, fixtures, and gates.
The database-free checkpoint runs the contract checks, the dependency-direction
gate, and the whole offline authoring journey:

```bash
cargo build --locked -p registry-schedulingctl
products/scheduling/scripts/check-checkpoint.sh
```

`examples/standalone-exact-time/` is exactly what
`schedulingctl init --template standalone-exact-time` writes, and the
checkpoint fails if the two drift apart. The runtime configuration schema is
derived from the strict Rust types, never hand-edited; its generator command
is in [RUNTIME-CONFIG.md](RUNTIME-CONFIG.md).

For PostgreSQL execution, the destructive test suites require a separate
disposable database and the `postgres-test` feature:

```bash
SCHEDULING_TEST_DATABASE_URL=postgres://user:password@host/database \
  cargo test --locked -p registry-scheduling --features postgres-test \
  --test postgres_commitments
```

`SCHEDULING_TEST_DATABASE_URL` names that disposable database for both
PostgreSQL suites, `registry-scheduling`'s commitment suite and
`registry-schedulingctl`'s records-apply suite. Both reset the `public`
schema, so never point either at retained operator data, and never point both
at one database. A test binary that skips because its database URL is absent
is not database verification.

## Dependency boundary

No scheduling crate, directly or through any shared dependency, may reach a
Base Registry Engine, Casework, Document Store, Evidence, or Messaging crate,
and none of those products may reach a scheduling crate. The restriction is
scoped to the MVP, because the crates that would compose across those
boundaries do not exist yet; the workspace `AGENTS.md` records what changes when one does. The
source-neutral core sits at the bottom of the product depending on no other
scheduling crate, and the client shares the core without ever linking the
runtime or adopter tooling.

## Observe an original receipt

`POST /v1/appointments/receipt` accepts the original request body and `Idempotency-Key`
under current ordinary read authority. It returns `200` with the retained
original success receipt for the same verified issuer and subject. It never
repeats the business operation. A same-principal read credential can observe
work after task authority ends; another service identity cannot impersonate
that principal. `409 receipt.unresolved` covers unavailable evidence such as
a missing, expired, or changed receipt, or a claim whose owner has been erased,
and does not prove that no effect occurred.
The receipt route authenticates before checking the JSON media type and decoding
its bounded body. The router still rejects a declared body larger than one MiB
before entering the handler. Authenticated callers retain the usual malformed
JSON, unsupported media type, request-shape and body-size refusals.
