# Registry Scheduling

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

Check reports `complete` or `incomplete` with field-addressed findings. Test
repeats that authoring status and replays the project's bounded synthetic
fixtures offline; a passing report carries the `offline_synthetic` proof
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
Then apply the live environment records and start:

```sh
scheduling --runtime-config "$PWD/runtime.yaml" migrate
schedulingctl records apply "$PWD/runtime.yaml" "$PWD/records.yaml"
scheduling --runtime-config "$PWD/runtime.yaml" serve
```

`migrate` applies the schema and binds the database to the policy's
scheduling id, which every later start verifies before it writes anything.
A `serve` that finds a schema older than the one its binary carries refuses
at the readiness check rather than serving against it, so an upgrade runs
`migrate` before it restarts the new runtime. Availability cursors last at
most 15 minutes; callers should deduplicate entries by their start when a
policy, records, or runtime change overlaps an in-flight listing.
The migration also retains the current policy document beside its digest. On
an upgrade from an earlier schema, start once with the unchanged policy to
backfill that document before publishing a policy change.
`records apply` is the one attributable operator write of a deployment's
environment records: the locations with their time zones, the resource pools
and their members, the published arrival windows, and the dated exceptions
such as closures. The policy references that supply by identifier; it does
not embed it. A records replacement locks standing supply and refuses to move,
remove, or reduce a window below its live bookings and holds; the operator
error names the affected window and deficit. Database
transport security is not configurable in production: the runtime requires
TLS on both connections, and the plaintext escape is a `postgres-test` build
switch documented in [RUNTIME-CONFIG.md](RUNTIME-CONFIG.md).

The served routes are the published catalogue, availability and the
separately authorized explain read, holds, and appointments with their
reschedule, cancel, and history routes. Every call presents a bearer access
token, and one of three authority profiles decides what it must carry; the
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
signing key and JWKS, migrates and applies example environment records, and
serves the runtime on loopback (see `products/scheduling/demo/README.md`). A
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
CloudEvents 1.0 event in canonical JSON and POSTs it to the configured
reminder destination with `content-type: application/cloudevents+json`,
exactly once per claim. A transport failure schedules an exponential retry, a
refusal the retry classes do not cover holds the intent for the operator, and
eight failed attempts hold it.

Every event carries the same envelope:

| Field | Value |
| --- | --- |
| `specversion` | `1.0` |
| `id` | the outbox intent's identifier |
| `source` | the deployment's `scheduling.id` from the policy, and nothing else |
| `type` | `org.registrystack.scheduling.` plus the intent's purpose |
| `time` | when the intent fell due, RFC 3339 |
| `data` | the payload the runtime committed |

There are four purposes, so four types: `confirmation` and `change` carry the
committed appointment's identifier, revision, offering, start, end, and the
policy revision it was committed under; `cancellation` carries the
identifier, revision, and reason; `reminder` carries the identifier,
revision, offering, start, and how many minutes before the start it was
minted for.

With no reminder destination configured, the intents stay readable in place:
they are written to the outbox and marked local, never pretended delivered.
Adopting the product does not require wiring a notification bus first.

Appointment observers are governed hooks. A policy may declare `phase: after`
with a URL handler for exactly three triggers:

| Trigger | Allowed projected fields |
| --- | --- |
| `appointment.confirmed` | `appointmentId`, `revision`, `offering`, `start`, `end`, `state`, `policyRevision` |
| `appointment.rescheduled` | `appointmentId`, `revision`, `offering`, `start`, `end`, `state`, `policyRevision` |
| `appointment.cancelled` | `appointmentId`, `revision`, `state` |

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
`retention.hookPayloadDays`. Operator replay is not exposed in this slice.

## Phase 1 scope and exclusions

Phase 1 is one booking surface over anchored supply. It excludes, as tracked
exclusions rather than accidents:

- Reassignment: no route moves an appointment to another party, and no
  evaluator takes a substitute recipient.
- Attendance routes: no check-in, arrival, or fulfilment surface exists, and
  the runtime records nothing about whether a party attended.
- Closure routes: closures are environment records the operator applies, and
  no route creates or lifts one.
- Remediation workflows: a refused or expired commitment ends at its problem
  answer, and nothing reopens it.
- Reports: no occupancy, utilization, or waiting-list reporting surface.
- Guest booking: a holder other than the verified caller cannot book on
  someone's behalf. Every commitment's grant names the caller, and the party
  a request carries is the party the caller commits.

`externalReferences` and the integration seams that would attach a Scheduling
appointment to another product's record are Phase 4 work. They are absent from
the wire types today, and adding them is a contract change, not a fill-in.

## Arrival windows and channel subquotas

A published window carries a total unit budget and, optionally, subquotas
keyed by booking channel. A subquota is a per-channel ceiling, not a reserved
floor: the evaluator checks the named channel's allocation against its
subquota, then checks the request against the window's published total, so an
unclaimed subquota stays available to the window's other channels up to that
total. A channel the policy declares but gives no subquota draws from the
total alone, and a request naming an undeclared channel is refused.

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
Base Registry Engine, Casework, or Evidence crate, and none of those products
may reach a scheduling crate. The restriction is scoped to the MVP, because
the crates that would compose across those boundaries do not exist yet; the
workspace `AGENTS.md` records what changes when one does. The source-neutral
core sits at the bottom of the product depending on no other scheduling
crate, and the client shares the core without ever linking the runtime or
adopter tooling.
