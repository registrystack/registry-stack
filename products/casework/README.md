# Registry Casework

Registry Casework gives a team one accountable inbox for source-owned work and
source-neutral reviews requested by another service. It can run without a
registry source for submitted-context reviews, or connect governed sources such
as Base Registry Engine. A project may configure either surface or both.
Source-backed holders can also [approve bounded agent tasks](TASK_GRANTS.md).

Machine-readable `caseworkctl --format json` output is versioned by the
[`caseworkctl` JSON wire contract](contracts/cli/README.md). Each report carries
an `apiVersion` and `kind` and is checked against its command-specific schema.

## Standalone unified reviews

Create the source-free starter, then inspect its effective configuration:

```sh
caseworkctl init ./casework --template standalone-decision
caseworkctl check ./casework
caseworkctl test ./casework
```

Check reports `complete` or `incomplete` with field-addressed findings. Test
repeats that authoring status and can still run the bounded synthetic fixtures
while authoring is incomplete. A passing fixture report has the
`offline_synthetic` proof boundary and `productionClosure: false`; it does not
establish source reachability or deployment readiness.

The maintained authored form is
[`examples/standalone-decision/casework.yaml`](examples/standalone-decision/casework.yaml).
It declares one `decision` review kind, one queue, its bounded JSON Schema
display, allowed answer outcomes, separate result and accountability retention,
and an admitted producer identity. The runtime does not install this policy
implicitly. Every accepted request must name a kind and producer declared by
the active project.

An operator must still configure PostgreSQL, token verification, human
Casework profiles, and a team serving the first review stage queue. The
Administrator bootstraps that directory through the authenticated directory
API. A standalone deployment does not start or depend on BReg.

An authenticated producer creates a request at `POST /v1/review-requests` with
an `Idempotency-Key`. Admission binds the producer's exact issuer and subject,
source namespace, kind, and optional completion destination. A producer can
read, cancel, poll results, or page its result feed only inside that same
binding. Producer authority never grants human review authority.

The submitted-context create body carries the configured kind, immutable
subject binding, an opaque requester correlation reference, a trusted qualified
initiator when the policy excludes the initiator, and display data validated
against the kind's bounded JSON Schema:

```json
{
  "kind": "decision",
  "subject": {
    "source": "standalone",
    "type": "batch",
    "id": "batch-0042",
    "version": "1",
    "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  },
  "requesterReference": "batch-0042",
  "initiator": {
    "issuer": "http://127.0.0.1:8091",
    "subject": "requester"
  },
  "context": {
    "strategy": "submitted",
    "snapshot": {
      "summary": "Review the 12 entries in the prepared batch",
      "reference": "batch-0042"
    }
  }
}
```

The initiator is compared with each reviewer's principal, which Casework
reads from the profile's `principalClaim`. A BReg producer sends its own issuer
and the value of its configured principal claim, so the exclusion holds only
when the Casework profiles read that same claim and the producer sets
`trustedInitiatorIssuer` to that issuer. The professional-review starter does
both.

A producer may also name an `initiatorProfile`: a requester profile, distinct
from every producer profile, that the person named as the initiator selects to
read `GET /v1/review-requests/{requestId}/history`. They see the same
requester-visible events and notes as the producer, only for a request that
producer admitted naming their exact issuer and principal. Any other request is
not found. Notes, cancellation, results, and clocks stay producer-only. The
initiator profile accepts only a person acting for themselves: like a reviewer
profile, it refuses delegated (`act`), grant-bearing, and non-human tokens.

It cannot select an actor, team, stage, outcome vocabulary, or arbitrary
callback. A typed review validation failure keeps the six-field problem body
value-free and may add the paired
`Registry-Casework-Validation-Path` and
`Registry-Casework-Validation-Reason` response headers. The path is bounded to
256 characters, the reason comes from a closed enum, and neither header echoes
rejected values.

Human reviewers use `/v1/review-tasks` to list, read, claim, assign, delegate,
release, draft, and decide work. A decided task read carries `decidedByCaller`,
true only when the current caller recorded the decision, so a reviewer whose
decide response was lost can confirm the outcome without the Supervisor-only
accountability record. Every mutation checks the current task revision,
membership, queue service, exclusions, and idempotency binding in the committing
transaction. `GET /v1/review-tasks/{taskId}/context` returns only the frozen
submitted context, or a bounded current source projection authorized for the
exact human caller, together with the policy snapshot pinned to that task.
Kind descriptions supply the currently configured kinds for discovery; task
handling uses the returned pinned snapshot. Casework pins the policy identity
and submission digest once, so a later configuration change cannot reinterpret
accepted work.

Results are read through `GET /v1/review-requests/{requestId}/result` or the
producer result feed. Completion-mode producers may instead configure one
authenticated logical destination. Outbound events contain no result payload
or reviewer identity and use a stable event id across bounded lost-ack retries.
Polling-only producers omit completion configuration.

The maintained
[`examples/payment-review`](examples/payment-review/casework.yaml) project is
the equivalent source-independent approval example. It owns the payment policy
and producer binding while its
[`runtime.example.yaml`](examples/payment-review/runtime.example.yaml) binds the
logical completion destination. The payment application still retrieves the
result and performs its own guarded, idempotent release. The completion event is
only a wake-up signal. The PostgreSQL fixture proves direct polling, lost
acknowledgement and receiver-restart recovery, expired-feed-cursor recovery,
and an exact source-owned release receipt without a BReg dependency.

`terminalDays` bounds producer-visible results. `accountabilityDays` independently
bounds protected accountability state and must be at least as long. Result-feed
and history cursors are bound to their caller and query context. After result
expiry, Casework erases request, context, result, history, notes, drafts, tasks,
and replay response payloads while retaining only the bounded tombstone needed
to prevent unsafe idempotency-key reissue until accountability expiry. The
producer and initiator identities are kept as request-bound sha256 tombstones for the
same period, so either one still receives `410` rather than `404` for an
expired request.

## Absence cover and explicit assignment

The Administrator directory response is one consistent snapshot of its revision,
teams, memberships, and served queues. Its serialized JSON is limited to 2 MiB.
Bootstrap and team updates that would exceed this aggregate limit are refused
with `request.invalid` before committing any change.

The authenticated directory API lists and mutates absence records. Staff can
manage their own absence when the cover is staff in the same team. Supervisors
can manage staff they currently supervise, and Administrators can manage any
directory staff. The ordered list returns pages of at most 1000 records and 2 MiB; use
`limit` to request fewer records and follow `nextCursor` until it is absent.
A page may contain fewer records than requested to stay within its byte limit.
The 15-minute cursor is bound to the caller, selected profile, role, page size,
and directory revision. Every page checks current authority. If the directory
changes or the cursor expires, restart the list without it. Every record uses
a start-inclusive, end-exclusive UTC period.
Casework refuses an invalid period, self-cover, overlapping absences for one
person, or a cover cycle with a value-free 422 problem. Writes require the
loaded directory revision in `If-Match` and an `Idempotency-Key`.

Administrators create or replace one team's staff, supervisors, and served
queues under the loaded directory revision. A served queue can belong to only
one team; remove it from the current team before assigning it elsewhere.
Each membership may carry a nullable display name for directory and scoped
target views. Accountable actor identities remain issuer-qualified principals
without display names.
Authority changes take effect immediately. Bounded maintenance releases held
items whose holder is no longer eligible and records visible lifecycle events.
Items with unresolved source attempts remain held for a later retry. The
directory response contains no work-item identifiers, and Administrator status
does not grant item payload access.

Supervisor profiles can assign visible work in a queue they currently serve. A
current Staff holder can delegate it. Casework resolves
active absence cover at mutation time and records the assignment owner, acting
person, and traversed absence ids. If the chain ends without an eligible staff
member, the item remains open in its serving queue with
`staffingDiagnostic: no_cover_available`; this staffing state is returned on
the item rather than as a problem response. A source-backed item requires
`Registry-Source-Profile`. Unified review-task assignment and delegation use
the `/v1/review-tasks/{taskId}` routes and apply the same current membership,
queue-service, reviewer-exclusion, and source-context authority checks.

Caseload movement is a review-then-apply operation for Supervisor profiles in
currently served queues. Preview returns only caller-visible items held by the
named person, optionally limited to one queue, and silently omits concealed or
denied source items. Its 15-minute cursor is bound to the actor, selected
Casework profile, optional source profile, and exact movement. Apply accepts 1
through 100 distinct reviewed item ids with their expected revisions and one
`Idempotency-Key`; it has no global
`If-Match`. Each selection is processed atomically and returns `moved`,
`not_visible`, `not_eligible`, `attempt_in_progress`, or `conflict`, so one
item cannot turn an undisclosed or stale item into a request-wide disclosure.

## Authored routing and clocks

A source request can name up to 32 projected logical fields, up to 64 ordered
routing rules, one optional `displayReference` field, and one clock. The
display reference must name a source-owned string field. Casework retains its
current value only as an exact, case-sensitive inbox lookup candidate, and
releases it only when the current caller's source read discloses the same
value. Missing or null values remain absent. A rule records an id and operator-facing
`because`, matches review or apply activity, an optional review stage, and up to
16 field predicates, then selects a declared queue. Predicates are closed to
`equals` or `oneOf`; a `oneOf` list contains at most 32 distinct JSON values.
The first matching rule wins, and the request's queue remains the fallback.

`caseworkctl source add` validates projected logical field ids and predicate
values against source-owned field schemas. Its generated BReg reader retains
only `get` and `list`. The record reference is always readable; only the exact
configured projection fields and `review_state` are added to request reads.
Lifecycle event projection remains record-only. Projection supplies bounded
routing facts to Casework. It does not grant display, mutation, decision, or
application authority to a Casework caller.

Source-backed inboxes accept one selector: either the three-part source subject
or an exact `reference` of at most 512 Unicode scalar values with no control
characters. The `sort` parameter is closed to `due`, `age`, or `type`; `due`
is the default. Cursor context binds the selector by a one-way reference hash
and the selected sort. Unified review tasks use their own bounded task list and
do not participate in source work-item selectors or sorts.

`GET /v1/work-items/next` returns the same `WorkItemPage` envelope with at most
one item. Empty `complete` and `budget_exhausted` pages are successful `200`
responses and retain `servedQueues`; callers follow `nextCursor` when present.
Its opaque cursor is bound to the actor, both selected profiles, optional queue,
the next-item feed, and fixed `due` ordering.

`CaseworkProject` accepts at most 16 named calendars and 32 named clocks. A
calendar declares an IANA timezone, one or more distinct working weekdays, and
a holiday-set id. Holiday dates and their immutable revision are supplied as a
separate live document; they are not embedded in deployed policy. A subject
clock uses `firstSubmittedAt`, completes on `reviewCompleted`, and pauses only
while `awaitingApplicant`. An activity clock uses `stageEnteredAt`, a calendar,
1 through 3650 working days, a local `HH:MM` due time, and optional at-risk,
reminder, and due-step policies. Each reminder and at-risk offset selects an
earlier working date at the same local due time. The due-date count excludes
the anchor's local date and skips non-working weekdays and holiday dates.

Activity clocks accept at most eight reminders and eight due steps. A due step
records a bounded reason and reassigns to a declared queue. These authored
types and their calendar evaluator are maintained independently of runtime
scheduling, so a deployment must not infer that a configured clock ran without
a recorded runtime occurrence.

A paused source clock does not make an item overdue through the passive
queue-age target. A separate clock occurrence that is still running keeps its
own deadline in effect.

The authenticated service description includes authored calendars and clocks
for Staff, Supervisor, and Administrator profiles so an operator can inspect
the policy referenced by source requests and live occurrences. Requester
profiles receive empty calendar and clock lists. Description data grants no
item or source authority.

Staff and Supervisor profiles can read up to 32 clock occurrences for one
currently visible source-backed item through
`GET /v1/work-items/{itemId}/clocks`. This read requires the matching
`Registry-Source-Profile`. Each occurrence exposes its state, pinned policy
digest, and separate calculation and recompute generations.

Administrator profiles publish immutable holiday-set revisions with an
`Idempotency-Key` and can read a named revision. An exact repeat is idempotent;
different content for an existing revision returns `precondition.failed`.
Changing a holiday revision does not silently rewrite active clock deadlines.
The Administrator previews and applies changes in batches of at most 100,
repeating those two operations until every active occurrence is pinned to the
selected immutable holiday revision. The preview records each expected
calculation generation and is bound to the actor and selected profile for 15
minutes. Applying the reviewed preview requires an `Idempotency-Key` and checks
all generations atomically. An expired preview returns
`clock.recompute-preview-expired`; create and review a new preview before
applying. An already-applied preview or changed generation returns
`precondition.failed`.

The maintained `examples/multi-stage-routing-clocks` project keeps this full
authoring path source-controlled without changing either starter. It contains
the exact imported source descriptions, a governed `region` projection and
two-stage routing rule, subject and activity clocks, a pinned external holiday
revision, and controlled fixtures. Run its offline checks with:

```sh
caseworkctl check products/casework/examples/multi-stage-routing-clocks
caseworkctl explain products/casework/examples/multi-stage-routing-clocks
caseworkctl simulate products/casework/examples/multi-stage-routing-clocks \
  --fixture products/casework/examples/multi-stage-routing-clocks/simulations/friday-review.yaml
caseworkctl simulate products/casework/examples/multi-stage-routing-clocks \
  --fixture products/casework/examples/multi-stage-routing-clocks/simulations/resubmitted-response.yaml
caseworkctl test products/casework/examples/multi-stage-routing-clocks
caseworkctl package products/casework/examples/multi-stage-routing-clocks \
  --output ./casework-policy-package
```

## The state machines the runtime enforces

`check` and `explain` report a project. The two state machines underneath it
belong to the runtime, not to any project, so they are reported on their own:

```sh
caseworkctl lifecycle
```

It names no project and reads none. The report carries the occurrence
lifecycle (the states an item in a queue moves through, and the events that
move it) and the review request lifecycle (a request in `reviewing`, the two
decision steps that leave it there, and the outcomes it settles into). Each state reports whether it is initial, terminal,
or unreachable, and how many transitions enter and leave it, all derived from
the transition table rather than declared alongside it. The occurrence table
is generated by running the runtime's own reducer over every state and event
pair, so it cannot describe a transition the runtime does not make.

Each edge's `guard` states only what the state machine itself checks. What the
runtime checks around that transition, from the caller's authority over the
queue to the revision compared against the locked row, is reported once per
machine as an ordered `enforcement` list: each layer names where the runtime can
refuse and which events it runs for. A layer is a named refusal point, not an
enumeration of the checks made there.

Not every decision settles a request. An approval that leaves the active stage
short of its required approvals is recorded and moves no stage, and an approval
that meets them while a later stage exists advances the stage; both return the
request to `reviewing`, and the report carries them as their own edges.

Which decision outcome a given review reaches, one of `approved`, `rejected`,
`changes_requested`, or `answered`, is a policy decision, made by the project's
stages, quorum, and exclusions. The other two terminal states are not policy
decisions: `cancelled` is the requester withdrawing their own request, and
`superseded` is applied automatically to a request still in `reviewing` when
the same admitted producer creates a replacement for the same subject and
policy. Neither consults a stage, a quorum, or an exclusion. This report describes the shape available to
every project, not the path one project takes.

## BReg change-request checkpoint

The original BReg starter supports one source, one review stage with one
required approval, one default queue, manual application, and a passive
48-hour target measured from first observation.

Start with authored inputs and inspect every source-side change before writing
it:

```sh
caseworkctl init ./casework --template professional-review
caseworkctl source add ./registry \
  --project ./casework --source-id professional-licences
caseworkctl source add ./registry \
  --project ./casework --source-id professional-licences --apply
caseworkctl check ./casework
caseworkctl test ./casework
```

`source add` drives the same-version public `bregctl check` and `bregctl explain
change-requests` interfaces. Preview reports the exact local BReg event and
read-only service grant additions plus the authority and optional executor runtime candidates. Apply
checks a staged copy before changing the authored registry, writes the imported
source description and runtime candidate, and checks BReg again. It does not
activate a package, provision an identity provider, or infer authority from the
imported metadata. Existing authored content is retained and conflicting ids
are refused.

`check` and `test` are offline. Check prints effective inbox limits and the
passive target default. When source metadata has been imported, it checks the
Casework approval policy, producer admission, routing field schemas, and selected
application contract. Test evaluates maintained synthetic fixtures against the
same effective inputs.

Package reviewed production policy into a new directory:

```sh
caseworkctl package ./casework --output ./casework-policy-package
```

The package contains only `casework.yaml`, its exact declared source
descriptions, and `casework.package.json`. The v1alpha1 manifest records the
policy digest and a sorted path, SHA-256 digest, and byte count for every
included file. Keep operator bindings and secrets outside the package. In the
production runtime configuration, set `package.root` to the absolute path of
the installed package directory. The runtime selects only the fixed
`casework.yaml` inside that directory. The service requires and verifies the
adjacent manifest when `listener.tlsTermination` is
`operator-controlled-upstream`. Local `development-loopback` can use the
authored project directory as `package.root`. `source add --apply` updates reviewed authoring
inputs; it does not activate a production package. The deployment operator
installs and atomically selects the reviewed package, then restarts or rolls out
Casework. Activating a new package does not rewrite running clock occurrences;
each keeps its pinned clock policy and calculation. Holiday changes use the
Administrator preview-and-apply flow described above.

The source-backed starter can use the explicit local configuration in
[Source-backed development](DEV-SOURCES.md). Every declared source still needs
a running source system with its own access profiles. For a deployment, follow
[Deploy Registry Casework](../../docs/site/src/content/docs/operate/casework.mdx)
to install the package, runtime configuration, and credentials. The deployment
runtime applies migrations and serves the package through the `casework`
binary:

```sh
casework --runtime-config /etc/registry-casework/runtime.yaml migrate
casework --runtime-config /etc/registry-casework/runtime.yaml serve
```

After the Administrator establishes the directory, check the same deployed
package and runtime configuration:

```sh
caseworkctl doctor --runtime-config /etc/registry-casework/runtime.yaml
```

Doctor distinguishes configuration, database, source, issuer, and directory
readiness. Directory readiness requires a serving team for every declared queue.
Directory setup is an ordinary authenticated Administrator API call;
administrator status does not grant BReg review or application authority.

The `casework` runtime configuration uses `apiVersion:
registry.registrystack.org/casework-runtime/v1alpha1` and `kind:
CaseworkRuntimeConfig`. Its package, file-secret, and audit paths are absolute.
Each provider is explicitly enabled. A `secret:env/NAME` reference resolves
only when `secretProviders.environment: {}` is also declared. The maintained
example is [`runtime.example.yaml`](examples/professional-review/runtime.example.yaml);
the complete field contract is in [RUNTIME-CONFIG.md](RUNTIME-CONFIG.md).

Every credential in the runtime file is an exact `secret:env/NAME` or
`secret:file/name` reference. Casework reads no other form and accepts no
inline value. A file reference names one path component under
`secretProviders.file.root`, and the opened file must be a regular file owned by
the runtime user, with mode `0400` or `0600`, and exactly one hard link. Every
resolved value, from either provider, must be non-empty text of at most 64 KiB
containing no NUL byte, so binary key material has to be encoded as text before
it is stored. Generate the audit journal secret as hexadecimal text:

```sh
umask 077
printf '%s' "$(openssl rand -hex 32)" > secrets/casework-audit-key
chmod 0400 secrets/casework-audit-key
```

A refused reference names itself and the rule it broke. It never carries the
resolved value.

The `casework` runtime serves plain HTTP behind operator-controlled TLS
termination. Runtime configuration must declare
`listener.tlsTermination: operator-controlled-upstream`;
`listener.networkExposure` defaults to
`private-address`, which accepts loopback and private addresses and rejects
public and wildcard binds. A container that needs a wildcard bind must declare
`listener.networkExposure: container-private` and keep the published listener on a
private container network. Browser requests go to the App Kit host, which calls
Casework server to server, so the Casework API does not enable CORS. Apply HSTS
on the proxy's TLS responses. The runtime applies its remaining security
headers and `Cache-Control: no-store` before returning a response.

For direct local development without a proxy, declare
`listener.tlsTermination: development-loopback`. That mode accepts only a loopback
listener with `listener.networkExposure: private-address`; it cannot be combined with a
private LAN address, a wildcard listener, or `container-private`.

Project validation requires unique source IDs. Each required scope is a
1–256 byte OAuth scope token using the RFC 6749 character set; empty scope
values and embedded whitespace are refused before packaging.

Each access profile must also require a scope unavailable from the combined
scopes of every other profile at the same or a lower role. Profiles may share
common scopes when each has its own scope discriminator. This keeps a token
with several valid lower or peer grants from selecting another profile's
identity or authority, including authority pinned to an existing review request
under an earlier policy. A higher-role credential may explicitly include a
lower profile's required scopes when it is intended to select that profile.

Casework accepts Administrator, Supervisor, and Staff credentials only when
the trusted issuer asserts the configured human identity claim. The operator
binding defaults to `humanIdentity: {claim: registry_actor_kind, value: human}`.
Configure the issuer to add that exact assertion only to interactive human
sessions. Requester and other service tokens can omit the claim or assert
another string such as `service`. Requester admission is exempt from the human
assertion check, and any human assertion on that token adds no Staff,
Supervisor, or Administrator authority. A missing, different, or non-string
claim is refused for a human role even when the token has valid Casework scopes
and names a directory member. Casework does not infer a human actor from a
subject, client identifier, or scope. This boundary relies on the configured
trusted issuer to classify sessions correctly.

`authentication.oidc.jwksSource` defaults to discovery: Casework reads the
issuer's metadata document at startup and follows its `jwks_uri`. Declare the
static alternative instead when the runtime cannot reach that document, when the
deployment is air-gapped, or when a test issuer's keys are pinned by hand:

```yaml
authentication:
  oidc:
    jwksSource:
      kind: static
      documentRef: secret:file/jwks.json
```

The referenced document is an ordinary JWKS holding uniquely named asymmetric
keys. A symmetric key, an empty key set, a missing or repeated `kid`, and a
document that is not JSON are all refused at startup. A static source performs
no rotation of its own, so rolling a signing key means replacing the referenced
document and restarting Casework.

The generated source reader has only BReg `get` and `list`, reads the target
record reference plus explicitly configured routing and display reference
fields, requests no reviewer reason fields, and carries no decision or
application operation.
Human review and application calls use the person's token and explicitly
selected BReg profile. Every promoted decision action and the apply action
accept a bounded reason, and the registry records the remark beside the action
it executes. A source that does not accept a reason on an action is refused as
`request.reason-unsupported` before preparing a durable source attempt.

Synchronization orders observations by the physical BReg record revision. At
the same revision, a changed HTTP representation ETag refreshes the existing
occurrence, including attachment verification changes. The representation ETag
is an equality check, not an ordering value or an action precondition. Periodic
readback repairs missed events while preserving claims, first-observation
timing, and unresolved action recovery.

Pending readback reserves batch capacity for both never-attempted subjects and
expired retries, then fills unused capacity from either group. Retries run in
oldest-attempt order, so sustained fresh arrivals do not prevent recovery.
Concealed or unavailable subjects keep their retry lease without repeatedly
taking priority over later work. Active items must
match the current source revision, proposal version, integrity, and binding
generation before offering coordination or decision actions. When that binding
moves, a caller-owned live attempt remains visible for recovery with no actions.
A successful action can also return or replay its completed receipt before
readback finishes when the current source binding exactly matches that receipt
within the same generation. The response retains the synchronizing item's local
binding and offers no actions.
Completed, cancelled, and superseded occurrences remain readable under current
source disclosure within the same source generation, with their retained
binding and no actions.

Source-backed retention is an explicit operator decision for one exact source
request. `caseworkctl retention erase PROJECT [--runtime-config FILE] --source-id ID
--request-kind KIND --request-id ID` previews a count-only report under
migration database authority; repeat it with `--apply` only after review. Apply
removes local payload copies and cancels local clock work while retaining
bounded tombstones. A pending or uncertain source attempt blocks erasure until
it is recovered or settled. The command makes no BReg call and does not erase
the external audit JSONL file.

Settling an uncertain source attempt is an explicit operator decision for one
attempt whose outcome recovery cannot observe. `caseworkctl attempt settle
PROJECT [--runtime-config FILE] --attempt-id UUID --outcome applied|not-applied
--reason TEXT --decided-by TEXT` previews the settlement under migration
database authority; repeat it with `--apply` only after the source owner has
confirmed the outcome. Only an uncertain attempt whose execution lease has
expired can be settled. `not-applied` refuses the attempt and returns the work
item to its holder; `applied` completes the attempt without a source receipt and
leaves the work item synchronizing until the next source observation. Apply
records an `attempt_settled` history event with the attempt, binding reference,
operation, outcome, reason, and decider, and no actor, in the same transaction
as the state change. The command makes no BReg call.

Only the actor who started a pending attempt can recover it. When that actor
cannot, `caseworkctl attempt mark-uncertain PROJECT [--runtime-config FILE]
--attempt-id UUID --reason TEXT --decided-by TEXT` previews marking the attempt
uncertain under the same migration database authority, and `--apply` records
it. Only a pending attempt whose execution lease has expired can be marked.
Apply rotates the execution token to fence the original executor, leaves the
work item synchronizing, and records an `attempt_uncertain` history event with
no actor whose detail carries the attempt, binding reference, operation,
`operatorReason`, `decidedBy`, `originalActor`, and `originalProfileId`. The
marking decides no source outcome and makes no BReg call; settle the attempt
afterwards.

A validated refusal from the first BReg action attempt keeps its source class.
Invalid action input returns `request.source-rejected`; a missing bound record
returns `source.record-missing`; and a refused reviewer binding returns
`source.reviewer-not-authorized`. A stale action remains
`work-item.not-offered`. Each problem uses a static detail and returns the item
to its holder without leaving an uncertain attempt.

The HTTP contract is generated deterministically from the Rust-owned problem
catalog and per-operation response table. The generator also checks the exact
router inventory, header constants, request extraction shape, success statuses,
and serialized DTO fields before it writes the document:

```sh
python3 products/casework/scripts/generate_openapi.py
python3 products/casework/scripts/generate_openapi.py --check
```

The local product wrapper runs that OpenAPI drift check, the dependency guard,
every product script test, and both maintained offline authoring journeys.
Build `caseworkctl` first or set `CASEWORKCTL_BIN`:

```sh
products/casework/scripts/check-checkpoint.sh
```

The dependency-direction guard reads Cargo metadata, including transitive
dependencies:

```sh
python3 products/casework/scripts/check_dependency_direction.py
python3 -m unittest products/casework/scripts/test_dependency_direction.py
```

The PostgreSQL checkpoint tests deliberately require **disposable** databases.
They reset the schemas they use and must never point at retained operator data.
The following operator-supplied variables select the maintained suites:

| Variable | Suite | Database |
|---|---|---|
| `CASEWORK_TEST_DATABASE_URL` | `--test postgres_transactions` | Its own: the suite resets `public` |
| `CASEWORK_VISIBILITY_TEST_DATABASE_URL` | `--test service_visibility` | Its own: the suite resets `public` |
| `CASEWORK_SOURCE_RETENTION_TEST_DATABASE_URL` | `--test source_retention_postgres` | Its own: the suite resets `public` |
| `CASEWORK_CLOCK_TEST_DATABASE_URL` | `--lib clocks::tests::source_clocks_survive_restart_and_preserve_subject_budget` | Its own: the test resets `public` |
| `CASEWORK_REVIEW_TEST_DATABASE_URL` | `--test review_postgres --test review_http --test review_payment_fixture_postgres` | May be shared: each fixture creates a unique schema |
| `CASEWORK_REVIEW_MIGRATION_TEST_DATABASE_URL` | `--test review_migration_postgres` | May be shared: the fixture creates a unique schema |
| `CASEWORK_ASSIGNMENT_TEST_DATABASE_URL` | `--test assignment_postgres` | May be shared: the fixture creates a unique schema |
| `CASEWORK_ROUTING_TEST_DATABASE_URL` | `--test routing_postgres` | May be shared: the fixture creates a unique schema |
| `CASEWORK_INBOX_TEST_DATABASE_URL` | `--test inbox_ordering_postgres` | May be shared: the fixture creates a unique schema |

The first four suites run `DROP SCHEMA public CASCADE`, so each of those four
variables must resolve to a database no other suite uses. The remaining suites
create a per-fixture schema and set `search_path`, so several may resolve to one
disposable database. A missing variable fails visibly rather than silently
skipping the required proof.

Create the databases, export the URLs, and enable the `postgres-test` feature:

```sh
export CASEWORK_TEST_DATABASE_URL=postgresql://localhost/casework_transactions_test
export CASEWORK_VISIBILITY_TEST_DATABASE_URL=postgresql://localhost/casework_visibility_test
export CASEWORK_SOURCE_RETENTION_TEST_DATABASE_URL=postgresql://localhost/casework_source_retention_test
export CASEWORK_CLOCK_TEST_DATABASE_URL=postgresql://localhost/casework_clocks_test
export CASEWORK_REVIEW_TEST_DATABASE_URL=postgresql://localhost/casework_review_test
export CASEWORK_REVIEW_MIGRATION_TEST_DATABASE_URL=postgresql://localhost/casework_review_test
export CASEWORK_ASSIGNMENT_TEST_DATABASE_URL=postgresql://localhost/casework_review_test
export CASEWORK_ROUTING_TEST_DATABASE_URL=postgresql://localhost/casework_review_test
export CASEWORK_INBOX_TEST_DATABASE_URL=postgresql://localhost/casework_inbox_ordering_test
cargo test -p registry-casework --features postgres-test --test postgres_transactions --locked
cargo test -p registry-casework --features postgres-test --test service_visibility --locked
cargo test -p registry-casework --features postgres-test --test source_retention_postgres --locked
cargo test -p registry-casework --features postgres-test --lib --locked \
  -- --exact clocks::tests::source_clocks_survive_restart_and_preserve_subject_budget
cargo test -p registry-casework --features postgres-test --locked \
  --test review_postgres --test review_http --test review_payment_fixture_postgres \
  --test review_migration_postgres --test assignment_postgres --test routing_postgres
cargo test -p registry-casework --features postgres-test --test inbox_ordering_postgres --locked
```

The maintained BReg, payment, and standalone review examples have one aggregate
non-browser proof. It also runs the owning Casework and BReg configuration,
runtime-schema, and retention-compatibility checks. The database must be
explicitly disposable; every included suite creates its own schema:

```sh
CASEWORK_REVIEW_EXAMPLES_DATABASE_URL=postgresql://localhost/casework_review_test \
  products/casework/scripts/check-review-examples.sh
```

Install the kit dependencies and browser from the [demo prerequisites](demo/README.md),
then run the automated technical checkpoint with the matching App Kit checkout:

```sh
products/casework/demo/run.sh \
  --app-kit-worktree /path/to/registry-app-kit \
  --evidence-dir /path/outside/product/checkouts/checkpoint-evidence
```

The verifier builds the current sources and local client candidate, starts
isolated services, and exercises the authenticated journey against BReg,
PostgreSQL, and the App Kit host. It requires Docker, Rust, Node.js, and Python
3. Keep both source trees unchanged during verification. Store the evidence
outside every Git repository. Automated results do not establish the value
checkpoint or replace its human comparison of the interface and first-use
experience.
