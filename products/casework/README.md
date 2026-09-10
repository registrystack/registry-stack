# Registry Casework

Registry Casework gives a team one accountable inbox for source-owned work and
for small human decisions requested by another service. It supports two
standalone deployment profiles: a hosted decision needs no registry source,
while the original checkpoint connects one governed Base Registry Engine
change-request source. A project may configure either surface or both.

## Standalone hosted decisions

Create the source-free starter, then inspect its effective configuration:

```sh
caseworkctl init ./casework --template standalone-decision
caseworkctl check ./casework
caseworkctl test ./casework
```

The maintained authored form is
[`examples/standalone-decision/casework.yaml`](examples/standalone-decision/casework.yaml).
It declares one `decision` kind, one queue, its bounded JSON Schema display,
allowed outcomes, and separate terminal and accountability retention periods.
The runtime does not install this kind implicitly. Every accepted hosted item
must name a kind declared by the active project.

An operator must still configure PostgreSQL, token verification, the
Administrator, Staff, Supervisor, and Requester profiles, and a team serving
the kind's queue. The Administrator bootstraps that directory through the
authenticated directory API. A standalone deployment does not start or depend
on BReg. It supplies an API and maintained client, not a staff-facing UI or an
external-reference resolver.

A Requester is the service integration role. It creates an item with an
`Idempotency-Key`, reads, adds and lists notes, or cancels only items created
under the same issuer, subject, and Requester profile, and pages its own
terminal feed. It cannot claim or decide. Staff, Supervisor, and Administrator
remain human roles and must carry the configured human-identity assertion.
Requester admission does not require that assertion; if it is present, it adds
no human-role or decision authority.

The create body contains only the configured kind, the requester's opaque
correlation reference, and display data validated against the kind's bounded
JSON Schema:

```json
{
  "kind": "decision",
  "requesterReference": "batch-0042",
  "display": {
    "summary": "Review the 12 entries in the prepared batch",
    "reference": "batch-0042"
  }
}
```

It cannot select an actor, team, outcome vocabulary, callback, URL to fetch,
or human/service classification. A typed hosted validation failure keeps the
six-field problem body value-free and may add the paired
`Registry-Casework-Validation-Path` and
`Registry-Casework-Validation-Reason` response headers. The path is bounded to
256 characters, the reason comes from a closed enum, and neither header echoes
rejected values.

A human Staff or Supervisor profile listed by the hosted kind uses the existing
work-item list, read, claim, and release routes without a source-profile header,
reads the retained hosted lifecycle history including requester notes, then
posts a declared outcome to the hosted-decision route. Current team service is
also required. Casework pins the kind version, policy digest, display, and
outcome vocabulary when it accepts the item, so a later configuration change
does not rewrite existing work.

Requester terminal results are ordered by terminal time and stable event id.
Each result is either a completed outcome with an opaque `actorRef`, or a
cancellation with its reason. The ordinary requester response never contains
the deciding person's issuer, subject, email, display name, internal note, or
decision reason. Casework retains the raw issuer-qualified identity and staff
reason in its protected accountability state. A Supervisor who currently
leads a team serving the item's queue can resolve one completed terminal
`eventId` through the separate accountability route. That read is audited and
ends when the accountability record expires. Cancellations have no deciding
actor accountability record.

`terminalDays` bounds the requester-visible terminal feed from the terminal
time. `accountabilityDays` independently bounds protected accountability state
from the same time and must be at least as long. Cursors are bound to the
requester's issuer, subject, selected profile, and feed context for 15 minutes.
A malformed, unknown, or context-mismatched cursor returns `cursor.invalid`.
If a matching cursor expires, the API returns `cursor.expired`; restart without
a cursor and deduplicate by `eventId`. Clients must poll within the configured
terminal period because an expired item is no longer available through the
requester read, notes, staff history, or terminal feed. The runtime retention
pass removes expired terminal events and item payload state, then removes the
protected raw actor record at its later accountability expiry.

Hosted idempotency follows the same outer accountability deadline. When the
item payload expires, Casework erases the stored response and retains no
request or display payload in the idempotency tombstone. It keeps only a
request hash and hashed binding metadata. An exact retry during that remaining
period returns `idempotency.expired` with HTTP 410 so the caller can reconcile
the original operation; a changed request under the same key remains
`idempotency.key-reused`. After the accountability deadline, Casework forgets
the tombstone and the key may be reused.

## Absence cover and explicit assignment

The authenticated directory API lists and mutates absence records. Staff can
manage their own absence when the cover is staff in the same team. Supervisors
can manage staff they currently supervise, and Administrators can manage any
directory staff. The ordered list is bounded to 1000 records. Every record uses
a start-inclusive, end-exclusive UTC period.
Casework refuses an invalid period, self-cover, overlapping absences for one
person, or a cover cycle with a value-free 422 problem. Writes require the
loaded directory revision in `If-Match` and an `Idempotency-Key`.

Administrators create or replace one team's staff, supervisors, and served
queues under the loaded directory revision. A served queue can belong to only
one team; remove it from the current team before assigning it elsewhere.
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
`Registry-Source-Profile`. Omitting that header selects hosted work.

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
routing rules, and one clock. A rule records an id and operator-facing
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
The Administrator first previews at most 100 changes. The preview records each
expected calculation generation and is bound to the actor and selected profile
for 15 minutes. Applying the reviewed preview requires an `Idempotency-Key` and
checks all generations atomically. An expired preview returns
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

## BReg change-request checkpoint

The original BReg starter supports one source, one review stage with one
required approval, one default queue, manual application, and a passive
48-hour target measured from first observation.

Start with authored inputs and inspect every source-side change before writing
it:

```sh
caseworkctl init ./casework --template professional-review
caseworkctl source add ./registry \
  --project ./casework --source-id professional-register
caseworkctl source add ./registry \
  --project ./casework --source-id professional-register --apply
caseworkctl check ./casework
caseworkctl test ./casework
```

`source add` drives the same-version public `bregctl check` and `bregctl explain
change-requests` interfaces. Preview reports the exact local BReg event and
read-only service grant additions plus a runtime destination candidate. Apply
checks a staged copy before changing the authored registry, writes the imported
source description and runtime candidate, and checks BReg again. It does not
activate a package, provision an identity provider, or infer authority from the
imported metadata. Existing authored content is retained and conflicting ids
are refused.

`check` and `test` are offline. Check prints effective inbox limits and the
passive target default. When source metadata has been imported, it checks the
complete ordered staged-review policy, routing field schemas, and manual
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
production operator configuration, set `project` to
`./casework-policy-package/casework.yaml`. The service requires and verifies
the adjacent manifest when `tlsTermination` is
`operator-controlled-upstream`. Local `development-loopback` can use the
authored project directly. `source add --apply` updates reviewed authoring
inputs; it does not activate a production package. The deployment operator
installs and atomically selects the reviewed package, then restarts or rolls out
Casework. Activating a new package does not rewrite running clock occurrences;
each keeps its pinned clock policy and calculation. Holiday changes use the
Administrator preview-and-apply flow described above.

After the operator supplies the separate runtime configuration and credentials,
the local workflow is:

```sh
caseworkctl db migrate ./casework --operator ./casework/operator.yaml
caseworkctl dev start ./casework --operator ./casework/operator.yaml
caseworkctl doctor ./casework --operator ./casework/operator.yaml
caseworkctl dev events ./casework
caseworkctl dev stop ./casework
```

Doctor distinguishes configuration, database, source, issuer, and directory
readiness. Directory setup is an ordinary authenticated Administrator API call;
administrator status does not grant BReg review or application authority.

The `casework` runtime serves plain HTTP behind operator-controlled TLS
termination. Runtime configuration must declare
`tlsTermination: operator-controlled-upstream`; `networkExposure` defaults to
`private-address`, which accepts loopback and private addresses and rejects
public and wildcard binds. A container that needs a wildcard bind must declare
`networkExposure: container-private` and keep the published listener on a
private container network. Browser requests go to the App Kit host, which calls
Casework server to server, so the Casework API does not enable CORS. Apply HSTS
on the proxy's TLS responses. The runtime applies its remaining security
headers and `Cache-Control: no-store` before returning a response.

For direct local development without a proxy, declare
`tlsTermination: development-loopback`. That mode accepts only a loopback
listener with `networkExposure: private-address`; it cannot be combined with a
private LAN address, a wildcard listener, or `container-private`.

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

The generated source reader has only BReg `get` and `list`, reads the target
record reference plus explicitly configured routing projection, requests no
reviewer reason fields, and carries no decision or application operation.
Human review and application calls use the person's token and explicitly
selected BReg profile.

Synchronization orders observations by the physical BReg record revision. At
the same revision, a changed HTTP representation ETag refreshes the existing
occurrence, including attachment verification changes. The representation ETag
is an equality check, not an ordering value or an action precondition. Periodic
readback repairs missed events while preserving claims, first-observation
timing, and unresolved action recovery.

Source-backed retention is an explicit operator decision for one exact source
request. `caseworkctl retention erase PROJECT [--operator FILE] --source-id ID
--request-kind KIND --request-id ID` previews a count-only report under
migration database authority; repeat it with `--apply` only after review. Apply
removes local payload copies and cancels local clock work while retaining
bounded tombstones. A pending or uncertain source attempt blocks erasure until
it is recovered. The command makes no BReg call and does not erase the external
audit JSONL file.

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

The PostgreSQL checkpoint tests deliberately require two **distinct,
disposable** databases. They reset their schemas and must never point at
retained operator data. Create both databases, export their URLs separately,
and enable the `postgres-test` feature:

```sh
export CASEWORK_TEST_DATABASE_URL=postgresql://localhost/casework_transactions_test
export CASEWORK_VISIBILITY_TEST_DATABASE_URL=postgresql://localhost/casework_visibility_test
cargo test -p registry-casework --features postgres-test --test postgres_transactions --locked
cargo test -p registry-casework --features postgres-test --test service_visibility --locked
```

The two variables must not resolve to the same database. The transaction suite
uses `CASEWORK_TEST_DATABASE_URL`; the disclosure, authorization, pagination,
outage, and HTTP boundary suite uses
`CASEWORK_VISIBILITY_TEST_DATABASE_URL`. A missing variable fails visibly rather
than silently skipping the required proof.

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
