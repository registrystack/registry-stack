# Coordinator product contract

Registry Coordinator is an optional Rust service for authenticated admissions of reviewed,
finite, acyclic workflows. One service and PostgreSQL 17 or newer are sufficient. Maintained
public clients reach downstream products over HTTP; each product retains its authorization,
data, and effect ownership. Coordinator owns durable progress, prepared commands, waits, and audit.

## Execution and authority

A `CoordinatorProject` has one `workflow` and optional reusable `contracts`, `types`, `functions`,
and `operations` assets. `project.id` names the Workflow and `project.version` is its human release
label. A compiled `workflowRevision` pins execution semantics independently of presentation titles
and descriptions. Imported contracts are local generated public artifacts, not runtime discovery.

A Function declares `runtime`, `source`, `entrypoint`, named `inputs`, and `output`. The bounded
pure Rhai profile takes one typed object of named inputs and returns one typed value. The host
checks both schemas and enforces operation, call, expression, string, array, map, and source limits.
Explicit limits can only narrow those ceilings. Functions cannot obtain credentials, access a
clock, filesystem, network, or database, or construct additional workflow steps.

The profile's callable names are the interpreter's own calls, the arithmetic, logic, string,
array, map and iterator packages, the number helpers `parse_int`, `parse_float`, `to_int`,
`to_float`, `sqrt`, `floor`, `ceiling`, `round`, `int`, `fraction`, `is_nan`, `is_finite`,
`is_infinite`, `to_degrees`, `to_radians`, `PI` and `E` (the arithmetic package adds `abs`, `sign`,
`min` and `max`), and `add_seconds` and `seconds_between`. The trigonometric, hyperbolic,
exponential and logarithmic functions are not available because their results can differ by host.
`replace` and `pad` are the host's own bounded versions: each refuses a result over the string limit
before building it, and `pad` refuses an empty padding string. A result that holds NaN or an
infinite number is refused with `function.execution`. Check
reports a call to any other name as `coordinator.function.unknown-call` at its position in the
Function source, unless the source defines that name. Calls are matched by name only: a wrong
argument count still fails when the Function runs. The check is an authoring aid, not a security
boundary: the engine still refuses any name it lacks when the Function runs. It also reads a string
literal given to `Fn`, `is_def_fn` or an array method such as `map` as a function name, and skips a
method call whose name the source also uses as a map key or property. `coordinatorctl explain functions` prints the
names, the interpreter ABI and the limits. The interpreter ABI names the helper set, so a frozen
definition from an earlier ABI is refused with `definition.abi` and the project is re-authored.

An Operation alias binds one exact versioned host operation to a logical runtime connection.
The [generated operation catalog](generated/operations/README.md) owns transport, preparation,
effect classification, recovery, and completion contracts. A Workflow sequences `call`, `choose`,
`wait-until`, `wait-for`, and `finish` steps with typed mappings. Mappings read input, available
prior step output, or literals; construct fields; or invoke a named Function with `inputs`.
The compiler resolves schema references and proves data availability on every route. Computed
commands are validated again before preparation, saving, or dispatch. Invalid commands report a
bounded `failurePath` without the submitted value.

A `fields` mapping builds an object member by member. Each member is a reference (`input`, `step`
or `literal`) or itself a `fields` mapping, so a Workflow builds a structured operation input, such
as a Proposal's Action input or a read-in-force `subject`, without a Function. Nesting reaches a
depth of 4, counting the outermost mapping as 1, and the whole mapping holds at most 64 members
across all levels; a nested object counts as one member, and so does each of its own members. A
nested member holds only references and further `fields` mappings, never a Function: compute such
a value in an earlier step and reference it. Member names follow the same rule at every level.
`wait-until`, `choose` and Function `inputs` still take references only. Compilation refuses a
fifth level with `mapping.fields-depth` and a 65th member with `mapping.fields-count`, each at the
member's path. The compiler checks every member against the operation input schema at that
member's path, and the built object is validated again before preparation, as for a flat mapping.
Service Studio's catalog forms write nested `fields` from an operation's input schema and read
them back in the same form.

A `choose` step routes on one mapped string with a case for every value it can read, or on a
`compare`. A compare has exactly one of `all` or `any`, each a list of 1 to 16 conditions. A
condition names a `value` reference and exactly one test: `equals` and `oneOf`, spelled as in
Casework routing, or `less`, `greater` or `present`. `less` and `greater` take a number, or a
calendar date when the reference's schema declares `format: date`; compilation refuses them on
any other type. The cases are exactly `matched` and `unmatched`. Conditions run in order and stop
at the first decisive one, so `present: true` before a numeric test guards an optional value. A
missing or wrongly typed value in any other test fails the run with `choice-invalid`, as a missing
case does today; it never routes silently to `unmatched`. Compare holds no Function and no clock.

Owner-generated numeric width annotations such as `int64` are accepted only on
matching numeric types. Validation intersects explicit bounds with the declared
width and the canonical safe-integer range, while retaining imported schema bytes
and their governed identity. The schema execution profile is pinned in every
snapshot; unknown formats and remote schema references remain refused.

Runtime connections form one tagged `connections` map. Supported types are `breg`,
`casework-review-producer`, `messaging`, `scheduling`, `external-http`, and `evaluation`.
Each variant owns its complete authority contract. A caller allowed to start a Workflow gains no
downstream authority. Credentials are acquired for each attempt, and each receiver checks its own
current policy. Waits, retries, restarts, and recovery never renew an approval or alter its original
principal, resource, scopes, bounds, or deadline.

## Governed Actions

`breg.invoke-action/v1` imports an exact Base Registry Engine (BReg) Action using `action.contract` and `action.id`.
Compilation pins the generated Action revision, mode, input, output, and declared refusals. The
maintained BReg client verifies current metadata without silently replacing a saved command or
condition. The operation invokes immediate Actions and returns their exact application results.
Compilation refuses a Proposal Action with `coordinator.operation.proposal-action`, and
preparation refuses one with `action-unavailable`. Proposal Actions use the
[Proposal operations](#breg-proposals-and-in-force-reads) instead. BReg decides application under
its current policy and commit-time conditions.
A notice after application is a separate `messaging.submit-message/v1` call,
authorized by Messaging. A refused notice leaves the registry application intact.

An Action call may declare `onDeclaredRefusal`. Only a validated owner-declared no-effect refusal
routes there, as `{refusalCode}`. Authentication, authorization, transport, protocol, and
preparation failures stay operational failures. A later refusal cannot settle an earlier uncertain
attempt. Success and refusal outputs are available only on their respective routes; after a join
reachable from both, the call output has no unambiguous schema and is unavailable. Without the
edge, a declared refusal fails the run with `product-refused`, like any other refusal.

## BReg Proposals and in-force reads

Five operations work with BReg Proposals and temporal records. Each Proposal operation names one
Proposal Action through `action.contract` and `action.id`, and compilation pins its revision as
for `breg.invoke-action/v1`. No operation in the catalog approves, rejects, decides or applies a
Proposal, and a catalog test holds that rule for every operation. BReg and its review authority
keep those decisions.

| Operation | Effect | Contract |
|---|---|---|
| `breg.read-proposal/v1` | read | Reads the Proposal named by input `proposalId` and declares the completion `proposal`. Use it when a person submitted the Proposal in BReg and the run started from it. |
| `breg.start-proposal/v1` | mutation, `same-command` | Starts a draft with inputs the workflow checked, for example facts read from other registries, and declares `proposal`. A person reviews and submits the draft in BReg and so becomes its initiator. |
| `breg.submit-proposal/v1` | mutation, `same-command` | Starts and submits a Proposal as two frozen BReg commands, each with its own idempotency key derived from the run's start identity and the step, and declares `proposal`. Use it only when no person started the run: an event, a schedule or a batch. |
| `breg.cancel-proposal/v1` | mutation, `same-command` | Cancels a Proposal this run started or submitted. |
| `breg.read-in-force/v1` | read | Reads the one record of a temporal Record type in force for a subject on a date. |

Each mutation sends its frozen command with the same key on every attempt, as other BReg calls
do. `breg.start-proposal/v1` and `breg.submit-proposal/v1` lift the Proposal refusal for their
own Action only. `breg.invoke-action/v1` keeps refusing a Proposal Action. Coordinator never
asserts who started a run. An initiator-excluding review policy refuses a workflow submission in
the review authority, and BReg reports it as the Proposal's `handoffRefusal`. A follow of
`breg.submit-proposal/v1` then holds the run with `proposal-handoff-refused` and shows the
allowlisted code to operators. A follow of `breg.read-proposal/v1` or `breg.start-proposal/v1`
keeps waiting and records the code in `lastObservation`, because the person who submitted cures it
by revising and resubmitting in BReg, and the refusal clears for that later submission version.

`breg.cancel-proposal/v1` is limited to work the run owns. Compilation requires its `proposalId`
input to map from the output of an earlier `breg.start-proposal/v1` or `breg.submit-proposal/v1`
step on every route, and refuses any other source with `definition.proposal-not-run-owned`. BReg
separately checks the connection profile's Cancel grant and caller ownership. Cancellation of a
Proposal a person started or submitted belongs to that person or an officer in BReg.

### The `breg-proposal` completion

`breg-proposal` is a host-owned completion kind, beside Casework `result` and the authored
`bounded-poll`. Compilation inserts the completion `proposal` for `breg.read-proposal/v1`,
`breg.start-proposal/v1` and `breg.submit-proposal/v1`, and refuses an authored completion that
tries to replace it; a start step needs no extra read step before a wait. A `wait-for` names it as
`completion: {step, name: proposal}`. The wait is keyed by the Proposal id. Scheduled reads follow
the BReg connection's `resultCheckSeconds` (60 to 86,400 seconds, default 900). The wait spaces
and budgets its reads by the deployment read floor, `minimumObservationIntervalSeconds` (default 30
seconds), as a Casework `result` wait does: its observation limit is
one read per floor interval over its timeout, plus one, and a wake-up or Check now may read
early, down to the floor, without exhausting that budget before the timeout. The step settles
only from the current Proposal Get, never from a Casework result for the Proposal subject and
never from a lifecycle event. A later `wait-for` may name the same `proposal` completion after an
earlier wait on it timed out, and observes the same Proposal afresh.

The settled output has `outcome`, `proposalId`, `submissionVersion`, `actionRevision`, the
retained `decision` (`status`, `decidedAt` and any `publicReason`), and the frozen `input` the
connection profile may read. Later steps bind to that input so they act on the record the
Proposal named. Each operation declares its own outcome set: `breg.read-proposal/v1` and
`breg.start-proposal/v1` declare `applied`, `rejected` and `cancelled`, and
`breg.submit-proposal/v1` declares those three and `returned`. An expired wait takes `onTimeout`
or reports `wait-timed-out`, as for any wait.

| Proposal read | Run started from a person's Proposal (`read-proposal`, `start-proposal`) | Run submitted it (`submit-proposal`) |
|---|---|---|
| `state: applied` | `applied` | `applied` |
| `state: rejected` | `rejected` | `rejected` |
| `state: cancelled` | `cancelled` | `cancelled` |
| `state: draft`, or `submitted` with `turn: party` | keeps waiting: the holder corrects and resubmits in BReg | `returned` |
| `submitted` with a `submissionVersion` above the one the run submitted | keeps waiting, recording the new version | `returned` |
| `submitted` with `turn: official` or `nobody` | keeps waiting | keeps waiting |
| `handoffRefusal` present | keeps waiting, recording the code in `lastObservation` | holds with `proposal-handoff-refused` |
| 404, 401 or 403 from BReg | holds with `proposal-unreadable` | holds with `proposal-unreadable` |

Route on `applied`, never on an approval. In manual application an approved Proposal is still
`submitted` until an officer applies it. A blocked application, including `package-changed` with
recovery `rebase`, is a turn change, not an outcome. For a follow of `breg.submit-proposal/v1`,
Revise or Rebase by someone other than the run ends the wait as `returned`, and that operation's
`choose` over `outcome` names all four cases. Read and start follows declare three, so their
`choose` names three. Case coverage refuses a missing case and a case the operation cannot return.
Coordinator never follows a different Proposal id.

Each read stores `last_observation` on the wait: Proposal `state`, `turn`, `submissionVersion`,
any allowlisted `handoffRefusal` code, `observedAt`, and `stateSince`, which is Coordinator's first
observation of the current state and turn and so is only as precise as the read interval. It holds
no person's name or other value, keeps only the latest read, and is deleted with the wait. BReg's
own Proposal history remains the audit trail. Inspection shows it in `waits[].lastObservation`.

### Reading the record in force

`breg.read-in-force/v1` takes `entity`, a structured `subject` of equality values on declared
fields, and a calendar `date`. It never accepts a filter string. Coordinator sends one BReg
`:as-of` read with `asOf` set to the date, an equality filter built from the subject and
`$top=2`, so BReg reads at most two rows. Only entities whose `temporal` uses date intervals are
accepted; compilation refuses other imports with `definition.read-in-force-entity`. BReg applies
the interval's own semantics, an exclusive end or an inclusive last day, as the record schema's
`x-registry-temporal` marker states; Coordinator never evaluates the interval itself.

| BReg answer | Step result |
|---|---|
| One record | Success with that record and its provenance as the output. |
| A successful read with zero records | The declared refusal `none-in-force`, routed by `onDeclaredRefusal`, which is required. |
| Two records | Holds the run with `in-force-ambiguous`; inspection names the two record identifiers and the date. |
| 401, 403 or 404 | A failure of the read through the ordinary error path. It is never `none-in-force`. |

BReg never answers a missing or empty row-boundary claim with an empty list: a missing claim is a
404 and an empty claim a 401, so a refused read cannot become "none in force". `coordinatorctl
check` warns `coordinator.read-in-force.may-be-ambiguous` unless some `temporal-non-overlap`
constraint on the entity is scoped only by fields the subject names, since otherwise BReg allows
two records for the same subject on the same date.

### Looking up a record and reading it with provenance

`breg.lookup-record/v1` finds the one record that a set of identifier fields resolves to, through
BReg's compiled `:lookup` selector. Its input is `entity` (the record-type route), `selector` (the
compiled lookup name) and `values`, a nested `fields` mapping of one to sixteen identifier fields.
Each value is text, a whole number or a flag. It never accepts a filter string, and `check`
refuses an empty or oversized `values` mapping. Coordinator sends the `:lookup` request with no
ETag. A selector that needs a verified claim and no field values cannot be reached by a service
identity, so the request is refused as `invalid-command` before BReg is contacted.

| BReg answer | Step result |
|---|---|
| One record | Success: `recordIdentifier`, string `revisionIdentifier`, `domainData` and `provenance`. |
| `lookup.unresolved` | The declared refusal `unresolved`, which `onDeclaredRefusal` may route. An unrouted refusal stops the run as `product-refused`. |
| 401, 403 or 404 (other than `lookup.unresolved`) | A failure of the lookup through the ordinary error path. It is never `unresolved`. |

BReg answers one value-free `lookup.unresolved` whether no record matched, two matched, the row is
hidden from the profile, or a claim was missing, so Coordinator cannot tell those apart and
neither can the workflow. For that reason `check` refuses an `onDeclaredRefusal` that routes
`unresolved` straight to a step that creates or changes a record (`definition.unresolved-route`):
`breg.invoke-action/v1`, `breg.start-proposal/v1`, `breg.submit-proposal/v1` and
`external.command/v1`, whose effect Coordinator cannot see. "Not found, so create" makes a
duplicate when two records match or one is hidden. The builder cost is one extra step: route to
a finish, another read or a Casework review request, and change data from a later step once a
person or that read has decided. Only the direct route is refused; a step that cannot write a
record (a Casework review request, a message, a scheduling call, a proposal cancellation) is
allowed, and so is a mutation later on the path.

`breg.read-record/v2` takes the same input as `breg.read-record/v1` and returns the same record
envelope plus a `provenance` member. `breg.read-record/v1` is unchanged, so existing bindings
keep their exact input and output. A BReg answer that already carries a `provenance` member is
refused as `invalid-response` rather than overwritten.

`provenance` holds `recordIdentifier`, `revisionIdentifier`, `etag` where BReg sends one, and
`observedAt`. `observedAt` is Coordinator's clock when the read returned, as an RFC 3339 instant
in UTC. It says when the workflow looked, not when the fact became true. A lookup's provenance
omits `etag`, because lookup sends and receives none.

`breg.read-record/v2` and `breg.lookup-record/v1` accept `record: {contract: <import>}` as
`breg.read-record/v1` does: `domainData` is limited to the record type's API names, omitted fields
are allowed and value types stay open.

Grants: `breg.lookup-record/v1` needs the BReg profile operation `lookup` and
`breg.read-record/v2` needs `get`. `coordinatorctl check` does not read BReg profiles, so a
missing grant is not found offline. It shows at run time as the failure `product-forbidden`,
never as `unresolved`.

`breg.lookup-record/v1` and `breg.read-in-force/v1` run under the connection's service identity
and take no grant. `check` refuses them on a connection that sets `taskAuthority`
(`workflow-binding`); `breg.read-record/v2` follows `breg.read-record/v1` and takes a grant on a
task-authority connection.

### Connection, codes and catalog

A `breg` connection gains two optional members. `resultCheckSeconds` spaces Proposal reads, with
the Casework bounds and default. `requestLink` is an `https` URL template with exactly one
`{proposalId}` placeholder, usually the BReg staff page for `/v1/proposals/{id}`; inspection then
offers "Open the request" for each Proposal wait. Neither is part of a live run's binding, so both
can change while runs wait. The link carries only the opaque id, which grants nothing without
BReg's own grant.

The table gives the plain sentence an operator UI shows for each code. For a run hold the engine
stores and returns only the code, and the UI maps it to the sentence; a `check` diagnostic also
carries its sentence as its `message`.

| Code | Where | Sentence shown |
|---|---|---|
| `coordinator.follow.long` | `check` warning | "This wait follows a request for more than 90 days. Long waits delay drain-based upgrades; shorten the time limit or route the timeout." |
| `coordinator.follow.timeout-unrouted` | `check` warning | "This wait has no route for a request that gets no decision in time, so the run fails with wait-timed-out. Add onTimeout." |
| `coordinator.read-in-force.may-be-ambiguous` | `check` warning | "The register allows two records in force for this subject on one date, so this read can hold the run. Add a temporal-non-overlap constraint over these subject fields in BReg, or name every field the constraint is scoped by." |
| `definition.proposal-not-run-owned` | `check` error | "Cancel only a request this run started or submitted: map proposalId from that step's output." |
| `definition.read-in-force-entity` | `check` error | "This record type has no date validity interval, so no record can be in force on a date." |
| `definition.unresolved-route` | `check` error | "A lookup is unresolved when no record matches, but also when two records match or a record is hidden from this profile, so creating a record from this route can make a duplicate. Route unresolved to a finish, another read or a Casework review request, and create the record from a later step. Step {name} ({op}) can create or change a record." |
| `mapping.fields-depth` | `check` error | "This fields mapping nests deeper than 4 levels. Flatten it, or build the inner value in an earlier step." |
| `mapping.fields-count` | `check` error | "This fields mapping builds more than 64 members across its levels. Remove members, or build part of the value in an earlier step." |
| `proposal-unreadable` | run hold | "BReg refused or concealed the request. Check the connection profile's get grant and row boundary, then retry." |
| `proposal-handoff-refused` | run hold | "The review authority refused to take the request this run submitted. A person may need to submit it; see the code shown." |
| `in-force-ambiguous` | run hold | "Two records are in force for this subject on this date. Correct the register, then retry." |
| `check.not-waiting` | HTTP 409 | "That step is not waiting." |

Run hold and failure codes stay in the closed kebab-case list; the dotted `breg.in-force.ambiguous`
spelling is not used. Doctor makes no BReg call for these waits; it adds a
`state.proposalWaitsByTurn` count of `party`, `official`, `nobody` and `unobserved` from stored
observations. A missing grant shows on the run itself as `proposal-unreadable`, or as BReg's
refusal of the start or submit step.

The generated operation catalog gains `breg.read-proposal/v1`, `breg.start-proposal/v1`,
`breg.submit-proposal/v1`, `breg.cancel-proposal/v1` and `breg.read-in-force/v1`. In outline: the
Proposal operations take `{proposalId}` or the Action's input object, built with a nested `fields`
mapping where it is structured, and return the Proposal output above; `breg.read-in-force/v1`
takes `{entity, subject, date}` and returns one Registry Record (`recordIdentifier`, string
`revisionIdentifier`, `domainData`) with its provenance: `asOf`, the date BReg echoed in the
response `meta`, and `observedAt`, Coordinator's clock when the read returned. The declared
refusal is `none-in-force`. The completion kind list gains `breg-proposal`, whose catalog
`minimumIntervalSeconds` is 30, as for Casework `result`. The catalog also gains
`breg.lookup-record/v1` and `breg.read-record/v2`, described under "Looking up a record and
reading it with provenance".

## Standalone review and named completions

`casework.submit-review-request/v1` and `casework.cancel-review-request/v1` use one configured
Casework review producer under its own service identity, with no task authority. Submission carries
the expected `PolicySelection`, subject, bounded reviewer context, and requester reference.
An ID selects the provider's current policy at first acceptance; an optional version and digest
require an exact pin. Acceptance stores a concrete `PolicyBinding`. Recovery preserves that
binding and the original selector, and results must match the accepted policy, subject, and
submission digest. Casework owns
reviewer authority and outcomes. This standalone review path needs no BReg connection and confers
no registry mutation authority.

Submission exposes the named `result` completion. Cancellation reports `cancelled`, or
`already-terminal` with the result that won the race; only `cancelled` establishes withdrawal.
Both mutations recover with the same saved request and key, without a read-only original-key
receipt. A `wait-for` names `completion: {step, name}` from an earlier accepted call on every route.
Its required `timeoutSeconds` is shorter than the run deadline. A settled result takes `next`;
timeout takes `onTimeout`, or reports `wait-timed-out`.

An optional `onCancel` takes a durable authored cleanup path. A leased read records intent and
routes when the read settles or the lease expires. Repeated cancellation preserves cleanup under
the original deadline and current downstream authority. Without that path, or after the wait
advances, ordinary cancellation stops future calls where possible. Cancellation never reverses an
accepted effect or implicitly withdraws a downstream request.

A configured Casework completion event reaches `POST /v1/review-completions`, authenticated by its
bearer token and recipient binding. The event only advances an eligible authoritative result read.
Every authentic well-formed event is acknowledged alike, regardless of a waiting run. It carries
no result authority and starts no run.

An `external.get/v1` alias can specialize its validated response and declare a named
`bounded-poll` completion. Its typed pure interpreter receives the original saved command and
latest validated response and returns `pending`, `complete` with a typed result, or a declared
`refused` code. The host owns GET transport, credentials, permitted destinations, scheduling,
correlation, and durable read budgets. External polling is independent of Casework and BReg.
Neither external operation offers an arbitrary HTTP method or a dynamic destination.

## Bounded external command

`external.command/v1` sends one POST to the single exact relative `commandPath` configured on a
runtime `external-http` connection. The runtime file owns the origin, the path, the credential,
and the size and time bounds. A Workflow supplies only the JSON object body, built by its input
mapping and checked against the operation input contract. Redirects are never followed. A
connection without `commandPath` stays read-only, and `coordinatorctl check` refuses a command
alias bound to it or to a connection of another type.

Before the first send, Coordinator freezes the command body and a request id derived from the
run's start identity and the step, and persists both. Every attempt sends that id as
`Idempotency-Key`. Automatic retry, restart, and `retry-same` send the same stored body with the
same id; no new id is minted for the step. Same-command recovery is safe only when the provider
deduplicates on that header.

The alias's required `interpret` Function receives the frozen `command` and the `{status, body}`
response, after the response is held to the alias's `responseSchema`. It returns `accepted` with
a typed result, `refused` with one of its declared codes, or `uncertain`. The accepted result is
the step output. Only a declared code routes to `onDeclaredRefusal`, as `{refusalCode}`; an
interpreter that never returns `refused` has no refusal route. Only a response whose status
Coordinator neither holds nor retries reaches the Function: a redirect, a 429 and any 5xx never
do. `coordinatorctl test` therefore refuses a scenario `response` reply with one of those
statuses at `scenario.reply`, naming the `uncertain` or `retryable` reply that models it.

The recovery class is same-command. Status 429 is trusted to mean the provider did not process
the command, and is retried under the ordinary retry-hint and spacing rules. Status 503 before
the last automatic attempt is retried the same way, but it may follow an effect, so the step stays
uncertain until a later attempt settles it: a deadline or retry limit reached first holds the run
as uncertain. A 503 whose retry could land at or after the run deadline is not retried; the step
is held as unknown at once, so `retry-same` can still send the same command with the same id while
the deadline is in the future. A `Retry-After` on either answer that is not one whole number of
seconds up to 86,400 is ignored, and the retry waits for the ordinary backoff. A connection that
could not be opened carried nothing and is retried. Once the request may have reached the
provider, a lost or broken exchange, a timeout, a redirect, any other server error, an oversize or
malformed response, a response outside the declared schema, an interpreter error, and an
`uncertain` interpretation each hold the run as uncertain. None is reported as a provider failure
or a negative business decision. The operation has no original-result receipt, so `reconcile`
cannot settle it. After an uncertain attempt, including a retried 503, a later declared refusal or
429 keeps the run held instead of routing or retrying. An accepted result is the provider's answer
as the project interprets it; Coordinator does not independently verify the provider's effect.

## Observation and uncertainty

Read observations have a persistent floor, including after restarts, wake-ups, retry, and
timeout: the deployment read floor, 30 seconds by default, for a Casework `result`, BReg
`proposal` or external `bounded-poll` read. `minimumObservationIntervalSeconds` can raise that
deployment-wide floor, up to 86,400 seconds.
Casework and BReg pending reads default to 900 seconds. The
`resultCheckSeconds` of a Casework or BReg connection accepts 60 to 86,400. An external
completion's `intervalSeconds` is constrained by the operation and deployment floor. Retry hints
can postpone observations within the host's 86,400-second ceiling. Invalid or excessive retry
hints hold the wait instead of accelerating it. Inspection exposes timing, observation
count/limit and the latest Proposal observation, without protected correlation values.

A Casework `result` or BReg `proposal` wait's observation limit is one read per deployment read
floor interval over its timeout, plus one. Scheduled reads follow `resultCheckSeconds`, which is
never below the floor, so reads brought forward by a completion wake-up or by Check now fit within the budget and
the wait still reaches its timeout route.

Check now (`POST /v1/runs/{run}/check` with the wait's `step`, or `coordinatorctl check-now --run
--step`) brings that wait's next read forward to now, or to the read floor when the last read was
more recent. It writes nothing downstream, performs no recovery, and needs the existing `inspect`
grant for the workflow; no new access action exists. It answers with the next read time and the
count and limit. A run that is not visible answers 404 `run.not-visible`, and a step that is not
an open wait answers 409 `check.not-waiting`. Every accepted Check now is audited with the caller
and the run.

Unavailable reads remain pending within the original budget. A refusal, invalid correlation, or
blocked source state stays held for investigation and recovery. None is evidence of a negative
business decision. A Coordinator timeout means the workflow stopped waiting; source-owned work
can continue. The timeout and run deadline do not reset during recovery.

Definite retryable effect responses can resend the durable original command under bounded retry
and deadline rules. An ambiguous mutation stays uncertain. Messaging submission and Scheduling
appointment creation or hold confirmation support original-key receipt reads. Scheduling hold
creation, rescheduling, and cancellation do not gain receipt evidence from a current appointment
read. Hold release is unkeyed and cannot be replayed after ambiguous dispatch. BReg Action and
Casework mutations do not gain receipt evidence from record reads or operator assertions. Lost,
missing, or expired receipts never establish absence.
`evaluation.evaluate/v1` freezes one potentially billable request. After possible dispatch,
automatic retry, same-command retry, and reconciliation cannot replay it. A completed evaluation
is reused; a pure policy interprets it before a separately authorized effect. Model confidence
is not calibrated across providers or a guarantee of correctness.

## Admission and integration

Coordinator is not a Review provider. A project that declares `workflow.review` is refused, and
the runtime serves no `/v1/review-requests` route. When a Workflow needs human review it submits
its own request to Casework under its independently registered producer identity.

An authored `workflow.eventTriggers` entry accepts a logical source, exact event type and
data-schema identity, a schema for the full event and an ordinary typed input mapping.
`POST /v1/events/{workflow}/{trigger}` accepts the shared platform HookEnvelope and v1 delivery
signature under the operator's `eventSources` key binding. The source owns event meaning and
disclosure. The receiving workflow uses the same finite execution engine and independently
authorized downstream connections as an explicit start.

The authenticated source URI, event ID and trigger bind admission independently of the local
source alias; canonical event bytes bind exact retries.
Admission, Run and durable job commit together. A repeated exact delivery recovers the same Run
before evaluating any changed mapping. Delivery attempt time must be fresh within 30 seconds;
the immutable event time may be older after an outage. Acknowledgement is an empty HTTP204 and
never a source mutation proposal. This trigger admission is distinct from the completion wake-up
route, which only advances an existing Run's eligible authoritative read.

An event workflow that writes to its own source must select meaningful state transitions and
use guards to avoid repeated fresh events. Ordinary product API calls do not propagate event
causation across products, so the envelope hop bound alone does not prevent those loops.

### Admission security coverage

These references map admission guarantees to maintained tests. They do not assert that a
particular candidate has run or passed them. The ordinary Rust test lane runs the pure checks;
`scripts/test-postgres.sh` runs the database-backed library tests and integration suites.
The native product-events journey additionally exercises a real BReg producer and Coordinator
receiver over HTTP.

| Guarantee | Owning test |
|---|---|
| A signature binds the destination, source, event contract and canonical body. | `event_trigger_tests::substituted_signature_destination_source_and_contract_are_refused` |
| Delivery attempt time is fresh; an old event commit time alone does not prevent recovery. | `event_trigger_tests::stale_delivery_noncanonical_body_and_header_body_disagreement_are_refused` and `exact_event_identity_survives_retry_replay_and_old_commit_time` |
| Concurrent delivery, restart, package activation and local source alias renaming recover one original Run; changed event bytes conflict. | `event_trigger_tests::postgres::event_admission_is_atomic_deduplicated_and_recovers_after_restart_and_activation` and `source_alias_rename_recovers_one_original_run_after_restart` |
| An admitted event grants no source mutation authority. | `breg_event_native::native_proposal_event_admits_one_run_without_conferring_apply_authority` |

The library tests live in `crates/registry-coordinator/src/event_trigger_tests.rs`; the other
targets live in `crates/registry-coordinator/tests/`. The dependency-direction and schema gates
remain the shared assurance for product independence and generated contract drift.

`POST /v1/runs` requires `workflow`, expected `workflowRevision`, `input`, and an idempotency key.
A fresh start must match the active computed revision. Recovery of an unknown admission retains
the original verified identity, key, revision, and input even after activation changes. Conflicting
reuse is refused. Existing runs retain their original protected definitions and prepared commands.
A run binds the computed revision of the reviewed package it was admitted under. The human
workflow version is a label recorded with the run and never compared, so it does not identify a
definition and a changed definition may reuse it.

`GET /v1/workflows/{workflow}` discovers the permitted active typed contract. Generated TypeScript
and Python wrappers provide typed `start`, `get`, and `cancel` through maintained public generic
clients, pin the revision, and check returned identity and declared outcome names. They add no
transport or authorization semantics. The server remains responsible for runtime schema checks.

Inspection adds accepted/unknown effects and named completion waits to step and recovery state.
Inputs, raw product responses, prepared requests, and correlation values stay protected. Public
terminal output is only the projection the reviewed Workflow declares.

## Deployment and custody

`coordinatorctl` checks, explains and tests projects offline, builds immutable
packages, plans and applies activation, and operates the authenticated API.
`coordinator` serves the activated packages without migrating at startup. Only
explicit apply resolves migration credentials. A split runtime database role
cannot migrate, activate or replace the custody markers.

Package closure and checksums, executable ABI, database identity, runtime role
and live connection compatibility are checked before execution. Apply refuses
incompatible live bindings. Health separates process liveness from readiness;
doctor reports activation, audit, recovery holds, aged work and retention counts.

Inputs, responses, prepared requests and outcomes are authenticated ciphertext,
including copies retained by Dispatch. Associated data binds ciphertext to its
database, run, purpose and step. Payload key versions have immutable registered
bytes; new versions require apply and retained versions remain available. The
separate admission key preserves command identity across payload key rotation.
Secrets are references and never belong in authored packages.

Verified caller policy and ownership govern start, progress and recovery APIs.
Operator authority is explicit. Durable audit precedes protected actions and
release of protected results. Recovery investigation references are retained as
keyed audit handles, never raw operator text. Retention erases eligible terminal
payloads while keeping spent-key tombstones. Live, uncertain and restore-review
work cannot be silently erased.

A deployment serves up to sixteen workflows, each from its own pinned package,
which is applied, upgraded, rolled back and explicitly removed on its own. One
deployment is one trust domain, so workflows that must not share connections run in
separate deployments. A start names its workflow and is admitted under that workflow's active definition, while
retained runs use their original versions. A workflow with runs that are not
terminal cannot be removed. A caller policy's `workflows` scopes its run actions
only. Deployment-wide operator actions reach every served workflow, including workflows
added later, and require `operator: true` instead of a workflow list.
`GET /v1/runs` returns at most 100 of the caller's most recently admitted runs,
newest first, from the workflows its policy lists; an operator policy lists every
owner's runs in those workflows. `limit` takes 1 to 100 and defaults to 20. The list supports `state` and `attention` filters and returns `nextCursor` when there
may be another page. `attention=true` selects effective states `attention` and `failed`;
`attention=false` excludes both. `proposal=<id>` selects the runs waiting on that BReg
Proposal, matched through the wait-key commitment, so no Proposal id is stored in clear.
`turn=party`, `official` or `nobody` selects runs whose Proposal wait last observed that turn.
Cursors carry these filters, and a cursor from an earlier version is refused. Continue with the
same filters and cursor; each page
reapplies the caller's current authority. Applications use
the authenticated HTTP API, through the maintained Coordinator client where one
fits. The Rust client and its Node.js and Python bindings are built from source;
they are not part of the unified client packages.
Refusals of that API, the request edge and the Casework wake-up route
use an RFC 9457 problem document whose `code` comes from one closed
`family.reason` vocabulary with one status each. A refusal names no submitted
value, a missing run and a run the caller may not see are the same
`run.not-visible`, and the operator fixes that `coordinatorctl` diagnostics
carry are not part of a problem. Shared Review producer routes use the same
Coordinator problem vocabulary and require the Review profile header. The shared
client accepts bounded provider-specific RFC 9457 problems without translating
them into a second problem namespace. Result lookup uses the protocol's bodyless
202 pending, 404 concealed, and 410 expired responses.

## Recovery and limits

The canonical definition snapshot is limited to 393,216 bytes across authoring,
packages and restore. `check` and `package` refuse a larger snapshot before
writing a package. Reduce schema annotations or function source when escaping
makes the canonical snapshot exceed this limit. A noncanonical snapshot must
fit both the incoming byte limit and the same canonical byte limit.

Inspection, same-command retry, authoritative receipt reconciliation and
cancellation use supported APIs. Operator text and an arbitrary receipt ID are
not evidence that an external command succeeded. Cancellation stops future
dispatch where possible and reports accepted or unresolved effects without
claiming rollback.

A restored deployment first runs in recovery-only mode and establishes a
persistent hold. The previous deployment must be externally fenced. Every
unfinished restored run requires review, including rows saved before command
preparation. Missing or expired receipts do not establish that no effect took
place. Incomplete execution history stays held; reopening unknown admissions
requires a separate explicit complete-history and fencing attestation. Complete
execution recovery may settle safe expired reads or local steps into held
failed work using their original protected definitions and commands, including
safe work already held after a lease lapsed. Calls that never prepared a
command are also eligible under the complete-history and fencing attestations,
since command preparation always precedes sending. This transition invalidates
stale worker completions and never starts work or claims success. Active
leases, prepared mutating leased or unknown calls, uncertain outcomes and
expired receipts stay protected. A prepared mutating command pending after a definite
retryable response is held as failed work, preserving its original command,
key and deadline until explicit same-command retry or cancellation. Active work
keeps its review mark so a later retryable result requires another recovery
decision before hold release. After hold release, an operator may retry the
held work within its existing deadline, or cancel it. Calls and waits retain their
deadlines; local `choose` and `finish` steps keep their existing completion
semantics. See the [deployment runbook](DEPLOYMENT.md) for the procedure and
executable restore test.

An uncertain evaluation with `hold-after-dispatch` recovery may be cancelled
and explicitly abandoned during complete execution recovery once its active
lease has ended. The protected definition and original prepared request must
match. Release rechecks eligibility and allows unrelated work to resume while
retaining `uncertain`, `cancelRequested`, the original request and spent start
identity. It never resumes the cancelled run or establishes its remote outcome.
Unknown product mutations do not qualify for this exception.

## Compatibility and verification

Protected state schema version 5 directly replaces earlier layouts. Apply and runtime access
refuse incompatible namespaces. Settle old work with its matching binary and preserve original
packages, keys, and audit until retention allows erasure, then provision a fresh namespace and
database identity. There are no legacy authoring aliases or automatic state conversions.

Offline checking and deterministic scenarios prove graph, mapping, schema, Function, and branch
behavior. Adapter HTTP checks, PostgreSQL state checks, and native service journeys establish their
own separately scoped assertions. Mock replies never prove human review or registry application.
The native service journeys compose the owning BReg, Casework, Scheduling and Messaging
services; the 961-second deferred-appointment journey checks the real long-wait boundary. They do
not establish provider delivery or distributed rollback.
See [contributor checks](README.md#verify-a-change).

Coordinator does not provide SQL steps, dynamic fan-out, arbitrary HTTP methods, automatic
compensation, or distributed rollback. Existing hooks and APIs remain available to external
orchestrators. The project, API, runtime, and deployment contracts are pre-1.0.
