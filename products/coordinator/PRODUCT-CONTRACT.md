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

An Operation alias binds one exact versioned host operation to a logical runtime connection.
The [generated operation catalog](generated/operations/README.md) owns transport, preparation,
effect classification, recovery, and completion contracts. A Workflow sequences `call`, `choose`,
`wait-until`, `wait-for`, and `finish` steps with typed mappings. Mappings read input, available
prior step output, or literals; construct fields; or invoke a named Function with `inputs`.
The compiler resolves schema references and proves data availability on every route. Computed
commands are validated again before preparation, saving, or dispatch. Invalid commands report a
bounded `failurePath` without the submitted value.

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

## Governed Actions and Proposals

`breg.invoke-action/v1` imports an exact Base Registry Engine (BReg) Action using `action.contract` and `action.id`.
Compilation pins the generated Action revision, mode, review policy, application policy, input,
output, and declared refusals. The maintained BReg client verifies current metadata without
silently replacing a saved command or condition. Immediate Actions return exact application
results. Proposal Actions create a draft and return it under `proposal`.

Starting a draft, submitting a Proposal, and applying a submission are separate effects.
`breg.submit-proposal/v1` evaluates the plan, freezes the selected submission, and exposes the
named `application` completion. Draft creation has no declared-refusal route. A known no-effect
plan refusal stops the generic submission operation without application observation or a notice;
Submit exposes no Action-specific typed refusal edge.
The observer correlates the exact Proposal ID, Action ID and revision, submission version, and
effect digest. Only authoritative application evidence settles `applied`; review approval is not
application evidence. A closed Proposal settles `closed`. Blocked, mismatched, unknown, or
uncertain application state holds the wait and cannot become a terminal business-failure branch.
The original prepared command and submission identity stay fixed across recovery.

`breg.apply-proposal/v1`, `breg.retry-proposal/v1`, and `breg.cancel-proposal/v1` are explicit calls
subject to the receiving BReg policy. A Review-provider workflow may assess a Proposal, but BReg
independently decides application under its current policy and commit-time conditions.
A notice after application is a separate `messaging.submit-message/v1` call,
authorized by Messaging. A refused notice leaves the registry application intact.

An immediate Action call may declare `onDeclaredRefusal`. Only a validated owner-declared no-effect refusal
routes there, as `{refusalCode}`. Authentication, authorization, transport, protocol, and
preparation failures stay operational failures. A later refusal cannot settle an earlier uncertain
attempt. Success and refusal outputs are available only on their respective routes; after a join
reachable from both, the call output has no unambiguous schema and is unavailable.

## Standalone review and named completions

`casework.submit-review-request/v1` and `casework.cancel-review-request/v1` use one configured
Casework review producer under its own service identity, with no task authority. Submission carries
the expected `PolicyBinding`, subject, bounded reviewer context, and requester reference. Accepted
requests and results must match that exact policy, subject, and submission digest. Casework owns
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
There is no external write operation, arbitrary HTTP method, or dynamic destination.

## Observation and uncertainty

Read observations have a persistent floor of at least 30 seconds, including after restarts,
wake-ups, retry, and timeout. `minimumObservationIntervalSeconds` can raise that deployment-wide
floor, up to 86,400 seconds. Casework and BReg pending reads default to 900 seconds. Casework
`resultCheckSeconds` accepts 60 to 86,400. An external completion's `intervalSeconds` is constrained
by the operation and deployment floor. Retry hints can postpone observations within the host's
86,400-second ceiling. Invalid or excessive retry hints hold the wait instead of accelerating it.
Inspection exposes timing and observation count/limit, without protected correlation values.

Unavailable reads remain pending within the original budget. A refusal, invalid correlation, or
blocked source state stays held for investigation and recovery. None is evidence of a negative
business decision. A Coordinator timeout means the workflow stopped waiting; source-owned work
can continue. The timeout and run deadline do not reset during recovery.

Definite retryable effect responses can resend the durable original command under bounded retry
and deadline rules. An ambiguous mutation stays uncertain. Messaging and Scheduling support
original-key receipt reads; BReg Action and Casework mutations do not gain receipt evidence from
record reads or operator assertions. Lost, missing, or expired receipts never establish absence.
`evaluation.evaluate/v1` freezes one potentially billable request. After possible dispatch,
automatic retry, same-command retry, and reconciliation cannot replay it. A completed evaluation
is reused; a pure policy interprets it before a separately authorized effect. Model confidence
is not calibrated across providers or a guarantee of correctness.

## Admission and integration

A Workflow may expose the shared Review protocol with `workflow.review`. Every declared
terminal outcome maps to one explicit Review status and, where required, an outcome code.
The computed Workflow revision pins that mapping, graph, Functions and contracts; project ID
and human version identify its `PolicyBinding`. Workflow metadata returns `reviewPolicy`, or
null when Review admission is unavailable. A completed workflow is approval only when its
authored outcome maps to `approved`.

Review producer policies bind an authenticated client to its producer identity, source
namespace, profile, allowed sources and workflows. `POST /v1/review-requests` admits the exact
shared `ReviewCreateRequest` as the ordinary Run input. The request and Run share one ID and
transactional admission path. The original subject, submission digest and policy stay fixed.
Results are immutable and available for the declared `resultRetentionSeconds`, default 86400,
from completion. Cancellation cannot renew a deadline or overwrite a completed outcome.
Recovery holds also govern result release and retention. If an assessment calls Casework,
Coordinator uses its own independently registered producer and computes that downstream
submission's binding rather than forwarding the upstream producer identity.

`breg.read-review-context/v1` reads only the exact frozen Proposal context allowed to its service
assessment grant. A reviewed earlier condition is evidence of that observation, not current
commit authority. BReg rechecks its own authorization, optimistic concurrency and authored
conditions when applying. Stale conditions refuse application without changing the reviewed
submission; a revised submission requires a fresh assessment.

An authored `workflow.eventTriggers` entry accepts a logical source, exact event type and
data-schema identity, a schema for the full event and an ordinary typed input mapping.
`POST /v1/events/{workflow}/{trigger}` accepts the shared platform HookEnvelope and v1 delivery
signature under the operator's `eventSources` key binding. The source owns event meaning and
disclosure. The receiving workflow uses the same finite execution engine and independently
authorized downstream connections as an explicit start.

The source URI, event ID and trigger bind admission; canonical event bytes bind exact retries.
Admission, Run and durable job commit together. A repeated exact delivery recovers the same Run
before evaluating any changed mapping. Delivery attempt time must be fresh within 30 seconds;
the immutable event time may be older after an outage. Acknowledgement is an empty HTTP204 and
never a source mutation proposal. This trigger admission is distinct from the completion wake-up
route, which only advances an existing Run's eligible authoritative read.

An event workflow that writes to its own source must select meaningful state transitions and
use guards to avoid repeated fresh events. Ordinary product API calls do not propagate event
causation across products, so the envelope hop bound alone does not prevent those loops.

`POST /v1/runs` requires `workflow`, expected `workflowRevision`, `input`, and an idempotency key.
A fresh start must match the active computed revision. Recovery of an unknown admission retains
the original verified identity, key, revision, and input even after activation changes. Conflicting
reuse is refused. Existing runs retain their original protected definitions and prepared commands.
A changed definition under an ID and human version already used by retained history is refused.

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
`attention=false` excludes both. Continue with the same filters and cursor; each page
reapplies the caller's current authority. Applications use
the authenticated HTTP API, through the maintained Coordinator client where one
fits: `registry_stack_client::coordinator` in Rust or the `coordinator`
namespace of the unified Node.js and Python clients.
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

Protected state schema version 4 directly replaces earlier pilot layouts. Apply and runtime access
refuse incompatible namespaces. Settle old work with its matching binary and preserve original
packages, keys, and audit until retention allows erasure, then provision a fresh namespace and
database identity. There are no legacy authoring aliases or automatic state conversions.

Offline checking and deterministic scenarios prove graph, mapping, schema, Function, and branch
behavior. Adapter HTTP checks, PostgreSQL state checks, and native service journeys establish their
own separately scoped assertions. Mock replies never prove human review or registry application.
The native reviewed Proposal journey composes the owning BReg and Casework services, correlates
the exact frozen submission and authoritative application, then requests a separate Messaging
notice. Approval produces one accepted notice only after application; rejection remains held and
cancellation closes without a notice. Its disposable clock advance checks observation semantics,
while the separate 961-second deferred-appointment journey checks the real long-wait boundary.
Neither establishes provider delivery or distributed rollback.
See [contributor checks](README.md#verify-a-change).

Coordinator does not provide SQL steps, dynamic fan-out, arbitrary HTTP methods, automatic
compensation, or distributed rollback. Existing hooks and APIs remain available to external
orchestrators. The project, API, runtime, and deployment contracts are pre-1.0.
