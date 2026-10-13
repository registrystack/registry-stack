# Coordinator product contract

Registry Coordinator is an optional Rust service. It executes reviewed, finite,
acyclic YAML workflows using bounded pure Rhai functions and maintained product
clients. One service and PostgreSQL 17 or
newer are sufficient. Receiving products retain authorization and ownership of
their effects.

## Execution and authority

A workflow can read current records, wait durably until an instant or for a
review result, choose a branch, call an approved product operation and finish
with a declared outcome. The authored
package contains the graph, functions and schemas; deployment configuration
binds its logical connections to endpoints and identities.

YAML owns the finite graph, waits and the references that carry values between
steps; pure Rhai computes values and selects an authored branch. `coordinatorctl
check` fits every reference, literal and `fields` mapping to the schemas it reads
and feeds before any run. Functions cannot make calls, acquire credentials or add
runtime steps.
They read no clock: `add_seconds` and `seconds_between` compute only over the
RFC 3339 instants they are given.

The ten supported operations are `read-record`, `submit-message`,
`read-scheduling`, `read-availability`, `create-appointment`, `invoke-breg-action`,
`external-get`, `evaluate-decision`, `submit-review-request` and
`cancel-review-request`.
Messaging submission and Scheduling appointment creation support same-command
recovery and read-only original-key receipts. Base Registry Engine (BReg) action
invocation and the two Casework review operations support same-command recovery
without a read-only receipt. The four read operations can be read again.

`submit-review-request` and `cancel-review-request` act as one Casework review
producer, named by the connection, under that producer's own service identity
and with no task authority. A submission names the review kind, the subject
record with its version and digest, the context a reviewer sees and the requester's
reference; its output is Casework's acceptance. Casework decides who reviews,
what outcomes a kind allows and whether a request supersedes another; the
Coordinator adds no review semantics. A cancellation reports `cancelled`, or
`already-terminal` with the result that ended the review first; a workflow
routes on the cancel step's `/outcome`, since only `cancelled` means the
cancellation ended the review.

A `wait-for` step waits for the result of a review request an earlier
`submit-review-request` step submitted on every route to it. `timeoutSeconds`
is required and shorter than the run deadline. The step reads the result with
the producer identity when it starts, every `resultCheckSeconds` of the
connection while the review is open, and once more at the timeout. A read
that cannot get an answer before the timeout leaves the wait open and spends
no attempt; its next read follows Casework's `Retry-After`, from 30 seconds up
to `resultCheckSeconds`, and without one comes five minutes later, or after
`resultCheckSeconds` when that is shorter. A settled
result continues the run at `next` as the step's output after it matches the
accepted request, subject, policy and submission digest. The timeout continues
the run at `onTimeout`, or fails it with `wait-timed-out`. An unknown request
fails with `review-request-unknown` and an expired result with
`review-result-expired`; the run deadline still ends the run as it ends any
step. Casework may supersede a request still under review when the same
producer submits another for the same subject record and kind; the waiting
run then reads the result `superseded`.

Casework's completion event for a request reaches `POST /v1/review-completions`
on the service listener with a configured bearer token and recipient binding.
The event is a wake-up only: it brings forward the next result read of a run
waiting on that request, never sooner than 30 seconds after the previous read,
and carries no result the Coordinator acts on. Every authentic event is
acknowledged alike, whether or not a run waits on its request. No event starts
a run.

`invoke-breg-action` uses a standing BReg service identity and an explicitly
permitted profile for an immediate governed action. Its input contains `action`
and an `input` object, with no grant field or task-authority fallback. The maintained
BReg client prepares the conditional request without mutation. Coordinator saves
that preparation and original key before dispatch. Recovery checks current
metadata and fresh authority while retaining the saved request and condition
ETags. Changed contracts, stale conditions and revoked authority do not silently
produce a replacement command. An ambiguous response remains uncertain; a
record read or operator assertion cannot establish action success.

An `invoke-breg-action` call may declare `onDeclaredRefusal`. BReg returns the
typed `422 action.refused` response only after validating the code against the
active package's declared refusal catalogue and guaranteeing that the refusal
had no action effect. The maintained adapter accepts the branch outcome only
for that exact problem class with a bounded refusal code. The branch output is
exactly `{refusalCode}`. It carries no problem detail, field path,
submitted value or raw response. The call's successful receipt remains the
output on `next`. A mapping may read the receipt only on routes reached through
`next`, and the refusal object only on routes reached through
`onDeclaredRefusal`; after those routes join, the call output is unavailable
because its shape is ambiguous. Authentication, authorization, transport,
protocol and preparation failures remain call failures. Without the optional
edge, a declared refusal also stops the run as refused.

A declared refusal is checkpointed atomically with its branch target. If a
prior attempt has an unknown effect, a later refusal cannot settle that
attempt, so the original command remains uncertain and the refusal branch is
not taken. The original command and workflow deadline remain fixed. A
checkpointed result retains the existing rule that following pure `choose` and
`finish` steps may complete, while a later call or wait still observes expiry.
If cancellation wins before the refusal checkpoint, the worker records the
completion as no-effect and leaves the run cancelled.

`external-get` is a configured read boundary: operators bind a base URL, exact
paths, allowed query parameter names, optional service authorization and a local
response schema through `runtime.externalHttpConnections`. Calls can supply only
a permitted path and query values. The adapter sends GET, refuses redirects and
validates the complete `{status, body}` response. Status 429, 502, 503 and 504
are retried within the run deadline, and the workflow sees one only after the
retries run out. It provides no external write operation or receipt. Omitted
authorization means a public read.

Each run keeps its original definition and prepared commands. A repeated
idempotency key under the same verified issuer, subject and flow returns its
original run when the input matches. A conflicting input is refused. New compatible package
versions apply to new starts; existing runs keep their pinned definitions.
A workflow ID and version identify one definition throughout retained run
history, including payload-erased tombstones. Apply refuses a changed definition
under a previously used version; give that definition a new version.

Snapshots pin the capabilities of every used operation. A changed definition
digest may require a new authoring version under the same history rule.

Credentials are acquired when a call is attempted. A wait, retry or restart
cannot extend a Casework approval deadline or change its principal, resource,
scopes or bounds. Receiving products verify current authority. Standing read
authority and read-only receipt observation cannot authorize a commitment.
Preparation and dispatch remain subject to cancellation, recovery holds and the
original workflow deadline. A retry cannot renew an original approval deadline.

An accepted Messaging submission is distinct from provider delivery. A failed
connection or lost response after sending may leave the effect unknown. The
original command and idempotency key are retained for bounded recovery.
If evaluating the following wait fails, the successful call and its output stay
recorded. The run fails with `mapping-invalid`; the accepted call cannot be
replayed to repair the mapping.
A computed call input is held to its operation's input contract before it is
prepared, saved or sent. An input outside it fails the run with
`invalid-command`, and the run and step status name where in `failurePath`, an
RFC 6901 pointer into the input. The computed value is not recorded, and an
unexpected member is reported at the object that holds it.

`evaluate-decision` uses an explicitly configured System One or OpenAI Decisions
protocol binding, bounded state and typed questions. Preparation is inert; the
exact request is saved before dispatch and the validated result is committed
with the next checkpoint. Evaluation is neither a repeatable read nor a Registry
mutation. Possible dispatch marks the result uncertain. Without proven provider
replay or original-result lookup, automatic and operator replay are refused.
A completed result is reused on restart. OpenAI per-question refusal is a typed
answer. A System One HTTP refusal stops
the call; it is not a negative answer or a typed review result. A malformed or
lost reply remains an uncertain call. HTTP 429 also remains held, including a
temporary rate limit with `Retry-After`; it does not permit automatic resend.
Accepted responses require the returned model and valid provider usage metadata.
Pure workflow policy interprets results before a separately authorized effect.
Model identity and native confidence are retained without claiming immutable
weights, determinism, accuracy or interchangeable confidence calibration.

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

A deployment serves up to sixteen flows, each from its own pinned package,
which is applied, upgraded, rolled back and explicitly removed on its own. One
deployment is one trust domain, so flows that must not share connections run in
separate deployments. A start names its flow and is admitted under that flow's active definition, while
retained runs use their original versions. A flow with runs that are not
terminal cannot be removed. A caller policy's `flows` scopes its run actions
only. Deployment-wide operator actions reach every served flow, including flows
added later, and require `operator: true` instead of a flow list.
`GET /v1/runs` returns at most 100 of the caller's most recently admitted runs,
newest first, from the flows its policy lists; an operator policy lists every
owner's runs in those flows. `limit` takes 1 to 100 and defaults to 20. The list
has no paging cursor and no state filter. Applications use
the authenticated HTTP API, through the maintained Coordinator client where one
fits: `registry_stack_client::coordinator` in Rust or the `coordinator`
namespace of the unified Node.js and Python clients.
Every refusal of that API, the request edge and the review-completion route
included, is an RFC 9457 problem document whose `code` comes from one closed
`family.reason` vocabulary with one status each. A refusal names no submitted
value, a missing run and a run the caller may not see are the same
`run.not-visible`, and the operator fixes that `coordinatorctl` diagnostics
carry are not part of a problem.

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

`coordinatorctl check --project DIRECTORY` checks `workflow.yaml` and
`functions.rhai`, plus optional `runtime.yaml` and `scenarios.yaml` companions.
Every YAML or YML file in the project root must have its supported envelope
and owned filename. The check aggregates companion errors and executes valid
scenarios against the loaded workflow. It reads only the root, with at most
1024 entries; other child directories produce an incomplete-check warning.
The owned `.coordinator` state and secret directory is never traversed.
Runtime checks remain offline unless `--environment` is selected and never
resolve secret values. An explicitly supplied runtime is checked once.

Scenario files use `kind: CoordinatorScenarios` and the API version
`id.registrystack.org/formats/coordinator/scenarios/v1alpha1`. Each case has a unique local `id`. Replies name their `type`: `success` carries a
foreign JSON `value`; `retryable`, `refused` and `uncertain` carry a `code`;
`declared-refusal` carries a non-empty `refusalCode` of at most 128 characters
without control characters; `receipt-expired` has no additional members. A
declared-refusal reply is accepted only for `invoke-breg-action`. It takes the
authored refusal edge, stops as refused when that edge is absent, and leaves a
prior unknown attempt uncertain. `waits` states what each
`wait-for` step the run reaches receives: `{type: event, value}` delivers the
event when the wait starts, and `{type: timeout}` moves the virtual clock by
the step's `timeoutSeconds`. A run without `onTimeout` stops as `timed-out`,
and one whose deadline passes first as `deadline-exceeded`. Inputs, successful replies and
expected outputs are foreign JSON values, including explicit nulls, while
ordinary scenario configuration follows the shared reader rules. An omitted
expected outcome is not checked; `{type: none}` checks its absence and
`{type: named, value: outcome-id}` checks a declared outcome.
`workflowElapsedSeconds` checks elapsed workflow virtual time.

Deterministic scenario tests use the same graph and function semantics with a
virtual clock and fake product replies. They complement PostgreSQL, process
restart and native-service tests; they do not prove actual downstream effects.
After a simulated receipt expiry, the run stays uncertain. Neither `retry-same`
nor `reconcile` can consume another reply, since the supported products cannot
confirm an original command through an expired receipt. Before receipt expiry,
a successful, explicitly declared reconciliation represents authoritative
confirmation of a Messaging or Scheduling command, never a new submission.
BReg action scenarios cannot declare successful reconciliation without a
read-only action receipt contract. Reconciliation can resolve an uncertain
outcome; a definite retryable reply requires
same-command retry.

The governed-action adapter has both mock HTTP checks and explicit native
acceptance checks. The first native check observes a committed patch after response
loss, reconstructs the adapters from saved preparation, and recovers with the
same body, key and conditions. It verifies one applied record revision, the same
application receipt, fresh metadata, a real read-only profile refusal and no
receipt lookup. The second uses actual `Worker` and `Store` objects with a real
BReg action and Messaging notice. It drops the accepted notice reply, reconstructs
the objects, and resolves the notice through its exact original receipt lookup.
Neither action nor notice is repeated; duplicate start admission returns the
original run. Acceptance does not establish provider delivery. Object
reconstruction is distinct from OS-process restart, which retains separate
`process_restart` coverage. PostgreSQL worker checks separately exercise
preparation and crash durability. The separate `scripts/test-real-services.py`
journey composes BReg, Casework, Scheduling and Messaging with a persisted wait
and an actual worker restart. It also runs the reviewed-notice flow against a
real Casework review producer whose completion events wake the waiting runs;
its timeout route is proven by scenarios only.
See [the contributor checks](README.md#verify-a-change)
for the explicit helper and its two distinct disposable loopback databases.
Successful runs clean up UUID-owned fixture resources; assertion failures may
retain diagnostic Coordinator and Messaging schemas. This explicit contributor
check is not a CI gate.
Native Casework and BReg applications may compose a governed application action
with a separate optional notice through their owning APIs.

Coordinator does not add language builders, a WASM toolchain, dynamic fan-out,
arbitrary HTTP methods or SQL steps, automatic compensation, or a visual editor.
It does not promise atomic distributed revocation or rollback of accepted
effects. Existing hooks and APIs remain available to external orchestrators.
Coordinator is pre-1.0: this contract, the workflow format, the HTTP API and
the runtime configuration may still change between releases.
