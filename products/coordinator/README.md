# Registry Coordinator

Use Registry Coordinator when your institution needs a reviewed sequence of
Registry Stack calls to continue across durable waits, service outages and
worker restarts. One optional Rust service executes finite, acyclic YAML plans
with declarative mappings and bounded pure Rhai functions. PostgreSQL stores encrypted progress and
prepared commands. Receiving products retain authorization and ownership of
every external effect.

The [product contract](PRODUCT-CONTRACT.md) describes the supported product boundary; the
[deployment runbook](DEPLOYMENT.md) covers installation, authenticated access,
package activation, operation and recovery. Coordinator does not claim
distributed rollback. It is pre-1.0: the workflow format, HTTP API, runtime
configuration and deployment contract may still change, so use the binaries and
documentation of one release together.

## Create and check a project

Run these commands from the maintained Registry Stack checkout. The two binaries
separate local authoring and deployment operations from the running service.

```sh
cargo run --locked -p registry-coordinator --bin coordinatorctl -- init --directory ./my-follow-up
cargo run --locked -p registry-coordinator --bin coordinatorctl -- check --project ./my-follow-up --explain
```

For the later `coordinatorctl` commands, use the installed executable from the
[deployment runbook](DEPLOYMENT.md#install-and-package), or the same `cargo run`
prefix followed by `--`. The starter
contains `workflow.yaml`, `functions.rhai`, `runtime.yaml` and `scenarios.yaml`,
plus a `.gitignore` that keeps the local `.coordinator/` directory out of version
control. Its project id is the directory name unless you pass `--id`. Init writes into
a new or empty directory and refuses one with content. Check validates the graph,
function exports, references, input/outcome schemas, the fit of every mapping and
execution bounds without credentials, network access or database writes. Add
`--runtime-config ./my-follow-up/runtime.yaml` to check the logical bindings as well.

`workflow.yaml` is a `CoordinatorProject` document. Its `project` block names the
workflow and version, `deadlineSeconds` states a bounded integer duration, and
`functionsFile` names `functions.rhai`. Each step declares its `type`: `wait-until`,
`wait-for`, `call`, `choose`, or `finish`.

Mappings carry values between steps, and a reference names one value.
`{type: input}` reads the workflow input, `{type: step, step: read-application}`
reads that earlier call's output and `{type: literal, value: applications}`
supplies an authored JSON value. An input or step reference may add an RFC 6901
`path`, such as `/data/recordIdentifier`, to select one member. The checker
proves the referenced call completed on every incoming route. A step reference
may also read a `wait-for` step that every incoming route left through its
`next`, which holds the result the wait received. Every mapping names
its form with `type`. A call `input` or a finish `output` is either
`type: fields`, an object built member by member from up to 64 references, or
`type: function`, a pure function with up to 16 reference `arguments`.
`waitUntil` and `choose` take one reference or `type: function`.

Every call uses `next` for its successful operation output. An
`invoke-breg-action` call may also name `onDeclaredRefusal`. That edge receives
only `{refusalCode}` from a validated, package-declared, no-effect action
refusal. A step reached only through `next` can read the action receipt, and a
step reached only through `onDeclaredRefusal` can read the refusal code. At a
join reachable through both edges, the call has no single output shape, so its
output is unavailable to mappings at or beyond the join.

```yaml
read-application:
  type: call
  connection: applications
  operation: read-record
  input:
    type: fields
    fields:
      collection: {type: literal, value: applications}
      recordId: {type: input, path: /applicationId}
  next: permission
```

Check fits every mapping to the schemas it reads and feeds before any run. A path
must name a member the workflow input schema or the call's
[operation output](generated/operations/README.md) declares; beneath an open
member any path is accepted. A `fields` mapping must set every member its
operation input or outcome requires and no member it does not declare. A literal
must satisfy its member's schema, and a reference cannot read a value declared
with another type or string format. A `waitUntil` reference must read a date-time
or plain string. A `choose` reference must read a string; when its schema lists
the values, the cases must match them exactly. Each refusal names the step, the
field path, what was expected and the fix: check reports the first refusal in each
step, in step order.
The published project schema holds each `fields` mapping to its operation's
member names in an editor too.

A function's result, and a value read beneath an open member, are known only
when the run computes them. `coordinatorctl test` holds every computed call input
to its operation input and every synthetic success reply to its operation output.
The service holds every computed call input to its operation input before it
prepares, saves or sends the call. An input outside it fails the run with
`invalid-command`, and the run and step status report the RFC 6901 path into the
input as `failurePath`, never the value.

All three configuration formats use the shared strict configuration reader and carry
editor schema modelines. JSON Schema fragments and scenario payloads retain their
own JSON value semantics, including nested null values; optional configuration
members are omitted. Check reports all independent structural errors with file,
line, column and a repair action, and never repeats a value read from a file or
the environment. Some errors mask the checks that depend on them, so a repair
can reveal further errors: a file that cannot be read, or a call to an operation
Coordinator does not offer, stops the workflow checks; an undeclared start step
or transition target skips the reachability, cycle and data-flow checks;
mappings are fitted to schemas only once the workflow, functions and schemas are
valid; and scenarios run only once the project loads.

Runtime files can also be checked alone:

```sh
coordinatorctl --runtime-config ./my-follow-up/runtime.yaml check --deny-warnings
```

The default check does not read environment values or secret material. It warns
where an environment expression defers a value check. Add `--environment` to
substitute those expressions explicitly; `--deny-warnings` makes deferred checks
fail. JSON reports use `CoordinatorCtlReport` on standard output, with `ok`,
`command`, `status` and a `diagnostics` array for refusals. Exit codes distinguish
accepted input (0), refused input (1), command usage (2) and unavailable resources
(3).

`explain --project DIR` lists the steps in graph order from start, one line each,
with each call's product, effect and recovery contract. `test --project DIR` runs
the project's `scenarios.yaml` with a virtual clock and fake product replies. It
uses the same graph, mapping and function semantics as the service. Each case
is reported by name. With `--format json`, a case that ran also gives the steps
its run took, the state it ended in and its outcome: identifiers the workflow
declares, and states the scenarios format accepts. A step, state or outcome
that differs from the expectation is named on both sides, for example
`/expect/path/3: expected step notify, observed step skipped`. For any other
member that differs, such as the output or the elapsed time, the report gives
the member's JSON Pointer and the class of each side: string, integer, number,
boolean, null, array, object, or absent. A case lists its first 20
differences and ends with a line counting the rest, such as `and 5 more
differences`. A function that fails is reported by the kind of failure and
its line and column in `functions.rhai`. Neither repeats a value read from a
file or computed by a run. Scenario tests never
acquire real credentials or send requests. Commands print readable text by
default; `--format json` supplies structured reports.

## Start from a maintained project

- [Delayed follow-up](examples/delayed-follow-up/README.md) waits durably,
  reads a current Base Registry Engine (BReg) record, chooses a reviewed notice
  policy and submits one message. Its deterministic scenarios cover permission changes, waits,
  uncertain responses, frozen command retries and refusals.
- [Deferred appointment](examples/deferred-appointment/README.md) reads a
  current BReg record, waits, reads Scheduling availability, books with an
  explicitly approved Casework deferred grant, then submits a separate Messaging
  notice. The original grant reference and deadline stay fixed while credentials
  are acquired freshly. Standing catalogue read authority, booking task authority
  and Messaging identity are separately configured.
- [Approved record check](examples/approved-record-check/README.md) exercises
  a BReg read through explicit Casework task authority.
- [Governed action follow-up](examples/governed-action-follow-up/README.md)
  reads an application, invokes a governed BReg action through a permitted service
  profile, and submits a separate notice through Messaging.
- [Decision follow-up](examples/decision-follow-up/README.md) asks a configured
  model for a typed decision over an application summary, applies an explicit
  confidence threshold, and invokes a governed BReg action only when both allow
  it; otherwise it finishes with `no-action` or `needs-review`.
- [Reviewed notice](examples/reviewed-notice/README.md) submits an application
  to Casework review as a review producer, waits for the result, sends a
  Messaging notice when the review approves it and withdraws the request when
  no decision arrives within fourteen days.
- [External directory](examples/external-directory/README.md) reads a configured
  directory over HTTP GET and chooses an outcome from the validated response.
- [Bounded poll](examples/bounded-poll/README.md) reads a BReg application at
  three fixed times and finishes with the decision or with `still-pending`, as
  described in [Waits and polling](#waits-and-polling).

```sh
coordinatorctl check --project products/coordinator/examples/deferred-appointment --explain
coordinatorctl test --project products/coordinator/examples/deferred-appointment
coordinatorctl test --project products/coordinator/examples/delayed-follow-up
```

Adapt the reviewed functions and owning product policy to your institution. YAML
declares the finite graph, waits, fixed logical connections and the references
that carry values between steps. Choose pure Rhai for logic within that graph:
selecting a branch, building a nested request or computing an instant. Rhai cannot acquire
credentials, contact products or construct additional steps. There are no SQL
steps, arbitrary HTTP methods, dynamic fan-out or automatic compensation.

Rhai reads no clock; it computes over the instants it is given.
`add_seconds(instant, seconds)` returns an RFC 3339 instant moved by a signed
number of seconds, written in UTC. `seconds_between(first, second)` returns the
whole seconds from the first instant to the second, truncated toward zero. An
instant without an offset, or a result outside the years 0000 to 9999, fails the
function with `function.execution`.

The supported operation inventory is fixed:

| Operation | Receiver | Effect | Recovery |
| --- | --- | --- | --- |
| `read-record` | Base Registry Engine (BReg) | Read | Read again |
| `submit-message` | Messaging | Mutation | Same command and read-only receipt |
| `read-scheduling` | Scheduling | Read | Read again |
| `read-availability` | Scheduling | Read | Read again |
| `create-appointment` | Scheduling | Mutation | Same command and read-only receipt |
| `invoke-breg-action` | BReg | Mutation | Same prepared command; no read-only receipt |
| `external-get` | Configured external HTTP service | Read | Read again |
| `evaluate-decision` | Configured typed decision service | Evaluation | Hold after uncertain dispatch |
| `submit-review-request` | Casework, as a review producer | Mutation | Same command; no read-only receipt |
| `cancel-review-request` | Casework, as a review producer | Mutation | Same command; no read-only receipt |

`invoke-breg-action` takes an action identifier and an object of action inputs.
It requires a standing BReg service identity and a profile that permits that
immediate action. It does not accept a Casework grant or inherit task authority.
The maintained BReg client owns metadata validation, condition ETags and prepared
command recovery. Preparation is nonmutating; its exact request and idempotency
key are saved before dispatch. Later attempts check current metadata and acquire
fresh credentials without refreshing the saved conditions or key. A changed
contract, denied authority or stale condition stops the action safely.

A workflow may route a BReg action refusal only from BReg's typed
`422 action.refused` response. BReg validates the code against the active
package's declared refusal catalogue and guarantees that the refusal had no
action effect. The maintained adapter validates the exact problem class and
bounded code. The refusal edge receives that code only, not an HTTP problem,
detail, field path or submitted value. Authentication,
authorization, transport, protocol and command-preparation failures remain
ordinary call failures. Omitting `onDeclaredRefusal` preserves that behavior
for every refusal.

The worker checkpoints a declared refusal's output and target together, as it
does a successful call result. A refusal received after an earlier uncertain
attempt cannot settle the original command, so the run remains uncertain and
does not branch. The saved command keeps its original deadline; this route does
not renew it. Once a call result is checkpointed, the existing pure-step rules
allow its following `choose` or `finish` to complete, while a later call or wait
still observes expiry. If cancellation wins before the refusal completion is
checkpointed, the no-effect completion is acknowledged and the run remains
cancelled.

`external-get` binds through `runtime.externalHttpConnections`, separately from
product connections. Operators configure the base URL, exact permitted paths,
query parameter names, optional service authorization and response schema. The
workflow supplies only a permitted path and query values. The adapter performs
GET, rejects redirects, and returns the validated `{status, body}` JSON value.
A 429, 502, 503 or 504 reply is retried first, as `external-rate-limited` or
`external-unavailable` with its `Retry-After` as the floor for the next attempt;
the workflow receives it only on the last attempt, as
[Recover safely](DEPLOYMENT.md#recover-safely) describes.
An omitted authorization block means a public read, with no borrowed caller
credential. See the [configuration reference](../../docs/site/src/content/docs/reference/coordinator-configuration.mdx)
for limits and defaults.

`evaluate-decision` accepts typed predicate, choice and rubric-score questions.
Bind its logical `decision` connection under `runtime.decisionConnections` using
the System One or OpenAI Decisions protocol. The exact request is frozen before
sending; the validated result is saved before the next step. Rhai can apply
thresholds to the saved answers, then a separate product call acquires its own
authority. A refused or uncertain model result grants no authority.

An evaluation may be billable and cannot be treated as a repeatable read. An
ambiguous dispatch stops without automatic retry, `retry-same` or receipt
reconciliation. Cancel and make a separately authorized new start if another
potentially billable evaluation is appropriate. The
[decision example](examples/decision-follow-up/README.md) demonstrates offline
branching and distinguishes model refusal from transport uncertainty. General
structured generation, model tools and asynchronous jobs are not supported.

`submit-review-request` and `cancel-review-request` hand work to Casework human
review as a review producer. Bind their logical connection under
`runtime.connections` with `product: casework`, the Casework access `profile`,
the `producer` id the Casework project lists under `reviewProducers`, and an
ordinary service `authorization`; `taskAuthority` is refused there. Every
submission carries the connection's producer, so a connection is one producer.
A submission names the review `kind`, the `subject` record under review with
its version and digest, the `context` a reviewer sees and a `requesterReference`; its
output is the accepted request, with Casework's `requestId`, `subject`,
`policy` and `submissionDigest`. A resend with the original key returns the
original acceptance while Casework keeps it, so `retry-same` can repeat an
uncertain submission, while
`reconcile` cannot resolve one: Casework has no read-only lookup by key.
`cancel-review-request` takes that accepted request and a `reason`, and reports
`cancelled`, or `already-terminal` with the result a reviewer already recorded.
Route on the cancel step's `/outcome`: only `cancelled` means the cancellation
ended the review, and `already-terminal` carries a decision the workflow
should report rather than treat as a withdrawal.
Reviewer authority, review policy and the decision stay with Casework. A
`wait-for` step waits for the result, as [Waits and
polling](#waits-and-polling) describes.

## Waits and polling

A `wait-until` step waits until one instant: an input value, a value from an
earlier call's output, or a pure function of them such as `add_seconds`. The
wait is stored in PostgreSQL, so it continues across service restarts, and an
instant that has already passed continues the run at once. When a wait ends at
or after the run's `deadlineSeconds`, the run expires with failure code
`deadline-reached` instead of taking its next step.

The workflow graph is finite and acyclic: no step leads back to an earlier one.
A poll is therefore unrolled. Each round is a `wait-until`, a current read and a
`choose` that either finishes or moves to the next round's wait, and the last
round finishes with an outcome saying the answer is not there yet. The caller
reads that outcome and, if it still needs the answer, starts a new run later.
[Bounded poll](examples/bounded-poll/README.md) reads a BReg application at its
first check time and one and two days later, then finishes `decided` or
`still-pending`.

A `wait-for` step waits for an event that belongs to the run. Its `event`
names the event `type` and what the event belongs to. `review-result`, the
result of a review request an earlier `submit-review-request` call submitted,
is the one event type:

```yaml
await-review:
  type: wait-for
  event: {type: review-result, request: submit-review}
  timeoutSeconds: 1209600
  next: decide
  onTimeout: withdraw
```

`request` names a `submit-review-request` call that every route to the wait
passes through. `timeoutSeconds` is required, from 1 second to one year, and
check refuses one that is not shorter than `deadlineSeconds`: even a wait that
starts at admission would reach the run deadline first and expire instead of
taking its timeout route. At run time the deadline still wins, so a wait that
starts late in the run expires it with `deadline-reached` when the deadline
comes before the timeout.

The step reads the result with the connection's producer authorization as soon
as the wait starts, then every `resultCheckSeconds` of that connection (900 by
default) while the review is open, and once more at the timeout. A read that
Casework answers as busy, or that cannot reach Casework, leaves the wait open:
the next read follows Casework's `Retry-After`, no sooner than 30 seconds and
no later than `resultCheckSeconds`, and without one comes five minutes later,
or after `resultCheckSeconds` when that is shorter. An outage shorter than the
timeout does not fail the run, and waiting runs do not all read again the
moment Casework recovers. Casework's
completion event for the request brings the next read forward, to no sooner
than 30 seconds after the previous one, however many events arrive. The event
carries no result and never settles the wait by itself; when it does not
arrive, the result checks still find the result. A completed result continues
the run at `next` with the result as the step's output, so a `choose` reads its
`/status`: `approved`, `rejected`, `changes-requested`, `answered`, `cancelled`
or `superseded`. The result must belong to the accepted request, with the same
request, subject, policy and submission digest; any other result fails the run
with `invalid-response`. A request Casework does not know fails the run with
`review-request-unknown`, and a result Casework no longer holds with
`review-result-expired`. When the timeout passes without a result, the run
continues at `onTimeout`, or fails with `wait-timed-out` when the step has
none. A step reached through `onTimeout` cannot read the wait's output, and a
result found by the read at the timeout wins over the timeout.

Casework supersedes a review request still under review when the same producer
submits another one for the same subject record, of any version, and the same
review kind. A run waiting on the superseded request reads the result
`superseded` and continues at `next`; the run that submitted the replacement
waits for that one. Choose on `superseded` wherever two runs of a flow can
submit for the same record. [Reviewed notice](examples/reviewed-notice/README.md)
submits a review, waits up to fourteen days, sends a notice on approval and
withdraws the request on timeout, finishing `decided-late` when a reviewer
decided first.

Runs start only from an explicit caller request, through `POST /v1/runs` or
`coordinatorctl start`. There are no event-started runs: a completion event only
brings forward the next read of a run already waiting on that request, and a
caller learns the outcome by reading the run's status.

## Add a maintained operation

For an operation on an existing product boundary, add a versioned descriptor in
`src/operations.rs` under `crates/registry-coordinator`. Declare its product,
effect, key requirement, preparation requirement, recovery semantics and read-only
receipt capability. Add the owning client adapter and routing, with focused
contract and recovery tests. Use the `AdapterSet` preparation seam when the client
requires a saved prepared command. Product metadata, authorization and wire
validation remain the maintained client's responsibility.

The operation schema derives from the catalog; regenerate the project schema.
The worker, store and offline scenario state machine consume those declared
capabilities. They do not need operation-specific execution branches. Snapshots
pin exact semantics, so changing a descriptor or its version cannot silently
reinterpret retained runs. Preserve the original descriptors for compatible
restore. Add offline scenarios using typed replies and only the declared
recovery capabilities; passing them does not prove a live product effect.
Coordinator exports are not generated into a language SDK.

## Package and deploy

```sh
coordinatorctl package --project ./my-follow-up --output ./follow-up-package
```

When the project has a `scenarios.yaml`, `package` runs it first and writes
nothing unless every case passes. The immutable package contains a Definition
snapshot and shared `SHA256SUMS` closure. It holds reviewed workflow/functions
and executable ABI identities.
Endpoints, credentials, private access policies, database identity, encryption
keys and audit custody remain in runtime configuration. Compatible new packages
serve new admissions while previously admitted runs keep their original snapshots
and command identities. A new version cannot reinterpret a repeated idempotency key.

Snapshots pin each used operation's capabilities. A newly packaged definition
with a changed digest needs a new workflow version if that ID and version
already exists in retained history.

A project is one flow and packages as one artifact; its workflow ID is the flow
name callers start. One deployment serves up to sixteen flows by listing one
pinned package per flow under `deployment.packages`, so each workflow stays one
reviewed artifact that is applied, upgraded and rolled back on its own.
[`examples/two-flow-runtime.yaml`](examples/two-flow-runtime.yaml) serves the
delayed follow-up and governed action examples from one runtime file.

Use [DEPLOYMENT.md](DEPLOYMENT.md) to provision OIDC clients, downstream bindings,
state-key custody, PostgreSQL split roles and a private listener. Apply explicitly
migrates and activates the pinned packages, one per flow. The service verifies activation and
never migrates during startup. Its authenticated admission API derives ownership
and idempotency scope from exact verified issuer and subject. Input identifiers
and grant references do not manufacture caller authority.

## Observe and recover

Authenticated status and list expose progress and the reviewed terminal
projection of the caller's own runs, from the flows its policy lists; an
operator policy reaches every owner's runs in those flows. Inspection shows bounded step metadata, uncertainty and the
available recovery action. Operator policy explicitly grants recovery and private
diagnostics. Run actions reach only the flows a policy lists; deployment-wide
operator actions such as `doctor` and the restore hold reach every flow and need
`operator: true` instead of a flow list. Inputs, product responses and prepared commands remain encrypted and
are absent from these responses.

For a compatible current call, inspection includes `recovery.operation`: its
pinned ID, version, product, effect, key and preparation requirements, recovery
semantics and `readReceipt` capability. When inspection can otherwise proceed,
it omits the field if no compatible current call is available, including pure
steps, erased payloads or incompatible snapshots. An unresolved original binding
can still refuse inspection. For example, `invoke-breg-action` declares
`same-command` recovery with `readReceipt: false`. `retryAllowed` and `reason`
describe the run's eligibility to be scheduled. The operation descriptor does
not prove current product authority or the existence of an original-key receipt.

A start names its flow and is admitted under that flow's active definition.
Previously admitted versions remain available for their existing runs.
`GET /v1/runs` returns at most 100 of the caller's most recently admitted runs,
newest first, from the flows its policy lists; an operator policy lists every
owner's runs in those flows. `limit` takes 1 to 100 and defaults to 20. The list
has no paging cursor and no state filter, so keep the run ID a start returns to
read an older run with `GET /v1/runs/{run}`. Institutional applications compose
through its authenticated HTTP API and the owning Casework, BReg and optional
Messaging APIs. The maintained Coordinator client covers the caller routes
`start`, `list`, `status`, `inspect`, `reconcile`, `retry_same` and `cancel` as
`registry_stack_client::coordinator` in Rust and the
`coordinator` namespace of the unified Node.js and Python clients; published
client packages carry it from the release that admits the Coordinator. It
resends only an admission whose outcome is unknown, under the same key, and
grants no access to the product records a flow touches.

Every refusal of the HTTP API, including a request refused before its route
runs and a refused review-completion event, is an RFC 9457
`application/problem+json` document with `type`, `title`, `status`, `detail`,
`code` and `traceId`. The `type` is the code with its dot replaced by a slash
under `https://id.registrystack.org/problems/registry-coordinator/`, the title
and detail are fixed sentences that belong to the code, and no member repeats
a submitted value. A refusal carries `Cache-Control: no-store` and a
`traceparent` header whose trace matches `traceId`; a 401 also carries
`WWW-Authenticate: Bearer`, and a 503 `Retry-After`. A run that does not exist
and a run the caller may not see answer the same 404 `run.not-visible`. The
generated OpenAPI document lists the codes each operation can answer, and the
identifier catalog registers the vocabulary. `coordinatorctl` diagnostics keep
their own `coordinator.*` codes and fixes, and a refused remote command names
the problem code and trace it received, such as `(problem run.not-visible,
trace 4bf92f3577b34da6a3ce929d0e0e4736)`. The service logs each server problem
(5xx) with its internal code and that `trace_id`; it does not log other
refusals.

| Code | Status | Title |
|---|---|---|
| `admission.held` | 409 | Admissions held |
| `admission.recovery-only` | 409 | Service admits no runs |
| `audit.response-unavailable` | 503 | Audited result unavailable |
| `authentication.refused` | 401 | Authentication refused |
| `binding.conflict` | 409 | Connection settings changed |
| `binding.live-conflict` | 409 | Live connection settings changed |
| `definition.refused` | 409 | Workflow definition refused |
| `deployment.activation-changed` | 409 | Active packages changed |
| `deployment.refused` | 409 | Deployment not serving |
| `evaluation.uncertain` | 409 | Evaluation outcome uncertain |
| `execution.held` | 409 | Execution held |
| `flow.not-served` | 404 | Flow not served |
| `flow.version-conflict` | 409 | Workflow version conflict |
| `idempotency.key-invalid` | 400 | Idempotency key invalid |
| `idempotency.key-reused` | 409 | Idempotency key reused |
| `input.invalid` | 400 | Start input invalid |
| `operation.not-authorized` | 403 | Operation not authorized |
| `receipt.expired` | 409 | Original receipt expired |
| `reconcile.raced` | 409 | Run changed during reconciliation |
| `reconcile.refused` | 409 | Reconciliation refused |
| `reconcile.unsupported` | 409 | Reconciliation unsupported |
| `request.body-too-large` | 413 | Payload too large |
| `request.invalid` | 400 | Request invalid |
| `request.limit-out-of-range` | 400 | List limit out of range |
| `request.method-not-allowed` | 405 | Method not allowed |
| `request.not-found` | 404 | Route not found |
| `request.reason-invalid` | 400 | Reason invalid |
| `request.retention-invalid` | 400 | Retention request invalid |
| `request.unprocessable` | 422 | Request unprocessable |
| `request.unsupported-media-type` | 415 | Unsupported media type |
| `restore.hold-required` | 409 | Restore hold required |
| `restore.lease-incompatible` | 409 | Held work incompatible |
| `restore.review-required` | 409 | Recovery review incomplete |
| `restore.unresolved` | 409 | Held work unresolved |
| `retry.refused` | 409 | Retry refused |
| `run.definition-incompatible` | 409 | Run definition unsupported |
| `run.not-visible` | 404 | Run not visible |
| `run.payload-erased` | 409 | Run payloads erased |
| `runtime.failure` | 500 | Coordinator runtime failure |
| `service.unavailable` | 503 | Coordinator service unavailable |

After a lost Messaging or Scheduling response, reconcile against the receiving
product's original-key receipt before retrying. BReg action reconciliation remains
unresolved because no read-only action receipt is available; an ordinary record
read does not prove that the original action succeeded. Same-command recovery
preserves the body, key, destination, caller and original task authority.
An unavailable product or expired receipt never proves that an effect did not
occur. Messaging acceptance records a
provider submission contract; provider delivery is a distinct observation.
Cancellation prevents later dispatch where possible and does not roll back an
appointment, governed action or notice already accepted by its owning product.

Retention erases eligible terminal payloads while preserving spent-key tombstones.
A retained run can still be inspected; it cannot be retried or reconciled without
its erased payload. Restore starts with dispatch and admission disabled. Recovery
hold marks every unfinished restored run for review, including commands not yet
prepared at the backup point. Execution history and admission history have separate
release requirements. The deployment runbook explains the explicit fencing and
complete-history attestations and the limits of older backups.

## Verify a change

The owning Cargo tests cover authoring, deterministic scenarios, runtime config,
package integrity, OIDC policy, product adapter boundaries, Scheduling command
recovery and the authoring of review waits. The PostgreSQL feature gates protect database-dependent suites from
ordinary workspace test runs.

```sh
cargo test --locked -p registry-coordinator --features schema \
  --test authoring --test authored_project --test authored_scenarios \
  --test cli_authoring --test runtime_config \
  --test deployment_surface --test http_boundary --test scheduling_adapter \
  --test breg_action_adapter --test external_http --test external_runtime \
  --test decision_protocol --test decision_runtime \
  --test casework_adapter --test wait_for_authoring \
  --test catalog_scenarios
products/coordinator/scripts/check-schemas.sh
cargo run --locked -p registry-coordinator --bin coordinatorctl -- openapi \
  > products/coordinator/generated/openapi/coordinator.openapi.json
```

With dedicated disposable PostgreSQL 17+ databases configured, use
`scripts/test-postgres.sh` for the maintained durable-state, encrypted-custody,
restart, deployment/router, review-wait and Messaging integration checks. That script first
builds the independent Messaging service and operator executable, then supplies
`COORDINATOR_MESSAGING_BIN` and `COORDINATOR_MESSAGINGCTL_BIN` to the tests.
The integration fixtures compose through Messaging's public HTTP contract and
refuse missing executables; Coordinator does not link its runtime as a test
dependency. The native-service
fixture script runs the controlled BReg, Casework, Scheduling and Messaging
journey. It requires Python 3, OpenSSL and PostgreSQL client tools, Docker,
distinct disposable PostgreSQL databases, and all ten native service/operator
binaries described by the script's `--help`. Build `messaging` and `scheduling`
with their own `postgres-test` features: the journey gives them plaintext
loopback databases, which only those builds accept. Those contributor checks do not replace the deployment runbook or imply
production credentials are needed to author a project.

The governed-action and external-directory examples have deterministic scenarios;
adapter checks use mock HTTP services and durable-state checks use PostgreSQL.
For native BReg action and notice acceptance, run this explicit helper from the checkout:

```sh
python3 products/coordinator/scripts/test-breg-action.py --env /absolute/path/coordinator-test.env
```

Provide Python 3, the current checkout's Cargo build prerequisites, and
distinct `COORDINATOR_TEST_DATABASE_URL` and
`COORDINATOR_MESSAGING_TEST_DATABASE_URL` values in the environment or named file.
Each URL must name an owned disposable PostgreSQL 17+ database on loopback.
The Coordinator database identity needs authority to create and drop unique
fixture databases and roles; both database identities must create and drop
fixture schemas. The helper builds current `breg`, `bregctl`, `messaging` and
`messagingctl` binaries and provisions synthetic credentials and data. Successful
runs clean up UUID-owned fixture resources without resetting the named databases.
Assertion failures can retain diagnostic Coordinator and Messaging schemas.
No live service credentials are required.

The first native check proves one governed patch was accepted despite a lost response.
Reconstructed `HttpAdapters` reload the saved preparation and recover with the
same body, key and conditions, leaving one applied record revision and returning
the same application receipt. It checks fresh metadata, refusal through a real
read-only profile, and no BReg receipt lookup during reconciliation.

The second check executes `Worker` and `Store` through a real BReg action and a
real Messaging notice submission. After the accepted notice reply is dropped,
reconstructed objects recover through the exact original notice receipt lookup.
The action and notice are not resubmitted, and duplicate start admission returns
the original run. This proves message acceptance, not provider delivery.
Reconstruction replaces Rust objects; it does not restart the Coordinator OS
process. The separate `process_restart` target retains process restart coverage.
The separate `scripts/test-real-services.py` journey composes BReg, Casework,
Scheduling and Messaging with a persisted wait and an actual worker restart.
Its default 961-second wait crosses the immediate approval limit. It checks
fresh credentials bounded by the original deferred approval, original-receipt
recovery after lost booking and notice replies, and refusal of expired, unknown
or mismatched approvals without additional effects. Waits shorter than 901
seconds are smoke checks and do not establish the long-wait boundary.
The journey also runs the reviewed-notice flow against a real Casework review
producer: two runs submit their review, a reviewer approves one and rejects the
other, and Casework delivers each completion to the Coordinator's
`/v1/review-completions` route. Both runs settle well before their 900-second
fallback read, only the approval sends its notice, and the live receiver
refuses a wrong token or recipient binding while acknowledging an authentic
event for an unknown request. The timeout route is proven by scenarios only.
The helper is an explicit contributor check, not a CI gate.
