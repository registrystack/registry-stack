# Coordinator pilot contract

Registry Coordinator is an optional Rust service for controlled institutional
pilots. It executes reviewed, finite, acyclic YAML workflows using bounded pure
Rhai functions and maintained product clients. One service and PostgreSQL 17 or
newer are sufficient. Receiving products retain authorization and ownership of
their effects.

## Execution and authority

A workflow can read current records, wait durably, choose a branch, call an
approved product operation and finish with a declared outcome. The authored
package contains the graph, functions and schemas; deployment configuration
binds its logical connections to endpoints and identities.

YAML owns the finite graph and waits; pure Rhai maps values and selects an authored
branch. Functions cannot make calls, acquire credentials or add runtime steps.

The eight supported operations are `read-record`, `submit-message`,
`read-scheduling`, `read-availability`, `create-appointment`, `invoke-breg-action`,
`external-get`, and `evaluate-decision`. The first five keep their original product contracts.
Messaging submission and Scheduling appointment creation support same-command
recovery and read-only original-key receipts. Base Registry Engine (BReg) action
invocation supports same-command recovery without a read-only action receipt. The four read
operations can be read again.

`invoke-breg-action` uses a standing BReg service identity and an explicitly
permitted profile for an immediate governed action. Its input contains `action`
and an `input` object, with no grant field or task-authority fallback. The maintained
BReg client prepares the conditional request without mutation. Coordinator saves
that preparation and original key before dispatch. Recovery checks current
metadata and fresh authority while retaining the saved request and condition
ETags. Changed contracts, stale conditions and revoked authority do not silently
produce a replacement command. An ambiguous response remains uncertain; a
record read or operator assertion cannot establish action success.

`external-get` is a configured read boundary: operators bind a base URL, exact
paths, allowed query parameter names, optional service authorization and a local
response schema through `runtime.externalHttpConnections`. Calls can supply only
a permitted path and query values. The adapter sends GET, refuses redirects and
validates the complete `{status, body}` response. It provides no external write
operation or receipt. Omitted authorization means a public read.

Each run keeps its original definition and prepared commands. A repeated start
key under the same verified issuer, subject and flow returns its original run
when the input matches. A conflicting input is refused. New compatible package
versions apply to new starts; existing runs keep their pinned definitions.
A workflow ID and version identify one definition throughout retained run
history, including payload-erased tombstones. Apply refuses a changed definition
under a previously used version; give that definition a new version.

Version 4 snapshots pin the capabilities of every used operation. Version 3
snapshots preserve their original bytes and five-operation semantics during
restore. Existing package commands remain unchanged, but a changed definition
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
`coordinator` serves the activated package without migrating at startup. Only
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

Each deployment admits one active flow definition, while retained runs use their
original versions. The list endpoint returns the latest caller-owned runs with
`limit` from 1 to 100, defaulting to 20, and has no pagination. Applications use
the authenticated HTTP API; no Coordinator export is available in
`@registrystack/client` yet.

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
`receipt-expired` has no additional members. Inputs, successful replies and
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
preparation and crash durability. The combined BReg, Casework, Scheduling and
Messaging journey remains deferred.
See [the contributor checks](README.md#verify-a-change)
for the explicit helper and its two distinct disposable loopback databases.
Successful runs clean up UUID-owned fixture resources; assertion failures may
retain diagnostic Coordinator and Messaging schemas. This explicit contributor
check does not add a CI gate.
Native Casework and BReg applications may compose a governed application action
with a separate optional notice through their owning APIs.

This pilot does not add language builders, a new WASM toolchain, dynamic fan-out,
arbitrary HTTP methods or SQL steps, automatic compensation, or a visual editor.
It does not promise atomic distributed revocation, rollback of accepted effects or
production availability. Existing hooks and APIs remain available to external
orchestrators.
