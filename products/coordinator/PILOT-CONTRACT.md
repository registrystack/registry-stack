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

Each run keeps its original definition and prepared commands. A repeated start
key under the same verified issuer, subject and flow returns its original run
when the input matches. A conflicting input is refused. New compatible package
versions apply to new starts; existing runs keep their pinned definitions.
A workflow ID and version identify one definition throughout retained run
history, including payload-erased tombstones. Apply refuses a changed definition
under a previously used version; give that definition a new version.

Credentials are acquired when a call is attempted. A wait, retry or restart
cannot extend a Casework approval deadline or change its principal, resource,
scopes or bounds. Receiving products verify current authority. Standing read
authority and read-only receipt observation cannot authorize a commitment.

An accepted Messaging submission is distinct from provider delivery. A failed
connection or lost response after sending may leave the effect unknown. The
original command and idempotency key are retained for bounded recovery.
If evaluating the following wait fails, the successful call and its output stay
recorded. The run fails with `mapping-invalid`; the accepted call cannot be
replayed to repair the mapping.

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
release of protected results. Retention erases eligible terminal payloads while
keeping spent-key tombstones. Live, uncertain and restore-review work cannot be
silently erased.

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
confirmation of the original command, never a new submission. Reconciliation
can resolve an uncertain outcome; a definite retryable reply requires
same-command retry.

This pilot does not add language builders, a new WASM toolchain, dynamic fan-out,
arbitrary HTTP or SQL steps, automatic compensation, or a visual editor. It does
not promise atomic distributed revocation, rollback of accepted effects or
production availability. Existing hooks and APIs remain available to external
orchestrators.
