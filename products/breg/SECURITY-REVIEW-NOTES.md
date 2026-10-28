# Base Registry Engine security review notes

Review notes for security-sensitive Base Registry Engine changes, held in
tracked material because commit messages do not survive a squash. Each
section names the change, the threat it answers, the defaults it ships, where
Rust enforces it, the tests that pin it, and the residual risk it accepts. The
security-invariant matrix in `contracts/security-invariant-matrix.yaml` is the
row-per-invariant baseline; this file is the narrative behind the decisions
and the residuals the matrix rows do not state.

## Proposal task authority, recovery and access explanations

A new Proposal application requires both current executor authority and the
original task authority retained for its exact submission, when one exists.
Apply preflight establishes current disclosure and the frozen submission before
loading that binding. The service observes current status outside the mutation
transaction, before acquiring Review or commit Evidence. The mutation then
reloads and compares the exact binding and checks its local deadline before
effects and at the final commit fence. Every new application attempt obtains
its own status observation. A separately authorized human executor and the
restricted built-in system executor keep their existing independent ceilings.

An exact completed receipt returns under current disclosure without another
retained-task status request. Cancellation and a Review rejection do not need
the old submitter's grant to remain active. Status refusal is a failed
precondition; an unavailable dependency is unavailable and remains eligible for
the existing bounded worker retry. A source can revoke after the remote status
observation and before local commit: BReg and the source share no distributed
transaction. Local expiry and submission-binding checks remain enforced.

Successor activation keeps pending Proposals inspectable and requires one
Proposal grant that can both obtain a condition, through Get or List, and
Cancel. An inspection grant still has to exist. The condition remains bound to
the selected profile, principal, purpose and target bounds. The activation
guard checks compiled permission shape; it does not prove that an operator has
provisioned a real identity satisfying the profile's claims and row bounds.

Human access explanations render the compiled actor, client, task, target,
input, attachment and ownership gates, the system application ceiling and row
reach. Caller ownership restricts Proposal documents, not the target Records.
Read paths retain their related-disclosure finding without being classified as
Action targets. These are review aids; runtime admission remains authoritative.
Authentication refusal warnings recover a poisoned timestamp while retaining
their existing rate limit; warning-state recovery supplies no caller authority.

The PostgreSQL `postgres_proposal_task_authority` and
`postgres_proposal_recovery_permissions` suites exercise the real public
lifecycle and worker boundaries, including successful receipt and cancellation
paths and refused activation preserving pending work. The CLI explanation and
consent-access tests cover human-readable authority and the distinct warning
surfaces. The authentication unit test pins warning recovery and rate limiting.

## Generated business identifiers

The public code is an immutable stored field, while the record UUID remains
the engine identity. The threat is a caller choosing or reusing a code, moving
it to a different uniqueness scope, or causing a Proposal retry or migration
to issue a code twice. Compiler validation in `compiler.rs` requires a bounded
string field and required stored scalar scope fields classified public or
internal and not references, excludes generated fields from caller-writable
contracts, and rejects incompatible successor rules.
Mutation admission in `mutation.rs`, `immediate_actions.rs`, and
`proposal_prepare.rs` refuses caller or Action values for generated fields and
later changes to either a generated field or its scope. Proposal Submit reserves
codes once and freezes them in the reviewed effects; Apply and Retry use those
effects without another allocation.

`generated_identifiers.rs` allocates and reserves inside the owning PostgreSQL
transaction. Sequence counters lock per scope; random codes use operating-system
entropy and bounded collision retries. An append-only reservation ledger keeps
issued values unavailable after tombstone or erasure. Migration-owned functions
have a pinned search path; the runtime role has only EXECUTE, with no direct
counter or reservation-table grants. `generated_ddl.rs` and
`postgres/interlock.rs` seed reservations and sequence high-water marks after a
reviewed backfill, then check the scoped unique constraint before activation.
The focused PostgreSQL allocator, Action, Proposal, and migration tests cover
role grants, rollback, scoped reuse, retained rows, replay, and recovery.

Generated codes are institution-facing labels, not proof of authority. A
holder still needs the ordinary Record or Action grant. A code space can fill;
the bounded allocator returns a conflict instead of silently recycling values.

Residual: the reservation ledger is append-only and no erasure path touches
it, so each issued value and its sequence scope values stay in
`registry_generated_identifier_reservations` after the Record is tombstoned or
erased. That is the price of never reissuing a code. It is acceptable because
the compiler limits generated fields and scope fields to public or internal
values (scope fields also cannot be references), so the ledger holds a
jurisdiction or category code beside an institution-issued number, never
restricted data or a link to a person. Hashing the scope values would remove
even that, and stays open if a register needs to scope by more sensitive data.

## Attachment storage and verification through the shared object store

The S3 adapter and the attachment verifier transport moved from
`registry-breg` into `registry-platform-objectstore`, so another product can
store and verify content under its own namespace without a second copy of the
signing, integrity, and verdict code. The threat is drift: a moved adapter
that signs, addresses, or accepts differently would change which bytes a
registry releases, or would leave the binding a registry pinned at its first
upload unrecognised.

The engine supplies its namespace, `NAMESPACE` in
`crates/registry-breg/src/attachment_storage.rs` and
`crates/registry-breg/src/attachment_verification.rs`: key prefix `breg`,
binding domains `breg-attachment-s3-v1` and
`breg-attachment-verification-http-v1`, and the attachment size bound. The
object key, the storage binding digest (domain, bucket URL, region, and the
digest of the database and registry scope), and the verification binding
digest (domain, URL, `policyId`) are computed as before, so a registry that
pinned its bindings starts unchanged. The request shapes, the four verifier
headers, the attempt and connect timeouts, the refusal of redirects, proxies,
retries, and versioned buckets, and the closed fail-closed verdict parser are
unchanged; `policyId` is still committed in the binding and never sent.

The only configuration change is the destination member: `endpoint` is now
`url` in both blocks (CFG-VAL-7), and `endpoint` is refused as a removed key.
The defaults are unchanged: storage defaults to `type: database` and
verification to `type: disabled`; the shared verifier block has no default of
its own.

### Tests

- `crates/registry-platform-objectstore/src/s3_tests.rs` pins the SigV4
  canonical request and signature, the header set, the object key and binding
  digest, and the refusal of missing, corrupt, oversized, versioned,
  redirected, and interrupted responses (BREG-SEC-54 now points here).
- `crates/registry-platform-objectstore/src/verifier_tests.rs` pins the
  request bytes and headers, the absence of `policyId` on the wire, the
  timeouts, the binding digest, and every unavailable verdict.
- `the_registry_namespace_keeps_its_key_prefix_and_binding_digest` in
  `crates/registry-breg/src/attachment_storage.rs` pins the engine's key
  prefix, domain, and request paths; the verifier tests in
  `crates/registry-breg/src/attachment_verification.rs` keep BREG-SEC-55.
- `attachment_destinations_are_named_url_and_the_endpoint_key_is_refused` in
  `crates/registry-breg/tests/runtime_config.rs` pins the removed-key refusal.

### Accepted residuals

- **Refusal messages name object storage.** An adapter error's display text
  says "object storage" rather than "attachment storage". Every engine call
  site maps the error to its own closed refusal, so no message an operator or
  caller sees changes.
- The crate's own notes are in the "Security review notes" section of
  `crates/registry-platform-objectstore/README.md`.

## Attachment verification on the shared dispatch core

Attachment verification moved from a lease, attempt counter, and retry time
held on each verdict row to the shared `registry-platform-dispatch` job core,
the same core the Document Store's verification uses. The threat is a weaker
worker: a verdict committed for bytes, a media type, or a verifier binding it
was not given, a verdict committed by a worker whose lease another worker
has taken over, an attempt the audit journal never records, or a file that
leaves quarantine without a verdict.

### Enforcement and defaults

- `attachment_store::install` creates
  `registry_internal.registry_attachment_verification_jobs` from the
  dispatch table declaration, and `put` enqueues one job in the upload
  transaction that creates a pending verdict row, so every pending row has
  exactly one job. The verdict row loses its lease, attempt, and retry
  columns and gains `verification_id`, the job's key.
- The claim selects a due job only when its verdict row is gone or decided,
  so the job can end, or when the row waits under the pinned verifier
  binding for live bytes a live reference holds
  (`CLAIM_PREDICATE` in
  `crates/registry-breg/src/attachment_verification_worker.rs`). Every
  dispatch transaction, and the transaction that reads the bytes, is
  admitted as before: bounded lock and statement waits, the shared registry
  lock, the ready registry identity, the attachment row-level security
  scope, and the pinned storage and verifier bindings.
- The attempt's `request` audit entry is accepted before the lease commits,
  and so before any byte is read or sent. The content read
  (`load_verification_content`) and the verdict write
  (`record_verification_verdict`) each require the job's lease token to be
  live, so a worker whose lease lapsed and was taken over cannot read or
  decide. Bytes are checked against the blob's size and SHA-256 before the
  verifier sees them.
- Only an `approved` or `rejected` answer from the configured verifier ends
  a job with a verdict. A verifier failure, a content read or integrity
  failure, or the 60-second attempt budget running out leaves the row
  pending and retries the job after a delay drawn with equal jitter between
  half and all of a base delay that starts at 30 seconds and doubles to one
  hour, so the first retry follows in 15 to 30 seconds and no delay exceeds
  one hour. The policy has no expiry, treats an uncertain outcome as a
  retry, and allows 32,767 attempts, so a quarantined file waits for a
  verdict rather than for an operator; a job that stops anyway fails the
  worker pass visibly.
- A lease a stopped worker left behind is recovered by the next claim to a
  backed-off retry, and the recovering worker writes that attempt's
  `unfinished` terminal entry. A verdict that arrives after its row was
  retired commits nothing and is audited as `discarded`, and the job of a
  retired row is deleted with the row unless a worker holds it, in which
  case that worker deletes it when it finishes.
- The audit schema is `breg-attachment-verification-audit/v3`, replacing
  `/v2` with the same record fields: the keyed verification reference is
  derived under the `breg-attachment-verification-v2` domain from the
  verification id and the lease token, in place of the
  `breg-attachment-verification-v1` domain over the content digest, content
  type, and lease id. A reader joining entries across the change branches on
  the schema, as `products/breg/contracts/audit-identity.md` states.
- The worker records its last success only for a pass that reached a
  verdict, or that found no due job while no job an earlier attempt failed,
  or a lapsed lease, waits for its retry, and no verifiable pending verdict
  is stranded: its job missing, or stopped (dead-lettered, unknown, expired,
  or cancelled) without a verdict. A stranded verdict is otherwise claimed
  by nothing, so the growing last-success age is its signal.

### Tests

`crates/registry-breg/tests/postgres_proposal_s3.rs`:
`verification_runs_on_the_shared_dispatch_job_table` pins the job table and
the removed verdict columns, the retry wait without a success, the verdict
after the retry, the lapsed-lease recovery and its `unfinished` entry, and a
single verifier request and verdict for a recovered job;
`native_verifier_worker_releases_only_exact_approved_bytes` keeps the exact
bytes, media type, binding, quarantine, and refusal checks against the
shared dispatcher. The unit tests in
`crates/registry-breg/src/attachment_verification_worker.rs` pin the policy
and the mapping of verifier answers. The new suite test was written first
and did not compile against the code before it.

### Accepted residuals

- **No row-level security on the job table.** The job table holds only job
  keys, states, attempts, and timestamps. The runtime role can read and
  change it without an admitted transaction, as it can the hook delivery
  state table. A changed job row can cause an extra
  verifier request or stall a verification; it cannot release bytes,
  because a verdict is written only into the admitted verdict row under a
  live lease, and a pending row stays quarantined.
- **No outer iteration bound.** The 180-second bound on a whole worker pass
  is gone. Each database statement is bounded by the 30-second statement
  timeout and the configured lock timeout, and the content read and
  verifier request by the 60-second attempt budget.
- **Double `unfinished`.** One attempt can be answered `unfinished` twice:
  by the worker that wrote it, and again by the worker that recovers its
  lapsed lease. The first comes from a finish whose commit cannot be
  confirmed, from a claim whose lease commit failed and whose read-back
  found nothing, and from a finish whose commit cannot be confirmed after
  `after_finished` deleted the job row of a retired verdict, so the
  read-back finds no row even when the finish committed. A worker whose
  lease lapsed before it finished writes no `discarded` or verdict entry at
  all: its finish is refused by the stale fence, the recovering worker's
  `unfinished` is the attempt's only terminal entry, and the lapsed pass
  emits `attachment_verification.worker.iteration_failed`.
- **Longer retry wait.** A verifier that recovers after a long outage may
  wait up to an hour, jitter included, before a quarantined file is
  retried.

## Immediate Action availability and guard refusal disclosure

An application may ask whether one referenced target currently satisfies an
immediate Action's field guards before presenting Invoke. The availability
route uses the exact selected Action profile and ordinary Get authority for the
target. A missing or row-denied target stays the ordinary concealed 404. A
guard or row boundary that depends on an unreadable field, and a profile that
lacks ordinary Get authority, returns the closed `not-disclosed` result without
an observed revision or missing-input names. The implementation does not read
hidden guard or boundary values to classify that result, and no answer includes
a guard ID or Record value.

Only per-target field guards are evaluated. Revision checks are neutral because
the observation supplies no condition token. Functions, SQL uniqueness,
Evidence, and other targets are outside the advisory result. The route supplies
no mutation authority, reserves no state, and does not replace the authoritative
checks inside the mutation transaction.

When Invoke fails a current field guard, the runtime records the failure while
it finishes the current-target admission checks: target locking and visibility,
condition tokens, link references, current-state patch-target authorization,
and the current grant. At Evidence finalization it also revalidates acquired
commit Evidence. An initial Evidence preflight forms the current commit-Evidence
requests but stops before external acquisition when a guard is already false.
The runtime returns `412 action.guard_failed` only when those prechecks pass and
the same selected profile can perform the ordinary target Get and read the
fields that establish the failed guard. An earlier refusal retains its normal
response. Stale conditions, a guard that no longer fails when
reread after rollback, and guard details outside that disclosure remain the
generic `412 precondition.failed`.

The distinct code confirms a current business-state blocker; it does not prove
the Action would otherwise succeed. Effect application, proposed-value authorization,
external Evidence acquisition after initial preflight, and database constraints
run only after guards pass. A hook-proposed Action whose guard fails settles as
the refused `hook.proposal.precondition_failed`. This prevents the distinct code
from becoming a hidden-field or row-existence oracle while letting an authorized
application distinguish a confirmed guard failure from stale input.

The focused PostgreSQL Action availability test covers selected-profile Get
authority, row concealment, hidden guard and boundary fields, closed unknown
responses, and the split between the distinct guard code and the generic
precondition code, including a second reference that is missing, foreign,
tombstoned, or stale while the first reference fails its guard. Runtime
mutation tests continue to prove that observation does not bypass commit-time
authority, concurrency, or guards.

Availability can become stale immediately after it is returned. Applications
must treat the answer as a form hint and handle Invoke refusal. The result
describes only the selected target's declared field guards, including a true
result when none apply. It gives no answer about form completeness, Functions,
Evidence, other targets, SQL constraints, or any other commit prerequisite.

## Runtime Evidence expiry and terminal webhook retention

Expired retained assertions and terminal delivery metadata must not accumulate
indefinitely merely because an operator did not schedule cleanup. The supervised
Evidence worker in `action_evidence_retention.rs` runs every minute, with at most
100 batches per tick and 1,000 expired rows per table per batch. It preserves the
fixed 24-hour acceptance window. A fixed security-definer function grants the
runtime only expiry execution, with a pinned search path; it grants neither
assertion reads nor arbitrary Evidence deletion. Each batch has an audit attempt
and terminal outcome, a shared activation lock, an exact registry identity check,
and a bounded query. Cancellation retains the pool's cancellation guard. Manual
erasure remains an independently authorized migration-credential operation.

The webhook worker uses the shared Hooks retention primitive and narrowly scoped
DELETE grants on its three delivery tables. It retains metadata for at least the
receipt and payload horizons. Dead letters age from their original terminal time
and require completed expiry and erased payloads. Active or uncertain work,
shared-event siblings, spent idempotency keys, and audit history remain protected.
Neither cleanup path recreates erased material or grants replay authority.

Hook operational logs carry only committed counts and a closed failure reason:
`registry-not-ready`, `lock-timeout`, `query-cancelled`, or `database`. A later batch
failure reports only earlier committed progress. A capped tick emits one warning,
a normal nonempty tick one completion, and an idle tick no completion. SQLSTATE
57014 means query cancellation; it does not establish a statement timeout. Raw
PostgreSQL error text, SQL, identifiers, and retained values are never logged.
Private admission diagnostics share the existing transaction implementation and
map back to the original errors for all non-retention callers.

Read audit `refusalReason` uses a closed vocabulary where the refusal boundary
establishes one. It adds no selector, credential, or record value to the audit.
The PostgreSQL Evidence retention, read/access-log, and webhook delivery suites
cover expiry, admission, audit, replay preservation, and cancellation. The webhook
log tests exercise capped and idle ticks, partial committed work, maintenance,
lock timeout, query cancellation, and raw-error canaries against PostgreSQL.

The batch bounds limit work rather than guarantee immediate erasure: downtime,
lock contention, audit failure, and a backlog can delay cleanup. Restore can
reintroduce previously erased rows; the runtime applies the same expiry rules
after startup admission. Backup retention remains an operator responsibility.

## Linear Immediate Action policies and target locking

Immediate Action authorization groups compatible effects into one policy per
action, entity, access profile, and command. The grouped policy requires
the same action context, effect membership, target record, row boundaries,
field set, and field values that the individual policies required. Execution
and replay authorization load each distinct target record once and apply every
effect-specific check to that loaded row. This keeps policy text and database
work linear at the documented 128-effect ceiling without widening the set of
rows or fields an action can use.

Schema reconciliation records a digest of each compiled policy definition in
the policy comment and preserves the PostgreSQL policy object when the digest
matches. Exact managed-catalog verification remains the activation boundary.
Reconciliation keeps a policy whose comment matches, so a policy whose
expression was altered while it kept that comment is not repaired: catalog
verification refuses it as drift and activation fails closed. Recovery is an
operator step: a database administrator clears that policy's comment and
applies the exact target package again, and reconciliation then replaces the
policy with its compiled definition. The optimization does not treat the comment
alone as proof that the enforced expression is correct.

The 128-effect regression compares grouped policy count and text size with the
effect count, exercises successful execution and replay, and retains refused
field and target cases. PostgreSQL tests also prove that repeated effects take
one target lock, unchanged reconciliation preserves policy object identity,
and an altered policy carrying the expected comment cannot become active.

The generated policy still depends on PostgreSQL's catalog representation and
expression deparser. The managed-catalog fingerprint and final exact policy
verification remain required on each supported PostgreSQL major, including
after a package activation.

## Activation ledger and unsigned packages

The change removes package signing and trust anchors, moves activation
authorization to the migration credential and an activation ledger in the
database, adds role separation between the migration and runtime roles, adds
an activation audit record, and changes deployment defaults
(`crates/registry-breg/src/migration.rs`,
`crates/registry-breg/src/postgres/migration_ledger.rs`,
`crates/registry-breg/src/postgres/roles.rs`,
`crates/registry-breg/src/postgres/interlock.rs`,
`crates/registry-breg/src/startup.rs`, `bregctl apply|plan|status`). A package
names no environment, instance, or database, so one package directory,
byte-identical under one package digest, is promoted through every
environment. The ledger is `registry_internal.registry_migrations`: one row
per activation, keyed by an activation id, in apply order, recording the
package digest, its predecessor's digest, the registry revision, the plan
kind (`initial` or `successor`, or `adopted` on a database an earlier release
adopted from before the ledger), the role mode, the runtime role,
and the operator reference only as a keyed hash. `registry_state` records the
active package digest and activation id, the database id, the maintenance
state, and the instance claim.

### Threat

1. A package is swapped on the configuration volume, or the runtime file is
   edited to name another package, by someone without the migration
   credential (BREG-SEC-02).
2. A staging runtime file is pointed at the production database
   (BREG-SEC-02).
3. An older package is applied over a newer one, or a package skips the
   active one (BREG-SEC-02).
4. A holder of the runtime credential rewrites what the ledger says was
   activated, so the runtime serves a package no operator applied
   (BREG-SEC-04, BREG-SEC-118 at apply, BREG-SEC-119 at startup).
5. An activation commits with no audit trace (BREG-SEC-120), or an
   operator's reference leaks through the ledger, the audit stream, or
   command output (BREG-SEC-121).
6. A database holding registry state this release does not recognise, such
   as one a release before the ledger activated, is served, planned, applied
   over, or read as though the ledger recorded it (BREG-SEC-122).

### Enforcement and defaults

1. **What authorizes an activation.** Possession of the migration credential
   and a verified package whose `migrationPlan.fromPackageDigest` names the
   digest the ledger records as active; an initial activation names none and
   is accepted only into a database with no registry state. No signature,
   signature threshold, or trust anchor is read anywhere. The package digest
   is the SHA-256 of the package's `SHA256SUMS`; every listed file is
   re-hashed before the digest is trusted. `package.expectedDigest` in the
   runtime file is an optional pin: when set, a package with another digest
   is refused before any database connection. Re-applying the active package
   is refused as already active (`apply.package.already-active`, naming
   `bregctl status`); an older package, a package that skips the active one,
   or another registry's package is refused as `apply.package.refused`, with
   the roll-forward remedy. Tests:
   `crates/registry-breg/tests/postgres_migration.rs`:
   `real_postgres_refuses_the_active_package_again_and_binds_only_the_recorded_package`,
   `real_postgres_each_activation_is_one_ledger_row_in_apply_order`.
   `crates/registry-breg/tests/postgres_package.rs`:
   `real_postgres_package_startup_apply_failure_and_old_process_are_closed`,
   `predecessor_package_refuses_altered_or_forged_closure_bytes`,
   `predecessor_package_reports_the_digest_the_database_ledger_is_compared_with`,
   `production_package_loads_without_signatures_or_a_trust_anchor`,
   `package_without_the_shared_envelope_is_refused_by_every_reader`.
   `crates/registry-breg/tests/runtime_config.rs`:
   `shared_package_envelope_and_pin_are_checked_before_startup`.
   `crates/registry-breg/tests/postgres_startup.rs`:
   `instance_claim_refuses_a_package_root_its_expected_digest_does_not_pin`.
   `crates/registry-bregctl/tests/cli.rs`:
   `apply_verifies_package_intent_before_database_authority_and_stays_value_free`,
   `apply_refuses_a_stale_shared_envelope_before_database_authority`,
   `production_package_publishes_the_unsigned_package_in_one_step`,
   `package_always_uses_production_compilation_and_never_offers_a_signing_command`,
   `retired_package_flags_are_refused_as_unknown_arguments`.
   `crates/registry-bregctl/src/lib.rs`:
   `apply_chain_refusals_name_the_operators_next_command`.
   `crates/registry-breg/tests/compiler_contract.rs`:
   `deployment_identity_keys_in_the_project_are_refused_as_unknown_fields`,
   `registry_revision_is_a_function_of_the_compiled_model_only`.
2. **Migration credential and runtime credential.** `bregctl apply`, `bregctl
   plan`, and `bregctl status` connect through `database.migrationUrlRef` as
   the migration role; the runtime serves through `database.runtimeUrlRef` as
   the runtime role. The runtime role holds `SELECT` on `registry_state` and
   `USAGE` on the managed schemas, and no grant on `registry_migrations`,
   which is why plan and status read the ledger as the migration role. Tests:
   `crates/registry-breg/tests/postgres_migration.rs`:
   `real_postgres_status_reads_the_ledger_without_the_apply_lock`,
   `real_postgres_a_plan_reports_each_pending_activation_and_writes_nothing`,
   `real_postgres_a_plan_refuses_what_apply_refuses_and_changes_nothing`.
   `crates/registry-bregctl/tests/cli.rs`:
   `plan_and_status_refuse_before_database_authority_and_name_the_next_command`.
   `crates/registry-breg/tests/postgres_import_authority.rs`:
   `the_runtime_role_cannot_rewrite_or_remove_the_instance_claim`.
3. **Role separation.** The role mode comes from the runtime file: single when
   `database.roles.migration` equals `database.roles.runtime`, split
   otherwise, and split roles need structurally distinct database references.
   The privileges are then asserted, not inferred. The production runtime
   starter `bregctl init` writes is split; `bregctl dev` and the quickstarts
   run single. Under split roles, apply (before maintenance) and startup
   (before readiness) refuse a runtime role that could write the ledger or the
   registry state, each naming its exact fix: a superuser (`ALTER ROLE ..
   NOSUPERUSER`), a member of the migration role (`REVOKE <migration> FROM
   <runtime>`), the owner of a registry schema, relation, or routine (one
   `ALTER .. OWNER TO <migration>` for each object the runtime role owns in a
   registry schema, run as a database administrator and followed by `bregctl
   apply`, so the fix leaves what the runtime role owns elsewhere in the
   database alone), a member of such an owner (`REVOKE <owner> FROM
   <runtime>`), a holder of a write privilege or of `CREATE` on a registry
   schema, directly or through `PUBLIC` (`REVOKE .. FROM <grantee>`), and a
   trigger on a product table that no compiled migration creates (`DROP
   TRIGGER`). The `REVOKE` and `DROP` fixes end with "then rerun the refused
   command". The reason for the ownership check: an owner of a table apply
   touches can add a deferred constraint trigger that runs as the migration
   role when apply commits and writes the ledger. Apply issues the runtime
   grants the active package gives and treats missing split grants as a change
   pending, so an ownership change that strips them is repaired by the next
   apply; split startup refuses missing grants, naming `bregctl apply`. A
   change of runtime role or role mode over the active package is recorded as
   its own successor activation (`metadata-only`, a fresh activation id), and
   apply revokes every privilege of a runtime role the activation stops
   serving with. A one-role runtime file is refused against a database last
   activated for a separate runtime role. In either mode, a runtime role with
   superuser, `BYPASSRLS`, `CREATEDB`, `CREATEROLE`, or database `CREATE` is
   refused at startup. `bregctl doctor` and the startup log
   (`startup.role_mode.single`) say that single mode catches mistakes but not
   someone holding the credential. Tests:
   `crates/registry-breg/tests/postgres_migration.rs`:
   `real_postgres_split_apply_refuses_a_runtime_role_that_owns_a_model_table`,
   `real_postgres_split_apply_names_an_ownership_change_for_every_kind_of_owned_object`,
   `real_postgres_split_apply_refuses_a_runtime_role_that_holds_schema_create`,
   `real_postgres_split_apply_names_the_fix_for_every_runtime_write_authority`,
   `real_postgres_a_role_change_reapply_of_the_active_package_is_its_own_activation`.
   `crates/registry-breg/tests/postgres_startup.rs`:
   `split_startup_refuses_a_runtime_role_that_can_write_the_ledger_and_writes_nothing`,
   `one_database_role_applies_the_initial_package_and_serves_reads`.
   `crates/registry-breg/tests/postgres_kernel.rs`:
   `real_postgres_kernel_proves_roles_rls_interlock_and_pool_isolation`.
   `crates/registry-breg/tests/runtime_config.rs`:
   `split_roles_need_structurally_distinct_database_references`,
   `one_role_may_serve_as_runtime_and_migration_role`.
   `crates/registry-breg/src/postgres/migration_ledger.rs`:
   `role_mode_is_single_exactly_when_the_roles_are_equal`.
   `crates/registry-bregctl/src/dev/tests.rs`:
   `the_dev_registry_serves_with_one_role_and_its_rehearsal_stays_split`.
   `crates/registry-bregctl/src/lib.rs`:
   `doctor_says_what_one_role_mode_does_not_guard`.
4. **Audit integrity of `breg-activation-audit/v1`.** Before any activation
   state changes, apply writes a request entry (`phase: attempt`, `outcome:
   started`) under the activation id, naming the activation and prior
   activation ids, the package and predecessor digests, the registry
   revision, the plan kind, the database id, environment, and instance id,
   the role mode, and the operator reference hash. An audit that refuses the
   request leaves the database as apply found it and reports
   `ActivationAuditUnavailable`. If retained local hook work refuses apply
   before maintenance, the accepted request receives a terminal `refused`
   response. Failure to record that response reports
   `ActivationRefusalAuditIncomplete`: the active package is unchanged, the
   registry remains ready, and no target is pinned. After the activation
   commits, apply writes the response (`phase: terminal`, `outcome: applied`);
   an activation that fails after its request answers `failed` once the
   durable state shows the
   target did not land, and one interrupted mid-plan leaves the registered
   `unfinished` response. A response the audit refuses after the commit is
   reported as `ActivationAuditIncomplete`, never as a failed activation.
   `bregctl plan` rehearses and rolls back and never opens the activation
   audit. Tests: `crates/registry-breg/tests/postgres_migration.rs`:
   `real_postgres_each_activation_audits_its_request_and_its_applied_response`,
   `real_postgres_a_failed_activation_audits_its_failed_response`,
   `real_postgres_a_refused_activation_request_entry_changes_nothing`,
   `real_postgres_a_refused_supersession_record_reports_the_activation_audit_incomplete`.
   Retained-local refusal coverage:
   `crates/registry-breg/tests/support/hook_activation.rs`,
   `retained_hook_refusal_audit_failures_preserve_ready_state`.
5. **Operator-reference hashing.** `--operator-reference` is refused offline,
   before any connection, when it is empty, longer than 512 bytes, contains a
   control character, or the audit profile is not keyed. The ledger stores
   only `operator_reference_hash`, the keyed audit hash of the reference in
   the domain `breg-activation-operator-reference-v1` with the activation id
   as context, and the activation audit carries the same hash. Neither the
   ledger row, the audit entries, nor the command's output repeats the raw
   reference. Tests: `crates/registry-breg/tests/postgres_migration.rs`:
   `real_postgres_an_operator_reference_is_recorded_only_as_its_keyed_hash`,
   `real_postgres_a_refused_operator_reference_leaves_the_database_unactivated`.
   `crates/registry-bregctl/src/lib.rs`:
   `apply_reports_a_refused_operator_reference_without_repeating_it`.
6. **What startup refuses, in order.** Before the database: the package's
   `SHA256SUMS` verification, the `package.expectedDigest` pin, and the
   package closure with every artifact rederived. Then, under a shared
   advisory lock: a database with no registry state (naming `bregctl apply
   --package DIR --initial`) or with registry state this release does not
   recognise, such as the pre-ledger kernel (`UnrecognizedDatabase`, one
   generic refusal that names no recorded value and says a release reads only
   the state its immediate predecessor wrote); under split roles, a runtime role
   that can write the ledger or state, and missing runtime grants; the
   instance claim, against the live database's system identifier and oid;
   `identity.databaseId` against the database id the ledger recorded
   (`DatabaseIdentityMismatch`); and the package digest against the ledger's
   active digest (`ActivePackageMismatch`, naming `bregctl plan --package
   DIR` then `bregctl apply --package DIR`). A registry held in maintenance is
   not ready. Startup no longer compares a recorded environment or instance
   id, since neither is recorded in `registry_state`, and verifies no
   signature and no trust anchor. Tests:
   `crates/registry-breg/tests/postgres_startup.rs`:
   `startup_refuses_an_unapplied_database_naming_the_initial_apply_and_writes_nothing`,
   `startup_refuses_an_unrecognised_registry_state_and_writes_nothing`,
   `split_startup_refuses_a_runtime_role_that_can_write_the_ledger_and_writes_nothing`,
   `a_restored_copy_refuses_to_serve_until_adopted`.
   `crates/registry-breg/tests/postgres_package.rs`:
   `real_postgres_package_startup_apply_failure_and_old_process_are_closed`,
   `local_unsigned_package_rederives_every_artifact_and_refuses_filesystem_tampering`.
   `crates/registry-breg/tests/postgres_package/fingerprint.rs`:
   `package_fingerprint_starts_refuses_drift_and_upgrades_without_rewriting_package_bytes`.
   `crates/registry-breg/tests/postgres_migration.rs`:
   `real_postgres_an_unrecognised_registry_state_is_refused_and_changes_nothing`.

### Design invariant replaced

The promotion unit design's invariants 3 and 7 put the activation audit record
in the same transaction as the ledger row. That cannot hold: the audit journal
is a file written through the process audit writer, and it cannot join a
PostgreSQL transaction. The invariant as enforced is request before, response
after commit: no activation state changes until the audit accepts the request
entry, and every activation whose request was accepted is answered by exactly
one terminal response, `applied` after the commit, `failed` once the target
is known not to have landed, or the registered `unfinished`. A crash between
the commit and the response leaves an `unfinished` response beside a
committed ledger row; the ledger row is the authority on what is active, and
the request entry is the independent trace that the activation was
attempted.

### Accepted deviations from the design

- The `bregctl test` receipt (`schema-test-receipt/v2`) binds the
  project source closure, including every reviewed migration file by path and
  SHA-256, in place of the retired `signingInputSha256`. A changed review
  invalidates the receipt. Tests:
  `crates/registry-bregctl/tests/cli/reviewed_migrations.rs`:
  `reviewed_successor_changed_review_invalidates_the_schema_test_receipt`,
  `reviewed_successor_is_shared_by_test_and_package_without_placeholder_fingerprint`.
  `crates/registry-breg/src/fixtures.rs`:
  `schema_test_receipt_binds_the_exact_project_source_without_granting_authority`.
- `identity.instanceId` uses the build-id grammar, because the CloudEvents
  source URN embeds it. Test: `crates/registry-breg/tests/runtime_config.rs`:
  `an_instance_id_outside_the_event_source_grammar_is_refused_naming_the_key`.
- `identity.environment` must equal `identity.databaseInitializationEnvironment`.
  Test: `crates/registry-breg/tests/runtime_config.rs`:
  `disagreeing_environment_identity_keys_are_refused_naming_both_keys`.
- Startup no longer compares a recorded environment or instance id. The
  database id and the active package digest are the bindings startup checks;
  the environment and instance id come from the runtime file for reporting
  and audit.
- The instance id also derives the webhook event source the delivery
  worker requires of every stored envelope, so a rename while deliveries
  are pending would dead-letter them silently. Startup refuses while any
  pending or leased delivery with an unexpired payload names another
  source, naming the stored source, the configured instance id, and the
  count; delivered, dead-lettered, and expired work does not block. A
  durable binding of the instance id in the registry state is not taken
  here; it is tracked in #1710.
  Test: `crates/registry-breg/tests/postgres_startup.rs`:
  `startup_refuses_an_instance_id_change_while_deliveries_are_pending`.
- Re-applying the active package is refused as already active; an older
  package folds into `apply.package.refused`, which names the roll-forward
  remedy, rather than a separate older-than-active refusal. Tests:
  `crates/registry-breg/tests/postgres_migration.rs`:
  `real_postgres_refuses_the_active_package_again_and_binds_only_the_recorded_package`.
  `crates/registry-bregctl/src/lib.rs`:
  `apply_chain_refusals_name_the_operators_next_command`.
- An empty successor plan, and a migration reconciliation onto the active
  package, are refused offline, before any database authority. Tests:
  `crates/registry-bregctl/tests/cli/reviewed_migrations.rs`:
  `apply_reports_an_unchanged_successor_as_nothing_to_apply`.
  `crates/registry-bregctl/src/lib.rs`:
  `apply_reports_an_empty_successor_plan_as_nothing_to_apply`.
- Apply checks the field encryption configuration and custody, and the event
  configuration, before it reads the database configuration. Test:
  `crates/registry-bregctl/tests/cli.rs`:
  `apply_requires_safe_field_encryption_custody_before_database_authority`.
- `bregctl plan` and `bregctl status` use the migration credential, because
  the split runtime role cannot read the ledger.
- `bregctl plan` takes the exclusive apply lock and rehearses apply's own
  checks and statements inside transactions it rolls back, so a plan and an
  apply cannot interleave and a plan never reports a pass apply would refuse.
  `bregctl status` takes no apply lock.
- `bregctl plan` has no `--initial`: the plan kind (initial, successor, role
  change, or already active) is detected from the database.
- Model-table columns and settings keep the name `active_package_revision`;
  their value is the activation id. Renaming them would change the live
  catalog, so every registry would need model DDL to follow.

### An unrecognised registry state

A release reads only the registry state its immediate predecessor wrote. The
kernel's state shape is read from the PostgreSQL catalog before startup,
`bregctl status`, `bregctl plan`, or `bregctl apply` reads or writes registry
state. A database holding registry tables in a shape this release does not
recognise, such as the kernel a release before the activation ledger
installed, is refused with one generic refusal (`UnrecognizedDatabase`) that
names no recorded value: startup binds no listener, and status, plan, and
apply change nothing. The release does not adopt such a database; the
operator upgrades it one release at a time. A database an earlier release
adopted keeps its `adopted` ledger row and the package order that adoption
kept in `registry_pre_ledger_package_positions`, which field-encryption
history erasure still reads (BREG-SEC-122). Tests:
`crates/registry-breg/tests/postgres_migration.rs`:
`real_postgres_an_unrecognised_registry_state_is_refused_and_changes_nothing`,
`real_postgres_erasure_orders_the_revisions_an_adoption_kept`.
`crates/registry-breg/tests/postgres_startup.rs`:
`startup_refuses_an_unrecognised_registry_state_and_writes_nothing`.

### Accepted residuals

- **Anyone holding the migration credential can apply any valid successor.**
  Review is a process step before apply; cross-organization delivery is
  checked with the release's own provenance (for example cosign) in the
  deploy step. In the target deployments the people who would sign are the
  people who operate, so signatures stopped no one the migration credential
  does not already stop.
- **Replay after a database restore.** A database restored to an earlier
  activation names that activation's package as active, so the successor
  applied after it applies again. It is the same transition. A destructive
  reviewed migration still needs backup evidence at most 31 days old.
- **Single-role mode does not separate the credentials.** With one role, a
  holder of the runtime credential can write the ledger and change which
  package the runtime serves. `bregctl doctor` and the startup log say so;
  production runs split.
- **A database superuser can edit the ledger.** As with any data in the
  database, this is not prevented; the activation audit stream, shipped to
  append-only storage, is the independent trace.

## Import authorities

The change adds the `import` operation and the operator-opened import
authority it requires (`crates/registry-breg/src/import_authority.rs`,
`bregctl import-authority open|close|close-expired|list`).

### Threat

Change control refuses `create` and `batch` as direct writes on a governed
entity, so a governed entity needs a way to receive its initial load. Without
a bound, an `import` grant would be a standing direct write that change
control does not see. The threats:

1. An import grant writes with no operator-opened window (BREG-SEC-109).
2. An import run keeps writing after its window closed, expired, ran out, or
   was superseded by a package activation (BREG-SEC-110).
3. A load writes more records than the operator approved (BREG-SEC-111).
4. The runtime role opens, closes, or reopens a window for itself
   (BREG-SEC-112).
5. An import grant reaches an item or batch route outside an ingestion run
   (BREG-SEC-113).

### Enforcement and defaults

- Run creation calls `import_authority::admit_run` in the run-creation
  transaction; every chunk calls `admit_chunk` under the authority's row lock
  in the chunk transaction, before any item is written, and counts the
  chunk's committed items against the volume there.
- Only the migration role opens or closes an authority. The runtime role has
  `SELECT` and an `UPDATE` of the counter and terminal status of an open row,
  under row-level security that refuses reopening.
- One open authority per entity (partial unique index). The window defaults
  to 7 days and is at most 30, with no extension. At most 16 input digests.
  The authority binds the activation id active when it opened. A successful
  activation supersedes every open authority in its terminal transaction and
  appends each transition record after the commit; a failed activation
  supersedes none.
- The operator reference and reason are stored and audited only as keyed
  hashes. Every transition is collected in its transaction and appended
  through the process audit writer after the commit.
- `import` mounts no item or batch route; the compiler refuses it beside
  `batch`, without entity batch bounds, and without an authenticated
  principal.

### Tests

`crates/registry-breg/tests/postgres_import_authority.rs`:
`an_import_run_is_refused_without_an_open_authority`,
`closing_the_authority_blocks_the_next_chunk_and_keeps_committed_ones`,
`every_chunk_counts_against_the_authority_until_it_is_exhausted`,
`the_runtime_role_cannot_open_close_or_reopen_an_authority`.
`crates/registry-breg/tests/postgres_migration.rs`:
`real_postgres_a_successor_activation_supersedes_every_open_import_authority`,
`real_postgres_a_failed_successor_activation_supersedes_no_import_authority`,
`real_postgres_a_refused_supersession_record_reports_the_activation_audit_incomplete`.
`crates/registry-breg/tests/import_grant_compiler.rs`:
`batch_is_still_refused_on_a_controlled_entity_and_the_message_suggests_import`.

### Accepted residuals

- **Input digests are labels, not verification.** The client computes the
  input digest over the file it reads and announces it with the run; the
  server never receives the file and does not recompute it. A pinned digest
  names the file the operator expects, and a holder of the import grant can
  announce a pinned digest over other items. The item volume is the bound the
  server enforces. The docs and `--input-sha256` help say so.
- **Admission reserves no volume, and import is create only.** Two runs under
  one authority are each admitted against the remaining volume and stop when
  the counter fills; re-running lines that already committed creates their
  records again. The import guide states the duplicate behaviour.
- **The runtime role can lower `committed_items`.** Its column grant and
  update policy check the volume bounds, not monotonic growth, so a
  compromised runtime could refill an authority's volume. This is treated as
  equivalent to the runtime role's existing `INSERT` power over records.
- **Operator hash context.** The reference and reason are keyed with the
  activation id as context, so one operator's reference hashes differently
  across activations; `--operator-reference` and `--reason` are argv values
  visible on the local host while the command runs.

## Instance claim

The change records which PostgreSQL database a registry serves from and
refuses a copy until an operator adopts it
(`crates/registry-breg/src/instance_claim.rs`, `bregctl instance-claim
status|adopt`).

### Threat

A logical restore carries a registry's committed state into another
database. Without a claim, the copy serves beside its original and the two
become divergent writers of one registry: both accept writes, admit imports,
and deliver outbox work from the same history (BREG-SEC-114). A copy could
also adopt itself through the runtime role (BREG-SEC-115), carry an import
window the operator closed after the backup (BREG-SEC-116), or record itself
as the claim on its next apply (BREG-SEC-117).

### Enforcement and defaults

- Startup and every readiness probe compare the claim with the live
  database: the system identifier when both expose it, the database oid
  alone otherwise. A mismatch refuses startup and answers readiness 503 with
  `startup.instance-claim.mismatch`.
- The runtime role holds `SELECT` only on the claim.
- The claim lives in `registry_state`. An activation records the claim, in
  the transaction that commits its ledger row, only when the state row
  carries none, as for a registry upgraded from a release before the claim,
  so an in-place upgrade starts without an operator adopting the database. A
  recorded claim is kept by every activation, so a restored copy keeps its
  original's claim and refuses to serve until adopted. Reinstalling the schema
  beside committed history records no claim, so a database never claims
  itself outside an activation.
- `adopt --acknowledge-original-retired` moves the claim under the migration
  role, raises its epoch, and supersedes every open import authority in one
  transaction, then appends the audit response. On a database the claim
  already names it does the same, recorded with the event `reclaimed`: that
  is the post-restore step after a physical restore.

### Tests

`crates/registry-breg/tests/postgres_startup.rs`:
`a_restored_copy_refuses_to_serve_until_adopted`.
`crates/registry-breg/tests/postgres_import_authority.rs`:
`the_runtime_role_cannot_rewrite_or_remove_the_instance_claim`,
`adopting_a_restored_copy_supersedes_every_open_authority`,
`reclaiming_after_a_physical_restore_supersedes_every_reopened_authority`,
`reinstalling_the_schema_beside_committed_history_leaves_an_unclaimed_database_to_adopt`.
`crates/registry-breg/tests/postgres_migration.rs`:
`real_postgres_an_activation_records_the_claim_a_database_has_never_recorded`,
`real_postgres_an_activation_keeps_a_claim_that_names_another_database`.

### Accepted residuals

- **Physical copies are not detected.** Point-in-time recovery, storage
  snapshots, and base backups keep the system identifier and database oid, so
  the copy matches the claim and serves without adoption, and an import
  authority closed after the backup point is open again on it. BREG-SEC-116
  holds for a physical restore only once the operator runs `bregctl
  instance-claim adopt` on it before it serves, which nothing enforces.
  Fencing the original stays with the operator.

## Audit retention and prune

This change adds no BReg audit prune, export, or retention floor. BReg
audit retention is the platform audit writer's file rotation and
`retentionDays`, and tamper evidence is shipping the stream to append-only
storage, as the operator documentation describes.

## Review recovery

The change adds `bregctl review-recovery resubmit|close` for a change-request
review its authority will not answer
(`crates/registry-breg/src/review_recovery.rs`), and orders the result poller
so fresh and webhook-signalled reviews go before reviews the authority
reported unknown.

### Threat

An operator action changes the state of a governed review. The threats are
resubmitting a review the authority already decided, opening a second review
beside a live one, and an unaccountable operator change to review state.

### Enforcement and defaults

- Both operations run in one verified migration transaction under the
  registry lock, behind the operator boundary request retention uses: package,
  database identity, and migration role are verified first.
- An audit `request` entry is accepted before the transaction opens and its
  `response` is written after the commit, naming the request only by its
  keyed reference. A commit whose response the audit destination refuses is
  reported as unaudited.
- Resubmission is limited to failure codes that mean BReg stopped waiting
  (`result-poll-attempts-exhausted`, `submission-recovery-expired`,
  `operator-closed`) and resends the exact retained request under its
  original idempotency key. A withdrawn proposal, a recorded result, an
  erased request, or a proposal no longer submitted is refused by a closed
  reason naming the state and code.

### Tests

`crates/registry-breg/tests/postgres_change_requests.rs`:
`an_operator_resubmits_or_closes_a_review_its_authority_lost`.
`crates/registry-breg/tests/postgres_review_executor.rs`:
`a_webhook_completion_makes_its_review_due_and_first_in_the_poll_queue`.

### Accepted residuals

- **Close does not withdraw the review at the authority.** `close` is
  allowed on any accepted review without a result; BReg sends nothing to the
  authority, so a reviewer there may still decide, and that late result is
  then refused. `operator-closed` is resubmittable, so the close is
  reversible.
- **Resubmission relies on the authority's idempotency.** If the authority
  no longer honours the original key, resubmitting opens a second review.
  The operator documentation says to confirm the authority lost the review
  first.
- Reviews the authority reported unknown still poll until the attempt
  budget fails them, ordered last.

## Package building and byte binding

The change wraps the BReg package in the shared package envelope
(`SHA256SUMS`, optional `REVISION`) and binds every consumer to the bytes the
shared verification checked (`crates/registry-breg/src/package.rs`,
`crates/registry-breg/src/runtime_config.rs`, `bregctl package`).

### Threat

A package file changes between verification and use, a package is swapped for
another under the same path, or an operator runs a package other than the one
they reviewed (release provenance).

### Enforcement and defaults

- Startup, `apply`, and operator tooling verify the shared envelope before
  any database authority is used: every listed file is re-hashed, and a
  changed, missing, or extra file, a symbolic link, or a special file is
  refused by name. `package.expectedDigest`, when set, must equal the package
  digest.
- The active and predecessor package loads read each file once and bind it
  to the per-file digest the shared verification recorded, so every later
  check runs over the verified bytes.
- `bregctl package` writes the envelope deterministically and still requires
  the `bregctl test` receipt.

### Tests

`crates/registry-breg/tests/runtime_config.rs`:
`shared_package_envelope_and_pin_are_checked_before_startup`.
`crates/registry-bregctl/tests/cli.rs`:
`apply_refuses_a_stale_shared_envelope_before_database_authority`.
`crates/registry-breg/tests/postgres_package.rs`:
`package_builder_is_deterministic_and_local_publication_loads`,
`local_unsigned_package_rederives_every_artifact_and_refuses_filesystem_tampering`.
`crates/registry-platform-config/src/package_tests.rs` covers the shared
writer and verifier.

### Accepted residuals

- A freshly supplied successor package is loaded without the active
  package's byte binding, because it verifies its own envelope on load.
- The OIDC issuer and JWKS URI accept loopback `http` in every environment,
  as before this change; `operate/breg.mdx` recommends an `https` issuer for
  production.

## Rehearsing over a predecessor built by an earlier release

The migration rehearsal's predecessor fingerprint comparison is advisory
(`rehearse_in_transaction` in `crates/registry-breg/src/postgres/rehearsal.rs`).

### Threat

A live registry runs a package an earlier engine release built. If the
rehearsal refused every predecessor whose measured catalog differs from its
recorded fingerprint, the operator could not test a successor, so an upgrade
stalls. Relaxing that comparison must not let a successor reach a schema the
candidate does not declare (release provenance).

### Enforcement and defaults

- The rehearsal's predecessor fingerprint comparison is advisory. The package
  manifest does not record which engine release built it, and the managed
  catalog includes tables the engine owns, so a predecessor built by an
  earlier release always drifts. A drift is reported as
  `migration.rehearsal.baseline-fingerprint-drift`, with the recorded and the
  measured fingerprints, and it does not stop `test`. Activation is still
  protected by the other checks. A predecessor schema that the current
  compiler cannot install is refused. The rehearsed migration must reach the
  candidate's own fingerprint. `apply` checks the live database before it
  migrates.
- The rehearsal installs the predecessor schema from the baseline the
  candidate's migration plan binds, not from the schema the predecessor's
  sources compile to under this compiler, so an engine-owned object this
  compiler adds, such as a reference index, is rehearsed as the plan creates
  it rather than refused as already present.

### Tests

`crates/registry-breg/src/tooling.rs`:
`a_packaged_baseline_without_an_index_reports_the_index_the_plan_adds`.
`crates/registry-breg/tests/postgres_migration.rs`:
`real_postgres_rehearsal_refuses_a_reviewed_plan_activation_would_refuse`
covers both a drift that is reported and a final mismatch that is still
refused, and
`real_postgres_rehearsal_refuses_a_predecessor_it_cannot_install` covers the
install refusal.
`crates/registry-breg/tests/postgres_reference_indexes.rs`:
`the_rehearsal_installs_a_predecessor_baseline_without_reference_indexes`.
`release/scripts/rehearse-upgrade.py --product breg` runs the upgrade from the
previous release end to end.

### Accepted residuals

- The same-engine fingerprint comparison does not stop `test`. The
  predecessor fingerprint is part of the package bytes `SHA256SUMS` binds, so
  a drift under the same engine comes from compiler nondeterminism or from a
  predecessor package altered together with its `SHA256SUMS`, and the strict
  final check still catches any effect on the candidate.

## Read paths over a target the profile holds no entry for

The change lets a read path answer when the caller's profile holds no
permission entry for the path's target entity
(`install_request_visibility_context` in
`crates/registry-breg/src/mutation.rs`). It changes which requests a
configured read route answers: such a request answered
`503 source.unavailable` before any row was read, and now returns what the
path grant authorizes.

### Threat

A relationship traversal inherits direct target rights, or widens the
target projection, filtering, ordering, or count authority its path grant
configures (BREG-SEC-21). A second threat is new here: skipping the owner
request visibility a change-request target would otherwise install, so a
profile that declares `requestVisibility: owner` sees other owners'
requests.

### Enforcement and defaults

- Admission is unchanged. `authorize_read_path_route` in
  `crates/registry-breg/src/api/mod.rs` admits the request only when the
  selected profile's entry on the source entity declares the path, and the
  HTTP layer conceals an undeclared path exactly like an unknown one, before
  record I/O. The response projection is the path grant's readable fields.
- Rows are bounded by the generated target policy
  (`read_path_target_policy` in `crates/registry-breg/src/generated_ddl.rs`),
  which requires the installed path id and root id, an active edge from that
  root, and the source profile's authority over the root. A target
  permission entry never took part in that policy, so its absence widens
  nothing.
- The function now looks the profile up only for a change-request entity,
  and installs the owner reference only when that entry declares
  `requestVisibility: owner`. A profile without an entry cannot declare owner
  visibility there, so there is nothing to install; the owner-scoped policy
  it would feed belongs to that entry and is not generated for the profile.
- Writes are unchanged. Both write call sites run after `validate_request`
  (and the batch validator), whose `selected_profile` refuses a profile
  without an entry on the written entity as `request.invalid` before any
  transaction opens. The attachment read path cannot reach it without an
  entry either: `execute_attachment` requires one before record I/O, so
  `load_authorized_attachment` keeps its code.

### Tests

`crates/registry-breg/tests/postgres_client_relationships.rs`:
`read_path_answers_when_the_profile_has_no_entry_for_its_target_entity`
returns exactly the one linked record under the path grant's projection,
and refuses a profile without the path grant with the same
`404 resource.not_found` as an unknown path.
`read_path_to_a_change_request_entity_leaves_owner_visibility_to_its_own_profile`
reads every linked request through the path, and proves each owner-visibility
submitter still sees only its own request; it fails if the owner reference is
not installed. The BREG-SEC-21 negative test
`relationship_route_uses_path_grant_not_direct_target_rights` in
`crates/registry-breg/tests/http_read_only.rs` is unchanged and still holds.

### Accepted residuals

- Other failures inside `read_rows` still answer `503 source.unavailable`;
  this change removes only the one a compiler-accepted configuration could
  reach on a healthy database.

## Located record and query refusals

The change adds a `fieldPath` to record and query `400` refusals
(`crates/registry-breg/src/problem_location.rs`, `admit_submitted_names` in
`crates/registry-breg/src/mutation.rs`, and `invalid_request_at` and
`invalid_query_at` in `crates/registry-breg/src/api/mod.rs`). It changes
what a refusal tells the caller.

### Threat

A refusal location discloses a field the caller's grant withholds, or lets
the caller tell an unknown name from a withheld one, so the refusal becomes
a probe of the compiled model. A location that echoes caller text also
carries caller-controlled bytes into responses and logs.

### Enforcement and defaults

- `fieldPath` is built only by `RequestLocation`'s constructors and by the
  fixed `QUERY_PARAMETERS` list and header names (`Idempotency-Key`, and
  `If-Match` on a batch, never the header's value). It carries a fixed envelope
  member, a compiled API name the caller's grant admits for writing, or a
  fixed parameter or header name. Every pointer segment is RFC 6901 escaped
  and the whole pointer is bounded to the schema's 256 characters.
- A name the caller supplied is never echoed. An unknown or withheld create
  member stops at `/data`, a patch path at `/<n>/path`, a batch item at
  `/items/<n>/data`, and a field inside `$select`, `$filter`, or `$orderby`
  at the parameter. An unrecognized query parameter or body member names no
  location at all.
- The index a location carries cannot depend on whether a withheld field
  exists. `admit_submitted_names` checks every submitted name against the
  selected grant in one pass, in body order, before normalization, value
  checks, or any record I/O, and treats an unknown name and a withheld name
  identically. Before this change a patch `test` of a withheld field was
  refused only inside the transaction, after an unknown one had already been
  refused at normalization; both now take the same branch before I/O.
- Query locations are attributed after parsing and admission in a fixed
  order that never consults the grant, so which parameter is named does not
  depend on a withheld field either. The feature API and lookup bodies keep
  their unlocated refusals: the feature API speaks its own parameter names,
  and lookup refusals keep the value-free equivalence BREG-SEC-20 pins.
- `detail` and `code` are unchanged, so typed clients keep matching them,
  and the Rust client accepts the new forms only on `request.invalid` and
  `query.invalid`. It retains a location only after the shared 256-character
  bound, BReg's closed location grammar, and the permitted problem-code pairing
  all pass; any other location is a protocol failure. Rust exposes the validated
  value only through the explicit `field_path` accessor, Node.js and Python copy
  it to their explicit error attributes, and no binding renders it through
  `Debug`, `Display`, or the exception message. The Node.js attribute is
  non-enumerable, so default `util.inspect`, `console.error`, and JSON object
  serialization omit it while direct `error.fieldPath` access remains available.

### Tests

`crates/registry-breg/tests/postgres_mutation.rs`:
`record_and_query_refusals_name_only_fixed_members_and_admitted_fields`
asserts byte-identical problems, apart from `traceId`, for an unknown and a
withheld field in a create body, a patch path, a patch `test`, a batch item,
`$select`, and `$filter`, including a withheld field placed ahead of an
unknown one, and asserts that no withheld or unknown name appears in any
body. It also refuses a create that omits a required field the grant does
not let the caller write at `/data`, byte-identical to an unknown field,
and a batch `If-Match` header at `If-Match`. `crates/registry-breg/tests/postgres_mutation_logical_names.rs` pins
the kebab-case field id refused at `/data`.
`crates/registry-breg/src/problem_location.rs` pins the rendered and
accepted grammar, and
`crates/registry-breg-client/tests/write_http_boundary.rs`:
`record_and_query_problem_paths_are_closed_bounded_and_retained_without_rendering`
pins the client's closed forms, retains every permitted location through the
explicit accessor, rejects malformed or code-incompatible locations, and proves
that retained locations do not enter rendered errors. The Node.js refusal tests
likewise retain action, record, and query locations through direct attribute
access while proving that default inspection and console formatting omit them.

### Accepted residuals

- A located refusal tells the caller which of its own admitted fields or
  parameters was wrong, and that a required field it may write is missing.
  Both are already in the caller's filtered contract.
- Application code using a typed client receives that validated location as a
  separate machine-readable attribute. It never receives arbitrary response
  text or a location that failed the closed grammar and problem-code pairing.
- Ingestion chunk items still answer an unlocated `request.invalid`.


## Row-boundary write refusals

The change refuses a direct create, patch, or batch item whose resulting row
falls outside the caller's row boundary with `412 precondition.failed`,
checked in Rust before any write (`authorize_record_snapshot` in
`crates/registry-breg/src/mutation.rs`, over
`ClaimContext::authorizes_record_snapshot` in
`crates/registry-breg/src/postgres/context.rs`; mapped by `mutation_problem`
in `crates/registry-breg/src/api/mod.rs`). Before it, the generated RLS
`WITH CHECK` policy refused the write inside PostgreSQL and the caller saw
`503 service.unavailable`, indistinguishable from an outage (#1771). It
changes authorization and what a refusal tells the caller.

### Threat

A write outside the boundary lands, or its refusal becomes a probe: it echoes
the prospective value, answers differently for a row that exists but is
hidden than for one that does not, or answers a unique-value conflict with a
row the caller cannot see. A second threat is the opposite mistake: turning a
real privilege failure into a `412`, so an operator misreads a broken role
grant as caller error.

### Enforcement and defaults

- The prospective row is checked against the compiled row boundaries with the
  same typed canonical values the generated row policies compare. A create
  checks its body before `admit_submitter_targets` and the insert; a patch
  checks the current row merged with the patch; an attachment write, which
  changes no field, checks the current row before the object store or the
  attachment table is written. A batch runs each item through the same path
  in one transaction, so one refused item commits none.
- The refusal is the fixed `precondition.failed` problem a stale `If-Match`
  answers, with no field name, value, or boundary claim in the body or the
  audit record. It is audited as a refusal and caches no idempotency result.
- RLS stays the storage backstop. A row the Rust check admits still meets the
  generated `WITH CHECK` policy, and a PostgreSQL failure of it, or of a
  table privilege, stays `503`: only `MutationError::AuthorizationRefused`,
  raised by the Rust check, maps to `412`. A malformed compiled claim context
  is an internal error and also stays `503`.
- A row the boundary hides stays invisible. A read of it answers
  `404 resource.not_found`, byte-identical to an absent id. A patch of it
  answers the `412` a patch of an absent id answers, because the guarded
  write finds no row to compare its `If-Match` with; this is the absence
  outcome mutations already used, not a new one.
- The boundary check runs before any unique constraint is consulted, so an
  out-of-boundary create that collides with a hidden row's unique value
  answers the same `412` as one that collides with nothing.
- Ingestion maps the refusal to a refused item, like a failed precondition.

### Tests

`crates/registry-breg/tests/postgres_mutation.rs`:
`real_postgres_row_boundary_write_refusals_are_safe_audited_and_atomic`
(BREG-SEC-138) pins the value-free `412` for a create and a patch, the
unchanged durable counts apart from the refusal audit, and a revoked table
privilege still answering `503`.
`real_postgres_row_boundary_refusals_reveal_no_hidden_row_and_batches_write_nothing`
pins a batch with one out-of-boundary item committing nothing, a patch and a
read of a hidden row byte-identical to an absent id, and an out-of-boundary
create colliding with a hidden unique value byte-identical to a
non-colliding one, with an in-boundary control proving the constraint fires.
`crates/registry-breg/src/postgres/context.rs`:
`optional_boundary_absence_is_a_refusal_while_malformed_snapshots_are_invalid`
pins an omitted or null boundary field as a refusal and a malformed snapshot
as an internal error.

### Accepted residuals

- The Rust check restates the generated row policy. If they diverge, a row
  RLS would admit is refused with `412`, or a row RLS refuses reaches
  PostgreSQL and answers `503`; neither writes outside the boundary.
- A unique constraint spans every boundary. An in-boundary create that
  collides with a hidden row's unique value still answers the value-free
  `409 mutation.conflict` (BREG-SEC-09), which tells the caller that value is
  taken somewhere. That is a property of a global unique constraint, not of
  this change.
- The attachment-write ordering is pinned by review only: the check can
  refuse there only when RLS shows a row the Rust boundary refuses, and the
  only effect it prevents is an unreferenced object left in an S3 store, which
  the Postgres suites cannot observe without a real S3 endpoint.

## First-party exchange clients in the local issuer

`bregctl dev` gives a multi-purpose client one generated first-party purpose
connection on the local ThunderID, and the client keeps its ordinary
authored scopes. That needed a change to the shared issuer description check
in `crates/registry-thunderid-tooling/src/description.rs`
(`IssuerDescription::validate`, the `token_exchange` branch).

### What changed

Before, every client with `token_exchange` had to hold exactly one permission
set: the assertion resource server with only the assertion scope, so its
client-credentials token could do nothing but bootstrap an exchange. Now the
rule depends on the mapping:

- A client listed on an `institutional_grant` connection, or on none, keeps
  the exact rule unchanged. The new `exact_bootstrap` condition is the
  logical negation of the old refusal.
- A client listed on a `first_party` connection passes when any of its role
  permissions on the assertion resource server contains the assertion scope,
  so its other authored permissions stay on its ordinary token. It is still
  refused when it holds no such permission.
- The first-party connection still signs only the claims it declares, at most
  16 attributes and 32 clients, and a client may be listed on one first-party
  signer only. `bregctl dev` refuses a multi-purpose clients file that would
  exceed those bounds before rendering. It also refuses a multi-purpose client
  listed on any authored exchange connection, whatever its mapping: the
  generated purpose connection already makes that client first-party, and the
  issuer then projects only that connection's claims into its exchanged
  tokens, so an exchange through an authored `institutional_grant` connection
  would omit the `registry_grant_*` claims BReg requires.

### Why this is tooling scope

The crate renders a development session's ThunderID declarative resources and
ships in no runtime: `registry-bregctl`, `registry-caseworkctl`, and
`registry-evidencectl` depend on it, and `registry-casework`,
`registry-evidence-client`, and
`registry-evidence-oid4vci` only as a dev-dependency. A production issuer is
operated separately, and each runtime still enforces its own issuer,
audience, scope, and boundary checks on every token, so a wider local client
token grants nothing a runtime profile does not.

### Effect on the other adopter CLIs

- `caseworkctl dev` builds only `institutional_grant` exchange connections
  (`crates/registry-caseworkctl/src/dev/integrations.rs`), so its clients meet
  the unchanged exact rule.
- `evidencectl dev` renders through `typed_local_description`, which sets no
  `token_exchange` and no exchange issuers, so the branch never runs for it.
- An exchange client on a first-party connection can now hold scopes beyond
  the assertion scope. Evidence already refuses to admit a client the owner
  also registered as a token-exchange client (`products/evidence/README.md`),
  so a borrowed BReg issuer session does not widen Evidence admission.

### Purpose JWKS listener

The local issuer fetches the dev purpose signer's JWKS from
`host.docker.internal` while `bregctl dev` acquires the alternate-purpose
tokens (`exchange_tokens` in `crates/registry-bregctl/src/dev/purpose.rs`).
On macOS the listener binds loopback. Linux Engine maps that name to the
bridge gateway, which a loopback listener never sees, so on Linux it binds
every interface, and anything on the host's networks can read the JWKS for
that window. It serves one public key and no other route, and it is stopped
once the tokens are acquired. The private key never leaves the owner-only
dev state directory.

### Tests

`crates/registry-thunderid-tooling/src/description.rs`:
`first_party_exchange_preserves_authored_client_permissions` accepts a
first-party client with an extra authored scope and refuses one whose
permissions lack the assertion scope.
`crates/registry-bregctl/src/dev/tests.rs`:
`multi_purpose_claim_union_is_refused_above_the_issuer_attribute_limit` and
`multi_purpose_client_is_refused_on_any_authored_exchange_connection` pin
the dev-side refusals.

## Automatic application recovery and retained webhook discard

Three operator and runtime paths change authority or destroy retained work.
Each carries an invariant row (BREG-SEC-139 to BREG-SEC-141) and a named
PostgreSQL negative test.

### Executor credential renewal

A review executor authenticates with exactly one of a fixed `tokenRef` or a
`privateKeyJwt` client assertion, and the runtime fetches a fresh token before
each discover and apply call. Token acquisition errors are value-free. A
token the authorization server refuses, or one the provider cannot use as
configured, blocks the job as `executor-denied` at once, so renewing the
credential and running `retry-application` resumes it; an unavailable
provider or a failed token exchange is retried as transient. The
outbound review lease is four times the request timeout so a token fetch
cannot outlive it. Dev binds a native executor only to a service client whose
apply profile, scopes, purpose, and principal match, at most eight of them.

### Requeueing an application blocked by executor authorization

`bregctl review-recovery retry-application` requeues only an application job
blocked with `executor-denied`, for the current submitted proposal with its
exact unexpired approval. It locks the job, submission, request, proposal, and
approval window rows, keeps the job's idempotency key, and refuses withdrawn,
unsubmitted, unapproved, and wrong-state requests. The worker still needs
current source authority when it resumes, so the retry grants nothing the
executor's corrected credentials or grants do not.

### Discarding a retained delivery

`bregctl hook discard` permanently closes one pending delivery, dead
letter with retained payload, or expired lease at its exact generation. The
generation and lease checks run under `FOR UPDATE` on the delivery state and
the shared outbox row, and a worker cannot apply after the discard because it
must still own the lease. A delivery with a proposal receipt is listed as
ineligible and refused, so a discard never hides a proposal an earlier
attempt committed or may still be applying. The shared payload stays while a
sibling delivery needs it. The request is audited before the mutation and
answered after commit through a readback. Refusals before the request is
recorded (stale generation, ineligible state, active lease, no payload) are
not audited.

### Local hook activation and settled URL completion

Activation must neither strand local work under an unavailable package nor
give a late predecessor answer successor authority. The retained-local
inventory in `crates/registry-breg/src/postgres/interlock.rs` guards plan and
apply before maintenance in `migration.rs`. Across captured revisions it counts
pending or leased local rows and operator-replayable dead letters with retained,
unexpired payloads. Other terminal metadata, non-replayable dead letters, and
rows whose payload expired or was erased can remain after activation.
`bregctl hook drain` attempts
only due local work for the active activation, with attempt and time bounds.
It preserves URL work, live leases, future retries and dead letters for their
existing recovery paths; a drain can itself produce more governed hook work.
Apply rechecks retention under its activation lock.

Drain executes reviewed Rhai/Wasm handlers in the `bregctl` process. In
`crates/registry-breg/src/hooks.rs`,
`HookOperatorService::from_runtime_config_with_execution` loads the active
package and execution configuration and uses the runtime database connection.
It needs the configured destination and audit secrets, handler assets, and,
when fields are encrypted, the existing field-encryption provider and keys.
The CLI may run on a different authorized operator host with access to those
assets, secrets, and the runtime database. It preserves serving-path custody
restrictions, including the local-only file key provider; it does not require
a migration credential. Listing,
replay and discard do not enable the execution-only Wasm runtime or
field-encryption service.

`crates/registry-breg/src/mutation/action.rs::apply_hook_change` recovers a
committed receipt before classifying an uncommitted answer against the live,
ready activation. An uncommitted proposal classified under a successor is a
non-replayable `hook.proposal.package_unavailable` dead letter. If completion
is interrupted before recording a proposal result and no receipt is recoverable,
final-lease recovery instead records `worker-interrupted` with no proposal code.
Explicit replay may remain eligible and send the event to the receiver again;
only a returned proposal classified under the successor receives the package
refusal. This does not give the old event successor mutation authority.

For a decision already settled, `settled_url_proposal` in
`crates/registry-platform-hooks/src/delivery/store.rs` admits completion only
for a URL handler with `Accepted` plus `Applied` or
`Refused`, or `Permanent` plus `DeadLettered`. Dispatch's
`crates/registry-platform-dispatch/src/postgres/dispatcher.rs` invokes its
separate finish verifier only for raw `Accepted` or `Permanent` outcomes.
Raw `MaybeSent` and `Transient` retain the ordinary verifier even if their
captured policy would make the next state terminal. BReg's
`verify_proposal_completion` omits only the `active_package_digest`,
`active_activation_id`, and `schema_fingerprint` comparisons. It retains
`package_id` and `database_id`, ready maintenance state, and the shared
activation lock. The store preserves exact lease token, generation, and
attempt comparisons, audit ordering, and commit-fate handling.
Claims, source reads, mutations, recovery and operator replay/discard/cancel
retain the ordinary active-package check. So do local, non-proposal,
transient, maybe-sent and inconsistent outcome pairs. The shared Dispatch
default remains strict for other consumers.

Coverage in `crates/registry-breg/tests/support/hook_activation.rs` includes
`retained_local_hooks_refuse_plan_and_apply_before_maintenance`,
`retained_hook_refusal_audit_failures_preserve_ready_state`, the local drain
scope, time-budget and Wasm tests, the in-flight predecessor answer and
committed-receipt tests, and
`classified_proposal_completion_preserves_registry_and_lease_fences`.
Its faults cover the lease token, generation, database, package, maintenance
state, and an unreadable registry state. No fault case covers the attempt
comparison in the shared Dispatch lease transition or the shared activation
lock that `verify_delivery_transaction` in `crates/registry-breg/src/hooks.rs`
takes; both are enforced, and their assurance rests on review of that code.
`in_flight_predecessor_answer_keeps_unreadable_activation_uncertain` continues
through final-lease recovery, explicit replay, a second receiver request, and
the successor's proposal refusal without a mutation. Complementing this
classified-completion coverage for BREG-SEC-67,
`real_postgres_terminal_retry_fences_a_late_proposal_application` in
`crates/registry-breg/tests/postgres_hook_changes.rs` retains the older
terminal-retry fence regression.
`crates/registry-platform-hooks/src/delivery/store.rs` tests the 48 typed
outcome combinations in
`only_consistent_terminal_url_proposals_use_completion_verification`.
`crates/registry-platform-dispatch/tests/postgres_dispatch.rs` covers the
default in `default_finish_verification_preserves_the_consumer_identity_fence`.
Its `completion_override_cannot_finish_*_with_refused_identity` tests cover
raw uncertain and transient outcomes, including exhausted policies, with a
permissive completion override and a refusing strict verifier. The refused
finish preserves the leased state, generation, attempt, lease token, and audit;
`completion_override_allows_accepted_and_permanent_with_refused_identity`
provides the allowed controls.

### Loopback destination names

The shared destination policy refuses `localhost` and `*.localhost`
(case-insensitive, trailing dot included) early. This only narrows what a
configuration may name.

## Immediate-action field sets under a locale collation

The change orders the written-field set in the generated immediate-action
row policy with the `"C"` collation
(`immediate_action_effect_group_expression` in
`crates/registry-breg/src/generated_ddl.rs`). The runtime binds each write to
the exact set of fields its selected effects may write, as a byte-ordered
array in the `registry.immediate_action_target_context` setting
(`action_target_group_context` in `crates/registry-breg/src/mutation/action.rs`),
and the policy compares it with jsonb array equality, which is
order-sensitive. The policy rebuilt the array ordered by the database's
default collation, so under a locale such as `en_US.utf8`, which ignores
hyphens at the first comparison level, `awarded-by` sorted before
`award-number` on one side and after it on the other, and PostgreSQL refused
the write with `503 service.unavailable` (#1820). It changes a row-level
security policy.

### Threat

The change widens what an immediate action may write: a context naming a
field outside the selected effects, omitting one, or repeating one passes the
policy.

### Enforcement and defaults

- Only the ordering used to build the comparison array changes. The policy
  still requires `fields` to equal exactly the distinct fields declared by the
  compatible selected effects; a context with an extra, missing, or
  duplicated field yields a different array and is refused. The effect ids,
  action id, contract fingerprint, profile, principal, purpose, target
  entity, operation, package revision, and target record predicates are
  unchanged.
- Before the change the two arrays held the same elements and could differ
  only in order, so the defect could refuse a write that should be accepted
  but never accept one that should be refused. `"C"` compares bytes, which is
  Rust's `String` order for UTF-8, so both sides now agree on every database
  collation.
- The Rust enforcement point, the context built from the compiled ceiling, is
  unchanged.
- An existing database keeps the old policy text until a package compiled by
  this release is activated; activation re-creates every compiled policy.

### Tests

`crates/registry-breg/tests/postgres_immediate_action_requirements.rs`:
`action_effect_fields_are_authorized_under_a_locale_collation` creates its
database with `en_US.utf8` collation, first asserts that the database orders
`awarded-by` before `award-number`, then expects the action to answer `200`
and store both fields. It answered `503` before the change. The existing
immediate-action PostgreSQL suites still pass on an `en_US.utf8` server.

### Accepted residuals

- The policy's refusal of a mismatched field set is pinned through the
  runtime's own contexts; no test sets a hand-built context with an extra
  field as the runtime role. That backstop predates this change.

## Background task supervision and worker progress metrics

The change makes a stopped background task end the process
(`SupervisedTask` and `serve` in `crates/registry-breg/src/startup.rs`, the
exit in `crates/registry-breg/src/main.rs`), reports failed review worker
iterations (`ReviewWorker` in `crates/registry-breg/src/review_store.rs`),
and adds three series to the metrics listener
(`crates/registry-breg/src/metrics.rs`): how long ago each worker last
completed an iteration, how long the oldest due item in each queue has
waited, and the package digest the process verified at startup. Successful
webhook iterations reach BReg through
`DeliverySeams::iteration_succeeded` in
`crates/registry-platform-hooks/src/delivery/seams.rs`. It changes a
deployment default: a worker or metrics listener that panics or returns
before shutdown is requested no longer leaves `breg` serving, and the
process exits with status 1. Its invariant row is BREG-SEC-146.

### Threat

A worker that dies while the process serves silently halts webhook
delivery, attachment verification, review submission and application, or
subject access log retention, and the last of these is a data-minimization
control. The process keeps answering `GET /ready`, so nothing outside it
notices. The added metrics could disclose data or credentials, or let a
scrape exhaust the runtime pool or hold locks the workers need.

### Enforcement and defaults

- `serve` supervises the webhook, attachment verification, review, and
  subject access log retention workers it starts, and the metrics listener.
  A task that panics or returns before shutdown is requested emits a closed,
  value-free `<task>.panicked` or `<task>.returned` error event, shuts the
  rest down within the shutdown grace, and returns
  `StartupError::BackgroundTaskStopped`; `main` logs
  `Base Registry Engine stopped` and exits 1. A requested shutdown reports
  no stop. `breg` does not restart a task in process, and `/ready` does not
  reflect worker state; recovery is the supervisor's restart.
- A failed review worker pass emits `review.worker.iteration_failed` instead
  of counting as idle, and the worker returns when its shutdown sender is
  dropped. The lookup outage warning joins the closed vocabulary as
  `review.result_lookups.unavailable` and drops its count field. The result
  feed's outage warnings stay outside that vocabulary: they back off per
  authority, warn only on a transition, and name the configured authority
  identifier.
- `breg_worker_last_success_age_seconds` carries only a closed `worker`
  label and an age; it is absent until the worker first succeeds. The
  attachment verification worker notes a success only for a pass that
  reached a verdict, or that found no due job while no job an earlier
  attempt failed waits for its retry and no verifiable pending verdict is
  stranded without a job that can still run. A pass whose content read or
  verifier request failed and left its job pending for a retry is never a
  success, and neither is an idle pass during that retry wait.
- `breg_queue_oldest_pending_age_seconds` carries only a closed `queue`
  label (`hook-delivery`, `review-submission`, `review-application`) and
  an age. Each scrape takes one runtime pool connection, serialized across
  scrapes by a mutex, inside a read-only transaction whose statement timeout
  is 5 seconds, and runs one aggregate statement that reads only
  `next_attempt_at`, state, lease, and attempt columns, never a row id,
  payload, or record value. A failed sample omits every queue line and
  emits the value-free `metrics.queue_sample.failed`. A webhook delivery
  whose lease expired is claimable again, so the webhook age counts it from
  `lease_expires_at`, and a process that stopped holding a lease cannot
  hide its delivery from the queue age. A review submission claim extends
  `lease_until` without advancing `next_attempt_at`, so the review
  submission age counts a claimable row from the later of the two.
- `breg_active_package_info` publishes the `package_digest` startup already
  verified against the activation ledger, a `sha256:` digest of the package
  bytes, and nothing else.

### Tests

`crates/registry-breg/tests/startup_http.rs`:
`a_panicking_background_task_stops_serve_with_a_distinct_error`,
`an_early_returning_background_task_stops_serve_with_a_distinct_error`,
`a_requested_shutdown_reports_no_background_task_stop`, and
`every_operational_event_renders_exact_closed_value_free_json_fields`,
which covers every stop code and the review and metrics events.
`crates/registry-breg/tests/postgres_review_executor.rs`:
`review_worker_returns_when_its_shutdown_sender_is_dropped`,
`a_failed_review_worker_iteration_emits_closed_value_free_operational_events`,
`an_idle_review_worker_iteration_records_its_last_success`,
`a_scrape_reports_how_long_the_oldest_due_item_in_each_queue_has_waited`,
`a_scrape_counts_a_claimable_cancellation_as_waiting_review_submission_work`,
`a_scrape_counts_an_expired_webhook_lease_as_waiting_delivery_work`,
`a_scrape_ages_an_expired_review_submission_lease_from_its_expiry`,
and `an_unreadable_queue_omits_every_queue_age_and_emits_a_closed_value_free_event`.
`crates/registry-breg/tests/postgres_webhook_delivery.rs`:
`real_postgres_webhook_worker_records_its_last_success_on_an_idle_iteration`.
`crates/registry-breg/tests/postgres_proposal_s3.rs`:
`verification_runs_on_the_shared_dispatch_job_table`, which pins the
attachment verification worker's success only when idle or after a verdict.
`crates/registry-breg/tests/postgres_access_log.rs`:
`a_retention_tick_without_failure_records_its_last_success`.
`crates/registry-breg/tests/postgres_startup.rs`:
`prepared_server_wires_services_and_static_jwks_readiness_tracks_database`
scrapes a real startup's metrics listener as the runtime role and expects
exactly the verified package digest and every queue.
`crates/registry-breg/src/metrics.rs`:
`worker_last_success_age_is_absent_until_the_worker_first_succeeds`,
`every_progress_worker_carries_a_distinct_snake_case_label`,
`queue_ages_are_published_only_for_a_sampled_scrape`,
`every_pending_queue_carries_a_distinct_snake_case_label`, and
`the_active_package_digest_is_published_once_as_an_info_series`.
`crates/registry-platform-hooks/src/delivery/service.rs`:
`the_worker_loop_notes_an_idle_iteration_without_failure_as_a_success`.
Each test the change adds was written first and failed, or did not compile,
against the code before it; the operational event test is extended with the
added codes.

### Accepted residuals

- **Crash loop.** A fault that recurs on every start, such as a worker that
  panics on the same queued item, makes the process restart repeatedly and
  takes reads and writes down between attempts, where earlier releases kept
  serving reads without the worker. The supervisor's restart backoff bounds
  how often; the stop code names the worker.
- **Package digest on the metrics listener.** Anyone who reaches the
  metrics listener can read the active package digest. It identifies the
  deployed package bytes, not their content, and `bregctl status` already
  reports it to an operator. The metrics listener carries no
  authentication, and the runtime file refuses a `metricsListener.bind`
  that is not a loopback or private address.
- **Scrape load.** A scrape holds one runtime pool connection for up to the
  5-second statement timeout, and a request waiting for a connection can
  wait behind it. Scrapes do not run concurrently, so a scraper cannot hold
  more than one connection, and the transaction is read-only and takes no
  row locks.
- **Readiness.** `/ready` does not reflect worker state, so a load balancer
  keeps routing to a process until it exits. Between a task stopping and the
  exit, the process drains within the shutdown grace.
- **Attachment queue.** The attachment verification queue is not sampled by
  `breg_queue_oldest_pending_age_seconds`. Its signal is the worker's
  `breg_worker_last_success_age_seconds`, which stops advancing while a job
  waits for a retry, a lease lapsed, or a verifiable pending verdict has no
  job that can still run (missing or dead-lettered), so an operator sees a
  stalled, lost, or given-up verification as a growing age.
- **Retention failures.** A failed subject access log retention pass still
  writes a raw error record without a closed `code`; only its last-success
  age and its stop code are closed.

## Migration lock contention and lock-free reconcile assessment

The change keeps a migration lock another session holds distinct from an
unreachable database (`MigrationLockHeld` in
`crates/registry-breg/src/postgres/mod.rs` and
`crates/registry-breg/src/migration.rs`, raised by `acquire_inner` in
`crates/registry-breg/src/postgres/interlock.rs`), reads the active identity
for a `migration reconcile` assessment without the lock
(`observed_active_identity` in
`crates/registry-bregctl/src/active_registry.rs`), and opens the audit writer
only under `--execute` (`ReconcileAudit` in
`crates/registry-breg/src/migration_reconcile.rs`). It touches the activation
interlock and audit integrity. Its invariant row is BREG-SEC-147.

### Threat

The bregctl preflight that bound the configured active package took the
exclusive lock and folded every failure into one unavailable refusal, so a
lock held by an apply, an adoption, or another reconcile sent the operator
to check `database.migrationUrlRef`, and `in_progress` could not be
reported. A lock-free read could instead let a reconciliation act on an
identity an apply is changing, and an assessment that writes nothing could
still be refused by an audit destination it never uses.

### Enforcement and defaults

- The lock statement alone maps PostgreSQL's lock timeout (`55P03`) and a
  shorter statement timeout (`57014`) to `MigrationLockHeld`; every other
  failure keeps its existing refusal. `refusal_before_maintenance` keeps it
  apart from `DatabaseUnavailable`, so `apply` and `plan` still change
  nothing and report `apply.database.in-progress`, with a sentence that names
  the held lock and the `retry-after-migration-lock-releases` suggested
  action. An unreachable database keeps `apply.database.unavailable`.
- The lock-free assessment preflight is safe because it authorizes nothing.
  It reads one committed snapshot of the state row and binds the configured
  package and database id to it exactly as the locked read did.
  `reconcile_failed_migration` then takes the exclusive lock, re-reads the
  maintenance snapshot under it, and refuses a snapshot whose identity
  differs from the one the preflight read before it assesses anything. The
  locked preflight released its lock before that step too, so the re-read
  under the lock was already the only fence.
- `--execute` keeps the locked preflight unchanged. A lock held there, or at
  the reconciliation's own acquisition, refuses as
  `migration.reconcile.outcome.in-progress` and changes nothing; an
  assessment reports `in_progress` as its outcome.
- An assessment holds only the keyed audit profile it validates the operator
  reference under. `--execute` opens the companion audit writer after the
  locked preflight and before any database change, and refuses as
  `migration.reconcile.audit.unavailable` when it cannot.
- `history erase`, `history rebaseline`, `field-encryption preflight`, and
  `field-encryption erase-history` keep the locked preflight and report a
  held lock as `<prefix>.active-registry.in-progress`.
- The history maintenance transactions take the exclusive lock through
  `lock_registry` in `crates/registry-breg/src/history_maintenance.rs`, which
  reads the lock wait with the same `lock_wait_ended` rule as
  `acquire_inner`. A held lock there refuses as `MigrationLockHeld` before the
  transaction changes anything, and `bregctl` reports it as
  `history.erase.in-progress`, `history.rebaseline.in-progress`, or
  `field-encryption.erase-history.in-progress` with the
  `retry-after-migration-lock-releases` suggested action. Its request entry is
  answered `unfinished`, as for any other refusal. An `erase-history` run
  refused part way keeps the records it already erased, each in its own
  committed transaction, and can be run again. `field-encryption preflight`
  takes no advisory lock, so it has no such refusal.
- Action Evidence retention, request retention, import authority
  maintenance, and instance claim adoption take the exclusive lock through
  the same `lock_registry`. A held lock refuses as `MigrationLockHeld` before
  their transaction changes anything, and `bregctl` reports it as
  `evidence-retention.in-progress`, `request-retention.in-progress`,
  `import-authority.in-progress`, or `instance-claim.in-progress` with the
  same suggested action. The Evidence erasure, the request-detail erasure,
  and the adoption answer their request entry `failed`, as for an outage;
  import authority maintenance records only committed transitions, so a
  refusal records nothing. A request-detail erasure that committed keeps its
  `committed` response when the external-deletion retry after it meets the
  held lock, and the command still reports `request-retention.in-progress`.

### Tests

`crates/registry-breg/tests/postgres_migration.rs`:
`real_postgres_reconciliation_reports_a_held_migration_lock_as_in_progress`
and `real_postgres_reports_an_unavailable_database_before_maintenance_as_unchanged`.
`crates/registry-breg/src/postgres/interlock.rs`: the competing lock
assertion in `failed_resume_and_ddl_timeout_are_fail_closed_on_real_postgres`.
`crates/registry-breg/tests/postgres_history_rebaseline.rs`:
`erasure_and_rebaseline_report_a_held_migration_lock_and_change_nothing`.
`crates/registry-breg/tests/postgres_action_evidence_retention.rs`:
`retention_reports_a_held_migration_lock_and_erases_nothing`.
`crates/registry-breg/tests/postgres_request_read_retention.rs`:
`request_detail_erasure_reports_a_held_migration_lock_and_erases_nothing`.
`crates/registry-breg/tests/postgres_import_authority.rs`:
`a_held_migration_lock_is_reported_and_no_authority_changes` and
`adopting_under_a_held_migration_lock_is_reported_and_supersedes_nothing`.
`crates/registry-bregctl/src/lib.rs`:
`apply_reports_a_held_migration_lock_as_an_activation_in_progress`,
`an_active_registry_read_reports_a_held_migration_lock_as_in_progress`,
`history_maintenance_reports_a_held_migration_lock_as_in_progress`, and
`operator_maintenance_reports_a_held_migration_lock_as_in_progress`.
`crates/registry-bregctl/src/request_retention.rs`:
`a_held_migration_lock_stays_distinct_from_a_refused_operation`.
`crates/registry-bregctl/src/active_registry.rs`:
`a_held_migration_lock_reads_as_in_progress_not_as_unavailable`.
`crates/registry-bregctl/src/reconcile_lifecycle.rs`:
`execution_refuses_a_held_migration_lock_as_in_progress`.
`products/breg/scripts/test-adopter-workflow.sh` holds the advisory lock from
a second session and proves assessment answers `in_progress` while
`--execute` refuses and `apply` refuses with `apply.database.in-progress`
and the wait-and-retry action, then proves assessment answers with a
read-only audit directory while `--execute` refuses. Each test the change
adds was written first and failed, or did not compile, against the code
before it.

### Accepted residuals

- **The assessment snapshot can be stale.** An apply may start or finish
  between the lock-free read and the locked assessment; the assessment then
  refuses the changed identity or reports what the lock-time snapshot holds.
- **A statement timeout is read as contention.** On the lock statement only,
  a statement timeout shorter than the lock timeout ends the wait first, so
  it is reported as a held lock. That statement waits for nothing else.
- **Execution outcomes without a transition.** `--execute` on a registry
  assessed as `ready`, or one whose identity changed under the lock, still
  answers with `executed: false` rather than a refusal.

## Expected package digest for apply and plan

The change adds `--expected-digest` to `bregctl apply` and `bregctl plan`
(`parse_expected_digest` and `lifecycle_failure` in
`crates/registry-bregctl/src/lib.rs`, and the check in `execute` in
`crates/registry-bregctl/src/apply_lifecycle.rs`), and keeps the runtime
file's `package.expectedDigest` mismatch sentence when the active package
loaders refuse the configured package (`active_package_envelope_error` in
`crates/registry-breg/src/runtime_config.rs`). It touches activation and
release provenance. Its invariant row is BREG-SEC-148.

### Threat

`apply` activated whichever verified package `--package` named. A directory
replaced or rebuilt between the review of `plan` and the `apply`, or a deploy
job pointed at another build, activated a package nobody reviewed, and
nothing tied the reviewed `packageDigest` to the activation. Separately, the
active package loaders reduced a `package.expectedDigest` mismatch to the
generic envelope refusal, so `apply`, `plan`, and the maintenance lifecycles
named neither digest and the operator could not tell a pin mismatch from a
damaged package.

### Enforcement and defaults

- `--expected-digest` takes only `sha256:` and 64 lowercase hex digits, the
  form `package` and `plan` print. Any other value is a clap usage error,
  exit status 2, `usage.invalid` in JSON mode.
- The comparison runs right after the target package is verified and before
  `DatabaseAccess::resolve`, so a mismatch resolves no database secret,
  opens no connection, takes no lock, and writes no audit entry. Both
  commands refuse with `apply.package.digest-mismatch` and the
  `rerun-plan-on-intended-package` suggested action. The message names the
  expected and the found digest; both are package identities, not secrets.
- Without the flag, behaviour is unchanged. The activation audit entry
  (`ActivationAttempt::begin` in `crates/registry-breg/src/migration.rs`)
  already records `packageDigest` and `predecessorPackageDigest`, so the
  flag adds no audit field.
- A `package.expectedDigest` mismatch on the configured active package keeps
  each command's code and path, for example `apply.package.refused` at
  `package.root`, and its message is the platform sentence naming the pinned
  and the found digest. Every other envelope refusal stays value free.

### Tests

`crates/registry-bregctl/tests/cli.rs`:
`apply_and_plan_refuse_a_package_other_than_the_expected_digest_before_database_contact`
runs both commands against an unreachable database URL and proves that no
flag and a matching digest reach the database while a mismatched digest
refuses first; `apply_and_plan_take_the_expected_digest_only_as_a_sha256_label`
covers malformed values; and
`apply_names_both_digests_when_the_active_package_misses_its_pin` covers the
pin sentence end to end. `crates/registry-bregctl/src/lib.rs`:
`an_active_package_pin_mismatch_names_both_digests` covers the six lifecycle
renderers. `crates/registry-breg/tests/runtime_config.rs`:
`the_active_package_loaders_name_both_digests_of_a_package_pin_mismatch`.
Each test the change adds was written first and failed against the code
before it.

### Accepted residuals

- **The flag is opt-in.** An `apply` without `--expected-digest` is bound to
  no reviewed digest and activates whichever verified package `--package`
  names, as before. A deploy job must pass the digest its review recorded.
- **The digest binds bytes, not authorship.** Packages are unsigned; a
  matching digest proves the reviewed bytes are the ones activated, not who
  built them.
- **The `breg` operational log keeps its closed refusal class.** `breg`
  startup keeps the pin sentence in its startup error, but its production
  operational log renders only `the Registry package was refused`, without
  the digests. `bregctl doctor` and `bregctl verify` against the same runtime
  file report the sentence.

## Reviewed migration rehearsal evidence

The change holds the `test` rehearsal of a reviewed migration to the lock and
statement timeouts its descriptor declares (`rehearse_assertions` and
`rehearse_reviewed_steps` in `crates/registry-breg/src/postgres/rehearsal.rs`),
retires the rehearsal receipt's `proofs` member
(`MigrationRehearsalReceipt` in `crates/registry-breg/src/migration_plan.rs`),
and names both schema fingerprints in `migration.review.fingerprint-mismatch`,
measured with `bregctl test --fingerprint-only`
(`measure` in `crates/registry-bregctl/src/test_lifecycle.rs`). It touches the
evidence a reviewed migration carries into a package, not activation:
`apply` already ran each reviewed statement under the declared timeouts and
never read `proofs`, so no security invariant row changes.

### Threat

A rehearsal that ran every reviewed statement under a fixed 5 second lock and
300 second statement timeout passed a migration that activation, under a
shorter declared bound, cancels, so `package` published a plan that fails in
maintenance. The `proofs` booleans read as evidence of lock-timeout and resume
behavior while proving neither: the parser accepted them only when they
equalled what the descriptor already fixed.

### Enforcement and defaults

- Before a migration's assertions and before each reviewed step, the rehearsal
  sets the descriptor's `lockTimeoutMilliseconds` and
  `statementTimeoutMilliseconds`, or a backfill step's own, through the same bounded setter activation uses, and
  restores the compiler's bound for the generated statements.
- A receipt that carries `proofs` is refused with `config.removed-key` at
  that member, by `bregctl` when it captures the receipt and by the runtime
  when it loads a package that carries one (see "Reviewed migration documents
  read through the shared reader").
- The mismatch refusal and the `--fingerprint-only` report carry schema
  fingerprints only, which are catalog digests and already appear in `test`
  reports and package manifests. `--fingerprint-only` takes no credentials,
  runs no fixtures, writes no receipt, and rolls its install back.

### Tests

`crates/registry-breg/tests/postgres_migration.rs`:
`real_postgres_rehearsal_holds_a_reviewed_migration_to_its_declared_timeouts`
(SQLSTATE `57014` in the rehearsal, then the same package refused by `apply`).
`crates/registry-bregctl/tests/cli/reviewed_migrations.rs`:
`reviewed_successor_refuses_a_receipt_that_carries_retired_proofs`.
`crates/registry-breg/tests/migration_plan.rs`:
`reviewed_package_whose_receipt_carries_the_retired_proofs_is_refused`.
`crates/registry-bregctl/src/lib.rs`:
`review_fingerprint_mismatch_names_the_declared_and_the_measured_fingerprint`.
`crates/registry-bregctl/tests/wasm_test_lifecycle.rs`:
`public_bregctl_test_fingerprint_only_measures_the_schema_the_full_run_binds`.
`products/breg/scripts/test-adopter-workflow.sh` asserts that the refusal
names both fingerprints.

### Accepted residuals

- The rehearsal runs over empty tables and does not load reviewed fixtures,
  which are bound by digest only, so a timeout that only real rows reach is
  found by the operator's own rehearsal on a restored copy and by `apply`.
- The receipt's `postgresMajor` is not compared with the server the rehearsal
  or `apply` runs on.

## Wasmtime build features

The change builds the pinned Wasmtime release behind the WebAssembly handler
executor without its default features
(`crates/registry-platform-script/Cargo.toml`). It keeps `cranelift`,
`runtime`, `pulley`, `threads`, and `parallel-compilation`, and moves
text-format parsing (`wat`) to a dev-dependency. It touches release
provenance, because a default feature linked a build script that embedded the
source commit into release binaries, and the deployment default for which
WebAssembly proposals a handler module may use.

### Threat

1. A release binary embeds the commit it was built from, so the image
   advisory baseline built from one commit never matches the candidate built
   from the next (`release/REPEATABLE-BUILDS.md`, "The source tree, not the
   checkout").
2. Engine surfaces the executor never calls (the module cache, GC, component
   model, profiling, debugging, coredumps, and the text parser) widen what a
   reviewed but hostile or careless module can reach.

### Enforcement and defaults

- `wasmtime-internal-cache`, whose build script keys the module cache on the
  enclosing git commit, is no longer in `Cargo.lock`. `cranelift-codegen`
  still reads the commit for its `VERSION` constant and stays behind the
  `GIT_CEILING_DIRECTORIES=/workspace` contract in
  `release/scripts/build-release-binaries.sh`.
- The executor admits WebAssembly binaries only; WebAssembly text is refused
  by the engine as well as by BREG's binary magic check.
- Without `gc`, a module using GC types, exception handling, or `externref`
  is refused at prepare, and therefore at compile time for action and hook
  handlers. Funcref tables and indirect calls stay admitted. `threads` is
  kept only so `Config::wasm_threads(false)` holds the proposal off.

### Tests

`crates/registry-platform-script/tests/wasm_executor_wat.rs`:
`wat_text_is_refused`, `gc_exceptions_and_externref_are_refused`, and
`funcref_tables_and_indirect_calls_are_admitted`, on both backends.
`crates/registry-platform-script/src/wasm.rs`:
`module_rejection_summary_keeps_the_summary_limit_not_the_name_limit`. The
first two failed against the default-feature build (it accepted text and
those proposals on the native backend).

### Accepted residuals

- **No gate pins the feature set.** Re-enabling `cache`, directly or through
  another crate unifying Wasmtime features, would bring the commit-reading
  build script back. The release build's full-commit read-back check and the
  git ceiling still apply, and `gc_exceptions_and_externref_are_refused`
  fails if `gc` is unified back on.
- **The handler SDK workspace is separate.** `products/breg/wasm-handler-sdk`
  has its own lock and builds Wasmtime with its default features for guest
  preinitialization; it ships in no release binary.

## WASM hook handlers in a build without WASM support

The change makes a build of `registry-breg` without the `wasm` feature refuse
a WASM hook handler at compile time, the way it already refuses a WASM action
handler (`validate_hook_assets` in `crates/registry-breg/src/compiler.rs`).
It changes which packages such a build activates, a deployment default.

### Threat

1. A feature-off build compiles a project, or loads a package, that declares a
   WASM hook. The hook is activated with no executor to run it, and each event
   it handles fails late with a source failure instead of the package being
   refused before it serves (BREG-SEC-149).

### Enforcement and defaults

- Without the `wasm` feature, every WASM hook handler yields
  `hook.handler.wasm_build_unsupported` at `entities[].hooks[].handler.type`
  before its module is looked up, so the refusal names the build rather than
  the module and no module diagnostic is reported.
- Package loading rederives the package through the same compiler, so the
  build refuses to load a package a wasm-enabled build produced.
- Default builds carry the `wasm` feature and are unchanged. The runtime's
  late refusal of a WASM hook, now in the shared executor in
  `registry-platform-hooks`, stays as a second line.

### Tests

`crates/registry-breg/tests/hook_declaration.rs`:
`a_wasm_hook_is_refused_by_a_build_without_wasm_support`, run under
`--no-default-features --features runtime,tooling` in the CI WASM refusal
suite. It was written first and failed against the code before the change,
which compiled the hook. The wasm-enabled hook admission tests in the same
file run only in builds with the feature.

### Accepted residuals

- **Refusal at load, not at the hook.** A deployment that switches to a
  feature-off build with a WASM-hook package active cannot load that package;
  the operator replaces it or deploys a build with the feature.

## Immediate action history commit allocation

### Threat

An immediate action records revision rows without indexing them in the
shared history commit journal. The latest snapshot omits accepted changes,
and coverage rebaselining refuses their unindexed revisions. An aliased patch
can also index one record twice if allocation follows effects rather than
changed records.

### Enforcement and defaults

The action mutation path allocates one ordinary mutation commit before its
transaction commits. It deduplicates effect results by entity and record,
retaining the resulting revision. Allocation uses the same package binding,
actor and request references, transaction, and commit-head locking as direct
mutations. Production activation always initializes the coverage baseline;
no missing-head compatibility path is introduced.

### Tests

`tests/support/action_history_commit_regressions.rs` reproduces the missing
head and missing membership before the fix. Its real PostgreSQL tests verify
one head advance, one member per changed record, a latest snapshot of an
action-patched record, and successful coverage rebaselining. Existing action
fault, retry, concurrency, and aliased-effect tests retain their rollback and
replay assertions with normal activation initialization.

### Accepted residuals

This corrects future action commits. It does not fabricate historical commit
positions for revisions that an earlier runtime left unindexed. The existing rebaseline command continues to refuse a retained journal head
that has no commit member; this change supplies no repair for those rows.

Affected pre-1.0 development databases containing unindexed action revisions
must be rebuilt before relying on snapshots or coverage rebaselining.

## Statistical datasets

### Threat

A count can disclose records beyond the caller's ordinary read authority. A
published release can expose small populations, depend on caller-specific
visibility, retain hidden true counts, or be silently rewritten after readers
have used it. The statistical invariants are BREG-SEC-150 through BREG-SEC-160.

### Enforcement and defaults

The compiler admits a live grant only when the selected profile already has
list and count authority and can filter every processing field. PostgreSQL
reuses the ordinary read relations and visibility predicates for the grouped
count, including the request-owner visibility context. Source entity
dependencies are extracted from the reviewed raw SQL
syntax tree and closed transitively. Publisher visibility must be independent
of its caller on every entity in that closure, with an operation that installs
an ordinary SELECT policy on each dependency. The compiler checks that operation
set and includes it in the definition digest. The digest also binds the types
and mappings of processing fields and the source columns read by their derived
SQL, so an unchanged expression cannot keep old releases visible after its
input definitions change. Unrelated field definitions do not enter the digest.
Encrypted processing fields and consent-gated count grants are refused.

Publication computes one ended period under the current package binding and
one statement snapshot, retaining its shared history head for the freshness
check. History erasure can make the release's snapshot bookmark unavailable;
the header then carries `snapshot: null` while publication continues. Persistence
rechecks bookmark coverage under the shared registry lock, so erasure between
computation and persistence also produces a null bookmark. Storage errors and
invalid history identity still fail closed. Rebaseline restores bookmarks for
later releases. Publication and withdrawal bind an idempotency receipt to the caller, route, selected profile,
package, and canonical request. A per-dataset-period transaction lock serializes
version allocation and final-status ordering. Only canonical disclosed documents
are persisted; exact live counts are not stored in release content.

Immutable version headers and content tables grant the runtime only SELECT and
INSERT. Withdrawal grants no table DELETE or UPDATE: one fixed owner function
records the closed withdrawal reason and erases the content atomically. Latest
and series reads omit withdrawn versions; a direct version read returns a
value-free withdrawal problem. Current grants and definition digests govern
retained reads, including a released-reader profile with no record authority.

Audit entries contain dataset, period, release identity, status, and digest
references, never cell values or true counts. Attempts precede database work;
terminal audit acceptance gates response bytes. A publication or withdrawal
that reaches its COMMIT without a proven outcome, because the COMMIT failed or
the work deadline passed while it was in flight, appends no terminal entry:
its attempt is answered `unfinished`, never `refused`, and the caller receives
503, as for an ordinary mutation whose commit is unresolved. Each request has an absolute
deadline, including lock waits and statement execution. Statistical work reserves
500 ms before the outer HTTP deadline to construct and enqueue its terminal
audit response. JSON representation
digests cover exact response bytes; CSV digests cover the CSV representation.
Both are sent with no-store cache policy.

Maintained clients verify and retain representation digests for live, release,
and series documents, and successful publication and withdrawal responses.
Every successful statistics response must carry the declared no-store and
authorization/accept cache policy; read and mutation responses use the same
validation. The CLI binds mutation success to the requested dataset and period:
publication also matches status and a positive version without withdrawal
metadata, while withdrawal matches the version and reason. Nullable snapshot
bookmarks remain valid.
The Rust client and its Node and Python bindings require positive signed
64-bit version selectors and canonical year, quarter, month, or day codes with
valid Gregorian dates and an exclusive end in the four-digit year domain.
Invalid selectors fail before token-provider acquisition or HTTP I/O. The CLI
reads its operator-supplied token file before calling the Rust client. Release listing
clients accept the complete envelope the server's
cursor codec can issue, while retaining a fixed size bound.

A request without a verified bearer token is refused with 401 before
authenticated refusal auditing, preventing unauthenticated requests from
filling that journal or observing sink health.
Authenticated unknown datasets and ungranted profiles enter refusal auditing;
unknown IDs use a fixed route identity so caller input cannot enter the journal.
Unmatched routes record the actual standard HTTP method and a fixed unknown
operation; extension-method tokens become `OTHER`.
Caller-filtered OpenAPI names only the selected profile; its query selector
still follows the runtime's actual default admission rules.

### Tests

`compiler_statistics.rs` exercises typed count admission, publisher dependency
closure, period models, generated contracts, definition digests, and grant
changes. Referenced field types and derived SQL input definitions are bound,
while unrelated field changes preserve the digest. `statistics.rs` verifies calendar periods, zero filling and margins,
checked arithmetic, suppression, independent rounding, canonical bytes, and
CSV escaping. The PostgreSQL statistics tests verify exact runtime privileges,
atomic withdrawal, unexpected grants and altered withdrawal functions, and the
authenticated HTTP release lifecycle. They also pin alias remapping in definition
digests, owner count parity, unauthenticated refusals under audit failure, stored-byte
digest equality, real definition successor activation, and publication after
maintained history erasure and rebaseline, including erasure between computation
and persistence. The outer HTTP timeout test blocks the source table and verifies
a refused terminal with no release or idempotency rows; the commit tests fail a
publication and a withdrawal at COMMIT, and let the work deadline pass during a
COMMIT that then becomes durable, and verify an `unfinished` answer with no
refused terminal; unmatched-route tests
verify method classification without recording caller-controlled values. The facility
workflow executes publication and JSON/CSV series reads through native CLI and
HTTP clients with separate access profiles.
`registry-breg-client/tests/statistics_http_boundary.rs` verifies complete
continuation propagation, version and calendar bounds before credentials or I/O, and
refusal of missing or mismatched publication and withdrawal digests, and
missing or incorrect cache headers on JSON, CSV, and listing reads. Native
Node and Python tests exercise the same client decisions. CLI lifecycle tests
refuse mismatched release identities and operation-specific response headers.

### Accepted residuals

Independent suppression and rounding do not prevent reconstruction. The tests
pin a four-plus-four case and seven positive cells whose rounded total reveals
that each suppressed value was one. Overlapping datasets, periods, revisions,
and external knowledge can amplify disclosure. Institutions must review their
population, dimensions, cadence, and release policy; this mechanism makes no
statistical confidentiality guarantee. With minimumCount 5 and roundingBase 5,
two suppressed positive cells and a rounded total of 10 force both cells to 4:
each lies in 1..4, and only a sum of 8 rounds to 10. Seven suppressed positive
cells and a rounded total of 5 force all seven to 1. Zero cells also disclose
group attributes. Deterministic rounding supports differencing across releases,
and no privacy budget limits repeated observations.

If an institution cannot accept the interval-pinning residual, cell key
perturbation is the next mechanism to evaluate through a separate statistical
design and review. It is not implemented by this threshold-and-rounding release
path.

Withdrawal erases the engine's stored content, not copies a reader already
obtained. Release headers and withdrawal reasons remain. Historical definitions
remain retained but unavailable under a different active definition digest.
Live evaluation-date-dependent datasets serve only the current period; released
computation evaluates at the period's reference date. Aggregate reads do not
emit per-subject access-log hits. Publication scans the declared source views;
there is no background refresh or shared aggregate cache.

## State older than the immediate predecessor

Before 1.0 a release reads only the state its immediate predecessor wrote.
The change removes the steps that upgraded, converted, or specifically
refused state written by builds older than v0.38.0: the webhook delivery
table upgrades in `crates/registry-platform-hooks/src/delivery_schema.rs`,
the legacy review data refusals and table upgrades in the registry's internal
schema install, the retired spellings `bregctl` still recognized, the
adoption of a database from before the activation ledger, the retired audit
table guard, the older catalog fingerprint, and the package, project, and
runtime shapes only earlier releases wrote. It touches data minimization (the
raw handler answer), audit integrity (the retired audit tables), deployment
defaults (what schema install, startup, and `apply` do to an existing
database), authorization (what the client reads as a request-field grant),
and release provenance (the release image and the upgrade rehearsal).

### Threat

1. A delivered webhook row keeps the raw handler answer bytes beside the
   payload erasure that promises value-free settlement, now that install no
   longer erases them while replacing the legacy answer constraint
   (BREG-SEC-69).
2. A request row holds a state from the retired local approval vocabulary
   (`approved`, `needs_changes`, `rejected`, `canceled`), and the runtime
   treats it as a current state instead of refusing it.
3. Removing the specific refusals turns a refusal into an acceptance: a
   retired package flag, a Mint-era or incomplete dev state file, or a
   `bregctl-data/v1` import sidecar is read as if it were current.
4. A release image ships without `bregctl`, or an upgrade is rehearsed from a
   release the promise does not cover, and the release evidence claims an
   upgrade path that was never exercised.
5. A database holding registry state this release does not recognise is
   served, planned, or applied over as though the ledger recorded it, now
   that it is no longer adopted (BREG-SEC-122).
6. Rows in the retired `registry_internal.registry_audit` and
   `registry_audit_head` tables are discarded, or kept and ignored, without
   the operator's acknowledgement, now that `apply` no longer guards them.
7. A database whose managed catalog has drifted from the package passes
   verification under the fingerprint the package does not carry.
8. A shape only an earlier release wrote is read under a default this
   release fills in, so what is authorized is not what the package or the
   server stated: a compiled permission target with
   no `operation` or `source`, served metadata with no
   `readableRequestFields`, version 1 prepared lifecycle evidence, a
   `package/v1` manifest, or a predecessor governed model with missing
   temporal value kinds.
9. A removed project or runtime key carrying deployment identity or package
   trust is accepted, or its refusal echoes the value it carried
   (BREG-SEC-01).

### Enforcement and defaults

- The delivery schema's
  `registry_webhook_delivery_state_answer_digest_required` constraint is
  part of the table definition, so every insert and update that keeps raw
  answer bytes on a row is refused by PostgreSQL. Terminal settlement still
  writes the answer digest only. Schema install runs only inside an apply, and
  v0.38.0 can serve a database last applied under an earlier release, so the
  table need not have been created by v0.38.0. v0.36.0 refused to serve a
  database until a rebuilt package was applied to it, and its install already
  erased kept answer bytes and added this constraint, so every database
  v0.38.0 can serve carries the constraint and no row in it carries the bytes.
- `RequestState::from_storage` accepts only the current vocabulary. Any other
  stored value is `WorkflowError::InvalidRestoredState`, which the API
  reports as the generic service-unavailable problem. No row is read past the
  refusal and the response names no stored value.
- Schema install creates current columns and constraints directly. The
  webhook dead-letter reason is defined in fresh creation; installation
  does not add it to an earlier table. Reinstalling current storage changes
  nothing.
- The retired package flags are no longer defined, so the argument parser
  refuses them as unknown arguments with exit status 2 before any file or
  database is read. Dev state is read strictly: a version other than the
  current one, or a missing recorded field, is invalid retained dev state and
  the file is left untouched. An import sidecar that is not the current
  format is an ordinary checkpoint refusal raised before any HTTP request,
  and its message renders no value.
- `release/docker/Dockerfile.breg` installs `bregctl` unconditionally, and
  `check-debian13-images.py` marks the tool required. `rehearse-upgrade.py`
  refuses a start before `FORWARD_PATH_FLOOR` (v0.38.0) before any download
  or container starts.
- The kernel's state shape is read from the PostgreSQL catalog before
  startup, `bregctl status`, `bregctl plan`, or `bregctl apply` reads or
  writes registry state. A shape this release does not recognise is
  `UnrecognizedDatabase`, one generic refusal that names no recorded value.
  Startup binds no listener, and status, plan, and apply change nothing. A
  database an earlier release adopted keeps its `adopted` ledger row and
  `registry_pre_ledger_package_positions`. This release serves it, and
  activates a successor over it, without rewriting either.
- Schema install has dropped the retired audit tables since v0.35.0, so no
  database v0.38.0 served holds them and the guard could no longer trigger on
  predecessor state. `apply` takes no acknowledgement and has no
  `apply.audit.retired_rows_present` refusal.
- Catalog verification computes the named-column fingerprint only and
  compares it with the package's. This narrows what startup and the
  successor check accept. Drift refusal is unchanged.
- Package read is strict. A `package/v1` manifest is an integrity refusal, a
  compiled permission target must carry `operation` and `source`, and a
  predecessor governed model is read exactly as v0.38.0 wrote it. The client
  refuses served metadata whose operation omits `readableRequestFields`
  instead of reading it as an empty grant, and refuses version 1 prepared
  lifecycle evidence. Each of these is refused, and none is read under a
  filled-in default.
- The removed project keys are refused by the strict source shape and the
  removed runtime keys by `deny_unknown_fields`, as `runtime_config.document`.
  Environment substitution runs before that refusal, so a `${VAR}` in a
  removed key is resolved first. When the variable is set, the refusal names
  the field and never the substituted value. When it is unset, the document
  is refused as `runtime_config.env_expansion`, which names neither the field
  nor the variable. `breg --config` is refused by the argument parser with
  exit status 2 and does not echo the path.

### Tests

1. `crates/registry-breg/tests/postgres_webhook_outbox.rs`:
   `real_postgres_delivery_schema_refuses_a_delivered_row_that_keeps_raw_answer_bytes`
   (BREG-NEG-69),
   `real_postgres_internal_schema_reinstall_is_idempotent`.
   `crates/registry-platform-hooks/src/delivery_schema.rs`:
   `a_recorded_answer_belongs_to_a_delivered_row`, and two tests that need
   PostgreSQL and run only where `HOOKS_TEST_DATABASE_URL` is set, which the
   `scheduling-postgres` job of `.github/workflows/ci.yml` does, failing
   unless at least one of them passes:
   `installing_over_an_installed_schema_changes_nothing`,
   `installing_fresh_delivery_storage_twice_keeps_dead_letter_reasons`.
2. `crates/registry-breg/src/request_workflow.rs`:
   `unknown_stored_request_states_are_invalid`.
3. `crates/registry-bregctl/tests/cli.rs`:
   `retired_package_flags_are_refused_as_unknown_arguments`.
   `crates/registry-bregctl/src/lib.rs`:
   `dev_start_takes_no_mint_issuer_flags`,
   `keygen_names_its_destination_only_with_output`.
   `crates/registry-bregctl/src/dev/tests.rs`:
   `a_retained_v1_state_is_invalid_without_mutation`,
   `a_retained_state_of_another_version_is_invalid_without_mutation`,
   `retained_state_missing_a_recorded_field_is_invalid`.
   `crates/registry-bregctl/src/data_lifecycle.rs`:
   `an_unknown_sidecar_version_is_refused_without_a_request_and_without_rendering_values`,
   `a_sidecar_of_another_version_in_the_current_shape_is_refused_without_a_request`.
4. `release/scripts/test_rehearse_upgrade.py`:
   `test_refuses_a_start_before_the_immediate_predecessor`,
   `test_main_refuses_an_earlier_start_before_any_download_or_container`.
   `release/scripts/test_check_debian13_images.py`:
   `test_required_operator_tools_cannot_be_optional`.
5. `crates/registry-breg/tests/postgres_migration.rs`:
   `real_postgres_an_unrecognised_registry_state_is_refused_and_changes_nothing`
   (BREG-NEG-122),
   `real_postgres_a_ledger_an_earlier_release_adopted_is_served_and_succeeded`.
   `crates/registry-breg/tests/postgres_startup.rs`:
   `startup_refuses_an_unrecognised_registry_state_and_writes_nothing`.
6. No test remains for the retired audit guard: its subject is gone. The
   install-twice tests in item 1 hold the schema install it relied on.
7. `crates/registry-breg/tests/postgres_package/fingerprint.rs`:
   `package_fingerprint_starts_refuses_drift_and_upgrades_without_rewriting_package_bytes`.
8. `crates/registry-breg/tests/immediate_action_compiler.rs`:
   `permission_targets_without_discriminators_are_refused`.
   `crates/registry-breg/tests/postgres_package.rs`:
   `predecessor_package_loads_after_an_unchanged_temporal_rewrite`,
   `predecessor_package_refuses_temporal_bindings_without_a_value_kind`,
   `predecessor_package_refuses_a_temporal_value_kind_its_fields_do_not_have`,
   `predecessor_package_refuses_temporal_scope_fields`.
   `crates/registry-breg-client/tests/write_http_boundary.rs`:
   `prepared_lifecycle_recovers_original_apply_after_action_disappears`
   (asserts version 1 evidence is refused).
   `crates/registry-breg-client/tests/metadata_contract.rs`:
   `request_metadata_grants_are_retained_and_required_on_every_operation`.
   `crates/registry-breg/tests/startup_ordering.rs`:
   `a_refused_package_keeps_the_cause_that_refused_it`.
9. `crates/registry-breg/tests/compiler_contract.rs`:
   `deployment_identity_keys_in_the_project_are_refused_as_unknown_fields`
   (BREG-NEG-01),
   `singular_manifest_projection_keys_are_refused_as_unknown_fields`.
   `crates/registry-breg/tests/runtime_config.rs`:
   `unknown_package_keys_are_refused_as_document_errors_without_their_value`,
   `an_unknown_package_key_holding_a_set_variable_is_refused_without_the_substituted_value`,
   `an_unknown_package_key_holding_an_unset_variable_is_refused_as_an_expansion_error`.
   `crates/registry-breg-mcp/src/config.rs`:
   `retired_config_keys_are_refused_as_unknown_fields`.

### Accepted residuals

- **A database older than v0.38.0 is not upgraded and not specifically
  refused.** Installing this release's schema over such a database leaves its
  old columns and constraints in place, and any failure surfaces later as a
  generic database error. The supported path is one release at a time, finishing
  each release's upgrade steps before starting the next.
- **Legacy answer bytes in a database never applied under v0.36.0 or
  later.** A delivery state table created before the answer constraint keeps
  whatever raw answer bytes it held, because `CREATE TABLE IF NOT EXISTS`
  does not add the constraint to an existing table. v0.36.0 through v0.38.0
  refuse to serve such a database until an apply, and each of their installs
  erases the bytes and adds the constraint, so that database is outside the
  upgrade promise.
- **Legacy review data is no longer named.** A request row in a retired
  approval state fails reads with the generic unavailable problem instead of
  a refusal at install that names the cause. Install has refused such data
  and rebuilt the four-state check since v0.36.0, whose apply every database
  v0.38.0 can serve has been through, so such a database holds none.
- **A leftover retired audit table is no longer dropped.** A database that
  v0.38.0 refused for its retired audit rows, and that was never applied
  again under v0.38.0, keeps the tables. In the common case v0.38.0 refused
  it while adopting it, inside the transaction that would have installed the
  ledger, so the database has no ledger and this release refuses it as
  `UnrecognizedDatabase`. A database that has a ledger and still holds the
  tables is refused by catalog verification, because the tables are not in
  the package's managed catalog. Either way the operator finishes the
  v0.38.0 apply first.
- **Pre-ledger support is kept where adopted state needs it.**
  `registry_pre_ledger_package_positions`, the `adopted` plan kind, and the
  sha256 package fingerprint stay, because a database an earlier release
  adopted has them and this release serves it without rewriting them. They
  stay until a release converts adopted state to the form a fresh ledger
  has: removing them before that would refuse a database the predecessor
  serves.
- **The authored `temporal.scopeFields` key stays accepted.** Predecessor
  rehearsal recompiles the v0.38.0 package's own sources, which may carry the
  key, so removing it would refuse a supported upgrade.

## HEAD on governed read routes

The change refuses HEAD on every governed GET route (BREG-SEC-161). It
touches audit integrity: the journal and the subject access log must name
only reads the engine served under the method the caller sent.

### Threat

axum's `get` routing also answers HEAD by running the same handler and
discarding the body. The engine takes the audited method from the compiled
route, so a HEAD to a record, history, statistics, attachment, GIS,
ingestion-run, or metadata route ran the whole read, wrote a subject access
log row where the entity keeps one, and journaled a GET the caller did not
send. No operation in the published OpenAPI document declares HEAD.

### Enforcement and defaults

`route_set` in `crates/registry-breg/src/api/mod.rs` applies one
`refuse_head` route layer after every governed route and merged route family
is registered. A HEAD request is handed to `not_found`, the handler the
router already uses for an unknown path or a method a route does not accept,
before profile authorization or record I/O. Under `/v1/statistics/` that path
journals an authenticated caller's HEAD as a refusal with method `HEAD` and
the fixed `statistics.unknown` identity; elsewhere it returns the concealed
404 without a journal entry, exactly as it does for PUT. Bearer verification
in `authenticated_router` still runs first, so an invalid credential is
refused as before.

The operational probes `/health`, `/healthz`, and `/ready` are registered
after the layer and keep answering HEAD. They return no registry data, are
not journaled, and probe tooling may send HEAD to them.

### Tests

Each route family has a negative test asserting the 404, no new journal
entry (exactly one HEAD refusal for statistics), and no subject access log
row, beside a GET control that is served. Outside statistics each test also
asserts that HEAD receives the status a PUT receives:

- `tests/postgres_access_log.rs`:
  `head_on_record_reads_is_refused_without_a_journaled_read`,
  `head_on_history_reads_is_refused_without_a_journaled_read`, and
  `head_on_subject_access_log_reads_is_refused_without_a_journaled_read`.
- `tests/postgres_statistics_http.rs`:
  `head_on_statistical_reads_is_refused_and_journaled_as_head`.
- `tests/postgres_spatial_read.rs`:
  `head_on_gis_reads_is_refused_without_a_journaled_read`.
- `tests/postgres_ingestion_runs.rs`:
  `head_on_ingestion_run_reads_is_refused_without_a_journaled_read`.
- `tests/postgres_change_requests.rs`:
  `attachment_downloads_write_a_subject_access_log_entry`.
- `tests/http_read_only.rs`:
  `head_is_refused_on_governed_reads_and_answered_only_by_probes`, covering
  the discovery routes and proving the probes still answer HEAD.

### Accepted residuals

Outside the statistics root a refused HEAD, like any other method a route
does not accept, leaves no journal entry. Journaling unaccepted methods on
every route family would be a separate change to the refusal path itself.
A caller that sent HEAD to a governed route now receives a 404 and must send
GET.

## Caller-scoped idempotency and the receipt horizon

The change moves the identity of a spent idempotency key off the audit hash
key and onto the verified caller, adds a receipt horizon to held responses,
and adds the operator command `bregctl idempotency-retention erase-expired`
(`crates/registry-breg/src/idempotency.rs`,
`crates/registry-breg/src/idempotency_retention.rs`,
`crates/registry-breg/src/mutation.rs`,
`crates/registry-breg/src/runtime_config.rs`). It touches authorization (who
may replay a held response), data minimization (raw caller identifiers are
persisted until the operator drops the receipt, and cleared then), audit
integrity (what rotating `audit.hashKeyRef` changes), and deployment defaults
(a seven-day horizon and caller-scoped receipt storage on fresh installation). The invariants are BREG-SEC-162 through
BREG-SEC-166.

### Threat

1. A spent row was found by a keyed hash under `audit.hashKeyRef`. Rotating
   that key made every spent row unfindable, so the exact retry of a write
   whose response was lost executed it a second time: a pseudonymization
   control decided write safety.
2. One caller's key replays another caller's held response, which can carry
   record values the second caller may not read, or refuses the second
   caller's request as a conflict.
3. Held responses, which carry record values, were kept for as long as the
   registry kept the row.
4. Dropping an expired held response frees its key, so a late retry executes
   a committed write again.
5. The raw issuer, principal value, and key a caller-scoped row needs to be
   found stay stored for as long as the registry keeps the row.
6. A configured issuer inside the namespace the engine scopes its own keys
   under lets a verified caller reserve, replay, or block a key the engine
   spends itself.

### Enforcement and defaults

- **Identity.** A spent row is found by `key_reference`, an unkeyed SHA-256
  over the domain `breg-idempotency-key-v2` and the length-prefixed key
  scope, issuer, subject, and key. While the receipt is held, a unique index
  on those four raw columns holds the same identity; once the sweep clears
  them, the digest alone keeps the key spent, and PostgreSQL treats the
  cleared nulls as distinct, so cleared rows never collide. Mutation keys, immediate-action keys, and the server-derived
  ingestion chunk keys use the configured `authentication.oidc.issuer` and
  the verified principal. The key scope is not the operation: every ordinary
  write (record mutations, batches, change-request routes, statistical
  releases, and immediate actions) spends caller keys in the one `mutation`
  scope, so a caller reusing a key on a different write route finds the
  spent row and is refused `409 idempotency.key-reused` by its binding.
  Ingestion chunk keys use the `ingestion_chunk` scope. A hook proposal
  application is spent by the delivery itself, in the `hook_proposal` scope:
  issuer `urn:registry-breg:hook-delivery`, subject the compiled delivery id,
  and the delivery's idempotency key. A coordinator built without a runtime
  configuration scopes keys under `urn:registry-breg:embedded-issuer`, which
  `IdempotencyPolicy::default` sets directly. `IdempotencyPolicy::new`, the
  only way to configure another issuer, refuses an empty issuer and every
  issuer under `urn:registry-breg:`. The runtime configuration also requires
  an `https` URL or a loopback `http` URL, so no verified token carries an
  engine issuer and no caller can reserve, replay, or collide with a
  delivery's application.
- **Binding.** `binding_reference` is an unkeyed SHA-256 over the canonical
  exact binding: method, route, target, package revision, response fields,
  canonical request digest, the raw verified claim context (principal,
  selected profile, purpose, row boundaries, submitter targets), and the
  task grant, action contract fingerprint, target authority, or handler
  answer digest where they apply. A byte-identical body under a different
  package, profile, or claims is therefore `409 idempotency.key-reused`.
- **Audit key.** Nothing that finds or binds a spent row reads
  `audit.hashKeyRef`. The keyed `request_reference` and principal reference
  stay in revisions and the audit journal as pseudonyms; rotating the key
  changes them for later writes only.
- **Horizon.** A held response stays available for
  `retention.receiptRetentionDays` after its commit: default 7, at least 1,
  at most 365, fixed on the row when it commits. Reading a spent key checks
  the binding first, erasure second, and the horizon third, so a changed
  request is told it conflicts, any retry of a key whose held response an
  erasure removed is `409 idempotency.key-reused` on either side of the
  horizon, and any other exact retry past the horizon is
  `410 idempotency.expired`. In every case nothing executes, whether or not
  the held bytes were dropped.
  Only successful responses are held; a refusal spends no key.
- **Sweep.** Expiry is enforced when the row is read, so the sweep only
  bounds how long held bytes stay stored, as `evidence-retention
  erase-expired` does for retained assertions. It runs under the migration
  credential, takes the registry lock, verifies identity, catalog, and
  readiness, and sets the body to null, the headers to an empty set, and the
  raw issuer, subject, and key to null with `receipt_dropped_at`, keeping the
  key reference, binding, scope, result references, and times. It covers
  every row past its horizon that has not been dropped, including rows whose
  held body request retention or `history erase` already removed. Every 409
  and 410 decision reads only the key reference, binding, erasure time,
  result kind, and receipt times, so a dropped row answers exactly as it did
  before the drop. A table check
  holds the raw caller and key present together exactly while
  `receipt_dropped_at` is null and absent together once it is set. The runtime
  role holds only `SELECT` and `INSERT` on the table, so no request path can
  drop or rewrite a held response. The request entry
  (`breg-idempotency-retention-audit/v1`) is accepted before the transaction
  opens and the response records the count; a commit that returned an error
  is read back on a fresh connection before the outcome is recorded.
- **Installation.** Fresh creation defines the caller-scoped columns and
  constraints directly. It converts no audit-keyed spent row. The generic
  successor capability mechanism remains available for later releases.

### Data minimization

`registry_internal.registry_idempotency` stores the raw issuer, principal
value, and key of a spent row until `bregctl idempotency-retention
erase-expired` drops its receipt, and clears them then; previously it stored
only a keyed hash. Request-retention erase (`bregctl request-retention
erase`) and `history erase` set a linked row's held body to null and mark it
erased, and leave the raw values in place until the same drop clears them
once the row's horizon has passed. No command deletes a spent row: the
digest row, with its binding, scope, result references, and times, is kept
indefinitely, because the results and application of an immediate action
hang off it and revision history reads its provenance from them. The audit
journal is unchanged and carries keyed references only. The binding digest is unkeyed,
so someone who can read the table can confirm a guessed low-entropy claim
value, such as a purpose or a row boundary, against it; that reader already
sees the raw principal beside it and the records it produced. `history erase`
still replaces held responses that could replay erased revisions with refusal
tombstones and leaves the spent row.

### Tests

- `tests/postgres_mutation.rs`:
  `real_postgres_exact_retry_after_audit_key_rotation_replays_and_never_reexecutes`,
  `real_postgres_idempotency_keys_are_scoped_per_caller`,
  `real_postgres_retry_after_receipt_horizon_is_refused_and_the_sweep_keeps_the_key_spent`
  (the sweep clears the raw caller, the exact retry answers 410, a changed
  one 409, and another caller's identical key executes as its own),
  `real_postgres_receipt_sweep_clears_the_raw_caller_of_every_expired_spent_key`
  (a held and an erased receipt are both cleared and both stay spent: the
  held key's exact retry answers 410 and the erased key's 409).
- `src/idempotency.rs`:
  `a_policy_refuses_every_issuer_the_engine_reserves`.
- `tests/postgres_batch.rs` proves over HTTP that another principal's batch
  under the same key executes as its own request and that an expired exact
  retry answers `410 idempotency.expired` without effects.
- `tests/runtime_config.rs`:
  `idempotency_receipt_horizon_defaults_to_seven_days_and_is_capped_at_a_year`.
- `registry-bregctl`: the held-lock, pin-mismatch, and invalid-configuration
  diagnostics of `idempotency-retention erase-expired`.

### Accepted residuals

- **Earlier spent keys do not carry into a fresh database.** v0.40.0 does
  not upgrade v0.39.0 state in place; apply to a new database. Resolve
  uncertain writes and stop earlier hook workers before moving callers.
  Entity uniqueness constraints refuse a duplicate create where the project
  declares them.
- **Issuer or principal mapping changes re-scope keys.** A retry across a
  change of `authentication.oidc.issuer` or of the principal claim is another
  caller's fresh request. The operator guide says to resolve uncertain writes
  before such a change.
- **Spent rows are never deleted.** The digest row is kept indefinitely for
  immediate-action provenance. Its raw caller and key are cleared only when
  the operator runs the sweep; the engine schedules nothing, so an operator
  who never runs it keeps them as long as the row.
- **A late retry cannot recover a lost body.** Past the horizon a client
  whose first response was lost must read the record or its history.
- **Ingestion chunk replays do not use the horizon.** A chunk replays from
  the run's own chunk receipt, which the run retains; the spent row behind it
  is never the source of that reply.
- **Ingestion run ownership follows the same rule.** Runs are owned by the
  verified caller as well; see
  [Ingestion run ownership by the verified caller](#ingestion-run-ownership-by-the-verified-caller).

## Ingestion run ownership by the verified caller

The change moves ingestion run ownership off the audit hash key and onto the
verified caller (#1930; `crates/registry-breg/src/ingestion_store.rs`,
`crates/registry-breg/src/postgres/mutation.rs`). It touches authorization
(who may list, read, continue, recover, or cancel a run), data minimization
(the raw issuer and principal are persisted on the run row), audit integrity
(what rotating `audit.hashKeyRef` changes), and fresh storage defaults.
The invariant is BREG-SEC-167.

### Threat

1. A run was found by `created_principal_reference`, a keyed hash under
   `audit.hashKeyRef`, and bound to a keyed claim context reference. Rotating
   the key hid every open run from its creator, so a bulk import could not
   resume, recover a lost chunk receipt, or be cancelled: a pseudonymization
   control decided who owns a run.
2. Moving ownership off the keyed hash must not let another principal list,
   read, continue, recover, or cancel a run.

### Enforcement and defaults

- **Owner.** `registry_ingestion_runs` stores `created_issuer`, the
  configured `authentication.oidc.issuer` the runtime scopes every caller
  under (`MutationCoordinator::caller_issuer`), and `created_subject`, the
  verified principal. Both are `NOT NULL` and non-empty. `created_by`
  compares both raw values; `visible_run` (read, cancel, receipt recovery),
  chunk submission, the listing filter, and the listing cursor all decide
  ownership through it, and another caller's run stays the concealed 404 it
  was.
- **Context.** `bound_context_reference` is an unkeyed SHA-256 over the
  domain `breg-ingestion-context-v2`, the database id, and the canonical raw
  verified claim context (principal, selected profile, purpose, row
  boundaries, submitter targets, and task grant), the same members the
  spent-key binding digests. Every operation still re-derives it and refuses
  a drifted context with `ingestion.profile_mismatch`.
- **Audit key.** Nothing that finds or binds a run reads `audit.hashKeyRef`.
  `created_principal_reference` stays on the run and on its audit records as
  the creator's pseudonym; rotating the key changes it for later audit
  records only.
- **Installation.** `ingestion_store::install` creates the verified creator
  columns directly and converts or discards no stored run.

### Data minimization

The run row now stores the creator's raw issuer and principal value, where it
stored only a keyed hash. They appear in no run response and no audit record:
responses carry run metadata only, and audit records carry the keyed
pseudonym. Runs have no retention horizon or erasure path of their own, so
the raw values stay with the run for the life of the database, as the run's
committed counts and digests do. The context reference is unkeyed, so
someone who can read the table can confirm a guessed low-entropy claim value
against it; that reader already sees the raw principal beside it.

### Tests

- `tests/postgres_ingestion_runs.rs`:
  `an_audit_key_rotation_keeps_every_run_with_its_verified_creator` opens two
  runs, rotates the audit key, and proves the creator still lists both, reads
  one, recovers and replays its committed chunk, completes it, and cancels
  the other, while another principal lists none and gets 404 on read,
  receipt, chunk, and cancel without a write;
  `run_access_is_creator_scoped_and_possession_grants_nothing`.
- `src/ingestion_store.rs`: `a_run_without_its_verified_creator_is_refused`.
- `src/postgres/mutation.rs`:
  `a_sibling_task_grant_changes_the_run_context_reference` pins the unkeyed
  context reference to the spent-key claim context and the database scope.

### Accepted residuals

- **Issuer or principal mapping changes re-scope runs.** After a change of
  `authentication.oidc.issuer` or of the principal claim, an open run belongs
  to no current caller; finish or cancel open runs before such a change.
- **Raw creator values stay with the run.** No run retention exists, so the
  issuer and principal stay as long as the run row does.

## Runtime file decoded by the shared reader

`runtime.yaml` is decoded through the shared runtime loader
(`registry-platform-config`), which reads and types the file in one pass,
instead of a product-side `serde_path_to_error` pass over the loader's
generic value. It touches deployment defaults and the value-free reporting of
operator configuration. This replaces the removed-runtime-key refusal codes
and the unset-variable wording that "State older than the immediate
predecessor" describes.

### Threat

An operator who cannot see every problem in the file, with its position,
edits it by trial and error, and a refusal that echoes a configured value
leaks a secret or a substituted value into logs and terminals. A product-side
second decode also loses the reader's all-unknown-keys reporting, so an
unknown key inside a platform block (`package`, `authentication.oidc`,
`audit`) was reported alone or not at all.

### Enforcement and defaults

- `runtime_config_loader()` in `crates/registry-breg/src/runtime_config.rs`
  declares the envelope and the removed keys (`database.url`,
  `database.password`, `database.plaintext`), and `RawRuntimeConfig` is
  decoded by the loader directly. The platform blocks are read through the
  reader's shared-block recipe, not serde `flatten`.
- Every member is closed, so a registry-project member such as `entities`,
  `webhooks`, or `telemetry` is refused as `config.unknown-key` wherever it
  appears. The heuristic that looked for those names across the document is
  removed; the binding maps (`eventDestinations`, `evidenceProviders`,
  `reviewAuthorities`, `reviewExecutors`) were already exempt from it, and a
  logical id there is still not a governed member.
- A listener `bind` that is not a numeric socket address and an
  `audit.hashKeyRef` that is not a secret reference are refused by the reader
  at their own pointer (`config.invalid-value`) rather than as the binding.
  The semantic checks that follow (private or loopback address, distinct
  sockets, provider roots) are unchanged.
- `breg` that refuses its runtime file prints one fixed sentence and the
  reader's diagnostics in the human shape on stderr. Each names the file path
  the operator passed, as Evidence and Casework already do, and none names a
  configured value. The JSON operational log on stdout carries only the
  closed refusal class and no path. `ReaderRefusal`'s `Debug` prints the
  deciding code and pointer only, so a startup error carried elsewhere never
  prints the path.
- The file bound is the shared 1 MiB (CFG-YAML-6), raised from 64 KiB. The
  bound on the document after `${...}` substitution is removed: a substituted
  value is held to the bound of the member it fills. The environment is
  operator-held, as the file is.
- A substitution refusal names the variable to set, as every product's does,
  and never its value or a `${NAME:?message}` message. The variable name is
  already written in the file the operator holds.

### Tests

- `crates/registry-breg/tests/runtime_config.rs`:
  `two_unknown_keys_inside_each_shared_block_are_all_reported_with_positions`
  (fails when a block is read through `flatten`),
  `a_document_refusal_names_its_field_and_never_echoes_the_refused_value`,
  `unknown_package_keys_are_refused_as_document_errors_without_their_value`,
  `an_unknown_package_key_holding_a_set_variable_is_refused_without_the_substituted_value`,
  `raw_database_urls_inline_secrets_and_plaintext_posture_are_refused`
  (the removed keys, value-free), `a_substitution_inside_a_secret_reference_is_refused`,
  and `an_oversized_substituted_value_is_refused_by_its_member_without_echo`.
- `crates/registry-breg/tests/startup_http.rs`:
  `provenance_operational_logs_metrics_and_traces_are_separate_closed_and_value_free`
  runs the `breg` binary on a refused file and proves stdout carries no path
  or value and stderr carries the reader's diagnostic with its position and
  fix and no value.
- `crates/registry-bregctl/src/doctor.rs`:
  `a_refused_runtime_file_reports_every_reader_diagnostic_unchanged`.

### Accepted residuals

- **Stderr names the file path.** An operator who forwards stderr into a
  shared log forwards the path of the runtime file. The path is the one the
  operator typed, and the stdout log stays path-free.
- **No bound on the substituted document as a whole.** A file of many
  `${...}` expressions that each expand to a large variable can make the
  decoded document much larger than the file. Both the file and the
  environment are operator-held; a bound belongs in the shared loader, for
  every product, if one is wanted.
- **The `bregctl` JSON report carries no line or column.** Reader
  diagnostics keep their code, pointer, and fix in `bregctl --format json`,
  but the tool report has no source position field; the human `breg` output
  carries it.

## Runtime references and URLs typed by the shared reader

Every `*Ref` member of `runtime.yaml` is decoded as the shared
`SecretReference`, and the URLs a runtime calls or compares (`listener.publicOrigin`,
an Evidence provider's `baseUrl`, the task-grant status `baseUrl` and
`sourceIssuer`, and the OIDC issuer and explicit JWKS URI) as the shared `Url`.
It touches secret reference handling, outbound endpoints, and the value-free
reporting of operator configuration.

### Threat

A product-side parse of each reference, repeated per block, can drift: one
block accepting a reference another refuses, or a refusal that echoes the
inline secret an operator pasted where a reference belongs. A URL checked only
after decode reports the whole block, not the member, so the operator cannot
tell which value to fix.

### Enforcement and defaults

- The database `runtimeUrlRef` and `migrationUrlRef`, `cursor.secretRef`, the
  review authority, review executor, and Evidence provider credentials
  (`tokenRef`, `privateKeyJwt.privateKeyRef`, `trustedJwksRef`,
  `caBundleRef`), an event destination's `hmacSha256KeyRef` and TLS
  `caBundleRef` and `clientIdentityRef`, the attachment storage and
  verification references, the field-encryption `dekRef`, and the task-grant
  status `privateKeyRef` and `caBundleRef` are `SecretReference`
  (`crates/registry-platform-config`). The reader refuses a value that is not
  `secret:env/NAME` or `secret:file/name` as `config.invalid-value` at the
  member and never repeats it. Which providers a reference may name is still
  checked against `secretProviders` after decode, unchanged; the
  field-encryption `dekRef` still refuses an environment reference.
- `Url` (`crates/registry-platform-yaml`) refuses anything but an absolute
  `http` or `https` URL with a host and no user information, of at most 2048
  characters. The product checks that follow are unchanged: `publicOrigin`,
  an Evidence `baseUrl`, and a task-grant `baseUrl` are `https`, with `http`
  only for a loopback host. `sourceIssuer` is compared with the Casework
  issuer and never fetched, so `http` stays accepted there; a non-URL issuer
  such as a `urn:` is now refused.
- An empty `authentication.oidc.assertionIssuers` mapping is refused: it
  restricts which authority each client may exchange from, and omitting the
  member is how a file applies no assertion-issuer rule (CFG-EMPTY-2). A
  client listed with `[]` is refused as well; "A listed assertion-issuer
  client names at least one issuer" below records that refusal.
- The published schema states the same: each reference is
  `$ref: SecretReference`, each URL `$ref: Url`, and an optional reference,
  path, or retention member publishes no `default: null` and says what
  omitting it means.

The shared issuer and explicit JWKS URI now refuse backslashes and host text
that the URL parser rewrites, with value-free `config.invalid-value` at the
member. Ordinary ASCII DNS case differences, punycode and IPv6 literals remain
accepted. Issuer comparison stays textual, and the existing HTTPS and
loopback rules still run after decode. The shared
`issuer_and_jwks_uri_are_checked_urls_when_read` test pins those refusals and
ordinary inputs. Base Registry Engine's `oidc_issuer_and_audience_follow_the_shared_issuer_block`
and `jwks_source_uri_kind_skips_discovery_under_the_shared_rules` in
`crates/registry-breg/tests/runtime_config.rs` pin the retained policy and
member-level typed refusals.

### Tests

- `crates/registry-breg/tests/runtime_config.rs`:
  `raw_database_urls_inline_secrets_and_plaintext_posture_are_refused` (an
  inline database URL refused at `/database/runtimeUrlRef` without its
  password), `invalid_event_destination_ids_origins_paths_cidrs_refs_and_ceilings_are_refused`
  (a traversing key reference refused at the member, value-free), and
  `invalid_assertion_issuer_shapes_are_refused` (the empty mapping refused,
  and a client listed with `[]` refused at the client).
- `crates/registry-breg/src/attachment_storage.rs` and
  `crates/registry-breg/src/attachment_verification.rs`: an inline
  credential is refused at decode and the error does not carry it.
- `crates/registry-breg/src/task_grant/config.rs`: user information,
  `http` outside loopback, and a fragment are refused in the status
  `baseUrl`.

### Accepted residuals

- **A provider-specific refusal comes after decode.** A reference that names
  a provider `secretProviders` does not enable is still refused by the
  product check, with the runtime's code, after the reader has accepted its
  shape.

## Reviewed migration documents read through the shared reader

The change reads the three reviewed migration documents, the descriptor, the
rehearsal receipt, and the backup binding, through the shared configuration
reader (`read_migration_descriptor`, `read_rehearsal_receipt`, and
`read_backup_binding_document` in `crates/registry-breg/src/migration_plan.rs`;
`read_backup_binding` in `crates/registry-breg/src/migration.rs`). Each now
starts with its `apiVersion` and `kind`, uses the convention's spellings, and
no longer has to be canonical JSON bytes. It touches the evidence a reviewed
migration carries into a package and the backup evidence `plan` and `apply`
require before a destructive step; the checks that evidence feeds are
unchanged, so no security invariant row changes.

### Threat

1. Dropping the canonical-bytes rule must not let a descriptor change after
   its rehearsal: the receipt's plan digest was the SHA-256 of the
   descriptor's exact bytes.
2. A document the reader cannot read must not reach the checks with a
   member silently dropped or defaulted, and a refusal must not echo a digest,
   path, or row count it was given.
3. A receipt or binding written in the previous spelling must not be read as
   an empty or partial one.

### Enforcement and defaults

- **Plan binding.** `planDigest` is the SHA-256 of the canonical JSON of the
  decoded descriptor, header included, so whitespace and key order are free
  while any member change, including its `apiVersion` or `kind`, breaks the
  binding with the refusal it had. The SQL and assertion files stay bound by
  their exact bytes. A package carries the descriptor bytes it was built
  from, and loading the package revalidates the plan through the same
  reader, so a package built from a descriptor in the previous spelling is
  refused on load.
- **Strict decode.** The binding keeps its 64 KiB cap and the descriptor and
  receipt their 1 MiB one. Unknown, duplicate, missing, and renamed keys, a
  wrong header, and a malformed digest are refused before any semantic check:
  `bregctl` and `plan`/`apply` print the reader's code, JSON pointer, line,
  and column, and the runtime's package load keeps its existing value-free
  refusal. Renamed keys carry a removed-key entry naming their replacement,
  and `proofs` is refused the same way.
- **Unchanged checks.** The binding's absolute path, owner-only file, size,
  age bound (`maximumAgeSeconds`, at most 31 days), prior package digest and
  schema fingerprint, database identity, and backup digest checks run as
  before, and so does every descriptor shape and step check.
- **Decoded change words.** Change classes, change codes, target kinds,
  recovery words, and step variants are written in kebab-case. Classification
  and coverage compare decoded variants and typed covers, never their written
  strings. No variant, classification rule, or cover rule changes. A word in
  its previous spelling does not decode and is refused at its member.
- **Value-free refusals.** Reader diagnostics name the key and the expected
  shape, never the value; `bregctl` prints them unchanged under one sentence
  naming the document.

### Tests

`crates/registry-breg/tests/migration_plan.rs`:
`reviewed_migration_documents_refuse_their_previous_spellings_at_each_key`,
`reviewed_descriptor_refuses_the_snake_case_spelling_of_each_enumerated_word`,
`reviewed_descriptor_reformatted_by_hand_keeps_its_rehearsal_binding`, and
`reviewed_package_whose_receipt_carries_the_retired_proofs_is_refused`.
`crates/registry-breg/src/migration.rs`:
`a_written_backup_binding_reads_back_through_the_shared_reader` and
`a_backup_binding_in_its_previous_spelling_is_refused_with_positioned_diagnostics`.
`crates/registry-bregctl/src/lib.rs`:
`a_refused_backup_binding_document_keeps_the_reader_diagnostics`.
`crates/registry-bregctl/tests/cli/reviewed_migrations.rs`:
`reviewed_successor_accepts_a_reformatted_descriptor_and_refuses_previous_spellings`,
`reviewed_successor_refuses_a_malformed_receipt_digest_at_its_key_without_repeating_it`,
`reviewed_successor_refuses_duplicate_keys_headerless_documents_and_extra_artifacts`,
and `reviewed_successor_refuses_a_receipt_that_carries_retired_proofs`.

### Accepted residuals

- **Packages carrying reviewed migrations are rebuilt.** A package built by an
  earlier release with a reviewed migration is refused on load after the
  upgrade; rewrite its documents in the new spelling and rebuild it. Nobody
  runs Base Registry Engine in production yet.
- **The migration ledger keeps its own spelling.** The backup references the
  ledger records (`sha256`, `byteLength`) are internal database state, not a
  document an operator writes, and are unchanged.

## A listed assertion-issuer client names at least one issuer

`authentication.oidc.assertionIssuers` in `runtime.yaml` decides which
assertion authority each OAuth client may exchange a subject token from. It
touches authentication configuration and a deployment default: how a file
writes "this client may exchange from no authority".

### Threat

Two spellings of the same posture read differently to an operator. A client
left out and a client listed with `[]` both exchange from no authority, but
`kiosk: []` beside populated clients reads like a placeholder to fill in
later, or like "no restriction for this client". An operator who believes
the second reading thinks a client is unrestricted when it is denied, or the
reverse after a careless edit, and a reviewer comparing two runtime files
cannot tell a deliberate denial from an unfinished one. The empty mapping `{}` was already refused for the
same reason.

### Enforcement and defaults

- `ListedIssuers` in `crates/registry-breg/src/runtime_config.rs` reads one
  client's list and refuses an empty one while the shared reader decodes the
  file, before any runtime state is built. `breg` does not start, and every
  `bregctl` command that reads the runtime file reports the same refusal.
- The refusal is `config.invalid-value` at
  `/authentication/oidc/assertionIssuers/<client>`. It says to list at least
  one assertion issuer for the client or to remove the client, and never
  repeats a value from the file.
- The published runtime schema states `minItems: 1` on the per-client list,
  beside the `minProperties: 1` it already states on the mapping.
- The verifier is unchanged. A client that is not listed still exchanges
  from no authority once the member is written, so removing the refused
  client keeps the posture the empty list had. Nothing fails open: the
  change only removes a second way to write a denial.
- `bregctl dev` builds each client's list by adding an issuer, so it never
  writes a client with an empty list.

### Tests

- `crates/registry-breg/tests/runtime_config.rs`:
  `invalid_assertion_issuer_shapes_are_refused` (negative: a client listed
  with `[]` beside a populated client is refused at the client's own
  pointer, and the refusal names the fix).
- `crates/registry-breg/src/runtime_config.rs`:
  `schema_refuses_a_client_listed_with_no_assertion_issuer` (the schema
  states `minItems: 1`).
- `crates/registry-breg/src/schema.rs`: the schema and parser parity test
  refuses the same instance under "OIDC assertion issuer client listed with
  no issuer".

### Accepted residuals

- **Removing the last listed client leaves `{}`.** That is refused too, so
  the operator must decide between listing another client and deleting the
  member, which applies no assertion-issuer rule at all. The release notes
  say so; the reader cannot decide it for them.

## Access profile permissions grouped by what each names

`accessProfiles[].permissions` in `registry.yaml` is the authored statement
of everything a profile may do. It was one list whose entries were told apart
by the member each carried (`entity`, `action`, or `dataset`); it is now a
mapping of three lists, `entities`, `actions`, and `datasets`, each read by
one strict shape. This changes the grammar of authorization configuration and
no authorization decision: the compiled access model is the one the list
compiled to. The reader is `PermissionsSource`, `EntityPermissionSource`,
`ActionPermissionSource`, and `DatasetPermissionSource` in
`crates/registry-breg/src/contract.rs`, with the shape refusal in
`crates/registry-breg/src/contract/sentinel.rs`. No security invariant row
changes.

### Threat

A change of grammar in the file that grants access can widen or silently drop
a grant in four ways. A permission is read as another kind, so members that
bound it (`rowBoundaries`, `readableFields`, `requireConsent`) are ignored. A
file in the earlier form is read as a profile that grants nothing, or as one
that grants something else, without telling its author. A member written
under the wrong group is dropped and the permission is accepted without the
bound it stated. Or the regrouping reorders or merges grants so that a
project compiles to different access than before.

### Enforcement and defaults

- **Each group reads one strict shape.** `permissions.entities`,
  `permissions.actions`, and `permissions.datasets` each deserialize one
  struct that denies unknown members. A member of another kind of permission
  is refused with `config.unknown-key` at the member, and an entry that does
  not name what its group lists is refused with `config.missing-key`. Nothing
  is inferred from the members present, and no member is dropped.
- **The earlier list is refused, never converted.** `sentinel::permissions`
  reads `permissions` through a shape union whose list and scalar variants
  are refusals: `config.invalid-value` at `/accessProfiles/N/permissions`,
  with a fix that names the three groups. `permissions: []`, which the
  earlier reader accepted as a profile that grants nothing, is refused the
  same way, so no file is read under a meaning its author did not write.
- **Refusals move earlier, none is removed.** Entity members on an action
  permission, action members on an entity permission, and `requireConsent`
  on an action permission were refused by the compiler; the reader now
  refuses them first. The five compiler diagnostics that refused a
  permission naming both an entity and an action, or neither, are deleted
  because no file can state that shape. An entity permission without
  `rowBoundaries` is still refused with the same fix, and `[]` is still not
  a way to write unrestricted reach.
- **An omitted group grants nothing.** `permissions`, and each group in it,
  defaults to empty. An empty group has the meaning an absent permission of
  that kind had; there is no implicit grant and no wildcard.
- **The compiled model is unchanged.** The compiler walks the entity
  permissions, then the action permissions, then the dataset permissions,
  each in the order written. For the 36 registry projects in this repository
  (the 31 under `products/breg` and five single-file fixtures of
  `crates/registry-breg/tests/fixtures`), `bregctl check`, `check
  --production`, the eight `explain` subjects, and the six `generate`
  selectors were captured before and after the reader changed: 576 exit
  codes are identical, every `explain` report and every generated file is
  byte-identical, and every registry revision is identical. The 57 files
  that differ are check reports, and they differ only where a diagnostic
  names its place: the pointer gains the group, and the line and column
  follow the regrouped file.
- **Diagnostics repeat no authored value.** The shape refusal and the
  unknown-key refusals name members and groups, never an entity, action,
  dataset, claim, or scope the file wrote.

### Tests

- `crates/registry-breg/tests/permission_groups.rs`:
  `one_permissions_list_is_refused_with_the_grouping_named` (negative: a
  list, `[]`, and a scalar are refused at `permissions` with the fix),
  `a_permission_written_under_another_group_is_refused_where_it_is_written`
  (negative: each of the six cross placements is refused with
  `config.unknown-key` at each foreign member and `config.missing-key` at the
  entry), `an_action_permission_states_no_row_reach` and
  `an_action_permission_carries_no_entity_member` (negative: every member
  only an entity permission carries is refused on an action permission),
  `an_entity_permission_states_its_row_reach` (negative: an omitted or empty
  `rowBoundaries` is refused), `a_group_lists_only_its_own_operations`,
  `a_dataset_permission_lists_at_least_one_operation`,
  `a_permission_lists_each_operation_once`,
  `permissions_holds_only_the_three_groups`,
  `a_group_that_is_omitted_or_empty_grants_nothing`,
  `the_groups_may_be_written_in_any_order`,
  `a_profile_groups_its_permissions_by_what_each_names`, and
  `a_profile_writes_its_permissions_back_grouped`.
- `crates/registry-breg/tests/consent_access.rs`:
  `gated_permissions_are_read_only` (negative: `requireConsent` on an action
  permission is refused when the project is read, and a gated profile that
  invokes an action targeting its gated entity is still refused with
  `breg.consent.require-read-only`).
- `crates/registry-breg/src/schema.rs`:
  `schema_states_permissions_as_one_list_per_kind` (the published project
  schema holds no untagged permission union).

### Accepted residuals

- **Every project is rewritten once.** No conversion is offered: the earlier
  list is refused with the fix named. Nobody runs Base Registry Engine in
  production yet.
- **`permissions: []` is no longer a way to write "grants nothing".** A
  profile that grants nothing omits the member or writes `permissions: {}`.
- **A package is rebuilt.** A package holds the project as written, so its
  digest changes while its registry revision does not. This release already
  refuses every package an earlier release built.

## Fresh storage and caller replay

Threat and enforcement: The installer must not invent an owner, free a spent key, or discard accountability. Fresh creation defines the verified ingestion creator and caller-scoped receipt columns directly. Installation contains no conversion of audit-keyed rows and no discard of creatorless runs. Request reasons, revision erasure bounds, review-result bounds, and field-encryption receipt checks are defined at creation; shared webhook installation does not repair an earlier table. Replay lookup, receipt retention, creator concealment, action-result provenance, and audit ordering are unchanged. Generic verified successors remain available for releases from v0.40.0 onward.

Verification: `tests/postgres_ingestion_runs.rs::an_audit_key_rotation_keeps_every_run_with_its_verified_creator` and `tests/postgres_mutation.rs::real_postgres_exact_retry_after_audit_key_rotation_replays_and_never_reexecutes`. Schema-only dumps of separate fresh
installations are compared before and after, with no ledger data.

Residual: v0.40.0 does not upgrade v0.39.0 state in place; apply to a new
database. No compatibility reader or migration of earlier state is provided.

## Tooling and statistics vocabulary

The CLI report words, migration-ledger kinds, and statistical operation names
use kebab-case. This changes what report, metadata, OpenAPI, and audit
consumers compare. It changes no authorization grant, verification result,
activation authority, or release decision.

### Threat

A renamed word must not select a different error recovery, bypass a migration
constraint, grant access to another statistical route, or misidentify a
statistical operation in its audit entry. A code copied from an HTTP client
must keep the decoded failure's classification and recovery advice.

### Enforcement and defaults

- `DiagnosticArtifact`, `SuggestedAction`, and `BaselineAssurance` keep the
  same Rust variants. Serde changes their written spelling only. Operation
  diagnostics retain their condition, severity, path, and corrective action.
  `tool_diagnostic` applies the CLI spelling to a borrowed closed diagnostic;
  the client's decoded Problem variant and the HTTP Problem vocabulary are
  unchanged. No variant or classification rule changes.
- Migration kinds are selected through `MigrationKind` variants. Its writer
  and the fresh ledger's CHECK constraints use `compiled-additive`,
  `metadata-only`, and `reviewed`. No row is converted. Statement checksums,
  review closure, role grants, and activation audit requirements are unchanged.
- Statistical routes retain the `Kind` variants and the existing compiled
  access grants. Their operation names are written in kebab-case in generated
  metadata and OpenAPI and in audit `operationId`. Dataset selection, HTTP
  method, publication, withdrawal, and replay rules are unchanged.

### Tests

- `crates/registry-bregctl/src/lib.rs`:
  `diagnostic_and_assurance_words_use_the_public_kebab_case_contract`,
  `baseline_assurance_words_use_the_public_kebab_case_contract`, and
  `runtime_path_refusal_uses_a_kebab_case_operation_code` check the written
  report contract; `statistics_http_failures_preserve_actionable_cli_diagnostics`
  sends the existing HTTP Problem vocabulary through the client and checks
  the CLI condition and recovery.
- `crates/registry-breg/src/postgres/migration_ledger.rs`:
  `stored_migration_kind_words_use_kebab_case` checks each stored kind.
  `crates/registry-breg/tests/postgres_migration.rs` checks fresh activation
  ledger rows and checksum constraints against real PostgreSQL.
- `crates/registry-breg/tests/compiler_statistics.rs`:
  `generated_artifacts_cover_the_effective_model_metadata_and_seven_routes`
  checks all seven metadata/OpenAPI operation names and operation identifiers.
  `crates/registry-breg/tests/postgres_statistics_http.rs`:
  `statistical_http_full_journey_preserves_visibility_release_and_withdrawal_rules`
  checks the real routes, visibility, release decisions, and audit operation
  names.

### Accepted residuals

Report and audit consumers that compare the old spellings must update with
this release. The engine does not accept both spellings or convert retained
rows. State from earlier releases is refused; install fresh.

## Module task-grant issuers and provenance sets

### Threat

An ill-shaped issuer identity or a repeated provenance requirement makes an
authored access profile ambiguous before it reaches authorization checks.

### Enforcement and defaults

- `TaskGrantSource` in `crates/registry-breg/src/contract.rs` reads a module
  profile's `taskGrant.sourceIssuer` through `members::url_text`, with the
  shared `Url` schema. An issuer outside that URL grammar is refused at its
  member. The issuer remains a comparison identity, not a fetch instruction.
- `provenanceFields` uses `members::unique_items` and the `UniqueSet` schema
  in project and module profiles. Distinct fields retain their declared
  order; a repetition is refused as `config.duplicate-item` at the repeated
  element rather than silently collapsed.
- These reader checks leave issuer matching and provenance enforcement for
  accepted profiles unchanged. The issuer refusal diagnostic never repeats
  the supplied issuer.

### Tests

`crates/registry-breg/tests/compiler_contract.rs`:
`a_module_profile_task_grant_issuer_is_read_as_a_url` refuses a URN issuer at
the source member without echoing it, and
`provenance_fields_are_read_as_a_set_in_a_project_and_a_module` accepts
distinct fields and refuses repetitions in both authored forms.

### Accepted residuals

The operator rewrites a refused declaration; no alias, deduplication, or
issuer discovery is supplied. These checks grant no task authority.

## JWKS source discriminator in runtime and MCP configuration

### Threat

A retired discriminator must not be ignored or interpreted as a default key
source in authentication configuration.

### Enforcement and defaults

The shared runtime loader names
`authentication.oidc.jwksSource.kind` as a removed key, with `type` as its
replacement. The MCP configuration loader does the same for
`resourceServer.jwksSource.kind`. Both refuse it as `config.removed-key` at
its own pointer before token processing. There is no alternate reader for
the retired member. Trusted key sources, signature checks, audience checks,
and client admission are unchanged for accepted configuration.

### Tests

- `crates/registry-breg/tests/runtime_config.rs`:
  `the_issuer_key_source_names_its_variant_in_a_type_member`.
- `crates/registry-breg-mcp/src/config.rs`:
  `each_removed_key_is_refused_with_its_replacement`.
- `crates/registry-platform-config/src/blocks_tests.rs`:
  `a_jwks_source_tagged_by_kind_is_refused`, and `loader_tests.rs`:
  `the_shared_removed_jwks_source_kind_key_names_type`.

### Accepted residuals

Operators must write the discriminator as `type`; the diagnostic names that
fix without repeating the configured value.

## Evidence in an action is gated by the action's declaration

### Threat

An action handler reaches `evidence::resolve`, and through it an operator
credential and an outbound request, without the reviewed project declaring
that the action consumes Evidence. The handler ABI identifier used to be a
second statement of that fact beside the action's `evidence` declaration.
With one ABI, `registry.action-handler/v1`, the declaration is the only
statement, so every branch that read the identifier must read the declaration
and must refuse wherever the identifier refused.

### Enforcement and defaults

- `compile_handler` in `crates/registry-breg/src/immediate_actions.rs`
  accepts one `abi` value. `registry.action-handler/v2` is refused as
  `breg.action.handler-abi-invalid` at the handler's `abi`, with no alias
  and no reading of the retired value; the message names the accepted
  identifier and repeats nothing from the file.
- `compile_source_for_action` in `crates/registry-breg/src/action_handler.rs`
  walks the handler source and admits a call in the `evidence` namespace only
  when the action declares `evidence` and the call is `evidence::resolve`
  with two arguments. A handler whose action declares none fails to compile
  with `breg.action.handler-helper-contract`, in statements, expressions,
  and nested blocks, exactly where a `registry.action-handler/v1` handler
  failed before.
- The declaration that opens the helper is itself checked after every
  handler has compiled: `compile_evidence` in
  `crates/registry-breg/src/action_evidence_contracts.rs` still requires a
  declared provider, a capability in the sealed contract, an exact
  fingerprint, and at most two capabilities. It refuses `evidence` on an
  action whose handler is absent or not Rhai with
  `breg.action.evidence-ceiling-invalid`, so a WASM handler never receives
  a resolver; a module action still cannot declare `evidence`.
- At run time `evaluate_with_engine` compiles the handler under the compiled
  action's own `evidence`, and `admit_handler` refuses an action that
  declares Evidence when no resolver is supplied, so its handler never runs
  on the input-only path. A resolver never reaches a WASM handler.
- `activate` in `crates/registry-breg/src/action_evidence_config.rs` binds
  an evaluator exactly when the compiled registry requires a provider, and
  still refuses a runtime binding set that differs from the required one.
  `invoke_action` in `crates/registry-breg/src/postgres/mutation.rs` routes
  an action that declares Evidence to the Evidence path, which answers
  unavailable when no evaluator is bound.
- One state disappears and none is added. A `registry.action-handler/v2`
  handler on an action with no `evidence` ran on the Evidence path with a
  zero-call ceiling and activated an evaluator with no provider. That
  project is now refused until it declares `registry.action-handler/v1`,
  and it then runs as an input-only action with no evaluator. Every handler
  that can call `evidence::resolve` now could call it before: it belonged to
  an action that declared `evidence` and named a Rhai handler.

### Tests

- `crates/registry-breg/tests/action_evidence_compiler.rs`:
  `evidence_calls_require_a_declared_capability_in_statements_expressions_and_nested_blocks`,
  `the_evidence_declaration_selects_the_capability_under_the_one_handler_abi`,
  `the_retired_evidence_abi_is_refused_where_it_is_declared`,
  `published_authoring_schema_accepts_farmer_and_rejects_every_other_abi`,
  and `refuses_origin_profile_output_ambiguity_and_budget_widening`.
- `crates/registry-breg/tests/immediate_action_compiler.rs`:
  `the_retired_v2_abi_is_refused_and_wasm_needs_a_wasm_capable_build`.
- `crates/registry-breg/tests/wasm_handler_admission.rs`:
  `an_evidence_declaration_stays_refused_for_wasm_handlers_under_the_feature`.
- `crates/registry-breg/src/action_evidence_config.rs`:
  `an_action_declaring_no_evidence_activates_no_evaluator_and_extra_bindings_fail_closed`.
- `crates/registry-breg/src/tests/action_handler_benchmark_tests.rs`:
  `cached_program_refuses_evaluation_for_a_different_evidence_declaration`.
- `crates/registry-bregctl/src/lib.rs`:
  `an_action_declaring_no_evidence_explains_no_evidence_lifecycle` and
  `an_action_declaring_evidence_explains_the_external_lifecycle_and_call_ceiling`.
- `crates/registry-breg/tests/postgres_action_evidence.rs`,
  `postgres_action_evidence_targets.rs`, and
  `postgres_action_evidence_retention.rs` run the farmer acceptance project,
  now declaring `registry.action-handler/v1`, against PostgreSQL.

### Accepted residuals

No alias or conversion is supplied: a project that still declares
`registry.action-handler/v2` does not compile, and a package that holds one
is refused when it is rederived. Evidence stays Rhai-only, and consuming
Evidence from an action remains a trial whose authoring contract is not
frozen for Version 1. These references name proof obligations, not an
execution claim.

## Client refusal and webhook audit vocabulary

### Threat

A receiver or audit consumer branching on a retired failure word may miss a
refusal or misclassify a delivery. Vocabulary changes must preserve the
closed failure variants and the audit identity that relates an attempt to
its terminal result.

### Enforcement and defaults

- Node and Python bindings project the same closed Rust failure variants
  using kebab-case words, including `invalid-request`, `header-bounds`,
  `trace-context`, and `media-type`. The mapping is in
  `crates/registry-breg-client-node/src/lib.rs` and
  `crates/registry-breg-client-py/src/lib.rs`. Shared transport words come
  from `TransportKind::kind`; retryability, unknown-outcome reporting and
  response validation are unchanged.
- `BRegHookVerificationError::code` in
  `crates/registry-breg-client/src/hook.rs` preserves distinct
  `invalid-delivery-time`, `duplicate-header`, `body-too-large`, and
  `invalid-key` causes alongside the signature and missing-header failures.
  Every message names the input to fix without rendering its value.
- `webhook_outcome_name` and `webhook_disposition_name` in
  `crates/registry-breg/src/audit.rs` write kebab-case words, such as
  `attempt-started`, `http-non-success`, `retry-pending`, and `dead-lettered`,
  under the existing `breg-webhook-audit/v2` schema. Dispatch still uses
  typed variants. Request/response pairing, attempt correlation, separate
  discard correlation and treatment of an interrupted delivery of unknown
  fate are unchanged.

### Tests

- `crates/registry-breg-client/tests/webhook.rs`:
  `fixed_vector_verifies_and_returns_exact_delivery` and
  `refusal_codes_are_closed_and_value_free` cover successful verification,
  the four refused variants and absence of supplied values from errors.
- `crates/registry-breg-client-node/__test__/immediate-actions.test.js`:
  `metadata-selected immediate action conditions and invocations use exact caller input`
  asserts `invalid-request`;
  `an immediate action recovers after a lost response from persisted bytes and the same key`
  asserts the transport kind and unknown outcome.
- `crates/registry-platform-httputil/src/client/mod.rs`:
  `every_transport_failure_reports_its_own_kebab_case_kind`.
- `crates/registry-breg/src/audit.rs`:
  `webhook_attempt_and_terminal_share_the_attempt_identity`,
  `webhook_discard_is_answered_under_a_phase_scoped_identity`, and
  `an_interrupted_terminal_of_unknown_fate_is_recorded_only_as_unknown`.

### Accepted residuals

Consumers must match the current words; no spelling conversion is provided.
The webhook refusal test covers failure variants and value absence, and the
audit tests cover correlation and unknown fate. They do not enumerate every
emitted code or audit word; the closed source mappings define that vocabulary.
These references name proof obligations, not an execution claim.


## Default reviewed-change example runtime

The default change-request example runner binds the `casework` authority its
placement and household fixtures declare. Its synthetic bearer token stays in
the runner's private disposable secret directory. Schema tests retain pending
review deliveries in the same transaction as submission and run no authority
worker, so this binding sends no request to the example endpoint.

`products/breg/scripts/test_change_request_runner.py` verifies the rendered
binding. The default `test-change-request-examples.sh` journey exercises both
reviewed fixtures and the person-name Rhai fixture against disposable TLS
PostgreSQL. The runner uses the maintained Cargo runtime-library helper for
source builds; installed mode retains its existing binary selection. No runtime
authority, review policy, delivery, or audit rule changes.

## Shipped database transport refusal

Threat: an operator copies `database.testOnlyPlaintext: true` from a disposable
test fixture into a shipped runtime configuration and silently loses database
TLS. The existing configuration guard refuses that member's true value in
builds without `postgres-test`, before opening a database connection. The
release binary build uses the default features plus `runtime`; it does not enable
`postgres-test`.

`database_test_only_plaintext_is_refused_outside_test_builds_with_its_fix` in `crates/registry-breg/tests/runtime_config.rs`
executes the actual native runtime process and requires the product's
`breg.runtime.plaintext-database` refusal and `testOnlyPlaintext` recovery
field. This regression is excluded from `postgres-test` builds so a permissive
test binary cannot satisfy the shipped-feature proof. The runtime guard and
release build feature selection are unchanged; the existing default-feature
test suite owns this check.

## Standing agent profiles and statistical publication

A standing agent profile, one that declares `actorKind: agent` and no
`taskGrant`, can no longer hold `publish` on a statistical dataset. The
change is an authorization ceiling enforced by the compiler. It adds no check
to the publication routes and changes no route, audit record, or release
decision. The runtime compiles a package's sources again when it loads the
package, so the rule holds at load as well as at build. Its invariant row is
BREG-SEC-168.

### Threat

A standing agent carries no human approval. Publishing a statistical release
and withdrawing one both commit at once: publication fixes released counts,
and withdrawal erases released content, with no draft for a person to
confirm. The three existing standing agent refusals read entity and action
permissions only, so a standing agent profile holding the dataset operation
`publish` compiled and was served.

### Enforcement and defaults

- `compile` in `crates/registry-breg/src/compiler/statistics.rs` checks every
  profile that holds `publish` on a dataset and refuses the package with
  `breg.access-profile.standing-agent-publish-forbidden` when the project
  access profile is a standing agent.
- The runtime authorizes publication and withdrawal through the unit
  entity's profile of the publisher's id. A project profile that grants
  nothing on that entity leaves the id free for a module to contribute, so
  the same check reads that unit entity profile and refuses a standing agent
  there, at `entities[id=<unit>].accessProfiles[id=<profile>]`. A module
  entity profile carries no dataset permission of its own: dataset
  permissions exist only on project access profiles.
- `read-live` and `read-releases` stay available to a standing agent. A
  publisher declaring `actorKind: human`, `actorKind: service`, or no
  `actorKind` is unchanged.
- No new refusal covers task-grant profiles. A task-grant profile declares
  `requiredPurposes`, and the existing publisher rules refuse those on the
  publisher's access to a dataset entity with
  `breg.statistical-dataset.publisher-caller-dependent`. A module cannot
  declare a `taskGrant`, so the unit entity profile a publication is
  authorized through is never a task-grant profile contributed by a module.

### Tests

`crates/registry-breg/tests/standing_agent_ceiling.rs`:
`standing_agent_cannot_publish_a_statistical_release` is the named negative
for the invariant row and exercises both enforcement points. It refuses a
standing agent declared as the project access profile and one a module
contributes as the unit entity profile, asserts the diagnostic path of each,
checks that the three sibling refusals stay silent, and compiles the
module-contributed profile declared human as its control.
`standing_agent_may_read_statistical_counts_and_releases` and
`human_service_and_unspecified_profiles_keep_publish` hold the accepted
cases, and `task_grant_profile_cannot_be_a_dataset_publisher` pins the
existing task-grant refusal. These are compiler tests; no PostgreSQL suite
changes, because no request path changes.

### Accepted residuals

- The ceiling binds profiles that declare `actorKind: agent`. A publisher
  profile without an `actorKind` accepts every declared actor kind by its own
  declaration, as it does for every other operation.
- A project profile and a module-contributed entity profile may share an id
  on an entity the project profile does not grant. A task-grant project
  profile can therefore hold the dataset permission `publish` while a module
  contributes the unit entity profile that authorizes it. That profile is
  neither a task-grant profile nor, under this check, a standing agent, so no
  agent token publishes through it; the project profile's grant is nominal.
  That conclusion rests on two refusals in `authorize_profile_claims`
  (`crates/registry-breg/src/api/mod.rs`), which this change leaves as they
  are. A delegated token is refused on a profile that is not an agent
  profile; `delegated_token_is_admitted_only_by_an_agent_profile` in
  `crates/registry-breg/src/api/tests/change_request_action_tests.rs` pins
  that for a profile without an `actorKind`. A task-grant token is refused on
  a profile without a task grant;
  `task_grant_token_is_refused_by_a_profile_without_a_task_grant` in the same
  file pins that for a profile without an `actorKind` and for a standing
  agent profile.
- The publication routes gain no check and do not compare actor kinds. The
  rule runs where the compiler runs: when a package is built, and again on
  every load, because `rederive` in `crates/registry-breg/src/package.rs`
  compiles the packaged sources and refuses the package when they no longer
  compile. A package built before this rule whose publisher is a standing
  agent is therefore refused at load. That refusal is the general package
  refusal and does not carry this diagnostic code: `breg` stops with
  `the Registry package was refused`, and `bregctl doctor` reports
  `startup.package.refused`. No test loads a package this rule refuses;
  `a_package_sealed_with_the_retired_project_header_is_refused` in
  `crates/registry-breg/tests/frozen_rhai_package.rs` shows the same load
  path refusing a sealed package whose project source the current reader
  refuses.

## Action revision provenance and access-log storage no predecessor left behind

Before 1.0 a release reads only the state its immediate predecessor wrote or
accepted. The change removes two tolerances for state only releases before
v0.39.0 could leave behind: the revision reader's acceptance of an immediate
action's effect identifier as a revision's journal operation, and the managed
catalog alternative that verified and served a database without the subject
access-log storage. It touches audit integrity (which journal provenance the
revision reader accepts, BREG-SEC-142) and deployment defaults (which managed
catalog startup, `bregctl`, and an apply verify).

### Threat

1. A revision journaled under an identifier that is not its entity's
   canonical record operation passes as action provenance. The removed
   tolerance accepted an effect identifier when a stored action result named
   that record, revision, effect, and mutation kind under an action the active
   package still declared. Removing it must not turn any other identifier
   into accepted provenance, and must not make a revision an action writes
   today unreadable (BREG-SEC-142).
2. A database whose managed catalog lacks an object every apply installs is
   verified and served. The removed alternative admitted a catalog without
   `registry_internal.registry_subject_access_log` and its expiry function
   for a package declaring no `accessLog`. Removing it must leave every such
   database refused, and must not move the recorded schema fingerprint of a
   database that holds the storage.

### Why v0.40.0 cannot leave either state

- Every revision v0.40.0 journals for a create, patch, or tombstone carries
  the entity's canonical operation identifier or, on a request lifecycle
  revision, a request journal operation. `MutationCoordinator` builds an
  action effect's operation as `records.<entity>.<kind>` before it calls
  `insert_revision`, direct writes pass the route's canonical identifier, and
  the history migration writes the `migration` kind under its own reference.
  v0.38.0 was the last release whose action path passed the effect
  identifier; v0.39.0 journals the canonical one.
- Every apply runs `install_mutation_schema`, which calls
  `subject_access_log::install` unconditionally, on the initial activation,
  a successor, a role change, and the rehearsal that computes a package's
  fingerprint. No statement in the product drops the table or the function.
  v0.38.0 introduced the storage, so only a database last applied by an
  earlier release lacks it.
- v0.40.0 does not serve or apply over a database an earlier release
  activated. It refuses a package under the retired package `apiVersion`
  (`PackageError::RetiredApiVersion`), startup refuses a database whose
  active package is not the one loaded (`StartupError::ActivePackageMismatch`),
  and a successor apply must bind the active package's digest. Every database
  v0.40.0 serves therefore took its initial activation from v0.40.0, which
  installed the storage and has journaled only the identifiers above.

### Enforcement and defaults

- `valid_revision_provenance` in
  `crates/registry-breg/src/postgres/revision_read.rs` accepts, for a create,
  patch, or tombstone revision, only `records.<entity>.<kind>` for the read
  entity and the stored mutation kind, or a request journal operation on a
  request lifecycle patch revision of an entity that declares change
  requests. Every other operation identifier is
  `ReadServiceError::Unavailable`: the detail read of that revision and any
  list page that includes it answer `503 source.unavailable`, and the problem
  names no stored value. An effect identifier is refused whether or not the
  active package declares it, the action that wrote the revision included.
- The revision reader no longer reads stored immediate-action results, so
  what the journal says about a revision's origin is decided from the journal
  row and the compiled entity alone.
- `ExpectedManagedCatalog::compiled` is the one catalog a compiled Registry
  admits. `verify_managed_catalog`, `runtime_grants_missing`, and
  `managed_schema_fingerprint` compare the database with it directly, and
  startup no longer selects a catalog from what the database holds. A
  database without the access-log table or its expiry function fails catalog
  verification with
  `PostgresKernelError::CatalogInvariant("managed object ownership differs
  from the closed catalog")`. Startup refuses it before binding a listener
  and writes nothing: `StartupError::RuntimeGrantsMissing` when a separate
  runtime role serves, because the runtime role's grants on the storage are
  missing with it, and `StartupError::DatabaseUnready` when one role serves.
- The catalog a database holding the storage is measured against is the one
  it was measured against before, so its recorded schema fingerprint does not
  move and no package needs rebuilding.
- The access-log retention worker starts for every verified database. It
  already did for every database holding the storage, whether or not the
  active package declares `accessLog`.

### Tests

`crates/registry-breg/tests/postgres_immediate_actions.rs`:
`action_written_revisions_are_readable_through_revision_history` is the named
negative for BREG-SEC-142. It reads the revisions an action writes through
the list and detail routes, then rewrites journal rows as the database
administrator and requires `503 source.unavailable` for a declared patch
effect identifier, the create effect identifier the writing action declares,
an undeclared effect, an effect declared against another entity, a declared
effect with another mutation kind, an action identifier, another entity's
record operation, and a request lifecycle revision journaled under an effect
identifier. It requires the same refusal from the list route, and a detail
read that succeeds again once the journal names the canonical identifier.

`crates/registry-breg/tests/postgres_migration.rs`:
`a_catalog_without_subject_access_log_storage_is_refused` drops the table and
function from an activated database and requires the catalog invariant
refusal for a package that declares no `accessLog` and for one that does,
then applies the active package again with separate roles and requires the
storage back under the same recorded fingerprint.
`subject_access_log_storage_survives_disabled_collection` holds that an
activation of a package declaring no `accessLog` installs the storage and
that disabling collection later keeps its rows and expiry authority.

`crates/registry-breg/tests/postgres_startup.rs`:
`startup_refuses_a_database_without_subject_access_log_storage_and_writes_nothing`
runs the real startup path against a database with the storage dropped,
first with separate roles and then with one role, and requires the two
refusals above with an unchanged managed-database snapshot.

### Accepted residuals

- A database that does hold a revision journaled under an effect identifier
  no longer reads it under any package: the record's affected history reads
  answer `503 source.unavailable` until the row is gone. No migration
  rewrites such rows, as none did before. Reaching that state takes a
  database v0.38.0 or earlier wrote, which v0.40.0 already refuses at the
  package level, or a write to the journal made outside the product.
- The tests reach the missing-storage state by dropping the storage from a
  database whose recorded fingerprint includes it. A database whose recorded
  fingerprint predates the storage cannot be built with current tooling, and
  the test hook that emulated one is removed with the tolerance, so its
  outcome is derived from the code and not executed: the same catalog
  refusal at startup, and, with separate roles, an apply of the active
  package that installs the storage and then fails the recorded-fingerprint
  comparison, which rolls the activation back and reports
  `MigrationError::ApplyFailed`.
- Applying the active package again reinstalls the storage only when it is an
  activation, which with unchanged roles means separate roles whose runtime
  grants are missing. With one role it answers
  `MigrationError::AlreadyActive` and repairs nothing. That holds for any
  managed object removed outside the product and is unchanged here.
- The index `registry_immediate_action_results_target_idx`, which served the
  removed lookup of a stored result by the revision it wrote, stays installed
  for every Registry that declares an immediate action. The schema
  fingerprint measures it, so removing it would move the fingerprint of every
  such package; no query reads it now.
- The package-level refusals rest on the manifest a supported tool wrote. A
  hand-edited manifest that presents an earlier release's database as a
  v0.40.0 one is outside the promise; such a database is still refused or
  read as unavailable by the checks above, never read under the removed
  tolerances.

## Development tokens for a client mapped to another resource

`bregctl dev` requests each local client token for the resource the session's
clients file assigns to that client. `token_async_with_claims` in
`crates/registry-bregctl/src/dev/mod.rs` reads the retained clients and asks
`config::client_resource` in `crates/registry-bregctl/src/dev/config.rs`
which RFC 8707 `resource` to send: the audience `issuer.clientResources` maps
the client to, or the session's own BReg audience (`State::audience`) for a
client with no entry. It previously sent the BReg audience for every client.
Startup (`tokens`), `bregctl dev token` (`fresh_token`), and the rehearsal
tokens that are not purpose exchanges all go through that function, so one
decision covers them.

### Threat

The change makes the audience of a development token depend on session
configuration, so the question is whether a caller can obtain a token for an
audience the session owner did not assign to that client: a client with no
mapping receiving a token for another product's resource, a mapped client
receiving a BReg token, or a token whose scopes the target resource does not
define. A token for the wrong audience is a credential another local runtime
would accept as its own.

### Enforcement and defaults

- `bregctl` enforces nothing about the issued token here. It only chooses
  which `resource` to put in the request, and the token's audience is decided
  by the issuer and checked by the runtime that receives the token.
- The choice has one implementation, `config::client_resource`, keyed by the
  exact client identifier. A client without an entry gets `State::audience`,
  never another client's resource. `dev export-client` and the local review
  and task-grant settings read the same function, so the resource a client is
  told to request and the one `bregctl` requests for it cannot differ.
- The mapping comes from state this `bregctl` wrote. A session reads its
  clients file through `config::clients`, which runs `validate`, and
  `initialize` writes the result to `.breg/dev/clients.json` in the
  owner-only session tree. `retained_clients` reads it back through
  `private::read` (owner only, a regular single-link file, opened without
  following a link, size bounded) and the closed `config::retained` reader.
  The command line names a client and never a resource: `fresh_token`
  refuses an identifier that is not a bounded local client ID and a client
  the retained file does not register, before it opens any credential path.
- `validate` in `config.rs` admits an `issuer.clientResources` entry only for
  a declared client, a declared `issuer.resources` audience, and client
  scopes that are all scopes of that resource, at most 32 entries. A session
  that borrows another session's issuer may declare none
  (`validate_borrowed_issuer_composition`), and `prepare` refuses to borrow a
  client the issuer owner maps to another resource.
- The issuer registration agrees with the request. `issuer_description`
  declares each `issuer.resources` audience as a resource server and points
  a mapped client's role permission at its mapped resource server in place
  of the BReg one.
- The receiving runtime is the check that matters. `runtime` in `config.rs`
  renders `authentication.oidc.audience` as `State::audience`, so the local
  registry is configured to accept that audience only, and a token requested
  for a mapped resource is not a registry credential.
- The request is signed with the named client's own `private_key_jwt`
  assertion key from `credentials/<client>/`, so the mapping changes which
  resource a client asks for and never which client asks. `PrivateKeyJwt` in
  `registry-platform-httputil` refuses a token response whose stated `scope`
  lacks a requested scope. The token is stored under the session's `secrets/`
  directory through `private::replace`, as before.

### Tests

`crates/registry-bregctl/src/dev/tests.rs`:
`dev_token_requests_the_clients_registered_external_resource` runs the real
token request against a local stand-in token endpoint and requires exactly
one `resource` form value, the mapped audience, with the mapped client's
identifier and scope.
`dev_token_for_an_unmapped_client_requests_the_breg_audience_only` is the
negative: in the same session, where another client is mapped, a client with
no entry sends exactly one `resource`, the session's BReg audience, which the
test requires to differ from the mapped one.

`borrowed_issuer_refuses_owner_only_declarations_before_preparation`, in the
same file and unchanged here, holds that a session borrowing an issuer cannot
declare `clientResources`.

### Accepted residuals

- The stand-in endpoint proves what `bregctl` sends, not what an issuer
  grants. What the pinned local issuer answers when a client requests a
  resource it holds no permission on is that issuer's behaviour, and no test
  in this repository pins it. `products/messaging/scripts/test-dev-shared-issuer.sh`
  starts an owner session whose clients are mapped to a Messaging resource
  against a real issuer and runs `bregctl dev token` for one of them. It
  requires the written header file and does not present that token to a
  runtime, it needs Docker, and it is not part of the database-free checks.
- No test pins the `validate` refusal of an `issuer.clientResources` entry
  that names an undeclared client, an undeclared audience, or a client whose
  scopes the resource does not define. The refusal is unchanged here.
- `config::retained` decodes the retained clients under the closed format and
  does not rerun `validate`. A retained file edited by the session owner after
  start can therefore map a client to a resource `validate` would have
  refused. The owner already holds every client key in the same tree, the
  issuer still decides what it issues, and the receiving runtime still checks
  the audience.
- A mapped client gets no client-credentials token for the BReg audience:
  `bregctl` requests one resource per client, never two.
- This is local development tooling. The token endpoint is the session's
  loopback issuer origin (`State::issuer_origin`), and these tokens are not
  deployment credentials.

## Entity source views without a security barrier

An entity source view, `registry_source.<entity>`, is created
`WITH (security_invoker=true)` and no longer with `security_barrier=true`
(`generate_ddl_with_actions` in `crates/registry-breg/src/generated_ddl.rs`).
Derived views and the spatial candidate view keep their barrier, and no
policy, grant, or role changes. The same change appends the record id to
every authored index and lets a list continuation over a required stored
field use one row comparison, so a filtered, sorted list page is served from
an index instead of reading and ordering every row the caller may read. The
barrier is what kept the planner from reaching those indexes: it holds a
barrier view as a separate subquery and pushes no ordering or limit through
it.

### Threat

A barrier view promises one thing: no predicate from outside the view that
is not leakproof runs against a row before the view's own condition has
accepted it. The source view's own condition is `record_lifecycle =
'active'`. Without the barrier the planner may evaluate a cheaper outside
predicate first, so the question is whether any row a caller may not read
can now reach such a predicate.

It cannot, because the rows a caller may read were never bounded by the view.
The view runs with `security_invoker`, every entity table has forced
row-level security, and PostgreSQL applies the policies of a table as
security conditions of that table: they run before every predicate that is
not leakproof, whether or not a view above the table is a barrier. Every
read policy carries `record_lifecycle = 'active'` itself, so a tombstoned row
is refused by the policy before any outside predicate sees it.

One read policy admits a row the view's condition refuses. The get policy of
a change-request entity (`request_get_lifecycle_expression`) also admits a
tombstoned request whose state is `cancelled` or `applied` and whose detail
is erased, so its owner or reviewer can still read that it ended. Such a row
may now reach an outside predicate before the view's lifecycle condition
drops it. The caller is one the same policy already lets get that request,
and the row's detail is erased, so no value reaches a predicate that the
caller could not already read.

### Enforcement and defaults

- Row-level security policies on `registry_data` tables stay the single
  read boundary. They are unchanged, and `FORCE ROW LEVEL SECURITY` stays on
  every entity table.
- The source view keeps `security_invoker=true`, so the policies evaluated
  are the runtime role's under the caller's claim context, never the view
  owner's.
- The view option is part of the managed schema fingerprint. A database
  whose source view regains `security_barrier`, or loses `security_invoker`,
  is drift and the runtime refuses to start against it.
- `CREATE OR REPLACE VIEW ... WITH (security_invoker=true)` over a view that
  held both options leaves `security_invoker=true` alone, as verified on
  PostgreSQL 17.5, so a replaced source view matches a fresh one and the DDL
  carries no explicit `security_barrier=false`.
- The runtime sends only SQL the engine generates. A list filter compares a
  column with a bound parameter through built-in operators, and reviewed
  derived SQL is held to the allowlist of BREG-SEC-143. The barrier was
  defense in depth against a predicate the engine does not emit.
- A current list uses the row comparison `(sort, id) > (...)` only for a
  required stored field read through the source view, where a served
  database holds no NULL (`FieldExpression::never_null` in
  `crates/registry-breg/src/postgres/read.rs`). Every other sort, and every
  history list, keeps the form that admits NULLS LAST. The cursor, its
  binding, and the page order are unchanged.

### Tests

`a_source_view_never_shows_a_predicate_a_record_that_row_security_hides` in
`crates/registry-breg/tests/postgres_compiled_schema.rs` is the executed
proof. On the compiled schema it asserts the source view carries only
`security_invoker=true` and that the plan of a read through it has no
subquery scan, so the view is flattened. It then reads the view as a
tenant-a caller through a predicate function that is not leakproof, costs
almost nothing so the planner would run it first if it could, and raises
when it is shown a named record. With a tenant-b record and a tombstoned
tenant-a record named, the read returns the one visible record and nothing
is raised: neither hidden row reached the predicate. With the visible record
named, the same read raises, which shows the probe does fire on a row that
passes the policy.

`package_fingerprint_starts_refuses_drift_and_upgrades_without_rewriting_package_bytes`
in `crates/registry-breg/tests/postgres_package/fingerprint.rs` sets
`security_barrier = true` on a source view, sees startup refused, resets it,
and sees startup allowed again, next to the existing `security_invoker`
pair.

`crates/registry-breg/tests/postgres_list_page_plans.rs` holds the plan
shape the change exists for: a filtered page sorted by a near-unique field,
by a low-cardinality field, and in record id order, each on its first page
and on a deep continuation, reads a bounded number of rows from its
declared index and has no sort node. The existing keyset, NULLS LAST,
tie-break, row-level security, and path-visibility suites pass unchanged.

### Accepted residuals

- A tombstoned, detail-erased change request may reach an outside predicate
  before the view's lifecycle condition, for a caller the get policy already
  lets read it. The row is still absent from every result, because the
  view's condition still applies.
- The order in which PostgreSQL evaluates policy conditions before other
  predicates is PostgreSQL behaviour the engine relies on and does not
  enforce itself. The executed proof would fail on a server that broke it.
- A read policy written to admit more than
  `record_lifecycle = 'active'` would widen what can reach a predicate. Any
  change that adds such a read policy must revisit this note.
- No security invariant row changes. No row names the barrier, and the
  read boundary rows already rest on row-level security.

## Compiler-owned DDL refreshed over a predecessor another compiler built

A successor plan compares what this compiler generates for the baseline
model with what it generates for the candidate. That comparison describes
the installed schema only when this compiler also generated the baseline
package's script. A package another compiler built, such as a v0.41.0
package under a compiler that appends the record id to authored indexes and
creates source views without a barrier, holds other DDL for the same model,
and a plan that ignored it would leave the database short of the candidate
schema.

The plan baseline therefore states the digest of the script its package
carries, `migrationPlan.priorBaseline.generatedDdlSha256`
(`CompiledRegistryMigrationBaseline` in `crates/registry-breg/src/package.rs`).
`load_predecessor_closure` reads it from the predecessor manifest's file
entry for `database/ddl.sql`, after the closure read has held the packaged
script to that digest; `from_compiled` computes it from the generated
script. `additive_migration_plan` compares it with the digest of the script
this compiler generates for the baseline model. When the two differ, or the
baseline states none, the plan also replaces the source view of every
retained entity and drops and recreates every retained authored index whose
statement the change leaves alone. When they are equal the plan carries
nothing extra. A reviewed successor is planned through the same function, so
it carries the same statements.

### Threat

Two things could go wrong. A refresh that is skipped when it is owed leaves
an upgraded database with source views that still hold the barrier and
indexes without the record id: a schema the candidate does not describe. A
refresh that is planned could become a way to run DDL nobody generated, or
to leave a source view with weaker options than a fresh install gives it.

Neither weakens what a caller may read. Row-level security on the entity
tables is the read boundary, as the note on source views without a security
barrier sets out, and the refresh changes no policy, no role, and no
`FORCE ROW LEVEL SECURITY` setting; a replaced view keeps the grants the
package gives it. The refresh statements are the
candidate's own generated `CREATE OR REPLACE VIEW` and `CREATE INDEX`
statements plus `DROP INDEX IF EXISTS` on a physical name taken from the
baseline's recorded names and quoted as an identifier; no authored or
caller-supplied SQL enters them. A replaced source view ends with exactly
`security_invoker=true`, the options a fresh install gives it.

A skipped refresh fails closed. Activation makes a package ready only after
the managed schema fingerprint of the database equals the candidate's
(`activate_verified_package` in
`crates/registry-breg/src/postgres/interlock.rs`), and startup verifies the
same fingerprint, so a database left on the earlier views or indexes is
refused and never served.

### Enforcement and defaults

- The digest is optional and its absence selects the refresh, so a baseline
  that says nothing about its script is treated as built by another
  compiler. A predecessor manifest with no generated DDL entry yields none.
- A stated digest must be `sha256:` followed by 64 lowercase hex digits;
  `validate_migration_baseline` refuses any other shape with the migration
  plan error.
- The digest is part of the plan baseline in the signed manifest, and
  `expected_migration_plan` rederives the whole plan from that baseline and
  the compiled candidate when a package is loaded. A packaged plan that
  carries more, fewer, or other statements than the rederived one is
  refused, so the refresh cannot be added to or removed from a package
  without changing the baseline it is derived from.
- A baseline that states this compiler's digest for a script another
  compiler installed plans no refresh. The result is the skipped refresh of
  the threat: activation refuses on the fingerprint and the target stays
  pinned. It is never a served database with a mixed schema.
- Reference indexes carry no compiler-owned key column and are never
  rebuilt. An authored index whose declared fields or columns change is left
  to the reviewed change that moves them.
- The statements run under the migration role inside the apply interlock,
  with the configured migration lock and statement timeouts, like every
  other compiler statement. A compiler-applied successor runs them in one
  transaction and a failure rolls all of them back.

### Tests

`crates/registry-breg/tests/postgres_package/compiler_upgrade.rs` is the
executed proof on PostgreSQL. Its fixture activates a package, rewinds the
authored index and both source views to the shape an earlier compiler
generated, and rewrites the packaged script and fingerprint to match, so the
package no longer derives under this compiler.
`an_unchanged_successor_over_an_earlier_compilers_package_refreshes_compiler_owned_ddl_once`
asserts the exact four refresh statements, that the applied database has the
fingerprint of a fresh install, that the index ends with the record id, that
each source view holds exactly `security_invoker=true`, and that startup
succeeds; it then plans a second unchanged successor with no statement and a
model change that leaves the index in place.
`a_model_change_over_an_earlier_compilers_package_carries_the_refresh_too`
and
`a_reviewed_change_over_an_earlier_compilers_package_carries_the_refresh_too`
hold the same end state for a compiler-applied and a reviewed change.

`crates/registry-breg/tests/package_change_plan.rs` holds the plan without a
database: a baseline with no digest and one with another digest both carry
the refresh, a baseline with this compiler's digest plans nothing, a baseline
without the key loads and serializes without it, a loaded predecessor states
the digest of its packaged script, and
`malformed_generated_ddl_digest_in_a_baseline_is_refused` holds the shape.
`a_baseline_activated_without_reference_indexes_gains_them_additively` in
`crates/registry-breg/tests/reference_indexes.rs` shows reference indexes
are added and never rebuilt by the refresh.

`release/scripts/rehearse-upgrade.py --product breg` runs the released
v0.41.0 binaries, then this workspace's, over one database and requires the
state to be served with no row lost.

### Accepted residuals

- The first successor over a package another compiler built rebuilds every
  authored index of every retained entity, whether or not that compiler's
  index differed. The digest says the scripts differ, not where.
- The refresh covers source views and authored indexes, the compiler-owned
  DDL that differs from v0.41.0. A later compiler change to another kind of
  generated statement must extend it, or the fingerprint check refuses the
  activation.
- Dropping an authored index takes an exclusive lock on its entity table
  until the apply transaction ends, and each rebuild reads the table once.
  The registry is in maintenance for that time.
- No security invariant row changes.

## Review policy selection at first acceptance

An ID-only Review policy selector delegates concrete version and digest choice
to the configured trusted provider at first durable acceptance. BReg freezes
the selector in the Proposal submission and stores the concrete accepted
binding separately. Supplying both `version` and `digest` instead requires that
exact policy before acceptance; partial pins are invalid.

The threat is substitution of a different policy identity or exact pin before
acceptance, or substitution of a different request, policy, subject, submission,
or result after acceptance. `PolicySelection::matches` in
`crates/registry-review-protocol/src/lib.rs` defines selection.
`check_accepted` in `crates/registry-review-client/src/client.rs` checks the
provider response against that selector, subject, and submission digest before
returning it to `run_one_submission` in
`crates/registry-breg/src/review_store.rs`. A mismatched response is a protocol
failure: BReg records `remote-uncertain` without retaining an accepted binding
or approval. The worker's additional `review-policy-changed` check is defensive;
the canonical client rejects these mismatches before that branch can run.

Once accepted, the worker refuses a replacement as
`review-acceptance-changed`, including after operator resubmit. Feed
reconciliation requires the same exact accepted binding, and
`crates/registry-breg/src/review_integration.rs` independently checks exact
result correlation before application. A review decision never grants source
write authority or bypasses current commit conditions.

### Tests

`first_acceptance_refuses_wrong_policy_id_or_exact_pin` in
`crates/registry-breg/tests/postgres_proposal_review_delivery.rs` uses the
existing HTTP provider and real PostgreSQL fixture to return an otherwise
correlated acceptance with the wrong ID, pinned version, or pinned digest.
Each is refused without a retained binding, result, or Record mutation. Its
permitted case accepts a newer version and digest for the same ID and retains
that exact binding without rewriting the frozen selector.
`current_policy_delivery_recovers_original_request_without_rewriting_frozen_identity`
holds lost-response recovery to the original request and idempotency key.
`operator_resubmit_preserves_acceptance_and_refuses_replacement_after_provider_loss`
holds operator recovery to the original acceptance and refuses changed policy
or request bindings. `result_correlation_requires_every_frozen_binding` in
`review_integration.rs` retains the exact-result negative cases.
These selection and correlation guarantees are recorded by BREG-SEC-34.

### Accepted residuals and operator choice

The trusted provider may change its policy while first acceptance is pending,
including switching between human review and automatic assessment. The
submission recovery window defaults to 30 days; operator resubmit restarts it
but preserves any existing acceptance. A new submission after
changes-requested selects the provider's current policy again unless pinned.
Use a complete exact pin when the version chosen at submission must be the
version that decides. ID-only selection intentionally trusts provider policy
administration until first acceptance, then preserves exact correlation.

## The task-grant status resource is named for what it binds

A `taskGrantStatus` entry names the audience its status credential is
requested for `statusResource` (was `caseworkResource`), because Coordinator
or an external task authority can answer grant status as well as Casework.
This is authorization configuration: the key selects the resource the
runtime's own status credential is issued for. The rename changes no
behavior. The value is read, validated as an absolute resource URI, and sent
exactly as before, and the old key is refused with `config.removed-key`
naming `statusResource` rather than read as an alias, so a file cannot carry
both spellings with different values. Tests:
`a_task_status_casework_resource_is_refused_naming_status_resource`, plus the
existing structural refusal tests that now use `statusResource`.

## Review state, decision and rejection on ordinary Proposal reads

A Proposal Get holder sees the review state, `resultId`, `completedAt` and
`availableUntil` of every retained submission version, the current one
included, through `GET /v1/proposals/{id}/submissions/{version}`, and the
current version's `decision` on the Proposal Get and in the list. Before the
per-version read, review state sat only behind the separately grantable
`get-review-status` operation. A deployment can no longer withhold it from a
Get holder: the grant to read the Proposal is the grant to read how its
Review went. This is a deliberate widening, recorded once for both reads by
BREG-SEC-177, and BREG-SEC-173 now names the summary as the part of review
data ordinary envelopes carry. `get-review-status` keeps the rest: the review
authority, the accepted policy binding, the subject binding and the context
reference.

`decision` is `{status, decidedAt, publicReason}`. It is read from the stored
result through the review protocol's own `ReviewResult` type, so a protocol
rename is a compile error rather than a silent omission. `publicReason` is the
text the protocol releases to the subject's owner and the only reviewer text
BReg serves. The reviewer's private `result`, notes, internal reason and
identity are never projected, and a stored result that does not decode as a
`ReviewResult` fails the read as unavailable rather than serving a partial
decision. A provider end (`cancelled`, `superseded`) and a result whose
content retention erased carry no decision. Lifecycle command responses omit
it. A read that serves a public reason records the fixed
`proposal-review-public-reason` marker in its audit entry's field-set
reference, never the text. The 410 `proposal.submission_expired` answer
audits a result count of zero.

A rejection of the current submission is terminal (BREG-SEC-178). The
`reject` transition has no caller operation: it runs only when BReg records a
verified review result for the exact current, not withdrawn submission, in
the transaction that records the result and under the Proposal state lock,
with a `rejected` lifecycle event whose `authorityKind` is `review`. A result
for a superseded version changes no lifecycle state. Every transition out of
`rejected` is refused with `proposal.rejected`, so rejected work can be
neither revised into approval nor applied. A changes-requested result keeps
the Proposal `submitted`, records `review-returned`, and grants nothing: the
revised version needs its own Review.

`turn` is derived from state that the same read already discloses and
carries no new data. The `turn` list filter runs after each Proposal is
authorized and projected, so it conceals exactly what the list already
conceals.

### Tests

`submission_read_reports_each_version_separately_and_is_gone_after_its_windows`
in `crates/registry-breg/tests/postgres_proposal.rs` asserts the exact
`decision`, that a reviewer-only canary in the private result never reaches
the response, the public-reason marker, that the public reason's text never
reaches the audit journal, and the zero result count of the 410 read.
`review_rejection_is_terminal_and_changes_requested_returns_to_the_party`
asserts the `rejected` state and event, the `review-returned` event, the
`turn` on the document, the event and the list filter, that the client offers
no Revise of a rejected Proposal, and that the server answers the exact inert
Revise link with 409 `proposal.rejected`. The workflow unit test in
`crates/registry-breg/src/proposal_workflow.rs` refuses Edit, Revise, Rebase,
Retry, Cancel and a second rejection from `rejected`.

### Accepted residuals

The public reason is whatever the reviewer wrote for the subject. BReg bounds
its length through the protocol type but cannot judge its content; a
reviewer who writes personal data there discloses it to every Get holder.

## Application actor disclosure is a separate Proposal grant

Proposal Get and the per-version submission read may now serve the stored
keyed actor pseudonym as `appliedBy` and the receipt time as `appliedAt`, but
only when the selected Proposal grant holds both `get` and the supplemental
`get-application-actor` operation. `application_actor_disclosed` in
`crates/registry-breg/src/mutation/proposal.rs` is the release point. It
requires the actual read authority to be Get and checks the selected compiled
profile for the supplemental operation. When a task grant supplies the Get
authority, it must also carry `get-application-actor` for the exact Proposal;
the selected profile alone cannot widen that delegated bound. List uses List
authority, so it omits both values even when the profile holds the supplemental
operation. Lifecycle responses also omit them. The server schema and client
require the pair to appear together and validate the pseudonym as the stored
`hmac-sha256:` prefix plus 64 lowercase hexadecimal characters and the time as
RFC 3339.

No new data is stored. The projection uses the existing `applied_by` and
`applied_at` receipt columns and never serves the raw issuer or subject. The
`breg-proposal-actor-v1` derivation remains keyed and scoped to the database
and verified caller issuer. A holder can link Proposals applied by the same
actor within that database and issuer. A holder who knows the applier of one
Proposal from another source can associate that actor with other matching
pseudonyms. A holder of the audit hash key can also recompute the value for a
known issuer and subject. The value is pseudonymous, not anonymous.

`application_actor_requires_its_dedicated_get_grant_and_is_issuer_scoped` in
`crates/registry-breg/tests/postgres_proposal.rs` proves that authorized Get
and per-version reads match the stored receipt, ungranted reads omit both
members, List omits both for granted and ungranted profiles, and the same
subject applied under another issuer produces a different pseudonym. This is
recorded by BREG-SEC-179.
`task_grant_get_requires_the_exact_application_actor_bound` in
`crates/registry-breg/tests/postgres_proposal_security.rs` proves that a task
grant with Get authority cannot borrow the supplemental operation from its
selected profile or from a bound for another Proposal.

## Audit activation identity and sibling payload expiry

Two audit-integrity changes ship together. First (#1693), every request,
operator, access-log and webhook audit record that carried the activation UUID
under `packageRevision` now names it `activationId`, and `packageRevision` is
reserved for `sha256:` package digests. The affected schemas advance as listed
in [audit identity](contracts/audit-identity.md); historical versions keep
their historical reading, so a reader branches on the schema. Import authority
records add `authorityActivationId`, the activation that opened the authority,
beside the current `activationId`. The `unfinished` response copies only fields
an attempt record carries, so it preserves the attempt's `activationId` and
never invents a `packageRevision`.

Second (#1800), webhook payload expiry no longer requires the shared payload to
be present. Every pending or dead-lettered delivery whose payload horizon has
passed is expired on its own: a pending delivery becomes `expired`, a
dead-lettered one keeps its state, and each gains `expired_at` and exactly one
`payload-expired` terminal audit entry, even when a sibling or a product
erasure already removed the payload. Before the change a sibling over an
already-erased payload was never expired, so the journal held no expiry
entry for it. Claiming still requires a present, unexpired
payload, so expiry sends nothing.

### Threat

1. An auditor or downstream reader takes an activation UUID for a package
   digest, or the reverse, and attributes an operation to the wrong package.
2. A delivery whose payload was erased under it is left without an expiry
   record, so the journal cannot show that the delivery ended, and retention
   cannot distinguish it from live work.

### What is preserved

Audit and replay retention are unchanged: no audit entry is removed or
rewritten, and replay still refuses erased or expired work. Reference-hash
domain strings, context inputs and their values are unchanged, including
Review recovery and import authority operator and reason references, so
existing correlations still match. No migration, credential or grant changes.

### Tests

The PostgreSQL harness checks every captured audit entry against
`crates/registry-breg/tests/fixtures/audit-identity-goldens.json` and the
identity value types (`assert_audit_identity_goldens` in
`crates/registry-breg/tests/support/postgres_harness.rs`), across every
journey that reads the audit journal. The Evidence-retention tests in
`crates/registry-breg/tests/postgres_action_evidence_retention.rs` refuse an
activation under `packageRevision`;
`a_successor_package_supersedes_an_open_authority` in
`crates/registry-breg/tests/postgres_import_authority.rs` pins both the
current and the original activation; and the operator retention journeys in
`crates/registry-breg/tests/postgres_native_retention.rs` check operator audit
identity. `real_postgres_webhook_delivery_retry_dead_letter_replay_is_package_bound_audited_and_confined`
in `crates/registry-breg/tests/postgres_webhook_delivery.rs` expires a pending
sibling after the shared payload is erased, and a dead-lettered sibling whose
payload was erased before expiry; each gains `expired_at` and one
`payload-expired` entry, and the receiver sees no request.

### Accepted residuals

A consumer that parsed the old schemas by field name must branch on the
schema version; there is no alias. Expiry of a dead-lettered delivery keeps
its `dead-lettered` state, so an operator distinguishes an expired dead letter
by `expired_at` and the audit entry, not by state.

## Deployment identity of a production package

`bregctl init --from` writes `canonicalBaseIri` as
`https://{id}.example.invalid`, so local development and schema tests run
before an adopter has chosen a hostname. `compiled_resource_iri` in
`crates/registry-breg/src/compiler.rs` derives default catalogue and Registry
Manifest resource IRIs from that base. A package that keeps the placeholder can
therefore publish derived catalogue identifiers in a namespace nobody controls,
and every registry initialized with the same project id derives the same ones.
Explicit resource IRIs remain unchanged.

### Threat

An initialized package reaches a production database unchanged. Its Registry
Manifest and catalogue projection can then carry default-derived identifiers
that resolve nowhere and that another registry with the same project id also
derives, and a relying party may store them before anyone notices. Replacing
the base afterwards changes those derived identifiers; explicit resource IRIs
stay unchanged. No read or write authority changes: the check governs which
identity a production package may carry, not who may use it.

### Enforcement and defaults

- `deployment_diagnostics` in `crates/registry-breg/src/compiler.rs` refuses a
  `canonicalBaseIri` whose host is `invalid` or ends in `.invalid` as
  `breg.registry.canonical-base-iri-reserved`. It is not part of
  `compile_project`, so `check`, `schema-test`, and `dev` accept the
  initialized identity.
- `bregctl package` applies it before it reads the test receipt
  (`refuse_deployment_identity` in `crates/registry-bregctl/src/lib.rs`), and
  `bregctl check --production` reports it. The local-development package
  `bregctl dev` builds does not apply it.
- `validate_deployment_identity` in `crates/registry-breg/src/package.rs`
  applies it again inside `load_package_with_verified_envelope` whenever the
  database initialization environment is not `local`, so `breg`, `bregctl
  apply`, and `doctor` refuse a package that did not pass through `bregctl
  package`, such as a local-development one, with
  `PackageError::DeploymentIdentity`. `DeploymentIdentity::from_raw` in
  `crates/registry-breg/src/runtime_config.rs` refuses a runtime configuration
  whose environment differs from its database initialization environment, so
  a production deployment cannot load under the `local` policy by naming it
  for one key only.
- A predecessor load does not apply it. Successor planning reads the active
  package through `load_active_predecessor_package`, so a production database
  whose active package carries a reserved identity remains inspectable while
  an operator prepares a successor that names a hostname the adopter controls.
  The focused tests below prove predecessor readability and separate valid
  candidate admission; they do not execute a complete successor plan and apply
  journey.

### Tests

`a_local_placeholder_package_cannot_load_for_a_production_database` in
`crates/registry-breg/tests/postgres_package.rs` loads one package carrying a
reserved identity for a `local` database, refuses it for a `production` one
with `PackageError::DeploymentIdentity`, and reads it as a production
predecessor. The test separately builds and loads a valid production candidate.
`dev_packages_the_placeholder_iri_in_process_and_retains_a_refusal` in
`crates/registry-bregctl/src/dev/tests.rs` shows a deployment package refuses
the reserved identity before reading the receipt while the local-development
package accepts it. `only_a_deployment_capture_refuses_the_reserved_placeholder_iri`
in `crates/registry-bregctl/src/lib.rs` holds the same split at capture, and
`a_refused_active_package_names_package_root_apart_from_the_target` there pins
`apply.package.deployment-identity-refused` and its remedy.

### Accepted residuals

- The check is a guard against an accident, not against an operator who means
  to bypass it: a database initialized for `local` accepts the reserved
  identity, as `bregctl dev` requires.
- Only the reserved `.invalid` namespace is refused. A hostname the adopter
  does not control but that is not reserved, such as `example.com`, passes.
- No security invariant row changes.

## OIDC issuer transport and private addresses

`breg` and `breg-review` fetch the operator-declared issuer's discovery
document and keys through the shared `IssuerNetworkPolicy` in
`crates/registry-platform-oidc/src/lib.rs`, instead of the strict
public-network policy. An issuer inside a container network or a private
subnet now starts, and a plain HTTP issuer beyond loopback is accepted under
an explicit opt-in.

### Threat

- A fetch policy that follows any address lets an issuer or JWKS URI reach an
  internal service the operator never meant to trust, including cloud
  metadata.
- Keys fetched over plain HTTP can be replaced by anyone on the path, who can
  then sign tokens `breg` accepts.

### Enforcement and defaults

- The declared issuer, and a JWKS URI declared in `jwksSource`, may resolve to
  a private or loopback address on any origin: they are configuration the
  operator wrote. A JWKS URI returned by discovery inherits that allowance only
  on the issuer's own origin; a discovered cross-origin endpoint stays under
  the strict policy and must use HTTPS. Cloud metadata and link-local
  addresses are refused for declared and discovered endpoints alike, and
  redirects stay disabled.
- Plain HTTP stays limited to loopback unless the runtime sets
  `authentication.oidc.allowInsecureHttp: true`, which defaults to `false`.
  `OidcIssuerConfig::check` in `crates/registry-platform-config/src/blocks.rs`
  refuses a non-loopback HTTP issuer or declared JWKS URI without it. At
  startup `IssuerNetworkPolicy::new` refuses such an issuer again, and the
  declared-key fetch policy refuses such a key URI. While the setting is on,
  `OidcVerifierConfig::key_source` in `crates/registry-breg/src/runtime_config.rs`
  logs a fixed startup warning, and `bregctl doctor` reports the
  `authentication.insecure-http` advisory from the same loaded file it
  checks.
- `breg-review` takes the private-address allowance but never the HTTP
  opt-in: it sends its client credentials to the token endpoint, so
  `signIn.allowInsecureHttp` is refused as an unknown key and a non-loopback
  HTTP issuer is refused with `breg.review-runtime.plain-http-endpoint`.

### Tests

`runtime_reads_the_explicit_http_issuer_opt_in` and
`non_loopback_http_issuer_refusal_names_the_opt_in` in
`crates/registry-breg/tests/runtime_config.rs` pin the opt-in, its startup
diagnostic, and the value-free refusal without it. In
`crates/registry-platform-oidc/src/lib.rs`,
`non_loopback_http_requires_the_named_opt_in_while_loopback_does_not`,
`a_cross_origin_jwks_must_use_https_even_under_the_http_opt_in`,
`cloud_metadata_is_refused_for_declared_and_discovered_key_endpoints`, and
`discovered_cross_origin_private_or_loopback_jwks_stays_refused` pin the
network rules, and `issuer_and_jwks_uri_are_checked_urls_when_read` in
`crates/registry-platform-config/src/blocks_tests.rs` pins the configuration
check.

### Accepted residuals

- Under `allowInsecureHttp: true`, an on-path attacker can substitute keys.
  The setting is the operator's explicit acceptance of that risk, and the
  startup warning and doctor advisory keep it visible.
- A declared issuer or JWKS URI can name any private address that is not
  cloud metadata or link-local. The operator who writes the runtime file is
  trusted to name the issuer.
- No security invariant row changes.

## Review identity and activation cancellation

Successful Review handoff metadata names the admitted producer explicitly. The
client bounds and validates it, preserves exact subject, policy and digest
checks, and never treats an identity mismatch as proof of rollback. BReg records
a distinct configuration failure and logs only the two bounded IDs. The real
BReg/Casework pairing regression and shared-client HTTP tests cover mismatch,
legacy absence, malformed metadata and uncertain effects. An explicit mismatch
is diagnosed only after the response digest matches the complete original
request and its subject source under the producer named by the provider.
Arbitrary, stale-request and wrong-namespace digests remain ambiguous protocol
failures rather than configuration diagnoses.

Activation withdraws blocked submitted rounds and closes application jobs in its
existing transaction. Submission leases fence an in-flight response; recovery
uses the original idempotency key solely to obtain and cancel the accepted
review. Result reconciliation retains exact historical evidence while refusing
to advance withdrawn or blocked work. Recovery keeps its existing audited
migration authority and reports the package-change reason only while the exact
Proposal is still submitted. Cancellation retains the existing withdrawn or
terminal refusal, even when the old block reason remains. Exact rollback can
clear the package block but cannot reopen a withdrawn round or closed job.
The go-live tests cover rollback with and without a prior job, late results,
producer cancellation, already failed rounds, lease fencing and the private
aggregate metric. Activation uses a fixed number of set-based updates per
Action, sharing ordinary lifecycle cancellation predicates. A PostgreSQL
statement-count regression checks mixed round states, older unfinished jobs,
lease fencing and rollback through a test-only bookkeeping entry point;
native activation journeys separately cover the closed-catalog boundary.
Authorized Get preserves the blocked projection of a cancelled automatic job
while the Proposal remains submitted, including after rollback. Native
activation/Get/Cancel and automatic Rebase tests preserve exact application bindings, non-owner and
current row-boundary refusal, and the closed job's lack of automatic retry.
The no-job path also requires the exact retained binding before exposing a
withdrawn round whose approval arrived late. Withdrawal takes precedence over
result status for current turn and Apply availability. Real-router Get, List,
turn filtering, Cancel and Rebase/Submit regressions cover automatic and manual
rounds after activation and exact rollback, including an AlreadyTerminal cancel
response. They retain wrong-owner, current-disclosure, malformed-binding and
non-withdrawn approved/no-job refusals, and prove no old job is created. SEC-181
keeps its shape-substitution proof; SEC-185 selects withdrawal and non-revival.

Casework's existing producer cancellation settles concealed tasks and clocks
without source reads. Its HTTP proof also refuses another producer and retains
reviewer and supervisor concealment. Remote cancellation is asynchronous, so
in-flight work and dependency outages are settled through retained exact
recovery; the change does not claim a cross-service atomic transaction.

## Hook adapter and executor in the platform crate

The hook delivery adapter and the local handler executor move from
`webhook.rs` and `hook_handler.rs` into `registry-platform-hooks`; BReg keeps
`apply_proposal`, the proposal completion barrier, its triggers and
projections, and its identity preflight in `crates/registry-breg/src/hooks.rs`.

**What changes for authority.** Nothing. The signing URL destination, the
pooled connection, the audit mapping, and the retry schedule are the same
code with the product prefix as a parameter. A local program still runs only
when its delivery id, package revision, handler kind, and handler digest
match the compiled package, and its message is still applied through
`apply_proposal` under BReg's own authorization and audit.

**Hook Rhai engine.** Hook programs now run on the bare
`registry-platform-script` engine, without the action planner helpers. Rhai
resolves functions when a call runs, so a package whose hook program calls
`join` still compiles and activates, and the call fails at execution as an
execution failure (dead-letter reason `handler-execution`), which
dead-letters every delivery of that hook; it does not reach a different
helper. No admission-time walk of called functions is added; the BReg
changelog tells operators to look for `handler-execution` dead letters after
upgrading. Action handlers keep the
planner engine. `a_hook_program_calling_a_planner_helper_fails_on_the_bare_engine`
in `crates/registry-breg/src/tests/hooks_tests.rs` pins this.

**WASM hook runtime.** Hook modules run on a hook-owned WASM runtime with its
own fuel, epoch ticker, and prepared-module cache, so a hook module and an
action module no longer share cache slots or eviction.

**Identity preflight.** BReg's preflight still reads
`registry_internal.registry_state` under a shared transaction advisory lock
and compares package id, database id, active package digest, activation id,
and schema fingerprint. It does not use the platform's activation-record
preflight: BReg's activation takes the same advisory lock exclusively, so a
delivery transaction and an activation are serialized rather than compared
against a snapshot, and the readiness and schema fingerprint checks have no
counterpart in the activation record. Moving BReg onto the shared preflight
is left to a separate change.

**Audit.** Hook delivery entries move to `breg-hook-audit/v1` with
`"event": "breg.hook-delivery"` and reference domains `breg-hook-event-v1` and
`breg-hook-delivery-v1`; the redaction and the field set are unchanged.
`contracts/audit-identity.md` and the audit identity goldens record the
change.

**Configuration.** `eventDestinations` moves to `destinations.hooks` and the
old key is refused with `config.removed-key`. The destination binding digest
keeps its internal `eventDestinations` member name, so retained deliveries
captured before the upgrade verify against the same digest.

## Proposal input write grants

A Proposal grant may name `writableInputs`. Without the field every declared
Action input stays writable, as before, and the compiled grant omits the field.

### Threat

- An applicant who may edit a draft overwrites a value another role recorded,
  such as a licence number an officer added, and submits it for review.
- A caller who must restate fixed inputs on Edit probes the equality check to
  learn a fixed value the grant cannot read.

### Enforcement and defaults

- The compiler refuses a list that names an undeclared input, a grant with
  neither Start nor Edit, Revise or Rebase authority, a review-status grant
  that carries the list, and a grant with Edit, Revise or Rebase that leaves a
  fixed input outside `readableInputs`
  (`breg.proposal.input-grant-invalid` and
  `breg.proposal.review-status-authority-invalid`).
- Start refuses a value for a fixed input. Edit, Revise and Rebase compare each
  fixed input with the draft or submitted version input inside the mutation
  transaction, preserving the distinction between an absent input and explicit
  `null` in the handler ABI. The refusal is
  `400 request.invalid` at `/input/<apiName>`, rolls back, and is audited by
  the existing Proposal refusal path without the value.
- The idempotency binding adds the list to the response contract only when it
  is declared, so existing request digests do not change.

### Tests

`writable_inputs_bound_start_edit_revise_and_rebase_to_the_named_inputs` in
`crates/registry-breg/tests/postgres_proposal.rs` covers Start, changed and
dropped Edit values, an unchanged restatement, Revise, Rebase, a grant without
the list, the unchanged draft and the value-free audit.
`proposal_writable_inputs_refuse_invalid_grants` and its neighbours in
`crates/registry-breg/src/package/tests/immediate_actions.rs` cover the compile
rules, and `fixed_inputs_distinguish_absent_and_null_and_name_the_api_name`
in `crates/registry-breg/src/mutation/proposal.rs` covers the comparison.

### Accepted residuals

- The refusal names the first fixed input's API name. The caller can already
  read that input and its name is in the Action contract.
- Proposal Get does not list `writableInputs`: the Rust and Node clients
  decode the Proposal document strictly. Explain output shows the compiled
  grant.
- Attachments keep their separate `writableAttachments` grant.
## Proposal draft inputs, manual queues, and guard copy keys

Draft completeness is independent of mutation authority. Start, Edit, Revise,
and Rebase validate every supplied input against its type, nullability, and
write grant; Submit checks required presence before evaluating the plan.
Immediate Invoke retains its required-input boundary. Fixed mappings remain
non-null when present. An excluded optional input preserves both its presence
and its value, including the handler ABI's distinction between absent and null.

The pending manual application predicate uses only the current retained local
submission and Review result. A required approval must be unexpired and its
submission must not be withdrawn. Collection authorization, ownership, target
boundaries, and per-document disclosure still gate each projection. For
caller-owned collections, the candidate query enforces the principal's owner
reference before the scan bound and any per-candidate read, so another holder's
rows cannot consume the request deadline or become cursors. Private candidate
scans share the request deadline; a successful continuation names
only an authorized Proposal, and timeout returns failure without a partial
page. Listing makes no per-Proposal Review request.

An authored field-guard `reason` is a bounded copy key. `guardReason` is
released only after all guard and row-boundary facts for the selected target
are readable. Commit-time guard enforcement remains transactional; a failed
attempt rolls back before re-observing disclosure. A missing or denied target
and unreadable facts retain the existing concealed or generic result.

The PostgreSQL regressions in `postgres_proposal.rs`,
`postgres_immediate_action_requirements.rs`, and `postgres_action_handlers.rs`
exercise those boundaries, including withdrawn results, hidden candidate
prefixes, deadline cancellation, exact input grants, and value-free Invoke and
Submit diagnostics;
`holder_list_never_reads_other_holders_proposals_or_exposes_them_as_cursors`
locks other holders' rows while the caller pages through only their own. Client
boundary and language-binding regressions retain typed, bounded extensions
without rendering their values in errors.

## Bounded authentication refusal stages

Credential diagnostics can disclose credentials or create unbounded log volume.
`RegistryAuthenticator::record_header_refusal` uses the verifier's existing
per-stage limiter before recording the fixed Header stage for missing or
malformed HTTP bearer credentials and compact-token admission failures. No
credential, claim, issuer, subject, profile, or raw error value enters the log.
Shared OIDC lifetime failures use the fixed Time stage; malformed token structure
continues to use Header. The public generic 401 and the refusal before record
I/O remain unchanged.

`compact_token_admission_logs_one_value_free_header_diagnostic` in
`crates/registry-breg/tests/http_auth.rs` covers empty, oversized, invalid-base64,
and duplicate-member credentials with repeated calls and canaries.
`malformed_or_duplicate_bearer_is_refused_before_record_io` covers absent,
malformed, and duplicate HTTP credentials, the fixed diagnostic, generic 401,
and zero record reads. The shared OIDC lifetime test covers missing, nonpositive,
and overlong time bounds. These are operational diagnostics, with no new audit
release condition or authentication authority.

## Proposal task-grant context disclosure and audited request parsing

### Threat

- A service substitutes another Review request, subject, policy or context
  contract, or asks for fields outside the source-authored projection.
- A context read survives withdrawal or a change in current Record, row or
  consent authority.
- An authenticated caller sends a malformed body or unsupported media type
  after the route and authority are known, but receives a refusal that bypasses
  the Proposal refusal journal or remains available when that journal fails.

### Enforcement and defaults

`get-task-grant-context` is a separate Proposal operation. Its selected
profile must admit the verified service actor, requester client, scope,
purpose, Action and target boundaries. The read then requires the exact
accepted Review request, concrete policy and subject binding, intersects the
requested fields with `readableContextFields`, resolves current Record
authority, and holds the Review row lock through disclosure. It neither
borrows human review-context authority nor grants another Proposal operation.

`task_grant_context` in `crates/registry-breg/src/api/proposals.rs` resolves the
known Proposal, Action and selected authority before it validates the request
media and body. It accepts one `application/json` Content-Type, reads a bounded
body, applies strict JSON and typed request decoding, and routes every admitted
media or body refusal through `admitted_http_refusal`. The audit record carries
the fixed Action, operation and method, not request values. If the refusal
append fails, the route returns service unavailable instead of releasing the
ordinary refusal. An unknown Proposal remains concealed before Action
attribution.

### Tests

`review_status_service_reads_only_its_exact_frozen_review_binding` in
`crates/registry-breg/tests/postgres_proposal_security.rs` exercises the exact
accepted request and policy, field projection, current authority and both
withdrawal race orders. `task_grant_context_malformed_requests_are_audited_and_fail_closed`
uses the real router for malformed JSON and an unsupported Content-Type,
checks one minimized refusal record for each, and refuses the HTTP answer when
the audit writer rejects that record. The public-client test
`task_context_refuses_invalid_or_cross_source_authority_before_credentials`
holds the earlier client-side binding and validation boundary. The product
traceability catalog records these proofs without claiming an execution run.

### Accepted residuals

- A valid selected profile authorizes the service for the configured Action
  and target boundaries, not for one caller-supplied Review request. Exact
  accepted Review correlation and current disclosure checks remain runtime
  conditions on every read.
- The route reads the known Proposal's Action identifier before body parsing so
  it can attribute an admitted refusal. It releases no Proposal or context
  values during that lookup or refusal.

## Raw API caller credentials

### Threat

A local raw API request uses a client registered for another resource, or the
tooling's bearer and endpoint selection is mistaken for BReg authorization.

### Enforcement and defaults

`bregctl api PATH --client CLIENT` requires a ready local development session,
selects only a client admitted to that BReg resource, obtains a fresh bearer
for the client's registered resource and scopes, and keeps it in memory. The
adapter uses the API origin retained by that session and creates no reusable
header file. A saved or explicit remote connection instead uses the endpoint
and authentication the operator selected. Both paths use the
[`registry-cli-api` security boundary](../../crates/registry-cli-api/README.md#security-boundary).

The helper adds no BReg grant. The runtime still verifies the credential,
resolves the configured access profile, and authorizes the requested route,
record, fields, and operation.

### Tests

- `crates/registry-bregctl/src/dev/tests.rs`:
  `local_api_accepts_only_clients_admitted_to_this_breg_resource`.
- The shared transport, saved-credential, and process tests named in the
  `registry-cli-api` security boundary.

These are maintained test references, not claims of execution in this note.

## Rhai 1.27 dependency review

The workspace selects Rhai's `compact_str` backend, keeping BReg's owned
strings, `ImmutableString` values, identifiers, and object-map keys off
`smartstring`'s reported unsound conversion. Rhai still declares
`smartstring` unconditionally, so the unused package remains in the resolved
dependency and advisory graph. The workspace exception stays scoped to that
residual until upstream removes the edge.

BReg keeps its 100,000-operation ceiling and its existing deadline and value
bounds. Rhai 1.27 now charges operations performed by a script callback that a
native function invokes. BReg's registered Evidence helper does not invoke a
script callback, and the maintained Rhai files use no callback-based
collection method. A separately governed action or hook script that does use
one may reach the unchanged ceiling sooner and should be compiled and
evaluated before activation.

The compiled Rhai handler inventory now records 1.27.0, so recompiling a
project with a Rhai handler produces a new behavior revision for each affected
Action. Operators must regenerate and reseal governed packages, review those
revisions, and activate them through the existing migration boundary rather
than reusing a package compiled for 1.26.1.

The shared platform test
`rhai_maps_use_compact_string_keys_and_owned_unicode_round_trips` guards the
backend selection. `native_plan_security` retains the BReg resource,
deadline, fresh-call recovery, closed-capability, and value-free error checks.
Existing package and protected CI gates cover the change; no new blocking gate
is introduced.

## Native Record timer compiler authority

Record timers add autonomous mutation authority only when the root project
grants the exact Record type and timer pair. A module may contribute a timer
definition, but cannot contribute `timerGrants` or make that definition
runnable by itself. Compilation refuses missing, dangling, duplicate, or
module-contributed grants. BREG-SEC-195 records this root-authority boundary.

The invoked Action is deliberately not a second public caller route and cannot
enter the Proposal lifecycle. Compilation also excludes remote Function,
Evidence, commit-Evidence, and consent-issuance capabilities. BREG-SEC-196
through BREG-SEC-198 separate those authority boundaries so each one names its
actual resolving refusal test.

The compiled system grant may Patch only the exact locked anchor and may Create
the Action's bounded new Records. Its read ceiling covers the anchor's control,
predicate, and mapped current-value fields plus each declared secondary Get's
exact Record type and read fields, including existence-only reads. Those Gets
do not grant mutation authority over another existing Record. The timer-specific
anchor Get counts once against the ordinary Action target ceiling, and its
newly materialized fields count once against the ordinary snapshot ceiling.
Ordinary Action admission refuses a Proposal-required mutation target before
the timer-specific defense-in-depth branch is reachable. Timer compilation
also refuses another existing-Record mutation target, an extra target past the
ceiling, and an oversized anchor read. BREG-SEC-199 records these combined
grant and bound checks. The maintained test observes
`breg.action.effect-controlled-target` for the Proposal-policy case; it does
not claim direct execution of the shadowed
`breg.timer.action-proposal-policy-bypass` diagnostic.

The resolving compiler tests are maintained in
`crates/registry-breg/tests/timer_authoring.rs`:

- `timer_authoring_is_closed_and_root_grants_are_root_only` covers the
  root-only `timerGrants` source boundary for BREG-SEC-195.
- `timer_requires_exact_root_grant_and_complete_mapping` covers missing and
  dangling exact root grants for BREG-SEC-195.
- `module_timer_definition_requires_and_uses_root_enablement` covers a
  contributed timer's required root grant, duplicate grant authority, and
  duplicate module contributions for BREG-SEC-195.
- `timer_refuses_public_invoke_and_non_immediate_actions` covers BREG-SEC-196.
- `timer_refuses_remote_function_and_evidence_capabilities`
- `timer_refuses_consent_issuance_capability`
- `timer_system_authority_is_anchor_and_create_bounded`

The direct positioned identifier-collision proof is
`timer_ids_share_positioned_record_type_namespaces_within_each_authored_file`
in `crates/registry-breg/tests/native_source_conventions.rs`. It covers both a
project Record type and a module Record-plus-extension namespace.

`timer_system_authority_is_anchor_and_create_bounded` includes the
Proposal-required target refusal, distinct-binding target ceiling, same-anchor
deduplication, and anchor snapshot-byte ceiling. These are maintained test
references, not a claim that this note executed them. No new gate mechanism is
introduced.

## Native Record timer runtime boundaries

### Transactional staging

Record timer staging is part of the ordinary mutation transaction, after the
complete Record effects are known and while the canonical Record-before-ledger
lock order is still held. Direct writes, Batch, ingestion, and Proposal Apply
therefore commit their Record revision, receipt, outbox work, timer generation,
and current marker together. A failure after staging rolls the complete write
back, and an exact replay returns the retained result without creating another
generation. BREG-SEC-200 records this boundary.

The primary negative proof is
`direct_timer_staging_rearms_cancels_replays_and_rolls_back_after_staging` in
`crates/registry-breg/tests/postgres_mutation.rs`. The bulk proofs are
`timer_batch_stages_once_in_canonical_order_and_rolls_back_after_staging` in
`crates/registry-breg/tests/postgres_batch.rs` and
`timer_ingestion_stages_checkpoint_receipt_and_generations_atomically` in
`crates/registry-breg/tests/postgres_ingestion_runs.rs`. Proposal Apply is
covered by `proposal_apply_stages_timer_rows_atomically_and_replays_without_rearming`
in `crates/registry-breg/tests/postgres_proposal.rs`.

### Stale-owner settlement

Timer completion, business refusal, technical settlement, retry transition,
and release retain the complete current marker, binding incarnation and
semantic revisions, package and activation, control and instance epochs, and
claim owner, epoch, token, and lease as database compare-and-set fences. A
resumed stale owner cannot append an attempt, consume an allowance, overwrite a
peer outcome, or change Record, history, receipt, or outbox state.
BREG-SEC-201 records this boundary.

`native_stale_outcome_technical_failure_cannot_overwrite_peer` and
`native_stale_outcome_business_refusal_cannot_overwrite_peer` in
`crates/registry-breg/tests/postgres_record_timer_native.rs` stop the old owner
after the real Action transaction has rolled back, let a higher-epoch peer
settle, then prove the stale settlement changes zero rows.

### Operator disclosure and audit

Timer operator status, list, and show use read-only admitted transactions and a
closed metadata-only projection. They expose occurrence identity, state,
bounded attempt summaries, value-free outcome codes, and retention status, but
not Record fields, mapped inputs, raw failure details, or claim tokens. Pause,
resume, and technical retry remain separate mutations with paired value-free
audit records and exact current control, occurrence, attempt, binding, window,
and state fences. BREG-SEC-202 records these disclosure and accountability
boundaries.

An operator request audit failure precedes the store mutation and refuses it.
If commit acknowledgement or the response audit is uncertain after the store
call, the service withholds a successful response and records the outcome as
unresolved or unfinished. It does not claim that a transition which may have
committed was reversed; status and show provide the recovery observation.

`operator_reads_pending_and_completed_occurrences_without_record_values` and
`operator_retry_grants_one_technical_allowance_and_refuses_other_states` in
`crates/registry-breg/tests/postgres_record_timer_operator.rs` prove the closed
projection, bounded history, keyed audit correlation, and refusal of stale or
ineligible transitions.

`encrypted_predicate_write_opens_the_same_occurrence_and_maps_current_plaintext`
in `crates/registry-breg/tests/postgres_record_timers.rs` adds a positive
encrypted-value proof for one successful worker path. The opened plaintext is
observed in the authorized Action effect, while a canary is absent from JSON
rendered from every timer table, the real admitted operator projection,
captured audit entries, and scoped worker tracing with an observed positive
capture control. It does not cover actual `bregctl` process logging or every
failure path.

These are maintained test references, not claims that this note ran the tests.
They add no operator authority, public data field, or new gate.

## Action and Proposal requester clients match verifier admission

### Threat

An access profile with only Action or Proposal permissions could name a
`requesterClients` entry absent from `authentication.oidc.allowedClients`.
Offline checking and startup accepted that configuration, although token
verification refused every request by the named client before its grant could
be used.

### Enforcement and defaults

`validate_claim_mapping` in `crates/registry-breg/src/auth.rs` now checks the
requester clients copied into every compiled Action permission and every
compiled Proposal permission, alongside the existing Record, statistical
dataset, trusted-actor, and consent-recipient checks. An absent client returns
`NamedClientNotListed`, which `bregctl check --runtime-config` reports as
`breg.runtime.clients-unlisted` without rendering the client identifier.

This change compares only the compiled requester clients with verifier
admission. It does not copy the Record and statistical-profile trusted-actor
restriction onto Action or Proposal permissions. A standing agent may still
start or edit its caller-owned draft under the existing operation ceiling.

### Tests

- `crates/registry-breg/tests/http_auth.rs`:
  `action_and_proposal_only_clients_are_checked_at_construction` refuses an
  unlisted Action-only client and an unlisted Proposal-only client, accepts
  both when listed, and accepts the Proposal-only standing agent without a
  trusted-actor mapping.
- `crates/registry-bregctl/tests/cli.rs`:
  `check_refuses_unlisted_clients_on_action_and_proposal_only_profiles` proves
  the offline runtime-config refusal and its listed-client control on the
  maintained minimal project with Record permissions removed.
- `crates/registry-breg/src/api/tests/immediate_action_tests.rs`:
  `proposal_task_scopes_are_exact_and_standing_agents_only_start_or_edit_owned_drafts`
  retains the existing standing-agent operation ceiling.

No request authorization or PostgreSQL path changes. The construction check
fails earlier on a configuration whose named client could never pass token
verification.
