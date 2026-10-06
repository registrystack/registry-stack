# Base Registry Engine security review notes

Review notes for security-sensitive Base Registry Engine changes, held in
tracked material because commit messages do not survive a squash. Each
section names the change, the threat it answers, the defaults it ships, where
Rust enforces it, the tests that pin it, and the residual risk it accepts. The
security-invariant matrix in `contracts/security-invariant-matrix.yaml` is the
row-per-invariant baseline; this file is the narrative behind the decisions
and the residuals the matrix rows do not state.

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
   is refused as already active (`apply.package.already_active`, naming
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
   <runtime>`), the owner of a registry table, sequence, view, or function,
   or a member of that owner (`REASSIGN OWNED BY <runtime> TO <migration>`
   followed by `bregctl apply`, or `REVOKE <owner> FROM <runtime>`), a holder
   of a write privilege or of `CREATE` on a registry schema, directly or
   through `PUBLIC` (`REVOKE .. FROM <grantee>`), and a trigger on a product
   table that no compiled migration creates (`DROP TRIGGER`). The `REVOKE`
   and `DROP` fixes end with "then rerun the refused command". The reason for
   the ownership check: an owner of a table apply touches can add a deferred
   constraint trigger that runs as the migration role when apply commits and
   writes the ledger. Apply issues the runtime grants the active package
   gives and treats missing split grants as a change pending, so a
   reassignment that strips them is repaired by the next apply; split startup
   refuses missing grants, naming `bregctl apply`. A change of runtime role or
   role mode over the active package is recorded as its own successor
   activation (`metadata_only`, a fresh activation id), and apply revokes
   every privilege of a runtime role the activation stops serving with. A
   one-role runtime file is refused against a database last activated for a
   separate runtime role. In either mode, a runtime role with superuser,
   `BYPASSRLS`, `CREATEDB`, `CREATEROLE`, or database `CREATE` is refused at
   startup. `bregctl doctor` and the startup log
   (`startup.role_mode.single`) say that single mode catches mistakes but not
   someone holding the credential. Tests:
   `crates/registry-breg/tests/postgres_migration.rs`:
   `real_postgres_split_apply_refuses_a_runtime_role_that_owns_a_model_table`,
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
   `ActivationAuditUnavailable`. After the activation commits, apply writes
   the response (`phase: terminal`, `outcome: applied`); an activation that
   fails after its request answers `failed` once the durable state shows the
   target did not land, and one interrupted mid-plan leaves the registered
   `unfinished` response. A response the audit refuses after the commit is
   reported as `ActivationAuditIncomplete`, never as a failed activation.
   `bregctl plan` rehearses and rolls back and never opens the activation
   audit. Tests: `crates/registry-breg/tests/postgres_migration.rs`:
   `real_postgres_each_activation_audits_its_request_and_its_applied_response`,
   `real_postgres_a_failed_activation_audits_its_failed_response`,
   `real_postgres_a_refused_activation_request_entry_changes_nothing`,
   `real_postgres_a_refused_supersession_record_reports_the_activation_audit_incomplete`.
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

- The `bregctl test` receipt (`breg-schema-test-receipt/v2`) binds the
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
  `startup.instance_claim.mismatch`.
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
`retainDays`, and tamper evidence is shipping the stream to append-only
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
  `migration.rehearsal.baseline_fingerprint_drift`, with the recorded and the
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

`bregctl webhook discard` permanently closes one pending delivery, dead
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
  attempt failed waits for its retry. A pass whose content read or verifier
  request failed and left its job pending for a retry is never a success,
  and neither is an idle pass during that retry wait.
- `breg_queue_oldest_pending_age_seconds` carries only a closed `queue`
  label (`webhook_delivery`, `review_submission`, `review_application`) and
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
`crates/registry-breg/tests/postgres_change_requests.rs`:
`real_postgres_attachment_verification_worker_records_its_last_success_when_idle`,
`real_postgres_attachment_verification_worker_records_no_success_while_the_verifier_fails`,
and `real_postgres_attachment_verification_worker_claims_the_next_due_job_without_waiting`.
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
  `breg_queue_oldest_pending_age_seconds`, because its row policy admits
  only a transaction the attachment worker has admitted; its worker progress
  age is published.
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
  nothing and report `apply.database.in_progress`, with a sentence that names
  the held lock and the `retry_after_migration_lock_releases` suggested
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
  `migration.reconcile.outcome.in_progress` and changes nothing; an
  assessment reports `in_progress` as its outcome.
- An assessment holds only the keyed audit profile it validates the operator
  reference under. `--execute` opens the companion audit writer after the
  locked preflight and before any database change, and refuses as
  `migration.reconcile.audit.unavailable` when it cannot.
- `history erase`, `history rebaseline`, `field-encryption preflight`, and
  `field-encryption erase-history` keep the locked preflight and report a
  held lock as `<prefix>.active_registry.in_progress`.
- The history maintenance transactions take the exclusive lock through
  `lock_registry` in `crates/registry-breg/src/history_maintenance.rs`, which
  reads the lock wait with the same `lock_wait_ended` rule as
  `acquire_inner`. A held lock there refuses as `MigrationLockHeld` before the
  transaction changes anything, and `bregctl` reports it as
  `history.erase.in_progress`, `history.rebaseline.in_progress`, or
  `field_encryption.erase_history.in_progress` with the
  `retry_after_migration_lock_releases` suggested action. Its request entry is
  answered `unfinished`, as for any other refusal. An `erase-history` run
  refused part way keeps the records it already erased, each in its own
  committed transaction, and can be run again. `field-encryption preflight`
  takes no advisory lock, so it has no such refusal.
- Action Evidence retention, request retention, import authority
  maintenance, and instance claim adoption take the exclusive lock through
  the same `lock_registry`. A held lock refuses as `MigrationLockHeld` before
  their transaction changes anything, and `bregctl` reports it as
  `evidence_retention.in_progress`, `request_retention.in_progress`,
  `import_authority.in_progress`, or `instance_claim.in_progress` with the
  same suggested action. The Evidence erasure, the request-detail erasure,
  and the adoption answer their request entry `failed`, as for an outage;
  import authority maintenance records only committed transitions, so a
  refusal records nothing. A request-detail erasure that committed keeps its
  `committed` response when the external-deletion retry after it meets the
  held lock, and the command still reports `request_retention.in_progress`.

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
`--execute` refuses and `apply` refuses with `apply.database.in_progress`
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
  commands refuse with `apply.package.digest_mismatch` and the
  `rerun_plan_on_intended_package` suggested action. The message names the
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
and names both schema fingerprints in `migration.review.fingerprint_mismatch`,
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
  sets the descriptor's `lockTimeoutMs` and `statementTimeoutMs`, or a
  backfill step's own, through the same bounded setter activation uses, and
  restores the compiler's bound for the generated statements.
- A newly captured receipt that carries `proofs` is refused by `bregctl`
  with `migration.review.receipt_proofs_retired`. A package the previous
  release built with one keeps loading, with the member ignored, so an
  active package survives the upgrade; nothing reads its values, and that
  acceptance is removed in the next release.
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
`reviewed_package_whose_receipt_carries_the_previous_release_proofs_still_loads`.
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
  `hook.handler.wasm_build_unsupported` at `entities[].hooks[].handler.kind`
  before its module is looked up, so the refusal names the build rather than
  the module and no module diagnostic is reported.
- Package loading rederives the package through the same compiler, so the
  build refuses to load a package a wasm-enabled build produced.
- Default builds carry the `wasm` feature and are unchanged. The runtime's
  late refusal of a WASM hook in `hook_handler.rs` stays as a second line.

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
Anonymous profiles, encrypted
processing fields, and consent-gated count grants are refused.

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

Anonymous refusals return before authenticated refusal auditing, preventing
unauthenticated requests from filling that journal or observing sink health.
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
digests, owner count parity, anonymous refusals under audit failure, stored-byte
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
- Schema install is `CREATE ... IF NOT EXISTS` plus the steps a database
  v0.38.0 can serve still needs. One of them is the dead-letter reason: v0.38.0
  introduced the column and its constraint and tolerates a delivery-state
  table without them, so install still adds both to such a table. Installing
  over an installed schema changes nothing.
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
   PostgreSQL and run only where `HOOKS_TEST_DATABASE_URL` is set, which no
   CI job does:
   `installing_over_an_installed_schema_changes_nothing`,
   `installing_over_a_table_without_dead_letter_reasons_adds_them`.
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
now persisted), audit integrity (what rotating `audit.hashKeyRef` changes),
and deployment defaults (a seven-day horizon and an upgrade that turns
earlier spent keys into tombstones no caller can find). The invariants are
BREG-SEC-162 through BREG-SEC-164.

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

### Enforcement and defaults

- **Identity.** A spent row is found by `key_reference`, an unkeyed SHA-256
  over the domain `breg-idempotency-key-v2` and the length-prefixed key
  scope, issuer, subject, and key, and by a unique index on those four raw
  columns. Mutation keys, immediate-action keys, and the server-derived
  ingestion chunk keys use the configured `authentication.oidc.issuer` and
  the verified principal. The key scope is not the operation: every ordinary
  write (record mutations, batches, change-request routes, statistical
  releases, and immediate actions) spends caller keys in the one `mutation`
  scope, so a caller reusing a key on a different write route finds the
  spent row and is refused `409 idempotency.conflict` by its binding.
  Ingestion chunk keys use the `ingestion_chunk` scope. A hook proposal
  application is spent by the delivery itself, in the `hook_proposal` scope:
  issuer `urn:registry-breg:hook-delivery`, subject the compiled delivery id,
  and the delivery's idempotency key. The configured issuer must be an
  `https` URL or a loopback `http` URL, so no verified token carries that
  issuer and no caller can reserve, replay, or collide with a delivery's
  application. A coordinator built without a runtime configuration scopes
  keys under `urn:registry-breg:embedded-issuer`.
- **Binding.** `binding_reference` is an unkeyed SHA-256 over the canonical
  exact binding: method, route, target, package revision, response fields,
  canonical request digest, the raw verified claim context (principal,
  selected profile, purpose, row boundaries, submitter targets), and the
  task grant, action contract fingerprint, target authority, or handler
  answer digest where they apply. A byte-identical body under a different
  package, profile, or claims is therefore `409 idempotency.conflict`.
- **Audit key.** Nothing that finds or binds a spent row reads
  `audit.hashKeyRef`. The keyed `request_reference` and principal reference
  stay in revisions and the audit journal as pseudonyms; rotating the key
  changes them for later writes only.
- **Horizon.** A held response stays available for
  `idempotency.receiptRetentionDays` after its commit: default 7, at least 1,
  at most 365, fixed on the row when it commits. Reading a spent key checks
  the binding first and the horizon second, so a changed request is told it
  conflicts and an exact retry past the horizon is `410 idempotency.expired`.
  Either way nothing executes, whether or not the held bytes were dropped.
  Only successful responses are held; a refusal spends no key.
- **Sweep.** Expiry is enforced when the row is read, so the sweep only
  bounds how long held bytes stay stored, as `evidence-retention
  erase-expired` does for retained assertions. It runs under the migration
  credential, takes the registry lock, verifies identity, catalog, and
  readiness, and sets the body to null and the headers to an empty set with
  `receipt_dropped_at`, keeping caller, key, binding, and times. The runtime
  role holds only `SELECT` and `INSERT` on the table, so no request path can
  drop or rewrite a held response. The request entry
  (`breg-idempotency-retention-audit/v1`) is accepted before the transaction
  opens and the response records the count; a commit that returned an error
  is read back on a fresh connection before the outcome is recorded.
- **Upgrade.** The engine feature `caller_scoped_idempotency` makes a
  rebuilt v0.39.0 package an engine-capability successor, so the apply runs
  the schema install. When `registry_idempotency` lacks the caller columns,
  the install adds them and converts every existing row into a tombstone
  before setting them `NOT NULL`. No row is deleted and no table is emptied.
  A tombstone keeps its `key_reference` (the earlier audit-keyed
  `hmac-sha256:` digest), binding, result kind, result references, erasure
  time, and commit time. It takes the reserved issuer
  `urn:registry-breg:pre-caller-scope`, its own `key_reference` as subject,
  the `mutation` scope, and the constant key `pre-caller-scope`, so the
  caller index holds. Its held response body becomes null and its headers an
  empty set, `receipt_dropped_at` is the upgrade time, and its horizon ends
  one microsecond after its commit. `registry_immediate_action_results`,
  `registry_immediate_action_applications`,
  `registry_action_evidence_uses`, and
  `registry_request_idempotency_links` keep every row. The stored action
  results are what keep a revision an engine before v0.39.0 journaled under
  a compiled effect identifier readable in history; emptying them made that
  read answer `503 source.unavailable`. No caller reaches a tombstone: lookup
  is by a `sha256:` key reference, which never equals an `hmac-sha256:` one,
  and `IdempotencyPolicy::new` refuses the reserved issuer as the configured
  one, which must be an `https` or loopback `http` URL anyway. The kept
  request idempotency links are read only by request retention, which counts
  and erases held bodies a tombstone no longer has, and by the replay check
  of a key that was found, which a tombstone never is.

### Data minimization

`registry_internal.registry_idempotency` now stores the raw issuer,
principal value, and key of every spent row for as long as the registry keeps
the row; previously it stored only a keyed hash. No command deletes a spent
row. Request-retention erase (`bregctl request-retention erase`) sets a
linked row's held body to null and marks it erased, and leaves the raw
issuer, subject, and key in that row, kept indefinitely; the receipt sweep
and `history erase` leave them in the same way. The audit journal is
unchanged and carries keyed references only. The binding digest is unkeyed,
so someone who can read the table can confirm a guessed low-entropy claim
value, such as a purpose or a row boundary, against it; that reader already
sees the raw principal beside it and the records it produced. `history erase`
still replaces held responses that could replay erased revisions with refusal
tombstones and leaves the spent row.

### Tests

- `tests/postgres_mutation.rs`:
  `real_postgres_exact_retry_after_audit_key_rotation_replays_and_never_reexecutes`,
  `real_postgres_idempotency_keys_are_scoped_per_caller`,
  `real_postgres_retry_after_receipt_horizon_is_refused_and_the_sweep_keeps_the_key_spent`,
  and
  `real_postgres_upgrade_from_the_audit_keyed_idempotency_shape_tombstones_spent_rows`.
- `tests/postgres_migration.rs`:
  `a_pre_caller_scoped_empty_successor_tombstones_audit_keyed_spent_keys`
  applies a package without the engine feature, restores the old table
  shape with a held row, and proves the successor apply keeps it as a
  tombstone without its held response and verifies the catalog.
- `tests/postgres_immediate_actions.rs`:
  `the_caller_scoped_idempotency_upgrade_keeps_legacy_action_revisions_readable`
  restores the old table shape under a committed immediate action whose
  revision carries the compiled effect identifier, installs the caller
  shape, and proves the revision still reads, every spent key, application,
  and action result is kept, and the exact retry runs as a fresh request.
- `src/idempotency.rs`:
  `a_policy_refuses_the_issuer_earlier_spent_keys_are_converted_under`.
- `tests/postgres_batch.rs` proves over HTTP that another principal's batch
  under the same key executes as its own request and that an expired exact
  retry answers `410 idempotency.expired` without effects.
- `tests/runtime_config.rs`:
  `idempotency_receipt_horizon_defaults_to_seven_days_and_is_capped_at_a_year`.
- `registry-bregctl`: the held-lock, pin-mismatch, and invalid-configuration
  diagnostics of `idempotency-retention erase-expired`.

### Accepted residuals

- **The upgrade forgets which caller spent each key.** A tombstone is never
  found again, so a request committed before the upgrade and retried after
  it executes again, and a hook delivery in flight across the upgrade can
  apply its proposal again. Nobody runs Base Registry Engine in production
  yet, so no earlier key is carried over. Entity uniqueness constraints still
  refuse a duplicate create where the project declares them.
- **Issuer or principal mapping changes re-scope keys.** A retry across a
  change of `authentication.oidc.issuer` or of the principal claim is another
  caller's fresh request. The operator guide says to resolve uncertain writes
  before such a change.
- **Spent rows are never deleted.** The horizon bounds held bytes, not the
  raw caller and key, which stay as long as the registry keeps the row.
- **A late retry cannot recover a lost body.** Past the horizon a client
  whose first response was lost must read the record or its history.
- **Ingestion chunk replays do not use the horizon.** A chunk replays from
  the run's own chunk receipt, which the run retains; the spent row behind it
  is never the source of that reply.
- **Other keyed references still bind ownership.** Ingestion run ownership
  (`created_principal_reference`) is a keyed hash under `audit.hashKeyRef`,
  so rotating the key hides an open run from its creator. It is outside the
  spent-key scope of this change.
