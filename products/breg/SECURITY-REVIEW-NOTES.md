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
kind (`initial`, `successor`, or `adopted`), the role mode, the runtime role,
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
6. A database a release before the ledger activated is adopted onto a package
   whose schema it does not have (BREG-SEC-122).

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
   `retired_package_flags_are_usage_errors_that_name_their_replacement`.
   `crates/registry-bregctl/src/lib.rs`:
   `apply_chain_refusals_name_the_operators_next_command`.
   `crates/registry-breg/tests/compiler_contract.rs`:
   `retired_package_identity_keys_are_refused_with_their_replacement`,
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
   --package DIR --initial`) or with the pre-ledger shape (naming `bregctl
   apply --package DIR`, which adopts it); under split roles, a runtime role
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
   `startup_refuses_a_pre_ledger_database_naming_the_adopting_apply_and_writes_nothing`,
   `split_startup_refuses_a_runtime_role_that_can_write_the_ledger_and_writes_nothing`,
   `a_restored_copy_refuses_to_serve_until_adopted`.
   `crates/registry-breg/tests/postgres_package.rs`:
   `real_postgres_package_startup_apply_failure_and_old_process_are_closed`,
   `local_unsigned_package_rederives_every_artifact_and_refuses_filesystem_tampering`.
   `crates/registry-breg/tests/postgres_package/fingerprint.rs`:
   `legacy_fingerprint_starts_and_upgrades_without_rewriting_package_bytes`.
   `crates/registry-breg/tests/postgres_migration.rs`:
   `real_postgres_a_pre_ledger_database_is_refused_until_it_is_adopted`.

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
  change, adoption, or already active) is detected from the database.
- Model-table columns and settings keep the name `active_package_revision`;
  their value is the activation id. Renaming them would change the live
  catalog and break adoption without model DDL.

### Adoption of a pre-ledger database

The first `bregctl apply --package DIR` on a database a release before the
ledger activated adopts it. It requires the recorded package id to equal the
package's, the recorded database id to equal `identity.databaseId`, and
maintenance `ready` with no pinned target; otherwise it refuses and changes
nothing. Under the exclusive apply lock and in one transaction it reshapes
the kernel tables, compares the live managed catalog fingerprint with the
package's `schemaFingerprint` and refuses and rolls back on a difference,
runs no model DDL, drops the pre-ledger migration history, carries any
instance claim into the state row, supersedes every open import authority,
and records one ledger row with plan kind `adopted`. `bregctl plan` runs the
same transaction and rolls it back. Adoption applies only to a pre-ledger
database: one the ledger already records is refused before anything
changes. Tests:
`crates/registry-breg/tests/postgres_migration.rs`:
`real_postgres_adoption_records_a_pre_ledger_database_as_its_first_activation`,
`real_postgres_adoption_refuses_a_package_whose_fingerprint_differs_and_changes_nothing`,
`real_postgres_adoption_refuses_a_database_left_in_maintenance`,
`real_postgres_adoption_refuses_a_database_the_ledger_already_records`,
`real_postgres_a_pre_ledger_database_is_refused_until_it_is_adopted`,
`real_postgres_a_plan_reports_an_adoption_and_leaves_the_pre_ledger_kernel`.

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
- **Adoption drops the pre-ledger migration history.** The dropped rows are
  not carried into the ledger, so they survive only in a backup taken before
  the adopting apply and in the audit stream the earlier release wrote.

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
  original's claim and refuses to serve until adopted. Adopting a pre-ledger
  database carries its claim into the state row. Reinstalling the schema
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
`real_postgres_an_activation_keeps_a_claim_that_names_another_database`,
`real_postgres_adoption_records_a_pre_ledger_database_as_its_first_activation`.

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
  `query.invalid`, never exposes them, and still turns any other location
  into a protocol failure.

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
`record_and_query_problem_paths_are_closed_bounded_and_discarded` pins the
client's closed forms.

### Accepted residuals

- A located refusal tells the caller which of its own admitted fields or
  parameters was wrong, and that a required field it may write is missing.
  Both are already in the caller's filtered contract.
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
`registry-relay-v2`, `registry-evidence-client`, and
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
each discover and apply call. Token acquisition errors are value-free. The
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
