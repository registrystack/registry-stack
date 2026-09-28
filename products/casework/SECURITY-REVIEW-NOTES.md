# Registry Casework security review notes

Review notes for security-sensitive Registry Casework changes, held in tracked
material because commit messages do not survive a squash. Each section names
the change, the threat it answers, the defaults it ships, where Rust enforces
it, the tests that pin it, and the residual risk it accepts. The
security-invariant matrix in `contracts/security-invariant-matrix.yaml` is the
row-per-invariant baseline; this file is the narrative behind the decisions
and the residuals the matrix rows do not state.

## Package activation ledger

The change moves every database write a package activation makes out of the
runtime and into `caseworkctl apply`, records each activation in the
`casework_activations` ledger (schema migration 19), and removes
`casework migrate` and `caseworkctl db migrate`
(`crates/registry-casework/src/activation.rs`, `caseworkctl plan|apply|status`).

### Threat

Before the change, the runtime migrated the schema, registered source
generations, and activated task templates when it started, with whichever
credential it was given. The threats:

1. Holding the service credential, or starting the service, activates a
   package or changes the schema (CASEWORK-SEC-23).
2. A package is activated with no durable audit record, or the operator's
   change reference leaks through the ledger or the audit trail
   (CASEWORK-SEC-24).
3. An apply lands on the wrong database, races another apply or the running
   service, strands pinned work, or leaves a partial activation
   (CASEWORK-SEC-25).
4. A package keeps serving work against a Base Registry Engine source whose
   compiled contract changed under the registry revision it pinned
   (CASEWORK-SEC-26).

### What authorizes an activation

Holding the migration credential (`database.migrationUrlRef`) and running
`caseworkctl apply`. Nothing is signed: the ledger records what was applied,
by which role mode, with which hashed change reference and backup references,
and the audit trail records the same activation. The package itself is
verified against its `SHA256SUMS` and, when set, `package.expectedDigest`, as
at every start; apply adds no second approval. Operators who need a
two-person rule enforce it on who can read the migration credential.

### Migration versus runtime authority

- Only `caseworkctl apply` resolves the migration credential. `casework serve`,
  `caseworkctl plan`, `status`, and `doctor` connect with the runtime
  credential; `plan` does so in a read-only transaction.
- The runtime code no longer migrates, registers source generations,
  activates or retires task templates, or checks stranded pinned work at
  startup. Its activation check (`runtime::check_activation`) only reads.
  That is what the runtime does, not what its credential can do: the runtime
  role keeps DML on the tables that hold template activation and source
  generations (see Residual risk).
- Startup refuses a database with no activation, a schema version other than
  its own, an active package other than the one it loaded, a source
  generation the ledger has not registered, a `databaseId` other than its own,
  and a split-role activation whose runtime role can now write the ledger.
  Each refusal names `caseworkctl plan` then `caseworkctl apply`. The
  database-identity refusal uses the Base Registry Engine's wording and names
  neither value.
- Startup also refuses a source whose served registry revision differs from
  the `sourceRevision` the package pins (`runtime::check_source_revisions`).
  The refusal names `caseworkctl check PROJECT --against-breg-package DIR
  --source-id ID`, then the repin through `caseworkctl source add ... --apply`,
  `package`, `plan`, and `apply`. An unpinned source is not compared, and a
  source that cannot be reached at startup is logged as a warning rather
  than refused, so an outage does not stop the service.
- `caseworkctl check PROJECT --against-breg-package DIR` runs the same
  comparison before deployment. It composes through the `bregctl` binary of
  the same version, which verifies the package bytes and rederives the
  registry revision; Casework takes no crate dependency on the Base Registry
  Engine. A stale pin is `casework.source-revision.stale`, and a project with
  no, several, or an unknown BReg source is refused rather than guessed
  (`casework.source.none`, `casework.source.ambiguous`,
  `casework.source.unknown`).
- What startup no longer checks: it does not verify or record stranded pinned
  work, and it takes no migration lock; apply does both.
- `casework migrate` and `caseworkctl db migrate` still parse, only to refuse
  with exit 2 and name the two commands.

### Role separation and grants

- When the runtime and migration credentials name different roles, apply
  grants the runtime role `USAGE` on the schema, `SELECT, INSERT, UPDATE,
  DELETE` on every other `casework_*` table, `USAGE, SELECT` on the sequences,
  and `EXECUTE` on the Casework functions. It revokes `INSERT, UPDATE, DELETE,
  TRUNCATE` on `casework_activations` and `casework_schema_migrations` from
  the runtime role and all privileges on them from `PUBLIC`, then grants
  `SELECT` on both. Every statement is idempotent and every split-role apply
  reissues them.
- The runtime role keeps broad DML on the work tables, including
  `casework_task_templates` and `casework_source_reconciliation_progress`.
  That is what serving needs. Split mode separates authority over the two
  ledgers and the schema, not over work data, template activation, or source
  generation registration.
- A trigger runs as whichever role fires it, including the migration role
  inside apply, and it has no owner of its own: one the runtime role attached
  while it owned a table survives `REASSIGN OWNED BY`. Apply therefore never
  issues `TRIGGER`, and refuses rather than revokes it, as below.
- The role mode is recorded from the runtime role's effective authority after
  the grants, not from whether the two credentials name different roles. The
  runtime role counts as single-role when it is a superuser or bypasses row
  security, holds `DELETE` or `TRUNCATE` on either ledger or `INSERT` or
  `UPDATE` on either ledger or any of its columns, is a member
  of the ledger's owner or the schema's owner, or is a member of the migration
  role. It counts as single-role too when it can reach the ledger through code
  that runs as the migration role: it owns, or is a member of the owner of,
  any `casework_*` table, sequence, view, or function, holds `TRIGGER` on a
  Casework table or view, or holds `CREATE` on the schema, and whatever role
  it is when a trigger no Casework migration creates is attached to a
  Casework table. A deferred constraint trigger on `casework_task_templates`,
  for example, fires as the migration role at apply's commit and can insert a
  ledger row. The triggers the migrations create are
  `activation::MIGRATION_TRIGGERS`, matched by table, name, and the function
  in the Casework schema they execute, and a unit test holds that set equal to
  the `CREATE TRIGGER` statements in the migrations.
- Split-role apply refuses such ownership, `CREATE`, `TRIGGER`, or trigger
  before it changes anything, with `casework.activation.role-mode-weakened`,
  rather than record it as single-role, since reassigning the objects,
  revoking the grant, or dropping the trigger takes the authority away. The
  refusal names each statement to run as the migration role:
  `REASSIGN OWNED BY <owner> TO <migration role>`,
  `REVOKE CREATE ON SCHEMA <schema> FROM <grantee>`,
  `REVOKE TRIGGER ON <schema>.<table> FROM <grantee>`, and
  `DROP TRIGGER <trigger> ON <schema>.<table>`. A privilege held through
  `PUBLIC` is named `FROM PUBLIC`. Reassigning takes the runtime role's
  grants on the objects too, so a fix with a `REASSIGN` ends with
  `caseworkctl apply --runtime-config FILE` to reissue them; the others end
  with rerunning the command that refused, or
  `caseworkctl plan --runtime-config FILE` to confirm. `plan` reports the same
  refusal once the ledger exists, and startup's refusal of a weakened
  split-role activation names the same statements from the same check
  (`activation::stray_authority`). A single-role deployment already holds the
  ledger and is refused none of these.
- A split-role runtime role that no longer holds every grant apply issues it,
  as after `REASSIGN OWNED BY` takes a table back, is refused at startup with
  `RuntimeError::RuntimeGrantsMissing`, naming
  `caseworkctl apply --runtime-config FILE`. `plan` reports the active
  package as pending, without effects when the runtime role can no longer
  read a Casework table, and apply reissues the grants. The grants checked
  are schema `USAGE`, `SELECT` on both ledgers, full DML on every other
  Casework table, `USAGE` on the sequences, and `EXECUTE` on the Casework
  functions.
- Re-applying the active package is allowed, and planned as pending, when the
  effective role mode differs from the latest row or the runtime role's grants
  are not current, so moving to split or rotating the runtime role reissues
  the grants. Re-applying with nothing to change is a refusal naming the
  digest.
- `plan` refuses, with `casework.activation.ledger-unreadable` and exit 1,
  when its role cannot read the ledger its search path reaches first: no
  `USAGE` on that schema, which would hide the ledger and read the database as
  empty, or no `SELECT` on `casework_activations` or
  `casework_schema_migrations`, as for a rotated runtime role before apply
  grants it. The refusal names `caseworkctl apply --runtime-config FILE`,
  then `plan` again. A database with no ledger is not refused.
- Single-role deployments are allowed. `status` and `doctor` then state that
  the runtime credential can activate packages and rewrite the ledger, so the
  ledger cannot show that it did not. `caseworkctl dev` creates single-role
  sessions, as local development needs no role separation; a session
  retained from an earlier release keeps its split roles.

### Audit integrity

- Apply writes through `with_operator_audit` under schema
  `casework-activation-audit/v1`. The request entry is appended before the
  apply transaction opens; a destination that refuses it leaves the database
  untouched and apply exits 3 with `casework.activation.audit-unavailable`.
- The response entry is appended after the commit. When the destination
  refuses it, apply confirms the ledger row and exits 3 with
  `casework.activation.applied-unaudited`, saying the package is active and
  must not be applied again. Template-invalidation events the apply causes are
  recorded under the same audited operation.
- Audit and database-connection failures are operational (exit 3), never a
  domain refusal (exit 1).

### Operator-reference hashing

`--operator-reference` is validated as bounded text and then stored and
audited only as a keyed hash under the audit hash key (`audit.hashKeyRef`),
with class `casework-operator-reference-v1` and the activation id as scope. The
same reference in two activations yields different hashes, so the ledger
cannot be joined across activations on it, and the text is never written.
`--backup` references (at most 16) are recorded as given; they name
snapshots, not people or tickets.

### Concurrency and lock order

Apply runs in one transaction under `pg_advisory_xact_lock` on the migration
lock key. Before any migration DDL it takes the locks runtime transactions
take first, in their order: the `casework_meta` singleton `FOR UPDATE`, then
every `casework_source_reconciliation_progress` row `FOR UPDATE`. Source
generation registration locks a source's progress rows before it rebinds that
source's subjects, the order reconciliation uses. A waiting apply therefore
holds no lock stronger than a row lock while the runtime works.

### Tests

- CASEWORK-SEC-23:
  `a_runtime_role_that_gained_ledger_authority_is_refused_at_startup_until_apply_records_it`,
  `a_runtime_role_that_owns_a_casework_table_is_refused_by_apply_and_at_startup`,
  `a_runtime_role_with_create_on_the_schema_is_refused_by_apply_and_at_startup`,
  `trigger_and_public_privileges_are_refused_naming_their_revoke`,
  `a_trigger_left_by_a_runtime_role_that_owned_a_table_is_refused_after_reassignment`,
  `a_trigger_on_a_casework_table_refuses_no_single_role_apply`,
  `ledger_writes_weaken_a_split_activation_until_apply_revokes_them`,
  `the_known_triggers_are_exactly_the_ones_the_migrations_create` (in
  `activation.rs`),
  `serve_refuses_an_unapplied_database_before_listening_or_writing` (through
  `serve_from_path`: the refusal, no listener, and no `casework_*` row written),
  `split_role_runtime_cannot_write_the_ledgers_but_still_serves`,
  `startup_refuses_an_unapplied_database_another_package_and_another_database`,
  `moving_to_split_and_rotating_the_runtime_role_reapply_the_active_package`,
  `plan_against_an_empty_database_writes_nothing`,
  `plan_as_a_rotated_runtime_role_that_cannot_read_the_ledger_names_apply`,
  `a_plan_whose_runtime_role_cannot_read_the_ledger_is_a_refusal_naming_apply`
  (in `registry-caseworkctl`),
  `a_session_connects_the_runtime_and_apply_with_one_database_credential` (in
  `registry-caseworkctl` dev), and the removed-command tests in `runtime.rs`
  and `registry-caseworkctl`.
- CASEWORK-SEC-24: `a_refused_audit_request_leaves_the_database_untouched`,
  `a_refused_audit_response_after_commit_reports_the_activation_applied_but_unaudited`,
  `the_same_operator_reference_in_two_activations_is_stored_under_different_hashes`,
  and `an_activation_audit_failure_is_operational_and_an_unaudited_commit_says_it_applied`.
- CASEWORK-SEC-25: `a_database_id_mismatch_is_refused_before_any_change`,
  `a_concurrent_apply_waits_for_the_migration_lock`,
  `an_apply_waiting_for_a_runtime_directory_lock_holds_no_migration_lock`,
  `stranded_work_is_refused_until_the_exact_package_is_acknowledged`, and
  `reapplying_the_active_package_is_refused_and_writes_nothing`.
- CASEWORK-SEC-26:
  `startup_refuses_a_pinned_source_revision_the_source_no_longer_serves` and
  `startup_accepts_a_current_pin_an_unpinned_source_and_an_unreachable_source`
  (in `runtime.rs`),
  `source_revision_pin_reports_the_pinned_and_the_served_registry_revision`
  (in `registry-casework-breg`), and the `check_against_a_breg_package_*`
  tests in `registry-caseworkctl`.

The PostgreSQL tests are in `crates/registry-casework/tests/activation_postgres.rs`
and need `CASEWORK_ACTIVATION_TEST_DATABASE_URL`.

### Residual risk

- Nothing is signed. Anyone holding the migration credential can activate any
  verified package; the ledger and audit trail record it after the fact.
- In single-role mode the runtime credential can rewrite the ledger.
- In split-role mode the runtime role keeps `SELECT, INSERT, UPDATE, DELETE`
  on `casework_task_templates` and `casework_source_reconciliation_progress`.
  A runtime credential holder can therefore activate or retire a task
  template, or register a source binding generation, without `caseworkctl
  apply` and without a ledger row or activation audit entry. Split mode
  protects the ledgers and the schema, not that activation state.
- A future migration that alters `casework_meta` itself could still meet a
  runtime transaction queued for its `FOR SHARE` lock; PostgreSQL detects the
  deadlock and rolls one side back, and apply can be retried.
- `plan`'s ledger-unreadable check follows the search path, so a ledger in a
  schema the path does not name is invisible to it, as it is to the runtime.
- A source unreachable at startup is served with its pin unchecked until
  the next start; its registry revision is not re-read while the service runs.
- `plan` sees the runtime role's membership in the migration role only through
  ownership; apply, which runs as the migration role, sees it directly.
- If reading the ledger back after a refused response entry also fails, apply
  reports a generic store failure; `caseworkctl status` then shows whether the
  activation committed.
