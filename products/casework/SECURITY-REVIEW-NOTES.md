# Registry Casework security review notes

The current review-only security contract is the maintained
`contracts/security-invariant-matrix.yaml` and its executable
`contracts/security-test-traceability.yaml`. The sections that follow preserve
historical review decisions, including the retired WorkItem/source-action
implementation. Their old symbols, migration numbers and recovery commands are
not instructions for the current runtime. Use the product README, runtime
configuration reference and current contract matrix for deployment behavior.

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

`registry-platform-activation` now owns the product-neutral ledger reads and
appends, `databaseId` and active-package comparisons, role observation,
runtime grants, indirect-authority and default-privilege checks, and lost
acknowledgement read-back. Casework retains its migrations, lock order,
stranded-work and source-generation hooks, audit wording, and refusal mapping
inside the same activation transaction. This moves implementation ownership;
the Casework invariants and executable tests below remain the product contract.

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
- The runtime code no longer migrates, registers source generations, or
  activates or retires task templates at startup. Its activation check
  (`runtime::check_activation`) and its stranded pinned work check (below)
  only read.
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
  no, several, or an unknown Base Registry Engine (BReg) source is refused rather than guessed
  (`casework.source.none`, `casework.source.ambiguous`,
  `casework.source.unknown`).
- Startup repeats the stranded pinned work comparison read-only, because a
  process still serving the earlier package can admit work between apply and
  this start. It refuses to serve unless `package.acknowledgeStrandedWork`
  names the package it loaded, records nothing, and takes no migration lock;
  apply holds the lock and records the activation.
- `caseworkctl plan` names the refusals schema migrations 15 and 17 would
  meet, counting the hosted-work and audit outbox rows without a lock and
  passing over a table the runtime role cannot read; apply counts them again
  under an exclusive lock in its own transaction.
- `casework` has no `migrate` subcommand and `caseworkctl` has no `db`
  subcommand; each is refused as an unrecognized subcommand with exit 2.

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
  (`activation::stray_authority`). Split-role apply also refuses, before any
  migration, a default privilege of the migration role that would grant the
  runtime role `TRIGGER` on the tables a migration creates, naming
  `ALTER DEFAULT PRIVILEGES FOR ROLE <migration role> [IN SCHEMA <schema>]
  REVOKE TRIGGER ON TABLES FROM <grantee>`, since a refusal after the
  migrations would name tables its rollback removes. A single-role
  deployment already holds the ledger and is refused none of these.
- A split-role runtime role that does not hold every grant apply issues it,
  as after `REASSIGN OWNED BY` takes a table back, is refused at startup with
  `RuntimeError::RuntimeGrantsMissing`, naming
  `caseworkctl apply --runtime-config FILE`. `plan` reports the active
  package as pending, without effects when the runtime role can no longer
  read a Casework table, and apply reissues the grants. The grants checked
  are schema `USAGE`, `SELECT` on both ledgers, full DML on every other
  Casework table, `USAGE` on the sequences, and `EXECUTE` on the Casework
  functions.
  Startup checks them whenever the runtime credential is split by its own
  authority, not only when the latest row records `split`, so a single-role
  activation whose `runtimeUrlRef` was rotated to a separate role refuses
  until apply grants that role. A rotated role that can still write the
  ledger is single-role, as the row records, and a split apply for it
  refuses that authority.
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
  `registry-caseworkctl` dev), `serve_is_the_only_subcommand` (in
  `runtime.rs`), `casework_migrate_is_refused_as_an_unrecognized_subcommand`
  (in `tests/command_line.rs`), and `db_is_refused_as_an_unrecognized_command`
  (in `registry-caseworkctl`).
- CASEWORK-SEC-24: `a_refused_audit_request_leaves_the_database_untouched`,
  `a_refused_audit_response_after_commit_reports_the_activation_applied_but_unaudited`,
  `the_same_operator_reference_in_two_activations_is_stored_under_different_hashes`,
  and `an_activation_audit_failure_is_operational_and_an_unaudited_commit_says_it_applied`.
- CASEWORK-SEC-25: `a_database_id_mismatch_is_refused_before_any_change`,
  `a_concurrent_apply_waits_for_the_migration_lock`,
  `an_apply_waiting_for_a_runtime_directory_lock_holds_no_migration_lock`,
  `stranded_work_is_refused_until_the_exact_package_is_acknowledged`,
  `activation_plan_refuses_a_package_that_drops_the_producer_of_an_in_flight_review`,
  and `reapplying_the_active_package_is_refused_and_writes_nothing`.
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
- Registering a changed source binding generation is not serialized against
  a running runtime's attempt reservation, which locks only the work item and
  does not read the subject's generation. A runtime still serving the earlier
  package can reserve an attempt under the earlier binding while or after
  apply rebinds the source, stranding it where the new runtime cannot execute
  or recover it. The race predates the activation ledger: the same
  registration ran at startup before. The mitigation is operational (stop
  every runtime on the earlier package before apply); the fix is #1723.
- `plan` sees the runtime role's membership in the migration role only through
  ownership; apply, which runs as the migration role, sees it directly.
- If reading the ledger back after a refused response entry also fails, apply
  reports a generic store failure; `caseworkctl status` then shows whether the
  activation committed.

## HTTP review fixes: source-profile input, empty inbox, moved-binding reads, strict JSON

The change closes #1443, #1467, and #1209 on the Casework HTTP boundary
(`crates/registry-casework/src/http.rs`, `review.rs`, `service.rs`, and the
BReg adapter's caller read).

### Which input decides the source profile

`POST /v1/work-items/{itemId}/decisions` and both attempt recovery routes read
`Registry-Source-Profile` and then required a `sourceProfileId` body member to
repeat it. Two inputs had to agree, so a caller could not tell which one
governed, and a mismatch was a generic `request.invalid`. The header is now
the only input, as on every other source-backed route: `DecideRequest` has no
`sourceProfileId`, and `RecoverAttemptRequest` is a closed empty object, so a
body that still names a profile is refused (`request.unprocessable`) rather
than ignored. The value Casework presents to the source adapter, binds into
the attempt lookup, and records is the header's. Nothing stored depended on
the body copy: the attempt lookup and every durable attempt already carried
the header's value. Tests:
`the_source_profile_header_alone_selects_the_profile_to_decide_and_recover`
(service_visibility) and
`decision_and_recovery_bodies_leave_the_source_profile_to_the_header`
(client http_boundary).

### What an empty-inbox refusal reveals

`GET /v1/review-tasks` without `Registry-Source-Profile` now answers
`source-profile.required` when its page would be empty, has no continuation,
and at least one candidate was skipped only because the header is absent. An
empty page cut short by its source-read budget, candidate scan, or deadline
keeps its `nextCursor` and `status` instead. The candidates are
already limited by the store to the caller's current membership and served
queues. The refusal is the static six-field problem body with no header of
its own: it names no task, request, subject, count, queue, or source, and it
is returned only in place of an empty page. What it discloses is one bit, that
the caller's queues hold at least one source-backed candidate. A page that lists anything
keeps today's behaviour. A source profile under which the source hides every
task still yields an ordinary empty page, so the refusal reveals nothing
about which tasks the source shows. Tests:
`an_inbox_emptied_only_by_the_missing_source_profile_says_so` and
`an_inbox_page_short_only_of_its_source_read_budget_continues_without_a_source_profile`
(review_http).

### A read across a binding change

A plain read of one work item, its history, and its clocks now return the
retained occurrence without actions when the source's binding generation
moved, or when the adapter refuses the caller read as `BindingMoved`.
Visibility is unchanged: the caller read still runs with the caller's own
credential under the selected source profile before anything is returned,
and `Concealed` or `Denied` still refuse the read as `work-item.not-visible`.
`SourceAdapter::read_for_caller` now states the contract this relies on:
`BindingMoved` means the source disclosed the subject to that caller. The
BReg adapter holds it, since its `BindingMoved` follows a successful
caller-credentialed record read; a record read the source answers with 409 or
412, which disclosed nothing, is now `Invalid` instead. Without a caller view
the response carries no display reference and no routing copy, so no
caller-filtered value reaches the caller from the service reader's copy. No
action is exposed across the move, and every mutation still refuses it
(`work-item.proposal-changed`). In those two cases a superseded occurrence
answers `work-item.superseded`; within one binding generation a superseded
occurrence keeps its historical read without actions, so its history stays
readable. Tests:
`a_plain_read_across_a_binding_move_returns_the_retained_item_without_actions`
(service_visibility) and
`a_conflicting_record_read_is_never_reported_as_a_moved_binding`
(casework-breg source_boundary).

### Duplicate JSON members

serde refused a duplicated field of a typed request struct, but a duplicate
inside a free-form member (a review draft body, a decision `result`, a
submitted context snapshot, `resultConstraints`) was accepted with the last
occurrence winning. A body could therefore carry a second value past
anything that read or logged the first, while the canonicalized value that
Casework hashed into the accountability digest was the last. Every mutating
route now parses with `parse_json_strict`, after the router's one MiB body
limit has bounded the bytes, and deserializes the closed type from that one
unambiguous value. A duplicate member at any depth is refused with 422
`request.unprocessable`, the class a duplicated typed field already received.
The parser inherits serde_json's recursion limit of 128. Tests:
`strict_json_accepts_one_unambiguous_document_in_a_json_media_type` and
`http_edge_returns_closed_problems_with_request_trace_and_security_headers`
(http unit tests), and one `*_refuse_a_duplicate_member` test per route
family (review_http).

### Residual risk

- The empty-inbox refusal tells a caller who omits the header that a
  source-backed candidate exists in their queues.
- An adapter other than BReg that returns `BindingMoved` from a caller read
  without the source disclosing the subject would break the documented
  contract and let a caller see the retained item without actions. Only the
  BReg adapter ships.
- The inbox still refuses a whole page with `work-item.proposal-changed` when
  the source's binding generation moved; only single-item reads changed.

### Checked issuer and JWKS URLs

The configured issuer and explicit JWKS URI use the shared checked `Url`
before authentication is constructed, refusing backslashes and host text the
URL parser rewrites with value-free `config.invalid-value` at the member.
ASCII DNS case differences, punycode and IPv6 literals remain accepted; issuer
comparison stays textual. The declared issuer may resolve to a private
address, and so may an explicit JWKS URI, which is declared configuration and
inherits the declared-issuer allowance on any origin. A discovered JWKS URI
inherits that allowance only on the same origin; a discovered cross-origin
private address is refused, and cloud metadata and link-local addresses remain
refused for declared and discovered endpoints alike. Plain HTTP remains
limited to loopback unless the runtime explicitly sets
`allowInsecureHttp: true`, in which case startup emits a fixed warning; that
setting never extends plain HTTP to a discovered cross-origin endpoint, which
must use HTTPS. Redirects remain disabled. The shared
`issuer_and_jwks_uri_are_checked_urls_when_read` test pins the new refusals and
ordinary inputs. Casework's `the_oidc_issuer_and_clients_are_the_shared_blocks`
in `crates/registry-casework/src/config.rs` pins the remote HTTP refusal at
`/authentication/oidc/issuer`, and `runtime_reads_the_explicit_http_issuer_opt_in`
there covers the explicit HTTP exception and its startup diagnostic.

### Denied signing keys and a token lifetime bound

Threat: a signing key the operator knows is compromised, or is retiring, keeps
authorizing tokens for as long as the issuer still publishes it; and an issuer
that mints long-lived access tokens extends what a stolen token can do beyond
what the deployment tolerates.

Enforcement: `authentication.oidc.deniedKids` is read by `DeniedKeyIds` in
`crates/registry-casework/src/config.rs` as at least 1 and at most 128 distinct
external key identifiers; an empty list and a 129th entry are refused at load
with the fix, and omitting the member denies no key. `verifier_profile` passes
the list to the shared verifier, whose `enforce_kid_allowed` refuses a listed
`kid` before the key set is consulted, with the same failure as an unavailable
key, so a caller cannot tell incident response from ordinary rotation; Casework
answers it as any other authentication refusal.
`authentication.oidc.maximumTokenLifetimeSeconds` accepts 1 through 7200 and is
refused at the member outside that range. When set, the shared verifier's
`enforce_max_token_lifetime` refuses a token whose `exp` minus `iat` exceeds it,
and a token missing either claim; omitting it keeps the issuer's own lifetime.

Tests: in `crates/registry-casework/src/config.rs`,
`omitting_denied_kids_and_maximum_token_lifetime_keeps_current_acceptance`,
`a_token_signed_by_a_denied_kid_is_refused_like_any_other_verification_failure`,
`a_token_outliving_the_maximum_token_lifetime_is_refused`, and
`an_empty_denied_kids_list_or_an_out_of_range_lifetime_is_refused_with_its_fix`;
`denied_key_ids_have_one_typed_contract_in_the_schema_and_reader` in
`crates/registry-casework/src/schema.rs` holds the schema to the reader; and
`oidc_rejects_denied_kid_before_jwks_lookup` and
`oidc_max_token_lifetime_rejects_missing_or_invalid_time_bounds` in
`crates/registry-platform-oidc/src/lib.rs` cover the shared enforcement.

Accepted residuals: denial is by key identifier, which the issuer assigns, so a
compromised key republished under another `kid` is accepted until that `kid` is
listed too. The denylist is runtime configuration, read when Casework starts,
so a listed key keeps authorizing on a running process until it restarts with
the change. The lifetime bound reads the token's own `iat` and `exp`, so it limits the
lifetime an issuer declared, not how long ago the token was actually minted.

### PostgreSQL support floor

Activation and startup require PostgreSQL 17 or newer. The shared activation
boundary checks the server version before observing migration or activation
relations, including an empty database. Older servers refuse with an upgrade
instruction before migrations or activation writes. The shared
`postgres_version_floor_precedes_missing_ledger_observation` database test
covers that entry point; unit tests pin the 16/17 version boundary.

## State older than the immediate predecessor

Before 1.0 a release reads only the state its immediate predecessor wrote.
The change removes what read, converted, or specifically refused state that
only releases older than v0.38.0 wrote: the version 0 reading of saved
attempt evidence in the BReg source adapter, the Mint session probe and the
per-field defaults in `caseworkctl dev` state, the by-name refusal of the
bare lifecycle hook in `caseworkctl source add`, the optional `caseworkctl`
install in the release image, and the upgrade rehearsal's steps for a
database, package, or audit table from before v0.38.0. It touches
authorization (what recovery accepts as evidence of a prepared source
action), data minimization (which lifecycle events a paired registry sends),
deployment defaults (what the release image carries), and release
provenance (what the upgrade rehearsal proves). The runtime's migrations,
its activation ledger, and its own audit guards are unchanged.

### Threat

1. Removing the version 0 reading turns saved attempt evidence that carries
   no version into evidence read under the current format, so recovery
   resumes a prepared source action from a shape this release never wrote.
2. Removing the Mint probe turns a refusal into an acceptance: a Mint-era or
   incomplete dev state file is read as current, with a missing field filled
   in by a default, and the session acts on resources that file never
   recorded.
3. A release image ships without `caseworkctl`, so the documented plan,
   apply, and doctor steps cannot run from the image the release evidence
   describes.
4. The rehearsal reports an upgrade path it never exercised, or passes while
   the upgraded runtime starts a fresh audit stream and the predecessor's
   records are no longer part of it.
5. Removing the by-name refusal of the bare `casework-lifecycle-v1` hook
   lets `source add` pair a registry that still carries it, so BReg keeps
   sending that hook's lifecycle events although Casework coordinates work
   only under the per-entity event type.

### Enforcement and defaults

- `decode_saved_attempt` in `crates/registry-casework-breg/src/lib.rs`
  requires the `version` member and accepts only the current version. Any
  other evidence is `SourceAdapterError::Invalid`, raised before the adapter
  sends a source request. Every release since the first Casework tag wrote
  version 1, so no attempt v0.38.0 can have retained is refused.
- `caseworkctl dev` reads its state strictly. A version other than the
  current one fails the ownership check, an unknown field or a missing
  recorded field is invalid retained dev state, and in every case the file
  is left untouched and no resource is changed. v0.38.0 writes version 2
  with every field present.
- `release/docker/Dockerfile.casework` installs `caseworkctl`
  unconditionally, and `release/scripts/check-debian13-images.py` refuses a
  Dockerfile that makes any operator tool conditional. v0.38.0 published
  `caseworkctl` for `linux-amd64`, the one platform the image is built for.
- `release/scripts/rehearse-upgrade.py` refuses a start before v0.38.0
  before any download or container starts, and runs the one path from it:
  the predecessor's `caseworkctl plan` and `apply`, then this release's.
  The upgraded runtime continues the predecessor's audit file, and the
  rehearsal fails when the file is empty before the upgrade or holds fewer
  records after it than before plus what the upgraded runtime must write.
- `caseworkctl source add` writes only the per-entity hook,
  `casework-lifecycle-v1-<entity>`, and never the bare one. The BReg
  compiler refuses one hook id on a second entity
  (`event.id.registry_duplicate`), and the Casework BReg adapter accepts
  only the event type a paired entity derives, so an event of the bare type
  is `SourceAdapterError::Invalid`. v0.38.0 refused the bare hook, so no
  project it paired carries one.

### Tests

1. `crates/registry-casework-breg/tests/prepared_recovery.rs`:
   `recovery_refuses_an_unsupported_saved_attempt_version_before_source_io`
   (no version, version 0, and version 2).
2. `crates/registry-caseworkctl/src/dev/tests.rs`:
   `retained_state_of_another_shape_is_invalid_without_mutation`.
3. `release/scripts/test_check_debian13_images.py`:
   `test_operator_tools_cannot_be_optional`.
4. `release/scripts/test_rehearse_upgrade.py`:
   `test_refuses_a_start_before_the_immediate_predecessor`,
   `test_main_refuses_an_earlier_start_before_any_download_or_container`,
   `test_a_stream_must_keep_the_previous_records_and_gain_the_new_ones`.
5. `crates/registry-caseworkctl/src/source_add.rs`:
   `a_bare_lifecycle_hook_is_left_as_an_authored_hook`;
   `products/casework/scripts/check-checkpoint.sh`, which runs
   `caseworkctl source add --apply` through `bregctl` on a registry that
   carries the bare hook on one request entity; and
   `crates/registry-casework-breg/tests/signed_event_intake.rs`:
   `a_lifecycle_event_type_no_paired_request_entity_derives_is_refused`.

### Accepted residuals

- **Dev state from a Mint-era session is no longer named.** It is refused
  as invalid retained state without the instruction to stop it with the
  older CLI. The changelog carries that instruction.
- **A bare lifecycle hook is no longer named.** A `registry.yaml` that
  carries one from before v0.34.0 keeps it as an authored hook, and BReg
  keeps sending its events to that hook's destination until an operator
  removes it. Casework refuses each one. The changelog carries the
  instruction to remove it.
- **The rehearsal no longer covers a start before v0.38.0.** An operator on
  an older release upgrades one release at a time, with each release's own
  rehearsal and upgrade steps.
- **The runtime still guards state older than v0.38.0.** The hosted-work
  and audit-outbox drop guards in `crates/registry-casework/src/store.rs`
  and the removed-key refusals stay as they are. Removing them needs a
  decision on a schema floor, because without one an unsupported upgrade
  from before the audit writer would drop unpublished audit rows silently.

## Deferred bounded task authorization

The stored grant now distinguishes an immediate window from explicit
`authorizationMode: deferred`, with a selected duration no longer than seven
days. Immediate defaults and serialized template bytes remain unchanged.
Short assertions and execution tokens do not extend the original grant.

The threat is delayed/restarted work needing repeated approval, or renewal
reviving, widening, or extending authority. Core template validation and the
PostgreSQL authorization-window constraints hold immediate grants to 900
seconds and deferred grants to 604800 elapsed seconds, independent of database
timezone and daylight saving changes. Casework checks the exact registered
agent, active immutable template, approver eligibility, proposal identity and
subject facts before assertion release, and checks again after source I/O.

The approver's own source access is observed only at approval, with the
approver's ephemeral credential. Later observations read the source through
the service reader and recheck Casework eligibility, proposal identity, and
subject facts, so a source-side withdrawal of that officer's access alone does
not end a grant before its deadline. Deferred mode stretches that reliance
from 900 seconds to the template's lifetime, at most seven days. This is an
accepted residual: repeating the approver's own source read at a later
observation would require Casework to retain a credential it must not keep.
Revocation, or removal of the officer's Casework eligibility, ends the grant
at its next observation, and `TASK_GRANTS.md` tells operators to use them when
source access is withdrawn and to keep deferred lifetimes no longer than the
work needs.

Retained work-item grants reuse the existing item and directory invalidation
triggers. A release withdraws authority permanently in its task transaction,
before any later reclaim, while a benign revision alone does not. Assignment
owner and absence metadata alone are not legacy grant eligibility inputs; the
existing contract continues to govern the current holder and template eligibility.

Deferred review grants bind a monotonic assignment generation maintained by a
task-row trigger. Responsibility changes increment it; draft revision changes
do not. The trigger owns the generation value even on an update attempting to
reset it. Approval captures the counter and rechecks it under the existing task
lock. Release/reclaim or reassignment back cannot revive a grant without a new
approval. A missing deferred counter fails closed. The first observed mismatch
uses the existing transactional invalidation history and audit path.

Review grant eligibility compares the request's current subject binding with
the approved one for every grant, immediate grants included. The task revision
an immediate grant pins covers the task row and not the request row, so a
subject that differs from the approved one invalidates the grant with reason
`eligibility` even when the task revision is unchanged
(`immediate_review_task_grants_refuse_a_changed_request_subject`).

Deferred grants cannot carry Evidence bounds (CASEWORK-SEC-27). Evidence checks
the earlier token and grant deadline and no grant status, and its contract that
an assertion stays usable after authority revocation only until the immutable
grant deadline assumes the 900-second immediate window. Core template
validation refuses `authorizationMode: deferred` with `bounds.type: evidence`
as `casework.task-template.deferred-evidence`; `caseworkctl check`, package
activation, and runtime project load all run it, and the generated project
schema carries the same condition. The assertion signer also refuses a stored
deferred Evidence grant, so no Evidence assertion is signed under the deferred
window. `deferred_authorization_cannot_carry_evidence_bounds` and
`task_assertion_refuses_a_deferred_evidence_grant` are the negative tests.

The core mode/window boundary test and deferred HTTP regressions exercise
restart with simulated elapsed authorization time, unrelated source revision
changes,
material proposal change, principal change, expiry, revocation, drafts,
completion, responsibility transitions, and database timezone boundaries. The simulation ages only synthetic
fixture timestamps; it does not assert a real sixteen-minute wall-clock wait.

Scheduling uses the shared platform exact-status transport before capacity
work and caps in-flight execution at the earlier token/grant deadline. The
resource servers still own their own mutations and atomic duplicate/business
limits. There is no distributed transaction between status observation and
resource commit. Temporary status/source failure refuses the current attempt;
review membership eligibility is checked when observed. Explicit revocation is
required when a withdrawal must remain effective after eligibility is restored
between observations.


## Exact supervisory request selection

The optional `requestId` query names the existing canonical request UUID. It
narrows the operational supervision list before pagination and does not change
its holder-free projection or grant reviewer, content, producer-result, or
accountability authority. No new route, store, index, or configuration is added.
The existing unique task index beginning with `request_id` supports selection.

The threat is disclosure of a shared request outside the caller's current
supervised queues, source visibility, pinned occurrence, or retention, or use
of a cursor from another selection to recover such a position. SQL membership,
served-queue, retention and exact request predicates precede the page limit.
Raw anchors must satisfy that same scope before source I/O. Existing expiring
scan checkpoints include the optional exact request selection in their caller
and profile context; omitting the selection keeps the existing context bytes.
An unknown, out-of-team, revoked, concealed or expired exact lookup returns the
neutral empty list. In particular, source concealment returns no checkpoint
even when that request has more tasks than the source-read budget. Missing
source profiles and unavailable sources keep the existing list refusals.
Accountability resolution retains its separate authorization and audit checks.

The maintained proof obligations are
`supervisory_request_lookup_precedes_pagination_and_conceals_inaccessible_requests_over_http`
in `crates/registry-casework/tests/review_http.rs` and
`supervisory_request_lookup_binds_scan_checkpoints_and_conceals_bounded_source_candidates`
in `crates/registry-casework/tests/review_postgres.rs`. They cover lookup beyond
the first page, multiple tasks, queue composition, neutral unauthorized and
source-concealed results, pinned source changes, retention, raw anchor scope,
and checkpoint selection binding. Client and binding regressions cover UUID
validation before I/O, exact query forwarding, and refusal of a response for
another request. These references are proof obligations, not execution claims.

## Retained selected outcomes and reviewer-owned discovery

The audited accountability read now returns the exact configured outcome and
its decision-time label through `decisionReceipt`. The decision transaction
stores the outcome code in the existing accountability row. The label and
policy identity come only from the request's retained immutable policy
snapshot, so a policy replacement cannot reinterpret an earlier selection.
No submitted context or structured result is read to resolve it. Approval
selects an outcome like every other decision. Fresh installation creates the outcome column directly;
no earlier selection is reconstructed during installation.

This remains the explicit audited Supervisor read, with current Supervisor
membership and service of the recorded queue. Both audit acceptance gates and
the independent accountability retention remain authoritative. It has no
source-profile input and survives result erasure as before. The new fields
grant no reviewer content access. Own receipts and own history still end at
result expiry or erasure.

The new bounded own-decisions list addresses a different threat: a previous
holder, colleague, administrator or caller using another profile must not
learn someone else's receipt, reason or submitted payload. SQL selects the
exact issuer-qualified retained decision author before the page limit, with
current membership, served queue, pinned deciding profile and retention. Each
candidate uses the existing caller-scoped source preflight, including the
pinned occurrence, and current scope is rechecked after source I/O. The only
display reference is the already retained producer correlation reference.

The existing bounded candidate, source-read, concurrency and deadline budgets
apply. Opaque scan checkpoints reuse the existing store and bind the caller,
selected profiles, queue and own-decisions view. Raw task anchors additionally
require current author scope before any source read. The author/time/task index
on existing decisions supports newest-first bounded queries; no service, store
or configuration is added. These are live walks, so scope changes may require
a refetch with the existing `410 review.result-expired` refusal.

Proof obligations are
`accountability_receipts_pin_selected_outcomes_through_independent_retention`
and `own_decisions_filter_authors_scope_and_continue_past_hidden_source_candidates`
in `crates/registry-casework/tests/review_postgres.rs`, and
`own_decision_discovery_and_audited_outcomes_are_minimal_over_http` in
`crates/registry-casework/tests/review_http.rs`. They cover the two selected
outcomes, pinned labels after policy changes, independent retention and legacy
absence, author versus prior holder, current scope, source concealment, bounded
continuation and minimal disclosure. Client regressions cover response scope,
order, receipt interpretation and native query validation. These references do
not assert that a live database or listener test has executed.

## Decided outcomes and public reasons

Threat: a producer reads a reviewer's private reasoning from the result it
receives, or settles on an approval whose meaning the policy never declared.
The private reason is accountability material; only the producer-facing
`publicReason` is meant to leave Casework.

Enforcement: every decision names a declared outcome of the pinned policy,
approval included, and `caseworkctl check` refuses a `purpose: approval`
policy without an approval outcome. A bare approval is refused with
`400 request.invalid` at `$.outcome`, reason `outcome-not-declared`, and the
`Registry-Casework-Validation-Allowed` header lists the declared IDs. Each
outcome declares `publicReason` as `required`, `optional` or `none`, with no
default. The runtime refuses a missing required public reason
(`public-reason-required`) and one the outcome does not declare
(`public-reason-not-declared`); a public reason over 2000 UTF-8 bytes is
refused as `maximum-bytes-exceeded` and a blank one or one carrying control
characters as `text-invalid`, as the private reason is, and the OpenAPI
document publishes the bound. Every approval in one stage names the same
outcome, so arrival order cannot pick the outcome released: an approval
naming another outcome than an earlier approval in its stage is refused at
`$.outcome`, reason `approval-outcome-differs`, with the chosen outcome in
the `Registry-Casework-Validation-Allowed` header, and is not recorded. The
final stage settles the request with that outcome and the public reason of
the approval that meets its threshold. Earlier stages' outcomes and reasons,
and the other approvers' public reasons, stay in the accountability record
and are not released. The ReviewResult
carries `outcome` and any `publicReason` on approved, rejected,
changes-requested and answered results and neither on cancelled or
superseded ones. The private reason stays in the accountability row and
never enters the result. The audit journal records only `publicReasonGiven`;
the published audit allow-list carries that flag and no reason text.

Verification: `rejected_cancelled_and_superseded_results_commit_atomically`
and `review_decisions_are_audited_after_the_decision_commits` in
`crates/registry-casework/tests/review_postgres.rs`, and the canary checks in
`crates/registry-casework/tests/review_http.rs`. They refuse a missing
required public reason, prove the result carries the outcome and public
reason without the private reason, and prove the audit text carries only the
flag. `reasons_over_the_byte_bound_name_the_bound` and
`input_bounds_name_the_byte_bound_before_the_text_rules` in
`crates/registry-casework-core/src/review.rs` prove an oversized reason names
the bound and a blank or control-character one stays `text-invalid`.
`an_approval_naming_another_outcome_than_its_stage_already_chose_is_refused`
and `approvals_in_one_stage_that_agree_settle_with_their_outcome` in the same
file, and `approvals_in_one_stage_must_agree_on_the_outcome_they_release` in
`crates/registry-casework/tests/review_acceptance_postgres.rs`, prove the
refusal, that it records nothing, and the agreeing settlement. These
references do not assert that a live database test has executed.

Residual: the public reason is reviewer-written free text released to the
producer; Casework bounds it but cannot judge its content. Approvers who
agree on an outcome may still write different public reasons, and only the
one from the approval meeting the threshold is released. BReg retains the
full ReviewResult, including any public reason, in its proposal review result
record until proposal retention erases it.

## Fresh schema and retained decisions

Threat and enforcement: Installation must not reinterpret retained decisions or replay responses. The creation statements write the final kebab-case values and the current task invalidation function directly. Protocol-word rewrites, legacy decision-outcome backfill, experimental hosted tables, and obsolete audit-outbox creation and removal are absent. Named refusals for populated hosted work and unpublished audit remain. No live decision, replay, ownership, or audit rule changes.

Verification: `tests/review_migration_postgres.rs::fresh_database_migrates_through_unified_reviews` and `tests/activation_postgres.rs::plan_reports_the_destructive_migration_refusals_apply_meets`. Schema-only dumps of separate fresh
installations are compared before and after, with no ledger data.

Residual: v0.40.0 does not upgrade v0.39.0 state in place; apply to a new
database. No compatibility reader or migration of earlier state is provided.


## Execution leases use the database clock

Threat: A host-written execution deadline can disagree with PostgreSQL's
clock, leaving a finished attempt live or shortening an active lease. Even a
database transaction timestamp sampled before an item-row lock wait can
consume the 30-second margin between the 330-second lease and the 300-second
source-action timeout before execution begins.

Enforcement: `reserve_attempt_for_execution` in
`crates/registry-casework/src/store.rs` writes its initial 330-second lease
with PostgreSQL `clock_timestamp()` at the INSERT after the item-row lock.
`finish_attempt` releases the lease with PostgreSQL `now()`, the transaction
clock. Recovery acquisition, execution fencing, and operator settlement
continue to use the database transaction clock. The execution token, caller
binding, state checks, locking, audit acceptance gates, and 330-second
lease duration are unchanged.

Verification: `reservation_waiting_on_item_lock_starts_a_full_execution_lease_after_unblock`
in `crates/registry-casework/tests/postgres_transactions.rs` holds the item
row lock for two seconds after observing the blocked reservation, then checks
the committed deadline against database time immediately before unlock. The
pre-fix run failed at its lease assertion. The existing
`reserving_an_attempt_sets_a_live_lease_on_the_database_clock` and
`finishing_an_attempt_releases_its_lease_on_the_database_clock` tests observe
the wall-clock reservation and transaction-clock release respectively while
returning ordinary PostgreSQL time. They check a bounded finite reservation,
refusal to recover a live lease, and immediate recovery after release through
an ordinary pool. They require no machine clock offset. The transaction suite
also covers live-lease settlement refusals, caller-scoped recovery, settlement
state checks, and audit failures.

Residual: PostgreSQL is the lease clock authority; reservation uses its wall
clock and release and recovery use its transaction clock. The initial 330
seconds start at the INSERT, so a delay between that INSERT and commit still
consumes some of the 30-second execution margin. This change adds no clock
synchronization service and does not change host-written history timestamps
or pagination lifetimes.

## Retained decision and client refusal vocabulary

A persisted decision must read as the decision that was made, and an
accountability response must not pair a receipt with another action or time.
`review_decision_receipt` in `crates/registry-casework/src/review.rs` reads the
stored word `changes-requested` as `ChangesRequested`, with its selected
outcome. The underscore spelling is refused rather than converted. Approval
still has no selected outcome.

The accountability read in `crates/registry-casework-client/src/client.rs`
checks the event identity, valid receipt, exact retained action and equal
decision time. Its enum-to-action comparison also uses `changes-requested`.
Current Supervisor membership, service of the recorded queue, retention and
audit acceptance remain authoritative. This spelling change grants no access
to a receipt or submitted content.

The Node and Python client mappings in their respective `src/lib.rs` expose
kebab-case failure words, including `invalid-request`, `header-bounds`,
`trace-context`, and `media-type`, from the same Rust failure variants. Shared
transport words come from `TransportKind::kind`. Response validation,
retryability and unknown-outcome reporting are unchanged. Callers branching
on these words must use the current vocabulary; no alias is supplied.

Proof obligations:

- `crates/registry-casework-client/tests/http_boundary.rs`:
  `accountability_receipts_must_match_the_retained_action_and_time` accepts
  matching `changes-requested`, refuses its underscore spelling, and refuses
  mismatched action and time.
- `crates/registry-casework/tests/review_postgres.rs`:
  `request_clock_completes_for_changes_requested_and_later_request_gets_fresh_budget`
  reads a persisted ChangesRequested receipt and checks its serialized
  `changes-requested` word.
- `crates/registry-casework-client-node/src/lib.rs`:
  `protocol_failures_use_the_public_snake_case_vocabulary` asserts the current
  `header-bounds`, `trace-context`, `media-type` and other protocol words.
- `crates/registry-casework-client-py/src/lib.rs`:
  `an_answer_the_binding_cannot_convert_is_a_protocol_failure_with_an_unknown_outcome`
  checks the protocol category, unknown outcome and fixed value-free message.
- `crates/registry-platform-httputil/src/client/mod.rs`:
  `every_transport_failure_reports_its_own_kebab_case_kind`.

The Python test does not enumerate every protocol word; the closed mapping
defines those words. These references do not assert that a native binding,
listener or live database test has executed.

## Inputs the immediate predecessor neither wrote nor accepted

Before 1.0 a release reads only the state its immediate predecessor wrote or
accepted. v0.40.0 was a clean break: every v0.40.0 Casework database starts
empty and is migrated to schema 21 by its own `caseworkctl apply`. The change
removes four pieces of code that recognized, by name or by shape, an input
v0.40.0 never wrote and already refused or never produced:

- the reading of a bare BReg continuation as a discovery cursor in the BReg
  source adapter;
- the by-name refusal of `casework.package.json` in a package root
  (`casework.package.retired-manifest`);
- the hidden `casework migrate` and `caseworkctl db` subcommands, which parsed
  only to refuse (`usage.removed-command` in the JSON report);
- the proof `caseworkctl dev` accepted in place of the ownership label on a
  database volume: the exact retained container mounting it.

It touches package verification (what a package root may hold), the command
surface through which a database is changed, authorization of local resource
removal (which Docker volume `caseworkctl dev` may remove), and source
discovery (what the adapter accepts as its own stored position). The
migrations, the activation ledger, the hosted-work and audit-outbox drop
guards, and the removed-key refusals are unchanged.

### Threat

1. Without the by-name refusal, a package root that holds
   `casework.package.json` verifies, and the runtime serves a directory
   `caseworkctl package` did not write.
2. Without the hidden subcommands, `casework migrate` or
   `caseworkctl db migrate` does something other than refuse: it starts the
   service, changes the database, or exits 0 so that a deployment script
   takes the database as migrated.
3. Without the container proof, a volume that carries no ownership label is
   taken as owned and removed.
4. A stored cursor that names no request entity is read as continuing some
   entity's listing.

### Why the guarded state cannot exist

- `caseworkctl package` at v0.40.0 writes `SHA256SUMS` and never
  `casework.package.json`, and the v0.40.0 runtime refused a root that held
  the file. No package v0.40.0 built or served holds it.
- `casework migrate` and `caseworkctl db migrate` already refused at v0.40.0.
  No procedure that works against v0.40.0 runs either.
- `caseworkctl dev` at v0.40.0 creates its volume with the ownership label
  and names it after a session identifier it generates. It reads only its own
  state format, which earlier releases did not write, so every session this
  release can read owns a volume v0.40.0 labeled.
- The adapter at v0.40.0 writes only cursors that name their request entity,
  into a database that began empty at v0.40.0.

### Enforcement and defaults

- `verify_casework_envelope` in `crates/registry-casework/src/config.rs`
  holds a package root to its `SHA256SUMS` through the shared package
  verification. A `casework.package.json` the sums do not list is an extra
  file, refused by name with `casework.package.invalid`. One the sums do
  list is a file `casework.yaml` does not name, refused by
  `verify_casework_contents` with `casework.package.unexpected-contents`. The
  `package.expectedDigest` pin is compared before the contents, so a listed
  file under a pin that names another digest is refused with
  `casework.package.digest-mismatch`. A root without `SHA256SUMS` is refused
  with `casework.package.invalid` whatever else it holds. Each refusal names `caseworkctl package`, and each
  is raised before the database is opened.
- `command` in `crates/registry-casework/src/runtime.rs` declares one
  subcommand, `serve`, and requires a subcommand. `caseworkctl` declares no
  `db` subcommand. The argument parser refuses either word as an
  unrecognized subcommand with exit 2 before any configuration is read:
  `casework` prints the parser's usage error, and `caseworkctl` prints its
  usage error or, with `--format json`, reports `usage.invalid` in a
  `CaseworkUsageReport`. Only `caseworkctl apply` resolves the migration
  credential, as before.
- `verified_volume_name` in `crates/registry-caseworkctl/src/dev/mod.rs`
  accepts a volume only when its name is the session's and its ownership
  label carries the session's identifier. Every other volume, including one
  with no labels, is refused with "database volume ownership differs from
  retained local state; no resource was changed" before any removal.
- `discovery_position` in `crates/registry-casework-breg/src/lib.rs` decodes
  a cursor only as a position that names its request entity. Any other
  shape is `SourceAdapterError::Invalid`, raised before a listing is
  requested, and an entity the source no longer declares is refused the same
  way.

### Tests

1. `crates/registry-casework/src/config.rs`:
   `a_stray_casework_package_json_is_refused_as_any_file_the_package_does_not_list`
   (unlisted, listed, and without `SHA256SUMS`).
2. `crates/registry-casework/src/runtime.rs`: `serve_is_the_only_subcommand`;
   `crates/registry-casework/tests/command_line.rs`:
   `casework_migrate_is_refused_as_an_unrecognized_subcommand`, which runs the
   binary with and without `--runtime-config` and compares the refusal with
   the one for a word that was never a command.
3. `crates/registry-caseworkctl/src/lib.rs`:
   `db_is_refused_as_an_unrecognized_command` (human and JSON output).
4. `crates/registry-caseworkctl/src/dev/tests.rs`:
   `a_volume_without_the_owner_label_is_never_removed` and
   `volume_removal_requires_the_retained_owner_label`.
5. `crates/registry-casework-breg/tests/signed_event_intake.rs`:
   `a_bare_continuation_is_refused_like_any_malformed_discovery_cursor` (one
   request entity and several).

### Accepted residuals

- **The replacement commands are no longer named.** A script that still runs
  `casework migrate` or `caseworkctl db migrate` gets the argument parser's
  usage error with exit 2, without the instruction to run `caseworkctl plan`
  then `caseworkctl apply`. The changelog and the deployment guide carry
  that instruction.
- **A retired package manifest is no longer named.** A root that holds
  `casework.package.json` is refused as holding an extra file, without the
  sentence that Casework no longer reads it. The refusal still names
  `caseworkctl package`, which writes a root without it.
- **An unlabeled dev volume is never reclaimed.** A volume named for the
  session that carries no ownership label is left in place and the command
  refuses. An operator who has one removes it with Docker.
- **A bare stored cursor stops discovery for its source.** A database that
  held one, which no supported upgrade produces, would have that source's
  discovery refused on every pass that resumes from it. No listing is
  requested from the source under it.
- **Schema versions before the predecessor's are still handled.** The
  `EFFECTS_SCHEMA_VERSION` comparison in
  `crates/registry-casework/src/activation.rs` stays: on a database older
  than the review tables it is what lets `caseworkctl plan` and `apply`
  reach the named hosted-work and audit-outbox drop refusals instead of a
  database error. It leaves with the decision on those guards.
