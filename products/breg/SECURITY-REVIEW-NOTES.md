# Base Registry Engine security review notes

Review notes for security-sensitive Base Registry Engine changes, held in
tracked material because commit messages do not survive a squash. Each
section names the change, the threat it answers, the defaults it ships, where
Rust enforces it, the tests that pin it, and the residual risk it accepts. The
security-invariant matrix in `contracts/security-invariant-matrix.yaml` is the
row-per-invariant baseline; this file is the narrative behind the decisions
and the residuals the matrix rows do not state.

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
  The authority binds the package revision active when it opened, and an
  activation supersedes it.
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
  package revision as context, so one operator's reference hashes differently
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
window the operator closed after the backup (BREG-SEC-116), or, for a
registry that predates the claim, claim itself on its first apply
(BREG-SEC-117).

### Enforcement and defaults

- Startup and every readiness probe compare the claim with the live
  database: the system identifier when both expose it, the database oid
  alone otherwise. A mismatch refuses startup and answers readiness 503 with
  `startup.instance_claim.mismatch`.
- The runtime role holds `SELECT` only on the claim.
- The claim is recorded only into a fresh database, one with no committed
  revision and no commit head, so an existing registry must be adopted once
  after its first apply on this release (a documented breaking step).
- `adopt --acknowledge-original-retired` moves the claim under the migration
  role, raises its epoch, and supersedes every open import authority in one
  transaction, then appends the audit response.

### Tests

`crates/registry-breg/tests/postgres_startup.rs`:
`a_restored_copy_refuses_to_serve_until_adopted`.
`crates/registry-breg/tests/postgres_import_authority.rs`:
`the_runtime_role_cannot_rewrite_or_remove_the_instance_claim`,
`adopting_a_restored_copy_supersedes_every_open_authority`,
`installing_the_claim_beside_committed_history_leaves_the_database_to_adopt`.

### Accepted residuals

- **Physical copies are not detected.** Point-in-time recovery, storage
  snapshots, and base backups keep the system identifier and database oid, so
  the copy matches the claim and serves without adoption, and an import
  authority closed after the backup point is open again on it. BREG-SEC-116
  holds for logical restores only. Fencing the original stays with the
  operator; after a physical restore, list and close every open import
  authority before serving.

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

The change wraps the signed BReg package in the shared package envelope
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
  to the per-file digest the shared verification recorded, so the signature,
  trust, environment, database, revision, and sequence checks run over the
  verified bytes.
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

## Upgrading from a package built before the shared envelope

The change lets predecessor reads accept a BReg package built by the
previous `bregctl` release, which has no `SHA256SUMS` or `REVISION`, and makes
the migration rehearsal's predecessor fingerprint comparison advisory
(`verify_predecessor_shared_package` in `crates/registry-breg/src/package.rs`,
`RuntimeConfig::verify_predecessor_package_envelope` in
`crates/registry-breg/src/runtime_config.rs`, and `rehearse_in_transaction` in
`crates/registry-breg/src/postgres/rehearsal.rs`).

### Threat

A live registry runs a package the previous release built. Without these
changes the operator cannot test, package, or apply a successor, so an
upgrade stalls. Relaxing the checks for that case must not let a package
that is unsigned, altered, or swapped act as a predecessor. It must not skip
a pinned digest silently, and it must not reach the runtime or a successor
load (release provenance).

### Enforcement and defaults

- The fallback runs only when shared verification reports a missing
  `SHA256SUMS`, and only on the predecessor reads: the `diff
  --runtime-config` baseline, the `test` and `package` baselines, the `apply`
  active package, and the field-encryption preflight. `breg` startup,
  candidate loads, `verify`, and `migration explain` stay strict. They refuse with `package.integrity_refused` and say to
  test, package, and apply a successor with this `bregctl`.
- A predecessor without the envelope still passes every signed-manifest
  check. The signature must verify against the configured trust anchor, and
  every file must match the size and digest its manifest records. Any file
  the manifest does not list is refused by the closure check, and that
  includes a stray `SHA256SUMS` or `REVISION`. The environment, instance,
  database, revision, and sequence bindings still apply.
- When the runtime configuration sets `package.expectedDigest`, the fallback
  refuses with `package.digest_pin_unverifiable`, because a pin cannot be
  checked on a package without `SHA256SUMS`.
- The rehearsal's predecessor fingerprint comparison is advisory. The package
  manifest does not record which engine release built it, and the managed
  catalog includes tables the engine owns, so a predecessor signed by an
  earlier release always drifts. A drift is reported as
  `migration.rehearsal.baseline_fingerprint_drift`, with the signed and the
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

`crates/registry-breg/tests/postgres_package.rs`:
`predecessor_built_before_the_shared_envelope_verifies_from_its_signed_manifest`,
`predecessor_without_the_shared_envelope_keeps_every_signed_manifest_check`,
`package_without_the_shared_envelope_is_refused_outside_predecessor_reads`.
`crates/registry-breg/tests/runtime_config.rs`:
`predecessor_without_shared_envelope_is_accepted_only_without_a_digest_pin`.
`crates/registry-bregctl/tests/cli.rs`:
`package_without_the_shared_envelope_is_refused_by_verify_with_the_successor_fix`,
`package_baseline_without_the_shared_envelope_is_read_unless_a_digest_pin_is_configured`,
`diff_reads_a_running_package_without_the_shared_envelope_unless_a_digest_pin_is_configured`,
`field_encryption_preflight_reports_the_digest_pin_on_a_predecessor_without_the_shared_envelope`.
`crates/registry-breg/src/tooling.rs`:
`a_signed_baseline_without_an_index_reports_the_index_the_plan_adds`.
`crates/registry-breg/tests/postgres_migration.rs`:
`real_postgres_rehearsal_refuses_a_reviewed_plan_activation_would_refuse`
covers both a drift that is reported and a final mismatch that is still
refused, and
`real_postgres_rehearsal_refuses_a_predecessor_it_cannot_install` covers the
install refusal.
`crates/registry-breg/tests/postgres_reference_indexes.rs`:
`the_rehearsal_installs_a_predecessor_baseline_without_reference_indexes`.
`products/breg/scripts/test-adopter-workflow.sh
--from-release` runs the upgrade from the previous release end to end.

### Accepted residuals

- A predecessor without the envelope has no package digest, so it cannot be
  pinned; it is bound only by its signature and the active revision in the
  runtime configuration. `SHA256SUMS` is unsigned, so the signed manifest
  already carried every integrity guarantee the fallback relies on, and the
  closure reader still refuses symbolic links and special files.
- The same-engine fingerprint comparison no longer stops `test`. Because the
  predecessor fingerprint is signed, a drift under the same engine can only
  come from compiler nondeterminism, and the strict final check still
  catches any effect on the candidate.
