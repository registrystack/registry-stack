# Base Registry Engine changelog

## Unreleased

- BREAKING: the database records every activation, the initial one included,
  as one row of `registry_internal.registry_migrations`, keyed by a UUID
  activation id and ordered by `apply_order`. Each row names the package
  digest, its predecessor digest, the `registryRevision`, the plan and
  migration kinds, the role mode, and the runtime role.
  - `registry_internal.registry_state` records the active package digest
    and the active activation id instead of a package revision, an
    environment, an instance id, and a package sequence, and holds the
    instance claim. The `registry_internal.registry_instance_claim` table is
    gone.
  - Records, the revision journal, captured outbox and delivery rows, audit
    entries, and import authorities name the activation that wrote them by
    its activation id wherever they named a package revision. Webhook event
    data and ingestion runs keep naming the active package by its digest as
    `packageRevision`, since a client knows the package it holds, not the
    activation the database recorded for it.
  - `bregctl apply` reports `activationId` instead of `packageSequence`.
  - Reconciliation audits under `breg-migration-reconcile-audit/v3`, naming
    `packageDigest`, `targetPackageDigest`, and `activationId` instead of
    `packageRevision`, `targetPackageRevision`, and `packageSequence`.
  - Webhook events take their `source` from the runtime `identity.instanceId`.
  - `breg` refuses to start on a database that records no activated package,
    naming `bregctl apply --package DIR --initial`, and on a database that
    predates the activation ledger, naming `bregctl apply --package DIR`. It
    checks the package pin and the physical instance claim before it reads the
    recorded identity, and `bregctl instance-claim` refuses a package root the
    runtime `package.expectedDigest` does not pin before it connects.

- `bregctl instance-claim adopt` also runs on a database the instance claim
  already names, as after a point-in-time recovery, a snapshot, or a base
  backup, which keep the claim matching and reopen every import authority
  closed after the backup point. It claims the database again with a raised
  epoch and supersedes every open import authority in one transaction,
  audited under `breg-instance-claim-audit/v1` with the event `reclaimed`.
  Run it once after any restore, before the database serves. The
  `instance_claim.already_current` refusal is gone.

- A runtime file refused as `runtime_config.document` says which field is
  wrong and why, such as an unknown `audit.destination` and the destinations
  it accepts, without repeating the refused value, in `bregctl doctor`,
  `bregctl verify`, and every other command that reports it. A
  removed package key is refused before any environment expression in its
  value is substituted, and the runtime file is read through the shared
  runtime configuration loader.

- BREAKING: an Evidence source export names the compiled model it came from
  as `provenance.registryRevision` instead of `provenance.packageRevision`,
  so `evidencectl` reports changed provenance for every BReg source on its
  next import.

- A runtime file may name one role as both `database.roles.migration` and
  `database.roles.runtime`, and then one reference as both
  `database.runtimeUrlRef` and `database.migrationUrlRef`. Two distinct roles
  still need two distinct references. With one role, `bregctl apply` grants
  that role nothing beyond the ownership it already holds and revokes only
  from `PUBLIC`, and `breg` serves as the owner of the registry schema.

- BREAKING: the schema fingerprint no longer measures the runtime role's
  grants, so one package fits a database served with one role or with two.
  Every package's schema fingerprint changes; rebuild each package with this
  `bregctl package`.

- BREAKING: `registryRevision` is a function of the compiled model only. The
  project's `package` block no longer appears in
  `compiled/effective-model.json`, so a project that declares a package
  identity compiles to a different `registryRevision` than it did before, and
  two projects that differ only in their package identity compile to the same
  one.

- BREAKING: a package is environment neutral and unsigned. One package built
  by `bregctl package` is the unit an operator promotes through every
  environment, and its identity is its package digest, the SHA-256 of its
  `SHA256SUMS`.
  - A project's `package.environment`, `package.instanceId`, and
    `package.sequence` are refused with `package.environment.removed`,
    `package.instance_id.removed`, and `package.sequence.removed`. Move the
    environment and the instance id to the runtime file's `identity`, and
    delete the sequence: a package names its predecessor through
    `migrationPlan.fromPackageDigest`. `package.sourceRevision` stays.
  - The manifest is `package/v2`. It no longer carries `packageRevision`,
    `environment`, `instanceId`, `databaseId`, `sequence`, `priorRevision`,
    `signaturePolicy`, or signatures, and `migrationPlan.fromRevision` is
    `fromPackageDigest`. A `package/v1` package is refused; rebuild it with
    `bregctl package`.
  - Trust anchors, package signatures, and the signing input are gone. A
    runtime file's `package.trustAnchorPath`, `package.activeRevision`,
    `package.activeSequence`, and `package.compilerSourceRevision` are refused
    with `runtime_config.package_key_removed`, naming what to do instead.
    `package.root` and `package.expectedDigest` stay.
  - A runtime file's `identity.instanceId` follows the grammar the project's
    `package.instanceId` had, a lowercase letter then at most 63 lowercase
    letters, digits, `-`, or `_`, and is refused otherwise with
    `runtime_config.invalid_instance_id`. `identity.environment` must equal
    `identity.databaseInitializationEnvironment`, or the file is refused with
    `runtime_config.environment_identity_conflict`.
  - A package without `SHA256SUMS`, built by an earlier `bregctl`, is no
    longer read as a predecessor through its signature. Rebuild it with this
    `bregctl`.
  - `bregctl package` and `bregctl test` drop `--database-id`,
    `--signature-threshold`, `--signature-key-id`, and `--signatures`, and
    `--baseline-runtime-config` is `--baseline-package DIR`, the predecessor
    package directory. Each retired flag exits 2 and names its replacement.
    `bregctl package` writes the package with its sum file and prints the
    package digest.
  - The schema-test receipt is `breg-schema-test-receipt/v2`. It drops the
    environment, instance id, database id, sequence, candidate revision, and
    signing input digest, and names the predecessor by `priorPackageDigest`.
    Its source closure also binds each reviewed migration file by path and
    digest, so a changed descriptor, statement, or rehearsal file makes the
    receipt stale. `bregctl test` no longer compares the runtime identity
    with the candidate.
  - A reviewed migration file outside the package layout, such as a backup
    binding, is refused when the package is built. The backup binding is an
    apply input only (`bregctl apply --backup`).
  - Reports name packages by `packageDigest` instead of a package revision,
    including `bregctl dev status`. `bregctl dev` keeps no package sequence,
    writes no trust anchor or active-package keys, and takes its event source
    from the runtime `identity.instanceId`.
  - The database records the active package digest. An initial apply accepts
    a package that names a predecessor. Applying a package that does not
    follow the active one is refused as `apply.package.refused`, which also
    covers a package older than the active one. An empty migration plan is
    refused before database authority, and `migration reconcile` refuses the
    active package as its target before database authority.

## v0.35.0 - 2026-09-28

- Upgrade a registry whose active package the previous `bregctl` release
  built. A package without the shared `SHA256SUMS` envelope is read as the
  predecessor by `diff --runtime-config`, `test --baseline-runtime-config`,
  `package --baseline-runtime-config`, `apply`, and the field-encryption
  preflight,
  verified from its signed manifest: the BReg signature against the trust
  anchor, every file's digest, and a closure that refuses any file the
  manifest does not list, including a stray `SHA256SUMS` or `REVISION`. Test,
  package, and apply a successor with this `bregctl`; do not rebuild the
  active package, which changes its revision and schema fingerprint.
  - `breg` startup, `verify`, and `migration explain` still refuse a
    package without `SHA256SUMS`, and say to apply a successor with this
    `bregctl`.
  - A runtime configuration that pins `package.expectedDigest` on such a
    predecessor is refused with `package.digest_pin_unverifiable`; remove the
    pin until the successor is active.
  - The migration rehearsal in `test` no longer refuses when the predecessor
    schema this compiler installs measures differently from its signed
    fingerprint, which a predecessor built by an earlier release always does.
    The test report carries the finding
    `migration.rehearsal.baseline_fingerprint_drift` with both fingerprints.
    A predecessor schema that cannot be installed is still refused with
    `migration.rehearsal.baseline_not_reproducible`, and the rehearsed
    migration must still reach the candidate fingerprint.
  - The migration rehearsal installs the predecessor schema the successor
    plan was computed from, so a successor of a package built before
    compiler-owned reference indexes no longer fails its rehearsal with
    `migration.rehearsal.compiler_statement_failed` on the index it adds.
  - `diff --runtime-config` classifies changes against the running package's
    signed migration baseline, so it reports an index the successor plan
    creates, such as a compiler-owned reference index, as a lock risk.
  - A registry activated by an earlier release records no instance claim, so
    `breg` refuses to serve it after the first successor apply on this
    release until the operator runs `bregctl instance-claim adopt
    --acknowledge-original-retired` once against its runtime configuration.

- Answer every audited request entry. A read, mutation, action, or request
  action that ends after its attempt without a terminal or refusal entry,
  because it failed, timed out, or its caller went away, writes a response
  with the phase `unfinished` under the same correlation. A read that fails
  after its rows were read writes the Refused terminal, and a terminal the
  destination refuses is logged instead of discarded.
  - A reviewed change-request apply records its attempt before the receipt
    preflight's reads and the review authority, and holds it through the
    action.
  - `migration reconcile` answers a transition that fails after its request
    entry with a `failed` response.
  - `request-retention erase` answers a refused or failed erasure with a
    `refused` or `failed` response, deletes the external attachment objects
    before it records a committed erasure, and records how many objects still
    wait for deletion. An erasure that committed without its response entry
    reports `request_retention.erasure.unaudited`. `request-retention
    cleanup-attachments` answers a failed cleanup with a `failed` response.
  - `history rebaseline`, a standalone `history erase`, and a
    field-encryption erase-and-rebaseline run answer their request entry with
    an `unfinished` response when they are refused or fail before their
    terminal entry, as does an attachment verification job that stops early.
  - `evidence-retention erase-expired` is audited under
    `breg-evidence-retention-audit/v1`: a request entry naming the cutoff
    before the erasure, and a response with the erased count or `failed`.
  - An ingestion run creation, cancellation, chunk replay, or receipt
    recovery refused after its `breg-ingestion-audit/v1` request entry is
    answered in that schema with a `refused` response, and not recorded again
    as a general refusal. A transition whose commit returned an error is
    answered `unfinished`, since that error does not prove a rollback.
  - Event delivery records a terminal outcome and a payload expiry only after
    the delivery state commits. An attempt whose lease commit fails is
    answered with `worker_interrupted`. A terminal outcome whose commit
    failed and cannot be read back is answered `worker_interrupted` with
    disposition `unknown`, which claims no delivery state. An operator replay writes a
    `replay_requested` request before the reset and a `replay_committed` or
    `replay_refused` response after it, or `replay_unfinished` when the
    reset's commit failed and its fate cannot be read back.

- BREAKING: write audit through the platform audit writer instead of a
  hash-chained journal in PostgreSQL. Each process opens one writer at
  startup and writes JSON Lines entries `{schema, correlation, phase, time,
  record}` to a file or to standard output. Nothing audit-related is stored
  in PostgreSQL any more.
  - The runtime configuration's `audit` section gains `destination` (`file`,
    the default, or `stdout`), `path` (required for `file`, absolute),
    `rotateBytes` (default 100 MiB) and `retainDays` (default 90).
    `hashKeyRef` still names the key that derives keyed references, and
    reference derivation is unchanged. A runtime configuration without
    `audit.path` is refused at startup.
  - A request writes a `request` entry before protected I/O and a `response`
    entry sharing its correlation before any disclosure. A mutation writes its
    response entry after its transaction commits; if the writer refuses it,
    the effect stays committed, the caller receives the audit-unavailable
    refusal, and a retry with the same idempotency key replays the stored
    result as an audited replay.
  - Audit schemas move to `breg-audit/v2`, `breg-webhook-audit/v2`,
    `breg-history-erasure-audit/v2`, `breg-history-rebaseline-audit/v2`,
    `breg-migration-reconcile-audit/v2` and
    `breg-field-encryption-audit/v2`. Attachment verification, attachment
    cleanup and ingestion-run records, which had no schema of their own, are
    `breg-attachment-verification-audit/v1`,
    `breg-attachment-cleanup-audit/v1` and `breg-ingestion-audit/v1`.
  - `bregctl` lifecycle commands that audit (`history erase`, `history
    rebaseline`, `field-encryption erase-history` and `migration reconcile`)
    write to their own sibling file beside the runtime's `path`, named
    `<stem>.bregctl.<extension>` (`audit.bregctl.jsonl` for `audit.jsonl`),
    and report `*.audit.unavailable` when it cannot be opened.
  - `bregctl audit verify`, `audit export` and `audit prune` are removed,
    with their `audit.*` diagnostics. Rotation and retention of the audit
    files replace pruning; ship or verify them with the log tooling that
    already reads your other JSON Lines files.
  - The `registry_internal.registry_audit` and `registry_audit_head` tables
    leave the managed catalog. The next `bregctl apply` against an existing
    database refuses while either table still holds rows, naming them and
    asking the operator to archive the rows first; passing
    `--acknowledge-retired-audit-discard` acknowledges discarding them and lets
    the apply drop the tables. The history-erasure coverage a successor
    package relies on, and field-encryption erase progress, are recorded in
    `registry_internal` state tables instead of being read back from audit.
    The managed catalog fingerprint changes, so every package must be rebuilt
    and signed again.
  - `bregctl doctor` checks that the audit destination is writable without
    opening it, so it runs beside a serving process. Two processes cannot
    share one audit file: a second runtime needs its own `path`.
  - To migrate, export the old journal with the previous release's `bregctl
    audit export` if you must retain it, add `audit.path` to each runtime
    configuration, then rebuild, sign and `bregctl apply` the package. If the
    database still carries rows in `registry_audit` or `registry_audit_head`,
    archive them first (for example with `psql` or `pg_dump --table`), then
    apply with `--acknowledge-retired-audit-discard`.
