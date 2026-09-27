# Base Registry Engine changelog

## Unreleased

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
