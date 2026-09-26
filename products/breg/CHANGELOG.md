# Base Registry Engine changelog

## Unreleased

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
    as a general refusal.
  - Event delivery records a terminal outcome and a payload expiry only after
    the delivery state commits. An attempt whose lease commit fails is
    answered with `worker_interrupted`. An operator replay writes a
    `replay_requested` request before the reset and a `replay_committed` or
    `replay_refused` response after it.

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
