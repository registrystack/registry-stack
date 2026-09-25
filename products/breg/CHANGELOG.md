# Base Registry Engine changelog

## Unreleased

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
    leave the managed catalog, and the next `bregctl apply` drops them from
    an existing database. The history-erasure coverage a successor
    package relies on, and field-encryption erase progress, are recorded in
    `registry_internal` state tables instead of being read back from audit.
    The managed catalog fingerprint changes, so every package must be rebuilt
    and signed again.
  - `bregctl doctor` checks that the audit destination is writable without
    opening it, so it runs beside a serving process. Two processes cannot
    share one audit file: a second runtime needs its own `path`.
  - To migrate, export the old journal with the previous release's `bregctl
    audit export` if you must retain it, add `audit.path` to each runtime
    configuration, then rebuild, sign and `bregctl apply` the package.
