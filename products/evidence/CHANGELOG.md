# Registry Evidence changelog

## Unreleased

- BREAKING: write audit through the shared platform audit writer instead of
  the keyed hash chain. Every entry is one JSON line with the members
  `schema`, `eventId`, `time`, `phase`, `correlation`, and `record`: an access
  attempt is a `request` entry, every terminal record a `response` entry, and
  `correlation` is the record's `operation`. Entries are not chained; ship
  them to append-only storage for tamper evidence.
  - The entry schemas are `registry.evidence.audit/v2`,
    `registry.evidence.audit.request-batch/v2`, and
    `registry.evidence.audit.authorization-refusal/v2`. The record no longer
    carries a `schema` member, and readers written for the chained `/v1`
    records do not read `/v2` entries.
  - The bundle `audit` section is now `hashKeyRef` and `hashKeyVersion`, both
    required. `format`, `hashSecretRef`, and `failClosed` are refused; every
    audit gate stays fail closed. Pseudonyms keep their
    `hmac-sha256:v<hashKeyVersion>:` prefix and are byte-identical for the same
    master and version.
  - The runtime `auditStorage` block is replaced by `audit`: `destination`
    (`file` by default, or `stdout`), `path` (required for `file`),
    `rotateBytes` (at least 1 MiB, 100 MiB by default), and `retainDays` (1 to
    36,500, 90 by default). Sealed files older than `retainDays` are deleted
    when the writer opens or rotates. `maximumFileBytes` is refused.
    `evidence check --require-audit-under` refuses a `stdout` destination.
  - `evidence verify-audit` is removed, and startup no longer verifies a chain.
    The runtime can no longer detect an audit master replaced without a
    `hashKeyVersion` change; the documented key rotation procedure owns that.
  - The `evidence_audit_segments` and `evidence_audit_bytes` metrics are
    removed.
  - `evidencectl doctor` checks a file audit destination with the audit
    writer's own rule and skips a `stdout` destination. `evidencectl target
    new` and the local bundles and runtime files `evidencectl` renders write
    the new `audit` blocks.
  - To migrate, rewrite the bundle `audit` section to `hashKeyRef` and
    `hashKeyVersion` and the runtime `auditStorage` block to `audit`, archive
    the old chained audit files to append-only storage, and point
    `audit.path` at a fresh file in a directory that holds no old sealed
    segments: retention deletes sealed files under the same name older than
    `retainDays`. Update audit readers to the `/v2` envelope
    before routing traffic to the new runtime.
