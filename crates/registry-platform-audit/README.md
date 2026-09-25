# registry-platform-audit

The audit writer, keyed audit references, redaction helpers, and the shared
authorization event shape for Registry Stack services.

## What It Provides

- `AuditWriter`, the one audit writer every product uses. It appends one JSON
  object per line (`schema`, `eventId`, `time`, `phase`, `correlation`,
  `record`): a `request` entry before protected I/O and a `response` entry with
  the outcome, both carrying the same `correlation`.
- `AuditDestination::File` (durable: fsync with group commit, size rotation,
  age-based retention) and `AuditDestination::Stdout` (one flushed line per
  entry, best-effort).
- `AuditProfile` and `AuditKeyHasher` for production keyed references derived
  from one deployment secret.
- `AuditKeyHasher::audit_reference_hash` for versioned, scoped audit reference
  handles whose service-owned canonical input stays outside the platform domain.
- `AuditKeyHasher::sensitive_value_hash` for generic field-bound audit lookup
  values used by redaction helpers.
- `redact` helpers for query strings, email addresses, and phone numbers.
- `AuthorizationAuditEvent` for one privacy-safe authorization event shape
  across products, using pseudonyms from each product's existing audit profile.
- `require_audit_under` to keep an audit path under a persistent root.

## Typical Use

```rust
use registry_platform_audit::{
    AuditDestination, AuditEntry, AuditProfile, AuditWriter, FileDestination,
};
use serde_json::json;

async fn write_audit_entries() -> Result<(), Box<dyn std::error::Error>> {
    let profile = AuditProfile::production_from_env("REGISTRY_AUDIT_HASH_SECRET")?;
    let destination = FileDestination::new("/var/lib/registry/audit/audit.jsonl")?;
    let writer = AuditWriter::open(AuditDestination::File(destination)).await?;

    let subject_ref = profile.key_hasher().hash("did:example:123");
    writer
        .append(AuditEntry::request(
            "registry.example.audit/v1",
            "request-1",
            json!({ "operationId": "credential.issue", "subjectRef": subject_ref }),
        ))
        .await?;
    // ... protected I/O happens only after the request entry is accepted ...
    writer
        .append(AuditEntry::response(
            "registry.example.audit/v1",
            "request-1",
            json!({ "operationId": "credential.issue", "outcome": "success" }),
        ))
        .await?;
    Ok(())
}
```

## Operational Notes

- The file destination takes a process-lifetime single-writer lock beside the
  active file. Each process writes its own stream; run one path per process and
  aggregate in the log pipeline.
- The file destination refuses a directory that is group- or world-writable
  and keeps its files owner-only.
- A failed write stops the writer until restart, so every later audited request
  fails closed.
- `stdout` is best-effort by nature: a flush does not prove the entry reached
  durable storage.

## Security Notes

- Entries are not hash-chained. Tamper evidence is a deployment concern: ship
  the stream to append-only storage or a SIEM that the service cannot rewrite.
- Use `AuditProfile::production_from_env` or
  `AuditProfile::production_from_secret_bytes` in production.
  `unkeyed_dev_only` is for tests and local development.
- The identifier key is an HKDF-derived sub-key of the deployment secret. Its
  derivation and the reference framing are pinned by known-answer tests, so
  keyed references stay stable across releases.
- Use `AuditKeyHasher::audit_reference_hash` for audit references
  instead of concatenating ad hoc hash inputs in each service. Keep service
  semantics and canonicalization in the consuming service.
- `AuthorizationAuditEvent` accepts only platform hash handles and Evidence's
  established key-versioned pseudonyms for principal, client, grant, and
  approver identity fields. It does not derive keys or replace a product's
  pseudonym scope policy.
- Redaction helpers intentionally avoid preserving email local parts, phone
  digits, or sensitive query values.

## Testing

```sh
cargo test -p registry-platform-audit
```

## License

Apache-2.0.
