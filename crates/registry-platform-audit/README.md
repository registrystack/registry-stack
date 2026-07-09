# registry-platform-audit

Tamper-evident audit envelopes, async sinks, JSONL verification, and redaction
helpers for registry services.

## What It Provides

- `ChainState` for serialized append-only audit chains.
- `AuditEnvelope` records with ULID ids, timestamps, previous hashes, payloads,
  and record hashes.
- `AuditSink` for pluggable persistence.
- Built-in `JsonlFileSink`, `JsonlStdoutSink`, and `SyslogSink`.
- `verify_chain` and `verify_jsonl_lines` for retained audit consistency
  checks.
- `AuditChainProfile`, `AuditProfile`, `AuditKeyHasher`, and `redact` helpers
  for production keyed chains and privacy-safe audit fields.
- `AuditKeyHasher::audit_reference_hash` for versioned, scoped audit reference
  handles whose service-owned canonical input stays outside the platform domain.
- `AuditKeyHasher::sensitive_value_hash` for generic field-bound audit lookup
  values used by redaction helpers.

## Typical Use

```rust
use registry_platform_audit::{AuditProfile, JsonlFileSink};
use serde_json::json;

async fn write_audit_event() -> Result<(), registry_platform_audit::AuditError> {
    let sink = JsonlFileSink::new("audit.jsonl");
    let profile = AuditProfile::registry_notary_from_env("REGISTRY_AUDIT_HASH_SECRET")?;
    let chain = profile.bootstrap_or_start_empty(&sink).await?;

    let envelope = chain
        .append(&sink, json!({
            "event": "credential.issued",
            "subject_ref": profile.key_hasher().hash("did:example:123"),
        }))
        .await?;

    assert!(envelope.prev_hash.is_some() || chain.last_hash().await.is_some());
    Ok(())
}
```

## Operational Notes

- `JsonlFileSink::new` rotates at 10 MiB and retains 50 files by default.
- `JsonlFileSink::with_rotation(path, 0, max_files)` disables size rotation.
- `AuditProfile::bootstrap_or_start_empty` and
  `AuditChainProfile::bootstrap_or_start_empty` read the sink tail hash before
  new appends, which is the normal startup path for persistent sinks.
- `JsonlStdoutSink` and `SyslogSink` cannot report a historical tail hash, so
  each process starts a fresh chain unless a consumer stores the tail elsewhere.

## Security Notes

- The chain APIs detect edits, insertions, deletions after the first retained
  envelope, and reordered envelopes inside the verified record set. The first
  retained envelope's `prev_hash` is the retained-set boundary.
- The chain APIs prove internal consistency of retained records. They do not
  prove completeness, detect deletion of leading retained records, or detect a
  self-consistent full rewrite by an actor who can replace all retained logs.
- Off-host audit shipping is the completeness guarantee. Evidence-grade Relay
  and Notary deployments refuse startup when a local `file` or `jsonl` sink is
  used without declaring off-host shipping.
- The chain does not replace durable storage, retention policy, clock integrity,
  or off-host log shipping.
- Use `AuditProfile::registry_relay_from_env` or
  `AuditProfile::registry_notary_from_env` in production. `unkeyed_dev_only` is
  for tests and local development.
- Use `AuditKeyHasher::audit_reference_hash` for durable audit references
  instead of concatenating ad hoc hash inputs in each service. Keep service
  semantics and canonicalization in the consuming service.
- Redaction helpers intentionally avoid preserving email local parts, phone
  digits, or sensitive query values.

## Testing

```sh
cargo test -p registry-platform-audit
```

## License

Apache-2.0.
