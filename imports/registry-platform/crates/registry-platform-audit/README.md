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
- `verify_chain_with_anchors` and `verify_jsonl_lines_with_anchors` for
  verification against trusted start or tail/head hashes stored outside the
  JSONL logs.
- `AuditChainProfile`, `AuditProfile`, `AuditKeyHasher`, and `redact` helpers
  for production keyed chains and privacy-safe audit fields.

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

- `JsonlFileSink::new` rotates at 10 MiB and retains 5 files by default.
- `JsonlFileSink::with_rotation(path, 0, max_files)` disables size rotation.
- `AuditProfile::bootstrap_or_start_empty` and
  `AuditChainProfile::bootstrap_or_start_empty` read the sink tail hash before
  new appends, which is the normal startup path for persistent sinks.
- `JsonlStdoutSink` and `SyslogSink` cannot report a historical tail hash, so
  each process starts a fresh chain unless a consumer stores the tail elsewhere.

## Security Notes

- The unanchored chain APIs detect edits, insertions, deletions, and reordered
  envelopes inside the verified record set. They prove internal consistency of
  that record set, not that the entire file could not have been rewritten by an
  actor who can replace all retained logs.
- To detect malicious full rewrites, store a trusted tail/head hash outside the
  JSONL files, such as in off-host storage, a transparency log, a deployment
  manifest, or operator-maintained evidence. Then verify with
  `verify_chain_with_anchors` or `verify_jsonl_lines_with_anchors`:

```rust
use registry_platform_audit::{
    verify_jsonl_lines_with_anchors, ChainVerificationAnchors,
};

fn verify_against_stored_tail(
    lines: impl IntoIterator<Item = String>,
    trusted_tail_hash: [u8; 32],
) -> Result<(), registry_platform_audit::ChainVerificationError> {
    verify_jsonl_lines_with_anchors(
        lines,
        ChainVerificationAnchors::from_trusted_last_hash(trusted_tail_hash),
    )?;
    Ok(())
}
```

- For retained suffixes after rotation, use `trusted_start_prev_hash` when the
  hash immediately before the retained set was stored externally. Combine it
  with `trusted_last_hash` when both ends are available.
- Anchors are verification inputs only. They do not change the JSONL envelope
  schema and remain compatible with existing persisted audit logs.
- The chain does not replace durable storage, retention policy, clock integrity,
  or off-host log shipping.
- Use `AuditProfile::registry_relay_from_env` or
  `AuditProfile::registry_notary_from_env` in production. `unkeyed_dev_only` is
  for tests and local development.
- Redaction helpers intentionally avoid preserving email local parts, phone
  digits, or sensitive query values.

## Testing

```sh
cargo test -p registry-platform-audit
```

## License

Apache-2.0.
