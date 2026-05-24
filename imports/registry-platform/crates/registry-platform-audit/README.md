# registry-platform-audit

Tamper-evident audit envelopes, async sinks, JSONL verification, and redaction
helpers for registry services.

## What It Provides

- `ChainState` for serialized append-only audit chains.
- `AuditEnvelope` records with ULID ids, timestamps, previous hashes, payloads,
  and record hashes.
- `AuditSink` for pluggable persistence.
- Built-in `JsonlFileSink`, `JsonlStdoutSink`, and `SyslogSink`.
- `verify_chain` and `verify_jsonl_lines` for retained audit verification.
- `AuditKeyHasher` and `redact` helpers for privacy-safe audit fields.

## Typical Use

```rust
use registry_platform_audit::{ChainState, JsonlFileSink};
use serde_json::json;

async fn write_audit_event() -> Result<(), registry_platform_audit::AuditError> {
let sink = JsonlFileSink::new("audit.jsonl");
let chain = ChainState::bootstrap(&sink).await?;

let envelope = chain
    .append(&sink, json!({
        "event": "credential.issued",
        "subject_ref": "hmac-sha256:...",
    }))
    .await?;

assert!(envelope.prev_hash.is_some() || chain.last_hash().await.is_some());
Ok(())
}
```

## Operational Notes

- `JsonlFileSink::new` rotates at 10 MiB and retains 5 files by default.
- `JsonlFileSink::with_rotation(path, 0, max_files)` disables size rotation.
- `ChainState::bootstrap` reads the sink tail hash before new appends, which is
  the normal startup path for persistent sinks.
- `JsonlStdoutSink` and `SyslogSink` cannot report a historical tail hash, so
  each process starts a fresh chain unless a consumer stores the tail elsewhere.

## Security Notes

- The chain detects edits, insertions, deletions, and reordered envelopes inside
  the verified record set.
- The chain does not replace durable storage, retention policy, clock integrity,
  or off-host log shipping.
- Use keyed `AuditKeyHasher::from_env` in production. `unkeyed_dev_only` is for
  tests and local development.
- Redaction helpers intentionally avoid preserving email local parts, phone
  digits, or sensitive query values.

## Testing

```sh
cargo test -p registry-platform-audit
```

## License

Apache-2.0.
