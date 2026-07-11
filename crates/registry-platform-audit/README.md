# registry-platform-audit

Tamper-evident audit envelopes, async sinks, JSONL verification, and redaction
helpers for registry services.

## What It Provides

- `ChainState` for serialized append-only audit chains.
- `AuditEnvelope` records with ULID ids, timestamps, previous hashes, payloads,
  and record hashes.
- `AuditSink` for pluggable persistence.
- `DurableAuditSink` for atomic, idempotent governed-operation writes keyed by
  stream, operation ULID, and phase.
- A `cfg(test)` in-memory conformance sink plus a public-API integration test.
  No in-memory sink exists in production builds.
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

## Durable Phase Contract

Access-capable consultation and materialization flows use
`DurableAuditSink::write_phase`, not `AuditSink::write`. Each
`DurableAuditWrite` carries:

- a closed stream kind;
- a canonical operation ULID whose server-minted provenance is enforced by the
  consumer;
- a closed phase accepted for that stream; and
- one non-empty top-level JSON object containing the consumer-owned safe event
  payload.

The stream/phase matrix is closed:

- `consultation` and `materialization` accept `attempt` and `completion`;
- `denial` accepts only `denial_decision`; and
- `startup_credential_probe` and `readiness_credential_probe` each accept
  `attempt` and `completion`.

`DurableAuditWrite` canonicalizes the safe payload with the shared RFC 8785
implementation and derives its SHA-256 digest internally, so payload and digest
cannot disagree. Integer values that are not exactly representable as IEEE 754
binary64 are rejected rather than rounded into a colliding digest; encode such
values as strings under a reviewed schema. Raw JSON parsers must reject
duplicate property names before constructing the `serde_json::Value`, because
the parsed value no longer retains that ambiguity. The write carries no
predecessor, envelope, or event identity. The sink first resolves duplicate
state, then builds the `AuditEnvelope` from the current durable chain head while
holding the same transaction or equivalent critical section that performs
insertion.

The sink-built envelope uses this stable record shape:

```json
{
  "schema": "registry.durable-audit/v1",
  "stream_kind": "consultation",
  "operation_id": "01J5K8M0000000000000000000",
  "phase": "attempt",
  "payload_digest": "sha256:<64 lowercase hex characters>",
  "payload": { "event": "consultation.attempt" }
}
```

The chained record therefore binds the schema, durable row key, phase, digest,
and payload. Reassociating an envelope with another row key is detectable.

The sink atomically inserts by `(stream_kind, operation_id, phase)`. The first
write returns `Inserted`. A retry with the same digest returns
`IdenticalDuplicate` and the identity of the envelope originally stored. A
retry with a different digest returns the deterministic `ConflictingDuplicate`
outcome with the original identity and must be treated as an integrity failure.
Only store availability or internal failure uses the error channel.

`DurableAuditSink` is deliberately independent of the append-only `AuditSink`.
There is no blanket adapter or fallback because stdout, syslog, and ordinary
JSONL appends cannot provide crash-safe or replica-safe phase idempotency. The
in-memory implementation is a conformance harness only. A fail-closed runtime
must use a durable implementation, with PostgreSQL as the initial state-plane
target.

## Operational Notes

- `JsonlFileSink::new` rotates at 10 MiB and retains 50 files by default.
- `JsonlFileSink::with_rotation(path, 0, max_files)` disables size rotation.
- `AuditProfile::bootstrap_or_start_empty` and
  `AuditChainProfile::bootstrap_or_start_empty` read the sink tail hash before
  new appends, which is the normal startup path for persistent sinks.
- `JsonlStdoutSink` and `SyslogSink` cannot report a historical tail hash, so
  each process starts a fresh chain unless a consumer stores the tail elsewhere.

## Security Notes

- The chain APIs detect edits, insertions, reordering, and deletions of
  interior records inside the retained set. The first retained envelope's
  `prev_hash` is the retained-set boundary.
- The chain APIs prove internal consistency of retained records. They do not
  prove completeness: removal of trailing records leaves a self-consistent
  shorter chain, and they do not detect deletion of leading retained records
  or a self-consistent full rewrite by an actor who can replace all retained
  logs.
- Off-host audit shipping is the completeness guarantee. Evidence-grade Relay
  and Notary deployments refuse startup when a local `file` or `jsonl` sink is
  used without declaring off-host shipping. Every evidence-grade shipping
  target, including `stdout` and `syslog`, also requires a
  `registry.audit.ack_cursor.v1` cursor. A cursor is healthy only when its
  `acked_at` is fresh and its `last_acked_hash` equals the live keyed chain
  tail. Equality establishes zero local backlog for the trusted shipper's
  claim. The unsigned local cursor is not cryptographic proof that a remote
  system received or retained the records.
- Shippers must replace the cursor atomically after a successful hand-off.
  Mount the cursor read-only for the Registry runtime. Cursor reads reject
  symbolic links and non-regular files and are limited to 16 KiB. Relay and
  Notary readiness handlers run the read through one 500 ms bounded worker so
  a stalled filesystem fails readiness without accumulating blocked workers.
- The chain does not replace durable storage, retention policy, clock integrity,
  or off-host log shipping.
- Safe payload objects passed to `DurableAuditWrite::new` must already exclude
  raw selectors, credentials, tokens, source URLs, and secret-derived
  fingerprints. Durable-write diagnostics include neither rejected input,
  payload contents, nor digests.
- `DurableAuditOperationId` validates canonical ULID syntax only. The consumer
  must enforce that the id is server-minted and is not derived from a subject
  selector, token, source identifier, or other sensitive input.
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
