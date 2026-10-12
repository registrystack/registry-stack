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
  values.
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
use zeroize::Zeroizing;

async fn write_audit_entries() -> Result<(), Box<dyn std::error::Error>> {
    let master_secret = Zeroizing::new(std::fs::read("/run/secrets/registry-audit-hash")?);
    let profile = AuditProfile::production_from_secret_bytes(master_secret)?;
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
- A stalled `stdout` destination is not a failed write. A destination that
  holds one line for 5 seconds is stalled: the request waiting on that line is
  refused, every later audited request is refused at once, and `ready()`
  reports false. When the destination takes the line the writer accepts
  entries again, with no restart. The start and the end of a stall are each
  logged once, with no entry content. The deadline is fixed and has no
  configuration key.
- A `stdout` destination writes on a thread of its own, at most 4096 lines
  behind the one being written; a line that finds the queue full is refused.
  An append waits for its line on the Tokio timer, so the runtime that appends
  needs its time driver; without one the append is refused before its line is
  queued.
- An active file whose last line was torn by an interrupted write is recovered
  at open: the bytes after the last complete line are copied to the owner-only
  side file `<path>.torn`, the active file is truncated to its last complete
  line, and the recovery is logged with the side file's path and byte count,
  never the bytes. An entry is acknowledged only after its batch is synced, so
  no acknowledged entry is lost. An existing side file holding other bytes is
  never overwritten; open refuses until it is archived.
- `AuditSegments` names the files a stream owns beside its active file (sealed
  segments, `.lock`, `.seq`, `.seq.tmp`, `.torn`) and lists sealed segments
  oldest first, read-only, so inspection tooling reads the namespace the writer
  manages. A configured path whose file name ends in one of those suffixes is
  refused, because a stream at the shorter name would own it.
- `stdout` is best-effort by nature: a flush does not prove the entry reached
  durable storage.

## Security Notes

- Entries are not hash-chained. Tamper evidence is a deployment concern: ship
  the stream to append-only storage or a SIEM that the service cannot rewrite.
- Use `AuditProfile::production_from_secret_bytes` in production.
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
  pseudonym scope policy. `without_purpose` builds an allowed or denied event
  that carries no purpose, for a product that never records one.
- Redaction helpers intentionally avoid preserving email local parts, phone
  digits, or sensitive query values.

### Stream write deadline: review record

A `stdout` destination whose reader stops reading used to hold every audited
request for as long as the reader stayed away. One thread now owns the
stream, and a caller waits one fixed deadline for its line. The four elements
of the change:

- **Invariant.** A caller is told an entry was accepted only after its line
  was written and flushed, and no caller waits on a stream destination longer
  than the write deadline (5 seconds, `STREAM_WRITE_DEADLINE`). A stall
  recovers by itself; a write error stops the writer until restart, as before.
  The deadline sits below the 10-second request timeout the Base Registry
  Engine defaults to and the Evidence reference projects set, so a stalled
  destination is answered as an unavailable audit destination, not as a
  timed-out request.
- **Enforcement point.** `LineStream` in `src/writer.rs`. `append` refuses
  before queueing when the stream has failed or the write in progress is
  older than the deadline, hands the line over with `try_send` so a full
  queue refuses, and waits for the outcome under `tokio::time::timeout`. The
  `audit-stream` thread is the only code that touches the sink; it skips a
  line whose caller already stopped waiting, so a refused caller's queued
  line is never written. `ready()` is false while the write in progress is
  older than the deadline. Dropping the writer closes the queue and waits one
  deadline for the thread, then leaves it and reports that once.
- **Executed proof.** In `src/writer.rs`, against a sink that holds its write:
  `a_stalled_stream_refuses_the_append_at_the_deadline_and_later_ones_at_once`,
  `readiness_follows_a_stall_and_returns_once_the_stream_drains`,
  `a_write_error_still_stops_the_stream_after_its_sink_recovers`,
  `a_stalled_stream_leaves_the_runtime_to_other_tasks`,
  `dropping_the_writer_waits_at_most_one_deadline_for_a_blocked_stream`,
  `dropping_the_writer_writes_the_entries_still_queued`,
  `a_full_stream_queue_refuses_a_line_instead_of_growing`, and
  `a_runtime_without_a_timer_refuses_the_append_before_queueing_its_line`.
  Through a product,
  `a_stalled_destination_is_not_ready_until_it_drains` in
  `registry-scheduling` holds readiness to the writer over the real deadline.
- **Remaining uncertainty.** The line the destination is holding when its
  caller's deadline passes cannot be withdrawn: the caller is refused and the
  line is still written when the destination takes it, which is logged. That
  is one line for each stall, and it records more than happened, never less.
  A `request` entry written that way has no `response` entry: its request
  was refused and ran no protected I/O. A `response` entry written that way
  is followed by the request's unfinished response. A destination slow
  enough that lines wait in the queue for most of a deadline can do the same
  with no stall reported. The start of a stall is logged by the first append
  or readiness check that sees it, not by a timer, so a writer nothing is
  asking logs it late. A full queue refuses lines without turning `ready()`
  false. A destination that never takes its line keeps one thread until the
  process exits, and unfinished response entries queued behind it when the
  writer is dropped are not written, which is reported once. An operator who
  sets a request timeout under 5 seconds still sees a timed-out request
  first. A refused entry does not undo work a product already committed: a
  product that writes its outcome entry after its transaction commits reports
  that operation as unresolved, as it does for a failed write.

## Testing

```sh
cargo test -p registry-platform-audit
```

## License

Apache-2.0.
