# Evidence Performance

Status: Measured, with group commit implemented; not a Version 1 contract
Date: 2026-08-03

## Purpose

Evidence trades request throughput for audit durability. This file records what
that trade costs, how it was measured, and the change that recovered most of
the cost without weakening the guarantee: group commit in the audit sink,
implemented in `crates/registry-evidence/src/audit.rs`. The current end-to-end
measurement lives in `OPERATOR-CONTRACT.md` under "Measured throughput".
Nothing here is a Version 1 commitment. Throughput is not a Definition of Done
row and is not a `CONCEPT.md` non-goal.

## The guarantee that sets the ceiling

The security invariant matrix requires that the disclosure-release record be
durably accepted before the response bytes reach the caller, and that the access
record be durably accepted before source access. `DurableJsonlSink` implements
this by calling `sync_all` inside the append, and `ChainState::append` holds the
chain mutex across that call so hash links cannot interleave.

The result is two serialized disk barriers per successful request.

This is Evidence-specific. The shared `JsonlFileSink` used by Notary, and
Relay's file sink, both end their append at `write_all` plus `flush` and never
call `sync_all`, so their records sit in the page cache and are lost on power
failure. Evidence is the only one of the three that survives that failure, and
the ceiling below is the price of it.

## Measured baseline before group commit

This section records the measurement that motivated group commit and is kept
as the before-figure. Measured with
`soak_reports_request_throughput_against_the_audit_ceiling` in
`crates/registry-evidence/src/runtime_tests.rs`. Two release-profile runs, 512
requests at 32 concurrent, against a local mock source, with each append
taking its own barrier:

| | run 1 | run 2 |
|---|---|---|
| Observed request rate | 122 rps | 161 rps |
| Measured audit ceiling | 131 rps | 163 rps |
| Mock source floor | 57,461 rps | 77,256 rps |
| Latency p50 / p95 / p99 | 260 / 293 / 308 ms | 196 / 212 / 225 ms |
| Share of audit ceiling | 93% | 99% |

Host: Apple M5 Max, 18 logical cores, APFS, macOS.

Attribution is unambiguous. The source served roughly 450 times faster than the
observed request rate, so it contributes nothing. Observed throughput sits at 93
to 99 percent of what the audit chain can sustain. Little's law agrees from the
other side: 32 concurrent divided by 161 rps is 199 ms against a measured 196 ms
p50, so nearly all request latency is queueing on the audit mutex rather than
work.

Per-append cost is 3.1 to 3.8 ms.

### Why this number is pessimistic

On macOS, `File::sync_all` issues `F_FULLFSYNC`, a true device write barrier. On
Linux the same call is an ordinary `fsync`, which on NVMe is far cheaper. **These
figures are a macOS floor and must be re-measured on the target Linux host
before they are quoted as production numbers or used to justify the work below.**

## Horizontal scaling works today

`DurableJsonlSink::open` takes an exclusive `flock`, so one process owns one
audit path. Nothing else is shared between requests. N processes with N distinct
audit paths therefore give N times the throughput with no code change. Only
vertical throughput is capped.

## Group commit

The lever for vertical throughput is batching the barrier, not removing it.
The audit sink in `crates/registry-evidence/src/audit.rs` implements this:
appends that arrive while a durable write is in flight form the next batch,
and one `fsync` covers the whole batch. There is no timer and no configured
window; a batch is exactly what queued behind the in-flight barrier, so the
sink degrades to one barrier per append when requests do not overlap.

Properties that survived the change, each held by tests in `audit.rs`:

- durability before release: an append resolves only after the barrier that
  covers its own bytes has completed, so no caller receives evidence ahead of
  its durable record;
- chain ordering: records are hash-linked in the order they were chained, and
  the on-disk order matches; batching must not drop or duplicate a record;
- fail-closed: a failed barrier fails every append it covers, and none of them
  may report success;
- fork detection: the pinned-path, fingerprint, and tail checks in
  `DurableJsonlSink::write` still bracket the batched write, and a batch that
  crosses the segment bound is split so each segment stays self-consistent.

The gain scales with concurrent arrivals rather than helping a single idle
request. With group commit in place, the end-to-end measurement in
`OPERATOR-CONTRACT.md` under "Measured throughput" sustained 7057
requests/second at 128 concurrent on the same host class that measured the
baseline rows in this file, with both durable audit appends per request kept.

The macOS caveat still applies to every figure in this file and in
`OPERATOR-CONTRACT.md`: re-measure on the target Linux host before quoting
production numbers.

## Regression baseline

Two tests cover this area:

- `concurrent_evidence_requests_keep_one_verifiable_audit_chain` runs in CI. It
  drives simultaneous evaluations and asserts one verifiable chain, two records
  per release, and a distinct evidence identity per request. Any interleaving or
  forking under concurrency fails it.
- `soak_reports_request_throughput_against_the_audit_ceiling` is `#[ignore]` and
  opt-in. It reports rates and asserts only correctness, because throughput
  thresholds are host properties and would otherwise be a source of flakes:

```bash
cargo test -p registry-evidence --lib --release -- --ignored --nocapture soak_reports
```

Record the host alongside any figure taken from it.

## Not measured

Notary's sink was read, not benchmarked. The claim that it is materially faster
on this axis is inference from the absent `sync_all`, not a measurement.
