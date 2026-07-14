# Registry Notary Scalability Spec

> **Status: Archived (2026-07-13).** This direct-source scalability plan was
> superseded when Registry-backed evidence moved behind Relay. Its connectors,
> runtime paths, and product-local load harness were removed before 1.0. This
> file is retained only as historical design context and is not current
> implementation or operator guidance.

## Purpose

Define the work needed to make `registry-notary` serve both synchronous credential issuance and batch backfills against third-party registries without the current single-threaded fan-out becoming the bottleneck. The fan-out diagnosis is provisional, to be confirmed by the Stage 0 load harness before Stage 1 ships.

## Background

Today the evaluation pipeline is strictly sequential at every level: `runtime::batch_evaluate` iterates batch items in a `for` loop (`crates/registry-notary-server/src/runtime.rs:362-421`); inside one target, claims are evaluated in order; inside one claim, source bindings are read one at a time via `SourceReader::read_one`. Both connector backends (`registry_data_api`, `dci` in `crates/registry-notary-server/src/standalone.rs:459-537`) do one upstream HTTP request per (claim, target, binding).

This is fine for one-off issuance, breaks down under any meaningful load, and ignores bulk capabilities the upstream Registry Data API and DCI search envelope already expose.

## Goals

- Parallelize the evaluation pipeline within a single request.
- Avoid duplicate upstream fetches inside one `batch_evaluate`.
- Use bulk upstream operations when the connector backend supports them, without breaking arbitrary third-party REST upstreams.
- Cap outbound concurrency per `source_connection` across **all** concurrent notary requests (process-global), so the notary cannot DOS an upstream regardless of inbound load.
- Establish measurable performance targets and a load-test harness to prevent regressions.

## Non-Goals

- Cross-request shared cache (Stage 4, gated on an explicit audit/freshness design pass).
- Connector-level streaming or pagination semantics (claim bindings remain single-record by design).
- Distinguishing transient vs. permanent upstream errors as a general hardening item; see Cross-Cutting Concerns for the minimum retry policy required once concurrency lands.
- Schema or contract changes to the public notary HTTP API.

## Stages

Each stage is independently shippable. Definition of Done is per stage.

### Stage 0: Load harness in `perf/`

**Change.** Establish a reproducible load harness in `perf/` with a mock upstream that supports configurable median latency, jitter, and concurrent-request counting. Scenarios: single-target sync issuance, `batch_evaluate` at sizes 10/100/1000, and a sustained-rate scenario across two concurrent inbound requests.

**Why.** Every later stage's DoD references measurements. Without the harness, "verified by load test" is decorative. Also validates that the bottleneck is fan-out before committing Stages 1-3 to that diagnosis; CEL evaluation (`runtime.rs:733-799`) and JSON projection on large records may dominate for some claim shapes.

**Definition of Done.**

- `perf/` contains a runnable scenario set with a documented invocation in this spec or `perf/README.md`.
- Baseline numbers captured for current (pre-Stage-1) code: per-scenario p50/p99 latency, sustained throughput, peak outbound concurrency per source connection.
- Mock upstream surfaces "max-observed concurrent in-flight requests" as a test assertion, not just a metric.

### Stage 1: Parallel evaluation inside one request

**Change.** Replace the sequential item loop in `runtime::batch_evaluate` with a bounded `JoinSet`. Inside one `evaluate`, run independent claims (no `depends_on` edges between them) concurrently; later DAG levels run after their predecessors complete. Inside one claim, fan out source bindings concurrently. Rework the `prior` map (`runtime.rs:487-561`, esp. the mut borrow at 491) so concurrent sibling claims at the same DAG level publish results without data races; either an `Arc<Mutex<BTreeMap<...>>>` or per-claim `OnceCell` in a level-keyed structure.

Add a per-`source_connection` outbound semaphore as a **process-global** `Arc<Semaphore>` keyed by `connection_id`, owned by `HttpEvidenceSources` and shared across all concurrent notary requests.

Provide a kill switch: `concurrency.items=1` and `concurrency.bindings=1` reproduce today's strictly-sequential behavior exactly.

**Why.** Highest leverage, no connector contract change, works for every backend including arbitrary third-party REST.

**Definition of Done.**

- New config keys: `concurrency.items` (default 16), `concurrency.bindings` (default 8), per-source `max_in_flight` (default 8); kill-switch behavior documented.
- Process-global cap test: two concurrent `batch_evaluate` calls against the same `source_connection` observe a combined inbound concurrency at the mock upstream capped at `max_in_flight`. Drives Goal "cannot DOS upstream" to a positive verification.
- Positive overlap test: two independent claims at the same DAG level, each with a 200ms mock upstream, complete a single-target `evaluate` in roughly 200ms (not 400ms) at `concurrency.bindings>=2`. Tolerance documented.
- DAG correctness test: claim B with `depends_on: [A]` never starts before A completes, including under high `concurrency.bindings`.
- Unhappy-path test: one target's read panics inside the `JoinSet`; remaining items complete; the panic surfaces as a request-level error; no futures leaked, semaphore permits returned.
- Numeric DoD against Stage 0 baseline: `batch_evaluate` of 100 items against a mock upstream at 100ms median completes in under `1.5 * ceil(100 / concurrency.items) * 100ms` end-to-end. Failure indicates concurrency is not actually overlapping.

### Stage 2: Per-request fetch memoization

**Change.** Inside one `batch_evaluate`, dedup upstream calls keyed on a **hash of the canonical serialized upstream request** (connection_id, dataset, entity, lookup_field, lookup_op, lookup_value, projected_fields_set, purpose; for DCI also query_type, registry_type, record_type, field_paths). Equivalent formulation: hash the bytes that *would* be sent on the wire.

Memoize at **`batch_evaluate` scope**, not per-target `evaluate` scope, so items sharing a binding share both the read **and** the `iat` baseline. Lift `now` for memoized siblings to the timestamp of the original upstream read; emit one audit event with redacted target handles rather than one per target.

Cache only successful results. Errors are not memoized: a transient flake must not poison every target in the batch.

**Why.** Two claims that share a binding for the same target currently fetch twice. Without lifting `now`, batch siblings would carry different `iat` values for credentials derived from the same upstream observation, making the audit story inconsistent.

**Definition of Done.**

- Positive test: one target, two claims sharing one binding: exactly one upstream HTTP request.
- Batch dedup test: 50 items across 3 claims sharing 1 binding by lookup value: exactly 50 upstream calls, not 150.
- Negative tests: two claims with different `lookup_op`, OR different `projected_fields_set`, OR different `purpose` do **not** share the memoized read. Run all three variants.
- DCI negative test: two claims with different `query_type` against the same connection do not memoize together.
- Error-not-cached test: first call returns 500; a subsequent call for the same key proceeds to a new upstream request.
- `iat` consistency test: items sharing a memoized read produce credentials with identical `iat`; the audit log records one source-read event listing all affected target handles.

### Stage 3: Bulk `read_many` with per-connection capability config

**Change.** Add `SourceReader::read_many(Vec<(SourceBindingConfig, EvidenceTarget)>) -> Vec<Result<Value, EvidenceError>>` with a default impl that runs `read_one` concurrently. Add per-`source_connection` `bulk_mode` config:

- `none` (default, safe for arbitrary third-party REST).
- `rda_in_filter` (relay-shaped RDA upstreams that support `EntityFilterOp::In`).
- `dci_batched_search` (DCI-spec upstreams accepting multi-entry `message.search_request[]`).

**RDA specialization.** One collection GET with `lookup_field=in:v1,v2,...&limit=N+1`. Per-target ambiguity cannot be derived from a flat row count if multiple targets share a lookup value. Resolution:

- Config-validation precondition: `rda_in_filter` requires `lookup.cardinality: one` AND operator attestation `bulk_mode_lookup_unique: true` on the connection.
- Runtime fail-safe: if total response rows exceed `N`, fall back to per-target `read_one` for the entire batch on this connection. Emit a `bulk_collision_fallback` metric so operators see the precondition is being violated.

**DCI specialization.** One POST with N `search_request[]` entries, each with its own `reference_id`. The current `records_path` (`config.rs:415`) is hardcoded to index `0` and cannot express per-entry projection: `read_many` for DCI **ignores `records_path`** and walks `message.search_response[]`, matching each entry's `reference_id` back to the originating target. `records_path` continues to govern `read_one` for backward compatibility. `dci.max_results` (config.rs:418-420, default 2) is overridden to `max(max_results, N)` when in batched mode so page_size scales with the batch.

**Why.** Bulk on relay-shaped or DCI-compliant upstreams turns N upstream calls into 1. Default `read_many` keeps arbitrary REST correct via concurrent `read_one`.

**Definition of Done.**

- `bulk_mode` config validates: unknown variants rejected at load time; `rda_in_filter` requires `bulk_mode_lookup_unique: true` and `lookup.cardinality: one`; defaults to `none`.
- RDA bulk integration test: 100 targets with unique lookup values produce 1 upstream HTTP request; results match a per-target reference run row-for-row.
- RDA collision-fallback test: a batch where two targets share a lookup value triggers per-target fallback; emits `bulk_collision_fallback`; results are correct for every target.
- DCI bulk integration test: 100 targets produce 1 POST with `message.search_request.len() == 100`; request body `page_size >= 100`; responses split by `reference_id`; results match a per-target reference run.
- DCI missing-record test: one target's `reference_id` is absent from the response; that target gets `target.not_found`; other targets are unaffected.
- `bulk_mode: none` cassette test: recorded wire bytes for a representative scenario match today's per-target sequence exactly.
- Backward-compatibility: `records_path` still drives `read_one` for DCI; the existing `read_one` test stays green.

### Stage 4: Short-TTL raw-record cache (gated)

**Change.** Optional cross-request cache of raw upstream JSON keyed identically to Stage 2. TTL configurable per `source_connection`. Claim evaluation always recomputes from cached or fresh records.

**Why.** Repeat reads of the same target within seconds (revocation polling, retry loops, parallel verifier traffic) bypass upstream.

**Pre-condition.** Separate design pass on cache vs. audit/freshness: what does `iat` mean for a credential issued from a cached record? Likely answer: cap max staleness per source connection, expose freshness as a per-profile policy, refuse cache for claims marked freshness-sensitive.

**Definition of Done.** Deferred until the design pass lands. Not in scope for the first push.

## Cross-Cutting Concerns

These apply across stages and have their own DoD bullets in the stage that introduces them.

- **Retry / backoff.** With Stage 1 concurrency, a flaky upstream multiplies failure surface linearly. Introduce a bounded retry (max 1 retry on transport error or 5xx, exponential backoff with jitter). Retries hold `max_in_flight` permits for their full duration. Required as part of Stage 1.
- **Timeout budget.** Per-call timeout (`standalone.rs:473, 516`) is unchanged for `read_one`. Under `read_many`, the per-call budget scales with batch size up to a configurable cap `source_connection.bulk_timeout_max`. Required as part of Stage 3.
- **Observability.** Per-`source_connection` in-flight gauge, outbound-latency histogram, batch-size histogram, memoization hit rate, bulk-vs-fallback counter, retry counter. Gauge and retry counter in Stage 1; memo hit rate in Stage 2; batch and fallback counters in Stage 3.
- **Feature flagging.** `concurrency.items=1` and `concurrency.bindings=1` reproduce today's behavior. `bulk_mode: none` reproduces today's wire behavior. Operators can disable Stages 1 and 3 per-deployment without code changes.
- **Config reload.** On hot reload, the per-connection semaphore is replaced atomically; outstanding permits drain naturally. `concurrency.*` changes take effect for new requests only; in-flight `JoinSet` sizes are not retroactively resized. Documented behavior, not enforced via DoD.
- **Target mapping cost.** `load_sources` maps the request target into each source binding (`runtime.rs:720`). Stage 1 parallelizes target mapping with `read_one`. Stage 3 invokes target mapping N times before issuing the single upstream call. Profiled as a follow-up if Stage 0 shows it is significant; not a Stage 1 DoD item.

## Performance Targets

To be locked down via Stage 0 measurements before Stage 1 lands. Proposed starting bar, revisable:

- **Sync issuance (p99)**: single target, one claim, one binding, upstream median 100ms: under 300ms end-to-end.
- **Batch backfill (sustained)** at the **default** `max_in_flight=8`: 3 claims, 1 binding each, RDA upstream at 100ms median: at least 50 targets per second per notary instance after Stage 1.
- **Batch backfill (stretch, tuned)** with `max_in_flight=16`: at least 100 targets per second per notary instance after Stage 1. This number is conditional on operators tuning `max_in_flight` upward against a tolerant upstream and does not contradict the default-politeness goal.
- **Outbound politeness**: process-global concurrent outbound calls per `source_connection` never exceed `max_in_flight`, verified across multiple concurrent inbound notary requests.

## Open Questions

1. Are the third-party upstreams we expect to integrate against mostly relay-shaped (RDA collection + `in:`) and DCI-spec compliant, or mostly arbitrary bespoke REST? Decides how much value Stage 3 actually delivers.
2. Concrete example registries to design `bulk_mode` against, so we are not abstracting over hypothetical API shapes.
3. Stage 0 harness location: standalone `perf/` in this repo, or shared infrastructure with `registry-relay/perf/`?
4. For RDA `rda_in_filter`: is operator-attested `bulk_mode_lookup_unique: true` acceptable, or should the notary verify uniqueness by inspecting the upstream entity schema response?

## Out of Scope

- Horizontal scaling of the notary itself (multiple instances, leader election). Stateless per request today; horizontal scale is a deployment concern, not a code change.
- Async issuance / job queue model. Current spec assumes synchronous request/response.
- Upstream contract negotiation. We adapt to what upstreams expose; we do not propose new upstream APIs here.
