# data_gate Performance And Load Testing Spec

## Purpose

Define a repeatable performance test program for `data_gate` that proves the server can serve protected, read-only dataset APIs with millisecond-scale latency under realistic request load and realistic data volume.

The tests must answer three questions:

- Are normal protected reads fast enough?
- Does latency remain stable as datasets get large?
- Does the server fail predictably under pressure instead of exhausting memory, file descriptors, CPU, or audit sinks?

This spec covers local developer runs, CI smoke checks, and longer manual or scheduled performance runs.

## Goals

- Measure end-to-end HTTP latency for authenticated public API requests.
- Measure the specific cached `304 Not Modified` path because it should stay fast even when backing datasets are large.
- Measure hot `200 OK` reads with realistic response sizes.
- Measure cold-start and first-request behavior after process start.
- Measure behavior under concurrent users and fixed request rates.
- Measure memory, CPU, audit, and error behavior for large datasets.
- Measure sustained throughput at fixed latency budgets.
- Keep generated test data synthetic, deterministic, and safe to commit when small enough.
- Make regressions visible through explicit thresholds.

## Non-Goals

- This is not a production capacity guarantee for every deployment shape.
- This is not a substitute for security testing.
- This does not require testing against real personal data.
- This does not require implementing bulk export endpoints. Bulk export is still unavailable unless a separate product spec enables it.
- This does not require public API backward compatibility for performance-only fixture config or scripts.

## Test Layers

### 1. Microbenchmarks

Use Rust benchmarks or focused timing tests for internal paths that should be microsecond to low-millisecond scale.

Required targets:

- API-key authentication in `src/auth/api_key.rs`.
- Dataset and entity lookup through the entity registry.
- `if_none_match_matches` in `src/api/entity.rs`.
- `strong_etag` and `entity_etag` in `src/api/entity.rs`.
- `EntityQueryEngine::read_collection` planning and execution in `src/query/mod.rs`.
- JSON serialization for representative records.
- Audit event creation and sink write, where practical.

Microbenchmarks are useful for catching local regressions before running full HTTP load tests, but they are not a replacement for HTTP tests.

### 2. HTTP Endpoint Load Tests

Use a load tool such as `k6` for scripted scenarios and thresholds. Use a quick CLI tool such as `oha` or `wrk` for ad hoc maximum-throughput checks.

Required public endpoints:

- `GET /health`
- `GET /ready`
- `GET /datasets`
- `GET /datasets/{dataset_id}`
- `GET /datasets/{dataset_id}/{entity}/schema`
- `GET /datasets/{dataset_id}/{entity}`
- `GET /datasets/{dataset_id}/{entity}/{id}`
- `GET /datasets/{dataset_id}/{entity}/aggregates`
- `GET /catalog`
- `GET /catalog/dcat-ap.jsonld`

Required auth cases:

- Valid token.
- Missing token.
- Invalid token.
- Valid token missing the required scope.
- Valid token with dataset scope but no entity-level read access, when config supports that distinction.

### 3. Data Volume Tests

Use synthetic datasets that vary row count, column count, field shape, and response size.

Required fixture families:

- Narrow rows: 5 to 10 columns.
- Medium rows: 25 to 50 columns.
- Wide rows: 100 or more columns.
- Numeric-heavy rows.
- String-heavy rows.
- Nullable rows.
- High-cardinality identifier rows.
- Mixed categorical rows that exercise aggregate group-by behavior.

Required row-count tiers:

- 1,000 rows.
- 10,000 rows.
- 100,000 rows.
- 1,000,000 rows.
- 5,000,000 rows, optional for local runs and required for scheduled capacity runs when hardware permits.

Required response-size tiers:

- About 100 KB.
- About 1 MB.
- About 10 MB.
- About 50 MB.
- About 100 MB or larger for stress runs only.

The 5,000,000 row tier may be skipped on local machines when the generated fixture or server run does not fit available memory. Skips must be recorded in the report with the machine memory and reason.

## Primary Workloads

### Cached 304 Dataset Read

Request:

```text
GET /datasets/clinic_capacity/facility
If-None-Match: "<known-etag>"
Authorization: Bearer <valid rows token>
```

Expected:

- Status is `304`.
- Response body is empty.
- Auth runs.
- Audit behavior is consistent with normal policy.
- The server does not read or serialize the full collection just to decide the response is unchanged.

This is the critical regression test for browser and API clients that revalidate data frequently.

Current implementation note: `src/api/entity.rs` currently calls `query.read_collection(...)` before computing the ETag and checking `If-None-Match`. The ETag itself is derived from kind, dataset id, entity name, ingest version, and request variant, so the data scan is incidental rather than fundamental. This workload is expected to expose the current cost and drive a future metadata-only ETag path based on registry-side ingest version.

### Hot 200 Dataset Read

Request:

```text
GET /datasets/clinic_capacity/facility
Authorization: Bearer <valid rows token>
```

Expected:

- Status is `200`.
- Response body is valid JSON.
- ETag is present.
- Response size is recorded.
- Latency is measured separately for small, medium, and large datasets.

### Cold First Request

Procedure:

1. Stop the server.
2. Start the release binary with the target perf config.
3. Wait until `/ready` succeeds.
4. Send one protected dataset request.
5. Record first-request latency.
6. Repeat according to the cold start measurement procedure below.

Expected:

- Startup and first-request costs are visible.
- Warm request latency is reported separately from cold request latency.

### Mixed Read Traffic

Use a realistic mix instead of only hammering one endpoint:

- 55 percent cached dataset reads.
- 20 percent hot dataset list reads.
- 10 percent single-record reads.
- 5 percent schema reads.
- 5 percent aggregate reads.
- 3 percent catalog reads.
- 2 percent auth failures or scope failures.

Expected:

- Error rate remains within threshold.
- p95 and p99 latency remain stable.
- Invalid requests do not meaningfully degrade valid traffic.
- Expected `401` and `403` requests are tagged separately from unexpected failures.

### Filtered Collection Read

Request a collection with declared allowed filters.

Expected:

- Status is `200`.
- Filter validation is included in handler timing.
- DataFusion planning and execution time are reported separately when tracing is available.
- Result size and latency are reported together, because highly selective and broad filters have different cost profiles.

### Expanded Collection Read

Request a collection with a declared expansion.

Expected:

- Status is `200`.
- Expansion access checks succeed for an authorized token.
- Expansion access denials return `403`, never `5xx`.
- Latency is compared against the same collection without expansion.

### Cursor Walk

Walk a paginated entity from page 1 through page K using the returned cursor.

Expected:

- Every page returns `200` until the final page.
- Cursor signing and validation overhead is included.
- The final page has no next cursor.
- Cursor invalidation returns the documented error and never `5xx`.

### Aggregate Query

Run configured aggregate endpoints in isolation.

Expected:

- Status is `200`.
- Group-by and disclosure-control behavior are exercised.
- DataFusion planning and execution time are captured when tracing is available.
- Latency and result cardinality are reported together.

### DCAT-AP Catalog Generation

Run `/catalog/dcat-ap.jsonld` in isolation.

Expected:

- Status is `200`.
- Response is valid JSON-LD.
- Latency and response bytes are reported.
- Catalog generation is measured separately from entity read traffic.

### Authorization Deny

Send requests with credentials that authenticate successfully but are not authorized for the requested surface.

Expected:

- Missing or malformed credentials return `401`.
- Valid credentials missing a scope return `403`.
- Valid credentials with a dataset scope but denied entity access return `403`.
- No deny path returns `5xx`.

### Large Response Stress

Exercise full collection reads that return large JSON bodies.

Expected:

- The server does not crash.
- Memory returns near baseline after the request completes.
- Concurrent large responses produce predictable latency and backpressure.
- If product limits are introduced later, oversized requests fail with explicit errors rather than partial responses.

### Large Dataset 304

Use the same entity over progressively larger backing data:

- 100,000 rows.
- 1,000,000 rows.
- 5,000,000 rows.

Send `If-None-Match` with a current ETag.

Expected:

- `304` latency does not scale linearly with row count.
- The server does not perform full JSON serialization for unchanged data.
- If ETag computation depends on data scanning, the result must be called out as a performance bug or accepted product tradeoff.

For the current implementation, this test is expected to show that the `304` path still routes through `read_collection`. A passing future implementation should make `304` latency mostly independent of backing row count.

### Refresh Under Read Load

Run moderate read traffic while triggering dataset refresh or reload on a fixed interval.

Expected:

- Read requests continue to succeed during registry or ingest swaps.
- p99 latency does not spike beyond the scenario threshold during swaps.
- Readers never observe partial registry state.
- Refresh failures are reported without corrupting the previous ready state.
- Audit records remain well-formed during swaps.

### Soak

Run moderate mixed traffic for at least 30 minutes.

Preferred scheduled run:

- 60 minutes.
- Mixed read traffic.
- Medium and large datasets.
- Audit sink enabled.

Expected:

- No sustained memory growth.
- No file descriptor growth.
- No audit sink backlog growth.
- No rising p95 or p99 trend at constant load.
- Error rate remains within threshold.

Memory growth is measured as p50 RSS during minutes 5 to 10 compared with p50 RSS during minutes 55 to 60 for a 60 minute soak. The ratio must remain below 1.10 after warmup.

## Load Profiles

Each endpoint scenario should support both concurrency-driven and rate-driven modes.

Concurrency profile:

| Profile | Virtual users |
| --- | ---: |
| Single user | 1 |
| Light | 5 |
| Moderate | 20 |
| Heavy | 50 |
| Stress | 100 |
| Breakpoint | 250 or more |

Rate profile:

| Profile | Request rate |
| --- | ---: |
| Light | 10 requests per second |
| Moderate | 50 requests per second |
| Heavy | 100 requests per second |
| Stress | 250 requests per second |
| Breakpoint | increase until p99 or error rate breaks threshold |

The breakpoint profile is expected to find a limit. It should not be used as a pass/fail test except to compare capacity between versions.

Thresholds must always name the load profile they apply to. A latency target without a virtual-user count or request-rate target is not a complete threshold.

## Metrics

Every run must capture:

- Total requests.
- Requests per second.
- Error rate.
- HTTP status distribution.
- Response bytes.
- p50, p90, p95, p99, and max latency.
- CPU utilization.
- Resident memory.
- Open file descriptors, where available.
- Process restarts or panics.
- Audit sink write failures.
- Audit sink type.
- HTTP protocol version.
- Keepalive setting.
- Compression setting.

When tracing spans are available, capture timing for:

- Auth.
- Dataset lookup.
- Entity lookup.
- Filter validation.
- DataFusion planning.
- DataFusion execution.
- ETag resolution.
- JSON serialization.
- Audit record construction.
- Audit sink write.
- Full handler time.

## Initial Thresholds

These are local release-build targets for a reference Apple Silicon developer machine. CI and production-like runners need their own threshold tables once their hardware is known.

| Scenario | Load profile | Sustained rate floor | p95 target | p99 target |
| --- | --- | ---: | ---: | ---: |
| Auth middleware only | microbenchmark | not applicable | under 1 ms | under 2 ms |
| Cached `304` small dataset | Moderate, 20 VU | 100 RPS | under 10 ms | under 25 ms |
| Cached `304` large dataset | Moderate, 20 VU | 100 RPS | under 15 ms | under 40 ms |
| `200` around 100 KB | Moderate, 20 VU | 100 RPS | under 25 ms | under 75 ms |
| `200` around 1 MB | Moderate, 20 VU | 50 RPS | under 50 ms | under 150 ms |
| `200` around 10 MB | Light, 5 VU | 10 RPS | under 250 ms | under 750 ms |
| `200` around 50 MB | Single user, 1 VU | 1 RPS | under 1500 ms | under 5000 ms |
| Health and readiness | Heavy, 50 VU | 250 RPS | under 5 ms | under 20 ms |

Required global thresholds:

- Valid-request failure rate equals 0 for normal load profiles.
- Expected `401` and `403` cases are tagged and excluded from valid-request failure rate.
- No `5xx` responses during normal load profiles.
- Scope failures return `403`, not `5xx`.
- Missing or invalid auth returns `401`, not `5xx`.
- Soak memory growth is less than 10 percent after warmup.

Stress and breakpoint runs may exceed latency thresholds, but they must still report the failure mode clearly.

Health and readiness thresholds intentionally allow some CI and scheduler noise even though the handlers should usually complete faster.

## Fixture Design

Create deterministic synthetic data under a perf-specific path.

Recommended layout:

```text
perf/
  README.md
  config/
    small.yaml
    medium.yaml
    large.yaml
  fixtures/
    generated/
      clinic_capacity_1k.parquet
      clinic_capacity_10k.parquet
      clinic_capacity_100k.parquet
      clinic_capacity_1m.parquet
      clinic_capacity_wide_100k.parquet
      clinic_capacity_strings_100k.parquet
      clinic_capacity_100k.csv
  scripts/
    generate_perf_data.py
    generate_perf_keys.py
  k6/
      cached_304.js
      hot_200.js
      mixed_read.js
      filtered_read.js
      expanded_read.js
      cursor_walk.js
      aggregates.js
      dcat_catalog.js
      auth_deny.js
      large_200.js
      large_304.js
      refresh_under_read_load.js
      soak.js
```

Small fixtures may be committed if they are useful for CI. Large generated fixtures should be ignored by Git and recreated locally or in scheduled jobs.

Fixture generation requirements:

- Use a fixed seed.
- Generate only synthetic records.
- Avoid real names, real identifiers, real addresses, real phone numbers, and real emails.
- Emit a manifest with row count, column count, file size, schema, and generation timestamp.
- Prefer Parquet for large fixtures because it matches efficient analytical storage paths.
- Include at least one 100,000 row CSV fixture so the CSV-backed path is measured.
- Keep XLSX coverage for format-specific ingest tests, but do not use XLSX as the main large-volume performance format.

## Tooling

Recommended tools:

- `cargo test` for focused correctness checks around perf-sensitive behavior.
- Criterion or equivalent Rust benchmarks for microbenchmarks.
- `k6` for scripted load scenarios, checks, and thresholds.
- `oha` or `wrk` for quick endpoint throughput checks.
- `ps`, `top`, `lsof`, or platform equivalents for local process observation.
- Optional: tracing output or metrics export if the server exposes it later.

The release binary must be used for all reported performance numbers:

```sh
cargo build --release
```

Debug builds are acceptable only for functional smoke tests.

## Environment Setup

Each perf run should use:

- A dedicated config file.
- Dedicated synthetic API keys.
- A dedicated audit sink choice.
- A dedicated server port.
- A clean generated fixture directory.
- Release build.

Never print raw keys in logs or checked-in files. Perf scripts may create throwaway local env files, but those files must be ignored by Git and deleted or rotated after use.

When a secret runner is available, prefer running the server with an env-file wrapper instead of sourcing raw keys into the interactive shell. For example:

```sh
op run --env-file=target/perf/perf.env -- target/release/data_gate --config perf/config/medium.yaml
```

The fallback local flow is acceptable for throwaway keys when shell history and logs are controlled.

Suggested local flow:

```sh
cargo build --release
uv run perf/scripts/generate_perf_data.py --profile medium
uv run perf/scripts/generate_perf_keys.py --env-file target/perf/perf.env
op run --env-file=target/perf/perf.env -- target/release/data_gate --config perf/config/medium.yaml
```

Then run scenarios in another shell:

```sh
op run --env-file=target/perf/perf.env -- k6 run perf/k6/cached_304.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/hot_200.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/mixed_read.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/filtered_read.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/cursor_walk.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/large_304.js
```

## k6 Scenario Requirements

Every k6 script must support:

- `BASE_URL`
- `DATA_GATE_TOKEN`
- Dataset id override when practical.
- Entity name override when practical.
- Duration override.
- VU or request-rate override.
- Expected audit sink label.
- Fixed HTTP protocol, keepalive, and compression settings where the tool supports them.

Scripts should use `Authorization: Bearer <key>` by default. A small compatibility scenario should also cover `X-Api-Key: <key>` because the server accepts both headers.

Every k6 script must check:

- Expected status.
- Response body expectations.
- Presence of ETag where expected.
- No unexpected `5xx`.

Every k6 script must declare `thresholds` so regressions fail the run with a non-zero exit code.

Expected `401` and `403` requests must be tagged or wrapped so they do not count as unexpected `http_req_failed` events. The report must still count them by status code.

Every k6 script must emit:

- Scenario name.
- Dataset id.
- Entity name.
- Expected response type.
- Request rate or VU count.
- Response byte summary.

## Audit Sink Matrix

Audit sink choice materially affects performance and must be pinned for every report.

Required sink coverage:

- `stdout` for developer smoke runs.
- `file` for normal local and CI perf runs.
- `chain` when audit chaining is enabled for a deployment profile.
- `syslog` only in environments where a real syslog target is configured.

Do not compare runs across different audit sinks as if they were the same workload.

## Protocol And Compression

Every reported run must state:

- HTTP version.
- Connection reuse behavior.
- Response compression setting.
- Client-side timeout.
- Server bind address.

Large JSON response tests should default to identity compression unless a compression feature is explicitly enabled in the server config. If compression is introduced later, run compressed and identity profiles separately.

## Cold Start Measurement

Cold start uses warm operating-system cache and cold process by default.

Procedure:

1. Run 10 independent cold-process starts.
2. Start the release binary with the same perf config.
3. Wait until `/ready` succeeds.
4. Send the first protected request.
5. Stop the process.
6. Report median and p95 of first protected request latency.

Optional cold-OS-cache runs may use platform-specific cache clearing, but they must be reported separately because they are more invasive and less portable.

## CI Strategy

CI should run fast checks only:

- Auth microbenchmark threshold or focused timing guard.
- Small cached `304` k6 smoke test, if `k6` is available in CI.
- Small hot `200` k6 smoke test, if `k6` is available in CI.
- Correctness tests for ETag behavior.

CI should not run million-row fixture generation on every commit unless the job is explicitly labeled as performance or nightly.

Scheduled or manual perf jobs should run:

- 100,000 row tests.
- 1,000,000 row tests.
- Mixed traffic.
- Large dataset `304`.
- Soak.
- Breakpoint test.

If k6 is not installed in CI, the job must either install a pinned version or skip the k6 smoke with an explicit skip reason.

## Reporting

Each run should write a short report under `target/perf/reports/` or an external CI artifact store.

Report fields:

- Git commit.
- Build profile.
- Machine or CI runner description.
- OS.
- Rust version.
- Server config path.
- Fixture manifest path.
- Scenario name.
- Tool versions.
- Start time.
- Duration.
- Request count.
- Status distribution.
- Latency percentiles.
- Error rate.
- Response byte summary.
- CPU and memory summary.
- Audit sink.
- HTTP protocol and compression settings.
- Pass/fail against thresholds.
- Notes on anomalies.

Do not commit generated reports unless a specific review asks for a captured baseline.

Regression comparison may be manual at first, using the report fields above. If automated gating is added later, define a checked-in baseline file with explicit tolerance per scenario. Do not compare against an unstated or machine-specific baseline.

## Acceptance Criteria

The load testing system is complete when:

- A developer can generate synthetic perf data from a documented command.
- A developer can start `data_gate` with a perf config without editing committed files.
- k6 scenarios exist for cached `304`, hot `200`, mixed reads, large `200`, large `304`, and soak.
- k6 scenarios exist for filtered reads, expanded reads, cursor walks, aggregates, DCAT-AP catalog generation, authorization-deny paths, and refresh-under-read-load.
- At least one small profile can run in CI or as a documented local smoke test.
- Large fixtures are reproducible and excluded from Git by default.
- Thresholds are declared in k6 scripts and fail with a non-zero exit code when latency or error rate regresses.
- Reports include enough context to compare results between versions.

## Product Implications To Monitor

Large full-collection JSON responses may become an API contract problem, not only an implementation problem. If tests show unstable memory or unacceptable latency for large reads, evaluate these product changes:

- Pagination.
- Field selection.
- Response compression.
- Explicit maximum response size.
- Export-oriented endpoint with different operational guarantees.
- Precomputed or metadata-based ETags.
- Streaming responses.

These changes require separate API decisions. The load test suite should make the pressure visible without silently changing public behavior.
