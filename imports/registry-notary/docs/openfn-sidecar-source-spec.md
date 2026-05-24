# Synchronous Adaptor Source Sidecar Spec

## Goal

Provide a small synchronous source sidecar that lets Registry Witness evaluate a
single-subject claim using OpenFn adaptors. The first implementation uses
OpenFn, but the contract is a synchronous Registry Data API-shaped source
contract, not an OpenFn-specific Witness connector.

## Architecture

Registry Witness calls the sidecar through the existing `registry_data_api`
source connector:

```text
GET /datasets/{dataset}/{entity}?{lookup_field}={lookup_value}&fields=a,b&limit=2
Authorization: Bearer <witness-to-sidecar-token>
Data-Purpose: <purpose>
```

The sidecar normalizes the target service response and returns:

```json
{ "data": [] }
```

or:

```json
{ "data": [{ "field": "value" }] }
```

It may return two records only to signal ambiguity. Registry Witness remains the
attestation authority: it owns caller auth, scopes, purpose, claim rules,
disclosure, provenance, audit, and credential issuance.

The production topology is sidecar-to-Witness over a private pod network or
localhost. The v1 channel uses a sidecar bearer token; token rotation is a known
deployment responsibility. Do not expose the sidecar publicly.

## V1 Execution Decision

Use a sidecar-owned, bounded pool of long-lived Node worker processes. Each
worker loads pinned OpenFn code and receives one request state at a time over a
private process channel. A subprocess-per-request CLI wrapper is acceptable only
for local proof-of-concept work.

Credentials never traverse a network socket; they stay within the sidecar
process tree.

OpenFn Lightning webhooks, work orders, and queued runs are not in the Witness
request path.

The sidecar owns concurrency:

- `max_workers` caps simultaneous OpenFn executions.
- Requests beyond capacity return `503` with `Retry-After`, not an unbounded
  in-memory queue.
- Each worker has a wall-clock timeout, memory limit, stdout/stderr byte limit,
  and forced kill path. The wrapper timeout must kill hung workers even if the
  OpenFn job timeout fails.
- Liveness restarts the sidecar if requests are arriving and no worker has
  completed a request within the configured liveness window.

## Credential And Job Loading

Target-service credentials are injected into the per-request OpenFn state as
`state.configuration` over the private worker channel. They must not be written
to per-request disk files. If a disk-backed fallback is ever added, it must use
mode `0600`, a per-request directory, and best-effort cleanup on timeout and
crash.

OpenFn jobs, adaptor versions, and credential schemas are declared in a sidecar
manifest bundled into the sidecar image:

```yaml
openfn:
  cli_build_tool: 1.2.5
  runtime: 1.9.3
limits:
  max_workers: 4
  worker_timeout_ms: 10000
  max_worker_memory_mb: 512
sources:
  openfn_crvs:
    dataset: civil_registry
    entity: civil_person
    job: jobs/opencrvs-person-lookup.js
    adaptor: "@openfn/language-http@7.2.0"
    credential_env: OPENCRVS_READER_CREDENTIAL_JSON
```

At startup, the sidecar verifies the installed OpenFn compiler/build tool,
runtime, and adaptor versions against the manifest. Readiness fails on any
mismatch, missing job, missing credential, missing smoke lookup, or failed smoke
lookup. Runtime execution must not fetch packages from the network.

## Requirements

- The sidecar must answer synchronously within a configured timeout.
- OpenFn build tooling, runtime, jobs, and adaptors must be version-pinned.
- Adaptors must be preinstalled or warmed before readiness succeeds.
- The sidecar must enforce `limit <= 2`, one lookup predicate, max output bytes,
  and max execution duration.
- The sidecar must enforce max request bytes and max single-query-parameter
  length before dispatching to a worker.
- The sidecar must pass `Data-Purpose` and correlation headers to downstream
  calls when the target adaptor supports it.
- The sidecar must emit structured logs and metrics with the inbound correlation
  ID, source id, outcome, duration, and worker id.
- The sidecar must not log or return credentials, raw secrets, credential
  lengths, credential hashes, or full environment dumps, including during
  startup and readiness checks.
- The sidecar must map outcomes to the RDA `data` array contract:
  not found `[]`, exact match `[record]`, ambiguous `[record1, record2]`.
- The sidecar trims extra fields from successful records before responding.
- If the target returns more than two matching records, the sidecar returns two
  records to preserve Witness's existing ambiguous-source behavior.

## HTTP Outcomes

| Cause | Sidecar status | Body shape |
| --- | --- | --- |
| Exact match | `200` | `{ "data": [record] }` |
| Not found | `200` | `{ "data": [] }` |
| Ambiguous | `200` | `{ "data": [record1, record2] }` |
| Missing or malformed sidecar token | `401` plus `WWW-Authenticate` | Problem Details |
| Well-formed but rejected sidecar token | `403` | Problem Details |
| Missing `Data-Purpose` | `400` | Problem Details |
| Invalid lookup, projection, or `limit > 2` | `400` | Problem Details |
| Worker pool saturated | `503` | Problem Details plus `Retry-After` |
| Target auth failure | `502` | Problem Details with operator-visible code |
| Target rate limit | `503` | Problem Details plus `Retry-After` when known |
| OpenFn worker crash or non-zero execution failure | `502` | Problem Details |
| Invalid or truncated OpenFn output | `502` | Problem Details |
| Worker wall-clock timeout | `504` | Problem Details |
| Oversized OpenFn output | `502` | Problem Details |

## Non-Goals

- Do not use OpenFn Lightning webhooks or queued runs for the synchronous Witness
  lookup path.
- Do not let OpenFn decide claim satisfaction or disclosure.
- Do not add a new Registry Witness connector until the RDA facade is proven
  insufficient. Trigger signals include needing typed source errors in Witness,
  needing request bodies instead of RDA query parameters, or needing Witness to
  participate in target-service OAuth flows.
- Do not support batch lookups in the first implementation.
- Do not retry OpenFn execution failures in v1; target reads may not be
  idempotent.

## Definition Of Done

Done means all items below are satisfied in one reviewed change set:

- A runnable sidecar exposes one RDA-shaped source endpoint backed by a pinned
  OpenFn job and returns only the documented `{ "data": [...] }` success shape.
- A manifest pins the OpenFn build tool, runtime, job files, adaptor versions,
  source-route bindings, timeout, worker memory limit, output byte limit,
  request byte limit, query-parameter length limit, and `max_workers`; startup
  rejects missing or mismatched entries.
- Startup/readiness fails until required adaptors are installed, credentials are
  present, the worker pool is available, and every configured source can execute
  a smoke lookup.
- Liveness distinguishes process health from readiness and remains responsive
  when workers are saturated or a worker is killed.
- A Registry Witness config points at the sidecar using `connector:
  registry_data_api` and evaluates one claim end to end through the sidecar.
- Automated tests cover exact match, not found, ambiguous result, invalid OpenFn
  output, timeout with worker kill, oversized output, missing purpose, bad
  sidecar token, worker-pool saturation, missing adaptor at boot, concurrent
  requests, truncated stdout, and no retry on OpenFn failure.
- Credential non-disclosure is verified on success and error paths, including an
  adaptor failure that writes state-like content to stderr.
- Logs, metrics, and HTTP responses are checked to confirm no configured
  credentials, target-service credentials, OpenFn environment secrets, or full
  request state are disclosed.
- Focused sidecar tests, affected `registry-witness-server` tests, formatter,
  linter, and build checks pass in CI or an equivalent local verification run.
- Implementation docs include local run instructions, manifest fields, expected
  deployment topology, and the exact verification commands used.
- A final reviewer pass confirms every DoD bullet with linked test, command, or
  code evidence before the work is called complete.

## Implementation Plan

Wave 0: Design Freeze And Review

- Lead: parent agent.
- Work: freeze this spec, list open product decisions, and create review
  checklist from the DoD.
- Review gate: one reviewer signs off that credential injection, concurrency,
  error mapping, readiness, and non-disclosure requirements are unambiguous.

Wave 1: Contract Harness

- Worker A owns sidecar HTTP contract tests and mock OpenFn worker fixtures.
- Worker B owns Registry Witness integration config and end-to-end test harness.
- Work can run in parallel because Worker A stays in the sidecar package and
  Worker B stays in Witness test/config surfaces.
- Review gate: tests fail against an empty sidecar and cover every HTTP outcome
  in the spec.

Wave 2: Sidecar Core

- Worker A owns manifest loading, version checks, route binding, and
  readiness/liveness.
- Worker C owns worker-pool lifecycle, per-request state injection, timeout,
  kill, output-size enforcement, and saturation behavior.
- Shared rule: no worker edits the same module without parent coordination.
- Review gate: code review checks process isolation, no credential files,
  bounded concurrency, and deterministic startup failure modes.

Wave 3: OpenFn Execution And Normalization

- Worker C owns pinned OpenFn worker execution.
- Worker D owns RDA normalization, field trimming, ambiguity handling, and error
  mapping.
- Review gate: reviewer validates the sidecar never returns OpenFn-native output
  directly and all failures map to the status table.

Wave 4: Security, Observability, And Negative Tests

- Worker E owns redaction tests, stderr/log leak tests, correlation IDs, metrics,
  and structured logs.
- Worker B extends Witness end-to-end tests for success and source failure.
- Review gate: security review verifies no secrets in logs, responses, temp
  files, process args, or failed worker output.

Wave 5: Final Integration

- Parent agent integrates branches, resolves conflicts, runs full focused
  verification, and updates docs.
- A reviewer performs a final diff review against the DoD checklist.
- Completion requires every DoD bullet to be marked with evidence. Partial
  implementation is not accepted unless the remaining item is listed as a
  blocker with an exact reason and the feature is not presented as done.
