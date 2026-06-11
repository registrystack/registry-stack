# registry-notary Performance Testing

Scaffolding for local, CI, and scheduled performance runs against the
`registry-notary` HTTP service. Goals: measure authenticated claim evaluation
latency, CEL-derived claim cost, batch evaluate throughput, peak outbound
concurrency, and the correctness of the politeness cap (Stage 1 DoD).

Notary's claim evaluation calls an upstream source over HTTP (DCI). To
isolate notary latency from any specific upstream, this harness ships a small
deterministic stub server (`perf/stub/source_stub.py`) that responds to DCI
search requests with seed-42 records. The perf configs point notary at the
local stub. Replacing the stub with a real upstream (a registry-relay running
its own perf config, for example) is left as a follow-up.

Credential issuance (`POST /v1/credentials`) is intentionally not covered in
v1: it requires a holder DID and a fresh Ed25519 proof of possession per
request, which is awkward to generate live in k6. Adding that scenario is
tracked separately.

---

## Setup

1. Install toolchain dependencies via `mise`:

   ```bash
   mise install
   ```

2. Build the release binary:

   ```bash
   cargo build --release -p registry-notary-bin
   ```

   The binary is written to `target/release/registry-notary`.

3. Install `k6` (see [k6 docs](https://k6.io/docs/get-started/installation/)).
   k6 v2.x is supported. Note: k6 v2 removed the `vu` export from `k6`; all
   scenarios in this harness use the globals `__VU` and `__ITER` instead.

---

## Generate API keys and signing material

```bash
uv run perf/scripts/generate_perf_keys.py --env-file target/perf/perf.env
```

Use `--force` to overwrite an existing file. File mode is set to `0600`.
Raw token values are never printed to stdout: only variable names and the
output path are reported.

The script writes:

- bearer + API-key tokens for the notary service (one shared verification
  identity matching the demo config, plus a deny-path identity)
- a bearer token consumed by the notary process when it calls the source stub
- an Ed25519 private JWK used by the notary credential issuer (notary will
  refuse to start without it, even if no issuance scenario is run)
- the base URL, claim ids, and subject id prefix that the k6 scenarios read

Do NOT commit `target/perf/perf.env`. It is gitignored.

---

## Start the source stub

```bash
uv run perf/stub/source_stub.py --profile medium
```

The stub binds `127.0.0.1:14256` by default and serves DCI search responses on
the paths notary expects:

- `POST /dci/crvs/registry/sync/search` (birth_date lookups)
- `POST /dci/fr/registry/sync/search` (farmed_land_size_hectares lookups)

Both paths accept the bearer token from
`EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN`. Records are derived from a fixed
seed (42); the `--profile` flag selects how many distinct subjects respond
with hits (1k for `small`, 100k for `medium`).

The stub is intentionally minimal: it implements the response shape notary
parses (`message.search_response[0].data.reg_records`) and nothing else. It
is not a registry-relay replacement.

### Stub flags

| Flag                  | Default | Description                                                       |
|-----------------------|---------|-------------------------------------------------------------------|
| `--profile`           | medium  | Subject pool size (`small`=1k, `medium`=100k).                    |
| `--bind`              | 127.0.0.1:14256 | Listen address.                                         |
| `--median-latency-ms` | 0       | Artificial median latency added to every search response (ms).    |
| `--jitter-ms`         | 0       | Uniform random jitter applied around the median (ms). The actual delay is `median + U(-jitter, +jitter)`, floored at 0. |

Example with simulated upstream latency:

```bash
uv run perf/stub/source_stub.py --profile small \
    --median-latency-ms 100 --jitter-ms 20
```

### Stub observability endpoints

| Endpoint              | Method | Description                                                         |
|-----------------------|--------|---------------------------------------------------------------------|
| `GET  /_stats`        | GET    | Returns `{"in_flight": N, "peak_in_flight": M, "total": T}`.       |
| `POST /_stats/reset`  | POST   | Resets all counters to 0. Returns `{"reset": true}`.               |
| `GET  /health`        | GET    | Returns `{"status": "ok"}`.                                         |

`peak_in_flight` is the assertion surface for Stage 1 DoD. After the
process-global semaphore lands, two concurrent `batch_evaluate` calls against
the same `source_connection` must observe combined inbound concurrency at the
stub capped at `max_in_flight`. The `/_stats` endpoint makes this observable
without a proxy or network tap.

---

## Start the notary server

With [1Password CLI](https://developer.1password.com/docs/cli/):

```bash
op run --env-file=target/perf/perf.env -- \
  target/release/registry-notary --config perf/config/medium.yaml
```

Without 1Password (source the env file directly):

```bash
set -a
. target/perf/perf.env
set +a
target/release/registry-notary --config perf/config/medium.yaml
```

Probe `/ready` and wait for `200`; it fails closed when a configured Redis
replay or credential-status backend is unavailable. To also verify
authenticated catalog access, probe `GET /v1/claims` and require a `2xx`
response. Any `4xx` or `5xx` response means the route, token, or server state
is not ready for perf measurement:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:14255/ready

curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $REGISTRY_NOTARY_BEARER_TOKEN" \
  http://127.0.0.1:14255/v1/claims
```

---

## Run k6 scenarios

All scenarios require `Accept: application/vnd.registry-notary.claim-result+json`
for evaluate and batch-evaluate requests. The scenarios set this automatically.
Generic `Accept: application/json` returns 406.

```bash
op run --env-file=target/perf/perf.env -- k6 run perf/k6/evaluate_extract.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/evaluate_cel.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/batch_evaluate_10.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/batch_evaluate_100.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/batch_evaluate_1000.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/politeness_concurrent.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/list_claims.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/auth_deny.js
```

Or source the env file and call `k6 run` directly. Each scenario writes its
result to `target/perf/results/<scenario>.json` so baselines can be diffed.
Set `REGISTRY_NOTARY_NO_THRESHOLD=1` only for CI smoke or wiring checks where
the goal is to verify that the scenario runs, not to enforce capacity targets.

---

## Capture a performance baseline

`perf/scripts/capture_baseline.py` starts the stub and notary, runs the full
scenario set, and writes a composite JSON to `perf/baselines/<tag>.json`. This
is the recommended way to produce a baseline for regression comparisons.

```bash
uv run perf/scripts/capture_baseline.py \
  --env-file target/perf/perf.env \
  --tag pre-stage-1 \
  --stub-profile small \
  --duration 20s \
  --skip-1000
```

To capture a baseline with simulated latency (better politeness numbers):

```bash
uv run perf/scripts/capture_baseline.py \
  --env-file target/perf/perf.env \
  --tag pre-stage-1-100ms-stub \
  --stub-profile small \
  --stub-latency-ms 100 \
  --stub-jitter-ms 10 \
  --duration 30s \
  --skip-1000
```

The baseline file records:

- `p50_ms` / `p95_ms` (p99 if available) per scenario
- `requests_per_sec` and `iterations` per scenario
- `stub_peak_in_flight`: peak concurrent in-flight requests at the stub
- `k6_exit_code`: 0 = all thresholds passed

Baselines live in `perf/baselines/`. Committed baselines represent the state
at a specific git commit. Do not commit baselines produced by a dirty tree for
regression purposes; use the git tag from `--tag` to identify the snapshot.

### Reading baselines for Stage 1 assertions

After Stage 1 lands, re-capture the baseline and assert:

- `stub_peak_in_flight <= max_in_flight` (default 8) for all batch scenarios.
- `batch_evaluate_100.p50_ms < pre_stage_1.batch_evaluate_100.p50_ms / concurrency.subjects`
  approximately (i.e., concurrency actually reduces wall-clock time).

The `/_stats/reset` call in `capture_baseline.py` ensures each scenario's
`stub_peak_in_flight` is independent.

---

## Profiles

| Profile | Subjects | Use case                              |
|---------|----------|---------------------------------------|
| small   | 1,000    | CI smoke check, quick iteration       |
| medium  | 100,000  | Standard developer run                |

`small` and `medium` are stub-side data sizes. The notary process itself sees
exactly one record per request, so notary memory is flat across profiles.
The profile influences only how widely k6 spreads its subject ids and so how
much cache locality the stub can exploit.

**Important**: set `REGISTRY_NOTARY_SUBJECT_COUNT` to match the stub profile.
The default env file sets it to 100000 (medium). For `--profile small`, pass
`-e REGISTRY_NOTARY_SUBJECT_COUNT=1000` to k6 or use `capture_baseline.py`
which does this automatically.

There is no `large` profile. Notary does not scan datasets: per-request work
is bounded by claim depth, source latency, and signing cost. Adding a 1M-row
tier would not exercise additional notary behavior.

---

## Scenarios

| Scenario                  | Endpoint                        | What it measures                                                          |
|---------------------------|---------------------------------|---------------------------------------------------------------------------|
| `evaluate_extract`        | POST /v1/evaluations           | Hot path: auth, single source fetch, extract rule, audit emit             |
| `evaluate_cel`            | POST /v1/evaluations           | CEL-derived claim (`farmer-under-4ha` depends on `farmed-land-size`)      |
| `batch_evaluate_10`       | POST /v1/batch-evaluations     | Batch of 10 subjects; baseline for Stage 1 concurrency comparison         |
| `batch_evaluate_100`      | POST /v1/batch-evaluations     | Batch of 100 subjects (equals `inline_batch_limit`); Stage 1 key scenario |
| `batch_evaluate_1000`     | POST /v1/batch-evaluations     | Batch of 1000 subjects; expects 413 today (see Known Gaps)                |
| `batch_evaluate`          | POST /v1/batch-evaluations     | Dynamic batch size via `REGISTRY_NOTARY_BATCH_SIZE`                      |
| `politeness_concurrent`   | POST /v1/batch-evaluations     | Two concurrent batch calls; asserts `stub_peak_in_flight` (Stage 1 DoD)  |
| `list_claims`             | GET /v1/claims                 | Catalog read, no source IO                                                |
| `auth_deny`               | mixed                           | 401 (missing/invalid token) and 403 (deny-path identity) only             |

All scenarios pass `data-purpose: perf` so notary's purpose-required check is
satisfied.

Each scenario's `handleSummary` writes to two locations:

- `target/perf/reports/<scenario>-<timestamp>.{json,txt}` (timestamped archive)
- `target/perf/results/<scenario>.{json,txt}` (stable path for baseline script)

---

## Runner script

`perf/scripts/run_scenario.py` orchestrates a single run end-to-end: it starts
the source stub, starts the notary binary, waits for both to come up, runs a
named k6 scenario while sampling the notary process (CPU, RSS, threads, FDs
on Linux), and tears down cleanly.

```bash
uv run perf/scripts/run_scenario.py \
  --scenario perf/k6/evaluate_extract.js \
  --notary-config perf/config/medium.yaml \
  --stub-profile medium \
  --env-file target/perf/perf.env
```

Note: `run_scenario.py` does not pass stub latency flags. Use
`capture_baseline.py` for baseline runs with latency simulation.

---

## Python test suite

`perf/tests/` contains pytest tests for the stub itself. Run with:

```bash
cd perf && uv run pytest tests/test_stub_inflight.py -v
```

Tests cover:

- `/_stats` shape: `in_flight`, `peak_in_flight`, `total` present and integer.
- `POST /_stats/reset` zeros all counters.
- Concurrent requests: `peak_in_flight >= N` for N concurrent requests (with
  `--median-latency-ms` ensuring they overlap in time).
- Latency simulation: single request takes at least `median - jitter` ms.

---

## Environment Variables

| Variable                                | Default                  | Description                                            |
|-----------------------------------------|--------------------------|--------------------------------------------------------|
| `REGISTRY_NOTARY_BASE_URL`             | `http://127.0.0.1:14255` | Notary base URL used by k6 scripts                    |
| `REGISTRY_NOTARY_BEARER_TOKEN`         | (generated)              | Bearer token with civil+farmer evidence scopes         |
| `REGISTRY_NOTARY_BEARER_TOKEN_HASH`    | (generated)              | Server-side SHA-256 fingerprint for bearer auth        |
| `REGISTRY_NOTARY_API_KEY`              | (generated)              | API-key token (same scopes; exercised in auth_deny)    |
| `REGISTRY_NOTARY_API_KEY_HASH`         | (generated)              | Server-side SHA-256 fingerprint for API-key auth       |
| `REGISTRY_NOTARY_NO_SCOPE_TOKEN`       | (generated)              | Valid bearer token with no evidence scopes (deny path) |
| `REGISTRY_NOTARY_NO_SCOPE_TOKEN_HASH`  | (generated)              | Server-side SHA-256 fingerprint for no-scope auth      |
| `REGISTRY_NOTARY_TOKEN_INVALID`        | `not-a-real-token-xxxx`  | Deliberately invalid token for 401 tests               |
| `REGISTRY_NOTARY_AUDIT_HASH_SECRET`    | (generated)              | HMAC secret for audit primary-key hashing              |
| `REGISTRY_NOTARY_PROFILE`              | `medium`                 | Profile name read by k6 for logs and tags              |
| `REGISTRY_NOTARY_BATCH_SIZE`           | `10`                     | Subjects per batch in `batch_evaluate.js`              |
| `REGISTRY_NOTARY_SUBJECT_COUNT`        | (matches stub profile)   | Pool size of distinct subject ids k6 cycles through    |
| `REGISTRY_NOTARY_CLAIM_EXTRACT`        | `date-of-birth`          | Claim id used in `evaluate_extract.js`                 |
| `REGISTRY_NOTARY_CLAIM_CEL`            | `farmer-under-4ha`       | Claim id used in `evaluate_cel.js`                     |
| `EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN`  | (generated)              | Bearer token notary sends to the source stub          |
| `EVIDENCE_SOURCE_STUB_BIND`             | `127.0.0.1:14256`        | Stub listen address                                    |
| `REGISTRY_NOTARY_ISSUER_JWK`           | (generated Ed25519 JWK)  | Required by notary even when issuance is not exercised |

Client scenarios use raw bearer and API-key values. Server config reads only
`sha256:<64 hex>` fingerprints from committed `fingerprint` references; raw
tokens must not be stored in config. Regenerate perf credentials with
`perf/scripts/generate_perf_keys.py` so the config commitments match the new
fingerprints.

---

## Known Gaps

1. **`batch_evaluate_1000` returns 413**: the perf config sets
   `inline_batch_limit: 100` and each claim's `max_subjects: 100`. Sending
   1000 subjects in one request hits the limit check before any source IO.
   The scenario is included as a forward reference for when the limit is
   relaxed. Expect 413 responses and a note in the result file.

2. **Credential issuance (`POST /v1/credentials`) not covered**: requires a
   holder DID and a fresh Ed25519 proof of possession per request. k6 does not
   have an Ed25519 library out of the box. Tracked separately.

3. **`stub_peak_in_flight = 1` at zero stub latency**: when the stub has no
   added latency, it responds fast enough that sequential notary fan-out
   completes each request before the next one is dispatched. The counter still
   records correctly; you just need `--stub-latency-ms >= 50` to observe
   meaningful overlap. The `pre-stage-1-100ms-stub.json` baseline uses 100ms
   latency and is the recommended reference for Stage 1 politeness assertions.

5. **No hot-reload of stub config**: changing `--median-latency-ms` requires a
   full restart of the stub. Baselines that mix latency settings need separate
   stub processes (which `capture_baseline.py` handles automatically).
