# registry-relay Performance Testing

This directory contains the scaffolding for local, CI, and scheduled performance runs
against the `registry-relay` HTTP service. The goal is to measure authenticated read latency,
ETag/304 cache behaviour, aggregate throughput, and error-path predictability across
small (1k), medium (100k), and large (1M) synthetic datasets.

---

## Setup

1. Install toolchain dependencies via `mise`:

   ```bash
   mise install
   ```

2. Build the release binary:

   ```bash
   cargo build --release
   ```

3. Install `k6` for HTTP load scenarios (see [k6 docs](https://k6.io/docs/get-started/installation/)).

---

## Generate Fixtures

Fixtures are synthetic and deterministic (fixed seed 42). They are not committed;
generate them locally before starting the server.

```bash
# Medium profile: 1k, 10k, 100k parquet + 100k CSV (recommended for everyday runs)
uv run perf/scripts/generate_perf_data.py --profile medium

# Large profile: adds 1M, wide_100k, strings_100k
uv run perf/scripts/generate_perf_data.py --profile large

# All tiers including optional 5M
uv run perf/scripts/generate_perf_data.py --profile all --include-5m

# Custom output directory (useful for CI isolation)
uv run perf/scripts/generate_perf_data.py --profile medium --out-dir /tmp/perf-fixtures
```

Generated files land in `perf/fixtures/generated/` (gitignored). A `manifest.json`
is written there after each run listing each fixture's path, row count, column count,
file size, schema, seed, and generation timestamp.

---

## Generate API Keys

```bash
uv run perf/scripts/generate_perf_keys.py --env-file target/perf/perf.env
```

Use `--force` to overwrite an existing file. The script sets file permissions to
`0600` automatically. Raw token values are never printed to stdout; only variable
names and the output path are reported.

Do NOT commit `target/perf/perf.env`. It is gitignored.

---

## Start the Server

With [1Password CLI](https://developer.1password.com/docs/cli/):

```bash
op run --env-file=target/perf/perf.env -- \
  target/release/registry-relay --config perf/config/medium.yaml
```

Without 1Password (source the env file directly):

```bash
set -a
. target/perf/perf.env
set +a
target/release/registry-relay --config perf/config/medium.yaml
```

Wait until `/ready` returns `200` before sending load:

```bash
curl -s http://127.0.0.1:18080/ready
```

---

## Run k6 Scenarios

k6 scripts live in `perf/k6/`. Pass the env file so k6 picks up the token and
base URL:

```bash
op run --env-file=target/perf/perf.env -- k6 run perf/k6/cached_304.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/hot_200.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/mixed_read.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/evidence verification scenario
```

Or source the env file and run k6 directly:

```bash
set -a; . target/perf/perf.env; set +a
k6 run perf/k6/cached_304.js
```

---

## Profiles

| Profile | Source fixture           | Rows  | Use case                            |
|---------|--------------------------|-------|-------------------------------------|
| small   | clinic_capacity_1k       | 1,000 | CI smoke check, quick iteration     |
| medium  | clinic_capacity_100k     | 100k  | Standard developer run              |
| large   | clinic_capacity_1m       | 1M    | Regression, capacity, latency budgets |

Config files in `perf/config/` mirror these profiles. Each config uses
`auth.mode: api_key` with the five key ids from `generate_perf_keys.py`
(`perf_rows`, `perf_metadata`, `perf_aggregate`, `perf_no_scope`,
`perf_evidence_verification`). The evidence-verification key carries the
`clinic_capacity:evidence_verification` scope and is the only key that can
exercise `perf/k6/evidence verification scenario`.

The `large` profile requires roughly 2 GB of memory for the server process.
The optional 5M tier (`--include-5m`) requires ~8 GB and should only be used on
capable hardware; skips must be noted in the report with machine specs and reason.

---

## Evidence Verification Scenario

`perf/k6/evidence verification scenario` exercises
`POST /evidence-offerings/{offering_id}/verifications` with a weighted mix:

| Mix | Decision   | Ruleset                | Why                                                                |
|-----|------------|------------------------|--------------------------------------------------------------------|
| 30% | match      | `facility-identity-v1` | Happy path, exercises HMAC + Ed25519 receipt sign                  |
| 50% | mismatch   | `facility-identity-v1` | Dominant adversarial workload; the path most worth baselining      |
| 20% | ambiguous  | `facility-region-v1`   | Rare but a deliberate timing outlier per the spec                  |

The scenario tags each request with `decision_expected: "match"|"mismatch"|"ambiguous"`,
so `http_req_duration` can be reported per decision path. Per-path thresholds
are defined inline in the scenario (first-pass: p95<50ms for match/mismatch,
p95<150ms for ambiguous; tighten after a baseline run). The aggregate
`evidence_verification` threshold key in `perf/k6/lib/common.js` is a backstop.

**The scenario requests
`application/vnd.registry-relay.evidence-verification+jwt`**, so the handler
returns a compact-serialized Ed25519-signed JWS. The decision is verified by
base64url-decoding the JWS payload segment and reading its `decision` claim.
The signature is NOT validated by k6: we trust the in-process signer and use k6
only for end-to-end latency.

The scenario depends on:

- `REGISTRY_RELAY_TOKEN_EVIDENCE_VERIFICATION` (generated by `generate_perf_keys.py`)
- `CLAIM_VERIFICATION_BINDING_KEY` env var on the server side (also generated)
- `REGISTRY_RELAY_PROVENANCE_JWK` env var on the server side: JSON-encoded
  Ed25519 private JWK for the receipt signer (also generated)
- The `claim_verification:` matching-engine block and `provenance:` block in
  `perf/config/*.yaml`

The match and mismatch cases target `fac-000000` from the seed-42 fixture. The
ambiguous case targets `region_code=R002`, which contains ~5,000 rows in the
100k fixture.

**Caveats:**

- The spec deliberately does not normalize timing between match, mismatch, and
  ambiguous. The per-decision tags exist precisely so future regressions in
  this asymmetry are observable.
- `did:web:127.0.0.1%3A18080` in the perf provenance block is a self-referencing
  placeholder so the server can boot in `gateway` issuer mode. The receipt
  carries this `iss` and the matching `kid`, but no external resolver fetches
  it during the perf run, so the value never needs to be reachable from
  outside the host.

---

## Criterion Microbenchmarks

`benches/claim_verification_bench.rs` covers the internal matching and receipt
hot path in isolation:

| Group                                  | Measures                                                          |
|----------------------------------------|-------------------------------------------------------------------|
| `normalize_small` / `_typical`         | `normalize_claim_value_for_hash` cost vs claim cardinality        |
| `hmac_small` / `_typical`              | Full HMAC envelope (canonicalize + HMAC-SHA256)                   |
| `jwt_receipt_small` / `_typical`       | Ed25519 EdDSA receipt signing on the typical payload              |

Run with:

```bash
cargo bench --bench claim_verification_bench
```

The k6 scenario covers the request path end to end; the criterion bench
isolates per-component cost so a future regression can be localized.

---

## Runner and Report Scripts

`perf/scripts/run_scenario.py` orchestrates starting the server, warming it up,
running a named k6 scenario, and stopping the server cleanly.

`perf/scripts/report.py` reads k6 JSON output and the manifest to produce a
structured performance report.

Both scripts are part of the committed performance harness and are documented there.

---

## Quick Postgres Live Comparison

Postgres live reads are freshness-first, not the high-throughput path. For a
quick local comparison, use the same machine and dataset shape for all runs:

1. Run the env-gated Postgres integration smoke to verify the live connector:

   ```bash
   DATA_GATE_POSTGRES_TEST_URL='postgres://localhost:55432/postgres?sslmode=disable' \
     cargo test --test postgres_snapshot -- --ignored --nocapture
   ```

2. Compare three query shapes from application logs and `/metrics`:

   - snapshot table query over a cached DataFusion table
   - Postgres live query selecting all declared columns
   - Postgres live query selecting only the entity fields needed by the request

3. Scrape the admin listener's `/metrics` after the live runs and compare:

   ```text
   registry_relay_datasource_live_scan_duration_seconds
   registry_relay_datasource_live_scan_wait_seconds
   registry_relay_datasource_live_scan_rows_total
   registry_relay_datasource_live_scan_bytes_total
   ```

The expected shape is simple: snapshot should be fastest for repeated reads,
Postgres live full export should be slowest, and Postgres live projection should
reduce exported bytes when callers request narrow fields. Treat live as the
correct choice only when freshness is worth the upstream database round trip.

---

## Environment Variables

| Variable                                  | Default                  | Description                                            |
|-------------------------------------------|--------------------------|--------------------------------------------------------|
| `REGISTRY_RELAY_BASE_URL`                 | `http://127.0.0.1:18080` | Server base URL used by k6 scripts                     |
| `REGISTRY_RELAY_TOKEN`                    | (generated)              | Token with `clinic_capacity:rows` scope                |
| `REGISTRY_RELAY_TOKEN_METADATA`           | (generated)              | Token with `clinic_capacity:metadata` scope            |
| `REGISTRY_RELAY_TOKEN_AGGREGATE`          | (generated)              | Token with `clinic_capacity:aggregate` scope           |
| `REGISTRY_RELAY_TOKEN_NO_SCOPE`           | (generated)              | Valid token with no `clinic_capacity:*` scope          |
| `REGISTRY_RELAY_TOKEN_EVIDENCE_VERIFICATION` | (generated)              | Token with `clinic_capacity:evidence_verification` scope  |
| `REGISTRY_RELAY_TOKEN_INVALID`            | `not-a-real-token-xxxx`  | Deliberately invalid token for 401 tests               |
| `REGISTRY_RELAY_DATASET_ID`               | `clinic_capacity`        | Dataset id used in k6 URL construction                 |
| `REGISTRY_RELAY_ENTITY`                   | `facility`               | Entity name used in k6 URL construction                |
| `PERF_ROWS_KEY_HASH`                      | (generated sha256 hash)  | Fingerprint read by registry-relay for `perf_rows`     |
| `PERF_METADATA_KEY_HASH`                  | (generated sha256 hash)  | Fingerprint for `perf_metadata`                        |
| `PERF_AGGREGATE_KEY_HASH`                 | (generated sha256 hash)  | Fingerprint for `perf_aggregate`                       |
| `PERF_NO_SCOPE_KEY_HASH`                  | (generated sha256 hash)  | Fingerprint for `perf_no_scope`                        |
| `PERF_EVIDENCE_VERIFICATION_KEY_HASH`        | (generated sha256 hash)  | Fingerprint for `perf_evidence_verification`              |
| `CLAIM_VERIFICATION_BINDING_KEY`          | (generated `hex:`)       | HMAC key for `claim_hash`; must stay stable across restarts |
| `REGISTRY_RELAY_AUDIT_HASH_SECRET`        | (generated)              | HMAC secret for sensitive audit identifiers; must stay stable across restarts |
| `REGISTRY_RELAY_PROVENANCE_JWK`           | (generated Ed25519 JWK)  | Private signing key for the evidence-verification receipt issuer |

All hash env vars follow registry-relay's convention: `sha256:<64 lowercase hex chars>`.
`CLAIM_VERIFICATION_BINDING_KEY` follows the format `hex:<64 lowercase hex chars>`
(see `docs/configuration.md` evidence-verification section).
