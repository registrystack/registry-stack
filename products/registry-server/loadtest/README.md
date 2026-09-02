# Registry Server load-test environment

A self-contained local stack for measuring Registry Server with pinned
PostgreSQL 17, Registry Mint, the `business-establishments` acceptance fixture,
and the opt-in private metrics listener. Everything disposable lives under
`loadtest/.run` and is never committed.

All seeded data is synthetic and deterministically generated from a fixed
seed. No real business, person, or identifier is involved.

## Prerequisites

- `cargo`, `docker`, `openssl`, `python3`, `uv`
- `k6` (`brew install k6`)

## Quick start

```bash
products/registry-server/loadtest/up.sh
products/registry-server/loadtest/seed.py --count 100000
products/registry-server/loadtest/run.sh --profile cursor-smoke
products/registry-server/loadtest/run.sh --profile steady
products/registry-server/loadtest/run.sh --profile sweep
products/registry-server/loadtest/down.sh
```

`up.sh --pool-max N` sizes the PostgreSQL pool (default 32, bound 1..128).
`seed.py --workers N` bounds concurrent batch requests (default 4). Seeds of
100,000 records or more run PostgreSQL `ANALYZE` after import. The documented
full-scale seed is 500,000 records.

## Operations are not HTTP requests

Rate settings are operations per second (`OPS`), not HTTP TPS. A workload
operation can issue more than one request:

- a paginated list follows page two when a cursor is present;
- a patch first fetches the current ETag;
- a virtual user may refresh its cached access token.

Every result therefore reports offered operations/s, achieved operations/s,
and actual HTTP requests/s separately.

## Profiles

| Profile | Default shape | Question it answers |
|---|---|---|
| `cursor-smoke` | one filtered page plus its continuation | Did the harness really execute page two with the Registry Server cursor contract? |
| `steady` | 50 operations/s, mixed workload, 10 min | Does the target rate hold without drops or failures and with p99 below 250 ms? |
| `sweep` | excluded warmup at 50 operations/s, then independent 2 min holds at 50, 75, 100, 125, and 150 | At which held rate do drops, errors, or tail-latency failure begin? |
| `burst` | 50 operations/s baseline, 30 s ramp to 250, 30 s hold, 30 s ramp down, 3 min recovery | Is a 5x campaign burst graceful, and does the service return to its baseline SLO? |
| `herd` | 200 VUs, one token and one protected read each | Does a coordinated client restart overload Mint or Registry Server? |
| `token-soak` | ramp to 200 VUs for 1 min | How does sustained token minting behave? This is intentionally separate from the one-shot herd. |

The steady mix is 40% code lookup, 30% point get, 20% filtered list, 7%
create, and 3% preconditioned patch. Sweep and burst are read-only. Workload
selection uses a deterministic per-VU PRNG (`RANDOM_SEED=20260902` by default).

## Tuning

`run.sh` accepts `--profile`, `--ops`, and `--duration`; other non-sensitive
arguments pass through to k6. HTTP debug and system-tag overrides are refused
because they can expose credentials, cursors, URLs, or record identifiers.
Profile-specific environment variables are:

- `steady`: `OPS=50`, `DURATION=10m`, `FOLLOW_CURSOR=1`
- `sweep`: `RATES=50,75,100,125,150`, `HOLD=2m`, `WARMUP_OPS=50`, `WARMUP_DURATION=2m`
- `burst`: `OPS=50`, `PEAK_OPS=250`, `BASELINE_DURATION=2m`, `RAMP_DURATION=30s`, `PEAK_DURATION=30s`, `RECOVERY_DURATION=3m`
- `herd`: `VUS=200`, `DURATION=30s` (maximum completion time)
- `token-soak`: `VUS=200`, `DURATION=1m`
- all workload profiles: `RANDOM_SEED`, `FOLLOW_CURSOR`

Examples:

```bash
products/registry-server/loadtest/run.sh --profile steady --ops 75 --duration 15m
RATES=50,60,70,80,90 HOLD=3m products/registry-server/loadtest/run.sh --profile sweep
PEAK_OPS=300 products/registry-server/loadtest/run.sh --profile burst
```

## Evidence

Each measured run gets an owner-only directory under `.run/results/` with:

- `manifest.json`: Git revision and dirty state, non-secret host/tool versions,
  pool size, seed counts, exact profile parameters, and timestamps;
- `k6-summary.json` and `k6-samples.json`: threshold data and raw metric
  samples with the system tag set restricted to status, method, operation name,
  scenario, and expected-response status;
- `telemetry.jsonl`: one-second Registry Server metrics plus local server and
  Mint CPU/RSS samples;
- `db-before.json`, `db-waits.jsonl`, and `db-after.json`: per-run-reset
  statement timing by safe category/query id, continuous wait counts, table
  sizes, and audit-chain length;
- `result.json`: the mechanically generated throughput, errors, drops, 504s,
  p50/p95/p99 by operation and phase, telemetry peaks, DB wait peaks, and SLO
  verdict;
- `safety.json`: evidence scan proving configured secrets, seeded record-id
  canaries, compact JWTs, unsafe k6 tags, SQL text, and response bodies were not
  persisted.

The sweep also creates `sweep-result.json`, including the first held rate that
failed its thresholds. The warmup is deliberately excluded from measurement,
and PostgreSQL statement statistics are reset before every held rate.

The harness never saves bearer tokens, client secrets, cursors, source records,
raw principals, request/response bodies, audit payloads, SQL text, or bound SQL
values. It passes secrets to k6 through the process environment, not command
arguments.

## Database diagnostics

The run wrapper captures DB diagnostics automatically. These commands are also
available for focused investigation:

```bash
products/registry-server/loadtest/dbstats.sh reset
products/registry-server/loadtest/dbstats.sh snapshot
products/registry-server/loadtest/dbstats.sh sample 1
products/registry-server/loadtest/dbstats.sh analyze
```

`pg_stat_statements` is cumulative until reset. A point-in-time snapshot alone
cannot attribute time to a profile or establish peak lock/pool pressure, which
is why measured runs reset it and sample waits continuously.

## Interpreting results

- The audit chain is a strong bottleneck hypothesis because audited requests
  serialize updates to a singleton chain head, but the harness should prove
  it per run using audit wait peaks and post-reset statement timing.
- Rising latency with low pool waiters points toward transaction/query work.
  Rising pool waiters indicates pool pressure.
- 504 `request.timeout` responses are saturation, not successful throughput.
- Capacity is the highest held rate that meets its full thresholds, not a rate
  merely touched during a ramp.
- Recovery is a separate burst scenario. Do not average it together with the
  overloaded phase.
- macOS Docker figures are directional. Re-run candidate capacity claims on a
  representative Linux host before citing them.

## Verification

```bash
python3 -m unittest products/registry-server/loadtest/support/test_evidence.py -v
bash -n products/registry-server/loadtest/{up,down,run,dbstats}.sh
for profile in products/registry-server/loadtest/profiles/*.js; do
  k6 inspect -e \
    ESTABLISHMENT_IDS_FILE=products/registry-server/loadtest/.run/seed/establishment-ids.txt \
    "$profile" >/dev/null
done
```

The inspect loop requires the synthetic seed pool because workload profiles
load it during k6 initialization. The live `cursor-smoke` is the end-to-end
proof that continuation actually occurs.
