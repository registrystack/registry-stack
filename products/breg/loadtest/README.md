# Base Registry Engine load-test environment

A local environment for measuring Base Registry Engine with the
`business-establishments` acceptance fixture. The launcher delegates the whole
service lifecycle to `bregctl dev`: its pinned PostgreSQL 17 container, stock
ThunderID 1.0.1 issuer, package rehearsal and activation, credentials, retained
state, and supervised BReg process. Load evidence and deterministic synthetic
seed data live under `loadtest/.run` and are never committed.

The acceptance fixture's alternate no-purpose schema-test step is omitted from
the copied load project because a native development project binds exactly one
client to each access profile. The fixture continues to own that authorization
proof. The load client carries the ordinary `business-operator` claims used by
the remaining journey and workload.

## Prerequisites

- `cargo`, `docker`, `python3`
- `k6` (`brew install k6`)

## Quick start

```bash
products/breg/loadtest/up.sh
products/breg/loadtest/seed.py --count 100000
products/breg/loadtest/run.sh --profile cursor-smoke
products/breg/loadtest/run.sh --profile steady
products/breg/loadtest/run.sh --profile sweep
products/breg/loadtest/down.sh
```

`seed.py --workers N` bounds concurrent batch requests (default 4). Seeds of
100,000 records or more run PostgreSQL `ANALYZE` after import. The documented
full-scale seed is 500,000 records. The stock development runtime fixes its
database pool at 4 connections; this harness does not patch private runtime
configuration behind the lifecycle's ownership boundary.

`up.sh` refuses any existing `.run` path and does not clear it. `down.sh` first
validates the launcher's ownership marker, then calls `bregctl dev stop
--remove` for that exact project. It retains the load evidence and synthetic
seed files. Move the stopped `.run` directory aside before starting another
environment.

## Operations are not HTTP requests

Rate settings are operations per second (`OPS`), not HTTP TPS. A workload
operation can issue more than one request:

- a paginated list follows page two when a cursor is present;
- a patch first fetches the current ETag.

Every result therefore reports offered operations/s, achieved operations/s,
and actual HTTP requests/s separately.

## Profiles

| Profile | Default shape | Question it answers |
|---|---|---|
| `cursor-smoke` | one filtered page plus its continuation | Did the harness really execute page two with the BReg cursor contract? |
| `steady` | 50 operations/s, mixed workload, 3 min | Does the target rate hold without drops or failures and with p99 below 250 ms? |
| `sweep` | excluded warmup at 50 operations/s, then independent 2 min holds at 50, 75, 100, 125, and 150 | At which held rate do drops, errors, or tail-latency failure begin? |
| `burst` | 50 operations/s for 30 s, 15 s ramp to 250, 30 s hold, 15 s ramp down, 90 s recovery | Is a 5x campaign burst graceful, and does the service return to its baseline SLO? |

The steady mix is 40% code lookup, 30% point get, 20% filtered list, 7%
create, and 3% preconditioned patch. Sweep and burst are read-only. Workload
selection uses a deterministic per-VU PRNG (`RANDOM_SEED=20260902` by default).

The harness deliberately does not benchmark ThunderID. Token-soak and
coordinated issuer-herd profiles measure the external issuer rather than BReg
capacity, so they are outside this harness. Before every k6 process, `run.sh` calls `bregctl dev token
loadtest-driver PROJECT`, validates its reported owner-only header file, and
gives k6 only that path. Each k6 invocation must fit within four minutes so the
single short-lived development token remains usable. Sweep obtains a fresh
token for its warmup and for every independent hold.

## Tuning

`run.sh` accepts `--profile`, `--ops`, and `--duration`; other non-sensitive
arguments pass through to k6. HTTP debug and system-tag overrides are refused
because they can expose credentials, cursors, URLs, or record identifiers.
Profile-specific environment variables are:

- `steady`: `OPS=50`, `DURATION=3m`, `FOLLOW_CURSOR=1`
- `sweep`: `RATES=50,75,100,125,150`, `HOLD=2m`, `WARMUP_OPS=50`, `WARMUP_DURATION=2m`
- `burst`: `OPS=50`, `PEAK_OPS=250`, `BASELINE_DURATION=30s`, `RAMP_DURATION=15s`, `PEAK_DURATION=30s`, `RECOVERY_DURATION=90s`
- all workload profiles: `RANDOM_SEED`, `FOLLOW_CURSOR`

Examples:

```bash
products/breg/loadtest/run.sh --profile steady --ops 75 --duration 4m
RATES=50,60,70,80,90 HOLD=3m products/breg/loadtest/run.sh --profile sweep
PEAK_OPS=300 products/breg/loadtest/run.sh --profile burst
```

## Evidence

Each measured run gets an owner-only directory under `.run/results/` with:

- `manifest.json`: Git revision and dirty state, non-secret host/tool versions,
  fixed development pool size, seed counts, exact profile parameters, and
  timestamps;
- `k6-summary.json` and `k6-samples.json`: threshold data and raw metric
  samples with the system tag set restricted to status, method, operation name,
  scenario, and expected-response status;
- `db-before.json`, `db-waits.jsonl`, and `db-after.json`: continuous wait
  counts, table sizes, and audit-chain length from the development database;
- `result.json`: throughput, errors, drops, 504s, p50/p95/p99 by operation and
  phase, DB wait peaks, and the SLO verdict;
- `safety.json`: evidence scan proving the current authorization header,
  seeded record-id canaries, compact JWTs, unsafe k6 tags, SQL text, and
  response bodies were not persisted.

The sweep also creates `sweep-result.json`, including the first held rate that
failed its thresholds. The warmup is excluded from measurement. The stock dev
database does not enable `pg_stat_statements`, so this harness does not claim
per-statement timings.

The harness never saves bearer tokens, assertion keys, cursors, source records,
raw principals, request/response bodies, audit payloads, SQL text, or bound SQL
values. The only authorization file is the owner-only header managed by
`bregctl dev` inside the project's ignored private state.

## Database diagnostics

The run wrapper captures diagnostics automatically. These commands are also
available for focused investigation:

```bash
products/breg/loadtest/dbstats.sh snapshot
products/breg/loadtest/dbstats.sh sample 1
products/breg/loadtest/dbstats.sh analyze
```

## Interpreting results

- The audit chain is a strong bottleneck hypothesis because audited requests
  serialize updates to a singleton chain head, but the harness should prove it
  per run using audit lock waits.
- 504 `request.timeout` responses are saturation, not successful throughput.
- Capacity is the highest held rate that meets its full thresholds, not a rate
  merely touched during a ramp.
- Recovery is a separate burst scenario. Do not average it together with the
  overloaded phase.
- macOS Docker figures are directional. Re-run candidate capacity claims on a
  representative Linux host before citing them.

## Verification

```bash
python3 -m unittest products/breg/loadtest/support/test_evidence.py -v
bash -n products/breg/loadtest/{up,down,run,dbstats}.sh
for profile in products/breg/loadtest/profiles/*.js; do
  k6 inspect -e \
    ESTABLISHMENT_IDS_FILE=products/breg/loadtest/.run/seed/establishment-ids.txt \
    -e AUTHORIZATION_HEADER_FILE=products/breg/loadtest/.run/project/.breg/dev/secrets/loadtest-driver.header \
    "$profile" >/dev/null
done
```

The inspect loop uses the synthetic seed pool and fresh header from a running
environment because workload profiles load both during k6 initialization. The
live `cursor-smoke` is the end-to-end proof that continuation actually occurs.
