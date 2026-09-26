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

`up.sh` builds `breg` and `bregctl` with the release profile, because latency
and capacity from an unoptimized build are not representative. `up.sh --debug`
builds the development profile instead, for iterating on the harness itself;
every run manifest records which profile was measured. On macOS the build goes
through `scripts/cargo-runtime-library-path.sh`, and the resolved AWS-LC FIPS
library directory is recorded in `.run/env.json` so later commands can execute
the same binaries directly.

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

`seed.py` seeds an environment once. It records `--count` and `--seed` in
`.run/seed` before the first batch and clears that record only after the id
pools are written. Batch idempotency keys and records follow those parameters,
so a seed that stops early resumes when rerun with the same `--count` and
`--seed`. Other parameters are refused, because they would leave the committed
records unaccounted for; run `down.sh` and start a fresh environment instead.

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

`run.sh` accepts `--profile`, `--ops`, and `--duration` (also as `--ops=N` and
`--duration=X`); other non-sensitive arguments pass through to k6. Arguments
that would change the offered load without the manifest recording it are
refused: `-d`, `-i`/`--iterations`, `-u`/`--vus`, `-s`/`--stage`, `--rps`,
`--execution-segment*`, `-e`/`--env`, and `-c`/`--config`, in every form, plus
the `K6_VUS`, `K6_ITERATIONS`, `K6_DURATION`, `K6_STAGES`, `K6_RPS`, and
`K6_CONFIG` environment variables; set profile parameters through the environment variables below.
HTTP debug and system-tag overrides are refused because they can expose
credentials, cursors, URLs, or record identifiers.
`--no-thresholds` and `K6_NO_THRESHOLDS` are refused too, because a run
without thresholds has no verdict.
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

The manifest, safety scan, and summaries are written by the product-neutral
`scripts/loadtest/evidence.py`, shared with the Evidence and Casework harnesses.
Each measured run gets an owner-only directory under `.run/results/` with:

- `manifest.json`: Git revision and dirty state, non-secret host/tool versions,
  build profile, fixed development pool size, seed counts, exact profile
  parameters, and timestamps;
- `k6-summary.json` and `k6-samples.json`: threshold data and raw metric
  samples with the system tag set restricted to status, method, operation name,
  scenario, and expected-response status;
- `db-before.json`, `db-waits.jsonl`, and `db-after.json`: continuous wait
  counts and table sizes from the development database. A run whose wait
  sampler exits early fails its verdict; a run too short for one sample reports
  its wait peaks as null;
- `result.json`: throughput, errors, drops, 504s, p50/p95/p99 by operation,
  per-phase counts, achieved rate, and latency, DB wait peaks, and the SLO
  verdict;
- `safety.json`: evidence scan proving the current authorization header,
  seeded record-id canaries, compact JWTs, unsafe k6 tags, SQL text, and
  response bodies were not persisted.

The sweep also creates `sweep-result.json`, including the first held rate that
failed its thresholds and an overall `pass`. A held rate that left no
`result.json` is recorded as failed with `missing: true`. The warmup is excluded from measurement. The stock dev
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

- Every request, reads included, writes a request entry and a response
  entry to the runtime's audit file, outside PostgreSQL. A mutation still
  waits for its own commit to be durable, so measure the host's sync cost with
  `docker exec <container> pg_test_fsync -s 1` before comparing hosts. The
  audit file shares the host disk with the database under the development
  stack.
- 504 `request.timeout` responses are saturation, not successful throughput.
- Capacity is the highest held rate that meets its full thresholds, not a rate
  merely touched during a ramp.
- Recovery is a separate burst scenario. Do not average it together with the
  overloaded phase.
- macOS Docker figures are directional. Re-run candidate capacity claims on a
  representative Linux host before citing them.

## Audit simplification measurement

The 2026-09-25 comparison used release builds at `9a05d3688` (database audit)
and `8821b3a67` (shared file writer), each with a 100,000-establishment seed,
2,000 businesses, 5,000 assignments, the stock four-connection pool, and
`RANDOM_SEED=20260902`. The before environment retained mutations from earlier
measurement runs, while the after environment started from a fresh seed. The
seeded identifier pools and nominal seed settings matched; historical state
was not reset identically. Both cursor-smoke checks passed. Two steady pairs ran
in before/after/before/after order at 50 operations/s for three minutes, then
each pair was repeated once in the same order. The optional sweep was omitted.

This was a shared Apple M5 Max development machine with 18 logical cores,
macOS 26.4.1 and Docker PostgreSQL. All figures are directional, not capacity
claims or absolute timing gates. The primary observations across the four
pairs were:

| Database observation | Before | After |
|---|---|---|
| Committed transactions per completed workload operation | 3.154–3.287 | 1.712–1.834 |
| Sampled audit-lock waiters, peak | 3 in every run | 0 in every run |
| Sampled audit-lock waiters, mean | 0.066–0.127 | 0 |
| `registry_internal.registry_audit_head` exists | yes | no |
| Database audit tables | `registry_audit`, `registry_audit_head` | none |

Transactions per operation means the `pg_stat_database.xact_commit` delta
divided by completed workload operations, including failed operations. It
includes monitoring transactions and background work. An operation may issue
multiple HTTP requests; neither the denominator nor the achieved rate counts
only successful requests. The observed transaction ratio fell by 41.8–47.4%
across the pairs, while failure counts and completed work differed.

The raw steady observations make those failures explicit:

| Run | Completed operations/s | HTTP 504 / all HTTP requests | p99 (ms) |
|---|---:|---:|---:|
| before-1 | 45.211 | 3,525 / 8,815 | 10,008.87 |
| after-1 | 44.940 | 2,938 / 8,830 | 10,002.94 |
| before-2 | 45.198 | 3,066 / 8,808 | 10,004.34 |
| after-2 | 45.037 | 3,061 / 8,827 | 10,007.16 |
| before-1-retry | 44.933 | 3,058 / 8,830 | 10,005.97 |
| after-1-retry | 45.131 | 3,150 / 8,832 | 10,005.97 |
| before-2-retry | 44.964 | 3,105 / 8,824 | 10,004.63 |
| after-2-retry | 45.220 | 3,929 / 8,794 | 10,014.87 |

Every steady run failed the harness SLO thresholds. Initial pairs 1 and 2
had slightly lower after rates and overlapping builds, so their timing
comparisons were discarded and each pair was rerun once. Unrelated builds
also overlapped the retries. Timing remains inconclusive: this series does
not establish successful throughput improvement or isolate the remaining
saturation cause. No thresholds or runtime settings were tuned.

Start/end one-minute host load averages ranged from 5.59 to 36.05. Every run
retained start/end uptime, build activity, one-second lock samples, database
counters, manifest, safety scan and raw k6 results. The build sampler counts
command lines matching Cargo/rustc, including wrappers, so its peaks are
conservative overlap indicators rather than exact compiler-process counts.

## Verification

```bash
python3 -m unittest scripts/loadtest/test_evidence.py products/breg/loadtest/support/test_harness.py -v
for script in products/breg/loadtest/{up,down,run,dbstats}.sh; do bash -n "$script"; done
shellcheck -x products/breg/loadtest/*.sh
for profile in products/breg/loadtest/profiles/*.js; do
  k6 inspect -e \
    ESTABLISHMENT_IDS_FILE="$PWD/products/breg/loadtest/.run/seed/establishment-ids.txt" \
    -e AUTHORIZATION_HEADER_FILE="$PWD/products/breg/loadtest/.run/project/.breg/dev/secrets/loadtest-driver.header" \
    "$profile" >/dev/null
done
```

The inspect loop uses the synthetic seed pool and fresh header from a running
environment because workload profiles load both during k6 initialization. The
paths are absolute because k6 resolves relative `open()` paths against the
script that calls it. The
live `cursor-smoke` is the end-to-end proof that continuation actually occurs.
