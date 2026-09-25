# Registry Casework load-test environment

A local environment for measuring Registry Casework's unified review surfaces
with the `standalone-decision` example. The launcher delegates the whole
service lifecycle to `caseworkctl dev`: its owned PostgreSQL container, the
stock local token issuer, credentials, the directory seed, retained state, and
the supervised Casework process. Load evidence and synthetic seed data live
under `loadtest/.run` and are never committed.

The example is copied into `.run/project` with two changes. Its producer
binding names the local issuer on the port this environment reserved and the
subject `caseworkctl dev identity loadtest-producer` reports, because the
checked-in example names a fixed port and a placeholder subject. The copy also
gets a `dev-clients.yaml` with four synthetic clients, one per access profile
the example declares, and a directory seed that puts `loadtest-staff` on the
`decisions` queue. A development project binds exactly one client to each
access profile, so every Staff request in a run comes from one principal and
every producer request from another.

## Prerequisites

- `cargo`, `docker`, `python3`
- `k6` (`brew install k6`)

`up.sh` builds `casework` and `caseworkctl` with the release profile, because
latency and capacity from an unoptimized build are not representative.
`up.sh --debug` builds the development profile instead, for iterating on the
harness itself; every run manifest records which profile was measured. On
macOS the build goes through `scripts/cargo-runtime-library-path.sh`, and the
resolved AWS-LC FIPS library directory is recorded in `.run/env.json` so later
commands can execute the same binaries directly.

## Quick start

```bash
products/casework/loadtest/up.sh
products/casework/loadtest/seed.py --count 2000
products/casework/loadtest/run.sh --profile smoke
products/casework/loadtest/run.sh --profile steady
products/casework/loadtest/run.sh --profile burst
products/casework/loadtest/down.sh
```

`seed.py` submits open review requests through the public producer contract,
then lists the Staff inbox to learn each request's task, because an accepted
request reports no task identifier. The oldest tasks become the read pool
(`--read-count`, default half the seed and at most 500, never fewer than 100).
Profiles only read those tasks, so inbox pages stay stable across runs. The
remaining tasks become the flow pool that decision flows consume in order.
`--workers N` bounds concurrent create requests (default 8).

`seed.py` seeds an environment once. It marks `.run/seed` in progress before
the first create request and clears the mark only after the pools are
recorded. A seed that stops early may leave open requests that no pool
accounts for, so a later `seed.py` refuses to run; run `down.sh` and start a
fresh environment.

`up.sh` refuses any existing `.run` path and does not clear it. `down.sh` first
validates the launcher's ownership marker, then calls `caseworkctl dev stop
--remove` for that exact project. It retains the load evidence and synthetic
seed files. Move the stopped `.run` directory aside before starting another
environment.

## Operations are not HTTP requests

Rate settings are operations per second (`OPS`), not HTTP TPS. A workload
operation can issue more than one request:

- an inbox list follows page two when a cursor is present;
- a decision flow claims a task, saves a private draft, decides it, and polls
  the answered result, which is four requests.

Every result therefore reports offered operations/s, achieved operations/s,
and actual HTTP requests/s separately.

## Profiles

| Profile | Default shape | Question it answers |
|---|---|---|
| `smoke` | one full review lifecycle | Does a producer submission reach Staff through the inbox continuation, and does the claim, draft, decide, result chain succeed with current revisions? |
| `steady` | 20 operations/s for 2 min: 18/s inbox mix plus 2/s decision flows | Does the target rate hold without drops or failures and within the recorded p99 bounds? |
| `burst` | inbox mix at 20 operations/s for 30 s, 15 s ramp to 100, 30 s hold, 15 s ramp down, 90 s recovery | Is a 5x campaign burst graceful, and does the service return to its baseline SLO? |

The inbox mix is 35% Staff inbox list (25 per page), 20% open a task, 10%
open its context, 15% producer request read, 10% pending-result poll, and 10%
new producer submission. Decision flows run as their own `steady` scenario at
`FLOW_OPS` per second, by default one tenth of the offered rate and at least
one. Each iteration takes
the next unused flow-pool task, so no two iterations race for a task and the
run carries no expected conflicts. `run.sh` reserves the scenario's upper
bound of flow tasks in `.run/seed/flow-offset` before k6 starts and refuses a
run the remaining pool cannot cover; an interrupted run therefore never hands
an already-decided task to the next one. `smoke` and `burst` never touch the
flow pool. Workload selection uses a deterministic per-VU PRNG
(`RANDOM_SEED=20260902` by default).

The harness does not benchmark the token issuer. Before every k6 process,
`run.sh` calls `caseworkctl dev token` for `loadtest-staff` and
`loadtest-producer`, validates each reported owner-only header file, and gives
k6 only those paths. Each k6 invocation must fit within four minutes so the
five-minute development tokens remain usable.

## Tuning

`run.sh` accepts `--profile`, `--ops`, and `--duration` (also as `--ops=N` and
`--duration=X`); other non-sensitive arguments pass through to k6. Arguments
that would change the offered load without the manifest recording it are
refused: `-d`, `-i`/`--iterations`, `-u`/`--vus`, `-s`/`--stage`, `--rps`,
`--execution-segment*`, and `-e`/`--env`, in every form, plus the `K6_VUS`,
`K6_ITERATIONS`, `K6_DURATION`, `K6_STAGES`, and `K6_RPS` environment
variables; set profile parameters through the environment variables below.
HTTP debug and system-tag overrides are refused because they can expose
credentials, cursors, URLs, or record identifiers.
`--no-thresholds` and `K6_NO_THRESHOLDS` are refused too, because a run
without thresholds has no verdict.
Profile-specific environment variables are:

- `steady`: `OPS=20`, `DURATION=2m`, `FLOW_OPS` (decision flows per second
  within `OPS`; one tenth of `OPS` by default, at least 1, below `OPS`)
- `burst`: `OPS=20`, `PEAK_OPS=100`, `BASELINE_DURATION=30s`, `RAMP_DURATION=15s`, `PEAK_DURATION=30s`, `RECOVERY_DURATION=90s`
- all profiles: `RANDOM_SEED`; `steady` and `burst`: `FOLLOW_CURSOR=1`

Examples:

```bash
products/casework/loadtest/run.sh --profile steady --ops 40 --duration 3m
FLOW_OPS=8 products/casework/loadtest/run.sh --profile steady --ops 40
PEAK_OPS=200 products/casework/loadtest/run.sh --profile burst
```

A 2-minute `steady` at the default rate reserves 242 flow tasks, so size the
seed to the runs you plan: `seed.py --count 2000` leaves 1,500 flow tasks,
enough for six default `steady` runs.

## Evidence

The manifest, safety scan, and summaries are written by the product-neutral
`scripts/loadtest/evidence.py`, shared with the Base Registry Engine and
Evidence harnesses. Each measured run gets an owner-only directory under
`.run/results/` with:

- `manifest.json`: Git revision and dirty state, non-secret host/tool versions,
  build profile, the runtime's fixed pool size, seed counts, exact profile
  parameters, and timestamps;
- `k6-summary.json` and `k6-samples.json`: threshold data and raw metric
  samples with the system tag set restricted to status, method, operation name,
  scenario, and expected-response status;
- `db-before.json`, `db-waits.jsonl`, and `db-after.json`: continuous wait
  counts, review table sizes, task states, and review history length from the
  development database. A run whose wait sampler exits early fails its
  verdict; a run too short for one sample reports its wait peaks as null;
- `result.json`: throughput, errors, drops, 504s, p50/p95/p99 by operation and
  phase, DB wait peaks, and the SLO verdict;
- `safety.json`: evidence scan proving both current authorization headers,
  seeded task and request id canaries, compact JWTs, unsafe k6 tags, SQL text,
  and response bodies were not persisted.

The development database does not enable `pg_stat_statements`, so this harness
does not claim per-statement timings.

The harness never saves bearer tokens, cursors, raw principals,
request/response bodies, SQL text, or bound SQL values. Task and request
identifiers exist only in the owner-only seed pools under `.run/seed`. The
only authorization files are the owner-only headers managed by `caseworkctl
dev` inside the project's ignored private state.

## Database diagnostics

The run wrapper captures diagnostics automatically. These commands are also
available for focused investigation:

```bash
products/casework/loadtest/dbstats.sh snapshot
products/casework/loadtest/dbstats.sh sample 1
products/casework/loadtest/dbstats.sh analyze
```

`auditLockWaiters` counts lock waits on statements that touch
`casework_review_history` or `casework_audit_outbox`. Review mutations append
their accountability rows to `casework_review_history` inside the mutating
transaction.

## Interpreting results

- The runtime's PostgreSQL pool is fixed at 32 connections with a 5-second
  checkout wait (`crates/registry-casework/src/store.rs`). Neither
  `caseworkctl dev` nor runtime configuration can change it, so the manifest
  records the constant, and tuning it is out of scope for this harness.
- The inbox list is the expected hot spot. One page of 25 loads up to 100
  candidate tasks, reads each candidate's request, then checks each returned
  task again, each on its own pool checkout. Expect `list_tasks` to dominate
  p99 and to be the first operation to degrade as the pool saturates.
- A cursor anchored on a task that has since left the caller's inbox (claimed
  by another reviewer or decided) is refused with 410. Profiles anchor
  continuations inside the never-mutated read pool, so 410s in a result are a
  finding, not expected churn.
- The `steady` p99 bounds are roughly twice the worst p99 of two 1-minute
  release-build runs on 2026-09-25 (Apple Silicon laptop, PostgreSQL under
  OrbStack, 1,000 seeded requests). Both runs held their rate with no drops or
  failures:

  | Operation | p99 at 10 ops/s | p99 at 20 ops/s | Bound |
  |---|---|---|---|
  | `get_task` | 46 ms | 20 ms | 100 ms |
  | `get_request` | 76 ms | 14 ms | 150 ms |
  | `list_tasks` | 371 ms | 309 ms | 750 ms |
  | `decide_task` | 225 ms | 190 ms | 500 ms |
  | all requests | 361 ms | 268 ms | 750 ms |

  The 10 ops/s run overlapped heavier host load than the 20 ops/s run, which
  is why some of its tails are longer. Re-derive the bounds before tightening
  them; they catch regressions and are not an SLO.
- Do not measure while the host is compiling. An earlier 20 ops/s run taken
  while parallel release builds held the load average above 60 dropped
  arrivals and pushed `list_tasks` p99 past 3 seconds.
- Casework has no request-timeout layer. Saturation shows first as rising
  latency, then as 503 `service-unavailable` once a request waits more than 5
  seconds for a pool connection (`crates/registry-casework/src/store.rs`).
  The shared `timeouts504` field therefore stays zero; read the 503 count in
  `httpStatuses` instead.
- Recovery is a separate burst scenario. Do not average it together with the
  overloaded phase.
- macOS Docker figures are directional. Re-run candidate capacity claims on a
  representative Linux host before citing them.

## Known gaps

- Only the standalone review surfaces are measured. The work-item inbox,
  source-owned work through the Base Registry Engine adapter, and attempt
  recovery need a running BReg source project and are not covered.
- Staff traffic comes from one principal, so per-member inbox fan-out across a
  large team is not modeled.

## Verification

```bash
python3 -m unittest scripts/loadtest/test_evidence.py products/casework/loadtest/support/test_harness.py -v
for script in products/casework/loadtest/{up,down,run,dbstats}.sh; do bash -n "$script"; done
shellcheck -x products/casework/loadtest/*.sh
run="$PWD/products/casework/loadtest/.run"
secrets="$run/project/.casework/dev/secrets"
for client in loadtest-staff loadtest-producer; do
  DYLD_FALLBACK_LIBRARY_PATH="$(jq -r .runtime_library_path "$run/env.json")" \
    python3 products/casework/loadtest/support/loadenv.py header \
    --caseworkctl "$(jq -r .caseworkctl "$run/env.json")" --project "$run/project" --client "$client" >/dev/null
done
for profile in products/casework/loadtest/profiles/*.js; do
  k6 inspect \
    -e READ_TASKS_FILE="$run/seed/read-tasks.txt" \
    -e STAFF_HEADER_FILE="$secrets/loadtest-staff.header" \
    -e PRODUCER_HEADER_FILE="$secrets/loadtest-producer.header" \
    -e RUN_NONCE=inspect \
    "$profile" >/dev/null
done
```

The inspect loop uses the synthetic seed pool and fresh headers from a running
environment because the profiles load them during k6 initialization. The paths
are absolute because k6 resolves a relative `open()` path against the module
that calls it, not the working directory. The unit
tests include a k6 run of `smoke` against a loopback stub when k6 is
installed; the live `smoke` is the end-to-end proof against the runtime.
