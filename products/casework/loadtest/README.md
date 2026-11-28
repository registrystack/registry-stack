# Registry Casework load-test environment

A local environment for measuring Registry Casework's unified review surfaces
with the `standalone-decision` example. The launcher delegates the whole
service lifecycle to `rstack dev` (see
[Run a project with rstack dev](https://docs.registrystack.org/configure/run-a-project-with-rstack-dev/)): its managed
PostgreSQL container, the throwaway local token signing key, credentials, the
directory seed, run state, and the supervised Casework process. Load evidence
and synthetic seed data live under `loadtest/.run` and are never committed.

The example is copied into `.run/project` with one change. Its `tests/`
scenario is replaced by one that only staffs the `decisions` queue, because the
example's own scenario also decides a request and the seed counts must start at
zero. The example's `dev.yaml` is used as it is: the `staff` person and the
`requester` person are the one Staff principal and the one producer principal
the harness acts as. Add people to `dev.yaml` when a workload needs distinct
people with the same role.

## Prerequisites

- `cargo`, `docker`, `python3`
- `k6` (`brew install k6`)

`up.sh` builds `casework`, `caseworkctl`, and `rstack` with the release profile, because
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

`down.sh` validates the launcher's ownership marker and calls
`rstack dev stop RUN --clean` to remove the managed volume and project state.
A plain stop keeps the managed data. The next `up.sh` archives a cleaned
`.run` directory, preserving its load evidence and synthetic seed files.
`up.sh` requires an active run to be stopped before starting another.

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
`run.sh` calls `rstack dev token` for the `staff` and `requester` people,
validates each reported owner-only header file, and gives k6 only those paths.
Each k6 invocation must fit within four minutes so the five-minute development
tokens remain usable.

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
only authorization files are the owner-only headers managed by `rstack dev`
inside the run's private state under `.run/state`.

## Database diagnostics

The run wrapper captures diagnostics automatically. These commands are also
available for focused investigation:

```bash
products/casework/loadtest/dbstats.sh snapshot
products/casework/loadtest/dbstats.sh sample 1
products/casework/loadtest/dbstats.sh analyze
```

`reviewHistoryLockWaiters` counts lock waits on statements that touch
`casework_review_history`. Review mutations append their accountability rows
to `casework_review_history` inside the mutating transaction. Audit entries go
to the runtime's audit destination, which `rstack dev` places in the run's
private state, so no database table carries them.

## Reading results

- The runtime's PostgreSQL pool is fixed at 32 connections with a 5 second checkout wait, and
  neither `rstack dev` nor runtime configuration changes it. The manifest
  records the constant.
- The inbox list is the expected hot spot: one page loads a bounded set of
  candidate tasks and checks each on its own pool checkout. Expect `list_tasks`
  to dominate p99 and to degrade first as the pool saturates.
- A cursor anchored on a task that has left the caller's inbox is refused with
  410. Profiles anchor continuations inside the never-mutated read pool, so a
  410 in a result is a finding.
- The `steady` p99 bounds catch regressions; they are not an SLO. Re-derive them
  on your own hardware before tightening them, and do not measure while the host
  is compiling.
- Casework has no request-timeout layer. Saturation shows first as rising
  latency, then as 503 `service-unavailable` once a request waits too long for a
  pool connection. The shared `timeouts504` field stays zero; read the 503 count
  in `httpStatuses`.
- Recovery is a separate burst scenario; do not average it with the overloaded
  phase.
- Figures from a development container host are directional. Re-run capacity
  claims on a representative Linux host before citing them.
- Only submitted-context reviews are measured. Current-source reads, due-ordered
  next-task selection, member holdings, caseload movement, clock recomputation
  and per-member inbox fan-out across a large team are not covered.
