# Registry Server load-test environment

A self-contained local stack for load-testing Registry Server: pinned
PostgreSQL 17 (TLS, `pg_stat_statements`), Registry Mint with one
private-key operator client and one client-secret driver client, and
Registry Server serving the `business-establishments` acceptance fixture
with the opt-in metrics listener enabled. Everything disposable lives under
`loadtest/.run` and is never committed.

All seeded data is synthetic and deterministically generated from a fixed
seed. No real business, person, or identifier is involved.

## Prerequisites

- `cargo`, `docker`, `openssl`, `python3`, `uv` (same set as the quickstart)
- `k6` (`brew install k6`)

## Quick start

```bash
products/registry-server/loadtest/up.sh                     # build + start the stack
products/registry-server/loadtest/seed.py --count 100000    # synthetic records
products/registry-server/loadtest/run.sh --profile steady   # 50 TPS mixed, 10 min
products/registry-server/loadtest/dbstats.sh                # DB-side sampling
products/registry-server/loadtest/down.sh                   # tear down
```

`up.sh --pool-max N` sizes the server's PostgreSQL pool (default 32, bound
1..128). `seed.py --workers N` bounds concurrent batch requests (default 4);
`--count 500000` is the documented full-scale seed and takes minutes.

## Why these profiles

Registries of this shape (civil registration, facility and business
registries, point-of-care verification) have a consistent load signature:

- **Reads dominate at 100:1 or more.** Writes are registration events; reads
  are every downstream check (deduplication searches, point-of-care lookups,
  monitoring collections).
- **Institutional clients, not humans**: tens to low hundreds of
  integrators with pooled connections and cached tokens, so realistic
  concurrency is 50-500 connections.
- **Diurnal shape**: business-hours peaks run 3-5x the daily mean; campaign
  days (drives, month-end reporting) spike 5-10x for hours.

A sustained mixed 50 TPS with documented behavior through 5x bursts
comfortably covers a large national registry; the sweep finds where the
server's actual ceiling sits.

| Profile | Shape | Question it answers |
|---|---|---|
| `steady` | 50 TPS constant arrival, mixed workload (40% code lookup, 30% point get, 20% filtered list, 7% create, 3% patch), 10 min (pass `DURATION=8h` for a soak) | Does p99 stay under 250ms with zero failed requests? |
| `sweep` | Read-only ramp 10 -> 600 TPS in 10 stages | Where is the throughput knee? |
| `burst` | 250 TPS plateau with 2x spikes | Is degradation under campaign bursts graceful? |
| `herd` | 200 VUs minting tokens simultaneously | Does a coordinated client restart sink Mint or the server? |

Each run scrapes the metrics listener before and after into
`.run/logs/metrics-{before,after}-<profile>-<stamp>.txt`.

## Tuning knobs

`run.sh` accepts `--profile`, `--tps`, and `--duration`; anything else is
passed through to k6. Profile-specific tuning is environment variables:

- `steady`: `TPS` (default 50), `DURATION` (default 10m), `FOLLOW_CURSOR` (default 1)
- `sweep`: `START_TPS` (10), `MAX_TPS` (600), `STAGES` (10), `STAGE_DURATION` (1m)
- `burst`: `TPS` plateau (250), `SPIKE_MULTIPLIER` (2), `SPIKE_SECONDS` (30)
- `herd`: `VUS` (200), `DURATION` (1m)

Example: `MAX_TPS=100 STAGES=3 STAGE_DURATION=10s run.sh --profile sweep`.

## How to read results

The expected bottleneck is the audit chain: every audited request appends a
hash-chained envelope under `SELECT ... FOR UPDATE` on the singleton
`registry_audit_head` row, and one GET costs three PostgreSQL transactions
(read plus two audit appends). Read the run against that model:

- `registry_server_http_request_duration_seconds` p99 rising while
  `registry_server_pool_connections{state="waiting"}` stays near zero means
  time is spent inside transactions — audit-chain serialization or query
  time. Confirm with `dbstats.sh` lock waits and `pg_stat_statements`.
- `waiting` climbing with flat p99 until a knee means pool exhaustion;
  compare runs at different `--pool-max`.
- 504s with problem code `request.timeout` are the saturation signal: the
  10s HTTP timeout fires while work is still queued.
- Soaks should watch audit table growth and dead tuples (`dbstats.sh`).

## Notes and caveats

- **macOS Docker numbers are directional, not citable.** The Docker network
  and CPU overhead distorts tails; use a Linux host for published figures.
- The seeder drives the public batch HTTP contract directly (the same
  surface `registry-serverctl data import` uses) with bounded parallelism
  and captures returned record ids for reference fields and the k6 id pool.
  `data import` remains the sequential, checkpointed path for auditable
  one-off imports.
- Tokens come from a real local Mint via `client_secret_post`; the herd
  profile deliberately hammers that endpoint. For steady-state runs the
  harness caches each token until shortly before expiry, matching how a
  well-behaved institutional client behaves.
- The server's metrics listener is loopback-only and opt-in
  (`metricsListener` in the runtime config); `up.sh` reserves an ephemeral
  port for it and records it in `.run/env.json`.

## Files

- `up.sh` / `down.sh` — environment lifecycle
- `support/loadenv.py` — helpers (ports, config generation, tokens, scraping)
- `seed.py` — deterministic synthetic seeder over the batch API
- `run.sh` — k6 wrapper (env wiring, before/after metric scrapes)
- `dbstats.sh` — pg_stat_statements, audit lock waits, table sizes
- `lib/token.js`, `lib/workload.js` — token handling and the weighted mix
- `profiles/` — steady, sweep, burst, herd
