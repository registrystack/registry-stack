# Evidence load-test environment

A local environment for measuring Evidence with one synthetic question: "Is
the person at least 18 years old?" over an offline source. The launcher builds
a project with `evidencectl init` from a tracked OpenAPI description, adds the
tracked `adult-status` question and derivation, and serves 200 synthetic people
through `evidencectl source mock serve`. It then delegates the service
lifecycle to `evidencectl dev`: the retained local issuer container, the
compiled development bundle, signing keys, and the supervised `evidence`
process. Load evidence and the synthetic subject pool live under
`loadtest/.run` and are never committed.

## Prerequisites

- `cargo`, `docker`, `python3`
- `lsof` on hosts other than Linux (macOS ships it), to confirm the source
  mock's working directory
- `k6` (`brew install k6`)

`up.sh` builds `evidence` and `evidencectl` with the release profile, because
latency and capacity from an unoptimized build are not representative.
`up.sh --debug` builds the development profile instead, for iterating on the
harness itself; every run manifest records which profile was measured. On
macOS the build goes through `scripts/cargo-runtime-library-path.sh`, and the
resolved AWS-LC FIPS library directory is recorded in `.run/env.json` so later
commands can execute the same binaries directly.

## Quick start

```bash
products/evidence/loadtest/up.sh
products/evidence/loadtest/run.sh --profile smoke
products/evidence/loadtest/run.sh --profile steady
products/evidence/loadtest/run.sh --profile burst
products/evidence/loadtest/down.sh
```

`up.sh` refuses any existing `.run` path and does not clear it. It picks free
loopback ports for the source mock, Evidence, and the issuer, and records them
with the mock's PID in `.run/env.json`. If startup fails, it stops only the
dev session and the mock that it started itself.

`down.sh` first validates the launcher's ownership marker. It then runs
`evidencectl dev stop` and `evidencectl dev clean` for that exact project. It
signals the source mock only while the recorded PID still runs the exact
command the launcher started, so a reused PID is never signalled. The load
evidence and subject pool are kept. Move the stopped `.run` directory aside
before starting another environment.

## Deviation from the stock limits: one principal per load client

The development bundle limits every principal to 60 requests per minute, with
a burst of 10. `evidencectl dev` hard-codes these values when it renders the
local bundle (`render_local_bundle` in
`crates/registry-evidencectl/src/authoring.rs`), and it offers no flag or
project setting to raise them. A single load client would therefore measure
the rate limiter, not the service, above one request per second.

The harness keeps the stock limits and does not patch private runtime
configuration behind the lifecycle's ownership boundary. Instead, `up.sh`
registers `LOAD_CLIENTS` synthetic clients (default 128, at most 256), named
`loadtest-001` onward, under one access policy. Each one is a distinct
principal with its own bucket. The workload assigns iterations to clients
round-robin, so each principal receives `rate / LOAD_CLIENTS` requests per
second.

`run.sh` refuses any offered or peak rate above 90% of `LOAD_CLIENTS`
requests per second (115 ops/s at the default). To offer more, start a fresh
environment with a larger `LOAD_CLIENTS`. The `limiter` profile shows that the
stock limit is still enforced for a single principal.

Consequences to keep in mind when reading results:

- the rate limiter is exercised with many small buckets, not one hot bucket;
- the per-principal audit and authorization work is spread over many
  pseudonyms, as it would be for many relying parties;
- clients must exist before `dev start`, because the compiled bundle fixes the
  authority profiles, so `LOAD_CLIENTS` is fixed for the life of an
  environment.

## Profiles

| Profile | Default shape | Question it answers |
|---|---|---|
| `smoke` | 12 sequential requests: 10 held subjects, 2 unknown | Does every held subject get a signed flattened ES256 JWS, and every unknown subject the expected refusal? |
| `steady` | 20 operations/s for 2 min | Does the target rate hold with no drops, no failed requests, no 429s, and p99 below 250 ms? |
| `burst` | 20 operations/s for 30 s, 15 s ramp to 100, 30 s hold, 15 s ramp down, 90 s recovery | Is a 5x burst graceful, and does the service return to its baseline SLO? |
| `limiter` | 20 back-to-back requests from one client | Is the stock per-principal limit still live (at least one 429)? |

One operation is one `POST /v1/evidence` request with a fresh 32-byte
`requestNonce`. Of those, 97% ask about one of 200 held subjects: 160 adults
and 40 minors, with birth dates fixed by the subject index. The other 3% ask
about one of 50 subjects the source does not hold. Subject selection uses a
deterministic per-VU PRNG (`RANDOM_SEED=20260925` by default).

The unknown-subject share exercises the refusal path. Evidence answers it with
`503 application/problem+json` and code `source.unavailable`, not 404. The
compact OpenAPI question has no "no match" rule, so the source's 404 is a
protocol failure of the fixed source. Only that exact problem is marked as an
expected status (`http.expectedStatuses(503)` on that request, tagged
`evidence_absent`). Any other 503 fails the `checks` threshold. These refusals
do not count against the failed-selector budget, which applies only to
malformed selectors.

The 250 ms p99 bound matches the Base Registry Engine harness. It leaves room
above the per-request cost measured locally: two durable audit appends, a
loopback source call, and an ES256 signature. It is not a production SLO.

The harness deliberately does not benchmark the issuer. Before every k6
process, `run.sh` calls `evidencectl dev token` for every load client (16 at a
time, about 14 s for 128 clients). It validates each reported owner-only
header file and checks that every token outlives the run window. It then gives
k6 only the list of header paths. Each k6 invocation must fit within four
minutes.

## Tuning

`run.sh` accepts `--profile`, `--ops`, and `--duration`; other non-sensitive
arguments pass through to k6. HTTP debug and system-tag overrides are refused
because they can expose credentials, nonces, or subject identifiers.
`--no-thresholds` and `K6_NO_THRESHOLDS` are refused too, because a run
without thresholds has no verdict.
Profile-specific environment variables are:

- `steady`: `OPS=20`, `DURATION=2m`
- `burst`: `OPS=20`, `PEAK_OPS=100`, `BASELINE_DURATION=30s`, `RAMP_DURATION=15s`, `PEAK_DURATION=30s`, `RECOVERY_DURATION=90s`
- all profiles: `RANDOM_SEED`
- `up.sh`: `LOAD_CLIENTS=128`

Examples:

```bash
products/evidence/loadtest/run.sh --profile steady --ops 50 --duration 3m
PEAK_OPS=110 products/evidence/loadtest/run.sh --profile burst
LOAD_CLIENTS=256 products/evidence/loadtest/up.sh
```

Run `limiter` on its own. It drains client `loadtest-001`'s bucket, which
refills at one request per second; the token fetch before the next run gives
it time to refill.

## Evidence

The manifest, safety scan, and summaries are written by the product-neutral
`scripts/loadtest/evidence.py`, shared with the Base Registry Engine and
Casework harnesses. Each run gets an owner-only directory under
`.run/results/` with:

- `manifest.json`: Git revision and dirty state, non-secret host and tool
  versions, build profile, subject-pool counts, the load-client count and the
  three stock rate-limit values read from the compiled bundle, exact profile
  parameters, and timestamps;
- `k6-summary.json` and `k6-samples.json`: threshold data and raw metric
  samples, with the system tag set restricted to status, method, operation
  name, scenario, and expected-response status;
- `result.json`: throughput, errors, drops, p50/p95/p99 by operation and
  phase, HTTP status counts (including 429 and 503), and the SLO verdict;
- `safety.json`: evidence scan proving that no current authorization header,
  subject-identifier canary, compact JWT, unsafe k6 tag, or request or response
  body was persisted.

The harness never saves bearer tokens, nonces, signed assertions, source
records, raw principals, or request or response bodies. The only
authorization files are the owner-only headers managed by `evidencectl dev`
inside the project's ignored private state. `.run/header-files.txt` lists
their paths, not their contents.

## Interpreting results

- The local runtime's source connection allows 8 concurrent source calls, and
  the listener allows 64 concurrent requests, with a 3 s source timeout and a
  10 s request timeout. The source mock accepts 64 concurrent requests. A
  latency knee near those concurrencies is the dev configuration, not the
  runtime's ceiling.
- Every successful request makes two durable audit appends before the
  response is released. On macOS, `sync_all` is `F_FULLFSYNC`, a real device
  barrier, so local figures are directional. See
  `products/evidence/PERFORMANCE.md`, and re-run candidate capacity claims on
  a representative Linux host before citing them.
- The issuer runs in Docker; on macOS that is a VM. It is used only between
  runs, so it does not affect request latency.
- A 429 in `steady` or `burst` means the offered rate outran the load
  clients' combined stock limit, not the service. Raise `LOAD_CLIENTS`.
- Recovery is a separate burst scenario. Do not average it together with the
  peak.

## Verification

```bash
python3 -m unittest scripts/loadtest/test_evidence.py products/evidence/loadtest/support/test_harness.py -v
bash -n products/evidence/loadtest/up.sh
bash -n products/evidence/loadtest/run.sh
bash -n products/evidence/loadtest/down.sh
shellcheck -x products/evidence/loadtest/*.sh
```

The unit tests need no running environment. When `k6` is installed, they also
run the `smoke` and `limiter` profiles against a loopback stub and check
client rotation, nonce shape and uniqueness, the expected refusals, and the
safety scan. The live `smoke` profile is the end-to-end proof against the real
runtime.
