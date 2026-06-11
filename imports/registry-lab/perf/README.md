# Registry Lab Performance Harness

This harness exercises the demo stack rather than a single binary. It assumes
the lab has generated `.env` secrets and the local Docker Compose topology is
running.

## Start the Lab

```bash
just generate
just build
just up
```

Wait for the standard smoke prerequisites to pass before collecting a baseline:

```bash
scripts/smoke.sh
```

## Run with Local k6

```bash
set -a
. .env
set +a
mkdir -p output/perf/results output/perf/reports

k6 run perf/k6/relay_stack_read.js
k6 run perf/k6/notary_relay_backed.js
k6 run perf/k6/openfn_sidecar_saturation.js
k6 run perf/k6/openfn_credential_issuance.js
```

The default profile is `smoke`. It intentionally uses a small VU count and a
short think time to validate routes without creating load. It is not a capacity
measurement.

Run a Relay capacity baseline with an explicit arrival rate:

```bash
REGISTRY_LAB_PROFILE=capacity \
REGISTRY_LAB_DURATION=2m \
REGISTRY_LAB_RATE=2000 \
REGISTRY_LAB_PRE_ALLOCATED_VUS=512 \
REGISTRY_LAB_MAX_VUS=2000 \
k6 run perf/k6/relay_stack_read.js
```

Run a breakpoint ramp:

```bash
REGISTRY_LAB_PROFILE=breakpoint \
REGISTRY_LAB_STAGES=1m:1000,1m:2000,1m:5000,30s:0 \
REGISTRY_LAB_PRE_ALLOCATED_VUS=512 \
REGISTRY_LAB_MAX_VUS=3000 \
k6 run perf/k6/relay_stack_read.js
```

## Run with Docker k6

Docker Desktop on macOS does not support `--network host` the same way Linux
does. Use `host.docker.internal` for loopback services:

```bash
docker run --rm \
  --env-file .env \
  -e CIVIL_RELAY_URL=http://host.docker.internal:4311 \
  -e SOCIAL_RELAY_URL=http://host.docker.internal:4312 \
  -e HEALTH_RELAY_URL=http://host.docker.internal:4313 \
  -e CIVIL_NOTARY_URL=http://host.docker.internal:4321 \
  -e SHARED_NOTARY_URL=http://host.docker.internal:4323 \
  -e OPENFN_NOTARY_URL=http://host.docker.internal:4324 \
  -v "$PWD:/workspace" \
  -w /workspace \
  grafana/k6:0.57.0 run perf/k6/notary_relay_backed.js
```

## Profiles

All scenarios are profile-aware via `REGISTRY_LAB_PROFILE`:

- `smoke`: `constant-vus`, defaults to `REGISTRY_LAB_VUS=4`,
  `REGISTRY_LAB_DURATION=30s`, and `REGISTRY_LAB_THINK_TIME_SECONDS=0.1`.
  This catches broken routes, auth drift, and basic latency regressions.
- `capacity`: `constant-arrival-rate`, defaults to each scenario's baseline
  target rate and `REGISTRY_LAB_THINK_TIME_SECONDS=0`. Use this for comparable
  requests-per-second baselines.
- `breakpoint`: `ramping-arrival-rate`, defaults to each scenario's ramp stages
  and `REGISTRY_LAB_THINK_TIME_SECONDS=0`. Use this to find the first target
  rate where latency or error thresholds fail.

Common overrides:

- `REGISTRY_LAB_PROFILE=smoke|capacity|breakpoint`
- `REGISTRY_LAB_DURATION=30s`
- `REGISTRY_LAB_VUS=4`
- `REGISTRY_LAB_RATE=1000`
- `REGISTRY_LAB_PRE_ALLOCATED_VUS=256`
- `REGISTRY_LAB_MAX_VUS=1200`
- `REGISTRY_LAB_THINK_TIME_SECONDS=0`
- `REGISTRY_LAB_STAGES=1m:1000,1m:2000,1m:5000,30s:0`

Keep hosted or shared environments opt-in; the default URLs are local loopback
ports.

Scenario defaults for capacity and breakpoint runs:

- `relay_stack_read`: capacity `1000 req/s`; breakpoint `1000 -> 2000 -> 5000`.
- `notary_relay_backed`: capacity `200 req/s`; breakpoint `100 -> 200 -> 400`.
- `openfn_sidecar_saturation`: capacity `25 req/s`; breakpoint `10 -> 25 -> 50`.
- `openfn_credential_issuance`: capacity `20 iterations/s`; breakpoint
  `10 -> 20 -> 40`.

## Reports

Each script writes:

- `output/perf/results/<scenario>.json`
- `output/perf/reports/<scenario>.txt`

The text summaries print the active profile, think time, rate/count gauges,
latency distributions (`avg`, `med`, `p90`, `p95`, `p99`, `max`), and
status-code counters. Status-specific counters are emitted as first-class
metrics because k6 does not include tag cardinality in the compact text summary.
