# registry-witness Performance Testing

Scaffolding for local, CI, and scheduled performance runs against the
`registry-witness` HTTP service. Goals: measure authenticated claim evaluation
latency, CEL-derived claim cost, batch evaluate throughput, and the catalog
read path on small (1k subjects) and medium (100k subjects) synthetic datasets.

Witness's claim evaluation calls an upstream source over HTTP (DCI). To
isolate witness latency from any specific upstream, this harness ships a small
deterministic stub server (`perf/stub/source_stub.py`) that responds to DCI
search requests with seed-42 records. The perf configs point witness at the
local stub. Replacing the stub with a real upstream (a registry-relay running
its own perf config, for example) is left as a follow-up.

Credential issuance (`POST /credentials/issue`) is intentionally not covered in
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
   cargo build --release -p registry-witness-bin
   ```

3. Install `k6` (see [k6 docs](https://k6.io/docs/get-started/installation/)).

---

## Generate API keys and signing material

```bash
uv run perf/scripts/generate_perf_keys.py --env-file target/perf/perf.env
```

Use `--force` to overwrite an existing file. File mode is set to `0600`.
Raw token values are never printed to stdout: only variable names and the
output path are reported.

The script writes:

- bearer + API-key tokens for the witness service (one shared verification
  identity matching the demo config, plus a deny-path identity)
- a bearer token consumed by the witness process when it calls the source stub
- an Ed25519 private JWK used by the witness credential issuer (witness will
  refuse to start without it, even if no issuance scenario is run)
- the base URL, claim ids, and subject id prefix that the k6 scenarios read

Do NOT commit `target/perf/perf.env`. It is gitignored.

---

## Start the source stub

```bash
uv run perf/stub/source_stub.py --profile medium
```

The stub binds `127.0.0.1:14256` by default and serves DCI search responses on
the paths witness expects:

- `POST /dci/crvs/registry/sync/search` (birth_date lookups)
- `POST /dci/fr/registry/sync/search` (farmed_land_size_hectares lookups)

Both paths accept the bearer token from
`EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN`. Records are derived from a fixed
seed (42); the `--profile` flag selects how many distinct subjects respond
with hits (1k for `small`, 100k for `medium`).

The stub is intentionally minimal: it implements the response shape witness
parses (`message.search_response[0].data.reg_records`) and nothing else. It
is not a registry-relay replacement.

---

## Start the witness server

With [1Password CLI](https://developer.1password.com/docs/cli/):

```bash
op run --env-file=target/perf/perf.env -- \
  target/release/registry-witness-bin --config perf/config/medium.yaml
```

Without 1Password (source the env file directly):

```bash
set -a
. target/perf/perf.env
set +a
target/release/registry-witness-bin --config perf/config/medium.yaml
```

Witness has no `/ready` endpoint. Probe with an authenticated `GET /claims`
and wait for `200`:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $REGISTRY_WITNESS_BEARER_TOKEN" \
  http://127.0.0.1:14255/claims
```

---

## Run k6 scenarios

```bash
op run --env-file=target/perf/perf.env -- k6 run perf/k6/evaluate_extract.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/evaluate_cel.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/batch_evaluate.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/list_claims.js
op run --env-file=target/perf/perf.env -- k6 run perf/k6/auth_deny.js
```

Or source the env file and call `k6 run` directly.

---

## Profiles

| Profile | Subjects | Use case                              |
|---------|----------|---------------------------------------|
| small   | 1,000    | CI smoke check, quick iteration       |
| medium  | 100,000  | Standard developer run                |

`small` and `medium` are stub-side data sizes. The witness process itself sees
exactly one record per request, so witness memory is flat across profiles.
The profile influences only how widely k6 spreads its subject ids and so how
much cache locality the stub can exploit.

There is no `large` profile. Witness does not scan datasets: per-request work
is bounded by claim depth, source latency, and signing cost. Adding a 1M-row
tier would not exercise additional witness behavior.

---

## Scenarios

| Scenario              | Endpoint                        | What it measures                                                  |
|-----------------------|---------------------------------|-------------------------------------------------------------------|
| `evaluate_extract`    | POST /claims/evaluate           | Hot path: auth, single source fetch, extract rule, audit emit     |
| `evaluate_cel`        | POST /claims/evaluate           | CEL-derived claim (`farmer-under-4ha` depends on `farmed-land-size`) |
| `batch_evaluate`      | POST /claims/batch-evaluate     | Bulk path; subjects per batch governed by `REGISTRY_WITNESS_BATCH_SIZE` |
| `list_claims`         | GET /claims                     | Catalog read, no source IO                                        |
| `auth_deny`           | mixed                           | 401 (missing/invalid token) and 403 (deny-path identity) only     |

All scenarios pass `data-purpose: perf` so witness's purpose-required check is
satisfied.

---

## Runner script

`perf/scripts/run_scenario.py` orchestrates a single run end-to-end: it starts
the source stub, starts the witness binary, waits for both to come up, runs a
named k6 scenario while sampling the witness process (CPU, RSS, threads, FDs
on Linux), and tears down cleanly.

```bash
uv run perf/scripts/run_scenario.py \
  --scenario perf/k6/evaluate_extract.js \
  --witness-config perf/config/medium.yaml \
  --stub-profile medium \
  --env-file target/perf/perf.env
```

---

## Environment Variables

| Variable                                | Default                  | Description                                            |
|-----------------------------------------|--------------------------|--------------------------------------------------------|
| `REGISTRY_WITNESS_BASE_URL`             | `http://127.0.0.1:14255` | Witness base URL used by k6 scripts                    |
| `REGISTRY_WITNESS_BEARER_TOKEN`         | (generated)              | Bearer token with civil+farmer evidence scopes         |
| `REGISTRY_WITNESS_API_KEY`              | (generated)              | API-key token (same scopes; exercised in auth_deny)    |
| `REGISTRY_WITNESS_NO_SCOPE_TOKEN`       | (generated)              | Valid bearer token with no evidence scopes (deny path) |
| `REGISTRY_WITNESS_TOKEN_INVALID`        | `not-a-real-token-xxxx`  | Deliberately invalid token for 401 tests               |
| `REGISTRY_WITNESS_PROFILE`              | `medium`                 | Profile name read by k6 for logs and tags              |
| `REGISTRY_WITNESS_BATCH_SIZE`           | `10`                     | Subjects per batch in `batch_evaluate.js`              |
| `REGISTRY_WITNESS_SUBJECT_COUNT`        | (matches stub profile)   | Pool size of distinct subject ids k6 cycles through    |
| `REGISTRY_WITNESS_CLAIM_EXTRACT`        | `date-of-birth`          | Claim id used in `evaluate_extract.js`                 |
| `REGISTRY_WITNESS_CLAIM_CEL`            | `farmer-under-4ha`       | Claim id used in `evaluate_cel.js`                     |
| `EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN`  | (generated)              | Bearer token witness sends to the source stub          |
| `EVIDENCE_SOURCE_STUB_BIND`             | `127.0.0.1:14256`        | Stub listen address                                    |
| `REGISTRY_WITNESS_ISSUER_JWK`           | (generated Ed25519 JWK)  | Required by witness even when issuance is not exercised |

All bearer + API-key tokens are raw strings (subject to constant-time
comparison server-side); witness does not use hashed fingerprints.
