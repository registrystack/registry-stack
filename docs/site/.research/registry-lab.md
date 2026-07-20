> **Status: historical research note**
>
> This note records pre-monorepo research and is not current architecture or release evidence. Use the published documentation and pinned source links for current claims.

# registry-lab — evidence packet

Last reviewed: 2026-05-23
Repo path: ../registry-lab
Reviewed against commit: aaa6f8057a11

## What it is

This demo runs three independent Registry Relay authorities, three independent Registry Witness verifiers, a static metadata publisher, and a narrated client. It uses functional domains only. The services simulate civil, social protection, and health registry patterns, but they are not real OpenCRVS, OpenSPP, DHIS2, OpenIMIS, MOSIP, or other product integrations.

It is a compose-based runnable local demo showcasing decentralized evidence service interactions across multiple registries.

## compose.yaml topology

File: `compose.yaml` (130 lines)

**Services:**

- `civil-registry-relay`
  - Image: `registry-relay:demo` (built locally)
  - Ports: `4311:8080`
  - Depends-on: none
  - Healthcheck: `registry-relay --help` every 30s (timeout 10s, 3 retries)
  - Volumes: `./config/relay:/etc/registry-relay:ro`, `./data/civil:/demo/data/civil:ro`, `civil-registry-cache:/var/lib/registry-relay/cache`

- `social-protection-registry-relay`
  - Image: `registry-relay:demo` (built locally)
  - Ports: `4312:8080`
  - Depends-on: none
  - Healthcheck: same as civil-registry-relay
  - Volumes: `./config/relay:/etc/registry-relay:ro`, `./data/social-protection:/demo/data/social-protection:ro`, `social-protection-registry-cache:/var/lib/registry-relay/cache`

- `health-registry-relay`
  - Image: `registry-relay:demo` (built locally)
  - Ports: `4313:8080`
  - Depends-on: none
  - Healthcheck: same as civil-registry-relay
  - Volumes: `./config/relay:/etc/registry-relay:ro`, `./data/health:/demo/data/health:ro`, `health-registry-cache:/var/lib/registry-relay/cache`

- `civil-witness`
  - Image: `registry-witness:demo` (built locally)
  - Ports: `4321:8080`
  - Depends-on: none
  - Healthcheck: none
  - Volumes: `./config/witness/civil-witness.yaml:/etc/registry-witness/civil-witness.yaml:ro`

- `social-protection-witness`
  - Image: `registry-witness:demo` (built locally)
  - Ports: `4322:8080`
  - Depends-on: none
  - Healthcheck: none
  - Volumes: `./config/witness/social-protection-witness.yaml:/etc/registry-witness/social-protection-witness.yaml:ro`

- `shared-eligibility-witness`
  - Image: `registry-witness:demo` (built locally)
  - Ports: `4323:8080`
  - Depends-on: none
  - Healthcheck: none
  - Volumes: `./config/witness/shared-eligibility-witness.yaml:/etc/registry-witness/shared-eligibility-witness.yaml:ro`

- `static-metadata-publisher`
  - Image: `python:3.12.3-slim-bookworm` (pulled)
  - Ports: `4331:8080`
  - Depends-on: none
  - Healthcheck: none
  - Volumes: `./static-metadata:/srv/static:ro`

- `demo-client`
  - Image: `python:3.12.3-slim-bookworm` (pulled)
  - Ports: none
  - Profile: `client` (only runs with `--profile client`)
  - Depends-on: all Relay and Witness services, static-metadata-publisher
  - Volumes: `./scripts:/workspace/scripts:ro`, `./output:/demo/output`

**Named volumes (persisted cache):**
- `civil-registry-cache`
- `social-protection-registry-cache`
- `health-registry-cache`

Inside Compose, services reach each other via DNS names like `http://civil-registry-relay:8080`. Witness containers do not mount source data; they read registry facts over HTTP from Relay. The demo client has no data mount.

All Relay services use `env_file: .env`, `environment: RUST_LOG: info`, and restart policy `unless-stopped`.

## Scripts inventory

Location: `scripts/`

- `generate-fixtures.py` — Generate deterministic synthetic CSV, XLSX, and Parquet fixtures for civil, social protection, and health registries.
- `generate-demo-secrets.py` — Generate local demo `.env` with SHA-256 credential hashes and JWK issuer keys.
- `publish-static-metadata.sh` — Publish portable static metadata manifest using registry-manifest CLI from vendor/registry-relay.
- `demo-flow.py` — Narrated client walkthrough: three scenarios (birth registration to child support, household benefit review, cross-authority conditional support).
- `smoke.sh` — Smoke tests: health/ready checks, evidence discovery, OpenAPI endpoints, scope denials, row/aggregate reads, evidence evaluation, credential binding.
- `release-check.sh` — Wrapper script that runs the full release checklist: fixtures, secrets, static metadata, build, compose up, smoke, demo, compose down.

**Tutorial command verification:**

| Command | Exists | Exact Match | Notes |
|---------|--------|------------|-------|
| `uv run scripts/generate-fixtures.py` | yes | yes | Python PEP 723 script (requires uv) |
| `scripts/generate-demo-secrets.py` | yes | **NO** | Must be run directly as executable (no `uv run`); supports `--print-summary` flag |
| `scripts/publish-static-metadata.sh` | yes | yes | Bash script, executable |
| `docker compose -f compose.yaml build` | yes | yes | Exact match |
| `docker compose -f compose.yaml up -d` | yes | yes | Exact match |
| `scripts/smoke.sh` | yes | yes | Bash script, executable |
| `docker compose -f compose.yaml --profile client run --rm demo-client` | yes | yes | Exact match; uses `--profile client` |

**Note:** The README shows `scripts/generate-demo-secrets.py` without `uv run` but it runs directly as an executable Python3 script. The README tutorial listing shows both commands inline without `uv run`, indicating the second script is not wrapped by the PEP 723 inline script mechanism.

## Fixture generation

`scripts/generate-fixtures.py` produces:

- **Civil registry CSV:** `/data/civil/civil_registry.csv` — children, caregivers, living adults, deceased adults across five districts.
- **Social protection XLSX:** `/data/social-protection/social_protection_registry.xlsx` — households, household members, enrollments with active, inactive, suspended, review-required cases.
- **Health registry Parquet:** `/data/health/health_registry.parquet` — active, suspended, pending-renewal, partially-serviceable facilities.

All fixtures are written under the `/data/` directory. Timestamps are deterministic (2026-01-01). The generator validates key coverage before writing (successful subject, failed predicates, deceased-member cases, cross-source subjects, health-linked support).

Fixtures are gitignored (`data/*` with `!data/.gitignore`); only the `.gitignore` is committed.

## Secret generation

`scripts/generate-demo-secrets.py` generates `.env` with local demo credentials:

**Generated artifacts:**

- `.env` file (gitignored) with raw and hashed tokens
- JWK issuer keys for Registry Witness and each Evidence Server instance
- SHA-256 hashes for all tokens (stored as `*_HASH` env vars)
- Raw tokens for client use (stored as `*_RAW` env vars)

**Credential types generated:**

1. Metadata client tokens for each Relay (civil, social, health)
2. Evidence source tokens for each Relay (used by Registry Witness when calling Relay)
3. Evidence-only tokens (scope: evidence disclosure only, no row/aggregate read)
4. Row-reader tokens (scope: row read only)
5. Aggregate-reader tokens (scope: aggregate consultation only)
6. Registry Witness client API keys and bearer tokens (separate for each witness)
7. Shared Registry Witness source tokens (distinct for civil, social, health)
8. Claim verification binding key and issuer JWKs for all Evidence Servers

**Security model:**
- Relay configs reference only `*_HASH` env vars (SHA-256 fingerprints)
- Witness configs reference `token_env` names
- No raw token is committed to git
- `.env` is gitignored; `.env.example` has inert placeholders only

## Static metadata publication

`scripts/publish-static-metadata.sh` wraps `vendor/registry-relay/scripts/run_registry_manifest_cli.sh publish` and publishes the portable manifest at `config/static-metadata/metadata.yaml` into `static-metadata/metadata/`.

**Process:**
1. Reads portable manifest from `config/static-metadata/metadata.yaml`
2. Invokes registry-manifest CLI with `publish` command
3. Outputs static bundle to `static-metadata/metadata/`
4. Verifies `static-metadata/metadata/index.json` was produced

**Served by:**
- `static-metadata-publisher` service at `127.0.0.1:4331`
- Python built-in HTTP server on port 8080 (mapped to 4331)

**Endpoints produced:**
- `http://127.0.0.1:4331/metadata/index.json`
- `http://127.0.0.1:4331/metadata/catalog.json`
- `http://127.0.0.1:4331/metadata/evidence-offerings.json`
- `http://127.0.0.1:4331/metadata/policies.jsonld`

**What it is NOT:**
The static bundle is generated from portable metadata config, not scraped from running Relay. It must not include source paths, table IDs, scopes, cache paths, or backend runtime details.

## Smoke check

`scripts/smoke.sh` (180 lines) runs ~30 test checks. File: `scripts/smoke.sh`.

**Verified endpoints and behaviors:**

1. **Health & readiness:** `/health` and `/ready` on all three Relays
2. **Discovery:** `/.well-known/evidence-service` on all three Witnesses
3. **OpenAPI:** `/openapi.json` on all three Relays and all three Witnesses
4. **Evidence offerings:** `/metadata/evidence-offerings` on Relays and `metadata/evidence-offerings.json` on static publisher
5. **Authorization scope denial:** POST to social Relay row endpoint with evidence-only credential → 403 `auth.scope_denied` (line 129–132)
6. **Positive row read:** GET social Relay household data with row-reader credential (line 134)
7. **Positive aggregate:** GET social Relay household aggregates with aggregate-reader credential (line 135)
8. **Aggregate denial:** GET aggregate with row-reader credential → 403 `auth.scope_denied` (line 137–140)
9. **Evidence evaluation (civil):** POST to `/claims/evaluate` on civil-witness → 200 with results (line 142–143)
10. **Evidence evaluation (health):** POST to `/claims/evaluate` on shared-witness → 200 with results (line 145–146)
11. **Evidence evaluation (shared cross-authority):** POST `/claims/evaluate` with multi-source result, source_count >= 2 (line 148–159)
12. **Missing subject evaluation:** POST with non-existent subject ID → 200/404/422 (line 161–162)
13. **Credential-bound evaluation:** POST `/claims/evaluate` with `Accept: application/dc+sd-jwt` → 200 (line 165)
14. **Full demo flow:** Runs `demo-flow.py`, verifies correlation ID in artifacts (line 167–168)
15. **Household benefit decision:** Artifact created with `boundary.relay_write_back = false` (line 169–171)
16. **Audit events:** Verifies service logs contain `auth.scope_denied`, `evaluate`, and 200 status events (line 173–177)

All checks use `x-request-id: decentralized-demo-correlation-001` (or `DEMO_CORRELATION_ID` override).

## Client flow

`scripts/demo-flow.py` (narrated client, ~250 lines) orchestrates three end-to-end scenarios:

**Scenario 1: Birth Registration to Child Support**
- Verifies civil facts via Registry Witness (civil-witness)
- Issues demo-grade credential with predicate disclosure
- Does not expose raw civil registry rows

**Scenario 2: Household Benefit Review from Registry Data**
- Client performs protected Relay row read (social-protection-registry-relay) with Data-Purpose header
- Client performs aggregate consultation (household eligibility band aggregates)
- Writes household-benefit-decision artifact without writing back to Relay
- Demonstrates scope binding: row-reader ≠ aggregate-reader

**Scenario 3: Cross-Authority Conditional Support**
- Static metadata leads client to shared-eligibility-witness
- Witness claim depends on civil, social protection, and health authorities
- Returns multi-source evidence result (source_count >= 2)

**Global:**
- All requests send `x-request-id` using `DEMO_CORRELATION_ID` env var (default: `decentralized-demo-correlation-001`)
- All artifacts saved to `DEMO_OUTPUT_DIR` (default: `output/`)
- Uses custom Ed25519 holder key for credential binding
- Requires OpenSSL for holder proof signature

## Verification points

After `docker compose up -d` and all services healthy:

**Civil Registry Relay** (host:port `127.0.0.1:4311`)
- Health: `GET /health` (requires CIVIL_METADATA_CLIENT_RAW token)
- Ready: `GET /ready` (requires token)
- OpenAPI: `GET /openapi.json` (requires token)
- Metadata: `GET /metadata/evidence-offerings` (requires token)
- Base: `http://civil-registry-relay:8080` (DNS) or `http://127.0.0.1:4311` (host)

**Social Protection Registry Relay** (host:port `127.0.0.1:4312`)
- Health: `GET /health` (requires SOCIAL_METADATA_CLIENT_RAW token)
- Ready: `GET /ready` (requires token)
- OpenAPI: `GET /openapi.json` (requires token)
- Metadata: `GET /metadata/evidence-offerings` (requires token)
- Data: `GET /datasets/social_protection_registry/household?limit=1` (requires row-reader token + Data-Purpose header)
- Aggregates: `GET /datasets/social_protection_registry/household/aggregates/households_by_eligibility_band` (requires aggregate-reader token)

**Health Registry Relay** (host:port `127.0.0.1:4313`)
- Health: `GET /health` (requires HEALTH_METADATA_CLIENT_RAW token)
- Ready: `GET /ready` (requires token)
- OpenAPI: `GET /openapi.json` (requires token)
- Metadata: `GET /metadata/evidence-offerings` (requires token)

**Civil Witness** (host:port `127.0.0.1:4321`)
- Discovery: `GET /.well-known/evidence-service` (requires CIVIL_EVIDENCE_CLIENT_BEARER token)
- OpenAPI: `GET /openapi.json` (requires token)
- Evaluate: `POST /claims/evaluate` (requires token, JSON body with subject and claims)

**Social Protection Witness** (host:port `127.0.0.1:4322`)
- Discovery: `GET /.well-known/evidence-service` (requires SOCIAL_EVIDENCE_CLIENT_BEARER token)
- OpenAPI: `GET /openapi.json` (requires token)
- Evaluate: `POST /claims/evaluate` (requires token)

**Shared Eligibility Witness** (host:port `127.0.0.1:4323`)
- Discovery: `GET /.well-known/evidence-service` (requires SHARED_EVIDENCE_CLIENT_BEARER token)
- OpenAPI: `GET /openapi.json` (requires token)
- Evaluate: `POST /claims/evaluate` (requires token, cross-authority claims)

**Static Metadata Publisher** (host:port `127.0.0.1:4331`)
- Index: `GET /metadata/index.json` (no auth)
- Catalog: `GET /metadata/catalog.json` (no auth)
- Evidence offerings: `GET /metadata/evidence-offerings.json` (no auth)
- Policies: `GET /metadata/policies.jsonld` (no auth)

## Environment requirements

**Docker Compose:**
- Docker Compose with support for `additional_contexts` (Docker Compose v2.20+)
- Buildkit syntax in Dockerfiles (`syntax=docker/dockerfile:1.7`)

**Python and uv:**
- Python 3.11+ (for `scripts/generate-fixtures.py` PEP 723 dependencies)
- `uv` command-line tool (for running PEP 723 scripts)
- `python3` for direct execution of `scripts/generate-demo-secrets.py` and `scripts/demo-flow.py`
- `openssl` command (required by `demo-flow.py` for holder proof signing)

**Runtime dependencies:**
- Docker daemon (for building and running compose services)
- `curl` (used by `smoke.sh`)
- `bash` (POSIX shell features)

**Base images pulled:**
- `python:3.12.3-slim-bookworm` (for static-metadata-publisher and demo-client)
- `rust:1-bookworm` (builder stage for Relay and Witness)
- `debian:bookworm-slim` (runtime stage)

## Cleanup

The exact teardown command:

```bash
docker compose -f compose.yaml down -v
```

The `-v` flag removes named volumes (civil-registry-cache, social-protection-registry-cache, health-registry-cache).

This is invoked automatically by `release-check.sh` via a trap on EXIT.

## Vendored or third-party content

`.gitmodules` defines:

```
[submodule "vendor/registry-relay"]
    path: vendor/registry-relay
    url: git@github.com:jeremi/registry-relay.git

[submodule "vendor/registry-witness"]
    path: vendor/registry-witness
    url: git@github.com:jeremi/registry-witness.git
```

**Vendored repos:**
1. `vendor/registry-relay` — Registry Relay source (upstream github.com/jeremi/registry-relay)
2. `vendor/registry-witness` — Registry Witness source (upstream github.com/jeremi/registry-witness)

Both are git submodules. They are included in Docker builds via `additional_contexts` mechanism:
- Relay: `COPY --from=registry_relay_src ...` (Dockerfile.registry-relay)
- Witness: `COPY --from=witness_src ...` (Dockerfile.registry-witness)

Environment overrides allow using sibling directories instead:
```bash
REGISTRY_RELAY_SOURCE_DIR=../registry-relay \
REGISTRY_WITNESS_SOURCE_DIR=../registry-witness \
docker compose build
```

## Explicit non-goals

From README:

- **Not a production deployment:** The demo uses CSV, XLSX, Parquet. It simulates civil, social protection, and health patterns but is not a real OpenCRVS, OpenSPP, DHIS2, OpenIMIS, MOSIP, or other product integration.
- **Demo-only credentials:** Local secrets use inert examples. No security for actual PII or registry data.
- **Walkthrough narrative:** The `demo-flow.py` script narrates three scenarios with hand-crafted, deterministic fixture data.

## Gaps and TODOs

1. **No explicit version pinning for Docker Compose:** `compose.yaml` does not specify `version:` field; relies on default inference.
2. **Witness healthcheck missing:** Relay services have healthchecks, but Witness services do not (only CLI help check would be meaningful).
3. **No log aggregation:** Services log to stderr/stdout; `smoke.sh` greps docker compose logs, but there is no centralized log collection.
4. **Static metadata not auto-regenerated:** If `config/static-metadata/metadata.yaml` changes, static bundle must be manually republished (not watched by compose).
5. **Demo client output cleanup:** `output_dir()` function in `demo-flow.py` deletes previous artifacts on re-run; no archive/backup.
6. **Hardcoded correlation ID:** Default `decentralized-demo-correlation-001` is a fixed string (though overridable via env var).
7. **No signal handling in demo-flow.py:** If interrupted mid-execution, partial artifacts remain in output/.
8. **Fixture data scope:** Only five districts, max ~100 rows per dataset; not representative of production scale.
9. **No explicit tenant/org scoping:** All services run in single namespace; no multi-tenant isolation demonstrated.
10. **README does not document all available credentials:** `.env.example` is more complete than README narrative on secret types.

## Naming and rename status

The directory has been renamed from `decentralized-evidence-demo/` to `registry-lab/`.

**Remaining references to old name found in repo:**

- `scripts/generate-fixtures.py` line 10: docstring `"""Generate deterministic synthetic fixtures for the decentralized demo."""`
- `scripts/generate-fixtures.py` line 10: creator metadata `"registry-relay-decentralized-demo-generator"`
- `scripts/generate-demo-secrets.py` line 2: docstring `"""Generate local credentials for the decentralized evidence demo.`
- `config/static-metadata/metadata.yaml`: `id: decentralized-demo-static-publication`
- `scripts/demo-flow.py` line 2: docstring `"""Narrated client flow for the decentralized evidence demo."""`
- `scripts/demo-flow.py` line 23: `PURPOSE = "https://demo.example.gov/purpose/decentralized-evidence-demo"`
- `scripts/demo-flow.py` line 27: `CORRELATION_ID = ... "decentralized-demo-correlation-001"`
- `scripts/smoke.sh` line 8: `correlation_id="${DEMO_CORRELATION_ID:-decentralized-demo-correlation-001}"`
- `scripts/smoke.sh` line 51: temp file `/tmp/decentralized-smoke-response.json`
- `scripts/smoke.sh` line 174: log file `/tmp/decentralized-smoke-service-logs.txt`
- `scripts/smoke.sh` multiple lines: `Data-Purpose: https://demo.example.gov/purpose/decentralized-evidence-demo`
- `README.md` line 160: `decentralized-demo-correlation-001` in narrative
- `.env.example`: all credential comments reference "decentralized evidence demo"

**Rename plan implication:** The functional names (`decentralized-evidence-demo`, `decentralized-demo-correlation-001`, `decentralized-demo-static-publication`) are intentional identifiers baked into credentials, log correlation, and spec URLs. They do not need to change when the directory/repo is renamed. However, docstrings and comments mentioning "the decentralized demo" could be updated to say "the registry-lab demo" or "the Registry Lab demo" for clarity.

The `.env` file is gitignored, so renaming it (e.g., `.env.registry-lab`) would not break anything, but it is not necessary.

**Verdict:** The rename is mostly cosmetic (directory name change). The internal protocol identifiers are intentionally stable and should not change.
