# registry-relay — evidence packet

**Last reviewed:** 2026-05-23  
**Repo path:** ../registry-relay  
**Reviewed against commit:** aec4394300c87e1f0e93b73580c9b12150552111

## What it is

Registry Relay is a config-driven Rust service that turns sensitive government tabular files and selected database tables into protected, read-only, domain-oriented APIs. V1 is built around two layers: Storage tables read local CSV, XLSX, Parquet, or PostgreSQL sources into Apache Arrow/DataFusion; Entities expose domain resources such as `household` or `individual`, with field projection, relationships, scopes, configured aggregates, semantic metadata, and audit records. It publishes restricted consultation APIs for authorized systems, not an open-data portal.

**Runtime:** Rust async HTTP service (Axum framework) listening on configurable socket address (default `0.0.0.0:8080`).

## Entry points

**Binary:** `target/release/registry-relay` (built via `cargo build --release`; see `justfile` line 11–12)

**How to run locally:**
```sh
just setup                    # Install Rust toolchain, fetch dependencies
just build                    # Build release binary
mkdir -p data
cp fixtures/example_social_registry.xlsx data/social_registry.xlsx
export PROGRAM_SYSTEM_API_KEY_HASH='sha256:<64 lowercase hex chars>'
export STATS_OFFICE_API_KEY_HASH='sha256:<64 lowercase hex chars>'
export VERIFICATION_SERVICE_API_KEY_HASH='sha256:<64 lowercase hex chars>'
just run                      # Runs with config/example.yaml by default
```
(README lines 54–155; src/main.rs lines 87–301)

**Config resolution** (src/main.rs lines 284–301):
1. `--config <path>` command-line flag
2. `REGISTRY_RELAY_CONFIG` environment variable
3. Default fallback: `./config/example.yaml`

**Default ports:** Data plane binds `0.0.0.0:8080` as configured in `config/example.yaml` line 1. Admin listener (optional) binds `127.0.0.1:8081` when `server.admin_bind` is set in config. Both are configurable; no hardcoded defaults in code.

## Public API routes

All routes registered via `server.rs` lines 158–235. Summary from README lines 175–202:

| Method | Path | Purpose | Source |
|--------|------|---------|--------|
| GET | `/health` | Liveness probe (unauthenticated) | src/api/health.rs:35 |
| GET | `/ready` | Readiness probe (unauthenticated) | src/api/health.rs:36 |
| GET | `/docs` | Scalar HTML API reference shell (public, no secrets) | src/api/docs.rs; src/server.rs:173 |
| GET | `/openapi.json` | OpenAPI 3.0 document (auth-gated) | src/api/openapi.rs |
| GET | `/datasets` | List configured datasets | src/api/datasets.rs |
| GET | `/datasets/{dataset_id}` | Fetch one dataset | src/api/datasets.rs |
| GET | `/datasets/{dataset_id}/{entity}/schema` | Entity JSON Schema | src/api/entity.rs |
| GET | `/datasets/{dataset_id}/{entity}` | Entity collection (rows, filtered/paginated) | src/api/entity.rs |
| GET | `/datasets/{dataset_id}/{entity}/{id}` | Single entity record by id | src/api/entity.rs |
| GET | `/datasets/{dataset_id}/{entity}/{id}/{relationship}` | Related entity records | src/api/entity.rs |
| GET | `/datasets/{dataset_id}/{entity}/aggregates` | List declared aggregates | src/api/aggregates.rs |
| GET | `/datasets/{dataset_id}/{entity}/aggregates/{aggregate_id}` | Compute one aggregate | src/api/aggregates.rs |
| GET | `/metadata` | Metadata landing page | src/api/metadata.rs |
| GET | `/metadata/catalog` | Full catalog JSON | src/api/metadata.rs |
| GET | `/metadata/dcat` | DCAT catalog (JSON-LD) | src/api/metadata.rs |
| GET | `/metadata/dcat/{profile}` | DCAT variant (e.g., `bregdcat-ap`) | src/api/metadata.rs |
| GET | `/metadata/shacl` | SHACL node shapes (JSON-LD) | src/api/metadata.rs |
| GET | `/metadata/policies` | ODRL policy statements | src/api/metadata.rs |
| GET | `/metadata/datasets` | Dataset listing | src/api/metadata.rs |
| GET | `/metadata/datasets/{dataset_id}` | One dataset metadata | src/api/metadata.rs |
| GET | `/metadata/datasets/{dataset_id}/policy` | Dataset-scoped ODRL offer | src/api/metadata.rs |
| GET | `/metadata/datasets/{dataset_id}/entities/{entity}/schema` | Entity schema (caller-scoped) | src/api/metadata.rs |
| GET | `/metadata/evidence-offerings` | List evidence offerings | src/api/metadata.rs; src/api/evidence_offerings.rs |
| GET | `/metadata/evidence-offerings/{offering_id}` | One offering | src/api/evidence_offerings.rs |
| POST | `/evidence-offerings/{offering_id}/verifications` | Submit claims for verification | src/api/evidence_offerings.rs:131–134 |
| GET | `/.well-known/did.json` | W3C DID document (when provenance enabled) | src/api/did.rs; src/server.rs:185–189 |
| GET | `/schemas/{schema_id}` | JSON Schema for VC subjects (when provenance enabled) | src/api/schemas.rs |
| GET | `/contexts/{context_id}` | JSON-LD context (when provenance enabled) | src/api/contexts.rs |
| **OGC API Records** (feature: ogcapi-records) | | | |
| GET | `/ogc/v1/records` | OGC Records landing | src/api/ogc/records.rs |
| GET | `/ogc/v1/records/collections` | Collections (datasets as records) | src/api/ogc/records.rs |
| GET | `/ogc/v1/records/collections/datasets/items` | Record items (entities) | src/api/ogc/records.rs |
| **SP DCI** (feature: spdci-api-standards) | | | |
| Various | `/sp-dci/*` | SP DCI-shaped endpoints | src/api/spdci.rs |

**Admin routes** (require `admin` scope; mounted only on `server.admin_bind`):
- `POST /admin/reload` — Full registry reload
- `POST /admin/datasets/{dataset_id}/tables/{table_id}/reload` — Reload one table
- `GET /metrics` — Prometheus-formatted metrics

(src/api/admin.rs; README lines 372–375)

## Configuration surface

**Config file:** YAML, parsed at startup (src/config/mod.rs; docs/configuration.md for full reference)

**Top-level keys in config:**
- `server` — HTTP listener(s), CORS, timeouts, cache dir
- `catalog` — Catalog metadata (title, base URL, publisher)
- `auth` — Authentication mode (api_key or oidc) and credentials
- `audit` — Audit sink (stdout, file, syslog) and format (JSONL)
- `datasets` — Array of dataset and entity configurations
- `metadata` — Optional split metadata manifest path
- `vocabularies` — Custom vocabulary prefix mappings
- `provenance` — Optional VC issuer configuration
- `claim_verification` — Optional claim verification binding key
- `evidence_verification` — Evidence offering rate limits
- `standards` — External standards adapters (SP DCI, PublicSchema)

**Environment variables read at startup:**
- `REGISTRY_RELAY_CONFIG` — Config file path (fallback to `--config` flag)
- `REGISTRY_RELAY_LOG_FORMAT` — `text` or `json` for operational logs (defaults to text; src/main.rs lines 74–85)
- `RUST_LOG` — Tracing filter level (defaults to `info`; src/main.rs:466)
- Per-API-key: `{api_key.hash_env}` — SHA-256 fingerprint of bearer token (e.g., `PROGRAM_SYSTEM_API_KEY_HASH`; src/main.rs:399–420)
- Per-OIDC-signer: `{signer.jwk_env}` — Raw JWK for token signature (provenance feature; src/config/provenance.rs)
- Per-claim-verification: `{binding_key_env}` — HMAC key for claim hashing (src/main.rs:243)
- Per-Postgres-source: `{connection_env}` — PostgreSQL connection string (src/connector/mod.rs)

**Config files shipped in repo:**
- `config/example.yaml` — V1 canonical config (api_key auth, CSV/XLSX/Parquet/Postgres sources)
- `config/example.oidc.yaml` — OIDC/OAuth2 variant (Zitadel target)
- `config/spdci_disability_registry.example.yaml` — SP DCI adapter example

## Auth and authorization

**Modes:** Exactly one of two at runtime (src/config/mod.rs:354–361; src/main.rs:320–340):

1. **API Key** (default V1):
   - Client sends bearer token via `Authorization: Bearer <key>` or `X-Api-Key: <key>` header
   - Server validates against SHA-256 fingerprint stored in env var (not YAML)
   - Scopes per key: `<dataset_id>:metadata`, `<dataset_id>:aggregate`, `<dataset_id>:rows`, `<dataset_id>:evidence_verification`, `admin`
   - Validation via `src/auth/api_key.rs`

2. **OIDC / OAuth2** (resource server mode):
   - Client sends bearer JWT in `Authorization: Bearer <token>`
   - Server validates against external IdP JWKS (resolved from discovery or explicit URL)
   - Issuer, audience, algorithms, scope mapping configured in `auth.oidc` block
   - Validation via `src/auth/oidc.rs` + `ReqwestJwksFetcher`

**Enforcement:** Global auth middleware (src/auth/middleware.rs) gates all protected routes. Health and ready endpoints are unauthenticated. Metadata routes respect dataset-level scopes (src/api/metadata.rs). Evidence verification enforces `dataset_id:evidence_verification` scope (src/api/evidence_offerings.rs).

## Data sources / backends supported

**File sources** (src/connector/mod.rs; FileConnector):
- **CSV** — parsed via `csv` crate (src/format/csv.rs)
- **XLSX** — parsed via `calamine` crate (src/format/xlsx.rs); max file size config `server.xlsx_max_file_bytes` (default 256 MB)
- **Parquet** — parsed via DataFusion (src/format/parquet.rs)
- All file formats load into Arrow/DataFusion at startup or on refresh

**Database sources** (PostgresConnector; src/connector/mod.rs):
- **PostgreSQL** — two modes:
  - **Snapshot:** Structured table or read-only query, loaded at startup or on refresh
  - **Live:** Structured table only, exposed as DataFusion `TableProvider` for pushdown filters/limits
- Connection string from `connection_env` (e.g., `RELAY_POSTGRES_URL`)
- Timeouts: `connect_timeout` (default 5s), `query_timeout` (default 30s)
- Live mode: `live_max_connections` (default 8)

(src/config/mod.rs:625–646; README lines 7–8)

## Metadata publication surface

**Static publication** (README lines 62–82):
- Portable `metadata.yaml` manifest (RESTless, standards-shaped, can be served without Relay)
- Compiled and published via `registry-manifest-cli` (sibling repo)
- Output bundle includes `index.json`, manifest, catalog JSON, DCAT, BRegDCAT-AP, SHACL, JSON Schemas

**Runtime endpoints** (src/api/metadata.rs; src/server.rs:199–200):
- All `/metadata/*` routes expose caller-scoped views (filtered by dataset/entity scope)
- Formats: JSON (default), JSON-LD (DCAT/SHACL), `application/ld+json`
- Content negotiation via `Accept` header

**Produced formats:**
- **Catalog JSON** — Relay's internal metadata catalog shape
- **DCAT JSON-LD** — Standard DCAT with distributions and data services
- **BRegDCAT-AP JSON-LD** — EU profile (CPSV public services, ADMS status, spatial coverage, publisher type)
- **SHACL JSON-LD** — Node shapes for entity validation
- **JSON Schema** — Entity and VC subject schemas
- **ODRL** — Policy/offer statements (embedded in DCAT)

(README lines 216–262; docs/metadata.md)

## Evidence offering verification

**What it is:** Relay-native capability to check whether submitted claims match registry data. Produces a verification receipt (not an official credential). Two modes:

1. **Relay-native** (`access.kind: registry-relay-verification`): Relay executes the check via `POST /evidence-offerings/{offering_id}/verifications`
2. **External Evidence Server** (`access.kind: evidence-server`): Metadata declares the endpoint; clients call directly

(docs/evidence-verification.md lines 1–14; README lines 204–208)

**Endpoint:** `POST /evidence-offerings/{offering_id}/verifications` (src/api/evidence_offerings.rs:131–134)

**Request body:** JSON claims matching the offering schema  
**Response:** Verification receipt (JSON or VC-JWT if client sent `Accept: application/vc+jwt`)

**Rate limiting:** Per-principal, per-offering. Configurable burst, window, max buckets (src/api/evidence_offerings.rs:39–115; src/config/mod.rs:104–147)

**Claim verification:** Optional hashing of submitted claims against a configured HMAC key for audit stability (src/server.rs:237–248; src/claim_verification.rs; requires `claim_verification.binding_key_env`)

(README lines 300–311; docs/evidence-verification.md; docs/ops.md for deployment)

## Standards referenced in code

| Standard | Token Name | Where It Appears | Strength |
|----------|-----------|------------------|----------|
| DCAT | `dcat:*` | src/api/metadata.rs (rendering), STANDARDS_ASSUMPTIONS.md (policy) | **emits**: `/metadata/dcat` endpoint generates `dcat:Dataset`, `dcat:Distribution`, `dcat:DataService`, `dcat:accessService`, `dcat:servesDataset` |
| DCAT-AP | `dcatap:*` | src/api/metadata.rs, registry-manifest-core dep (v0.1.1), STANDARDS_ASSUMPTIONS.md | **implements**: BRegDCAT-AP JSON-LD serialization, applicableLegislation rendering |
| BRegDCAT-AP | BRegDCAT-AP | Cargo.toml (registry-manifest-core), docs/metadata.md, README:216–262 | **emits**: `/metadata/dcat/bregdcat-ap` profile includes CPSV services, ADMS status, publisher type, spatial coverage |
| OGC API Records | `ogcapi-records` | Cargo.toml (feature flag), src/api/ogc/records.rs, config/example.yaml | **implements**: Feature-gated `/ogc/v1/records` landing, collections, items endpoints per OGC Records spec |
| OGC API Features | `ogcapi-features` | Cargo.toml (feature flag), src/api/ogc/features.rs | **partial**: Feature-gated; GeoJSON support for spatial features |
| OpenAPI | utoipa/utoipa-axum | Cargo.toml, src/api/openapi.rs, README:212–214 | **emits**: `/openapi.json` document with best-effort schema annotations |
| JSON Schema | jsonschema crate | Cargo.toml, src/api/schemas.rs, registry-manifest-core | **emits**: `/schemas/{schema_id}` for entity and VC subject validation |
| JSON-LD | serde_json | Registry-manifest-core renderer | **emits**: All metadata endpoints return `application/ld+json` variants |
| SHACL | pyshacl validation | src/api/metadata.rs (endpoint), justfile:49–67 (validation recipes) | **emits**: `/metadata/shacl` node shapes; external validation via pySHACL or SEMIC ITB |
| ODRL | `odrl:*` predicates | src/api/metadata.rs, STANDARDS_ASSUMPTIONS.md, registry-manifest-core | **emits**: `odrl:Offer`, `odrl:permission`, `odrl:prohibition`, `odrl:duty`, `odrl:constraint` in catalog |
| CPSV | `cpsv:PublicService` | src/api/metadata.rs, STANDARDS_ASSUMPTIONS.md, docs/metadata.md | **emits**: Public service metadata when declared in dataset config |
| OIDC / OAuth2 | JWT, JWKS, discovery | src/auth/oidc.rs, src/config/mod.rs:378–421 | **validates**: Bearer JWTs against external IdP JWKS; no token minting |
| W3C Verifiable Credentials | VC-JWT, compact serialization | src/provenance/ modules, Cargo.toml (jsonwebtoken), README:301–311 | **issues**: Compact JWS-wrapped VCs for responses when provenance enabled and client sends `Accept: application/vc+jwt` |
| SP DCI | SP DCI API shape, disability registry | src/api/spdci.rs, Cargo.toml (feature: spdci-api-standards), config/spdci_*.yaml | **maps_to**: SP DCI query/response shapes when feature enabled |
| PublicSchema | CEL mapping | Cargo.toml (feature: publicschema-cel), src/provenance/publicschema.rs | **aligns_with**: Optional CEL-based entity-to-VC mapping for PublicSchema profiles |

(STANDARDS_ASSUMPTIONS.md:1–100; src/api/metadata.rs; src/config/mod.rs; Cargo.toml; README lines 16–28)

## Tests and fixtures of interest

**Test config fixtures:**
- `config/example.yaml` — V1 reference config (CSV, XLSX, Parquet, Postgres; API key auth)
- `config/example.oidc.yaml` — OIDC config targeting local Zitadel
- `config/spdci_disability_registry.example.yaml` — SP DCI adapter example

**Data fixtures:**
- `fixtures/example_social_registry.xlsx` — Demo registry used by README walkthrough
- `profiles/example-civil-registration/fixtures/metadata.yaml` — Portable metadata manifest example
- `tests/fixtures/shacl/dcat-ap-catalog-smoke.ttl` — Minimal SHACL smoke test

**Integration tests** (tests/*.rs; ~45 test files):
- `tests/entity_routes.rs` — Row query, filtering, pagination
- `tests/aggregates_entity.rs` — Aggregate computation
- `tests/catalog_entity.rs` — DCAT/SHACL/BRegDCAT-AP rendering
- `tests/auth_flow.rs` — API key and OIDC validation
- `tests/config_provenance.rs` — VC issuance and signing
- `tests/claim_verification_jwt_receipt.rs` — Evidence verification with claim hashing
- `tests/postgres_snapshot.rs` — Postgres snapshot source
- `tests/format_csv.rs`, `tests/format_xlsx.rs`, `tests/format_parquet.rs` — Format parsers
- `tests/spdci_api_standards.rs` — SP DCI adapter behavior
- `tests/oidc_zitadel.rs` — End-to-end OIDC against live Zitadel

**Performance fixtures:**
- `perf/` — k6 scenarios, fixture generation, Criterion benches

## Explicit non-goals or limitations

From README and code:

- **Not a write platform:** "Write" operations (provisioning, inserts, updates) are intentionally out of scope (README:14)
- **Not an open-data portal:** Relay publishes restricted consultation APIs for authorized systems only (README:10)
- **Not a proof of authority:** Evidence-offering verification produces a receipt, not an official source credential or eligibility decision (docs/evidence-verification.md:1–2)
- **Not policy enforcement:** ODRL policies are published as metadata for downstream governance; Relay does not evaluate or enforce them (STANDARDS_ASSUMPTIONS.md:94–100)
- **No key/JWKS rotation at runtime:** Key and JWKS reloads require a restart unless a future provider adds live reload (src/main.rs:317–319)
- **No live Schema hot reload:** Entity schemas are compiled at startup and do not reload dynamically
- **Postgres live mode limits:** Only structured tables, no arbitrary queries; read-only column projection and gateway-side filters/limits (README:20)
- **No stream ingestion:** File and database sources are batch (snapshot or table scans); no Kafka, pub/sub, or event-streaming backends (README:7–8)

## Gaps and TODOs found in the repo

Search for `TODO`, `FIXME`, `XXX` in src/ returned no results at search time (2026-05-23). Code is actively maintained; gaps are tracked via GitHub Issues and review documents.

**Known open issues** (from review docs):
- BRegDCAT-AP emitter dropped `dct:conformsTo` for offerings (docs/evidence-offering-refactor-implementation-review-pass2.md)
- No golden JSON-LD fixtures for offering listings in DCAT tests
- External SEMIC SHACL validator integration not in CI (docs/evidence-offering-refactor-implementation-review.md)

(Consult AGENTS.md and GitHub Issues for current task board)

## Naming and rename status

**Crate name:** `registry-relay` (Cargo.toml:2)  
**Binary name:** `registry-relay` (compiled to `target/release/registry-relay`)  
**Repo slug:** `registry-relay` (no underscore in module/binary/repo name)

**Old naming (deprecated):**
- Pre-V0.1: Internal references used `registry_relay` underscore form in some docs
- Current: All public-facing names use hyphen (`registry-relay`) in Cargo.toml, binary, and CLI

**Rename status:** Complete in V0.1.0. No legacy underscore references leak into API or config surface.

---

**Attestation:** This packet documents the `registry-relay` repo at commit aec4394 as read on 2026-05-23. All paths, file:line citations, and facts are verified against the actual source. No statements appear here that are not grounded in README, code, config examples, or test fixtures.
