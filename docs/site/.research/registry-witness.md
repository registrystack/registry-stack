> **Status: historical research note**
>
> This note records pre-monorepo research and is not current architecture or release evidence. Use the published documentation and pinned source links for current claims.

# registry-witness — evidence packet

Last reviewed: 2026-05-23
Repo path: ../registry-witness
Reviewed against commit: b4128a369c62ddb8e75dafb2e3834cd87f28d2d0

## What it is

**From README:** "Standalone Registry Witness workspace, claim evaluation, credential issuance, and attestation service."

**Structure:** Rust workspace with three crates:
- `registry-witness-core`: portable domain, config, auth, audit, request/response contracts
- `registry-witness-server`: Axum HTTP routes, runtime evaluation, renderers, credential issuance wiring, HTTP source connectors, auth middleware, audit emission
- `registry-witness-bin`: process startup, config loading, bind address, tracing, graceful shutdown

**Implementation:** Rust (Tokio async runtime, Axum web framework, jsonwebtoken library)

**Status:** Service (HTTP API + library components).

## Entry points

- **Binary:** `crates/registry-witness-bin/src/main.rs:1–83`
  - Entrypoint: `#[tokio::main]` at line 29
  - Subcommand: `openapi` to dump OpenAPI document (line 25–26)
  - Default: run HTTP service on configured bind address

- **Default port:** Configurable via `server.bind` in YAML; demo default: `127.0.0.1:4255` (demo/config/registry-witness.yaml:7)

- **Build/Run:**
  - `cargo run -p registry-witness-bin -- --config demo/config/registry-witness.yaml`
  - `cargo run -p registry-witness-bin -- openapi`

## Public API routes

All routes defined in `crates/registry-witness-server/src/api.rs:32–46`. Auth required (API key or Bearer token).

| Method | Path | Purpose | Source |
|--------|------|---------|--------|
| GET | `/openapi.json` | Fetch OpenAPI document | api.rs:37 |
| GET | `/.well-known/evidence-service` | Discover service capabilities | api.rs:38 |
| GET | `/.well-known/evidence/jwks.json` | Fetch issuer JWKS | api.rs:39 |
| GET | `/claims` | List claims | api.rs:40 |
| GET | `/claims/{claim_id}` | Get one claim definition | api.rs:41 |
| GET | `/formats` | List supported output formats | api.rs:42 |
| POST | `/claims/evaluate` | Evaluate claims for one subject | api.rs:43 |
| POST | `/claims/batch-evaluate` | Batch evaluate claims | api.rs:44 |
| POST | `/evidence/render` | Render evidence in requested format | api.rs:45 |
| POST | `/credentials/issue` | Issue credential from evaluation | api.rs:46 |

**OpenAPI document:** Generated at runtime via `crates/registry-witness-server/src/openapi.rs:8–248`.
- `info.title`: "Registry Witness API" (openapi.rs:12)
- `info.version`: "0.1.0" (openapi.rs:13)

## Claim model

**Location:** Claim definitions are YAML-configured. Configuration structure at `crates/registry-witness-core/src/config.rs:272–300` (struct `ClaimDefinition`).

**How claims are configured:**
- Array of `ClaimDefinition` objects under `evidence.claims` in YAML
- Each claim has `id`, `title`, `version`, `subject_type`, `value`, `inputs`, `source_bindings`, `rule`, `disclosure`, `formats`, `credential_profiles`, optional `cccev`, optional `oots`
- Example: demo/config/registry-witness.yaml:69–107 (claim `date-of-birth`)

**Claim type definition:**
- Defined by `rule` field (type union: Extract, Exists, Cel, Plugin) at config.rs:441–456
- Example rule types:
  - `Extract`: source + field (config.rs:442–444)
  - `Exists`: source presence (config.rs:446–447)
  - `Cel`: CEL expression + bindings (config.rs:449–452)
  - `Plugin`: external plugin (config.rs:454–455)

**Evaluation against sources:**
- Runtime evaluator at `crates/registry-witness-server/src/runtime.rs:200+` (function `evaluate_claim`)
- Rules evaluated based on type:
  - Extract: simple field extraction (runtime.rs ~550+)
  - Cel: Expression evaluation via `cel-mapper-core` (runtime.rs:730–807)
- Source data loaded async via `SourceReader` trait (runtime.rs:28–49)

## Source connectors

**Connector types:** Enum `SourceConnectorKind` at config.rs:399–404 defines two kinds:
```
SourceConnectorKind {
  RegistryDataApi,
  Dci,
}
```

**1. Registry Data API connector — PRESENT**
- **Evidence:** config.rs:402 (`RegistryDataApi`)
- **HTTP implementation:** standalone.rs:451–497 (`read_remote_registry_data_api_one`)
- **Request flow:** POST to `{base_url}/{dataset}/{entity}` with query params
- **Response parsing:** Lines 451–497 parse JSON response, extract via lookup config
- **Config:** SourceConnectionConfig at config.rs:336–341; binding.connector can be `registry_data_api`

**2. SP DCI (Decentralized Connectivity Infrastructure) connector — PRESENT**
- **Evidence:** config.rs:403 (`Dci`)
- **Config struct:** DciSourceConnectionConfig at config.rs:345–361
  - Default paths: `/registry/sync/search`, `/message/search_response/0/data/reg_records` (config.rs:379–392)
  - Default sender_id: "registry-witness" (config.rs:383–384)
  - Default query_type: "idtype-value" (config.rs:387–388)
  - Max results: 2 by default (config.rs:395–396)
- **HTTP implementation:** standalone.rs:499–545 (`read_external_dci_http_one`)
- **Request body:** standalone.rs:549–615 (`dci_search_request_body`) generates DCI-shaped search request
- **Response parsing:** standalone.rs:617–660 (`project_dci_record`) extracts fields via field_paths
- **Example config:** demo/config/registry-witness.yaml:32–50 (connections `crvs` and `farmer_registry` with DCI config)

**3. Generic HTTP connector — IMPLICIT**
- Both Registry Data API and DCI connectors use HTTP (reqwest client at standalone.rs:82–116)
- `HttpEvidenceSources` struct (standalone.rs:82–115) manages HTTP connections
- Timeout: 10 seconds (standalone.rs:34)
- Auth: Bearer token per connection (standalone.rs:92–96, 467, 513)

**Note:** There is no explicit "generic HTTP connector" abstraction; all source connections are HTTP-based and mapped to either RegistryDataApi or Dci.

## Credential issuance

**1. SD-JWT VC issuance — PRESENT**
- **Module:** `crates/registry-witness-core/src/sd_jwt.rs:1–259`
- **Entry point:** `sd_jwt::issue()` at sd_jwt.rs:115–173
- **Issuer struct:** `EvidenceIssuer` at sd_jwt.rs:28–113
  - Loads Ed25519 JWK from environment (from_profile_key at sd_jwt.rs:35–44)
  - Signs with EdDSA algorithm (jsonwebtoken library at sd_jwt.rs:105–109)
  - Public JWK exported as JSON (sd_jwt.rs:93–95)
- **Key handling:**
  - JWK format: OKP curve Ed25519 with d (private) and x (public) components (sd_jwt.rs:49–56)
  - Key source: environment variable `REGISTRY_WITNESS_ISSUER_JWK` (config.rs:561, standalone.rs:174)
  - PKCS#8 seed encoding: sd_jwt.rs:205–212
- **Signing:**
  - Algorithm: EdDSA (sd_jwt.rs:108, 162)
  - Token type: "dc+sd-jwt" header (sd_jwt.rs:163)
  - Payload structure: iss, iat, exp, vct, id, _sd_alg, _sd, cnf (sd_jwt.rs:127–159)
- **Disclosures:** Individual claim fields wrapped in SD-JWT disclosures with SHA-256 digests (sd_jwt.rs:180–189)
- **Library:** jsonwebtoken v10 (Cargo.toml:24)

**2. W3C Verifiable Credentials Data Model — NOT PRESENT**
- No references to W3C VC Data Model specification in code
- No use of `@context` with W3C VC namespace (though CCCEV rendering uses JSON-LD @context)
- Issued credentials are SD-JWT format, not VC Data Model JSON objects

**3. Generic JWT — PRESENT**
- Used internally for signing and verification
- jsonwebtoken library provides JWT primitives (Cargo.toml:24)
- EdDSA signature algorithm (sd_jwt.rs:108)
- Header extraction in api.rs:13 (holder proof validation)

**4. CCCEV-shaped evidence — PRESENT**
- **Format constant:** `FORMAT_CCCEV_JSONLD = "application/ld+json; profile=\"cccev\""` (model.rs:10)
- **Renderer:** `render_cccev()` at runtime.rs:909–930
- **Evidence node builder:** `render_cccev_evidence_node()` at runtime.rs:933–990
- **Output structure:**
  - `@context` with cccev, dcterms, foaf, time, xsd namespaces (runtime.rs:915–927)
  - Evidence nodes as `cccev:Evidence` type (runtime.rs:983)
  - CCCEV properties: `cccev:isProvidedBy`, `cccev:supportsRequirement`, `cccev:supportsValue`, `cccev:validityPeriod`, `cccev:isConformantTo` (runtime.rs:921–924, 985–988)
  - Supported value structure with `cccev:SupportedValue` and `cccev:providesValueFor` (runtime.rs:970–978)
- **Configuration:** Optional `cccev` config in claim definition (config.rs:297, demo/config/registry-witness.yaml:55–57)
  - `requirement_type`: string field in CccevConfig (config.rs:343)

## Disclosure policy

**Type and enforcement:**

Disclosure is a multi-level system controlling what data is revealed to the caller.

**Disclosure profiles enum:** `DisclosureProfile` at model.rs:13–40
- `Value`: full value disclosed
- `Predicate`: only satisfaction (true/false) disclosed
- `Redacted`: value completely hidden

**Disclosure downgrade enum:** `DisclosureDowngrade` at model.rs:42–60
- `Deny`: no downgrade allowed (strict)
- `Default`: downgrade to claim's default disclosure
- `Redacted`: downgrade to redacted

**Configuration:**

Per-claim disclosure policy at config.rs:272–300 (ClaimDefinition):
```yaml
disclosure:
  default: value
  allowed: [value, redacted]
```

**Enforcement point:** runtime.rs:841–890 (function `view_claim`)
- Checks caller's disclosure request against claim's `allowed` list
- If not allowed, applies downgrade strategy (runtime.rs:863–875)
- Downgrade options:
  - Deny: returns DisclosureNotAllowed error (runtime.rs:867)
  - Default: uses claim's default_disclosure (runtime.rs:870)
  - Redacted: downgrade to Redacted profile (runtime.rs:873)
- Result stored in ClaimResultView.disclosure (model.rs:222)

**Example configuration:** demo/config/registry-witness.yaml:100–104
```yaml
disclosure:
  default: value
  allowed: [value, redacted]
```

## Audit events

**Audit event structure:** `EvidenceAuditEvent` at model.rs:263–276
- Fields: event_id, occurred_at, principal_id, decision, method, path, status, verification_id, claim_hash, row_count, error_code

**Emission point:** standalone.rs:326–366 (function `emit_audit`)
- Collects request/response metadata
- Attaches verification context (EvidenceAuditContext from api.rs:108–113)
- Calls `state.audit.emit()` at standalone.rs:347

**Sink types:** Enum `AuditSink` at standalone.rs:243–246
- `Stdout(Mutex<Box<dyn Write + Send>>)`
- `File(Mutex<Box<dyn Write + Send>>)`

**Format:** JSONL (JSON Lines) — one audit event per line
- test: standalone.rs:805–819 (`stdout_audit_sink_emits_raw_jsonl`)
- Serialized via serde_json to `EvidenceAuditEvent`

**Configuration:**
- audit.sink: "stdout" (default) or "file" (config.rs:170–186)
- audit.path: required if sink=file (config.rs:173)
- Example: demo/config/registry-witness.yaml:23–25 (sink: file, path: demo/var/registry-witness-audit.jsonl)

**Redaction:** Fields like claim_hash, verification_id are optional and redacted by design (model.rs:271–273)

## Configuration surface

**Configuration file format:** YAML, loaded at bin/main.rs:45–46 via `serde_yml`

**Top-level config:** `StandaloneRegistryWitnessConfig` at config.rs:10–95

**Sections:**

1. **server** (config.rs:129–140)
   - `bind`: SocketAddr, default "127.0.0.1:8081" (config.rs:143–146)

2. **auth** (config.rs:149–165)
   - `api_keys`: array of `EvidenceCredentialConfig` (config.rs:153)
     - `id`, `token_env` (env var name), `scopes` (list of strings)
   - `bearer_tokens`: array of `EvidenceCredentialConfig` (config.rs:155)

3. **audit** (config.rs:168–186)
   - `sink`: "stdout" or "file" (config.rs:170)
   - `path`: optional file path (config.rs:173)

4. **evidence** (config.rs:224–300)
   - `enabled`: boolean (config.rs:227)
   - `service_id`: string, default "registry-witness" (config.rs:228–229)
   - `api_version`: string, default "2026-05" (config.rs:231)
   - `api_base_url`: string, default "/" (config.rs:232–233)
   - `claims_url`: string, default "/claims" (config.rs:234–235)
   - `formats_url`: string, default "/formats" (config.rs:236–237)
   - `inline_batch_limit`: usize, default 100 (config.rs:238–239)
   - `claims`: array of `ClaimDefinition` (config.rs:241)
   - `credential_profiles`: map of profile_id → `CredentialProfileConfig` (config.rs:243)
   - `source_connections`: map of connection_id → `SourceConnectionConfig` (config.rs:245)

**Environment variables:**

- **Auth credentials:**
  - `REGISTRY_WITNESS_API_KEY`: API key token (referenced via token_env)
  - `REGISTRY_WITNESS_BEARER_TOKEN`: Bearer token (referenced via token_env)

- **Source connections:**
  - Each source connection has `token_env`: name of bearer token env var for that source (config.rs:338)
  - Example: `EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN` (demo/config/registry-witness.yaml:35)

- **Credential issuance:**
  - Each credential profile has `issuer_key_env`: name of JWK env var (config.rs:559)
  - Example: `REGISTRY_WITNESS_ISSUER_JWK` (demo/config/registry-witness.yaml:55)

**Validation:** config.validate() at config.rs:21–95 enforces:
- evidence.enabled must be true
- At least one API key or bearer token configured
- All source bindings must reference valid source connections
- Credential profiles with proof_of_possession="required" must use did:jwk
- depends_on relationships form a DAG (no cycles)

## Auth and authorization

**Authentication mechanism:**

Request headers checked in order at standalone.rs:223–240:

1. **API Key** (x-api-key header):
   - Header: `x-api-key: <token>`
   - Lookup: Case-insensitive constant-time comparison (subtle::ConstantTimeEq) at standalone.rs:225
   - Source: config.auth.api_keys (loaded from env vars at standalone.rs:217)

2. **Bearer Token** (Authorization header):
   - Header: `Authorization: Bearer <token>`
   - Extraction: strip "Bearer " prefix at standalone.rs:233
   - Lookup: Case-insensitive constant-time comparison at standalone.rs:235
   - Source: config.auth.bearer_tokens (loaded from env vars at standalone.rs:218)

3. **Failure:** Returns `EvidenceError::MissingCredential` (standalone.rs:239)

**Authorization (scopes):**

- Authenticated principal carries scopes (model.rs:251–260, struct `EvidencePrincipal`)
- Scope check: `has_scope()` method at model.rs:258–260
- Per-claim scope requirement: optional `required_scope` in source binding (config.rs:326)
- Enforcement: standalone.rs:382–402 (function `validate_claim_scopes`)
  - Collects all required scopes for a claim (standalone.rs:352–371)
  - Validates principal has all scopes
  - Denies with ScopeDenied error if missing (standalone.rs:402)

**Middleware:** `auth_audit_middleware` at standalone.rs:301–323
- Extracts principal from request headers
- Stores in request extensions (used by route handlers)
- Calls audit on success and failure

**Issuer authentication:**

Source connectors authenticate to external sources with bearer tokens:
- HTTP header: `Authorization: Bearer <token>` (standalone.rs:467, 513)
- Token source: source connection config (config.rs:338)

## Standards referenced in code

| Token | File:Line | Claim Level | Notes |
|-------|-----------|-------------|-------|
| SD-JWT VC | sd_jwt.rs:2 | implements | "Minimal SD-JWT VC issuer"; "dc+sd-jwt" header and format |
| JSON Web Token (JWT) | sd_jwt.rs passim | implements | jsonwebtoken library; EdDSA signing |
| CCCEV | runtime.rs:909–990 | renders | JSON-LD rendering with cccev: namespace and vocabulary |
| JSON-LD | runtime.rs:915 | emits | @context structure for CCCEV rendering |
| EdDSA | sd_jwt.rs:108, 162 | implements | Signing algorithm for credentials |
| did:web | config.rs example, sd_jwt.rs:237 | aligns_with | Example issuer identifier format in tests |
| DCI (Decentralized Connectivity) | standalone.rs passim | implements | Connector kind; search/sync protocol defaults |
| RFC 3339 | time::Rfc3339 import | emits | Timestamp format for issued_at, expires_at |
| Base64url | base64::URL_SAFE_NO_PAD | implements | JWK encoding, disclosure encoding |

**Standards NOT found in code:**
- W3C Verifiable Credentials Data Model (credential format is SD-JWT, not VC envelope)
- ODRL (no policy/obligation reference)
- DCAT (data catalog; no data.europa.eu/r8g references)
- OGC API Records (no OGC references)
- PROV-O (provenance vocabulary; only internal ClaimProvenance struct)
- DPV (Data Privacy Vocabulary; no privacy markup)

## Tests and fixtures

**Test files:**

- `crates/registry-witness-server/tests/standalone_http.rs`: HTTP integration tests
  - Line 195–284: registry_data_api flow test
  - Line 429–487: CEL evaluation test
  - Line 476: audit sink validation
  - Lines 805–839: audit event format and error handling

- `crates/registry-witness-server/tests/decentralized_cross_source_cel.rs`: Cross-source CEL evaluation
  - Line 120+: DCI connector configuration
  - Multi-source CEL expression evaluation

- `crates/registry-witness-server/tests/common/mod.rs`: Test helpers

- `crates/registry-witness-core/src/sd_jwt.rs:221–259`: SD-JWT unit tests
  - Line 226–231: disclosure digest test
  - Line 235–258: JWT header stability test

**Key fixtures:**

- Demo config: demo/config/registry-witness.yaml (crvs + farmer_registry sources, DCI + cert profiles)
- Test JWK: hardcoded at sd_jwt.rs:236 (test issuer)

## Explicit non-goals

From README (lines 5–9):

> This repository owns claim configuration, claim evaluation, disclosure policy,
> Registry Witness API routes, credential issuance primitives, HTTP source
> connectors, fail-closed API key and bearer-token auth, and redacted audit event
> emission. **Registry Relay may publish metadata that points to a Registry Witness,
> but Registry Witness does not import or link Registry Relay code.**

Implication: Registry Witness is intentionally **decoupled** from Registry Relay; it does not depend on or re-use Registry Relay libraries.

## Gaps and TODOs

**In-code TODOs/FIXMEs:** None found in source code (grep search returned empty).

**Design gaps observed:**

1. **No W3C VC Data Model envelope** — Credentials are SD-JWT; no VC wrapper for multi-format portability.
2. **Limited holder binding** — Proof of possession only supports did:jwk; other DID methods not supported (config.rs:46–66).
3. **Plugin rule type declared but unimplemented** — RuleConfig::Plugin variant exists (config.rs:454–455) but no implementation found.
4. **No explicit caching of credential profiles** — Lookup happens per request (runtime.rs:993–1014).
5. **Fixed DCI defaults** — DCI search_path, records_path, max_results are hardcoded defaults; limited flexibility for non-DCI-compliant registries.
6. **Audit sink write errors surface as request errors** — Audit write failure causes caller to receive error response, not transparent logging (standalone.rs:312, 320, 346).

## Naming and rename status

**Crate names:**
- `registry-witness-core` (version 0.1.0)
- `registry-witness-server` (version 0.1.0)
- `registry-witness-bin` (version 0.1.0)

**Service identity:**
- Default service_id: "registry-witness" (config.rs:249)
- Configurable in YAML: `evidence.service_id` (config.rs:228)
- Example: "demo.registry-witness" (demo/config/registry-witness.yaml:29)

**Old labels:** No references to deprecated names in code. Single-source codebase, no migration artifacts.

**Constants:**
- `FORMAT_CLAIM_RESULT_JSON = "application/vnd.registry-witness.claim-result+json"` (model.rs:9)
- `FORMAT_CCCEV_JSONLD = "application/ld+json; profile=\"cccev\""` (model.rs:10)
- `FORMAT_SD_JWT_VC = "application/dc+sd-jwt"` (model.rs:11)
