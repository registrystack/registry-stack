# registry-atlas — evidence packet

Last reviewed: 2026-05-23
Repo path: ../registry-atlas
Reviewed against commit: e4092a176f04fb315d28099acb056e0a91b73d3c

## What it is

Registry Atlas is a standards-first workbench for inspecting published catalogue and registry discovery artifacts. It is a browser SPA (single-page application) built with React 19 and TypeScript, running on Vite. The backend is a Node.js/Express server providing a same-origin fetch proxy. The semantic analysis engine runs in WebAssembly compiled from Rust crates (semantic-asset-discovery-core, semantic-asset-discovery, system-capability-discovery).

## Entry points

Build and run (package.json scripts:3717):
- `pnpm install` — install dependencies
- `pnpm dev` — start dev mode (builds WASM, runs concurrently)
  - UI on `http://127.0.0.1:5177` (Vite dev server)
  - Fetch proxy on `http://127.0.0.1:3717` (Express server)
- `pnpm server` — run Express server only
- `pnpm build` — production build (TypeScript check, Vite build, WASM compile)
- `pnpm check` — full verification (lint, test, build)
- `pnpm check:release` — release verification (Rust tests, lint, test, build, semantic checks)

Scripts present in repo (package.json:6-18):
- `build:wasm` — compile semantic-asset-discovery WASM from Rust
- `test` — run Vitest tests
- `lint` — run ESLint
- `canonicalize:system-fixtures` — normalize capability discovery fixtures
- `check:rust` — run Rust tests via cargo
- `check:semantic` — semantic discovery validation

Node 22+ required (engines:48).

## UI surface

The Atlas UI is a single React component workspace (App.tsx) with five main zones:

**Workspace tabs** (App.tsx:55, WorkspaceTab union):
1. **overview** — discovery summary, profile, validation status, missing items
2. **registry** — searchable list or map view (RegistryViewMode) of discovered datasets, services, distributions, catalogs
3. **capabilities** — system capability discovery search interface; query builder for strict needs-based matching
4. **evidence** — raw DiscoveryReport JSON, artifact tree, comparison view (App.tsx:57, ComparisonMode: "core"/"publisher"/"diff")

**Entry mechanisms** (App.tsx:94-115):
- URL input field with session history (stores last 5 URLs in sessionRecentCatalogues)
- Bearer token input (session-only, never persisted; see Token storage section)
- Profile selector (DCAT-AP 3.0.0, DCAT-AP 2.1.1, BRegDCAT-AP, Registry Relay publisher-specific profile) — inferred from catalog if not specified
- Curated demo fixtures bundled for offline use

**View states** (App.tsx:47-54):
- empty, loading, ready, fetch-error, parse-error, auth-required, unsupported

## Capability discovery

**Spec reference:** SYSTEM_CAPABILITY_DISCOVERY_SPEC.md

**Purpose:** answers operational questions ("Where can I find if someone is a farmer?") by indexing semantic metadata and producing **candidate answer routes** — not final authority claims.

**V0.1 strictness (SYSTEM_CAPABILITY_DISCOVERY_SPEC.md:84-88):**
- No fuzzy matching, synonym expansion, or AI inference
- Only exact matches after documented canonicalization (whitespace trim, Unicode normalization, case fold, compact IRI expansion)
- Every match backed by machine-verifiable evidence in metadata or explicit reviewed mappings
- Input shapes: structured `CapabilityQuery` with named `InformationNeed` objects; each need lists accepted `Term` values (label, IRI, field) or reviewed mappings
- No free-form natural-language queries; no implicit term invention

**Example (README.md:39-50, Rust struct):**
```rust
CapabilityQuery::new("social_protection_program")
    .need(InformationNeed::new("farmer_status")
        .requires_any([Term::label("Farmer")]))
```

**CLI equivalent (README.md:57-63):**
```bash
cargo run -q -p system-capability-discovery --bin system-capability-query -- \
  --envelope fixtures/system-capability/registry-relay-all-standards.envelope.json \
  --need-all disability_status label "Disabled Person" \
  --pretty
```

**Output:** CapabilityIndex produces candidate routes with strict evidence signals:
- exact label/IRI match to discovered metadata terms
- field name match (only when not ambiguous; requires `requires_all` for disambiguation)
- strict evidence references (no hand-waved explanations)
- gaps flagged explicitly (e.g., `LegalBasisUnknown`, `AuthorityUnknown`, `FreshnessUnknown`)

**Implementing code:** (crates/system-capability-discovery/)
- src/types.rs:49-59 — CapabilitySource struct (report, envelope, reviewed mappings, assertions)
- src/matcher.rs — strict matching rules
- tests/strict_matcher.rs — matching behavior specification
- tests/registry_relay_demo.rs — Registry Relay fixture validation

## Fetch proxy

**Server implementation:** server/index.mjs:342-441

**Default port:** 3717 (DEFAULT_PORT:10)

**Endpoint:** GET `/api/proxy?url=<target-url>`

**Functionality:**
- Accepts target URL as query parameter
- Performs DNS lookup with address resolution (isPrivateAddress check)
- Blocks private-network targets (10.0.0.0/8, 127.0.0.0/8, 192.168.0.0/16, 169.254.0.0/16, 172.16.0.0/12, fc00::/7, fe80::/10, etc.) unless ATLAS_PROXY_ALLOW_LOCAL=1 or NODE_ENV!=production (line 37-38)
- Enforces HTTP/HTTPS only (rejects data:, file:, ftp:, etc.)
- Strips embedded credentials from URL (line 137-138)
- Follows redirects up to limit (DEFAULT_REDIRECT_LIMIT:13, default 3; configurable via ATLAS_PROXY_REDIRECT_LIMIT)
- Enforces timeout (DEFAULT_TIMEOUT_MS:11, default 8s; configurable via ATLAS_PROXY_TIMEOUT_MS)
- Enforces response size limit (DEFAULT_MAX_BYTES:12, default 2MB; configurable via ATLAS_PROXY_MAX_BYTES)
- Whitelists allowed content types (application/json, application/ld+json, application/schema+json, text/*, application/yaml, etc.; line 16-26)
- Redacts sensitive URL query params (token, api_key, secret, password, etc.; isSensitiveQueryName:60-63)
- Pins DNS lookup to prevent TOCTOU (fetchPinned:234-275)
- Forwards Bearer token header (x-atlas-bearer request header; only sent on same-origin redirects; line 246-247)
- Returns JSON response with status, headers, body, media type, redirect chain

**Bearer token handling (README.md:31-32):** Session-only; forwarded to proxy request; never written to browser storage or server logs.

**Health endpoint:** GET `/api/health` (line 354-356) — returns `{"ok": true, "status": "ok"}`

**Error responses:** problem+json with machine-readable error codes (invalid_url, dns_lookup_failed, private_network_blocked, upstream_timeout, response_too_large, content_type_blocked, etc.)

## Discovery artifacts consumed

Atlas parsers handle these artifact kinds (fixtures/system-capability/registry-relay-all-standards.report.json):
- `dcat_catalog` — DCAT Catalogue (JSON-LD RDF)
- `dataset` — DCAT Dataset
- `distribution` — DCAT Distribution
- `data_service` — DCAT DataService
- `open_api` — OpenAPI 3.x specification (application/vnd.oai.openapi+json)
- `api_description` — OGC API Records or other API description
- `json_schema` — JSON Schema (for validation/discovery)
- `shacl` — SHACL shapes graph (RDF/Turtle or JSON-LD)
- `policy` — ODRL policy documents
- `class` — RDF class definitions (RDFS/OWL/SKOS)
- `metadata_index` — OGC API Records metadata landing page
- `catalog` — Generic catalog container

**Parser code:**
- src/lib/parser.ts:54-80 — DCAT JSON-LD parser (parseDcatJsonLd)
- src/lib/jsonld.ts:1-60 — JSON-LD namespace expansion and traversal
- Rust core: crates/semantic-asset-discovery-core/src/parser.rs — metadata classification and link discovery

**Format support:**
- JSON-LD (primary; application/ld+json)
- JSON Schema (application/schema+json)
- OpenAPI (application/vnd.oai.openapi+json)
- Turtle/N-Triples via N3 parsing (text/turtle)
- YAML (application/yaml, application/x-yaml)

## Standards referenced in code

Comprehensive evidence table (code search conducted across TypeScript, Rust, fixtures):

| Standard | File:Line | Claim Level | Details |
|----------|-----------|------------|---------|
| **DCAT** (Distributed Catalogue) | src/lib/parser.ts:36 | Required | `dcat:contactPoint`, `dcat:theme`, `dcat:keyword`, `dcat:landingPage`, `dcat:endpointURL`, `dcat:mediaType`, `dcat:distribution`, `dcat:accessService`, `dcat:servesDataset` |
| **DCAT-AP** (DCAT Application Profile) | App.tsx:73-76 | Required | v3.0.0, v2.1.1 profile support; dcatap:applicableLegislation, dcatap:availability |
| **BRegDCAT-AP** | App.tsx:76 | Reference | Registry Relay publisher-specific profile |
| **Dublin Core (dcterms)** | src/lib/parser.ts:32-52 | Required | dcterms:title, dcterms:description, dcterms:publisher, dcterms:accessRights, dcterms:conformsTo, dcterms:issued, dcterms:modified, dcterms:format, dcterms:license, dcterms:source, dcterms:creator, dcterms:provenance |
| **JSON-LD** | src/lib/jsonld.ts:1-60 | Required | Namespace expansion via @context, compacted/expanded form handling, graph flattening |
| **JSON Schema** | src/lib/artifacts.ts, fixtures | Required | Classification and structure validation of datasets |
| **OGC API Records** | App.tsx:111-114 | Supported | Landing page parsing; OGC API Records metadata index |
| **OpenAPI** | server/index.mjs:245, App.tsx:106-109 | Supported | application/vnd.oai.openapi+json content type; security scheme extraction |
| **SHACL** (Shapes Constraint Language) | fixtures/system-capability/registry-relay-all-standards.report.json:kind=shacl | Supported | SHACL shapes for validation graphs |
| **CCCEV** (Core Criterion Evidence Vocabulary) | SYSTEM_CAPABILITY_DISCOVERY_SPEC.md (implied) | Reference | Structured capability assertion; via evidence/findings in DiscoveryReport |
| **SKOS** (Simple Knowledge Organization System) | src/lib/jsonld.ts:20 | Supported | skos:definition, skos:prefLabel, concept schemes |
| **OWL** (Web Ontology Language) | src/lib/jsonld.ts:14 | Supported | Ontology and class hierarchies |
| **PROV** (Provenance Ontology) | src/lib/jsonld.ts:15, STANDARDS_ASSUMPTIONS.md:41 | Supported | dcterms:provenance assertions |
| **ODRL** (Open Digital Rights Language) | src/lib/parser.ts:39, server/index.mjs:245 | Supported | odrl:hasPolicy for usage policies |
| **FOAF** (Friend of a Friend) | src/lib/jsonld.ts:11 | Supported | foaf contact metadata |
| **vCard** | src/lib/jsonld.ts:21 | Supported | vcard:ContactPoint for contact info |
| **Schema.org** | src/lib/jsonld.ts:18, SYSTEM_CAPABILITY_DISCOVERY_SPEC.md:218 | Reference | Schema.org Person, properties as identity terms |

## Configuration surface

**Environment variables (server/index.mjs):**
- `ATLAS_PROXY_ALLOW_LOCAL` — "1" to allow localhost/private IP targets in production; default inferred from NODE_ENV
- `ATLAS_PROXY_MAX_BYTES` — max response size in bytes (default 2097152, 2MB)
- `ATLAS_PROXY_TIMEOUT_MS` — upstream request timeout in ms (default 8000)
- `ATLAS_PROXY_REDIRECT_LIMIT` — max HTTP redirect chain length (default 3)
- `NODE_ENV` — "production" mode disables localhost access unless ATLAS_PROXY_ALLOW_LOCAL=1
- `PORT` — server listen port (default 3717)

**Build flags (Rust Cargo features):**
- Semantic asset discovery uses conditional compilation for profile detection (crates/semantic-asset-discovery-core/src/profiles.rs)
- WASM build script: scripts/build-semantic-asset-discovery-wasm.mjs

## Tests and fixtures

**Vitest tests (tests/ directory):**
- tests/proxy.test.ts — fetch proxy security, DNS blocking, content-type filtering, error responses
- tests/dcat-parser.test.ts — DCAT JSON-LD parsing, catalog structure, dataset/distribution extraction
- tests/discovery.test.ts — end-to-end semantic discovery, artifact fetching, report generation
- tests/systemCapabilityDiscovery.test.ts — capability query matching, strict term matching, evidence scoring
- tests/readiness.test.ts — readiness status computation, missing items detection
- tests/App.test.tsx — React component rendering, tab navigation, fixture loading

**Rust tests (crates/):**
- crates/system-capability-discovery/tests/strict_matcher.rs — strict matching semantics, requires_any/requires_all
- crates/system-capability-discovery/tests/registry_relay_demo.rs — Registry Relay fixture validation
- crates/semantic-asset-discovery-core/tests/fixture_acceptance.rs — metadata classification, standard artifact recognition
- crates/semantic-asset-discovery-cli/tests/cli.rs — CLI argument parsing, fixture processing

**Fixtures (src/fixtures/, fixtures/system-capability/):**
- registry-relay-dcat-ap.jsonld — bundled DCAT catalog (offline demo)
- registry-relay-system-capability.envelope.json — DiscoveryRunEnvelope with fetch summary and rejected fetches
- registry-relay-all-standards.report.json — DiscoveryReport with all artifact kinds (DCAT, SHACL, JSON Schema, OGC API, OpenAPI)
- system-capability/*.json — capability query test cases

## Explicit non-goals

**From README.md (lines 31-32):** Bearer tokens are session-only and "are never written to browser storage or server logs."

**From SYSTEM_CAPABILITY_DISCOVERY_SPEC.md (lines 76-89, Non-Goals):**
- MUST NOT query live person-level data
- MUST NOT bypass authorization
- MUST NOT decide user access permissions
- MUST NOT make governance approval decisions
- MUST NOT perform fuzzy matching, implicit synonym expansion, or approximate semantic ranking in core matching layer
- MUST NOT require embeddings, language models, ontology reasoners, or large search infrastructure
- MUST NOT hide uncertainty, missing evidence, or ambiguous system boundaries
- MUST NOT turn semantic-asset-discovery into a domain-specific government registry

**From STANDARDS_ASSUMPTIONS.md (lines 21-36):** Atlas-derived hypotheses (candidate_route, gaps, confidence scores) are not standards predicates and MUST NOT be published back into metadata catalogues as if they were source-verified claims.

## Gaps and TODOs

1. **Query assist layer not implemented:** SYSTEM_CAPABILITY_DISCOVERY_SPEC.md:90-97 states V0.1 is "conservative evidence-to-route index" without AI, embeddings, or fuzzy matching. Query assist (natural-language search, synonym suggestion, embedding-based ranking) is explicitly deferred to a "later optional layer."

2. **No persistent token storage by design:** Bearer tokens are session-only. No mechanism for token refresh, credential expiry, or persistence across browser restarts. Callers must re-supply tokens per session.

3. **Reviewed mappings not yet populated:** SYSTEM_CAPABILITY_DISCOVERY_SPEC.md:152-177 defines ReviewedMappingSet structure and consumption (domain synonyms, country profiles, sector vocabularies) but no UI or ingestion interface present in Atlas v0.1.

4. **Governance workflow incomplete:** STANDARDS_ASSUMPTIONS.md:30-35 mentions "reviewed claims" from "human or governance workflow" but no workflow UI or assertion storage in current codebase.

5. **No federated discovery:** Proxy blocks private IPs unless allow-local is set. No built-in support for discovering across multiple independent publishers or aggregating reports.

6. **Content-type whitelist restrictive:** Only JSON, JSON-LD, JSON Schema, YAML, Turtle, and text/* are allowed through proxy. RDF/XML, N-Quads, custom formats blocked.

7. **No field-level lineage in UI:** Discovery report contains artifact references and link chains but UI does not yet visualize multi-hop discovery paths (e.g., "metadata -> DCAT link -> SHACL -> JSON Schema").

8. **Capability scoring incomplete:** STANDARDS_ASSUMPTIONS.md:74-91 describes candidate_route vs. candidate_source distinction (stronger claim requires authority + legal basis + CPSV evidence) but scoring algorithm not fully exposed in tests.

9. **No bulk/batch processing:** Atlas is per-URL discovery. No batch endpoint to discover multiple catalogs in parallel or schedule recurring harvests.

10. **Refresh indicators absent:** No UI signal for "data last fetched at" or "results may be stale". Envelope includes fetch timestamps but not surfaced to user.

## Naming and rename status

- **DiscoveryReport** — portable evidence contract for discovered metadata (SEMANTIC_ASSET_DISCOVERY_SPEC.md:137)
- **DiscoveryRunEnvelope** — optional host state from online discovery (fetch summary, rejected fetches, envelope)
- **CapabilitySource** — indexed capability discovery input (report + envelope + mappings + assertions)
- **CapabilityIndex** — queryable strict matcher over CapabilitySource(s)
- **CapabilityQuery** — user input for capability discovery (needs, terms, country, purpose)
- **InformationNeed** — named question within a capability query (e.g., "farmer_status")
- **Term** — accepted match target (label, IRI, field name, or reviewed mapping reference)
- **candidate_route** — discovered asset/capability matching a need (weak evidence)
- **candidate_source** — stronger route with authority + legal basis + CPSV evidence
- **FetchedArtifact** — metadata downloaded from a URL with headers, status, body bytes, hash
- **SemanticAsset** — classified and extracted piece of metadata (Dataset, Service, Shape, etc.)

No renaming campaigns detected in commit history. Nomenclature is stable across specification and implementation layers.
