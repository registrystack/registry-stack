# Metadata And Runtime Split Spec

Status: historical implementation spec. The split has landed through the
external `registry-manifest-core` and `registry-manifest-cli` crates. See
[metadata.md](../metadata.md), [configuration.md](../configuration.md), and
[development.md](../development.md) for the current operator and contributor
contract.

This document specifies a standards-first split of `registry-relay` into:

- a portable metadata library
- the Relay runtime
- profile data and fixtures for ecosystem adoption
- a thin metadata CLI crate

The split direction is still right, but the implementation must respect the
current codebase: catalog and SHACL rendering are currently coupled to
`crate::config::Config`, `crate::entity::EntityRegistry`, and several Cargo
feature branches. The first slice is therefore not a clean file move. It is an
adapter extraction: introduce a portable metadata manifest, compile it into a
runtime-independent view, and make Relay adapt its current config and registry
state into that view while the demo config is split.

The project has no external users yet. We should use that to do the clean
breaking refactor now, while keeping the implementation simple enough to finish.

## Decision

Split by responsibility, not by current file names:

```text
registry-manifest-core
registry-manifest-cli
registry-relay
profiles/
```

`registry-manifest-core` owns the portable standard-facing metadata model,
validation, syntactic IRI normalization, compilation, and pure renderers.

`registry-manifest-cli` is a thin binary crate for validating manifests and
rendering static artifacts. It depends on `registry-manifest-core`; the core
library must not depend on `clap` or CLI concerns.

`registry-relay` owns live behavior: HTTP routing, auth, audit, observability,
source bindings, query execution, runtime capabilities, OpenAPI route assembly,
OGC HTTP routes, aggregates, verification, claim verification, provenance,
admin surfaces, health, DID, contexts, cache behavior, and runtime errors.

`profiles/` starts as data, fixtures, and validators for non-normative,
hypothetical application examples and similar consumers. Real OpenCRVS,
OpenSPP, OpenIMIS, SP DCI, or PublicSchema profiles should be added only after
reviewing official artifacts or working with the relevant maintainers. Promote
profile work to a Rust crate only after there are at least two generators or
shared profile abstractions that justify it.

Do not preserve the current mixed config shape unless a short transitional
reader is clearly cheaper than converting tests and demo fixtures.

## Terminology

Use these terms consistently:

- `metadata manifest`: the portable `metadata.yaml` document.
- `relay config`: the operational `relay.yaml` document.
- `compiled metadata`: the validated, normalized, renderer-ready view produced
  by `registry-manifest-core`.
- `runtime rows`: source-backed entity data served by Relay.
- `OGC API Records records`: catalog records that describe resources.

Do not use "records" for both runtime rows and OGC catalog records. Runtime
entity data should use `rows` or `items` in new surfaces. OGC API Records keeps
the standards term `Record`.

## Current Codebase Notes

These are implementation facts the split must account for:

- `src/metadata/catalog.rs` depends on `crate::config::Config` and
  `crate::entity::EntityRegistry`.
- `src/metadata/shacl.rs` depends on `crate::config::Config`,
  `crate::entity::EntityRegistry`, and catalog types.
- Current metadata renderers contain feature-gated branches for
  `standards-cel-mapping`, `publicschema-cel`, `spdci-api-standards`,
  `ogcapi-features`, and `ogcapi-records`.
- Current SHACL/DCAT output already includes BRegDCAT-AP concepts such as
  `adms:status`, `dspace:participantId`, ELI access-rights, and authority
  publisher typing.
- Current entity "schema" output is an ad-hoc JSON envelope, not JSON Schema.
- Current demo configs embed runtime field bindings such as `from: <column>`
  across many files. Splitting config is a fixture conversion project, not a
  small cleanup.
- In-flight OGC work already split `src/api/ogc.rs` into `src/api/ogc/` and
  added `tests/ogc_records_api.rs`. Treat this as current code, not future work.

## Design Principles

- Standards first, machinery second.
- Metadata describes meaning. Runtime config describes behavior.
- Public metadata must not reveal storage or backend implementation details.
- Runtime metadata visibility must not imply runtime row access.
- Static publication should work without running Relay.
- Profiles should be boring data, deterministic generators, validators, and
  golden fixtures, not a framework.
- Keep remote distribution, signing, federation, and control-plane features out
  of scope until a real deployment requires them.
- Normalize compact IRIs only by syntactic prefix expansion from the manifest
  `vocabularies` block. Do not dereference vocabularies or perform semantic
  reasoning in core.

## What We Learn From X-Road

X-Road is useful here as a standards-boundary reference, not as an architecture
to copy wholesale.

Transferable patterns:

- Separate distributed or published configuration from local runtime
  enforcement.
- Expose service and entity discovery as explicit metadata operations.
- Distinguish broad discovery from caller-allowed discovery.
- Let clients retrieve descriptions through stable standard-facing surfaces.
- Hide backend endpoint details when exposing public descriptions.
- Treat identifiers and participants as first-class metadata.

Non-transferable patterns for this project right now:

- Central server and security server topology.
- Certificate-heavy trust model.
- Signed MIME configuration directories.
- Federation and configuration proxies.
- SOAP/WSDL compatibility as a product requirement.
- A full metadata control plane.

The simple translation for Registry Relay is:

```text
list catalogs and entities
list visible catalogs and entities for this caller
get schema or semantic description for one entity
get runtime rows only through Relay
publish static metadata without Relay
```

## Goals

- Make registry metadata reusable without running the Relay API.
- Let external projects validate and render metadata manifests.
- Make Relay consume metadata instead of owning the metadata model.
- Support catalog JSON, DCAT, DCAT application profiles, SHACL, JSON Schema,
  and link-free OGC API Records record bodies.
- Support ecosystem profile packs without coupling them to Postgres,
  DataFusion, Axum, auth, audit, source ingestion, or Relay-specific config.
- Keep the first implementation bounded enough to complete in a worktree.

## Non-Goals

- No compatibility shim for old configs unless tests show it is cheaper than a
  clean conversion.
- No remote metadata publishing protocol.
- No signing, trust anchors, federation, or metadata proxies.
- No generic registry platform.
- No replacement for civil registration, social protection, OpenIMIS, or SP DCI APIs.
- No vocabulary dereferencing or semantic reasoning in core.
- No profile-specific business logic in `registry-manifest-core`.
- No runtime dependency from metadata-core back into Relay.
- No OGC HTTP link generation in metadata-core.

## Package Boundaries

### `registry-manifest-core`

Owns portable metadata.

Responsibilities:

- Parse metadata manifests.
- Validate metadata manifests.
- Normalize compact IRIs by prefix expansion from manifest vocabularies.
- Compile manifests into `CompiledMetadata`.
- Model catalogs, datasets, entities, fields, identifiers, relationships,
  codelists, labels, descriptions, constraints, conformance claims, and
  standard mappings.
- Render pure metadata artifacts:
  - catalog JSON
  - DCAT JSON-LD
  - DCAT application profile JSON-LD, including BRegDCAT-AP
  - SHACL shapes
  - JSON Schema Draft 2020-12
  - link-free OGC API Records record bodies
- Provide golden tests for renderer stability.

Must not depend on:

- Axum
- DataFusion
- Tokio Postgres
- HTTP routing
- auth
- audit
- observability middleware
- source ingestion
- runtime bindings
- secret handling
- Relay query execution
- `utoipa`
- `clap`

Candidate layout:

```text
crates/registry-manifest-core/
  Cargo.toml
  src/
    lib.rs
    manifest.rs
    validate.rs
    compile.rs
    vocab.rs
    render/
      catalog.rs
      dcat.rs
      json_schema.rs
      ogc_records.rs
      shacl.rs
  tests/
    fixtures/
```

Extraction rule:

Current renderer code should not be lifted directly. First define portable input
types in core, then adapt current `Config` plus `EntityRegistry` into those
types from Relay. Feature-gated runtime concerns stay in Relay unless the output
is a pure metadata profile selected by manifest data.

### `registry-manifest-cli`

Owns local validation and rendering commands.

Responsibilities:

- Validate `metadata.yaml`.
- Render static artifacts from a manifest.
- Return explicit metadata error codes.
- Avoid networking, signing, federation, and runtime API behavior.

Candidate layout:

```text
crates/registry-manifest-cli/
  Cargo.toml
  src/main.rs
```

Candidate commands:

```bash
registry-metadata validate metadata.yaml
registry-metadata render metadata.yaml --format catalog
registry-metadata render metadata.yaml --format dcat
registry-metadata render metadata.yaml --format dcat --profile bregdcat-ap
registry-metadata render metadata.yaml --format bregdcat-ap
registry-metadata render metadata.yaml --format shacl
registry-metadata render metadata.yaml --format json-schema --dataset vital-events --entity person
registry-metadata render metadata.yaml --format ogc-records
registry-metadata publish metadata.yaml --out public/metadata
```

`publish` means local file generation only.

### `registry-relay`

Owns live behavior.

Responsibilities:

- Load Relay runtime config.
- Load and compile metadata manifests through `registry-manifest-core`.
- Adapt current config and `EntityRegistry` state into compiled metadata during
  the transition.
- Validate runtime bindings against compiled metadata.
- Start HTTP listeners.
- Enforce authentication, scopes, purpose headers, and visibility.
- Bind metadata fields to concrete sources.
- Execute queries and aggregates.
- Serve runtime row APIs.
- Serve OGC API Records and OGC API Features HTTP routes.
- Serve runtime OpenAPI documents.
- Serve verify, claim verification, provenance, and provenance issuance routes.
- Serve admin, DID, health, context, and operational routes.
- Emit caller-scoped metadata views where runtime authorization applies.
- Maintain observability, audit, cache, and redaction behavior for runtime
  surfaces.
- Map errors to problem-details HTTP responses.

Concrete module ownership:

- `src/observability.rs`: Relay.
- `src/audit/`: Relay.
- `src/connector/`: Relay.
- `src/source/`: Relay.
- `src/ingest/`: Relay.
- `src/format/`: Relay.
- `src/table_provider/`: Relay.
- `src/api/admin.rs`: Relay.
- `src/api/did.rs`: Relay.
- `src/api/provenance_issuance.rs`: Relay.
- `src/api/health.rs`: Relay.
- `src/api/contexts.rs`: Relay.
- `src/spdci.rs`: Relay execution. Profile descriptors and fixtures live under
  `profiles/example-benefits-sync/`.
- `src/config/validate.rs` and `src/config/capabilities.rs`: Relay runtime
  config validation.

Must not define the canonical metadata model. It may define runtime-specific
views, OpenAPI schemas, and authorization predicates over compiled metadata.

Because metadata-core must not depend on `utoipa`, Relay should expose OpenAPI
schema types through Relay-owned DTOs or newtypes instead of deriving
`utoipa::ToSchema` on core metadata structs.

### `profiles/`

Owns ecosystem-specific profile packs as data first.

Responsibilities:

- Store profile descriptors.
- Store example manifests.
- Store source artifacts used by generators.
- Validate profile conformance.
- Generate metadata manifests from known external artifacts where useful.
- Keep golden outputs for generated metadata.
- Document unsupported or lossy mappings.

Initial layout:

```text
profiles/
  example-civil-registration/
    profile.yaml
    fixtures/
  example-social-benefits/
    profile.yaml
    fixtures/
  openimis/
    profile.yaml
    fixtures/
  example-benefits-sync/
    profile.yaml
    fixtures/
  example-person-schema/
    profile.yaml
    fixtures/
```

Each `profile.yaml` should include:

- profile id
- profile version
- upstream system or standard
- supported input artifacts
- required concepts
- optional concepts
- required identifiers
- cardinality expectations
- codelist expectations
- unsupported mappings
- conformance checks
- fixture list
- generator command, if any

Profile validation is stricter than core validation. A manifest can be valid
generic metadata while failing an example civil registration or example social
benefits profile check. In that case it must not claim conformance to that
profile.

## Metadata Manifest Model

The manifest is the source of portable meaning.

Example:

```yaml
schema_version: registry-metadata/v1

catalog:
  id: civil-registration
  base_url: https://example.gov
  title:
    en: Civil Registration Catalog
  description:
    en: Registry metadata for civil registration entities.
  publisher:
    name: Ministry of Home Affairs
    iri: https://example.gov/agencies/mha
    authority_type: eli:PublicAuthority
  participant_id: https://example.gov/agencies/mha
  conforms_to:
    - https://semiceu.github.io/BRegDCAT-AP/releases/3.0.0/
  standards:
    dcat: "3.0"
    shacl: "1.1"
    json_schema: "2020-12"
  application_profiles:
    - id: dcat-ap
      version: "3.0"
    - id: bregdcat-ap
      version: "3.0.0"

vocabularies:
  person: https://person-schema.example.gov/vocab/
  civreg: https://civil-registration.example.gov/vocab/
  sync: https://benefits-sync.example.gov/vocab/
  eli: http://data.europa.eu/eli/ontology#
  adms: http://www.w3.org/ns/adms#

profiles:
  - id: example-civil-registration
    version: "1"
  - id: bregdcat-ap
    version: "3.0.0"

datasets:
  - id: vital-events
    title:
      en: Vital Events
    conforms_to:
      - https://semiceu.github.io/BRegDCAT-AP/releases/3.0.0/
    status: under_development
    access_rights: restricted
    entities:
      - name: person
        title:
          en: Person
        identifiers:
          - name: person_id
            kind: local
        fields:
          - name: person_id
            type: string
            required: true
            constraints:
              min_length: 1
              max_length: 64
              pattern: "^[A-Za-z0-9-]+$"
            concepts:
              - psc:Person.identifier
          - name: birth_date
            type: date
            concepts:
              - psc:Person.birthDate
              - civreg:BirthRecord.child.birthDate
          - name: sex
            type: code
            codelist: sex
            constraints:
              in:
                - female
                - male
            concepts:
              - psc:Person.sex
        relationships:
          - name: mother
            target_entity: person
            cardinality: zero_or_one
            role: parent

codelists:
  - id: sex
    scheme_iri: https://example.gov/codelists/sex
    external_ref: https://example.gov/codelists/sex.ttl
    concepts:
      - code: female
        iri: https://example.gov/codelists/sex/female
        label:
          en: Female
      - code: male
        iri: https://example.gov/codelists/sex/male
        label:
          en: Male
```

Metadata fields are logical fields. They must not contain table names, database
column names, source URLs, access scopes, required runtime filters, source
identifiers, source file paths, secrets, or backend service endpoints.

Manifest slots required by renderers:

- `catalog.base_url`
- `catalog.conforms_to`
- `catalog.application_profiles`
- `datasets[].conforms_to`
- `fields[].constraints.pattern`
- `fields[].constraints.min_length`
- `fields[].constraints.max_length`
- `fields[].constraints.in`
- `codelists[].scheme_iri`
- `codelists[].external_ref`

SHACL rendering rules:

- Use `sh:pattern` for field regex constraints.
- Use `sh:minLength` and `sh:maxLength` for string length constraints.
- Use `sh:in` for inline enumerations.
- Use codelist `scheme_iri` as a `skos:ConceptScheme`.
- Use `external_ref` for externally governed codelists such as ICD, IATI, or
  national code systems.
- Avoid project-private predicates for codelists when a standard SHACL or SKOS
  representation is available.

JSON Schema rendering rules:

- Emit JSON Schema Draft 2020-12.
- Use OpenAPI 3.1 compatible JSON Schema.
- Emit `$schema: "https://json-schema.org/draft/2020-12/schema"`.
- Emit `$id` as
  `{base_url}/metadata/schema/{dataset_id}/{entity}/schema.json`.
- Emit a real object schema with `type`, `properties`, `required`,
  constraints, and definitions where needed.
- The current ad-hoc entity schema envelope is a Relay DTO, not the target JSON
  Schema output.

DCAT rendering rules:

- Emit a base `dcat.jsonld`.
- Emit one artifact per application profile:
  `dcat.<profile_id>.jsonld`.
- BRegDCAT-AP is a first-class application profile. It must not be hidden
  behind a generic `standards.dcat: "3.0"` flag.
- DCAT-AP, BRegDCAT-AP, GeoDCAT-AP, and HealthDCAT-AP can share internal
  renderer helpers, but they cannot be treated as one identical output.

OGC API Records rendering rules:

- Metadata-core may render link-free record bodies as `serde_json::Value`.
- Link-free record bodies may include record id, type `"Record"`, properties,
  geometry, and `conformsTo`.
- Metadata-core must not render absolute `self` or `alternate` links.
- Relay injects links through a runtime `LinkTemplate` because absolute URLs,
  pagination, caller context, and route availability are runtime concerns.

## Compiled Metadata

`CompiledMetadata` is the stable boundary between portable metadata and Relay.

Shape:

```rust
pub struct CompiledMetadata {
    inner: Arc<CompiledMetadataInner>,
}

pub struct CompiledMetadataInner {
    pub catalog: CompiledCatalog,
    pub datasets: BTreeMap<DatasetId, CompiledDataset>,
    pub entities: BTreeMap<EntityKey, CompiledEntity>,
    pub codelists: BTreeMap<CodelistId, CompiledCodelist>,
    pub profiles: Vec<ProfileClaim>,
}

impl CompiledMetadata {
    pub fn filter(
        &self,
        predicate: impl Fn(&CompiledDataset, &CompiledEntity) -> bool,
    ) -> CompiledMetadata;
}
```

Ownership rules:

- `CompiledMetadata` is owned by core.
- It should be cheap to clone through `Arc`.
- `filter` lives in core because renderers need a scoped metadata view.
- Runtime principals, scopes, and authorization decisions stay in Relay.
- Relay supplies the predicate used to build a public, authenticated, or
  caller-scoped compiled view.
- Core errors use `registry_manifest_core::Error`.
- Relay errors use `registry_relay::Error` and wrap core errors with
  `#[from]`.
- Problem-details HTTP mapping stays in Relay.

## Relay Runtime Config

`relay.yaml` is operational. It references the manifest and binds logical fields
to live sources.

Example:

```yaml
server:
  bind: 127.0.0.1:8080

metadata:
  manifest_path: ./metadata.yaml
  public_endpoints: false

sources:
  civil_registry:
    kind: postgres
    url_env: REGISTRY_RELAY_DATABASE_URL

runtime:
  datasets:
    vital-events:
      entities:
        person:
          source: civil_registry
          table: people
          bindings:
            person_id: id
            birth_date: date_of_birth
            sex: sex_code
          capabilities:
            rows: true
            search: true
            aggregate: false
            verify: true
          visibility:
            metadata: public
            rows_scope: rows:read
          required_filters:
            - name: jurisdiction
              field: jurisdiction_code
```

Runtime bindings are allowed to mention:

- source ids
- tables
- columns
- file paths
- scopes
- capabilities
- required filters
- visibility rules
- query limits
- runtime route behavior

Runtime bindings must not redefine the semantic meaning of fields. If a field
is missing from compiled metadata, the runtime binding is invalid.

## Standard-Facing Surfaces

Use one canonical metadata surface list. Static publication and app-embedded
endpoints should expose the same artifacts where possible.

Metadata-only surfaces:

```http
GET /metadata
GET /metadata/catalog
GET /metadata/dcat
GET /metadata/dcat/{profile}
GET /metadata/shacl
GET /metadata/datasets
GET /metadata/datasets/{dataset}
GET /metadata/datasets/{dataset}/entities
GET /metadata/datasets/{dataset}/entities/{entity}
GET /metadata/datasets/{dataset}/entities/{entity}/schema
GET /metadata/datasets/{dataset}/entities/{entity}/shacl
GET /metadata/profiles
GET /metadata/profiles/{profile}
```

Runtime surfaces:

```http
GET /entities/{entity}/rows
GET /entities/{entity}/rows/{id}
GET /ogc/v1
GET /ogc/v1/collections
GET /ogc/v1/collections/{collectionId}/items
GET /ogc/v1/records
GET /ogc/v1/records/collections/{collectionId}/items
GET /openapi.json
```

Other Relay runtime and operational surfaces remain Relay-owned:

```http
GET /health
GET /contexts/*
GET /did/*
GET /admin/*
POST /entities/{entity}/verify
POST /entities/{entity}/claim/verify
GET /provenance/*
```

Rule:

```text
metadata endpoints describe meaning
runtime endpoints expose behavior
runtime rows are not OGC API Records records
```

Public Relay metadata endpoints are opt-in through runtime config. Static
publication is the default public publishing path. If a metadata response is
caller-scoped, Relay builds a scoped compiled metadata view before rendering it.

## Publication Model

Publishing metadata should be boring and web-native. Civil registration,
social protection, OpenIMIS, and similar systems should not need to run Registry
Relay or join a registry network to publish standard metadata.

### Static Publication

The default publishing model is generated static artifacts served from stable
URLs.

Example artifact layout:

```text
public/metadata/
  index.json
  metadata.yaml
  catalog.json
  dcat.jsonld
  dcat.dcat-ap.jsonld
  dcat.bregdcat-ap.jsonld
  shacl.jsonld
  schema/
    vital-events/
      person/
        schema.json
  profiles/
    example-civil-registration.json
    bregdcat-ap.json
```

Example URLs:

```http
GET /metadata/index.json
GET /metadata/metadata.yaml
GET /metadata/catalog.json
GET /metadata/dcat.jsonld
GET /metadata/dcat.bregdcat-ap.jsonld
GET /metadata/shacl.jsonld
GET /metadata/schema/vital-events/person/schema.json
GET /metadata/profiles/example-civil-registration.json
```

These files can be served by an existing application, static hosting, object
storage, GitHub Pages, nginx, or a documentation site.

### Discovery

Prefer discovery mechanisms that already fit the web:

- Add `Link: <https://example.gov/metadata/index.json>; rel="describedby"` on
  an application landing page or relevant API responses.
- Add an HTML `<link rel="describedby" href="/metadata/index.json">` on a
  landing page.
- Expose `/.well-known/api-catalog` for standards-facing API and metadata
  discovery.
- Optionally expose `/.well-known/dcat-catalog` as a compatibility alias for
  DCAT harvesters that look for that informal convention.

If a project-specific well-known URL is still needed, namespace it explicitly:

```http
GET /.well-known/registry-relay/v1
```

Do not use a generic `/.well-known/registry-metadata` path. It is invented and
not IANA-registered.

The metadata index is a small JSON document:

```json
{
  "schema_version": "registry-relay-metadata-index/v1",
  "manifest": "/metadata/metadata.yaml",
  "catalog": "/metadata/catalog.json",
  "dcat": "/metadata/dcat.jsonld",
  "dcat_profiles": [
    {
      "id": "bregdcat-ap",
      "version": "3.0.0",
      "url": "/metadata/dcat.bregdcat-ap.jsonld"
    }
  ],
  "shacl": "/metadata/shacl.jsonld",
  "schemas": [
    {
      "dataset": "vital-events",
      "entity": "person",
      "url": "/metadata/schema/vital-events/person/schema.json"
    }
  ],
  "profiles": [
    {
      "id": "example-civil-registration",
      "version": "1",
      "url": "/metadata/profiles/example-civil-registration.json"
    }
  ]
}
```

The index discovers metadata artifacts. It does not grant access, advertise
secrets, or describe backend source bindings.

### App-Embedded Metadata Endpoints

Applications may expose the canonical metadata endpoint list through read-only
routes instead of static files. These endpoints remain metadata-only surfaces.
They must not imply runtime row access.

### Catalog Harvesting

DCAT is the primary harvestable artifact for national data catalogs, SP DCI
registries, PublicSchema indexes, donor interoperability portals, and similar
systems.

Harvesters should be able to discover DCAT through `rel="describedby"`, the
metadata index, or `/.well-known/api-catalog`, then follow links to datasets,
distributions, schemas, SHACL shapes, profile claims, publisher metadata,
contact metadata, licensing, version information, and application-profile
outputs. `/.well-known/dcat-catalog` remains only a compatibility alias for
harvesters that already expect it.

### Relay Publication

Registry Relay may publish the same metadata through its `/metadata` endpoints,
and may add runtime-aware links for callers authorized to see them. Relay
publication is optional. Static publication remains the baseline path for
example civil registration app, example social benefits app, OpenIMIS, and other systems that only want to publish
metadata artifacts.

## Standards Boundary

### Owned By `registry-manifest-core`

- Catalog document model.
- DCAT JSON-LD rendering.
- DCAT application profile rendering, including BRegDCAT-AP.
- SHACL rendering.
- JSON Schema Draft 2020-12 rendering.
- Link-free OGC API Records record body rendering.
- External concept references.
- Profile claim slots.
- Codelist and relationship metadata.

### Owned By `registry-relay`

- OpenAPI documents with paths, security schemes, tags, and runtime operation
  visibility.
- OpenAPI DTOs or newtypes required because core must not depend on `utoipa`.
- OGC API Records HTTP routes, landing pages, conformance, collections,
  pagination, filtering, and links.
- OGC API Features item routes.
- Runtime auth and caller-specific visibility.
- Source-backed query behavior.
- Aggregate, verify, claim verification, and provenance execution.
- Cache, audit, observability, and redaction rules for runtime responses.

### Owned By `profiles/`

- Example civil registration profile descriptors.
- Example social benefits profile descriptors.
- Future OpenIMIS profile descriptors after official review.
- Example benefits sync profile descriptors and fixtures.
- Example person-schema profile descriptors and fixtures.
- Profile-specific generators.
- Profile-specific validation fixtures.

## Visibility Rules

Use three concepts:

- `public`: safe to expose without authentication.
- `authenticated`: visible to authenticated users.
- `scoped`: visible only when the caller has a configured scope.

Metadata visibility is not runtime row access.

An entity may be publicly described while its runtime rows require strict
authorization. Conversely, a runtime-bound entity may be hidden from public
metadata if its existence is sensitive.

Relay should expose two discovery modes:

- broad metadata discovery, for public or authenticated catalog use
- allowed metadata discovery, for caller-specific operational use

This mirrors the useful standard-facing part of X-Road's `listMethods` versus
`allowedMethods` distinction without copying its protocol.

## Validation

### Metadata Validation

`registry-manifest-core` validates:

- schema version
- required catalog fields
- application profile ids and versions
- dataset ids
- entity names
- field names
- field types
- field constraints
- codelist references
- codelist schemes and external references
- relationship target entities
- identifier definitions
- vocabulary prefixes
- compact IRI syntax
- `conforms_to` IRI syntax
- duplicate ids
- renderer preconditions

### Runtime Validation

`registry-relay` validates:

- metadata manifest exists and compiles
- runtime dataset ids exist in compiled metadata
- runtime entity names exist in compiled metadata
- every binding references a metadata field
- required filters reference bound fields or runtime-only filter definitions
- capabilities are compatible with the entity and source
- visibility scopes are known
- source configuration is complete
- secrets are referenced through environment variables or secret providers
- current demo, docs, fixtures, and tests no longer rely on mixed config fields

### Profile Validation

`profiles/` validators check:

- required concepts for the profile
- profile-specific field cardinality
- profile-specific identifier rules
- profile-specific codelists
- profile-specific generated output
- unsupported or lossy mappings are declared

## Error Codes

Core metadata errors:

- `metadata.manifest.file_not_found`
- `metadata.manifest.parse_failed`
- `metadata.manifest.version_unsupported`
- `metadata.manifest.validation_failed`

Runtime binding errors:

- `runtime.binding.dataset_missing`
- `runtime.binding.entity_missing`
- `runtime.binding.table_missing`
- `runtime.binding.field_missing`
- `runtime.binding.filter_missing`
- `runtime.binding.relationship_missing`

Profile errors:

- `profile.config.version_unsupported`
- `profile.validation.required_concept_missing`
- `profile.validation.cardinality_mismatch`
- `profile.validation.codelist_mismatch`
- `profile.validation.unsupported_mapping`
- `profile.generator.input_missing`
- `profile.generator.output_changed`

Error type decision:

- `registry-manifest-core` owns portable manifest validation.
- Relay maps core failures into stable `metadata.manifest.*` startup codes and
  owns `runtime.binding.*` validation plus runtime HTTP mappings.
- Profile validation errors stay outside core and use `profile.*`.
- Problem-details response mapping stays in Relay.

## Testing

Required checks:

- metadata-core unit tests
- renderer golden tests
- CLI validate and render tests
- Relay config loading tests
- runtime binding validation tests
- API tests for metadata routes
- API tests for OpenAPI route visibility
- API tests for OGC capability visibility
- negative tests for runtime leakage in metadata outputs
- profile validation fixture tests
- fixture conversion audit for `demo/`, `docs/`, `fixtures/`, and tests

Dependency checks:

- `registry-manifest-core` must not depend on Axum, DataFusion, Tokio Postgres,
  auth, audit, observability, source ingestion, `utoipa`, `clap`, Relay, or
  profiles.
- `registry-manifest-cli` may depend on `registry-manifest-core`.
- `registry-relay` may depend on `registry-manifest-core`.
- Relay tests may depend on `registry-manifest-core` as a dev dependency.
- Metadata-core tests must not depend on profiles.
- Profile validators may depend on `registry-manifest-core`.
- Profiles must not depend on `registry-relay`.

## Locked Decisions

- CLI lives in `registry-manifest-cli`, not metadata-core.
- Profiles start as a `profiles/` directory of data, fixtures, validators, and
  optional generators, not as a crate.
- Public Relay metadata endpoints are opt-in. Static publication is the default
  public path.
- Runtime entity data uses `rows` or `items`, not `records`.
- JSON Schema output targets Draft 2020-12.
- DCAT application profiles render as separate artifacts.
- Metadata-core renders link-free OGC API Records record bodies only.
- Relay owns all HTTP links, OpenAPI routes, OGC route behavior, auth, audit,
  observability, runtime config validation, and problem-details mapping.

Open questions that remain real:

- Which real ecosystem profile should be first after the hypothetical examples?
- Should BRegDCAT-AP be implemented before other DCAT profiles because the
  current code already emits parts of it?
- Which demo config should be the canonical fixture conversion target?

## Implementation Plan

Because there are no external users, implement the target architecture directly,
but do not pretend the renderers can be moved cleanly. Merge the first metadata
model and split-config work into one slice so there is no long-lived duplicate
source of truth.

### Phase 1: Core Projection And Split Demo Configs

- Add `crates/registry-manifest-core`.
- Add `crates/registry-manifest-cli`.
- Define `MetadataManifest`, `CompiledMetadata`, codelist schemes, field
  constraints, application profile claims, and renderer inputs.
- Add split `*.metadata.yaml` manifests for the demo runtime configs.
- Add the corresponding `metadata.manifest_path` bindings in the runtime YAMLs.
- Add a Relay adapter that builds compiled metadata from the split files.
- Port catalog and SHACL rendering through the compiled metadata view.
- Keep current config-to-renderer code only long enough to compare outputs.

Done when:

- metadata-core builds without runtime dependencies
- demo `*.metadata.yaml` manifests validate
- Relay boots from runtime YAML plus split metadata manifests
- golden catalog and SHACL fixtures match expected output
- runtime-only source, scope, filter, and binding fields stay out of the
  metadata manifests
- runtime binding errors distinguish metadata manifest failures from runtime
  binding failures

### Phase 2: Renderer Completion

- Implement DCAT base rendering.
- Implement BRegDCAT-AP as an application profile artifact.
- Implement JSON Schema Draft 2020-12 rendering.
- Implement link-free OGC API Records record body rendering.
- Replace project-private codelist predicates with SHACL/SKOS-compatible
  output where the manifest contains enough information.

Done when:

- golden fixtures exist for catalog, base DCAT, BRegDCAT-AP, SHACL, JSON Schema,
  and link-free OGC record bodies
- JSON Schema output includes `$schema`, `$id`, `type`, `properties`, and
  `required`
- BRegDCAT-AP output is selected by `catalog.application_profiles`
- golden fixtures still match after the Relay adapter is removed

### Phase 3: Runtime Surfaces

- Rewire `/metadata/*` outputs to use compiled metadata.
- Rewire `/openapi.json` to include only runtime-bound and visible operations.
- Rewire OGC routes to assemble runtime routes from metadata plus capabilities.
- Rename or clearly separate runtime row APIs from OGC Records terminology.
- Add tests proving source table names, source ids, internal columns, required
  filters, scopes, file paths, backend URLs, SQL, and secrets do not leak through
  public metadata outputs.

Done when:

- phase 1 and phase 2 golden fixtures still match
- runtime OpenAPI and OGC outputs are scoped by capabilities
- public metadata does not expose runtime bindings
- metadata visibility tests prove visibility does not grant runtime row access

### Phase 4: Static Publication And CLI

- Implement `registry-metadata validate`.
- Implement `registry-metadata render`.
- Implement local static publication to `public/metadata/`.
- Generate `metadata/index.json`.
- Support `rel="describedby"` documentation and `/.well-known/api-catalog`.
- Optionally support `/.well-known/dcat-catalog` as a compatibility alias.

Done when:

- CLI validates the demo manifest
- CLI renders all supported artifacts without starting Relay
- generated publication bundle contains no runtime-only fields
- all index links resolve within the bundle

### Phase 5: Profiles

- Add example civil registration and example social benefits profile
  descriptors first.
- Add real PublicSchema and SP DCI descriptors only after review with their
  canonical artifacts.
- Add one generated or hand-authored fixture per initial profile.
- Add profile validation command or test harness.

Done when:

- at least one non-Relay profile fixture validates through metadata-core
- profile validation can fail without making the base metadata manifest invalid
- profile fixture outputs are deterministic
- profile outputs declare unsupported or lossy mappings

## Recommended First Slice

Start with the smallest slice that proves phases 1 and 2 only:

1. Create `registry-manifest-core`.
2. Create `registry-manifest-cli` with minimal `validate`.
3. Define the portable manifest and compiled metadata types.
4. Add `*.metadata.yaml` manifests and runtime `metadata.manifest_path` bindings
   for the demo configs.
5. Adapt Relay to compile metadata from those files.
6. Render catalog and SHACL from compiled metadata.
7. Validate that runtime bindings reference metadata fields.
8. Add golden fixtures for catalog and SHACL.
9. Keep runtime-only source, scope, filter, aggregate, and adapter settings out
   of the metadata manifests after tests are converted.

This first slice is not the full plan. It intentionally excludes complete API
surface rewiring, static publication, and ecosystem profiles. It proves the
architecture before the rest of the worktree fans out.

## Worktree Implementation Wave Plan

Implement this split in a dedicated worktree, with small commits per wave and
expert workers assigned by package boundary. Workers can run in parallel inside
a wave, but the next wave should start only after the current wave's exit gate
is satisfied.

Because the current repository already has active OGC/API work, the worktree
should be created only after those changes are either committed or intentionally
carried forward. Do not reformat, revert, or clean up unrelated dirty files as
part of this split.

### Wave 0: Worktree, Baseline, And Move Map

Purpose:

- Establish the worktree.
- Capture the current behavior before moving code.
- Map what belongs to metadata-core, Relay, profiles, and the CLI.

Worker lanes:

- Workspace lane: create the worktree, confirm branch strategy, and record
  baseline command results.
- Inventory lane: map current metadata code under `src/metadata`, metadata
  routes under `src/api`, config loading, demo configs, and tests that assert
  catalog, SHACL, schema, OpenAPI, and OGC behavior.
- Coupling lane: document every current dependency from catalog and SHACL
  renderers to `Config`, `EntityRegistry`, Cargo features, and Relay modules.
- Fixture lane: count and locate mixed config fields in `demo/`, `docs/`,
  `fixtures/`, and tests.
- Boundary lane: identify metadata-safe fields versus runtime-only fields.
- Test lane: add or mark leakage tests that must pass by the end of the split.

Deliverables:

- Worktree branch for the split.
- Baseline report with passing and failing checks.
- Move map for modules, fixtures, and tests.
- Renderer coupling map.
- Fixture conversion inventory.
- Boundary checklist for metadata-safe and runtime-only concepts.

Verification:

- `cargo test`
- `cargo test --all-features`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo fmt --all -- --check`

Exit gate:

- Baseline command results are recorded, even if some fail before the split.
- The move map is clear enough that workers can edit separate files without
  stepping on each other.
- Dependency boundary rules are written down before new crates are created.
- In-flight OGC directory work is treated as current code.

Risks:

- Existing dirty work may already contain behavior needed by the split.
- Starting extraction before the renderer coupling is explicit will spread churn
  across all packages.

### Wave 1: Workspace Skeleton And Boundary Guards

Purpose:

- Create the package shape with as little behavior change as possible.
- Make dependency direction visible early.

Worker lanes:

- Cargo lane: convert the repository to a Cargo workspace.
- Relay package lane: move the existing Relay package into
  `crates/registry-relay` with the smallest path changes needed.
- Metadata package lane: add a minimal compiling
  `crates/registry-manifest-core`.
- CLI lane: add a minimal compiling `crates/registry-manifest-cli`.
- Profiles lane: add `profiles/` as data, not a crate.
- Dependency lane: keep runtime dependencies only in `registry-relay`.

Deliverables:

- Workspace `Cargo.toml`.
- Compiling `registry-relay` package.
- Minimal compiling `registry-manifest-core`.
- Minimal compiling `registry-manifest-cli`.
- `profiles/` directory with initial descriptor shape.
- Dependency guard for core.

Verification:

- `cargo metadata`
- `cargo check -p registry-relay`
- `cargo check -p registry-manifest-core`
- `cargo check -p registry-manifest-cli`
- `cargo fmt --all -- --check`
- `cargo tree -p registry-manifest-core`

Exit gate:

- `registry-relay` still builds.
- `registry-manifest-core` has no dependency on runtime, OpenAPI, CLI, Relay,
  or profile code.
- Package dependency direction is enforced.

Risks:

- Path churn can obscure behavior changes.
- Moving the package too aggressively can make review harder than the
  architecture itself.

### Wave 2: Core Projection Plus Split Demo Config

Purpose:

- Prove metadata-core with real split config.
- Avoid two long-lived sources of truth.

Worker lanes:

- Model lane: implement portable manifest, compiled metadata, codelists,
  constraints, application profile claims, and conformance slots.
- Config lane: create split metadata manifests for the demo runtime configs.
- Adapter lane: adapt Relay's runtime config and `EntityRegistry` state into
  compiled metadata while old renderers are still available for comparison.
- Validation lane: implement metadata manifest validation and runtime binding
  validation.
- Error lane: split core errors from Relay errors.
- Test lane: add catalog and SHACL golden tests from the split demo fixture.

Deliverables:

- `MetadataManifest`.
- `CompiledMetadata`.
- `registry_manifest_core::Error`.
- Split demo configs.
- Relay binding validation against compiled metadata.
- Golden fixtures for catalog and SHACL.

Verification:

- `cargo test -p registry-manifest-core`
- `cargo test -p registry-relay config`
- `cargo test -p registry-relay metadata`
- `cargo tree -p registry-manifest-core`

Exit gate:

- Metadata-core builds and tests without runtime dependencies.
- Relay boots from split config.
- Catalog and SHACL golden fixtures are deterministic.
- No metadata-core type carries source ids, table names, SQL, file paths,
  backend URLs, scopes, required filters, auth policy, or runtime route
  behavior.
- Runtime binding failures use `runtime.binding.*`.

Risks:

- Pulling runtime concepts into core because they are convenient for current
  Relay APIs.
- Leaving old mixed config as a hidden source of truth.

### Wave 3: Renderer Completion

Purpose:

- Finish the portable standard outputs before rewiring every runtime route.

Worker lanes:

- DCAT lane: implement base DCAT and BRegDCAT-AP profile outputs.
- SHACL lane: implement constraints, `sh:in`, codelist schemes, and external
  codelist references.
- JSON Schema lane: implement Draft 2020-12 schemas with stable `$id`.
- OGC metadata lane: implement link-free OGC API Records record bodies.
- Golden-test lane: add deterministic fixtures for every renderer.

Deliverables:

- Base `dcat.jsonld`.
- `dcat.bregdcat-ap.jsonld`.
- SHACL output without avoidable project-private codelist predicates.
- Draft 2020-12 JSON Schema output.
- Link-free OGC API Records bodies.

Verification:

- `cargo test -p registry-manifest-core`
- Renderer golden tests.
- `cargo run -p registry-manifest-cli -- validate demo/.../metadata.yaml`
- One CLI render check per supported format.

Exit gate:

- Golden fixtures match.
- JSON Schema includes `$schema`, `$id`, `type`, `properties`, and `required`.
- BRegDCAT-AP is selected through manifest application profiles.
- OGC record bodies contain no absolute runtime links.

Risks:

- Treating all DCAT application profiles as one output.
- Letting current ad-hoc schema envelopes masquerade as JSON Schema.

### Wave 4: Runtime Surfaces Rewired To Core

Purpose:

- Route all standards-facing metadata outputs through compiled metadata.
- Keep runtime API behavior owned by Relay.

Worker lanes:

- Metadata API lane: rewire the canonical `/metadata/*` endpoint list.
- OpenAPI lane: keep OpenAPI generation in Relay and filter operations by
  runtime capabilities and visibility.
- OGC lane: keep OGC HTTP route assembly, links, landing pages, conformance,
  pagination, and filtering in Relay.
- Runtime rows lane: rename or clearly separate runtime row APIs from OGC API
  Records terminology.
- Leakage lane: add negative tests proving runtime details do not appear in
  public metadata outputs.
- Utoipa lane: replace direct `ToSchema` coupling on core types with Relay DTOs
  or newtypes.

Deliverables:

- Metadata endpoints describe meaning only.
- Runtime endpoints expose behavior only through Relay.
- OpenAPI and OGC outputs remain runtime-aware and capability-scoped.
- Public metadata excludes source tables, source ids, internal columns, source
  URLs, scopes, required filters, secrets, SQL, and backend details.

Verification:

- `cargo test -p registry-relay metadata`
- `cargo test -p registry-relay openapi`
- `cargo test -p registry-relay ogc`
- `cargo test -p registry-relay --all-features`

Exit gate:

- Metadata route golden fixtures still match.
- Public metadata endpoints expose semantic meaning only.
- Caller-scoped metadata is rendered from a scoped compiled view.
- Runtime OpenAPI and OGC routes expose only authorized and capability-enabled
  operations.
- Metadata visibility tests prove visibility does not grant runtime row access.

Risks:

- OGC API Records has both link-free metadata and runtime HTTP behavior. Keep
  record bodies in core and all HTTP concerns in Relay.
- Runtime row terminology can drift back to ambiguous "records."

### Wave 5: Static Publication And CLI

Purpose:

- Let civil registration, social protection, and similar projects publish
  metadata without running Registry Relay.
- Keep publication static, boring, and web-native.

Worker lanes:

- CLI lane: finish `registry-metadata validate` and `render`.
- Publication lane: implement local artifact generation under
  `public/metadata/`.
- Discovery lane: generate `metadata/index.json`, document `rel="describedby"`,
  and support `/.well-known/api-catalog`.
- Standards lane: validate DCAT as the primary harvestable catalog artifact.
- Docs lane: document how applications can publish metadata without adopting
  Relay.

Deliverables:

- Static metadata artifact generator.
- Metadata index with manifest, catalog, DCAT, DCAT profile artifacts, SHACL,
  schemas, and profile links.
- Example publication bundle for a non-Relay deployment.
- Short publication guide for application maintainers.

Verification:

- Generated index links resolve within the bundle.
- Static bundle contains no runtime-only fields.
- A consumer can start from `metadata/index.json`, `/.well-known/api-catalog`,
  or a describedby link and discover DCAT, schemas, SHACL, and profile claims.
- DCAT JSON-LD validates with the existing SHACL workflow where applicable.

Exit gate:

- Static publication works from metadata-core artifacts without starting Relay.
- Example civil registration and example social benefits bundles can publish
  using only metadata tooling.
- Publication does not introduce remote federation, signing, certificate
  exchange, or a metadata control plane.

Risks:

- Treating publication as a network platform feature.
- Making artifact URLs, media types, or profile claims unclear for adopters.

### Wave 6: Profiles

Purpose:

- Make ecosystem adoption concrete without making core depend on ecosystem
  projects.
- Keep profile validation stricter than base metadata validation.

Worker lanes:

- Example civil registration lane: add profile descriptor, required concepts, codelists,
  identifiers, cardinality expectations, unsupported mappings, and one civil
  registration fixture.
- Example social benefits lane: add profile descriptor, required concepts, codelists,
  identifiers, cardinality expectations, unsupported mappings, and one social
  protection fixture.
- PublicSchema and SP DCI lane: add descriptors only after
  the examples prove the shape and official artifacts are reviewed.
- Validation lane: add profile conformance checks that can fail independently
  from core metadata validation.
- Golden-test lane: add deterministic profile fixture outputs.

Deliverables:

- `profiles/example-civil-registration/profile.yaml` plus fixtures.
- `profiles/example-social-benefits/profile.yaml` plus fixtures.
- Initial example person-schema and benefits-sync descriptors.
- `profile.*` errors for profile failures.

Verification:

- Profile validation fixture tests.
- `cargo test -p registry-manifest-core`
- Fixture and golden output checks.

Exit gate:

- At least one non-Relay profile fixture validates through metadata-core.
- Core-valid manifests can fail profile validation without failing base
  metadata validation.
- Profile outputs declare unsupported or lossy mappings.
- Profiles depend on metadata-core only.

Risks:

- Encoding application runtime behavior as metadata conformance.
- Claiming profile conformance when required concepts, codelists, identifiers,
  or cardinalities are incomplete.
- Turning profiles into a framework too early.

### Wave 7: Integration Gate And Cleanup

Purpose:

- Prove the split end to end.
- Remove stale mixed-config assumptions from docs and tests.

Worker lanes:

- Test lane: run focused API tests first, then full workspace checks.
- Dependency lane: enforce package dependency direction with `cargo tree` or a
  small dependency check script.
- Fixture lane: audit `demo/`, `docs/`, `fixtures/`, and tests for old mixed
  config fields.
- Docs lane: update README, demo, and development docs for final split commands
  and file layout.
- Standards lane: review artifact names, media types, profile claims, DCAT
  harvestability, BRegDCAT-AP output, SHACL, and JSON Schema consistency.
- Adoption lane: review example profiles from an adopter perspective.
- Review lane: self-review for leftover mixed config, runtime leakage, stale
  temporary notes, and unconverted tests.

Deliverables:

- Full split implemented with clean package boundaries.
- Migration note from mixed config to `metadata.yaml` plus `relay.yaml`.
- Adoption note showing example static publication paths.
- Remaining open questions reduced to rollout decisions only.

Verification:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- `cargo test --workspace`
- `cargo bench --no-run`, if benchmark surfaces or public APIs moved
- `cargo tree -p registry-manifest-core`
- `just validate-catalog-shacl catalog=<generated-dcat-or-catalog>`, if the
  command exists

Exit gate:

- No old mixed metadata/runtime config remains in converted fixtures.
- No runtime-only field appears in portable metadata.
- Runtime OpenAPI, OGC, aggregates, verify, claim verification, provenance,
  auth, audit, observability, cache, source, and admin behavior remain owned by
  Relay.
- Full test suite passes, or every skipped or failing check has a named blocker
  and exact command result.

Risks:

- Workspace-wide checks may reveal unrelated pre-existing failures. Record them
  separately from split regressions.
- Fixtures becoming demos only. They should be conformance assets that external
  projects can copy, publish, and validate.
