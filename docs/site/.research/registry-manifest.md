> **Status: historical research note**
>
> This note records pre-monorepo research and is not current architecture or release evidence. Use the published documentation and pinned source links for current claims.

# registry-manifest — evidence packet

**Last reviewed:** 2026-05-23  
**Repo path:** `../registry-manifest`  
**Reviewed against commit:** `77125ec04f50157749a257eab3661ef82e613ce3`

---

## What it is

Registry Manifest is a portable Rust workspace for modeling, validating, and rendering standards-facing registry metadata without running Registry Relay. It owns metadata manifests, compiled metadata models, validation, vocabulary prefix expansion, and pure renderers for catalog JSON, DCAT JSON-LD, BRegDCAT-AP JSON-LD, SHACL, JSON Schema Draft 2020-12, OGC API Records item bodies, policy documents, and evidence-offering metadata.

**Type:** Library + CLI (Rust workspace with two crates)  
**Language:** Rust  
**Main crate:** `registry-manifest-core` (pure library, zero external data deps); `registry-manifest-cli` (command-line tool consuming core)

---

## Manifest model

**Schema location:** Defined in Rust struct types, YAML serialization via serde_yml.  
**File:** `crates/registry-manifest-core/src/lib.rs`

**Top-level types:**

- `MetadataManifest` (line 19): Root struct with `schema_version: "registry-manifest/v1"`
- `CatalogManifest` (line 38): Catalog metadata
- `DatasetManifest` (line 112): Dataset definitions with entities, policies, evidence offerings
- `EntityManifest`: Structural schema with fields, identifiers, relationships
- `RequirementManifest`: CCCEV-style requirements
- `EvidenceTypeManifest`: Evidence type definitions
- `EvidenceOfferingManifest`: Evidence service offerings
- `DatasetPolicyManifest`: Dataset-scoped access policies
- `PolicyRuleManifest`, `PolicyDutyManifest`, `PolicyConstraintManifest`: ODRL policy terms
- `CodelistManifest`: Enumerated value schemes
- `StandardsManifest` (line 56): Declares dcat, shacl, json_schema versions in use

**Schema version constraint:** Manifest validation requires `schema_version == "registry-manifest/v1"` (line 856).

---

## Renderers actually implemented

All rendering functions exist in `crates/registry-manifest-core/src/lib.rs`:

| Target | Renderer | File:Line | Output Format |
|--------|----------|-----------|----------------|
| **catalog** | `render_catalog()` | lib.rs:1102 | JSON |
| **DCAT** | `render_base_dcat()` | lib.rs:1142 | JSON-LD (dcterms, dcat, skos contexts) |
| **BRegDCAT-AP** | `render_breg_dcat_ap()` | lib.rs:1165 | JSON-LD (+ dcatap, eli, cv contexts; line 1198: extends base DCAT) |
| **SHACL** | `render_shacl()` | lib.rs:1520 | JSON-LD (sh: http://www.w3.org/ns/shacl#) |
| **JSON Schema** | `render_entity_schema_draft_2020_12()` | lib.rs:1544 | JSON (schema draft 2020-12, line 12 constant) |
| **OGC API Records** | `render_ogc_records_items()` | lib.rs:1554 | JSON (OGC Records 1.0, line 1579) |
| **policies / ODRL** | `render_policy_collection()` | lib.rs:1212 | JSON-LD (odrl, dcterms contexts) |
| **policies (per-dataset)** | `render_dataset_policy_document()` | lib.rs:1225 | JSON-LD policy document |
| **evidence-offerings** | `render_evidence_offerings()` | lib.rs:1130 | JSON |
| **evidence-offering (single)** | `render_evidence_offering()` | lib.rs:1136 | JSON |

**DCAT profile variants** (line 1514-1515): `render_dcat_profile()` dispatches to base DCAT or BRegDCAT-AP by id string. Profile ids "dcat", "dcat-ap" render base; "bregdcat-ap" renders BRegDCAT.

**Not present:**
- GovStack DR BB renderer (not implemented)
- SP DCI renderer (not implemented)
- Separate PROV-O renderer (PROV concepts referenced but not as standalone render target)
- CCCEV renderer as standalone (CCCEV mapping present in requirements/evidence structure but rendered as part of policy documents)

---

## CLI surface

**File:** `crates/registry-manifest-cli/src/main.rs`

| Subcommand | Signature | Line | What it does |
|------------|-----------|------|--------------|
| `validate` | `validate <metadata.yaml>` | 27–32 | Load YAML, validate manifest schema and rules. Prints "metadata manifest valid: {path}" on success. |
| `render` | `render <metadata.yaml> --format <format> [--profile <id>] [--dataset <id>] [--entity <name>] [--offering <id>]` | 34, 45–95 | Compile manifest, dispatch to renderer by format string. Outputs JSON to stdout. |
| `publish` | `publish <metadata.yaml> --out <dir>` | 35, 97–221 | Compile manifest, render all artifacts (catalog, DCAT, DCAT profiles, BRegDCAT-AP, SHACL, JSON-Schema per entity, OGC Records, evidence offerings, policies), write to output tree, generate index.json manifest. |
| `validate-profiles` | `validate-profiles [profiles-dir]` | 36, 223–252 | Scan profiles/ for profile.yaml descriptors, validate schema version, profile id/version, required concepts, identifiers, cardinality, codelist expectations; validate all referenced fixture manifests. |
| `--help` / `-h` | (implicit) | 37 | Print usage string. |

**Supported render formats** (line 51–92 dispatch):
- `catalog` → catalog JSON
- `evidence-offerings` → all offerings JSON
- `evidence-offering` (+ `--offering <id>`) → single offering JSON
- `policies` → policy collection JSON-LD
- `policy` (+ `--dataset <id>`) → per-dataset policy document JSON-LD
- `dcat` (+ optional `--profile <id>`) → base DCAT or profile
- `bregdcat-ap` → BRegDCAT-AP JSON-LD
- `shacl` → SHACL JSON-LD
- `json-schema` (+ `--dataset <id> --entity <name>`) → Draft 2020-12 schema JSON
- `ogc-records` → OGC API Records items JSON

---

## Validation flow

**Entry point:** `pub fn validate_manifest()` (lib.rs:855)

**What it does:**
1. Checks schema_version == "registry-manifest/v1" (line 858), rejects otherwise
2. Collects validation errors across multiple passes:
   - Catalog: base_url (HTTP), title, publisher, application_profiles supported list
   - Requirements validation (line 3343): collect requirement ids, check reference integrity
   - Evidence types validation (line 3383): check proves links, type structure
   - Datasets: per-entity field/relationship/identifier validation
   - Codelists: id uniqueness, concept structure
   - Policies: ODRL term validity, cardinality constraints
   - Evidence offerings: reference checks
3. Returns `Result<(), MetadataError>` with detailed path+message errors (line 900)

**Dependencies:** 
- No external validation library (jsonschema, shacl)
- Custom in-code validators: `validate_http_url()`, `validate_uri()`, `validate_id()`, `validate_cardinality()`, `validate_policy_iri()`
- No SHACL runtime execution

**Validation performed on:**
- Manifest structure (schema version, required fields)
- URL/URI format (HTTP base_url, vocab IRIs)
- Identifier patterns (alphanumeric, dashes)
- Cardinality strings ("0..1", "1..n", "1..1")
- Codelist reference integrity
- Policy term conformance (valid ODRL actions, operators, constraints)
- Concept URI resolution (vocabulary prefix expansion)

---

## Fixtures and profiles

**Profiles directory:** `profiles/`

**Profile structure:** Each profile has `profile.yaml` (descriptor) + `fixtures/metadata.yaml` (test manifest)

**Example profiles:**
1. `profiles/example-civil-registration/` — Vital events, person identifiers, birth/death records
2. `profiles/example-social-benefits/` — Benefits enrollment, recipient data
3. `profiles/example-person-schema/` — Person schema mappings
4. `profiles/example-benefits-sync/` — Sync protocol and benefits data

**Profile descriptor schema version:** `registry-manifest-profile/v1` (line 293 in cli/main.rs)

**Fixture validation** (cli/main.rs:341–477): Validates that fixture manifests:
- Parse as valid YAML
- Satisfy manifest validation rules
- Claim the profile and version
- Contain all required concepts (IRIs), identifiers, codelists by id
- Meet cardinality expectations (min/max field counts)
- Do not contain runtime-only keys (line 520–535 list: bindings, capabilities, column, file_path, query, required_filters, rows_scope, scope, source, source_id, table, url, url_env, visibility)

---

## Output artifacts

**From `publish` command** (cli/main.rs:97–221), writes to `<out>/`:

| File | Format | Contents |
|------|--------|----------|
| `metadata.yaml` | YAML | Copy of input manifest |
| `catalog.json` | JSON | `render_catalog()` output |
| `dcat.jsonld` | JSON-LD | `render_base_dcat()` output |
| `dcat.{profile-id}.jsonld` | JSON-LD | Per application profile (e.g., `dcat.bregdcat-ap.jsonld`) |
| `shacl.jsonld` | JSON-LD | `render_shacl()` output |
| `evidence-offerings.json` | JSON | `render_evidence_offerings()` output |
| `evidence-offerings/{offering-id}.json` | JSON | Per offering |
| `policies.jsonld` | JSON-LD | `render_policy_collection()` output |
| `policies/{dataset-id}.jsonld` | JSON-LD | Per-dataset policy document |
| `schema/{dataset-id}/{entity-name}/schema.json` | JSON Schema | Draft 2020-12 for each entity |
| `profiles/{profile-id}.json` | JSON | Compiled profile structure |
| `index.json` | JSON | Manifest index with links to all artifacts |

**Index structure** (line 203–217): Schema version, paths to all artifacts, array of documents with urls.

---

## Standards referenced in code

Organized by token/namespace found in renderer code:

| Standard | File:Line Evidence | Claim Level | Notes |
|----------|-------------------|------------|-------|
| **DCAT v3** | lib.rs:17, 1142 (render_base_dcat), 3503 | **emits** | Renders `dcat:Catalog`, `dcat:Dataset`, `dcat:*` properties; uses EU data theme taxonomy (line 3506) |
| **DCAT-AP** | lib.rs:127 comment, 3780 (dcatap:applicableLegislation) | **aligns_with** | Maps dataset.applicable_legislation to dcatap:applicableLegislation IRIs |
| **BRegDCAT-AP** | lib.rs:1165, README line 5 | **emits** | Extends base DCAT; renders breg-specific context (dcatap, cv, eli namespaces) |
| **SHACL 1.1** | lib.rs:61 (StandardsManifest.shacl), 1520, 3713 (sh: http://www.w3.org/ns/shacl#) | **emits** | Renders shape graph with sh:NodeShape, sh:path, sh:datatype, sh:minCount, sh:maxCount |
| **JSON Schema Draft 2020-12** | lib.rs:12, 1544, README line 5 | **emits** | Constant JSON_SCHEMA_DRAFT_2020_12; renders $schema, type, properties, required, etc. |
| **OGC API Records 1.0** | lib.rs:1554–1579, 3641–3651 (ogc_records_conformance) | **emits** | Renders OGC Records items and collections; conformsTo list includes OGC Records 1.0 conf classes |
| **JSON-LD** | lib.rs:3706–3800 (jsonld_context functions) | **emits** | All DCAT, policy, public service outputs are JSON-LD with @context, @type, @id |
| **ODRL 2.0** | lib.rs:1212–1280 (render_policy_collection, render_dataset_policy), 3712, 3751–3765 | **emits** | Renders odrl:Policy, odrl:Rule, odrl:Constraint, odrl:Duty, odrl:action/target/assignee properties |
| **CCCEV (Core Criterion and Evaluation Evidence Vocabulary)** | lib.rs:RequirementManifest (line 186–202), evidence rendering | **maps_to** | Represents CCCEV evidence requirements; does not emit standalone CCCEV, but structure aligns with CCCEV core classes |
| **CPSV (Core Public Service Vocabulary)** | lib.rs:136–141 comment, 1285–1310 (public_services), 3502, 3769 | **emits** | Renders cpsv:PublicService nodes with cpsv:produces links to datasets; holdsRequirement references |
| **Dublin Core Terms (dcterms)** | lib.rs:3504, 3520–3535 | **emits** | Core metadata terms: dcterms:title, dcterms:identifier, dcterms:conformsTo, dcterms:accessRights, dcterms:accrualPeriodicity, etc. |
| **FOAF** | lib.rs:3711 | **emits** | JSON-LD context includes foaf prefix (http://xmlns.com/foaf/0.1/) for agent nodes |
| **ADMS (Asset Description Metadata Schema)** | lib.rs:135–136 comment, 3597–3601 (AdmsStatus), 3708 | **emits** | Renders adms:status IRIs for dataset lifecycle (UnderDevelopment, Active, Completed, Deprecated, Withdrawn) |
| **SKOS (Simple Knowledge Organization System)** | lib.rs:1325, 3714 | **emits** | Renders skos:ConceptScheme, skos:inScheme, skos:hasTopConcept for codelists |
| **ELI (European Legislation Identifier)** | lib.rs:1275, 3777 | **emits** | Includes eli: namespace for authority type and legislative references |
| **RDF/RDFS** | lib.rs:3743 | **references** | rdfs: namespace in JSON-LD context for seeAlso |
| **GovStack DR BB** | Not found | **not_present** | No render target or GovStack-specific mappings identified |
| **SP DCI** | README line 15, profiles/ notes | **compares_against** | Mentioned as potential profile source but not rendered; profiles are marked "non-normative until reviewed against official SP DCI" |

---

## Tests

**Notable tests in `crates/registry-manifest-core/tests/metadata_core.rs`:**

| Test Name | Line | What it proves |
|-----------|------|----------------|
| `as_needed_update_frequency_maps_to_eu_as_needed_iri()` | 11 | Update frequency vocabulary mapping to EU authority IRIs |
| `validates_profile_fixtures()` | 60 | All four example profiles (civil-reg, benefits, person-schema, benefits-sync) pass validation |
| `validation_reports_manifest_errors()` | 72 | Manifest validation catches base_url format, entity name patterns, missing codelists, unsupported profiles, bad cardinality strings |
| `validation_rejects_duplicate_entities()` | 115 | Dataset cannot contain duplicate entity names |
| `validation_rejects_duplicate_evidence_offering_ids_globally()` | 130 | Evidence offering ids must be unique across dataset |
| `breg_dcat_emits_standard_public_service_evidence_without_source_truth_claims()` | 801 | BRegDCAT-AP rendering includes CPSV public service nodes; does not claim source-of-truth |
| `policy_manifest_validates_and_renders_odrl_offer()` | 308 | ODRL policy structure validates and renders with correct action/constraint terms |
| `compile_expands_vocabularies_and_codelist_schemes()` | 635 | Vocabulary prefix expansion works; concept IRIs are expanded from shorthand |

**Golden fixtures** (crates/registry-manifest-core/tests/fixtures/golden/):
- `example-civil-registration.catalog.json` — Output of render_catalog()
- `example-civil-registration.base-dcat.json` — Output of render_base_dcat()
- `example-civil-registration.breg-dcat-ap.json` — Output of render_breg_dcat_ap()
- `example-civil-registration.shacl.json` — Output of render_shacl()
- `example-social-benefits.enrollment.schema.json` — Output of render_entity_schema_draft_2020_12()
- `example-benefits-sync.ogc-records-items.json` — Output of render_ogc_records_items()

Tests assert these golden outputs match render outputs exactly (cli test line 55–58).

---

## Explicit non-goals

From README (line 88–92):

> This repository must stay portable. `registry-manifest-core` must not depend on Registry Relay, Evidence Server, Axum, DataFusion, Postgres, auth, audit, observability, runtime row access, secret handling, `utoipa`, or `clap`.
> 
> Registry Relay may publish these artifacts over HTTP and scope them for callers, but those runtime concerns stay outside this repository.

**Boundary:** 
- No HTTP serving (Axum excluded)
- No database queries (Postgres, DataFusion excluded)
- No authentication/authorization scoping
- No audit logging or observability instrumentation
- No secret management
- Pure compilation and rendering only

---

## Gaps and TODOs

**Search result:** `rg "TODO|FIXME"` crates/registry-manifest-core/src/lib.rs returns zero matches.  
No in-code TODO/FIXME items found touching user-visible behavior.

---

## Naming and rename status

**Crate names:**
- `registry-manifest-core` (Cargo.toml package name)
- `registry-manifest-cli` (Cargo.toml package name)
- Workspace root refers to both

**Schema versions:**
- Manifest: `registry-manifest/v1` (enforced line 856)
- Profile descriptor: `registry-manifest-profile/v1` (cli/main.rs:293)
- Publish index: `schema_version: "registry-manifest-index/v1"` (cli/main.rs:204)

**Old/legacy labels:** None found. Repo is young; no renames or deprecations noted.

---

## End of packet

All claims verified against commit `77125ec04f50157749a257eab3661ef82e613ce3`.  
For questions on specifics, cite file:line from evidence above.
