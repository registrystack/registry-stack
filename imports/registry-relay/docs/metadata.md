# Portable Metadata

Registry Relay separates portable metadata from runtime configuration.

Portable metadata describes what a registry means: catalogs, datasets, entities,
fields, identifiers, relationships, vocabularies, codelists, standards, and
application-profile claims. Runtime configuration describes how Relay serves the
data: files, tables, columns, scopes, filters, aggregates, adapters, reloads,
and operational limits.

The split has two goals:

- Let a civil registration application, social benefits application, or similar
  registry system publish standards-friendly metadata without running Registry
  Relay.
- Let Registry Relay validate at startup that its runtime bindings still match
  the public metadata it exposes.

## Files

A runtime config may point at a metadata manifest:

```yaml
metadata:
  manifest_path: ./benefits_casework.metadata.yaml
```

Relative paths are resolved from the runtime config file, not the shell's current
directory. The demo configs use this convention:

```text
demo/config/benefits_casework.yaml
demo/config/benefits_casework.metadata.yaml
```

The runtime YAML keeps operational bindings:

- source paths, table ids, schemas, and physical columns
- API keys, scopes, and access policy
- allowed filters, required filters, limits, and expansions
- aggregates, claim verification, SP DCI, OGC Features, ingest, and refresh

The metadata manifest keeps standard-facing semantics:

- catalog id, base URL, publisher, standards, and application profiles
- dataset title, description, status, access rights, conformance, and coverage
- entity names, titles, identifiers, fields, relationships, concepts, and units
- SHACL constraints, JSON Schema constraints, codelists, and vocabularies
- profile claims for ecosystem-specific validation

Metadata manifests must not contain runtime-only details such as source paths,
table ids, physical columns, auth scopes, backend URLs, or SQL.

## Minimal Manifest

```yaml
schema_version: registry-metadata/v1

catalog:
  id: example-civil-registration-demo
  base_url: https://metadata.example.gov
  title: Example Civil Registration Metadata
  publisher:
    name: Civil Registration Authority
  standards:
    dcat: "3.0"
    shacl: "1.1"
    json_schema: "2020-12"
  application_profiles:
    - id: bregdcat-ap
      version: "3.0"

vocabularies:
  ex: https://example.gov/vocab/

datasets:
  - id: vital_events
    title: Vital Events
    description: Civil registration event metadata
    owner: Civil Registration Authority
    access_rights: restricted
    sensitivity: personal
    entities:
      - name: birth_registration
        title: Birth Registration
        identifiers:
          - name: id
            kind: primary
        fields:
          - name: id
            type: string
            required: true
          - name: date_of_birth
            type: date
            required: true
          - name: sex
            type: code
            codelist: sex

codelists:
  - id: sex
    scheme_iri: ex:codelists/sex
    concepts:
      - code: female
      - code: male
      - code: unknown
```

## Validation

Validate one manifest:

```sh
just metadata-validate profiles/example-civil-registration/fixtures/metadata.yaml
```

Validate the profile fixtures:

```sh
just metadata-validate-profiles
```

Validate all demo split configs:

```sh
cargo test --test demo_configs_load
```

Startup distinguishes two classes of split failures:

| Code | Meaning |
| --- | --- |
| `metadata.manifest.file_not_found` | The configured manifest cannot be read |
| `metadata.manifest.parse_failed` | YAML did not deserialize |
| `metadata.manifest.version_unsupported` | `schema_version` is not supported |
| `metadata.manifest.validation_failed` | Manifest failed semantic validation |
| `runtime.binding.dataset_missing` | Runtime dataset is absent from metadata |
| `runtime.binding.entity_missing` | Runtime entity is absent from metadata |
| `runtime.binding.table_missing` | Runtime entity points at an unknown runtime table |
| `runtime.binding.field_missing` | Runtime field or claim binding is absent from metadata |
| `runtime.binding.filter_missing` | Runtime filter binding is absent from metadata |
| `runtime.binding.relationship_missing` | Runtime relationship binding is absent from metadata |

## Rendering

Render individual artifacts:

```sh
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml catalog target/metadata/catalog.json
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml dcat target/metadata/dcat.jsonld
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml shacl target/metadata/shacl.jsonld
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml json-schema target/metadata/person.schema.json "--dataset vital-events --entity person"
```

Supported formats are:

- `catalog`
- `dcat`
- `bregdcat-ap`
- `shacl`
- `json-schema`
- `ogc-records`

`json-schema` renders Draft 2020-12 schemas. OGC Records rendering produces
link-free record bodies; Relay injects runtime HTTP links when serving the OGC
API Records surface.

## Static Publication

Publish a static bundle:

```sh
just metadata-publish profiles/example-social-benefits/fixtures/metadata.yaml target/metadata/example-social-benefits
```

The bundle contains:

```text
index.json
metadata.yaml
catalog.json
dcat.jsonld
dcat.<profile>.jsonld
shacl.jsonld
schema/<dataset>/<entity>/schema.json
profiles/<profile>.json
```

The `index.json` file is the discovery entry point. A project can serve the
bundle under `/metadata/`, link to `/metadata/index.json` with
`rel="describedby"`, or expose `/.well-known/dcat-catalog` when a harvester
expects that path.

Do not use a custom well-known path for this project. The portable route is
ordinary static web publishing plus standard links.

## Relay Endpoints

When Relay loads a split manifest, authenticated callers can access scoped
metadata through:

```text
GET /metadata
GET /metadata/catalog
GET /metadata/dcat
GET /metadata/dcat/{profile}
GET /metadata/shacl
GET /metadata/profiles
GET /metadata/profiles/{profile}
GET /metadata/datasets
GET /metadata/datasets/{dataset_id}
GET /metadata/datasets/{dataset_id}/entities
GET /metadata/datasets/{dataset_id}/entities/{entity}
GET /metadata/datasets/{dataset_id}/entities/{entity}/schema
GET /metadata/datasets/{dataset_id}/entities/{entity}/shacl
GET /metadata/schema/{dataset_id}/{entity}/schema.json
GET /metadata/ogc/records
GET /metadata/ogc/records/{record_id}
```

These routes use the caller's `metadata` scopes. They do not grant row access,
verify access, aggregate access, claim-verification access, or admin access.

The older `/catalog`, `/catalog/dcat-ap.jsonld`, `/datasets`, and runtime
entity routes remain operational discovery surfaces for Relay clients. Portable
metadata consumers should use `/metadata/*` or static publication.

## Profiles

The `profiles/` directory contains non-normative data descriptors and fixtures
for consumers of the portable model. The app profiles are hypothetical examples,
not OpenCRVS, OpenSPP, or other upstream conformance claims:

- `profiles/example-civil-registration`
- `profiles/example-social-benefits`
- `profiles/example-person-schema`
- `profiles/example-benefits-sync`

Profiles are data first, not Rust crates. Promote one only when there are
multiple generators or validators that need shared code.

## Boundary Rules

- Keep metadata portable and standards-oriented.
- Keep runtime config operational and deployment-specific.
- Expand compact IRIs syntactically from the manifest's `vocabularies`; do not
  dereference vocabularies during rendering.
- Use application profiles explicitly. Base DCAT and BRegDCAT-AP are separate
  artifacts, not a single generic DCAT output.
- Use OGC Records only for catalog records. Runtime entity rows are rows or
  items, not records.
