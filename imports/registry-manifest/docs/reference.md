# Registry Manifest reference

Look up CLI subcommand flags, manifest key definitions, federation metadata, publish output paths, and the runtime-only key list.

## CLI subcommands

Source:
[`crates/registry-manifest-cli/src/main.rs`](https://github.com/jeremi/registry-manifest/blob/bb7bc6d015f519a9d1a6b6a0b661a2d28566af9d/crates/registry-manifest-cli/src/main.rs)

### `validate`

Parses and validates a manifest. Prints `"metadata manifest valid: <path>"` and the
canonical `source_manifest_digest` on success. Exits non-zero and prints all errors
on failure.

```text
validate <metadata.yaml>
```

### `render`

Compiles the manifest and writes one renderer's output to stdout.

```text
render <metadata.yaml> --format <format> [--profile <id>] [--dataset <id>] [--entity <name>] [--form <id>] [--offering <id>]
```

### `publish`

Compiles the manifest, runs all renderers, writes the full artifact tree to `<dir>`, and writes `index.json`.

```text
publish <metadata.yaml> --out <dir>
```

### `validate-profiles`

Scans `profiles-dir` for `profile.yaml` descriptors, validates descriptor schema, and validates all referenced fixture manifests.

```text
validate-profiles [profiles-dir]
```

### Render format values

The `--format` flag on `render` accepts:
Terms used in the table include Data Catalog Vocabulary (DCAT), BRegDCAT-AP, Core Public Service
Vocabulary Application Profile (CPSV-AP), Shapes Constraint Language (SHACL), Open Digital
Rights Language (ODRL), OGC API Records, and SKOS-shaped codelist metadata.

| Format value | Required flags | Output |
| --- | --- | --- |
| `catalog` | None | Catalog JSON |
| `evidence-offerings` | None | All evidence offerings JSON |
| `evidence-offering` | `--offering <id>` | Single evidence offering JSON |
| `policies` | None | ODRL policy collection JSON-LD |
| `policy` | `--dataset <id>` | Per-dataset ODRL policy document JSON-LD |
| `dcat` | `--profile <id>` optional | Base DCAT JSON-LD. With `--profile bregdcat-ap`, renders the BRegDCAT-AP variant. `--profile dcat` and `--profile dcat-ap` also render base DCAT. |
| `bregdcat-ap` | None | BRegDCAT-AP JSON-LD (shorthand; equivalent to `--format dcat --profile bregdcat-ap`) |
| `cpsv-ap` | None | CPSV-AP 3.2.0 service catalogue JSON-LD |
| `shacl` | None | SHACL node shapes JSON-LD |
| `json-schema` | `--dataset <id>` and `--entity <name>` | JSON Schema Draft 2020-12 |
| `form-json-schema` | `--form <id>` | Form JSON Schema Draft 2020-12 |
| `ogc-records` | None | OGC API Records FeatureCollection JSON |

Valid `--profile` values for `--format dcat`: `dcat`, `dcat-ap` (both render base DCAT), and `bregdcat-ap` (renders BRegDCAT-AP JSON-LD).
Use `--format cpsv-ap` for the service catalogue rather than `--format dcat --profile cpsv-ap`.

## Manifest top-level keys

Schema version enforced: `registry-manifest/v1`.
Source:
[`crates/registry-manifest-core/src/lib.rs`](https://github.com/jeremi/registry-manifest/blob/bb7bc6d015f519a9d1a6b6a0b661a2d28566af9d/crates/registry-manifest-core/src/lib.rs)
(`MetadataManifest` struct).

| Key | Type | Required | Description |
| --- | --- | --- | --- |
| `schema_version` | string | Yes | Must equal `"registry-manifest/v1"`. |
| `catalog` | `CatalogManifest` | Yes | Catalog title, publisher, base URL, application profiles list, standards versions. |
| `datasets` | list of `DatasetManifest` | Yes | One entry per dataset. |
| `vocabularies` | map | No | Prefix expansions used by concept, requirement, form, and evidence references. |
| `profiles` | list of `ProfileClaim` | No | Local profile claims included in catalog output. |
| `requirements` | list of `RequirementManifest` | No | CCCEV-aligned requirement definitions. |
| `evidence_types` | list of `EvidenceTypeManifest` | No | Evidence type definitions. |
| `authorities` | list of `AuthorityManifest` | No | Public authority records referenced by public services. |
| `public_services` | list of `ServiceManifest` | No | CPSV-AP public services and channels. |
| `data_services` | list of `DataServiceManifest` | No | DCAT data services referenced by services and evidence offerings. |
| `forms` | list of `FormManifest` | No | Local form-profile records linked from public services and channels. |
| `codelists` | list of `CodelistManifest` | No | Enumerated value schemes with concept URIs. |
| `federation` | `FederationManifest` | No | Public Registry Notary federation metadata for delegated evaluation. |
| `evaluation_profiles` | list of `EvaluationProfileManifest` | No | Public profile-to-ruleset bindings for Registry Notary delegated evaluation. |

### CatalogManifest keys

| Key | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string | Yes | Catalog identifier string. |
| `title` | `LocalizedText` | Yes | Human-readable catalog title. Plain string or `{en: "...", fr: "..."}` locale map. |
| `publisher` | `PublisherManifest` | Yes | Publisher record with `name` (string, required), `iri` (optional), and `authority_type` (optional). |
| `base_url` | string | Yes | HTTP URL used as the base for all relative artifact references. |
| `application_profiles` | list of `ApplicationProfile` | No | Profile IDs and versions the catalog declares support for (for example, `[{id: "bregdcat-ap", version: "3.0.0"}]`). |
| `standards` | `StandardsManifest` | No | Declares DCAT, SHACL, and JSON Schema versions in use. |

### DatasetManifest keys (common keys; see [source](https://github.com/jeremi/registry-manifest/blob/bb7bc6d015f519a9d1a6b6a0b661a2d28566af9d/crates/registry-manifest-core/src/lib.rs) for the full type definition)

| Key | Description |
| --- | --- |
| `id` | Dataset identifier string (alphanumeric and dashes). Must be unique. |
| `title` | Human-readable dataset title. |
| `entities` | List of `EntityManifest` entries describing domain resources and their fields. |
| `policies` | List of `DatasetPolicyManifest` entries describing ODRL access policies. |
| `evidence_offerings` | List of `EvidenceOfferingManifest` entries. |
| `public_services` | Dataset-scoped public registry services, when a dataset is itself the produced registry resource. |
| `codelists` | List of codelist IDs referenced by this dataset's fields. |

### CodelistManifest keys

| Key | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string | Yes | Codelist identifier. Must be unique within the manifest. |
| `scheme_iri` | string | Yes | Concept scheme IRI or CURIE. |
| `version` | string | No | Version marker for this codelist scheme. Rendered on generated codelist nodes when present. |
| `valid_from` | string | No | Start date or instant for this codelist version's validity window. Rendered on generated codelist nodes when present. |
| `valid_to` | string | No | End date or instant for this codelist version's validity window. Rendered on generated codelist nodes when present. |
| `external_ref` | string | No | Optional external codelist document IRI. |
| `concepts` | list of `CodelistConcept` | No | Code values and optional concept IRIs or labels. |

### Service-first keys

| Key | Description |
| --- | --- |
| `public_services[].holds_requirements` | Requirement IDs rendered as `cv:holdsRequirement`. |
| `public_services[].channels` | CPSV-AP channel records for online, office, phone, or other access paths. |
| `public_services[].forms` | Form IDs linked through the local `registry_manifest:hasForm` predicate. |
| `requirements[].evidence_type_lists` | Grouped CCCEV evidence options. All evidence types inside one list are required together; multiple lists are alternatives. |
| `forms[].sections[].fields[].concept` | Information concept IRI collected by the form field. |
| `forms[].sections[].fields[].supports_requirement` | Requirement ID supported by the field. |
| `forms[].sections[].fields[].fulfillment` | Manual input, file upload, registry lookup, evidence exchange, self-declaration, or already-known mode metadata. |

### Federation metadata keys

Registry Manifest federation metadata supports Registry Notary static-peer delegated evaluation.
It is public discovery metadata, not an access grant.

Fields of `FederationManifest`.

| Key | Required | Description |
| --- | --- | --- |
| `node_id` | Yes | Publishing Notary node id. MVP validation requires `did:web`. |
| `issuer` | Yes | HTTPS issuer URL. Host must bind to the `did:web` node id. |
| `jwks_uri` | Yes | HTTPS JWKS URL partners use to verify signed federation responses. |
| `federation_api` | Yes | HTTPS federation API base URL. |
| `supported_protocol_versions` | Yes | Must include `registry-notary-federation/v0.1`. |

Fields of `EvaluationProfileManifest`.

| Key | Required | Description |
| --- | --- | --- |
| `id` | Yes | Public profile id. Must be unique. |
| `ruleset` | Yes | Public ruleset id. Must be unique and referenced by `registry-notary` offerings. |
| `claim_id` | Yes | Notary claim id evaluated for the profile. |
| `subject_id_type` | Yes | Subject id type the profile accepts. |
| `max_source_observed_age_seconds` | No | Optional public freshness hint. Runtime enforcement is in Registry Notary config. |

For `EvidenceOfferingAccessManifest` with `kind: registry-notary`:

- `conforms_to` must be `registry-notary-federation/v0.1`.
- `endpoint_url` must be HTTPS.
- `discovery_url` must be HTTPS.
- `ruleset` must reference an existing `evaluation_profiles[].ruleset`.
- A top-level `federation` block is required.

### Runtime-only keys

The following keys must not appear in a portable manifest.
Their presence causes `validate`, `publish`, and `validate-profiles` to fail.
They belong in Registry Relay or Registry Notary runtime configuration, not in a metadata manifest.

`admin_bind`, `admin_listener`, `audit`, `auth`, `bind`, `bindings`, `capabilities`,
`column`, `config_trust`, `file_path`, `listener`, `listeners`, `peer_allowlist`,
`peers`, `private_jwk`, `private_jwk_env`, `query`, `replay`, `required_filters`,
`rows_scope`, `scope`, `secret_provider`, `secret_providers`, `signing_keys`,
`source`, `source_id`, `table`, `token_url`, `url`, `url_env`, `visibility`

Source:
[`crates/registry-manifest-core/src/lib.rs`](https://github.com/jeremi/registry-manifest/blob/bb7bc6d015f519a9d1a6b6a0b661a2d28566af9d/crates/registry-manifest-core/src/lib.rs)
(`RUNTIME_ONLY_KEYS`).

## Schema versions

The root version marker field is `schema_version`.
Source manifests, profile descriptors, and generated manifest-owned formats use explicit format IDs:

| Format | `schema_version` value |
| --- | --- |
| Metadata manifest | `registry-manifest/v1` |
| Profile descriptor | `registry-manifest-profile/v1` |
| Publish index | `registry-manifest-index/v1` |
| Catalog JSON | `registry-manifest-catalog/v1` |
| Evidence offerings collection JSON | `registry-manifest-evidence-offerings/v1` |
| Single evidence offering JSON | `registry-manifest-evidence-offering/v1` |
| ODRL policy collection JSON-LD | `registry-manifest-policy-collection/v1` |
| Single ODRL policy JSON-LD | `registry-manifest-policy/v1` |
| SHACL JSON-LD | `registry-manifest-shacl/v1` |
| Generated codelist node | `registry-manifest-codelist/v1` |
| Entity JSON Schema | `registry-manifest-entity-json-schema/v1` |
| Form JSON Schema | `registry-manifest-form-json-schema/v1` |
| OGC Records FeatureCollection JSON | `registry-manifest-ogc-records/v1` |

Codelist source definitions use `version` for the codelist scheme version and
`valid_from` / `valid_to` for the codelist validity window.
Manifest-owned JSON-LD maps these bare keys to stable Registry Manifest RDF terms:
`schema_version` -> `registry_manifest:schemaVersion`,
`version` -> `registry_manifest:version`,
`valid_from` -> `registry_manifest:validFrom`, and
`valid_to` -> `registry_manifest:validTo`.

### Extension policy

`registry-manifest/v1` and the manifest-owned `*/v1` generated formats make a
compatibility promise for additive evolution. A post-beta producer may add optional
fields to existing mapping objects without requiring a new major schema version.
Beta-era readers must ignore unrecognized fields while continuing to require and
validate the fields they understand. Unknown fields do not relax existing validation:
required fields, identifier syntax, URI syntax, reference integrity, collection limits,
and runtime-only key rejection still apply.

Readers must treat unrecognized fields as advisory extension data. A reader may expose
or preserve extension data when it has a typed extension model, but it must not fail
only because an otherwise valid manifest includes an unknown optional key such as a
future evidence offering `supported_modes`, `required_subject_binding`, `result_format`,
`disclosure_profile`, or `risk_tier`.

Breaking changes require a new schema version. Breaking changes include removing or
renaming required fields, changing the meaning of an existing field, changing an existing
field to an incompatible type, or making previously valid V1 manifests invalid except
for validation bugs, security fixes, or explicitly forbidden runtime-only keys.

## Publish output artifacts

Source:
[`crates/registry-manifest-cli/src/main.rs`](https://github.com/jeremi/registry-manifest/blob/bb7bc6d015f519a9d1a6b6a0b661a2d28566af9d/crates/registry-manifest-cli/src/main.rs)
(`publish_command`).

All paths are relative to the `--out` directory.

| Artifact path | Format | Source renderer | Version marker |
| --- | --- | --- | --- |
| `metadata.yaml` | YAML | Copy of input manifest | Root `schema_version` |
| `catalog.json` | JSON | `render_catalog()` | `schema_version: registry-manifest-catalog/v1` |
| `dcat.jsonld` | JSON-LD | `render_base_dcat()` | Standards profile output |
| `cpsv-ap` | JSON-LD | `render_cpsv_ap()` when the catalog declares the `cpsv-ap` profile | Standards profile output |
| `cpsv-ap.jsonld` | JSON-LD | `render_cpsv_ap()` when the catalog declares the `cpsv-ap` profile | Standards profile output |
| `dcat.<profile-id>.jsonld` | JSON-LD | `render_dcat_profile()` per application profile | Standards profile output |
| `shacl.jsonld` | JSON-LD | `render_shacl()` | `schema_version: registry-manifest-shacl/v1` |
| `evidence-offerings.json` | JSON | `render_evidence_offerings()` | `schema_version: registry-manifest-evidence-offerings/v1` |
| `evidence-offerings/<offering-id>.json` | JSON | `render_evidence_offering()` per offering | `schema_version: registry-manifest-evidence-offering/v1` |
| `policies.jsonld` | JSON-LD | `render_policy_collection()` | `schema_version: registry-manifest-policy-collection/v1` |
| `policies/<dataset-id>.jsonld` | JSON-LD | `render_dataset_policy_document()` per dataset | `schema_version: registry-manifest-policy/v1` |
| `schema/<dataset-id>/<entity-name>/schema.json` | JSON Schema Draft 2020-12 | `render_entity_schema_draft_2020_12()` per entity | `schema_version: registry-manifest-entity-json-schema/v1` |
| `forms/<form-id>/schema.json` | JSON Schema Draft 2020-12 | `render_form_schema_draft_2020_12()` per form | `schema_version: registry-manifest-form-json-schema/v1` |
| `ogc-records/items.json` | GeoJSON FeatureCollection | `render_ogc_records_items()` | `schema_version: registry-manifest-ogc-records/v1` |
| `profiles/<profile-id>.json` | JSON | Compiled profile structure | Profile descriptor `schema_version` |
| `index.json` | JSON | Bundle manifest index | `schema_version: registry-manifest-index/v1` |

The `index.json` structure contains the schema version, digest metadata, top-level
artifact URLs, and arrays for per-profile, per-schema, per-policy, and per-offering
documents.
Source:
[`crates/registry-manifest-cli/src/main.rs`](https://github.com/jeremi/registry-manifest/blob/bb7bc6d015f519a9d1a6b6a0b661a2d28566af9d/crates/registry-manifest-cli/src/main.rs)

Digest fields use `sha256:<hex>` values:

- `source_manifest_digest`: canonical digest of the typed `metadata.yaml` manifest after
  parsing. YAML comments, formatting, and mapping order do not affect this digest, but
  semantic manifest changes do.
- `package_digest`: canonical digest of the published package inventory. It covers the
  `source_manifest_digest` plus the sorted `artifacts` entries.
- `artifacts[].sha256`: content digest for each published metadata artifact listed in
  `artifacts`.

The `artifacts` inventory uses paths relative to `--out`, records each artifact's media type,
and excludes `index.json` because it contains the package digest. Discovery documents under
`.well-known/` are also excluded because they may be written under a separate `--site-root`
while still pointing at the same `/metadata/index.json` entry point.

Publish bundles follow the same additive compatibility rule. A future producer may add
new artifact files, new typed index links, and new `artifacts[]` entries without breaking
beta-era readers. Readers must consume the artifact paths and index links they understand
and ignore unknown top-level index members or artifact metadata members. The
`package_digest` covers the complete sorted `artifacts` inventory, so adding an artifact
intentionally changes the package digest. Artifacts that describe the bundle digest, such
as a future `provenance.jsonld`, must avoid a circular digest dependency by either
describing the source manifest digest, describing a separately defined pre-provenance
inventory, or being excluded by an explicitly versioned future digest rule.

Minimal example shape:

```json
{
  "schema_version": "registry-manifest-index/v1",
  "source_manifest_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "package_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  "artifacts": [
    {
      "path": "metadata.yaml",
      "media_type": "application/yaml",
      "sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    },
    {
      "path": "catalog.json",
      "media_type": "application/json",
      "sha256": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    }
  ],
  "manifest": "/metadata/metadata.yaml",
  "catalog": "/metadata/catalog.json",
  "evidence_offerings": "/metadata/evidence-offerings.json",
  "evidence_offering_documents": [],
  "policies": "/metadata/policies.jsonld",
  "policy_documents": [],
  "dcat": "/metadata/dcat.jsonld",
  "dcat_profiles": [],
  "service_catalogues": [
    {
      "id": "cpsv-ap",
      "version": "3.2.0",
      "url": "/metadata/cpsv-ap.jsonld",
      "aliases": ["/metadata/cpsv-ap"],
      "media_type": "application/ld+json"
    }
  ],
  "shacl": "/metadata/shacl.jsonld",
  "schemas": [],
  "form_schemas": [
    {
      "form": "child-support-review-form",
      "url": "/metadata/forms/child-support-review-form/schema.json"
    }
  ],
  "profiles": [],
  "application_profiles": [
    {
      "id": "cpsv-ap",
      "version": "3.2.0"
    }
  ]
}
```

## Golden fixture coverage

The test suite in
[`crates/registry-manifest-core/tests/metadata_core.rs`](https://github.com/jeremi/registry-manifest/blob/bb7bc6d015f519a9d1a6b6a0b661a2d28566af9d/crates/registry-manifest-core/tests/metadata_core.rs)
asserts exact output for the following renderer and profile combinations.
These golden files live under `crates/registry-manifest-core/tests/fixtures/golden/`.

| Golden file | Renderer | Profile |
| --- | --- | --- |
| `example-civil-registration.catalog.json` | `render_catalog()` | `example-civil-registration` |
| `example-civil-registration.base-dcat.json` | `render_base_dcat()` | `example-civil-registration` |
| `example-civil-registration.breg-dcat-ap.json` | `render_breg_dcat_ap()` | `example-civil-registration` |
| `example-civil-registration.shacl.json` | `render_shacl()` | `example-civil-registration` |
| `example-social-benefits.enrollment.schema.json` | `render_entity_schema_draft_2020_12()` | `example-social-benefits` |
| `example-benefits-sync.ogc-records-items.json` | `render_ogc_records_items()` | `example-benefits-sync` |
