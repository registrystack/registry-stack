# Registry Manifest reference

Look up CLI subcommand flags, manifest key definitions, evidence and evaluation metadata, publish output paths, and the runtime-only key list.

## CLI subcommands

Source:
[`crates/registry-manifest-cli/src/main.rs`](../../../crates/registry-manifest-cli/src/main.rs)

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
publish <metadata.yaml> --out <dir> [--site-root <dir>]
```

`--site-root` is optional. When set, the two `.well-known/*` discovery documents are written
under `--site-root` instead of `--out`; every other artifact still writes under `--out`. See
[Publish output artifacts](#publish-output-artifacts).

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
[`crates/registry-manifest-core/src/lib.rs`](../../../crates/registry-manifest-core/src/lib.rs)
(`MetadataManifest` struct).

| Key | Type | Required | Description |
| --- | --- | --- | --- |
| `schema_version` | string | Yes | Must equal `"registry-manifest/v1"`. |
| `catalog` | `CatalogManifest` | Yes | Catalog title, publisher, base URL, application profiles list, standards versions. |
| `datasets` | list of `DatasetManifest` | No | One entry per dataset. |
| `vocabularies` | map | No | Prefix expansions used by concept, requirement, form, and evidence references. |
| `profiles` | list of `ProfileClaim` | No | Local profile claims included in catalog output. |
| `requirements` | list of `RequirementManifest` | No | CCCEV-aligned requirement definitions. |
| `evidence_types` | list of `EvidenceTypeManifest` | No | Evidence type definitions. |
| `authorities` | list of `AuthorityManifest` | No | Public authority records referenced by public services. |
| `public_services` | list of `ServiceManifest` | No | CPSV-AP public services and channels. |
| `data_services` | list of `DataServiceManifest` | No | DCAT data services referenced by services and evidence offerings. |
| `distributions` | list of `DistributionManifest` | No | Concrete deliveries or representations, each belonging to exactly one dataset. Empty and absent collections are canonically equivalent. |
| `forms` | list of `FormManifest` | No | Local form-profile records linked from public services and channels. |
| `codelists` | list of `CodelistManifest` | No | Enumerated value schemes with concept URIs. |
| `evaluation_profiles` | list of `EvaluationProfileManifest` | No | Public profile-to-ruleset bindings for delegated evaluation. |
| `ecosystem_bindings` | list of `EcosystemBindingManifest` | No | Ecosystem-specific integration bindings, such as governed-evidence gateway metadata. See [Ecosystem binding keys](#ecosystem-binding-keys). |

### CatalogManifest keys

| Key | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string | Yes | Catalog identifier string. |
| `title` | `LocalizedText` | Yes | Human-readable catalog title. Plain string or `{en: "...", fr: "..."}` locale map. |
| `description` | `LocalizedText` | No | Human-readable catalog description. Same shape as `title`. |
| `publisher` | `PublisherManifest` | Yes | Publisher record with `name` (string, required), `iri` (optional), and `authority_type` (optional). |
| `base_url` | string | Yes | HTTP URL used as the base for all relative artifact references. |
| `participant_id` | string | No | Federation participant identifier. Defaults to `base_url` when omitted. Rendered in catalog JSON. |
| `conforms_to` | list of string | No | Conformance URIs, expanded through `vocabularies`. Rendered as `dcterms:conformsTo` in DCAT output and as `conforms_to` in catalog JSON. |
| `application_profiles` | list of `ApplicationProfile` | No | Profile IDs and versions the catalog declares support for (for example, `[{id: "bregdcat-ap", version: "3.0.0"}]`). |
| `standards` | `StandardsManifest` | No | Declares DCAT, SHACL, and JSON Schema versions in use. |

### DatasetManifest keys (common keys; see [source](../../../crates/registry-manifest-core/src/lib.rs) for the full type definition)

| Key | Description |
| --- | --- |
| `id` | Dataset identifier string (alphanumeric and dashes). Must be unique. |
| `iri` | Optional canonical dataset IRI. When absent, the existing fragment identity `#dataset-<id>` is retained. |
| `version` | Optional deliberate dataset release version. It is independent of records, schemas, and package activation. |
| `title` | Human-readable dataset title. |
| `entities` | List of `EntityManifest` entries describing domain resources and their fields. |
| `policies` | List of `DatasetPolicyManifest` entries describing ODRL access policies. |
| `evidence_offerings` | List of `EvidenceOfferingManifest` entries. |
| `public_services` | Dataset-scoped public registry services, when a dataset is itself the produced registry resource. |
| `codelists` | List of codelist IDs referenced by this dataset's fields. |

### Semantic concept keys

| Key | Type | Required | Description |
| --- | --- | --- | --- |
| `datasets[].entities[].concept_uri` | IRI or configured CURIE | No | Class concept for the entity. Rendered as the node shape `sh:targetClass` and as `concept_uri` in catalog JSON. |
| `datasets[].entities[].fields[].concepts` | ordered list of IRI or configured CURIE | No | Semantic concepts the field carries. See [Ordering and authority of `fields[].concepts`](#ordering-and-authority-of-fieldsconcepts). |
| `datasets[].entities[].relationships[].concept_uri` | IRI or configured CURIE | No | Property concept for the relationship. Rendered as the relationship property shape `sh:path`. |

#### Ordering and authority of `fields[].concepts`

`fields[].concepts` is an ordered list and the order is part of the published
contract:

- The **first entry is the generated property identifier** for the field. SHACL
  renders it as the property shape `sh:path`, and the entity JSON Schema renders
  it as `x-concept-uri`.
- **Every entry is preserved in author order** in catalog JSON under
  `datasets[].entities[].fields[].concepts`. Entries after the first are
  additional references. They change no generated identifier.
- **An empty list falls back to a deterministic manifest URI**,
  `<base_url>/metadata/datasets/<dataset>/entities/<entity>/fields/<field>`. The
  entity JSON Schema then omits `x-concept-uri`, and catalog JSON reports an
  empty `concepts` list rather than the fallback.

Reordering the list moves the generated property identifier and changes SHACL
and JSON Schema output. Appending a concept does not. Treat a reorder as a
breaking metadata change and an append as an additive one.

#### What a concept reference does not do

A concept IRI describes the meaning of published metadata. It carries no
authority of its own.

- **It asserts no relation between concepts.** Listing several concepts on one
  field records several independent vocabulary references. Registry Manifest
  renders no `skos:exactMatch`, `skos:closeMatch`, `owl:sameAs`, or other
  mapping predicate between them, and the first entry has no precedence over the
  rest beyond supplying the generated property identifier. Where two vocabulary
  terms are equivalent, that claim belongs to the vocabularies that publish it,
  not to the manifest that references both.
- **It grants no access and triggers no safeguard.** Concepts do not activate
  Registry Relay authorization, redaction, filtering, purpose handling, or
  privacy classification, and no Registry Stack service changes its disclosure
  decisions because a field names a particular concept. `concepts` is not a
  classification field.
- **It is not validated against the vocabulary it names.** Validation checks
  that each entry is a well-formed `http`/`https` IRI, a `urn:`/`did:` IRI, or a
  CURIE whose prefix is declared in `vocabularies` or built in. It does not check
  that the term exists, that its domain matches the entity, or that its range
  matches the field type.
- **It is never resolved.** Vocabulary prefix expansion concatenates the
  declared namespace with the suffix and checks the result is a well-formed IRI.
  Nothing is fetched, dereferenced, or reasoned over at validate, compile,
  render, or publish time, so a manifest validates and renders identically
  offline.

#### Multi-vocabulary example

[`products/manifest/fixtures/semantic-concepts/aligned-person-concepts.metadata.yaml`](../fixtures/semantic-concepts/aligned-person-concepts.metadata.yaml)
is a non-normative example that binds one `birth_date` field to a PublicSchema
term and to an EU SEMIC Core Person Vocabulary term:

```yaml
- name: birth_date
  type: date
  concepts:
    - https://publicschema.org/date_of_birth
    - http://data.europa.eu/m8g/birthDate
```

That renders one property shape with `sh:path` set to
`https://publicschema.org/date_of_birth`, and catalog JSON publishes both IRIs
in that order. No equivalence between the two terms is rendered or implied.

The example also carries a field with no concept and a field with one concept,
so it shows all three generated outcomes in one manifest.

Vocabulary references in that example were checked on 2026-09-06:

- PublicSchema publishes `https://publicschema.org/manifest.json`, which reports
  version `0.3.0` with maturity `draft` and base URI `https://publicschema.org/`.
  Terms are rooted directly at that base URI, so `https://publicschema.org/Person`
  and `https://publicschema.org/date_of_birth` are the canonical forms. The
  vocabulary publishes no stable release tag, so the example is pinned to that
  draft snapshot and is non-normative.
- The EU SEMIC Core Person Vocabulary 2.00, published 2022-04-01, defines
  `http://www.w3.org/ns/person#Person` and `http://data.europa.eu/m8g/birthDate`.

Registry Manifest makes no PublicSchema or SEMIC conformance claim on behalf of
a manifest that references their terms.

### DistributionManifest keys

| Key | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string | Yes | Unique distribution identifier. |
| `dataset` | string | Yes | Exactly one existing dataset id. |
| `access_service` | string | No | Existing data-service id. The service must include the distribution dataset in `serves_datasets`. |
| `access_url` | HTTP(S) URL | No | Access location for the distribution. |
| `download_url` | HTTP(S) URL | No | Direct download location for the distribution. |
| `media_type` | string | No | IANA `type/subtype` value without parameters, rendered as its IANA media-type IRI. |
| `format` | IRI or configured CURIE | No | Distribution format identifier rendered as `dcterms:format`. |
| `title` | `LocalizedText` | No | Human-readable title. |
| `description` | `LocalizedText` | No | Human-readable description. |
| `iri` | IRI or configured CURIE | No | Canonical distribution IRI. A deterministic metadata IRI is derived when absent. |

A distribution must declare at least one of `access_service`, `access_url`, or
`download_url`.

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

Every `data_services[]` entry requires a non-empty `serves_datasets` list of
existing dataset ids. Filtered metadata removes hidden dataset memberships,
hidden-only data services, and public-service relationships to either.

### Evidence offering access keys

An evidence offering's `access` block is public discovery metadata, not an access grant. The
`kind` vocabulary is open: a manifest may name any access kind, and the runtime that consumes
the manifest decides which kinds it can serve. Registry Manifest checks the endpoint shape of
one kind, `registry-evidence`, because that kind names a service whose shape this repository
defines.

Fields of `EvaluationProfileManifest`.

| Key | Required | Description |
| --- | --- | --- |
| `id` | Yes | Public profile id. Must be unique. |
| `ruleset` | Yes | Public ruleset id. Must be unique and referenced by `registry-evidence` offerings. |
| `claim_id` | Yes | Public claim id evaluated for the profile. |
| `subject_id_type` | Yes | Subject id type the profile accepts. |
| `max_source_observed_age_seconds` | No | Optional public freshness hint. Runtime enforcement belongs to the service that answers the offering, not to the manifest. |
| `evidence_pack` | No | Optional `EvidencePackMetadata` object. Shares its shape with `ecosystem_bindings[].evidence_pack`. See [Ecosystem binding keys](#ecosystem-binding-keys). |

For `EvidenceOfferingAccessManifest` with `kind: registry-evidence`:

- `conforms_to` must be present and non-blank. It names the response profile the endpoint
  returns, for example `registry.assertion-evidence/v1`. The manifest layer does not pin a
  particular profile version, so it is not required to be a URI.
- `endpoint_url` is required and must be HTTPS.
- `discovery_url` is required and must be HTTPS. It points at the document a relying party
  reads to verify what the endpoint returns, for example an issuer JWKS.
- `ruleset`, when set, must reference an existing `evaluation_profiles[].ruleset`.

For every other `kind`, `conforms_to` is validated as an ordinary optional URI and the rest of
the `access` block is left to the consuming runtime.

### Ecosystem binding keys

Ecosystem bindings declare ecosystem-specific integration metadata. The only binding type
currently valid is `governed-evidence`, which carries evidence-pack and ODRL enforcement
metadata for a governed evidence gateway. A complete worked example is the
`baseline-dpi/v1` binding in
[`ecosystem_binding_parses_validates_compiles_and_renders_catalog`](../../../crates/registry-manifest-core/tests/metadata_core.rs).

Fields of `EcosystemBindingManifest`.

| Key | Required | Description |
| --- | --- | --- |
| `id` | Yes | Binding identifier. The `id`/`version` pair must be unique among ecosystem bindings. |
| `version` | Yes | Binding version string. |
| `profile` | Yes | Profile identifier the binding applies to. |
| `type` | Yes | Binding type. Only `governed-evidence` is currently valid. |
| `title` | No | `LocalizedText`. Must be non-empty when present. |
| `description` | No | `LocalizedText`. Must be non-empty when present. |
| `vocabulary` | No | Opaque object. Not structurally validated. |
| `request_envelope` | No | Opaque object. Not structurally validated. |
| `response_envelope` | No | Opaque object. Not structurally validated. |
| `transport` | No | Opaque object. Not structurally validated. |
| `trust_framework` | No | Opaque object. Not structurally validated. |
| `credential_format` | No | Opaque object. Not structurally validated. |
| `assurance_model` | No | Opaque object. Not structurally validated. |
| `conformance` | No | Opaque object. Not structurally validated. |
| `evidence_pack` | Conditional | `EvidencePackMetadata` object. Required, with the fields marked Yes in the `EvidencePackMetadata` table, when `type` is `governed-evidence`. Optional otherwise, though any fields present are still validated. |
| `profiles` | No | List of `ProfileClaim` (`id`, `version`). Each `id` must be unique within the binding. |

Fields of `EvidencePackMetadata`. This type is shared by `ecosystem_bindings[].evidence_pack`
and `evaluation_profiles[].evidence_pack`. Whenever an `evidence_pack` is present, every field
in this table is validated for shape (object fields must be objects, string lists must use only
supported values and be unique, `policy_hash` must match the `sha256:<64 lowercase hex>`
pattern, `odrl_policy_url` must be HTTPS). The "Required" column applies only when the
`evidence_pack` belongs to a `governed-evidence` ecosystem binding; outside that case, every
field is optional.

| Key | Required (governed-evidence) | Description |
| --- | --- | --- |
| `pack_id` | Yes | Evidence pack identifier. |
| `pack_version` | Yes | Evidence pack version string. |
| `source_basis` | Yes | Object describing the evidence pack's source basis. |
| `semantic_profile` | Yes | Object describing the evidence pack's semantic profile. |
| `evidence_envelope` | Yes | Object describing the evidence pack's evidence envelope shape. |
| `required_gates` | Yes | Must include all of: `purpose`, `jurisdiction`, `legal_basis`, `consent`, `authority_basis`, `requester_identity`, `subject_identity`, `subject_relationship`, `assurance`, `source_binding`, `source_freshness`, `requested_disclosure`, `credential_format`, `route_scope`. |
| `allowed_outputs` | Yes | Must include `minimized_json`, currently the only supported output value. |
| `policy_id` | Yes | Policy identifier. |
| `policy_version` | No | Policy version string. |
| `policy_hash` | Yes | Digest of the canonical inline policy, formatted `sha256:<64 lowercase hex>`. Must match the digest of `policy` when `policy` is present. |
| `source_mapping` | No | Opaque object. Not structurally validated. |
| `policy` | No | Canonical inline policy object. When present, its digest must match `policy_hash`. |
| `fixtures` | No | Opaque list. Not structurally validated. |
| `synthetic_data` | No | Opaque list. Not structurally validated. |
| `odrl_policy_url` | No | Must be an HTTPS URL when present. |
| `odrl_enforcement` | Yes | `OdrlEnforcementProfile` object; see the `OdrlEnforcementProfile` table that follows. |

Fields of `OdrlEnforcementProfile`.

| Key | Required | Description |
| --- | --- | --- |
| `profile` | Yes | Must equal `registry-evidence-gateway-pdp/v1`. |
| `constraint_terms` | Yes | At least one term. Each must be `odrl:purpose` or `odrl:spatial`. Terms must be unique. |

Source:
[`crates/registry-manifest-core/src/lib.rs`](../../../crates/registry-manifest-core/src/lib.rs)
(`EcosystemBindingManifest`, `EvidencePackMetadata`, `OdrlEnforcementProfile`).

### Runtime-only keys

The following keys must not appear in a portable manifest.
Their presence causes `validate`, `publish`, and `validate-profiles` to fail.
They belong in a service's runtime configuration, such as Registry Relay's, not in a metadata manifest.

`admin_bind`, `admin_listener`, `audit`, `auth`, `bind`, `bindings`, `capabilities`,
`column`, `config_trust`, `file_path`, `listener`, `listeners`, `peer_allowlist`,
`peers`, `private_jwk`, `private_jwk_env`, `query`, `replay`, `required_filters`,
`rows_scope`, `scope`, `secret_provider`, `secret_providers`, `signing_keys`,
`source`, `source_connections`, `source_id`, `table`, `token_url`, `url`, `url_env`, `visibility`

Source:
[`crates/registry-manifest-core/src/lib.rs`](../../../crates/registry-manifest-core/src/lib.rs)
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

`registry-manifest/v1` and the manifest-owned `*/v1` generated formats reject an
unknown key at parse time (issue #249). `MetadataManifestFields` and its nested
manifest structs carry `deny_unknown_fields`, and the manifest's hand-written
`Deserialize` impl reports the offending key by its full dotted path, for example
`catalog.publisher.x_post_beta_publisher_hint: unknown field`. A manifest that
carries a misspelled or ad-hoc key fails `validate`, `render`, and `publish` instead
of parsing with the key silently dropped.

The runtime-only and secret-bearing key checks run first, over the raw parsed value,
before the strict key check runs. Readers must reject unrecognized or extension keys
that look credential-bearing, including keys such as `client_secret`, `password`,
`credential`, `credentials`, `api_key`, `private_key`, `token`, or `secret`, plus
compound variants such as `secret_key`, `credential_env`, `password_env`, and
`client_secret_env`.

Extensions belong in the manifest's modeled extension points, not in ad-hoc keys.
`EvidencePackMetadata` (`source_basis`, `semantic_profile`, `evidence_envelope`,
`source_mapping`, `policy`, `fixtures`, `synthetic_data`) and
`EcosystemBindingManifest` (`vocabulary`, `request_envelope`, `response_envelope`,
`transport`, `trust_framework`, `credential_format`, `assurance_model`,
`conformance`) hold arbitrary JSON under a named, already-modeled field, and the
top-level `vocabularies` map holds an open set of prefix expansions. A field that is
not one of these must be added to the struct in `registry-manifest-core` before a
producer can send it; the schema no longer tolerates a key it does not model.

Before Registry Stack v1.0.0, a minor release may make a breaking Manifest
change while retaining `registry-manifest/v1`. The affected Manifest changelog
must mark it `BREAKING:`, give concrete migration steps, and the specification
version history must record it. Breaking changes include removing or renaming
required fields, changing the meaning or type of an existing field, or making
previously valid V1 manifests invalid except for validation bugs and security
fixes. From Registry Stack v1.0.0, such a change requires a new manifest schema
version.

## Publish output artifacts

Source:
[`crates/registry-manifest-cli/src/main.rs`](../../../crates/registry-manifest-cli/src/main.rs)
(`publish_command`).

All paths are relative to the `--out` directory, except the two `.well-known/*` discovery
documents, which are relative to `--site-root` when that flag is set.

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
| `.well-known/api-catalog` | JSON | `write_api_catalog()`, always written | n/a; a linkset object with no `schema_version` field |
| `.well-known/registry-manifest.json` | JSON | `write_legacy_registry_manifest_discovery()`, always written | `schema_version: registry-manifest-discovery/v1` |

The `index.json` structure contains the schema version, digest metadata, top-level
artifact URLs, and arrays for per-profile, per-schema, per-policy, and per-offering
documents.
Source:
[`crates/registry-manifest-cli/src/main.rs`](../../../crates/registry-manifest-cli/src/main.rs)

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
[`crates/registry-manifest-core/tests/metadata_core.rs`](../../../crates/registry-manifest-core/tests/metadata_core.rs)
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
