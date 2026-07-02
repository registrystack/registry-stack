# Registry Manifest overview

Registry Manifest is a portable Rust workspace that takes one `metadata.yaml` file and
derives every standards-facing artifact other systems need to find, understand, and connect
to a registry. It can also publish public Registry Notary federation metadata that helps
partners configure static-peer delegated evaluation.
It does not serve HTTP, does not talk to databases, and does not handle credentials.
You can run it on a laptop, in a CI pipeline, or in a static hosting workflow with no
server required.

**Stack commitments:** interoperability, reviewability.

## What Registry Manifest emits

Registry Manifest ships pure renderer functions.
Each renderer takes a compiled manifest and returns a serialized document.
No renderer makes network calls or reads files beyond the manifest input.

| Output format | `--format` value |
| --- | --- |
| Catalog JSON | `catalog` |
| DCAT JSON-LD | `dcat` |
| CPSV-AP service catalogue JSON-LD | `cpsv-ap` |
| BRegDCAT-AP JSON-LD | `bregdcat-ap` |
| SHACL node shapes JSON-LD | `shacl` |
| JSON Schema Draft 2020-12 | `json-schema` |
| Form JSON Schema Draft 2020-12 | `form-json-schema` |
| OGC API Records FeatureCollection JSON | `ogc-records` |
| ODRL policy collection JSON-LD | `policies` |
| Per-dataset ODRL policy document JSON-LD | `policy` |
| Evidence offerings collection JSON | `evidence-offerings` |
| Single evidence offering JSON | `evidence-offering` |

Federation metadata appears inside the catalog and evidence-offering JSON outputs. It is not a
separate render format. Codelists are emitted as embedded SKOS-shaped nodes inside the SHACL
and DCAT/BRegDCAT-shaped linked-data outputs; there is not yet a standalone SKOS artifact.

Not yet implemented: GovStack DR BB, SP DCI, standalone SKOS, and standalone PROV-O.

The `dcat` format dispatches based on an optional `--profile` flag: `--profile dcat` or
`--profile dcat-ap` renders base Data Catalog Vocabulary (DCAT); `--profile bregdcat-ap`
renders the Business Registers Extended DCAT Application Profile (BRegDCAT-AP) variant.
Omitting `--profile` with `--format dcat` defaults to base DCAT.
For external validator smoke checks and claim boundaries, see
[ITB/SEMIC validation smoke checks](itb-semic-validation.md).

## When to use Registry Manifest

You have a registry or public-service workflow and need to publish machine-readable metadata:
a Core Public Service Vocabulary Application Profile (CPSV-AP) service catalogue, a DCAT
catalog, OGC Records item collection, Shapes Constraint Language (SHACL) shapes, JSON Schema
for API contract documentation, a local form profile, codelist metadata, or Open Digital
Rights Language (ODRL) policies
declaring access terms.
Write one `metadata.yaml`, run `registry-manifest-cli publish`, and get a static directory
of all those artifacts ready to host anywhere.
The published `index.json` includes a canonical digest of the source manifest, a package
digest, and per-artifact digests so operators can compare or pin bundles without running
Registry Relay.

If you need runtime metadata served over HTTP with per-caller scoping and authorization,
that is Registry Relay's job.
Relay uses Registry Manifest's renderers internally.

## A minimal manifest

A manifest must declare `schema_version: registry-manifest/v1` at its root.
The following skeleton shows the required top-level keys:

```yaml
schema_version: registry-manifest/v1
catalog:
  id: my-registry
  base_url: https://registry.example.gov
  title:
    en: My Registry
  publisher:
    name: Example Authority
    iri: https://registry.example.gov/authority
    authority_type: eli:PublicAuthority
  participant_id: https://registry.example.gov/authority
datasets:
  - id: my-dataset
    title:
      en: My Dataset
    entities:
      - name: my_entity
        title:
          en: My Entity
        identifiers:
          - name: entity_id
            kind: local
        fields:
          - name: entity_id
            type: string
            required: true
requirements: []
evidence_types: []
public_services: []
forms: []
```

A manifest must not contain runtime bindings such as source file paths, table names,
database scopes, backend credentials, peer allowlists, federation signing keys, replay stores,
or pairwise subject hash secrets.
Those live in Registry Relay or Registry Notary configuration; the manifest is portable and
runtime-independent.

A full working example is at
`profiles/example-civil-registration/fixtures/metadata.yaml`.

## The metadata model

The top-level struct is `MetadataManifest`, which groups catalog, dataset,
entity, service, form, evidence offering, dataset policy, requirement, evidence
type, codelist, federation, evaluation profile, and ecosystem binding metadata.
Full field-by-field documentation is in [Registry Manifest reference](./reference.md).

Grouped evidence is explicit.
An `evidence_type_lists` entry under a requirement is one option group; all evidence types
in that list are required together.
Multiple lists on the same requirement are alternatives.

Federated evaluation metadata is explicit too.
The top-level `federation` block advertises the publishing Notary node id, issuer, JWKS URL,
federation API URL, and supported protocol versions.
The top-level `evaluation_profiles` list binds public profile ids and ruleset ids to Notary
claim ids and subject id types.
A `registry-notary` evidence offering must reference one of those ruleset ids through
`access.ruleset`.
Registry Manifest validates that link, but Registry Notary still decides which peers may call it.

## Validation

When you run `validate` or `publish`, Registry Manifest performs multi-pass validation
before any rendering occurs:

1. Confirms `schema_version == "registry-manifest/v1"`.
2. Validates catalog fields: HTTP base URL, title, publisher, and supported application
   profiles list.
3. Validates requirement and evidence-type reference integrity.
4. Validates grouped evidence type lists, including duplicate list IDs, empty lists,
   unknown evidence types, and evidence types that do not prove the owning requirement.
5. Validates public service, channel, authority, form, and data-service references.
6. Validates per-dataset entities, fields, relationships, identifiers, codelists,
   cardinality strings, and ODRL policy terms.
7. Validates evidence-offering references.
8. Validates Registry Notary federation metadata when `registry-notary` access is declared:
   HTTPS URLs, `did:web` issuer binding, protocol version, unique evaluation profile ids, unique
   rulesets, and `access.ruleset` references.
9. Rejects runtime-only keys such as source paths, table names, scopes, backend bindings,
   visibility rules, and capability declarations.

All errors are collected and returned together so a single run surfaces every problem in
the file.

Validation also expands vocabulary prefixes (for example, `person:Person.identifier`
becomes a full IRI) and resolves codelist concept references before any renderer runs.

## The CLI surface

`registry-manifest-cli` exposes four subcommands:

- `validate`: parse and validate a manifest file. Exits non-zero on any validation error.
- `render`: compile a manifest and write one renderer's output to stdout. Accepts
  `--format`, `--profile`, `--dataset`, `--entity`, `--form`, and `--offering` selectors.
- `publish`: compile a manifest, run all renderers, write every artifact to an output
  directory, and generate an `index.json` manifest of the bundle.
- `validate-profiles`: scan a `profiles/` directory for profile descriptors, validate
  their schema, and validate all referenced fixture manifests.

See [Validate and render a manifest](./validate-and-render.md) for the `validate`, `render`,
and `publish` subcommands in steps.
See [Validate against profile fixtures](./profile-fixtures.md) for `validate-profiles`.

## Profile fixtures

The `profiles/` directory contains non-normative profile descriptors and fixture manifests.
A profile descriptor (schema version `registry-manifest-profile/v1`) declares:

- Required and optional concept IRIs a conforming manifest must reference.
- Required identifiers and codelists with expected code values.
- Cardinality expectations per entity field.
- Runtime-only keys that must not appear in a portable fixture manifest.

Four example profiles ship in the repository: `example-civil-registration`,
`example-social-benefits`, `example-person-schema`, and `example-benefits-sync`.
These are examples until reviewed against official OpenCRVS, OpenSPP, OpenIMIS, SP DCI,
or maintainer-provided artifacts.

Four additional subdirectories exist in `profiles/` for
[`opencrvs`](../profiles/opencrvs/),
[`openimis`](../profiles/openimis/),
[`openspp`](../profiles/openspp/),
and
[`spdci`](../profiles/spdci/).
Each contains only a `README.md` that marks it as a placeholder pending official review.

## v0 caveats

Registry Manifest is at v0.1.
The manifest schema version `registry-manifest/v1` is enforced in code.
Manifest-owned formats freeze at beta, including the root manifest schema,
profile descriptor schema, generated artifact formats, codelists, and the static
publication bundle format.
Profile fixtures in `profiles/` are non-normative examples.
The static publication bundle format includes `index.json` schema version
`registry-manifest-index/v1`.

The test suite includes golden-fixture assertions for the older example profiles and the
standards-shaped renderer outputs, including CPSV-AP and OGC Records fixtures.

## See also

- [Validate and render a manifest](./validate-and-render.md)
- [Validate against profile fixtures](./profile-fixtures.md)
- [Registry Manifest reference](./reference.md)
