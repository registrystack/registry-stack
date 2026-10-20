# Registry Manifest overview

A registry manifest is one `metadata.yaml` file that describes a registry for the systems that
need to find and understand it: its catalogue and publisher, its datasets, entities, and fields,
the public services and forms around it, the codelists it uses, and the Evidence it can offer.
Registry Manifest is the Rust library and the `registry-manifest` command that check that file
and render it into standards-shaped metadata. It serves no HTTP, reads no database, and handles
no credentials, so it runs anywhere, including CI.

## What a manifest holds, and what it refuses

A manifest declares `schema_version: registry-manifest/v1` and a `catalog`, then lists what the
registry offers under `datasets`, `public_services`, `forms`, `requirements`, `evidence_types`,
and the other top-level collections. Its format is closed: it refuses unknown keys, dangling
references, and runtime bindings such as a source path, a table name, a database scope, a
caller allowlist, a credential, or a signing key. Those belong to the runtime that serves the
registry, so the same manifest stays portable across deployments.

[RS-DM-MANIFEST](https://docs.registrystack.org/spec/rs-dm-manifest/) is the normative data
model, and the [Registry Manifest reference](./reference.md) documents every field.

## Who writes one

A registry publisher or integrator writes `metadata.yaml` by hand to publish catalogue metadata
for a registry, whatever runs it. A Base Registry Engine (BReg) project does not write one by
hand: `bregctl generate manifest` projects one from the project's `manifestProjection` through
the Registry Manifest library, with a DCAT catalogue. The projection carries only the datasets
within its access profile and classification ceiling, and keeps the labels and identifiers of
every other dataset out of both the manifest and the catalogue, relationship edges included.

## The `registry-manifest` commands

- `validate` checks one manifest offline and reports every finding at each stage together:
  first the document's shape, then the manifest rules. Each finding has its code, line, column,
  and fix.
- `render` writes one format to standard output: catalog JSON, DCAT or BRegDCAT-AP, CPSV-AP,
  SHACL, JSON Schema, form JSON Schema, OGC API Records, ODRL policies, or Evidence offerings.
- `publish` renders the formats the manifest declares into a directory, with an `index.json` that
  records the digest of the source manifest and of each file, so an operator can compare or pin a
  bundle.
  It does not empty the directory first, so publish into a clean one.
- `validate-profiles` checks profile descriptors and their fixture manifests.

[Validate and render a manifest](./validate-and-render.md) walks through the first three, and
[Validate against profile fixtures](./profile-fixtures.md) covers the last.
[ITB/SEMIC validation smoke checks](./itb-semic-validation.md) runs rendered DCAT and
BRegDCAT-AP through the public EU Interoperability Test Bed validators.

## What metadata does not do

Published metadata is descriptive. It grants no access, and naming a service in a manifest does
not make it trusted. BReg and Registry Evidence each keep their own access decisions. Host the published directory as
static files, and replace the whole directory to publish a new revision.

Registry Manifest is pre-1.0. The `registry-manifest/v1` schema version is enforced in code, and
the five `example-*` profiles under `products/manifest/profiles/` are non-normative.
