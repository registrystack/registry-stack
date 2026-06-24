# Validate and render a manifest

Check a `metadata.yaml` file for errors, inspect individual rendered artifacts
(service catalogues, catalog metadata, validation shapes, JSON Schemas, form schemas, and policies),
or produce a complete static publication bundle for hosting.

The validator collects all errors across every validation pass before reporting, so a single run surfaces every problem in the file.
You do not need to fix one error at a time and re-run.

For profile fixture validation, see [Validate against profile fixtures](./profile-fixtures.md) instead.

## Prerequisites

- Rust toolchain installed (the workspace uses stable Rust).
- The `registry-manifest` repository cloned locally.

Build the CLI before running commands:

```sh
cargo build -p registry-manifest-cli
```

The commands in this page use `cargo run -p registry-manifest-cli --` as a prefix.
If you have installed the binary directly, replace that prefix with `registry-manifest-cli`.

The four example profile fixtures in the repository serve as ready-made manifest inputs.
The commands in this how-to use
[`profiles/example-civil-registration/fixtures/metadata.yaml`](https://github.com/jeremi/registry-manifest/blob/bb7bc6d015f519a9d1a6b6a0b661a2d28566af9d/profiles/example-civil-registration/fixtures/metadata.yaml)
as the example path.
Substitute your own manifest path as needed.

## Steps

### 1. Validate the manifest

```sh
cargo run -p registry-manifest-cli -- validate \
  profiles/example-civil-registration/fixtures/metadata.yaml
```

On success, the CLI prints:

```text
metadata manifest valid: profiles/example-civil-registration/fixtures/metadata.yaml
source_manifest_digest: sha256:...
```

On failure, all validation errors are printed together.

Validation checks include:

- `schema_version` equals `"registry-manifest/v1"`.
- Catalog `base_url` is a valid HTTP URL.
- Entity names match the required identifier pattern.
- Cardinality strings are well-formed (`"0..1"`, `"1..n"`, `"1..1"`).
- Codelist references resolve to defined codelists.
- Grouped evidence type lists reference known evidence types that prove the owning requirement.
- Public service, authority, channel, form, and data-service references resolve.
- ODRL policy terms use recognized action and operator values.
- Evidence offering references are internally consistent.
- Runtime-only keys such as table names, source paths, scopes, and backend bindings are absent.

### 2. Render a single artifact

Use `render` to write one renderer's output to stdout.
The `--format` flag selects the renderer.

Render the catalog JSON:

```sh
cargo run -p registry-manifest-cli -- render \
  profiles/example-civil-registration/fixtures/metadata.yaml \
  --format catalog
```

Render base DCAT JSON-LD:

```sh
cargo run -p registry-manifest-cli -- render \
  profiles/example-civil-registration/fixtures/metadata.yaml \
  --format dcat
```

Render a Core Public Service Vocabulary Application Profile (CPSV-AP) service catalogue:

```sh
cargo run -p registry-manifest-cli -- render \
  fixtures/cpsv-ap/health-linked-child-support.metadata.yaml \
  --format cpsv-ap
```

To render the BRegDCAT-AP profile variant via `--format dcat`, pass `--profile bregdcat-ap`.
Alternatively, use the `--format bregdcat-ap` shorthand:

Render BRegDCAT-AP JSON-LD:

```sh
cargo run -p registry-manifest-cli -- render \
  profiles/example-civil-registration/fixtures/metadata.yaml \
  --format bregdcat-ap
```

For optional public ITB/SEMIC validator smoke checks against rendered DCAT and
BRegDCAT-AP artifacts, see
[ITB/SEMIC validation smoke checks](itb-semic-validation.md).

Render SHACL (Shapes Constraint Language) node shapes:

```sh
cargo run -p registry-manifest-cli -- render \
  profiles/example-civil-registration/fixtures/metadata.yaml \
  --format shacl
```

Render a JSON Schema Draft 2020-12 for a specific dataset and entity.
The civil-registration fixture has dataset `vital-events` with entities `person` and
`vital_event`. Substitute accordingly for your manifest:

```sh
cargo run -p registry-manifest-cli -- render \
  profiles/example-civil-registration/fixtures/metadata.yaml \
  --format json-schema \
  --dataset vital-events \
  --entity person
```

Render a form JSON Schema Draft 2020-12 document:

```sh
cargo run -p registry-manifest-cli -- render \
  fixtures/cpsv-ap/health-linked-child-support.metadata.yaml \
  --format form-json-schema \
  --form child-support-review-form
```

Render OGC API Records item bodies:

```sh
cargo run -p registry-manifest-cli -- render \
  profiles/example-civil-registration/fixtures/metadata.yaml \
  --format ogc-records
```

Render the ODRL (Open Digital Rights Language) policy collection:

```sh
cargo run -p registry-manifest-cli -- render \
  profiles/example-civil-registration/fixtures/metadata.yaml \
  --format policies
```

Render a per-dataset ODRL policy document (substitute your dataset ID for `vital-events`):

```sh
cargo run -p registry-manifest-cli -- render \
  profiles/example-civil-registration/fixtures/metadata.yaml \
  --format policy \
  --dataset vital-events
```

Render evidence offerings:

```sh
cargo run -p registry-manifest-cli -- render \
  profiles/example-civil-registration/fixtures/metadata.yaml \
  --format evidence-offerings
```

Render a single evidence offering by ID (substitute the offering ID defined in your manifest's
`evidence_offerings` list):

```sh
cargo run -p registry-manifest-cli -- render \
  profiles/example-civil-registration/fixtures/metadata.yaml \
  --format evidence-offering \
  --offering <offering-id>
```

All `render` output goes to stdout.
Redirect to a file when you want to inspect or diff it:

```sh
cargo run -p registry-manifest-cli -- render \
  profiles/example-civil-registration/fixtures/metadata.yaml \
  --format bregdcat-ap > /tmp/breg.jsonld
```

### 3. Publish a static bundle

`publish` runs every renderer, writes all artifacts to a directory, and creates an
`index.json` that lists every artifact with its relative path, media type, and SHA-256
digest.

```sh
cargo run -p registry-manifest-cli -- publish \
  profiles/example-civil-registration/fixtures/metadata.yaml \
  --out target/metadata/public
```

The output directory will contain `catalog.json`, `dcat.jsonld`, `cpsv-ap.jsonld` when the
manifest declares the profile, `shacl.jsonld`, per-entity JSON Schema files, form JSON Schema
files, `ogc-records/items.json`, evidence-offering files, and per-dataset policy documents.
Linked-data outputs include embedded SKOS-shaped codelist nodes when the manifest declares
codelists.
See [Registry Manifest reference](./reference.md) for the full artifact list.

The `index.json` at the root of the output directory carries schema version
`registry-manifest-index/v1`, links to every artifact, and includes:

- `source_manifest_digest`: the canonical digest of the typed source manifest.
- `package_digest`: a digest over the source manifest digest and the published artifact inventory.
- `artifacts`: per-artifact `path`, `media_type`, and `sha256` entries.

`artifacts` excludes `index.json` itself and `.well-known/*` discovery documents. The index
is excluded because it contains the package digest, and `.well-known/*` may be written under
`--site-root` while still discovering the same metadata bundle.

Future publish bundles may add optional artifacts and corresponding `index.json` entries.
Readers should ignore artifact paths, top-level index links, and artifact metadata members
they do not understand, while continuing to validate known required fields and digests. Adding
an artifact changes the `package_digest` because the digest covers the full artifact inventory.

## Verification

After `validate`, confirm the exit code is zero:

```sh
cargo run -p registry-manifest-cli -- validate \
  profiles/example-civil-registration/fixtures/metadata.yaml
echo "exit code: $?"
```

After `publish`, confirm the key artifacts are present:

```sh
ls target/metadata/public/catalog.json \
   target/metadata/public/dcat.jsonld \
   target/metadata/public/ogc-records/items.json \
   target/metadata/public/shacl.jsonld \
   target/metadata/public/index.json
```

Profile-specific artifacts such as `cpsv-ap.jsonld` or `dcat.<profile-id>.jsonld` are only
written when the manifest declares the corresponding application profile.

## Troubleshooting

### "schema_version mismatch" or validation error on schema_version

The manifest root must declare `schema_version: registry-manifest/v1`.
Check the first line of your YAML.

### Validation prints errors about cardinality strings

Cardinality values must match the pattern `"0..1"`, `"1..1"`, or `"1..n"`.
Check your `cardinality_expectations` blocks.

### `--format json-schema` produces no output or errors

The `json-schema` format requires both `--dataset <id>` and `--entity <name>`.
Confirm both flags are present and match IDs defined in your manifest.

### `--format policy` errors on dataset not found

The `policy` format requires `--dataset <id>`.
The ID must match a `DatasetManifest` entry in your manifest.

### `publish` writes an empty or partial directory

A validation failure inside `publish` aborts the run.
Run `validate` first to confirm the manifest is clean before running `publish`.

### Validation rejects a key like `source`, `table`, or `scope`

Portable manifests cannot include runtime binding keys. Move data-source locations, database
tables, caller scopes, credentials, peer allowlists, signing keys, and replay-store settings to
Registry Relay or Registry Notary runtime configuration.
