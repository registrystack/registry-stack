# Validate and render a manifest

Check a `metadata.yaml` file for errors, inspect individual rendered artifacts
(service catalogues, catalog metadata, validation shapes, JSON Schemas, form schemas, and policies),
or produce a complete static publication bundle for hosting.

The validator reports every problem at each stage together: first every problem with the
document's shape, then, once the document reads, every manifest rule it breaks.
You do not need to fix one error at a time and re-run.

For profile fixture validation, see [Validate against profile fixtures](./profile-fixtures.md) instead.

## Prerequisites

- Rust 1.95.0 through rustup, the version the checkout's `rust-toolchain.toml` pins.
- A Registry Stack checkout
  (`git clone https://github.com/registrystack/registry-stack.git`). Run every command below
  from its root.

Build the CLI before running commands:

```sh
cargo build --bin registry-manifest
```

Each command below uses `cargo run --bin registry-manifest --` as a prefix. Each release also
publishes the Linux amd64 binary `registry-manifest-<tag>-linux-amd64`, with `<tag>` from the
[latest release](https://github.com/registrystack/registry-stack/releases/latest); installed as
`registry-manifest`, it replaces that prefix.

The fixtures of the five `example-*` profiles serve as ready-made manifest inputs.
Each command below uses
[`products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml`](../profiles/example-civil-registration/fixtures/metadata.yaml)
as the example path.
Substitute your own manifest path as needed.

## Steps

### 1. Validate the manifest

```sh
cargo run --bin registry-manifest -- validate \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml
```

On success, the CLI prints:

```text
metadata manifest valid: products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml
source_manifest_digest: sha256:3867f310494f2817077e8fc44f5c64d424a60ed9caa047d8284ff650f85a4abc
0 errors, 0 warnings in 1 file
```

On a refusal, the CLI prints one sentence and then every finding to standard error, and
exits 1. Each finding names its code, the file, line, and column, the member's JSON
Pointer, and the fix, and never repeats the refused value. For a `base_url` with no scheme:

```text
registry-manifest validate refused the manifest.
error[manifest.metadata.invalid-url] metadata.yaml:4:13 /catalog/base_url
  URL must start with http:// or https://
  next: Write an absolute URL with the scheme the message names and a host.
1 error, 0 warnings in 1 file
```

Add `--format json` for a machine-readable report. The exit codes are listed in the
[reference](./reference.md#check-exit-codes-and-diagnostics).

Validation checks include:

- `schema_version` equals `"registry-manifest/v1"`.
- Catalog `base_url` is a valid HTTP URL.
- Entity names match the required identifier pattern.
- A relationship's `cardinality` value is one of `one`, `zero_or_one`, `many`, or
  `zero_or_more`.
- Codelist references resolve to defined codelists.
- Grouped evidence type lists reference known evidence types that prove the owning requirement.
- Public service, authority, channel, form, and data-service references resolve.
- Every distribution names one existing dataset, names a serving data service
  when `access_service` is present, and declares at least one access mechanism.
- ODRL policy terms use recognized action and operator values.
- Evidence offering references are internally consistent.
- Runtime-only keys such as table names, source paths, scopes, and backend bindings are absent.

### 2. Render a single artifact

Use `render` to write one renderer's output to stdout.
The `--format` flag selects the renderer.

Render the catalog JSON:

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml \
  --format catalog
```

Render base DCAT JSON-LD:

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml \
  --format dcat
```

Render a Core Public Service Vocabulary Application Profile (CPSV-AP) service catalogue:

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/fixtures/cpsv-ap/health-linked-child-support.metadata.yaml \
  --format cpsv-ap
```

To render the BRegDCAT-AP profile variant via `--format dcat`, pass `--profile bregdcat-ap`.
Alternatively, use the `--format bregdcat-ap` shorthand:

Render BRegDCAT-AP JSON-LD:

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml \
  --format bregdcat-ap
```

For optional public ITB/SEMIC validator smoke checks against rendered DCAT and
BRegDCAT-AP artifacts, see
[ITB/SEMIC validation smoke checks](itb-semic-validation.md).

Render SHACL (Shapes Constraint Language) node shapes:

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml \
  --format shacl
```

Render a JSON Schema Draft 2020-12 for a specific dataset and entity.
The civil-registration fixture has dataset `vital-events` with entities `person` and
`vital_event`. Substitute accordingly for your manifest:

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml \
  --format json-schema \
  --dataset vital-events \
  --entity person
```

Render a form JSON Schema Draft 2020-12 document:

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/fixtures/cpsv-ap/health-linked-child-support.metadata.yaml \
  --format form-json-schema \
  --form child-support-review-form
```

Render OGC API Records item bodies:

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml \
  --format ogc-records
```

Render the ODRL (Open Digital Rights Language) policy collection:

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml \
  --format policies
```

Render a per-dataset ODRL policy document (substitute your dataset ID for `vital-events`):

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml \
  --format policy \
  --dataset vital-events
```

Render evidence offerings (the civil-registration fixture declares none, so this uses the
CPSV-AP fixture):

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/fixtures/cpsv-ap/health-linked-child-support.metadata.yaml \
  --format evidence-offerings
```

Render a single evidence offering by ID (substitute the offering ID defined in your manifest's
`evidence_offerings` list):

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/fixtures/cpsv-ap/health-linked-child-support.metadata.yaml \
  --format evidence-offering \
  --offering health-coverage-evidence-offering
```

All `render` output goes to stdout.
Redirect to a file when you want to inspect or diff it:

```sh
cargo run --bin registry-manifest -- render \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml \
  --format bregdcat-ap > /tmp/breg.jsonld
```

### 3. Publish a static bundle

`publish` runs every renderer, writes all artifacts to a directory, and creates an
`index.json` that lists every artifact with its relative path, media type, and SHA-256
digest.

```sh
cargo run --bin registry-manifest -- publish \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml \
  --out target/metadata/public
```

The output directory will contain `catalog.json`, `dcat.jsonld`, `cpsv-ap.jsonld` when the
manifest declares the profile, `shacl.jsonld`, per-entity JSON Schema files, form JSON Schema
files, `ogc-records/items.json`, evidence-offering files, and per-dataset policy documents.
`publish` always writes two well-known documents under `.well-known/` too:
`api-catalog` (a linkset of the published artifact URLs) and `registry-manifest.json` (schema
`registry-manifest-discovery/v1`, which points to `/metadata/index.json` and the main artifacts).
Linked-data outputs include embedded SKOS-shaped codelist nodes when the manifest declares
codelists.
See [Registry Manifest reference](./reference.md) for the full artifact list.

By default, `.well-known/*` writes under `--out` alongside every other artifact. Pass
`--site-root <dir>` to write the two well-known documents under a separate directory instead,
useful when the metadata bundle is published as a sibling of a larger site root:

```sh
cargo run --bin registry-manifest -- publish \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml \
  --out target/metadata/public \
  --site-root target/site
```

The `index.json` at the root of the output directory carries schema version
`registry-manifest-index/v1`, links to every artifact, and includes:

- `source_manifest_digest`: the canonical digest of the typed source manifest.
- `package_digest`: a digest over the source manifest digest and the published artifact inventory.
- `artifacts`: per-artifact `path`, `media_type`, and `sha256` entries.

`artifacts` excludes `index.json` itself and the `.well-known/*` documents. The index
is excluded because it contains the package digest, and `.well-known/*` may be written under
`--site-root` while still discovering the same metadata bundle.

Future publish bundles may add optional artifacts and corresponding `index.json` entries.
Readers should ignore artifact paths, top-level index links, and artifact metadata members
they do not understand, while continuing to validate known required fields and digests. Adding
an artifact changes the `package_digest` because the digest covers the full artifact inventory.

## Verification

After `validate`, confirm the exit code is zero (1 means the manifest was refused,
2 that the arguments were not understood, and 3 that the file could not be read):

```sh
cargo run --bin registry-manifest -- validate \
  products/manifest/profiles/example-civil-registration/fixtures/metadata.yaml
echo "exit code: $?"
```

After `publish`, confirm the key artifacts are present:

```sh
ls target/metadata/public/catalog.json \
   target/metadata/public/dcat.jsonld \
   target/metadata/public/ogc-records/items.json \
   target/metadata/public/shacl.jsonld \
   target/metadata/public/index.json \
   target/metadata/public/.well-known/api-catalog \
   target/metadata/public/.well-known/registry-manifest.json
```

Profile-specific artifacts such as `cpsv-ap.jsonld` or `dcat.<profile-id>.jsonld` are only
written when the manifest declares the corresponding application profile.

## Troubleshooting

### `manifest.metadata.unsupported-version` on `/schema_version`

The manifest root must declare `schema_version: registry-manifest/v1`.
Check the first line of your YAML.

### `config.null-value` or `config.substitution-not-allowed`

A manifest never writes `null`: omit an optional member instead. A manifest is a
portable description that nothing substitutes values into, so text that contains
`${...}` is refused; write the value itself.

### Validation prints errors about cardinality values

A relationship's `cardinality` field must be one of `one`, `zero_or_one`, `many`, or
`zero_or_more`. Check each entity's `relationships` list.

Profile-level cardinality expectations (`cardinality_expectations` in a profile descriptor)
are a different check, run by `validate-profiles`. See
[Validate against profile fixtures](./profile-fixtures.md).

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
tables, caller scopes, credentials, caller allowlists, signing keys, and replay-store settings to
runtime configuration.
