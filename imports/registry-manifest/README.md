# Registry Manifest

Registry Manifest is a portable Rust workspace for modeling, validating, and rendering standards-facing registry metadata without running Registry Relay.

It owns metadata manifests, compiled metadata models, validation, vocabulary prefix expansion, and pure renderers for catalog JSON, DCAT JSON-LD, BRegDCAT-AP JSON-LD, SHACL, JSON Schema Draft 2020-12, OGC API Records item bodies, policy documents, and evidence-offering metadata.

## Workspace

- [`crates/registry-manifest-core`](crates/registry-manifest-core/README.md):
  manifest contracts, validation, compilation, and renderers.
- [`crates/registry-manifest-cli`](crates/registry-manifest-cli/README.md):
  command-line validation, rendering, static publication, and profile fixture validation.
- `profiles/`: non-normative profile descriptors and metadata fixtures.
- `examples/`: runnable static publication examples and notes.
- `docs/`: repository-level design and release notes.

The checked-in profiles are examples until reviewed against official OpenCRVS, OpenSPP, OpenIMIS, SP DCI, or maintainer-provided artifacts.

## Commands

Format:

```sh
cargo fmt --all -- --check
```

Lint:

```sh
cargo clippy --workspace --all-targets -- -D warnings
```

Unit and golden renderer tests:

```sh
cargo test -p registry-manifest-core
```

CLI tests:

```sh
cargo test -p registry-manifest-cli
```

Validate profile descriptors and fixtures:

```sh
cargo run -p registry-manifest-cli -- validate-profiles profiles
```

Validate a metadata manifest:

```sh
cargo run -p registry-manifest-cli -- validate profiles/example-civil-registration/fixtures/metadata.yaml
```

Render one artifact:

```sh
cargo run -p registry-manifest-cli -- render profiles/example-civil-registration/fixtures/metadata.yaml --format bregdcat-ap
```

Publish a static metadata directory:

```sh
cargo run -p registry-manifest-cli -- publish profiles/example-civil-registration/fixtures/metadata.yaml --out target/metadata/public
```

The generated bundle uses `/metadata/index.json` as its canonical metadata
entry point. When the output directory is mounted as `/metadata`, the publisher
also writes `/.well-known/api-catalog` at the public root for standards-aligned
API and metadata discovery. The older `/.well-known/registry-manifest.json`
document is retained for compatibility with early Registry Manifest clients.

Workspace build:

```sh
cargo build --workspace --all-targets
```

## Supported Render Formats

`registry-manifest render` supports:

- `catalog`
- `evidence-offerings`
- `evidence-offering` with `--offering <id>`
- `policies`
- `policy` with `--dataset <id>`
- `dcat`
- `bregdcat-ap`
- `cpsv-ap`
- `shacl`
- `json-schema` with `--dataset <id> --entity <name>`
- `ogc-records`

## Boundary

This repository must stay portable. `registry-manifest-core` must not depend on Registry Relay, Evidence Server, Axum, DataFusion, Postgres, auth, audit, observability, runtime row access, secret handling, `utoipa`, or `clap`.

Registry Relay may publish these artifacts over HTTP and scope them for callers, but those runtime concerns stay outside this repository.
