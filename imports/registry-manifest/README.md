# Registry Metadata

Registry Metadata is a portable Rust workspace for modeling, validating, and rendering standards-facing registry metadata without running Registry Relay.

It owns metadata manifests, compiled metadata models, validation, vocabulary prefix expansion, and pure renderers for catalog JSON, DCAT JSON-LD, BRegDCAT-AP JSON-LD, SHACL, JSON Schema Draft 2020-12, OGC API Records item bodies, policy documents, and evidence-offering metadata.

## Workspace

- `crates/registry-metadata-core`: manifest contracts, validation, compilation, and renderers.
- `crates/registry-metadata-cli`: command-line validation, rendering, static publication, and profile fixture validation.
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
cargo test -p registry-metadata-core
```

CLI tests:

```sh
cargo test -p registry-metadata-cli
```

Validate profile descriptors and fixtures:

```sh
cargo run -p registry-metadata-cli -- validate-profiles profiles
```

Validate a metadata manifest:

```sh
cargo run -p registry-metadata-cli -- validate profiles/example-civil-registration/fixtures/metadata.yaml
```

Render one artifact:

```sh
cargo run -p registry-metadata-cli -- render profiles/example-civil-registration/fixtures/metadata.yaml --format bregdcat-ap
```

Publish a static metadata directory:

```sh
cargo run -p registry-metadata-cli -- publish profiles/example-civil-registration/fixtures/metadata.yaml --out target/metadata/public
```

Workspace build:

```sh
cargo build --workspace --all-targets
```

## Supported Render Formats

`registry-metadata render` supports:

- `catalog`
- `evidence-offerings`
- `evidence-offering` with `--offering <id>`
- `policies`
- `policy` with `--dataset <id>`
- `dcat`
- `bregdcat-ap`
- `shacl`
- `json-schema` with `--dataset <id> --entity <name>`
- `ogc-records`

## Boundary

This repository must stay portable. `registry-metadata-core` must not depend on Registry Relay, Evidence Server, Axum, DataFusion, Postgres, auth, audit, observability, runtime row access, secret handling, `utoipa`, or `clap`.

Registry Relay may publish these artifacts over HTTP and scope them for callers, but those runtime concerns stay outside this repository.
