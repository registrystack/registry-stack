# Registry Manifest

> **Experimental:** This codebase is under active development. Its APIs are evolving quickly and may be unstable.

Release label: pre-1.0 technical release for evaluation and integration pilots.

Registry Manifest is the commons contract and schema kernel for registry
metadata. It is a portable set of Rust crates for modeling, validating, and
rendering standards-facing registry metadata without running Registry Relay.

It owns metadata manifests, compiled metadata models, validation, vocabulary prefix expansion, and pure renderers for catalog JSON, DCAT JSON-LD, BRegDCAT-AP JSON-LD, CPSV-AP JSON-LD, SHACL, JSON Schema Draft 2020-12, form JSON Schema, OGC API Records item collections, policy documents, evidence-offering metadata, embedded SKOS-shaped codelist metadata, and public federation metadata for Registry Notary delegated evaluation.

## Monorepo layout

- [`crates/registry-manifest-core`](../../crates/registry-manifest-core/README.md):
  manifest contracts, validation, compilation, and renderers.
- [`crates/registry-manifest-cli`](../../crates/registry-manifest-cli/README.md):
  command-line validation, rendering, static publication, and profile fixture validation.
- `profiles/`: non-normative profile descriptors and metadata fixtures.
- `examples/`: runnable static publication examples and notes.
- `docs/`: repository-level design and release notes.

The checked-in profiles are examples until reviewed against official OpenCRVS, OpenSPP, OpenIMIS, SP DCI, or maintainer-provided artifacts.

## Commands

Run these commands from `products/manifest` in the Registry Stack monorepo.
Cargo discovers the root workspace from this directory. Root CI runs the same
Manifest tests and profile-fixture validation as part of the workspace gate.

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
cargo test --locked -p registry-manifest-core
```

CLI tests:

```sh
cargo test --locked -p registry-manifest-cli
```

Validate profile descriptors and fixtures:

```sh
cargo run --locked -p registry-manifest-cli -- validate-profiles profiles
```

Validate a metadata manifest:

```sh
cargo run --locked -p registry-manifest-cli -- validate profiles/example-civil-registration/fixtures/metadata.yaml
```

Render one artifact:

```sh
cargo run --locked -p registry-manifest-cli -- render profiles/example-civil-registration/fixtures/metadata.yaml --format bregdcat-ap
```

Publish a static metadata directory:

```sh
cargo run --locked -p registry-manifest-cli -- publish profiles/example-civil-registration/fixtures/metadata.yaml --out target/metadata/public
```

The generated bundle uses `/metadata/index.json` as its canonical metadata
entry point. When the output directory is mounted as `/metadata`, the publisher
also writes `/.well-known/api-catalog` at the public root for standards-aligned
API and metadata discovery. The older `/.well-known/registry-manifest.json`
document is retained for compatibility with early Registry Manifest clients.
The index records the canonical `source_manifest_digest`, package-level digest,
and per-artifact SHA-256 digests operators can use to compare published bundles.

Workspace build:

```sh
cargo build --workspace --all-targets
```

Commons contract-kernel check:

```sh
scripts/check-contract-kernel.sh
```

Consumer manifests can be passed as arguments. Each file is validated and
published into `target/contract-kernel/` so Relay, Notary, and adopter demos can
exercise the same schema and renderer contract before a commons release:

```sh
SOLMARA_LAB_DIR=/path/to/solmara-lab
scripts/check-contract-kernel.sh "$SOLMARA_LAB_DIR/metadata/solmara-wave1.metadata.yaml"
```

Optional ITB/SEMIC smoke check for selected DCAT and BRegDCAT-AP artifacts:

```sh
scripts/itb-semic-smoke.sh
ITB_SEMIC_REMOTE=1 scripts/itb-semic-smoke.sh
```

See [ITB/SEMIC validation smoke checks](docs/itb-semic-validation.md) for the
claim boundary and known BRegDCAT-AP warning behavior.

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
- `form-json-schema` with `--form <id>`
- `ogc-records`

## Registry Notary Federation Metadata

Registry Manifest can publish public metadata that helps a partner configure the
Registry Notary delegated-evaluation MVP:

- top-level `federation` metadata with `node_id`, `issuer`, `jwks_uri`,
  `federation_api`, and `supported_protocol_versions`;
- top-level `evaluation_profiles` that bind public profile IDs and `ruleset`
  IDs to Notary claim IDs and subject ID types, optionally with `evidence_pack`
  policy identity metadata;
- top-level `ecosystem_bindings` that publish governed evidence binding IDs,
  versions, profiles, and ODRL enforcement metadata for runtime PDP selection;
- `registry-notary` evidence offerings whose `access.ruleset` references one
  of those evaluation profile rulesets.

This metadata is discovery and documentation only. It does not grant runtime
access; the serving Notary still enforces its local `federation.peers` policy,
request signature checks, purpose allowlist, replay protection, and audit
behavior.

## Boundary

Registry Manifest must stay portable. `registry-manifest-core` must not depend on
Registry Relay, Registry Notary, Axum, DataFusion, Postgres, auth, audit,
observability, runtime row access, secret handling, `utoipa`, or `clap`.

Registry Relay may publish these artifacts over HTTP and scope them for callers, but those runtime concerns stay outside this repository.
