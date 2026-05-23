# registry-relay Development Guide

This guide is for contributors working on the gateway codebase. Operator docs live in [ops.md](ops.md), [configuration.md](configuration.md), [api.md](api.md), [metadata.md](metadata.md), [evidence-verification.md](evidence-verification.md), and [provenance.md](provenance.md).

## Local Setup

Install the pinned toolchain and fetch dependencies:

```sh
just setup
```

Build the release binary:

```sh
just build
```

Run with the canonical example config:

```sh
mkdir -p data
cp fixtures/example_social_registry.xlsx data/social_registry.xlsx
export PROGRAM_SYSTEM_API_KEY_HASH='sha256:<64 lowercase hex chars>'
export STATS_OFFICE_API_KEY_HASH='sha256:<64 lowercase hex chars>'
export VERIFICATION_SERVICE_API_KEY_HASH='sha256:<64 lowercase hex chars>'
just run
```

For richer local flows, use the demo pack in [../demo/README.md](../demo/README.md).

## Verification Commands

Use the project recipes when possible:

```sh
just fmt-check
just lint
just test
just build
just deny
```

`just ci` runs the full local gate. For focused iteration, run the narrow Rust test first, then at least the closest broader check before finishing.

Useful focused examples:

```sh
cargo test --test auth_flow
cargo test --test catalog_entity
cargo test --features ogcapi-records --test ogc_records_api
cargo test --test api_docs
cargo test provenance
```

Portable metadata checks are separate from the Relay runtime:

```sh
just metadata-validate profiles/example-civil-registration/fixtures/metadata.yaml
just metadata-validate-profiles
cargo test --test demo_configs_load
```

`just metadata-*` recipes use an installed `registry-metadata` binary when one
is present, a sibling checkout during local development, or the published
`https://github.com/jeremi/registry-manifest` tag configured by
`scripts/run_registry_metadata_cli.sh`.

The demo runtime configs are split-backed: every `demo/config/*.yaml` points
at a sibling `*.metadata.yaml` manifest, and `demo_configs_load` validates the
runtime bindings against those manifests. Keep [metadata.md](metadata.md)
current when changing the manifest model, renderer outputs, publication layout,
or `/metadata/*` routes.

Render static artifacts during metadata work:

```sh
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml catalog target/metadata/catalog.json
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml dcat target/metadata/dcat.jsonld
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml shacl target/metadata/shacl.jsonld
just metadata-render profiles/example-civil-registration/fixtures/metadata.yaml json-schema target/metadata/person.schema.json "--dataset vital-events --entity person"
just metadata-publish profiles/example-civil-registration/fixtures/metadata.yaml target/metadata/public
```

DCAT-AP catalog validation runs at two levels:

```sh
REGISTRY_RELAY_RUN_EXTERNAL_SHACL=1 \
  cargo test --test catalog_entity generated_catalog_can_run_external_shacl_validation_when_enabled
```

The CI workflow also exports a sample catalog and validates it with the
local SHACL smoke profile. For a manual external check against the
European Commission SEMIC validator, run:

```sh
just validate-catalog-semic catalog=target/dcat-ap/metadata.bregdcat-ap.jsonld
```

or trigger the `dcat-ap-external-validation` GitHub Actions workflow.
The default external profile is `dcatap.3_0_1_base`.

For offline diagnostics against the vendored SEMIC SHACL resources, run:

```sh
just validate-catalog-semic-local catalog=target/dcat-ap/metadata.bregdcat-ap.jsonld
```

The local recipe defaults to `bregdcatap.2_1_0` and is a compatibility/gap
check only. Keep the external SEMIC recipe as the release validation signal.

## Coverage Metrics

Use `cargo-llvm-cov` when you need quantitative coverage metrics to complement the qualitative test review:

```sh
cargo install cargo-llvm-cov
rustup component add llvm-tools-preview
cargo llvm-cov --all-features --json --summary-only --output-path target/llvm-cov-summary.json
```

The summary report is written under ignored `target/` artifacts. For a quick local refresh after an instrumented coverage build already exists, add `--no-clean` to reuse compiled coverage artifacts:

```sh
cargo llvm-cov --all-features --json --summary-only --output-path target/llvm-cov-summary.json --no-clean
```

If a Homebrew-managed Rust toolchain cannot find `llvm-cov` or `llvm-profdata`, install Homebrew LLVM and point `cargo-llvm-cov` at it explicitly:

```sh
brew install llvm
LLVM_COV="$(brew --prefix llvm)/bin/llvm-cov" \
LLVM_PROFDATA="$(brew --prefix llvm)/bin/llvm-profdata" \
cargo llvm-cov --all-features --json --summary-only --output-path target/llvm-cov-summary.json
```

External-service tests remain ignored unless their required environment is configured, such as `DATA_GATE_POSTGRES_TEST_URL` for PostgreSQL and the Zitadel OIDC variables documented in [configuration.md](configuration.md#oidc-oauth2).

## Project Layout

```text
src/api/          HTTP handlers and route-local helpers
src/audit/        audit records, sinks, redaction, hash chaining
src/auth/         auth trait, API-key provider, scope checks
src/config/       YAML model, loader, validation, provenance config
src/entity/       entity registry built from config
src/format/       CSV, XLSX, and Parquet decoders
src/ingest/       source ingest, cache layout, refresh, readiness
src/metadata/     Relay adapters for scoped metadata publication
src/provenance/   VC-JWT issuance, DID Web, schemas, contexts, signers
src/query/        entity and aggregate query planning
src/server.rs     router composition and cross-cutting middleware
profiles/        ecosystem profile descriptors and fixture metadata manifests
```

Portable metadata crates live in the public
`https://github.com/jeremi/registry-manifest` repository. Relay consumes
`registry-manifest-core` as a tagged Git dependency and shells out to
`registry-manifest-cli` only for local validation, rendering, and static
publication helper recipes.

Storage tables are private. Public routes must go through entity config, scope checks, audit, and query planning.

## Change Guidelines

- Keep the public URL space entity-shaped. Do not expose table ids in data-plane paths.
- Add config fields through `src/config/mod.rs` and validation in `src/config/validate.rs`.
- Keep portable metadata in the split `registry-manifest-core` crate; it must not depend on Relay runtime, Axum, DataFusion, auth, scopes, OpenAPI, or connector code.
- Keep auth scopes independent. Metadata, rows, evidence verification, aggregate, and admin must not imply one another.
- Treat audit as a product surface. New routes should populate endpoint kind, dataset/entity/table ids, purpose, row count, suppression count, and stable error code when applicable.
- Prefer structured parsers and DataFusion expressions over string-built query logic.
- Do not log raw keys, fingerprints, private JWKs, row values, or full environment dumps.
- For user-visible API behavior, update [api.md](api.md) and focused integration tests in the same change.
- For operator-visible config behavior, update [configuration.md](configuration.md), [ops.md](ops.md), and config-loader tests.
- For portable metadata behavior, update [metadata.md](metadata.md), metadata-core tests, and split config binding tests.

## Adding An Endpoint

1. Add the route handler under `src/api/`.
2. Mount it in `src/api/mod.rs` and `src/server.rs` on the correct public, protected, or admin surface.
3. Enforce the exact scope needed for the operation.
4. Ensure audit fields are populated and sensitive inputs are redacted.
5. Add OpenAPI coverage in `src/api/openapi.rs` when the endpoint is public.
6. Add focused tests for success, missing auth, wrong scope, and malformed input.
7. Update [api.md](api.md) if clients need to know about the behavior.

## Adding Config

1. Add the serde model to `src/config/mod.rs` or `src/config/provenance.rs`.
2. Add validation in `src/config/validate.rs`.
3. Update `config/example.yaml` only when the field is part of the canonical example.
4. Add positive and negative loader tests under `tests/config_loader.rs` or a focused test file.
5. Update [configuration.md](configuration.md) and [ops.md](ops.md) when operators must set or rotate it.

## Documentation Style

Docs should describe the current supported behavior first, then any reserved or deferred surfaces. Keep `README.md`, `docs/api.md`, `docs/configuration.md`, `docs/evidence-verification.md`, and `docs/ops.md` operationally current.

Inline Rust docs should explain invariants and boundaries that are easy to break while editing. Avoid comments that repeat obvious field names or preserve obsolete implementation scaffolding after the code has matured.
