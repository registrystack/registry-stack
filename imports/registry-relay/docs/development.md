# registry-relay Development Guide

This guide is for contributors working on the gateway codebase. Operator docs live in [ops.md](ops.md), [configuration.md](configuration.md), [api.md](api.md), and [provenance.md](provenance.md).

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
cargo test --test api_docs
cargo test provenance
```

## Project Layout

```text
src/api/          HTTP handlers and route-local helpers
src/audit/        audit records, sinks, redaction, hash chaining
src/auth/         auth trait, API-key provider, scope checks
src/config/       YAML model, loader, validation, provenance config
src/entity/       entity registry built from config
src/format/       CSV, XLSX, and Parquet decoders
src/ingest/       source ingest, cache layout, refresh, readiness
src/metadata/     catalog, DCAT-AP, and SHACL metadata
src/provenance/   VC-JWT issuance, DID Web, schemas, contexts, signers
src/query/        entity and aggregate query planning
src/server.rs     router composition and cross-cutting middleware
```

Storage tables are private. Public routes must go through entity config, scope checks, audit, and query planning.

## Change Guidelines

- Keep the public URL space entity-shaped. Do not expose table ids in data-plane paths.
- Add config fields through `src/config/mod.rs` and validation in `src/config/validate.rs`.
- Keep auth scopes independent. Metadata, rows, verify, aggregate, bulk export, and admin must not imply one another.
- Treat audit as a product surface. New routes should populate endpoint kind, dataset/entity/table ids, purpose, row count, suppression count, and stable error code when applicable.
- Prefer structured parsers and DataFusion expressions over string-built query logic.
- Do not log raw keys, fingerprints, private JWKs, row values, or full environment dumps.
- For user-visible API behavior, update [api.md](api.md) and focused integration tests in the same change.
- For operator-visible config behavior, update [configuration.md](configuration.md), [ops.md](ops.md), and config-loader tests.

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

Docs should describe the current supported behavior first, then any reserved or deferred surfaces. Keep `README.md`, `docs/api.md`, `docs/configuration.md`, and `docs/ops.md` operationally current.

Inline Rust docs should explain invariants and boundaries that are easy to break while editing. Avoid comments that repeat obvious field names or preserve obsolete implementation scaffolding after the code has matured.
