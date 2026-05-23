# Relay Metadata Core Integration Map

> **Note:** the external crate is now published as `registry-manifest-core`. This document was written when it was called `registry-metadata-core`; the old name is preserved in the body for historical accuracy. The filename is left unchanged to keep links stable.

Status: implemented in the metadata runtime split branch.

This map records Relay integration points used by the split metadata runtime
work. `registry-metadata-core` now exposes concrete manifest, compiled metadata,
validation, and renderer APIs consumed by Relay through a small adapter.

## Current Relay Flow

- `src/config/loader.rs` loads and validates the operational Relay YAML into
  `config::Config`.
- `src/entity/mod.rs` compiles runtime entity state with
  `EntityRegistry::from_config(&Config)`.
- `src/api/metadata.rs` scopes visible metadata by the caller's metadata scopes,
  then renders the canonical `/metadata/*` surfaces through
  `registry-metadata-core`.
- `src/api/datasets.rs` builds dataset summaries directly from `Config` and
  caller scopes.
- `src/metadata/catalog.rs` joins `Config` and `EntityRegistry` into the current
  Relay catalog model, including runtime links and feature-gated standards
  metadata.
- `src/metadata/shacl.rs` renders DCAT-AP, SHACL shapes, and entity schema JSON
  from the current catalog model.
- `src/api/openapi.rs` remains Relay-owned because route assembly, security, and
  runtime features are not portable metadata concerns.

## Safe Adapter Boundary

Once core exposes a real API, add a Relay-owned adapter rather than moving
runtime types into core:

- Suggested module: `src/metadata/core_adapter.rs`.
- Inputs: `&Config`, `&EntityRegistry`, and a caller-scoped set of visible
  `(dataset_id, entity_name)` pairs.
- Output: the core compiled or renderer-ready metadata type, plus Relay-owned
  runtime link templates added after compilation.
- Error mapping: core manifest errors should map to `metadata.manifest.*`;
  Relay binding errors should stay in Relay as `runtime.binding.*`.

The adapter should validate that runtime bindings reference compiled metadata
datasets, entities, fields, and filters. It must not pass source paths, table
ids, backend URLs, auth scopes, required runtime filters, or audit policy into
portable core renderers.

## Implemented Wiring

Implemented in this branch:

1. Added the dependency to `Cargo.toml` for `registry-relay`.
2. Added `src/metadata/core_adapter.rs`.
3. Kept the standards-facing `/metadata/*` route auth checks Relay-owned and
   removed the old public `/catalog` aliases.
4. Replaced only the pure metadata construction inside `src/metadata/catalog.rs`
   and `src/metadata/shacl.rs` with calls through the adapter.
5. Left OpenAPI, OGC HTTP routes, entity row routes, auth, audit, cache, and
   ETag behavior Relay-owned.

## Tests To Update First

- `tests/catalog_entity.rs`: catalog, DCAT, SHACL, visibility, and feature-gated
  standard metadata expectations.
- `tests/config_loader.rs` and `tests/config_entities.rs`: binding validation
  failures once metadata manifests are separate from relay config.
- `tests/ogc_records_api.rs`: OGC Records should consume portable record bodies
  when core exposes them, while Relay keeps HTTP links and pagination.
- `tests/error_taxonomy.rs`: add `runtime.binding.*` variants only when Relay
  actually maps those failures.

## Historical Blocker

Earlier exploration found only a placeholder `crates/registry-metadata-core`.
That blocker is resolved in this branch: the crate now includes `src/lib.rs`,
manifest types, compiled metadata types, renderer functions, validation, and an
error API.
