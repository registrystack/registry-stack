# Standards Adapter Operator Guide

Registry Relay's standards adapters are optional views over the same protected
dataset and entity model. They do not create new authorization bypasses, source
systems, or write APIs.

Use this guide as the adapter checklist. The detailed configuration fields live
in [configuration.md](configuration.md), and the HTTP behavior lives in
[api.md](api.md).

## Common Rules

For every adapter:

- Build the binary with the required Cargo feature.
- Configure the underlying dataset, entity, scopes, and metadata first.
- Keep source data read-only.
- Confirm adapter routes use the same scopes as the native Relay capability
  they expose.
- Include purpose headers where the underlying entity requires them.
- Test both allowed and denied callers.
- Treat generated standards payloads as views of Relay's runtime model, not as
  separate source-of-truth records.

## OGC API Features

Purpose: expose configured spatial entities as protected GeoJSON Features.

Enablement:

```sh
cargo build --features ogcapi-features
```

Operator checklist:

- Configure `spatial` on each entity that should appear as a collection.
- Use CRS84 coordinates.
- Prefer point fields or existing GeoJSON fields for V1.
- Grant `metadata_scope` for discovery and `read_scope` for feature items.
- Preserve required filters and `Data-Purpose` expectations from the entity.
- Validate that `bbox` and `datetime` behavior matches the configured fields.

Do not use this adapter to publish open geospatial data unless the Relay auth
and metadata policy explicitly allow that audience.

## OGC API Records

Purpose: expose a metadata-only catalog view for visible datasets.

Enablement:

```sh
cargo build --features ogcapi-records
```

Operator checklist:

- Ensure portable metadata has useful titles, descriptions, publisher fields,
  themes, keywords, profiles, and contact points.
- Grant only `metadata_scope` to catalog consumers that do not need rows.
- Confirm records do not include row data, source paths, secrets, private table
  ids, or runtime backend URLs.
- Validate the Records output against the deployment's catalog expectations.

The Records adapter is not a search engine over registry rows.

## OGC API EDR

Purpose: expose configured `admin_area` spatial aggregates through an
Environmental Data Retrieval-style area interface.

Enablement:

```sh
cargo build --features ogcapi-edr
```

Operator checklist:

- Configure aggregates before enabling the adapter.
- Use aggregate scopes for data retrieval and metadata scopes for discovery.
- Confirm disclosure controls are acceptable for area queries.
- Test temporal bounds only on aggregates that declare a temporal field.
- Validate geometry coverage and administrative area identifiers with the
  consuming GIS team.

EDR responses are aggregate views. They must not become a way to enumerate
individual entity records.

## SP DCI Sync

Purpose: expose configured entities through SP DCI sync-search style APIs.

Enablement:

```sh
cargo build --features spdci-api-standards
```

Use `standards-cel-mapping` as well when a registry entry uses CEL response
mapping.

Operator checklist:

- Configure `standards.spdci.registries` entries for each named registry.
- Configure `standards.spdci.disability_registry` only when disability-specific
  routes should resolve.
- Confirm generic search uses the entity read scope.
- Confirm disability status checks use the entity evidence-verification scope.
- Document which SP DCI APIs are intentionally unsupported.
- Test with the Bruno or demo fixtures before exposing the adapter to another
  system.

The async search, subscribe, callback, and transaction-status APIs are out of
scope for the current sync adapter.

## PublicSchema VC Mapping

Purpose: map Relay entity-record provenance credentials to PublicSchema-shaped
credential subjects.

Enablement:

```sh
cargo build --features publicschema-cel
```

Operator checklist:

- Enable provenance first.
- Configure the entity `provenance.publicschema` mapping.
- Validate the mapping against the target PublicSchema JSON Schema.
- Confirm the VC contains only fields intended for downstream disclosure.
- Keep mapping files under review with the schema version they target.

PublicSchema mapping changes are contract changes for credential consumers.
Version and test them like API changes.

## Verification Commands

Focused adapter checks:

```sh
cargo test --all-features --test ogc_api --test ogc_records_api --test ogc_edr_api
cargo test --all-features --test spdci_api_standards --test publicschema_cel_feature
```

Broader local gate:

```sh
just lint
just test
```
