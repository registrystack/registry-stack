# registry-manifest-core

Portable metadata contracts, validators, compilers, and renderers for registry
catalogs.

This crate is the source of truth for metadata manifests. It stays independent
of Registry Relay runtime concerns so static publishers, CLIs, and services can
share the same metadata model.

## What It Provides

- Manifest structs for catalogs, datasets, entities, fields, policies,
  codelists, requirements, profiles, and evidence offerings.
- Strict validation with unknown-field rejection through Serde.
- Manifest compilation into lookup-friendly metadata models.
- Pure renderers for catalog JSON, DCAT JSON-LD, BRegDCAT-AP JSON-LD, SHACL,
  JSON Schema Draft 2020-12, OGC API Records items, policies, and evidence
  offerings.

## Typical Use

```rust
use registry_manifest_core::{compile_manifest, render_catalog, MetadataManifest};

fn render(manifest: &MetadataManifest) -> Result<serde_json::Value, registry_manifest_core::MetadataError> {
    let compiled = compile_manifest(manifest)?;
    Ok(render_catalog(&compiled))
}
```

## Boundary

This crate must remain portable. It must not depend on Registry Relay, Axum,
DataFusion, Postgres, auth, audit, observability, runtime row access, secret
handling, `utoipa`, or `clap`.

## Testing

```sh
cargo test -p registry-manifest-core
```

## License

Apache-2.0.
