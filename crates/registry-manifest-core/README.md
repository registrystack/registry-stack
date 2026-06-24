# registry-manifest-core

Portable metadata contracts, validators, compilers, and renderers for registry
catalogs. This crate is the commons contract/schema kernel used by Registry
Relay, Registry Notary metadata workflows, and Registry Lab fixtures.

This crate is the source of truth for metadata manifests. It stays independent
of Registry Relay runtime concerns so static publishers, CLIs, and services can
share the same metadata model.

## What It Provides

- Manifest structs for catalogs, datasets, entities, fields, policies,
  codelists, requirements, profiles, evidence offerings, federation metadata,
  and evaluation profiles.
- Strict validation with unknown-field rejection through Serde.
- Manifest compilation into lookup-friendly metadata models.
- Pure renderers for catalog JSON, DCAT JSON-LD, BRegDCAT-AP JSON-LD, CPSV-AP JSON-LD, SHACL,
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

Federation fields are metadata only. Runtime peer policy, request verification,
replay storage, audit emission, and source reads remain Registry Notary
responsibilities.

## Testing

```sh
cargo test -p registry-manifest-core
```

The CPSV-AP integration tests include a project contract validator named
`validate_cpsv_ap_service_first_contract`. It first parses the rendered fixture
through a JSON-LD-to-RDF parser, then checks the service-first profile contracts
that Registry Manifest relies on. This is not a replacement for official SEMIC
CPSV-AP SHACL/profile validation, which remains an external conformance check.

The service-first form profile is intentionally local. It supports validation
references, sections, repeatable sections, field cardinality, one-level
conditional visibility, fulfillment modes, and generated JSON Schema artifacts
for smoke-test payload validation.

## License

Apache-2.0.
