# registry-notary-core

Portable Registry Notary domain model, configuration, and credential
primitives.

This crate owns the serializable contracts shared by the server, binary, tests,
and downstream tooling.

## What It Provides

- Standalone Registry Notary configuration types and validation.
- Claim, subject, source binding, disclosure, and evaluation models.
- Static-peer federation config models, validation constants, and audit fields
  for delegated evaluation.
- Error types used across the workspace.
- SD-JWT VC issuance helpers for claim views.
- OpenAPI-compatible schema derives for public contract types.

## Typical Use

```rust
use registry_notary_core::StandaloneRegistryNotaryConfig;

fn load(raw_yaml: &str) -> Result<StandaloneRegistryNotaryConfig, Box<dyn std::error::Error>> {
    let config: StandaloneRegistryNotaryConfig = serde_norway::from_str(raw_yaml)?;
    config.validate()?;
    Ok(config)
}
```

## Boundary

This crate is runtime-neutral. It should not own Axum routes, outbound HTTP
clients, tracing setup, process startup, or storage for evaluated evidence.

## Testing

```sh
cargo test -p registry-notary-core
```

## License

Apache-2.0.
