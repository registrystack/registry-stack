# registry-witness-server

Standalone Registry Witness runtime, API routes, auth, audit, source connectors,
renderers, and credential issuance wiring.

## What It Provides

- Axum routers for the Registry Witness API.
- Runtime claim evaluation with dependency ordering and batch memoization.
- HTTP Registry Data API and DCI source connectors.
- API-key and bearer-token auth through `registry-platform` primitives.
- Redacted audit event emission.
- JSON, SD-JWT VC, and credential response renderers.
- OpenAPI document generation.

## Typical Use

```rust
use registry_witness_core::StandaloneRegistryWitnessConfig;
use registry_witness_server::{standalone_router, StandaloneServerError};

fn app(config: StandaloneRegistryWitnessConfig) -> Result<axum::Router, StandaloneServerError> {
    standalone_router(config)
}
```

## Features

- Default: `registry-witness-cel`.
- `registry-witness-cel`: enables CEL-backed claim expression evaluation through
  `cel-mapper-core`.

Run server tests without default features when checking the non-CEL binary
shape:

```sh
cargo test -p registry-witness-server --no-default-features
```

## Security Notes

- The server starts fail-closed when credentials are missing or invalid.
- Source connectors send explicit purpose headers and use configured source
  tokens.
- Replay persistence and deployment-grade retention remain consumer and
  operator responsibilities.

## Testing

```sh
cargo test -p registry-witness-server --no-default-features
cargo test -p registry-witness-server --all-features
```

## License

Apache-2.0.
