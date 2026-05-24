# registry-platform-testing

Shared fixtures and assertions for registry-platform consumers.

## What It Provides

- `MockIdp`, an in-process OIDC issuer with discovery, JWKS, token minting, and
  key rotation.
- `MockHttpUpstream`, a WireMock-backed upstream with request-size tracking.
- Ed25519 JWK fixtures for signing and verification tests.
- `assert_chain_integrity` for audit envelope assertions.
- `oidc_verifier_config` for a standard EdDSA test verifier configuration.

## Typical Use

```rust
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::json;

async fn configure_test_idp() -> Result<(), Box<dyn std::error::Error>> {
let idp = MockIdp::start().await;
let token = idp.mint_token(json!({
    "aud": "registry-api",
    "sub": "subject-1",
    "client_id": "client-a",
    "scope": "claims:read",
}));

let mut config = oidc_verifier_config(idp.issuer(), vec!["registry-api".to_string()]);
config.allowed_clients = vec!["client-a".to_string()];

let _ = (token, config);
idp.stop().await;
Ok(())
}
```

## Fixture Notes

- Fixtures are deterministic and intended for tests only.
- `MockIdp::rotate_key` switches JWKS output to a second Ed25519 key.
- `MockHttpUpstream::assert_max_request_bytes` is useful for verifying upload
  and proxy boundaries.
- `wiremock_server` exposes the underlying server when tests need custom
  matchers beyond the convenience API.

## Testing

```sh
cargo test -p registry-platform-testing
```

The crate also owns a cross-crate integration test that exercises middleware,
OIDC, and audit behavior together.

## License

Apache-2.0.
