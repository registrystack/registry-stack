# registry-platform-testing

Shared fixtures and assertions for registry-platform consumers.

## What It Provides

- `MockIdp`, an in-process OIDC issuer with discovery, JWKS, token minting, and
  key rotation.
- `MockHttpUpstream`, a WireMock-backed upstream with request-size tracking.
- Ed25519 JWK fixtures for signing and verification tests.
- `assert_chain_integrity` for internally consistent audit envelope assertions.
- `assert_chain_integrity_with_anchors` for retained chains or checks that must
  be bound to a trusted start or tail hash.
- `assert_replay_duplicate_rejected` for reusable replay-store duplicate checks.
- `oidc_verifier_config` for a standard EdDSA test verifier configuration.
- Federation fixture helpers for building signed Witness request/response JWTs.
- Provider-backed Ed25519 signer and JWKS helpers for tests that exercise the
  production signing abstraction.
- `sign_openid4vci_proof_jwt` for building OID4VCI holder proof JWTs in tests.

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

## Public Items

### `MockIdp`

In-process OIDC issuer. Key methods:
- `start()` — bind a random port, spawn the server.
- `issuer()` — base URL string.
- `discovery_url()` — `{issuer}/.well-known/openid-configuration` URL string;
  useful when wiring test OIDC config that reads discovery from a URL.
- `jwks_uri()` — `{issuer}/jwks.json` URL string.
- `mint_token(claims)` — sign a JWT with the current key and default claim
  normalization (`iss`, `iat`, `nbf`, `exp`).
- `rotate_key()` — switch to the second fixture key, simulating a key rollover.
- `stop()` — graceful shutdown.

### `MockExpectation<'a>`

Builder returned by `MockHttpUpstream::expect(method, path)`. Wire up the
response with:
- `respond(ResponseTemplate)` — arbitrary WireMock response.
- `respond_status(u16)` — status only.
- `respond_json(u16, Value)` — JSON body.
- `respond_body(u16, bytes)` — raw bytes.

Also tracks request body size (used by `assert_max_request_bytes`).

### `ChainAssertionError` and `ChainAssertionAnchors`

Type aliases for `registry_platform_audit::ChainVerificationError` and
`registry_platform_audit::ChainVerificationAnchors`. Exported here so test
code only needs to import from this crate.

### `ReplayAssertionError`

Error type returned by `assert_replay_duplicate_rejected`. It lets downstream
integration tests assert a `ReplayStore` accepts the first scoped key and rejects
the duplicate with `AlreadySeen`.

### JWT signing helpers

- `sign_ed25519_compact_jwt(private_jwk, typ, kid, claims)` — parse a JWK
  string then sign a compact JWT with the given `typ` and `kid`.
- `sign_ed25519_compact_jwt_with_key(private, typ, kid, claims)` — sign with
  an already-parsed `PrivateJwk`.
- `sign_ed25519_compact_jwt_with_provider(signer, typ, claims)` — sign with a
  `SigningProvider`; the JWT header `kid` is taken from the provider.
- `jwks_from_private_jwk(private)` — return `{"keys": [public]}` as a
  `serde_json::Value`; useful for mocking a JWKS endpoint.
- `jwks_from_signing_provider(signer)` — return a JWKS from provider public
  metadata, without private JWK members.
- `fixtures::ed25519_signer()` — return a `LocalJwkSigner` backed by the
  primary Ed25519 fixture key.
- `sign_openid4vci_proof_jwt(private_jwk, audience, nonce, now_unix_seconds)` —
  build an OID4VCI holder proof JWT (`typ = openid4vci-proof+jwt`) with the
  holder's `did:jwk` inline in the `jwk` header. For use in credential endpoint
  tests; **not** for production.

### Federation fixture helpers

These helpers produce deterministic JWT claim sets matching the
`registry-witness-federation/v0.1` protocol. They are intended for Witness
federation tests only; the domain knowledge is isolated here so callers don't
have to re-implement the claim layout.

- `federation_request_fixture_claims(issuer, subject_node_id, audience_node_id, now)` —
  claims for a federation evaluate request JWT.
- `federation_response_fixture_claims(issuer, subject_node_id, audience_node_id, request_jti, now)` —
  claims for a federation evaluate response JWT.

### Federation constants

| Constant | Value | Use |
|---|---|---|
| `FEDERATION_PROTOCOL` | `"registry-witness-federation/v0.1"` | `"protocol"` claim value |
| `FEDERATION_REQUEST_JWT_TYPE` | `"registry-witness-request+jwt"` | `"typ"` header for request JWTs |
| `FEDERATION_RESPONSE_JWT_TYPE` | `"registry-witness-response+jwt"` | `"typ"` header for response JWTs |
| `FEDERATION_EVALUATE_ACTION` | `"evaluate"` | `"action"` claim value |
| `FEDERATION_REQUEST_FIXTURE_JTI` | (fixed ULID string) | Deterministic `"jti"` for request fixtures |
| `FEDERATION_RESPONSE_FIXTURE_JTI` | (fixed ULID string) | Deterministic `"jti"` for response fixtures |
| `FEDERATION_FIXTURE_PROFILE` | `"disability_status_predicate"` | `"profile"` claim value |
| `FEDERATION_FIXTURE_PURPOSE` | (URL string) | `"purpose"` claim value |

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
