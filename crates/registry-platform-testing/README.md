# registry-platform-testing

Shared fixtures and assertions for registry-platform consumers.

This crate is test-only. It fails to compile unless callers enable the
`test-utils` feature, and it should appear only in `[dev-dependencies]`.

## What It Provides

- `MockIdp`, an in-process OIDC issuer with discovery, JWKS, token minting, and
  key rotation.
- `TestAuthorizationServer` (feature `test-authorization-server`), an
  in-process authorization server with the authorization-code, client
  credentials, and token-exchange grants.
- `MockHttpUpstream`, a WireMock-backed upstream with request-size tracking.
- Ed25519 JWK fixtures for signing and verification tests.
- `assert_chain_integrity` for internally consistent audit envelope assertions.
- `assert_json_absent_strings` for focused audit non-leak checks over JSON
  records.
- `oidc_verifier_config` for a standard EdDSA test verifier configuration.
- Provider-backed Ed25519 signer and JWKS helpers for tests that exercise the
  production signing abstraction.

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

### `TestAuthorizationServer`

In-process OAuth 2.0 authorization server, behind the
`test-authorization-server` feature. It serves OIDC discovery, RFC 8414
metadata, a JWKS, `/authorize`, and `/token` over loopback HTTP, and issues RFC
9068 `at+jwt` access tokens signed with the Ed25519 fixture key.

- `/authorize` runs the authorization-code grant with PKCE S256 only. Redirect
  URIs match exactly. It is test-only: nobody signs in, and the code is issued
  for the `login_hint` subject, else for the builder's `logged_in_subject`,
  else the flow ends with `login_required`.
- `/token` accepts `authorization_code` (one-time codes, PKCE verified),
  `client_credentials`, and RFC 8693 token exchange. Confidential clients
  authenticate with `private_key_jwt` (EdDSA, ES256, ES384, RS256, or RS384,
  selected by `kid`, each assertion `jti` accepted once); public clients send
  only `client_id` and may use only the authorization-code grant.
- A token exchange takes an access-token subject this server issued and has
  not expired, an optional actor token that must be the exchanging client's
  own `client_credentials` token, and exactly one `resource` the client is
  allowed. Requested scopes must be a subset of the subject token's. The issued
  token names the subject's `sub`, the client in `azp` and `client_id`, the
  resource as a single-string `aud`, and expires no later than the subject
  token.
- `ExchangeProfile::Conformant` (the default) issues `act = {"sub": ...}` and
  the exchanging client's `registry_actor_kind`.
  `ExchangeProfile::IssuerQualifiedActor` issues `act = {"sub": ..., "iss":
  ...}` and copies `registry_actor_kind` from the subject token, a shape some
  deployed servers emit.

Register clients with `TestClient::new(id)` plus `with_public_jwk`,
`with_redirect_uri`, `with_resource`, `with_actor_kind`, `with_token_lifetime`,
and `with_service_subject`. `verifier_config(audiences)` returns a
`registry-platform-oidc` verifier configuration that accepts the server's
access tokens, and `issue_access_token` signs one directly, with a
caller-chosen expiry, for refusal tests.

### `MockExpectation<'a>`

Builder returned by `MockHttpUpstream::expect(method, path)`. Wire up the
response with:
- `respond(ResponseTemplate)` — arbitrary WireMock response.
- `respond_status(u16)` — status only.
- `respond_json(u16, Value)` — JSON body.
- `respond_body(u16, bytes)` — raw bytes.

Also tracks request body size (used by `assert_max_request_bytes`).

### `ChainAssertionError`

Type alias for `registry_platform_audit::ChainVerificationError`. Exported here
so test code only needs to import from this crate.

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

## Fixture Notes

- Fixtures are deterministic and intended for tests only.
- `MockIdp::rotate_key` switches JWKS output to a second Ed25519 key.
- `MockHttpUpstream::assert_max_request_bytes` is useful for verifying upload
  and proxy boundaries.
- `wiremock_server` exposes the underlying server when tests need custom
  matchers beyond the convenience API.

## Testing

```sh
cargo test -p registry-platform-testing --features test-utils
cargo test -p registry-platform-testing --all-features
```

The crate also owns a cross-crate integration test that exercises middleware,
OIDC, and audit behavior together.

## License

Apache-2.0.
