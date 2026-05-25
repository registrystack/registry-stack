# registry-platform-oidc

OIDC discovery, JWKS caching, and JWT verification for registry services.

## What It Provides

- Discovery document fetch and validation.
- JWKS fetching with positive cache, bounded negative `kid` cache,
  singleflight refreshes, and forced refresh cooldowns.
- Fetch URL policy integration through `registry-platform-httputil`.
- JWT verification with issuer, audience, algorithm, `typ`, `kid`, time, client,
  and scope handling.
- Scope mapping for translating provider scopes into platform permissions.

## Typical Use

```rust
use std::{sync::Arc, time::Duration};

use jsonwebtoken::Algorithm;
use registry_platform_oidc::{
    fetch_discovery, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig,
    TokenVerifier, TokenVerifierConfig,
};

async fn build_verifier() -> Result<TokenVerifier, Box<dyn std::error::Error>> {
let discovery = fetch_discovery(
    &OidcDiscoveryConfig {
        issuer: "https://issuer.example".to_string(),
        jwks_uri_override: None,
        discovery_timeout: Duration::from_secs(5),
        max_doc_bytes: 1024 * 1024,
    },
)
.await?;

let fetcher = Arc::new(JwksFetcher::new(
    discovery.jwks_uri,
    JwksFetcherConfig::defaults(),
));

let verifier = TokenVerifier::new(
    TokenVerifierConfig {
        issuer: "https://issuer.example".to_string(),
        audiences: vec!["registry-api".to_string()],
        allowed_algorithms: vec![Algorithm::EdDSA],
        allowed_typ: vec!["JWT".to_string()],
        scope_claim: "scope".to_string(),
        scope_separator: ' ',
        scope_map: None,
        allowed_clients: vec!["registry-client".to_string()],
        leeway: Duration::from_secs(60),
    },
    fetcher,
);

Ok(verifier)
}
```

## Security Notes

- `fetch_discovery` and `JwksFetcher::new` use `FetchUrlPolicy::strict`.
- Use `*_with_policy` constructors only for tests or controlled local
  development.
- Discovery, returned JWKS URI validation, and JWKS refreshes are bound by the
  configured timeout, including DNS validation.
- Allowed algorithms and token types must be explicit. Keep `allowed_algorithms`
  as narrow as the provider allows.
- `kid` values are capped generously and unknown `kid` entries are evicted from
  the negative cache to keep issuer compatibility without unbounded memory use.
  Negative `kid` entries are retried after the forced-refresh cooldown so real
  provider key rotations are not blocked for the full negative-cache TTL.
- If `allowed_clients` is set, `azp` takes precedence over `client_id`; `sub` is
  never used as a client identity.
- Store replay state, authorization decisions, and tenant boundaries in the
  consuming service.

## Testing

```sh
cargo test -p registry-platform-oidc
```

## License

Apache-2.0.
