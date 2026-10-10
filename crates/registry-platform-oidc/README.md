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
- Strict extraction and client/resource binding for the shared contextual
  authorization claims.
- Typed exact task-grant status bindings and operator-pinned status clients,
  reused by Base Registry Engine (BReg) and Scheduling without runtime product
  dependencies. `TaskGrantStatusRegistry::validate_configuration` checks the
  same nonsecret structure before activation without resolving credentials or
  contacting status/token endpoints.

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

    let config = TokenVerifierConfig::access_token_profile(
        "https://issuer.example",
        vec!["registry-api".to_string()],
        vec![Algorithm::EdDSA],
        vec!["at+jwt".to_string()],
    )
    .with_allowed_clients(vec!["registry-client".to_string()])
    .with_leeway(Duration::from_secs(60));

    Ok(TokenVerifier::new(config, fetcher))
}
```

## Security Notes

- `fetch_discovery` and `JwksFetcher::new` use `FetchUrlPolicy::strict`.
- Use `*_with_policy` constructors only for tests or controlled local
  development.
- Discovery, returned JWKS URI validation, and JWKS refreshes are bound by the
  configured timeout, including DNS validation.
- Use the named profiles for access-token flows so related ID token and
  UserInfo JWT `typ` checks stay aligned. Allowed access-token algorithms and
  token types remain explicit inputs; keep `allowed_algorithms` as narrow as the
  provider allows.
- `kid` values are capped generously and unknown `kid` entries are evicted from
  the negative cache to keep issuer compatibility without unbounded memory use.
  Negative `kid` entries are retried after the forced-refresh cooldown so real
  provider key rotations are not blocked for the full negative-cache TTL.
- If `allowed_clients` is set, `azp` takes precedence over `client_id`; `sub` is
  never used as a client identity.
- Task-grant parsing is optional until any configured core grant claim is
  present. Once present, every core member, the configured approver claim, and
  both token and grant deadlines are required. Product runtimes still own
  trusted source-issuer mappings and the supported operation vocabulary.
- Grant bounds are a closed tagged union: `evidence`, `breg`, or `scheduling`.
  A verifier built before a variant existed rejects the unknown tag as a
  malformed claim, so a grant minted for one product can never be interpreted
  by another product's runtime. `SchedulingPermission` values are scoped to
  one service and location pair, carry at most 64 permissions of 32 actions,
  and never admit wildcards; their `Debug` output redacts every claim value.
- Store replay state, authorization decisions, and tenant boundaries in the
  consuming service.

### Task-grant `scheduling` bounds: review record

The `scheduling` tag was added to the closed `GrantBounds` union so a task
grant can carry the scheduling permissions a registry booking surface needs.
The four elements of the change:

- **Threat.** A grant minted for another product being replayed against a
  scheduling runtime, or a scheduling grant carrying unbounded, wildcard, or
  oversized permission content that a verifier would accept and later fail to
  enforce. The closed union answers the first: an unknown tag is a malformed
  claim for every verifier, old or new. The per-value bounds answer the
  second, and they mirror the BReg bounds exactly (64 permissions, 32 actions
  each, 512-byte service and location values, unique `(service, location)`
  pairs), so the worst case a signed claim can carry is the same
  compositional bound BReg already allows.
- **Wire format.** The claim serializes as `"scheduling": {"permissions":
  [{"service": ..., "location": ..., "actions": [...]}]}` with
  `deny_unknown_fields` at every level; unknown members are refused, not
  ignored. `SchedulingPermission` is exported from the crate root beside
  `BregPermission`, so issuers construct scheduling grants programmatically
  and relying products can name the type in their signatures.
- **Issuer and verifier compatibility.** Issuers may mint the `scheduling`
  tag only once every verifier they target understands it: a verifier built
  before this variant rejects the whole grant as malformed (fail-closed, both
  for old binaries and for products that never add scheduling support).
  Rolling a verifier back to a pre-`scheduling` build therefore hard-fails
  scheduling grants; that is the intended direction, but an operator doing a
  rollback needs to know it. The first Registry Stack release whose verifier
  accepts the tag should be recorded here when the release is cut.
- **Test evidence.** The scheduling-grant tests in `authorization_claims.rs`
  cover acceptance of a valid scheduling grant, refusal of unknown fields at
  the union and nested-struct levels, the 512/513-byte service and
  128/129-byte action boundary values, the 64-permission and 32-action
  limits, unique `(service, location)` enforcement, wildcard refusal,
  redacted `Debug` output, round-trip serialization of the tag spelling, and
  a downstream case that BReg's binding refuses a scheduling grant because it
  carries no BReg permissions.

## Testing

```sh
cargo test -p registry-platform-oidc
```

## License

Apache-2.0.

## Fresh task authorization status

`task_grant::TaskGrantStatusBinding::from_verified` captures the original
verified grant principal, client, resource, purpose, bounds, disclosed identity
subjects, and deadline. Products first enforce their own supported bounds and
claim profile. BReg retains its product-specific persisted binding and refuses
non-BReg bounds before delegating to the shared transport.

`TaskGrantStatusRegistry` pins each authority to its endpoint and the resource
server's own private-key-JWT service credential. Each `check` obtains a fresh
strict status document and compares every immutable member. Only the service
credential is cached; a positive authorization observation never is. Unknown
sources, inactive/mismatched contexts, and expired grants are refused. Outages
are unavailable. A status endpoint rejecting the resource server's service
credential with HTTP 401 or 403 also makes the observation unavailable; it does
not establish that the task grant is inactive. Concealed or missing grants
(HTTP 404) remain refused. The complete observation, including service token
acquisition, is bounded to ten seconds, with a five-second status HTTP timeout and a 64 KiB
response ceiling. Products decide when the check precedes their effects and
how failures map to their own API; the primitive owns no mutation or durable
lifecycle state.
