# registry-platform-oidc-py

Internal PyO3 binding for exact Registry Stack access-token and related ID-token
verification. The unified Python client may assemble this module; it is not a
separate published package.

`AccessTokenVerifier` fixes one issuer, resource, client, asymmetric signing
algorithm, access-token media type, clock policy and bounded set of projected
scalar claims. `verify()` returns a `VerifiedToken` and never returns or stores
the bearer. A related ID token is checked separately with an expected nonce.

The public constructor is:

```python
AccessTokenVerifier(
    issuer,
    resource,
    client_id,
    *,
    algorithm,
    maximum_access_token_lifetime_seconds,
    access_token_type="at+jwt",
    maximum_id_token_lifetime_seconds=3600,
    clock_skew_seconds=60,
    claim_names=(),
    jwks_uri=None,
    allow_insecure_http=False,
)
```

`from_static_jwks(jwks_json, issuer, resource, client_id, ...)` supplies the
same policy without network access and accepts only the platform primitive's
public asymmetric JWKS format. `verify(token)` and `verify_access_token(token)`
return immutable `VerifiedToken` objects with `kind`, `issuer`, `audiences`,
`subject`, `client_id`, `scopes`, `expires_at`, `issued_at`, `not_before`, and a
copy of the explicitly selected scalar `claims`. `verify_id_token(token,
expected_nonce)` applies the related ID-token profile and an exact nonce check.

The boundary admits one of `EdDSA`, `ES256`, `ES384`, `RS256`, or `RS384`.
Tokens are limited to 128 KiB, static JWKS documents to 256 KiB, selected claim
names to 32, audiences to 16, scopes to 256 and 32 KiB total, individual scopes
to 512 bytes, selected values and identifiers to 2 KiB, configured lifetimes to
24 hours, and clock skew to five minutes. Failures expose only the stable
`configuration`, `verification`, or `runtime` kind and a fixed message.

The wrapper verifies authentication only. Python service configuration owns
persona and profile requirements, and each Registry Stack product remains the
authority for its operations, rows and fields.
