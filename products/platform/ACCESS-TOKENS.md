# Access tokens for separate resources

You can register one OAuth client with your issuer and request separate access
tokens for each Registry Stack resource. Each resource server independently
checks its audience, admitted client, scopes and actor profile. Separate
per-resource tokens are the recommended deployment pattern. Existing bounded
multi-audience tokens remain accepted where the owning profile supports them
and includes its target audience; an additional audience alone is no refusal.
A token without the target audience grants no access to that resource.
Casework task-client profiles retain their narrower audience rules.

## Interoperable baseline

Use RFC 9068 `typ: at+jwt` and RS256 or ES256 with public asymmetric signing
keys. `application/at+jwt` is the equivalent media-type spelling accepted by
the shared verifier. Do not substitute an ID token or UserInfo JWT. Algorithms
are resource policy: Casework, Scheduling and Messaging admit RS256/ES256;
BReg keeps its one explicitly configured algorithm, including its existing
product-specific choices. Configure RS256 or ES256 for the common profile,
rather than widening every product to the union of all supported algorithms.

| Resource server | Resource and audience | Scopes and actor profile | Token type and algorithms | Lifetime and clock skew | Renewal |
|---|---|---|---|---|---|
| BReg | Request the deployment resource; token must carry its configured audience. | Selected access profile, configured scope claim/separator, `registry_actor_kind` and contextual rules. Actor kind is profile-specific. | Configured access-token type; common `at+jwt`. One configured algorithm, common RS256/ES256. | Required configured maximum 1-7200 seconds; `leewayMilliseconds` whole seconds, 0-300000 ms. | Resource server never refreshes; caller obtains a replacement token. |
| Casework | Request the Casework resource; configured audience. | `requiredScopes` in the selected Requester/Staff/Supervisor profile; scope claim defaults to `registry_scopes`. Human routes require configured `humanIdentity`, default `registry_actor_kind: human`. Task clients use their separate actor profile. | `at+jwt`, RS256/ES256. | `exp`/`nbf` enforced; optional `maximumTokenLifetimeSeconds`; zero verifier skew. | Caller obtains another per-resource token. |
| Scheduling | Request the Scheduling resource; configured audience. | Read `readsScope` (default `scheduling:read`), separate explain scope; mutations require their task-grant authority. Scope claim defaults to `scope`; actor/grant validation remains Scheduling-owned. | `at+jwt`, RS256/ES256. | `exp`/`nbf` enforced; no additional maximum lifetime or skew configured. Task grants have separate deadlines. | Caller obtains another per-resource token. |
| Messaging | Request the Messaging resource; configured audience. | One declared access profile selects clients, scopes and permitted actor kinds. Scope claim defaults to `scope`. | `at+jwt`, RS256/ES256. | `exp`/`nbf` enforced; no additional maximum lifetime or skew configured. | Caller obtains another per-resource token. |

The canonical `PrivateKeyJwt` client provider caches only its own configured
resource token and reacquires it before expiry. Token exchange is uncached.
Use one provider instance per resource and scope set. Python exposes it as
`registry_client.auth.PrivateKeyJwt`; `registry_client.breg.PrivateKeyJwt`
remains the same class for compatibility. Rust exposes `registry_stack_client::auth`.
The provider's `resource` is the RFC 8707 resource indicator for the issued
access token. Its optional `audience` instead names the private_key_jwt client
assertion's audience (default: token endpoint); it does not select an access-token
audience. Keep that distinction when configuring one shared OAuth registration.
A provider does not choose scopes, derive an audience or grant downstream authority.

## Issuer networking

Plain HTTP on literal IPv4/IPv6 loopback or `localhost` is accepted for local
use. Beyond loopback, explicitly set `allowInsecureHttp: true` only for an
operator-approved unencrypted network. The declared issuer and declared JWKS
endpoint may resolve to private networks. A discovered endpoint inherits that
allowance only on the exact issuer origin; a discovered cross-origin endpoint
must use HTTPS and public addresses. Cloud metadata and link-local addresses
remain denied. A hostname resolving to loopback is not a literal-loopback
exception. See [the shared verifier](../../crates/registry-platform-oidc/README.md).

## Safe diagnostics

Public invalid-credential responses remain generic 401 `authentication.refused`.
Authenticated profile/route failures retain their documented 403 or concealment,
and a verifier outage retains its product's 503. Internal verification stages
are fixed labels: header, algorithm, token-type, key, signature, issuer,
audience, time, client, scope, profile and unavailable. Each verifier emits at
most one diagnostic per stage per minute. These logs contain no credential,
claim, issuer, audience, scope, key or subject values. Use the selected
configuration and safe local validation to identify the mismatched field;
never add token contents to runtime logs. Local fixture validation should name
the field/rule and expected profile category without printing its input values.
