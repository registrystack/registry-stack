# registry-platform-httputil

Outbound HTTP utilities for registry services.

## What It Provides

- `OutboundClientBuilder::try_build` with explicit rustls, retries and redirects
  disabled, ignored proxy environment variables, and optional exact CA pinning.
  Pinned bundles are limited by
  `MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES` and
  `MAXIMUM_TRUSTED_ROOT_CERTIFICATES` before client construction.
  Pair it with `ServiceBaseUrl` for configured credential-bearing services or
  `FetchUrlPolicy` for user-controlled destinations.
- `read_bounded` for response bodies with content-length and streaming byte
  limits.
- `ServiceBaseUrl`, bearer token providers, and `PrivateKeyJwt` for hardened
  credential-bearing clients without product semantics. The private-key-JWT
  provider uses a closed `client_credentials` request shape. Its `exchange`
  method accepts a bounded JWT subject assertion and uses RFC 8693 with the
  provider's configured resource and scopes. Every exchange is fresh and does
  not use or replace the service-token cache. Returned task bounds remain the
  consuming resource server's authorization responsibility.
  `redeem_authorization_code` redeems an authorization code with its PKCE
  verifier and redirect URI for a relying party that signs people in, with the
  same client assertion and configured resource and no scope parameter. It
  checks input shape before any request, refuses a response scope missing a
  configured scope, and never touches the service-token cache. It returns a
  `RedeemedAuthorizationCode`: the access token, a monotonic expiry when the
  issuer stated one, and the unverified ID token, which the caller verifies
  before reading any claim.
- `ExchangeAuthorization` for one immutable host-verified person or task-grant
  context. The first-party source signs a bounded grantless JWT; the remote
  source obtains a new assertion with a narrowly configured bootstrap on each
  refresh. Both use `PrivateKeyJwt.exchange` for the exact configured client,
  resource and scopes. Cache life never exceeds the context deadline. A
  first-party context can exchange once; renewed person authority requires
  fresh host source verification and a new provider. The shared closed JSON
  parser `exchange_authorization_from_json` is used by Node and Python bindings.
  `ExchangeAuthorization::upstream` instead presents, once, an access token
  another authorization server issued and the host has already verified,
  including its audience (`UpstreamSubjectToken`, with a closed
  `SubjectTokenType`). It may add the service's own client-credentials token
  as the RFC 8693 actor token, acquired from a shared `PrivateKeyJwt` for the
  same client and token endpoint and never returned to the caller. The context
  deadline may not pass the subject token's expiry, so the exchanged token is
  never handed out after the subject token ends, whatever lifetime the issuer
  states. A stated scope must hold every requested scope; an omitted one means
  the scope requested (RFC 6749 section 5.1), and the resource server's own
  scope check stays authoritative.
- Shared strict response-header bounds and exact-one delta-seconds
  `Retry-After` parsing.
- `ProxyHeaderPolicy` plus request and response header filters for proxy-safe
  forwarding.
- `url::append_path_segments` for safe path construction.
- `FetchUrlPolicy` for SSRF-resistant outbound URL validation and DNS evidence.
- `ValidatedFetchUrl` for immediate GET requests pinned to DNS evidence observed
  during validation, with a default request timeout.
- Async validation with a wall-clock timeout around DNS resolution.
- Marker-typed fixed-destination requests and opaque bounded response bodies for
  registry-data and credential endpoints.
- A closed no-expiry OAuth client-credentials response decoder that returns a
  fresh, move-only bearer authorization capability.
- A decoder pinned to the OpenCRVS DCI adapter v1.9.0-rc.1. It verifies the
  exact compact RS256 response sibling against the fresh two-key OpenCRVS JWKS,
  enforces the closed DCI envelope, and sends only a logical record wrapper
  through the caller-supplied closed JSON schema. This remains product-specific
  so configuration cannot weaken signature or correlation rules.

## Typical Use

```rust
use registry_platform_httputil::{read_bounded, FetchUrlPolicy};

async fn fetch_document() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let url = "https://issuer.example/.well-known/openid-configuration".parse()?;
    let validated = FetchUrlPolicy::strict()
        .validate_dns_pinned_for_immediate_fetch_with_timeout(&url, std::time::Duration::from_secs(5))
        .await?;
    let response = validated.immediate_get()?.send().await?;
    let body = read_bounded(response, 1024 * 1024).await?;
    Ok(body)
}
```

## URL Policy

- `FetchUrlPolicy::strict` allows HTTPS only and denies localhost, private
  ranges, link-local ranges, and cloud metadata endpoints.
- Known metadata endpoints include link-local metadata services and public-IP
  metadata services such as `100.100.100.200`; IPv4-mapped IPv6 literals are
  normalized before classification.
- `FetchUrlPolicy::dev` allows HTTP and HTTPS, but plain HTTP is allowed only
  for loopback hosts. Non-loopback private ranges stay denied.
- `FetchUrlPolicy::validate` is deprecated compatibility. It resolves the host
  but discards DNS evidence, so it is not sufficient protection for a later
  request. Use `validate_dns_pinned_for_immediate_fetch` plus
  `ValidatedFetchUrl::immediate_get` for outbound fetches.
- Use `validate_dns_pinned_for_immediate_fetch_with_timeout` in async request
  paths when hostnames are user-controlled or provider-controlled.
- Userinfo in URLs is rejected to avoid credential smuggling.
- DNS results are captured as evidence and can be used to build an immediate
  pinned request.
- `ValidatedFetchUrl::immediate_get` applies a 30 second request timeout and a
  10 second connect timeout by default. Use `immediate_get_with_timeout` or
  `RequestBuilder::timeout` for a tighter per-call bound.
- Requests built from `ValidatedFetchUrl` disable redirects and ignore proxy
  environment variables, so a redirect response cannot move the fetch to a URL
  that bypassed validation.
- Enabling private-network HTTP does not by itself allow link-local or cloud
  metadata targets. Keeping `deny_cloud_metadata = true` denies those ranges;
  set it to `false` only for explicit, trusted fixtures or deployments that
  intentionally fetch such endpoints.

## Proxy Header Filtering

- `ProxyHeaderPolicy::strict` strips hop-by-hop headers, `Connection`-nominated
  headers, `Authorization`, `Cookie`, `Host`, `Forwarded`, `X-Forwarded-*`, and
  `X-Real-IP`.
- Let the trusted proxy adapter inject verified forwarding and authority
  headers after filtering. Preserve caller-supplied forwarding or host headers
  only when that is an intentional compatibility boundary.

## Features

- Default: `rustls`.

## Testing

```sh
cargo test -p registry-platform-httputil
```

## License

Apache-2.0.
