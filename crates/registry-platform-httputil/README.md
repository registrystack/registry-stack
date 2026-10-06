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
- `client::retry_keyed_mutation`, the bounded same-key resend loop shared by
  the product clients. Each attempt reports a `KeyedMutationAttempt`:
  `Settled` ends the loop, `Retryable` is resent after 250 ms and then 500 ms,
  or after a `Retry-After` that is longer and at most
  `MAXIMUM_MUTATION_RETRY_AFTER_SECONDS` (5), and `Unknown` ends the loop
  because an identical resend could not settle it. A longer requested wait,
  or a `Retry-After` that `RetryAfter::from_headers` finds unusable (an
  HTTP date, a fraction, a duplicate field), ends the retries. The count is
  the caller's, `DEFAULT_MUTATION_RETRIES` (2) by default, clamped to
  `MAXIMUM_MUTATION_RETRIES` (2), and 0 sends once. A refusal that answers a
  resend returns the earlier unknown-outcome error, since it does not prove
  the earlier attempt left no effect. The loop never builds a request or a
  key; the closure resends the caller's exact bytes.
- `client::classify_keyed_attempt`, the one rule that turns an attempt into a
  `KeyedMutationAttempt` from the client's own judgement of its error and the
  answer's status line: a known outcome settles, an unknown one is resent on
  a 5xx answer or when a resend may settle it, and an answer with a 4xx
  status line is never resent, even when its body could not be read.
- `ProxyHeaderPolicy` plus request and response header filters for proxy-safe
  forwarding.
- `url::append_path_segments` for safe path construction.
- `FetchUrlPolicy` for SSRF-resistant outbound URL validation and DNS evidence.
- `ValidatedFetchUrl` for immediate GET requests pinned to DNS evidence observed
  during validation, with a default request timeout.
- Async validation with a wall-clock timeout around DNS resolution.
- Marker-typed fixed-destination requests and opaque bounded response bodies for
  registry-data and credential endpoints.
- A side-effecting send class for data destinations, compiled only by
  `DataDestinationRequestTemplate::new_script_send` and refused by every
  read-only constructor. It sends a POST with a JSON or form body, or a GET
  whose content travels in the query string only behind an explicit
  `QueryStringContentAcknowledgement` that the content reaches the
  destination's access logs.
- A typed AWS SigV4 path for bounded JSON 1.0 sends. It accepts only `POST /`
  with no query, freezes the signing service, constructs `Content-Type` and
  `X-Amz-Target`, and signs the final fixed-origin authority, body, and headers
  inside the send path. Credentials use zeroizing storage and redacted
  diagnostics. Ordinary script templates cannot set SigV4 authentication
  headers.
- `ProductionAddressPolicy`, the production fixed-destination private-CIDR
  validation and resolved-address classification for a product that opens its
  own non-HTTP connection: it resolves once, classifies every answer, and
  connects only to an admitted address.
- `DestinationSendError::delivery_certainty`, which reports a failed send as
  `NotSent` when it failed before the connection was established (policy
  refusal, resolution, connect, or TLS handshake) and conservatively as
  `MaybeSent` for every failure after it.

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

- Data destinations using `DestinationProfile::ProductionHttps` or
  `DestinationProfile::PrivateServiceHttp` refuse `localhost` and every
  `*.localhost` name when the binding is constructed, including trailing-dot
  absolute names and regardless of allowed private CIDRs. Local receivers
  require `DestinationProfile::LoopbackDevelopmentHttp`.
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
- `ValidatedFetchUrl::immediate_get_with_additional_roots` trusts the given
  certificate authorities beside the system roots for that one request. It
  adds trust anchors and never removes one or disables hostname verification.
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
