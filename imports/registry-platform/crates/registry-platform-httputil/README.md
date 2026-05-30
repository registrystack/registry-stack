# registry-platform-httputil

Outbound HTTP utilities for registry services.

## What It Provides

- `OutboundClientBuilder` with request and connect timeouts, no redirects, and
  ignored proxy environment variables by default. It does not validate target
  URLs; pair it with `FetchUrlPolicy` for user-controlled destinations.
- `read_bounded` for response bodies with content-length and streaming byte
  limits.
- `url::append_path_segments` for safe path construction.
- `FetchUrlPolicy` for SSRF-resistant outbound URL validation and DNS evidence.
- `ValidatedFetchUrl` for immediate GET requests pinned to DNS evidence observed
  during validation, with a default request timeout.
- Async validation with a wall-clock timeout around DNS resolution.

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
- Enabling private-network HTTP does not by itself allow link-local or cloud
  metadata targets. Keeping `deny_cloud_metadata = true` denies those ranges;
  set it to `false` only for explicit, trusted fixtures or deployments that
  intentionally fetch such endpoints.

## Features

- Default: `rustls`.

## Testing

```sh
cargo test -p registry-platform-httputil
```

## License

Apache-2.0.
