# registry-platform-httputil

Outbound HTTP utilities for registry services.

## What It Provides

- `OutboundClientBuilder` with timeouts, no redirects, and ignored proxy
  environment variables by default.
- `read_bounded` for response bodies with content-length and streaming byte
  limits.
- `url::append_path_segments` for safe path construction.
- `FetchUrlPolicy` for SSRF-resistant outbound URL validation.
- `ValidatedFetchUrl` for immediate GET requests pinned to DNS evidence observed
  during validation.

## Typical Use

```rust
use registry_platform_httputil::{read_bounded, FetchUrlPolicy, OutboundClientBuilder};

async fn fetch_document() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
let client = OutboundClientBuilder::new()
    .user_agent("registry-service/0.1")
    .build();

let url = "https://issuer.example/.well-known/openid-configuration".parse()?;
let validated = FetchUrlPolicy::strict().validate_for_immediate_fetch(&url)?;
let response = validated.immediate_get()?.send().await?;
let body = read_bounded(response, 1024 * 1024).await?;
let _ = client;
Ok(body)
}
```

## URL Policy

- `FetchUrlPolicy::strict` allows HTTPS only and denies localhost, private
  ranges, link-local ranges, and cloud metadata endpoints.
- `FetchUrlPolicy::dev` allows HTTP and HTTPS, but plain HTTP is allowed only
  for loopback hosts. Non-loopback private ranges stay denied.
- Userinfo in URLs is rejected to avoid credential smuggling.
- DNS results are captured as evidence and can be used to build an immediate
  pinned request.

## Features

- Default: `rustls`.
- Optional: `native-tls`.

Use one TLS backend at a time in consumers.

## Testing

```sh
cargo test -p registry-platform-httputil
```

## License

Apache-2.0.
