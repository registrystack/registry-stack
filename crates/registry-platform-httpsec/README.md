# registry-platform-httpsec

Axum and Tower helpers for browser-facing HTTP security.

## What It Provides

- `CorsPolicy` with explicit origin validation.
- Restrictive CSP header generation through `CspBuilder`.
- `security_headers` middleware for CSP, content sniffing, referrer, and frame
  protections.
- Conditional Cross-Origin-Resource-Policy handling.
- Request body limit layer construction.
- RFC 9457 Problem Details responses with `application/problem+json`.
- A standard body-limit problem response.
- `TraceId` and `TraceContext`, the shared strict W3C `traceparent` transport
  primitives for Registry service responses.
- `ProblemBody`, the fixed value-free Registry Stack problem envelope with
  `type`, `title`, `status`, `detail`, `code`, and `traceId` members.

## Typical Use

```rust
use axum::{http::Method, Router};
use registry_platform_httpsec::{
    corp_conditional, request_body_limit, security_headers, CorsPolicy, CspBuilder,
};

let cors = CorsPolicy {
    allowed_origins: vec!["https://app.example.test".to_string()],
    allowed_methods: vec![Method::GET, Method::POST, Method::OPTIONS],
    allowed_headers: Vec::new(),
    allow_credentials: false,
};

let app = Router::new()
    .layer(corp_conditional())
    .layer(security_headers(CspBuilder::restrictive()))
    .layer(cors.layer())
    .layer(request_body_limit(1024 * 1024));
let _ = app;
```

## Behavior

- Wildcard CORS origins are rejected.
- Credentialed CORS requires explicit allowed headers.
- HTTPS origins are accepted. HTTP origins are accepted only for loopback
  development origins.
- Existing security headers are preserved when `security_headers` is applied.
- Invalid, duplicate, or absent inbound `traceparent` values receive a fresh
  server trace. One valid lower-case W3C version 0 `traceparent` is retained.
  Caller `tracestate` is never echoed.

## Security Notes

- Keep CORS allowlists environment-specific and as narrow as possible.
- `CspBuilder::restrictive` is the safe baseline. Extend it in application code
  only for concrete frontend needs.
- Body limits reduce risk but do not replace endpoint-level validation.
- Product crates retain ownership of their closed problem-code mappings and
  response policy. The shared envelope does not accept arbitrary extras or
  caller-controlled diagnostic text.

## Testing

```sh
cargo test -p registry-platform-httpsec
```

## License

Apache-2.0.
