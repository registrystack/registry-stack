# registry-platform-httpsec

Client-safe HTTP validation plus Axum and Tower helpers for HTTP security.

## What It Provides

- Restrictive CSP header generation through `CspBuilder`, including a
  `deny_by_default` policy (`default-src 'none'`) and an optional
  `form-action` directive for server-rendered forms.
- `security_headers(csp, posture)` middleware for CSP, content sniffing,
  referrer, and frame protections. A development process also marks every
  response with `Registry-Posture: development`, overwriting a value a handler
  set. A production process sends no mark. `security_headers_without_posture`
  is the transitional entry point for a caller that holds no posture yet, and
  behaves as production.
- `posture_mark(posture)`, a layer that only sets the development mark, for
  routers that do not use `security_headers`.
- `bearer_challenge()`, the `Bearer` value every 401 carries in
  `WWW-Authenticate`.
- With the `refusal-trace-id` feature, `refusal_detail::name_failed_check(posture)`,
  a layer that adds a `failedCheck` member to a JSON refusal body that carries
  a refusal note when the posture is development. In production it returns the
  response untouched and does not read the body.
- Conditional Cross-Origin-Resource-Policy handling.
- Request body limit layer construction.
- RFC 9457 Problem Details responses with `application/problem+json`.
- A standard body-limit problem response.
- `shutdown_signal`, which installs SIGTERM (Unix) and Ctrl-C handlers before
  it returns and fails with the operating system error when one cannot be
  installed, so a service refuses startup instead of waiting on a signal it
  cannot observe.
- `normalize_framework_rejection`, which re-answers axum's 400, 413, 415 and
  422 framework bodies in the service's own problem vocabulary through a
  caller-supplied mapping from `FrameworkRejection`.
- `TraceId` and `TraceContext`, the shared strict W3C `traceparent` transport
  primitives for Registry service responses. With the `refusal-trace-id`
  feature, which pulls in `registry-platform-authcommon` and so the crypto
  stack, `TraceId` implements `registry_platform_authcommon::RefusalTraceId`, so a
  service passes its request trace id to `record_refusal!`.
- `loopback`, a re-export of `registry-platform-loopback`, the one definition
  of loopback for outbound destinations and loopback origins:
  `loopback_address`, `loopback_host` and `loopback_literal`. A literal in `127.0.0.0/8`, `::1` or the IPv4-mapped
  form of `127.0.0.0/8` is loopback, and so is the exact name `localhost`
  once the connection is pinned to loopback addresses
  (`LoopbackHost::pinned_by`). A site that accepts the name must pin the
  connection; a site that cannot pin uses `loopback_literal`. Bind sites keep
  their own, stricter rule. The module is available with
  `default-features = false`.
- `ProblemBody`, the fixed value-free Registry Stack problem envelope with
  `type`, `title`, `status`, `detail`, `code`, and `traceId` members.
- `response_trace_id` for exact-one canonical W3C v0 response correlation.
- `ProblemDocument::parse_exact` for exact-six-member received problems, and
  `parse_with_field_path` for products that define the one optional bounded
  `fieldPath`. Products retain their own closed problem catalogs and
  location grammars.

## Typical Use

```rust
use axum::Router;
use registry_platform_httpsec::{
    corp_conditional, request_body_limit, security_headers, CspBuilder,
};
use registry_platform_posture::Posture;

let app = Router::new()
    .layer(corp_conditional())
    .layer(security_headers(CspBuilder::restrictive(), Posture::Production))
    .layer(request_body_limit(1024 * 1024));
let _ = app;
```

## Behavior

- Existing security headers are preserved when `security_headers` is applied.
  The development posture mark is the exception: it overwrites.
- Invalid, duplicate, or absent inbound `traceparent` values receive a fresh
  server trace. One valid lower-case W3C version 0 `traceparent` is retained.
  Caller `tracestate` is never echoed.

## Security Notes

- The crate builds no CORS layer. Only the Evidence public check route answers
  cross-origin requests, from its own layer.
  `corp_conditional` marks a response `cross-origin` only when another layer
  has already set `Access-Control-Allow-Origin` on it.
- `CspBuilder::restrictive` is the safe baseline. Extend it in application code
  only for concrete frontend needs.
- `CspBuilder::deny_by_default` loads nothing; add only the directives a page
  needs, for example `with_style_src(&["'self'"])`. A page with forms also sets
  `with_form_action`, because `form-action` does not fall back to
  `default-src`. Directive sources are static code constants; a source holding
  whitespace, `;` or `,` is refused so it cannot add a directive.
- Body limits reduce risk but do not replace endpoint-level validation.
- Product crates retain ownership of their closed problem-code mappings and
  response policy. The shared envelope does not accept arbitrary extras or
  caller-controlled diagnostic text.

## Testing

```sh
cargo test -p registry-platform-httpsec
```

Client-only users can disable Axum and Tower with `default-features = false`.

## License

Apache-2.0.
