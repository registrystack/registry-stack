# registry-platform-authcommon

Provider-independent authentication helpers shared by registry services.

## What It Provides

- Strict `Authorization: Bearer <token>` parsing.
- Bounded compact access-token admission with strict JSON duplicate-member
  rejection before OIDC verification.
- Canonical API-key fingerprints in `sha256:<64 lowercase hex>` format.
- Constant-time API-key fingerprint comparison through `subtle`.
- A 32-byte minimum raw API-key entropy floor for generated keys.
- `FailedCheck`, the closed set of checks a request can fail, each with a
  stable kebab-case label (`as_str`). It is operator-side only and is never
  written to a response.
- `RefusalTraceId`, the trace id a refusal line may carry. It is sealed by
  convention, and `registry_platform_httpsec::TraceId` implements it under
  httpsec's `server` feature. This crate does not depend on httpsec.
- Behind the `refusal-recorder` feature: `RefusalRecorder`, which counts
  every refusal in `<product>_request_refusals_total{check}` and admits at
  most five log lines per check per minute, and `record_refusal!`, which
  writes the admitted line with `failed_check`, `suppressed`, an optional
  code-defined `remedy` and an optional `trace_id` (a `RefusalTraceId`).

## Typical Use

```rust
use registry_platform_authcommon::{
    fingerprint_api_key, parse_bearer_token, validate_api_key_entropy, verify_api_key,
};

fn validate_request(header: &str, raw_key: &str) -> Result<(), Box<dyn std::error::Error>> {
let token = parse_bearer_token(header)?;

validate_api_key_entropy(raw_key)?;
let fingerprint = fingerprint_api_key(raw_key);
assert!(verify_api_key(raw_key, &fingerprint)?);

let _ = token;
Ok(())
}
```

## Behavior

- The Bearer scheme is ASCII case-insensitive.
- The scheme and token must be separated by exactly one ASCII space.
- Empty tokens, commas, extra token parts, and token whitespace are rejected.
- Fingerprints must be lowercase hex and include the `sha256:` prefix.

## Security Notes

- `validate_api_key_entropy` enforces key length, not randomness quality. Key
  generation still belongs to a cryptographically secure generator.
- Store and compare fingerprints, not plaintext API keys.
- Treat returned Bearer tokens as secrets and avoid logging them.
- Alert and diagnose on the refusal counter, not on the log line. The log
  budget is process-wide, so unauthenticated traffic can spend a check's
  lines; `suppressed` on the next admitted line shows how many were dropped.
- Call `record_refusal!` outside any span that records request values (a
  URI, query, header, client id or subject). Formatters print the enclosing
  span's fields on the refusal line.

## Testing

```sh
cargo test -p registry-platform-authcommon
cargo test -p registry-platform-authcommon --features refusal-recorder
```

## License

Apache-2.0.
