# registry-platform-authcommon

Provider-independent authentication helpers shared by registry services.

## What It Provides

- Strict `Authorization: Bearer <token>` parsing.
- Canonical API-key fingerprints in `sha256:<64 lowercase hex>` format.
- Constant-time API-key fingerprint comparison through `subtle`.
- A 32-byte minimum raw API-key entropy floor for generated keys.

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
- Empty tokens, extra token parts, and token whitespace are rejected.
- Fingerprints must be lowercase hex and include the `sha256:` prefix.

## Security Notes

- `validate_api_key_entropy` enforces key length, not randomness quality. Key
  generation still belongs to a cryptographically secure generator.
- Store and compare fingerprints, not plaintext API keys.
- Treat returned Bearer tokens as secrets and avoid logging them.

## Testing

```sh
cargo test -p registry-platform-authcommon
```

## License

Apache-2.0.
