# registry-platform-crypto

Crypto primitives shared by registry services.

## What It Provides

- `PrivateJwk` and `PublicJwk` parsing for OKP/Ed25519 JWKs.
- EdDSA signing and verification helpers.
- Public JWK thumbprints through `PublicJwk::jkt`.
- DID validation for allowed `did:web` and `did:key` inputs.
- JSON Canonicalization Scheme style byte output for `serde_json::Value`.
- Constant-time comparison dependencies for consumers that need them.

## Typical Use

```rust
use registry_platform_crypto::{sign, verify, PrivateJwk};

fn sign_payload() -> Result<(), Box<dyn std::error::Error>> {
let private = PrivateJwk::parse(r#"{
  "kty": "OKP",
  "crv": "Ed25519",
  "d": "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw",
  "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
  "alg": "EdDSA",
  "kid": "did:web:issuer.example#key-1"
}"#)?;

let public = private.public();
let signature = sign(b"registry-platform", &private)?;
verify(b"registry-platform", &signature, &public)?;
Ok(())
}
```

## Supported Algorithms

This crate currently supports EdDSA with OKP/Ed25519 keys. Unsupported JWK
algorithms are rejected at parse time. Add new algorithms only when a registry
consumer needs them and can define the interoperability and security policy.

## Security Notes

- `PrivateJwk` redacts private material in `Debug`.
- `PrivateJwk::public` strips private members before serialization.
- `did:web` validation rejects IP literals, localhost, obvious metadata hosts,
  empty labels, and path traversal.
- Signing helpers validate key material before use.

## Testing

```sh
cargo test -p registry-platform-crypto
```

## License

Apache-2.0.
