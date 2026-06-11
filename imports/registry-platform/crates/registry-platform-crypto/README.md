# registry-platform-crypto

Crypto primitives shared by registry services.

## What It Provides

- `PrivateJwk` and `PublicJwk` parsing for OKP/Ed25519 JWKs.
- EdDSA signing and verification helpers.
- `SigningProvider` and `LocalJwkSigner` for code that should sign without
  depending directly on in-process private JWK ownership.
- `KeyProviderKind`, `KeyStatus`, `KeyReadiness`, and `KeyReadinessSnapshot`
  for provider-neutral readiness reporting and live-apply gates.
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

Provider-backed callers can wrap the same key material:

```rust
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};

async fn sign_with_provider() -> Result<(), Box<dyn std::error::Error>> {
let private = PrivateJwk::parse(r#"{
  "kty": "OKP",
  "crv": "Ed25519",
  "d": "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw",
  "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
  "alg": "EdDSA",
  "kid": "did:web:issuer.example#key-1"
}"#)?;

let signer = LocalJwkSigner::new(private)?;
let _signature = signer.sign(b"registry-platform").await?;
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
- `LocalJwkSigner` requires a non-empty `kid`, stores local key material behind
  shared ownership, and exposes only public JWK metadata through
  `SigningProvider`.
- Production deployments that require key isolation should implement
  `SigningProvider` over an external service such as Vault Transit or a cloud
  KMS. Adapters must bound timeouts and error messages, avoid secret-bearing
  logs, and provide configured public JWK metadata when the backing service
  cannot export it directly.
- Readiness-gated live apply should use `KeyReadinessSnapshot`; only
  `status = active` plus `readiness = ready` is accepted. Degraded,
  not-ready, unknown, publish-only, and disabled keys fail closed before
  anti-rollback state changes.
- Provider posture should use the shared provider/readiness labels and follow
  the product-neutral redaction contract in
  [`docs/secret-provider-readiness.md`](../../docs/secret-provider-readiness.md).
- `did:web` validation rejects IP literals, localhost, obvious metadata hosts,
  empty labels, and path traversal.
- Signing helpers validate key material before use.

## Testing

```sh
cargo test -p registry-platform-crypto
```

## License

Apache-2.0.
