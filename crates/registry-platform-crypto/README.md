# registry-platform-crypto

Crypto primitives shared by registry services.

## What It Provides

- `PrivateJwk` and `PublicJwk` parsing for OKP/Ed25519, EC/P-256, EC/P-384, and
  RSA JWKs.
- EdDSA, ES256, ES384, RS256, and RS384 signing and verification helpers.
- `SigningProvider` and `LocalJwkSigner`, plus the `transit` feature's
  `TransitSigner`, for code that should sign without depending directly on one
  private-key storage model. The opt-in feature keeps HTTP and async-networking
  dependencies out of offline verifiers.
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

This crate currently supports EdDSA with OKP/Ed25519 keys, ES256 with EC/P-256
keys, ES384 with EC/P-384 keys, and RS256 and RS384 with RSA keys. Unsupported
JWK algorithms are rejected at parse time. RSA keys must use a 2048-8192-bit
modulus. Private RSA JWKs must include the full two-prime CRT fields `n`, `e`,
`d`, `p`, `q`, `dp`, `dq`, and `qi` so the key can be imported into AWS-LC. Add
new algorithms only when a registry consumer needs them and can define the
interoperability and security policy.

## Security Notes

- `PrivateJwk` redacts private material in `Debug`.
- `PrivateJwk::public` strips private members before serialization.
- Raw JWK JSON and decoded `did:jwk` payloads are limited to 64 KiB and reject
  duplicate members before interpretation. Every `PublicJwk` deserialization
  rejects symmetric or asymmetric private members (`k`, `d`, `p`, `q`, `dp`,
  `dq`, `qi`, and `oth`) while continuing to ignore non-secret extension
  metadata.
- `LocalJwkSigner` requires a non-empty `kid`, stores local key material behind
  shared ownership, and exposes only public JWK metadata through
  `SigningProvider`.
- `TransitSigner` supports the common Vault/OpenBao ES256 Transit API through a
  dedicated local proxy's Unix socket. It requires a pinned key version,
  non-exportable and non-backup custody metadata, an exact configured public
  JWK match, bounded requests and responses, and a successful local
  sign-and-verify check before reporting ready. Signing inputs are SHA-256
  hashed locally and sent with Transit `prehashed: true`, so assertion bytes do
  not cross the signing-provider boundary. The proxy owns authentication and
  token renewal; the application never receives its token.
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
cargo test -p registry-platform-crypto --features transit
```

## License

Apache-2.0.
