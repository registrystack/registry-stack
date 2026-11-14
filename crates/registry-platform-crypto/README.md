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
- Version 1 hook delivery signing and receiver verification, including input
  bounds, signature-version checks, constant-time comparison, and
  receiver-selected delivery-time skew.
- HMAC-SHA256 tags and legacy-interoperability HMAC-SHA1 verification in
  `mac`, with constant-time verification that refuses a tag of the wrong
  length, and a constant-time byte comparison for shared secrets such as URL
  tokens. `constant_time_eq` is also exported at the crate root and is the
  shared compare for secrets.
- `sha3_256(bytes)` exposes AWS-LC's SHA3-256 digest for a consumer with a
  pinned external protocol that requires it. The consumer defines the exact
  preimage, output representation, and any signature policy.
- `random_base64url(bytes)` (also `random::random_base64url`): an unpadded
  base64url token of 16 to 64 operating-system random bytes, for nonces,
  `state` values, and session references; other sizes are refused.
- `xchacha_seal` (feature `xchacha-seal`): XChaCha20-Poly1305 `seal` and
  `open` with a fresh random 192-bit nonce, at the `nonce || ciphertext ||
  tag` level; callers keep version bytes, key derivation, and associated
  data.

`jws` (always compiled) parses, verifies, and signs compact JWS. Parsing
bounds each segment before decoding, reads the header with the strict JSON
parser, and refuses `crit` and `b64`. `CompactJws::verify` requires the header
`alg` to equal the key's algorithm and to be in the caller's allow-list, and
returns the payload only after the signature verifies. `sign_compact_jws` takes
`alg` and `kid` from the `SigningProvider` and refuses them in the caller's
extra header members. Errors never carry the token or key material.

The `jwe` feature adds `jwe`: compact `ECDH-ES` decryption over P-256 with
A128GCM or A256GCM (RFC 7516, RFC 7518 section 4.6), on aws-lc-rs. The
recipient key is an `EcdhEsP256Key` (redacted `Debug`, public JWK export with
`use` `enc` and `alg` `ECDH-ES`). `decrypt_compact_ecdh_es` accepts only an
empty encrypted-key segment, `alg` exactly `ECDH-ES`, an `enc` from the
caller's allow-list, an on-curve P-256 `epk`, and a `kid` equal to the key's
when present; it refuses `zip` and `crit`, feeds `apu` and `apv` into the KDF,
and uses the transmitted header segment as AAD. Every failure is one opaque
`JweError`; the closed reason is readable only under test. The
`jwe-test-support` feature adds `encrypt_compact_ecdh_es_for_tests` and
`EcdhEsP256Key::to_pkcs8_der_for_tests` so a service can simulate a wallet; it
is not a production surface. `tests/fixtures/gen_jwe_vectors.py` regenerates
the independent jwcrypto vectors in `tests/fixtures/jwe-vectors.json` (see the
script header for the command).

`sealed_value` protects bounded product-owned durable values with AES-256-GCM,
HKDF-SHA256 domain separation, caller-supplied context and key versions. It
reuses the field encryption envelope mechanism; the BReg Version 1 field
contract and bounds remain unchanged. Consumers own key custody, retention,
rotation, and the database/run/purpose identity authenticated with each value.

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

## Document signatures (cms-signing)

The opt-in `cms-signing` feature, in `document_signature`, provides the CMS,
certificate and RFC 3161 pieces a product needs to apply a document seal (an
electronic seal under ETSI EN 319 142-1) as a PAdES baseline signature at
level B-B or B-T. This is the only meaning of "seal" in `document_signature`;
`sealed_value::seal` and `field_encryption::seal_field` mean authenticated
encryption of a stored value, not a document seal. The product owns
the document format: for a PDF it reserves the signature dictionary, computes
the byte ranges the signature covers, and embeds the returned CMS. The
pyHanko, EU DSS and veraPDF runs on sealed files Registry Render answered,
and what they do not show, are recorded in
[`products/render/EVIDENCE.md`](../../products/render/EVIDENCE.md).

```rust
use registry_platform_crypto::{
    accept_timestamp_response, add_signature_timestamp, random_timestamp_nonce,
    sign_detached, timestamp_request, CertificateChain,
};

async fn seal(
    chain_pem: &[u8],
    signer: &dyn registry_platform_crypto::SigningProvider,
    byte_ranges: &[&[u8]],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let chain = CertificateChain::from_pem(chain_pem)?;
    let signature = sign_detached(byte_ranges, &chain, signer).await?;
    let nonce = random_timestamp_nonce()?;
    let request = timestamp_request(&signature.signature_value, nonce)?;
    // The product's own bounded HTTP client posts the request as
    // application/timestamp-query and returns the response body.
    let response = post_timestamp_query(&request).await?;
    let timestamp = accept_timestamp_response(&response, &signature.signature_value, nonce)?;
    Ok(add_signature_timestamp(&signature.cms_der, &timestamp.token_der)?)
}
```

What it does:

- `CertificateChain::from_pem` reads the seal certificate first, then each
  issuer in turn. It refuses empty input, any PEM block that is not a
  `CERTIFICATE` (a private key included), a block that is not a DER X.509
  certificate, a repeated certificate, a chain whose issuer and subject
  names do not link each certificate to the next, and a first certificate
  that is a CA's (basic constraints cA, or the keyCertSign key usage), such
  as a root CA certificate given alone. It exposes the seal
  certificate's DER, SHA-256 fingerprint, validity, and display name (subject
  organization, else common name).
- `CertificateChain::check_for_signing` refuses a seal certificate that does
  not hold the signer's public key, that has neither the digitalSignature nor
  the nonRepudiation key usage, or whose validity does not include the given
  time. Errors name the certificate by fingerprint only, never by subject.
  `CertificateChain::allows_document_signing_purpose` says whether the seal
  certificate has no extended key usage or one naming document signing (RFC
  9336 or Microsoft's), Adobe Authentic Documents, email protection or
  anyExtendedKeyUsage, for a caller to warn on, not refuse.
- `sign_detached` signs the concatenated parts as detached `SignedData`:
  id-data content, the chain in `certificates`, one signer identified by
  issuer and serial number, and exactly the signed attributes content type,
  message digest and signing certificate v2. It writes no signing time; PAdES
  carries the claimed time in the signature dictionary. ES256 and RS256 use
  SHA-256, ES384 and RS384 use SHA-384, and EdDSA is refused. It runs
  `check_for_signing` at the current time first, converts a provider's JWS
  ECDSA signature to DER, and verifies the encoded result before returning.
- `timestamp_request` builds an RFC 3161 request over the SHA-256 of the
  signature value, with a nonce and `certReq`. `accept_timestamp_response`
  refuses a response that is too large or malformed, not granted, without a
  token, not `SignedData` over a TSTInfo, or for another imprint or nonce; a
  token whose signature does not verify; and a token signed by a certificate
  without a critical extended key usage of exactly id-kp-timeStamping, or
  whose validity does not include the token's time. `add_signature_timestamp` re-checks the token
  against the signature and adds it as the signature timestamp unsigned
  attribute, which makes the signature B-T.

What it does not do:

- No certification path validation. Chain order is checked by names, not by
  verifying each certificate's signature, and no trust anchor is configured.
  Whether the seal CA and the timestamp authority are trusted is the relying
  party's decision, made by its validator.
- No revocation checking: no CRL or OCSP fetch, no revocation data embedded.
- No long-term validation: no B-LT or B-LTA level, no document security store,
  no archive timestamps.
- No qualification claims. Whether a seal is advanced or qualified under eIDAS,
  or recognised under any other scheme, depends on the certificate, its issuer
  and the key custody, not on this encoding. Nothing in this crate asserts it.
- No network access. The caller sends the timestamp request and bounds the
  response read.

The `test-support` feature adds `document_signature::test_support`: an
in-memory `TestPki` with a root CA, an issuing CA, ES256, ES384, RS256 and RS384
seal certificates with private JWKs for `LocalJwkSigner`, a timestamp
authority with a critical timeStamping extended key usage,
`respond_to_timestamp_request`, and, on Unix, `TestTransit`, a Transit signing
proxy that serves one P-256 key version from a private JWK. Enable it from
`[dev-dependencies]` only.

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
  token renewal; the application never receives its token. A refused
  initialization returns a `TransitInitializationError` naming one cause, such
  as an unreachable socket or a pinned version below `min_encryption_version`,
  and never a provider response, path, or key material.
- `TransitSignerConfig::discover` binds to the public key Transit itself holds
  for the pinned version, after the same custody and version checks, for a
  caller with no identity to pin yet. Nothing outside Transit vouches for that
  key, so the caller anchors it before relying on a signature: it requests a
  certificate for the key, or checks the key against the certificate that
  certifies it, as a document seal does.
- `transit_rsa_no_oid` is the opt-in raw Transit primitive for a reviewed
  legacy profile that signs a 64-byte lowercase hexadecimal digest with RSA
  PKCS#1 v1.5 and no digest OID. It pins the exact RSA public SPKI DER SHA-256
  and key version, revalidates that binding and custody metadata before every
  sign or verify, uses fixed `/none` endpoints through the bounded Unix-socket
  proxy with redirects disabled, and verifies each signer result through the
  pinned key before release. The signer requires a service-created key. The
  `imported_key` flag records the origin of the verification entry. Operators
  import only the provider's public key for that entry and grant the trusted
  proxy verify-only access to it.
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
- `mac::verify_hmac_sha1` exists only to verify schemes a provider already
  signs with HMAC-SHA1; a scheme a registry product defines uses HMAC-SHA256.
  A `MacMismatch` refusal carries no tag, key, or message.
- The delivery signature helper preserves the exact length-prefixed Version 1
  wire input. Receivers pass the HTTP method, request target, content type,
  delivery headers, and body exactly as received, and choose a bounded accepted
  delivery-time skew for their deployment.

## Testing

```sh
cargo test -p registry-platform-crypto
cargo test -p registry-platform-crypto --features transit
cargo test -p registry-platform-crypto --all-features
```

To check document signatures with OpenSSL, write the interoperability
artifacts into an empty directory and verify them there:

```sh
export REGISTRY_CMS_INTEROP_DIR=/path/to/empty/dir
cargo test -p registry-platform-crypto --all-features \
  write_openssl_interop_artifacts -- --ignored
dir="$REGISTRY_CMS_INTEROP_DIR"
for alg in es256 es384 rs256; do
  for level in b-b b-t; do
    openssl cms -verify -binary -inform DER -in "$dir/$alg-$level.p7s" \
      -content "$dir/content.bin" -CAfile "$dir/root.pem" -out /dev/null
  done
  openssl ts -verify -queryfile "$dir/$alg.tsq" -in "$dir/$alg.tsr" \
    -CAfile "$dir/root.pem"
  openssl ts -reply -in "$dir/$alg.tsr" -text
done
```

## License

Apache-2.0.
