# registry-platform-sdjwt

SD-JWT VC issuance and holder-proof validation helpers.

## What It Provides

- `SdJwtIssuer` for provider-backed EdDSA, ES256, RS256, ES384, and RS384
  SD-JWT VC issuance.
- `SdJwtIssuanceInput` with issuer, subject reference, optional caller-provided
  credential id, validity, profile, optional status claim, holder confirmation,
  and disclosures.
- Disclosure digest sorting for deterministic `_sd` payload ordering.
- Holder-proof validation with signature, audience, lifetime, subject, replay id,
  disclosure hash, evaluation id, credential profile, and claim-set bindings.
- `validate_key_binding_jwt` for RFC 9901 section 4.3 key-binding JWTs: the
  confirmed holder key signs a closed four-claim payload over a challenge, an
  audience, an issue time, and the `sd_hash` of the presented SD-JWT.
- `validate_oid4vci_proof_jwt` for OpenID for Verifiable Credential Issuance 1.0
  proof JWTs, returning the one public key the proof authenticated.

## Typical Use

```rust
use registry_platform_crypto::PrivateJwk;
use registry_platform_sdjwt::{
    Disclosure, HolderConfirmation, SdJwtIssuer, SdJwtIssuanceInput,
};
use serde_json::json;

async fn issue_credential() -> Result<(), Box<dyn std::error::Error>> {
let issuer_key = PrivateJwk::parse(r#"{
  "kty": "OKP",
  "crv": "Ed25519",
  "d": "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw",
  "x": "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
  "alg": "EdDSA",
  "kid": "did:web:issuer.example#key-1"
}"#)?;

let issuer = SdJwtIssuer::from_jwk(issuer_key)?;
let signed = issuer.issue(SdJwtIssuanceInput {
    iss: "did:web:issuer.example".to_string(),
    sub_ref: "did:example:subject".to_string(),
    credential_id: None,
    iat: 1_700_000_000,
    exp: 1_700_000_600,
    vct: "https://issuer.example/vct/registry-credential".to_string(),
    status: None,
    cnf: None::<HolderConfirmation>,
    disclosures: vec![Disclosure {
        name: "claim".to_string(),
        value: json!({"allowed": true}),
    }],
}).await?;

let _ = signed;
Ok(())
}
```

## Security Notes

- This crate currently signs with EdDSA/Ed25519, ES256/P-256, RS256/RSA,
  ES384/P-384, or RS384/RSA through a `registry-platform-crypto`
  `SigningProvider`. Holder-proof validation only accepts an EdDSA holder
  proof (see `HOLDER_PROOF_ALLOWED_ALGORITHM` in `src/lib.rs`); the issuance
  algorithm list above does not extend to holder proofs.
- `SdJwtIssuer::from_jwk` is intended for local development, tests, and simple
  deployments using mounted private JWK material. Production deployments that
  require key isolation should pass an external signer implementation with
  `SdJwtIssuer::from_signing_provider`.
- The SD-JWT header `kid` is always taken from the signing provider. Issuance
  input cannot override it.
- Holder-proof validation returns `jti` so consumers can perform replay
  detection in their own storage.
- `HolderProofPolicy::default` uses a 5-minute max lifetime and an empty
  audience. Set the audience explicitly in production.
- `validate_key_binding_jwt` and `validate_oid4vci_proof_jwt` verify the
  signature before parsing any claim, so no decision is taken from an unverified
  token. Both reject duplicate JSON members outright instead of resolving them,
  accept only the header parameters and payload claims they name, compare the
  challenge in constant time, and bound `iat` with checked arithmetic so a
  policy duration that cannot be represented is reported rather than clamped.
- Comparing a challenge is not consuming one. Both validators check equality
  only; single use of a nonce or `c_nonce` belongs to the caller's challenge
  store, as RFC 9901 section 7.3 requires.
- `validate_oid4vci_proof_jwt` accepts an inline public `jwk` or a canonical
  local `did:jwk:...#0` `kid`. It refuses remote `kid` resolution, `x5c`, and
  private key material because this crate owns neither a remote resolver nor a
  certificate trust anchor and must not receive holder secrets.
- This crate validates cryptographic and binding checks, not credential
  revocation, replay storage, or authorization policy.

## Testing

```sh
cargo test -p registry-platform-sdjwt
```

## License

Apache-2.0.
