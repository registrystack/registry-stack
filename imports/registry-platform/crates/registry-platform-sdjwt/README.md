# registry-platform-sdjwt

SD-JWT VC issuance and holder-proof validation helpers.

## What It Provides

- `SdJwtIssuer` for EdDSA-backed SD-JWT VC issuance.
- `SdJwtIssuanceInput` with issuer, subject reference, validity, profile,
  signing key id, holder confirmation, and disclosures.
- Disclosure digest sorting for deterministic `_sd` payload ordering.
- Holder-proof validation with signature, audience, lifetime, subject, replay id,
  disclosure hash, evaluation id, credential profile, and claim-set bindings.

## Typical Use

```rust
use registry_platform_crypto::PrivateJwk;
use registry_platform_sdjwt::{
    Disclosure, HolderConfirmation, SdJwtIssuer, SdJwtIssuanceInput,
};
use serde_json::json;

fn issue_credential() -> Result<(), Box<dyn std::error::Error>> {
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
    iat: 1_700_000_000,
    exp: 1_700_000_600,
    vct: "https://issuer.example/vct/registry-credential".to_string(),
    signing_kid: "did:web:issuer.example#key-1".to_string(),
    cnf: None::<HolderConfirmation>,
    disclosures: vec![Disclosure {
        name: "claim".to_string(),
        value: json!({"allowed": true}),
    }],
})?;

let _ = signed;
Ok(())
}
```

## Security Notes

- This crate currently signs with EdDSA/Ed25519 through
  `registry-platform-crypto`.
- Holder-proof validation returns `jti` so consumers can perform replay
  detection in their own storage.
- `HolderProofPolicy::default` uses a 5-minute max lifetime and an empty
  audience. Set the audience explicitly in production.
- This crate validates cryptographic and binding checks, not credential
  revocation, replay storage, or authorization policy.

## Testing

```sh
cargo test -p registry-platform-sdjwt
```

## License

Apache-2.0.
