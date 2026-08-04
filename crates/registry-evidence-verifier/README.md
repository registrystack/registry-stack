# registry-evidence-verifier

Portable verification core for signed Evidence Version 1 responses.

## What It Provides

- `verifier::verify_flattened_jws` and `verifier::verify_sd_jwt_vc` for strict,
  fail-closed acceptance of the two signed response formats against a
  relying-party policy.
- `verifier::EvidenceVerificationPolicy` and its declarative
  `EvidenceVerificationPolicyDocument` form, including expected subjects,
  expected output value forms, accepted assurance profile, request nonce echo,
  accepted assertion lifetime, and clock skew.
- `model` wire types: the closed `Evidence` payload, its public value forms,
  the flattened JWS response, the unsigned envelope, and the JWKS document.
- `contracts::evidence_schema` and `contracts::evidence_contract_accepts`: the
  single source of the published Evidence payload schema and of the payload
  validation every verification performs.
- `sdjwt_vc` mapping between an Evidence payload and its SD-JWT VC issuance
  input and disclosed claim set.

## Typical Use

```rust
use registry_evidence_verifier::{
    model::{Evidence, JwksDocument},
    verifier::{verify_flattened_jws, EvidenceVerificationPolicy, VerificationError},
};

/// `serialized_jws` is the stored response body, `trusted_jwks` is the key set
/// the relying party pinned out of band, and `policy` carries the complete
/// independent expectation. The call returns the accepted payload or refuses.
fn accept(
    serialized_jws: &[u8],
    trusted_jwks: &JwksDocument,
    policy: &EvidenceVerificationPolicy,
) -> Result<Evidence, VerificationError> {
    verify_flattened_jws(serialized_jws, trusted_jwks, policy)
}
```

`verify_flattened_jws_report` and `verify_sd_jwt_vc_report` are the same checks
with cryptographic authenticity reported separately from current validity.

## Security Notes

- Verification is fail-closed: an unexpected protected header member, a
  disclosure that is not covered by the signed digests, a payload that the
  Version 1 schema rejects, or an expectation the policy states but the payload
  does not satisfy all return an error rather than a partial result.
- Every accepted input is bounded before it is decoded, so an oversized
  response cannot be turned into unbounded work or allocation.
- Trusted keys come only from the caller-supplied JWKS document. This crate
  never fetches key material and never accepts a key named by the response.
- The wire types redact their `Debug` output, so a verified payload cannot leak
  disclosed material into a log line, a panic message, or a snapshot.
- This crate verifies one stateless assertion. It holds no revocation state, no
  replay storage, and no authorization policy.

## Testing

```sh
cargo test -p registry-evidence-verifier
```

## License

Apache-2.0.
