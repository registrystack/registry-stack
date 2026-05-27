# registry-platform-oid4vci

OID4VCI protocol constants, metadata structs, and proof validation helpers for
registry services acting as credential issuers.

## What It Provides

- Protocol constants (`PROOF_JWT_TYPE`, `SD_JWT_VC_FORMAT`, `AUTHORIZATION_CODE_GRANT_TYPE`, etc.).
- `CredentialIssuerMetadata` and `CredentialConfigurationMetadata` for
  `.well-known/openid-credential-issuer` responses.
- `CredentialConfigurationMetadata::sd_jwt_vc()` for constructing an SD-JWT VC
  configuration entry matching the OID4VCI draft spec.
- `CredentialOffer::authorization_code()` for constructing credential offer objects.
- `validate_proof_jwt` for verifying a holder-bound proof JWT presented at the
  credential endpoint. Validates structure, `typ`, signature, audience, nonce,
  and time bounds. Returns a `ValidatedProof` carrying the holder JWK and
  verified claims.
- `ProofValidationPolicy` for configuring validation parameters.
- Wire types for nonce, credential, and error responses.

## Spec References

- [OpenID for Verifiable Credential Issuance (OID4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- Proof JWT type: `openid4vci-proof+jwt`
- Grant type: `authorization_code`
- Credential format: `dc+sd-jwt`

## Security Notes

- **Nonce replay is a caller responsibility.** `validate_proof_jwt` validates that
  the nonce in the proof matches `policy.expected_nonce`, but it does not track
  nonce usage across calls. Callers must store and reject used nonces. The
  `ValidatedProof::nonce` field carries the nonce back for this purpose.
- Proof JWTs must use EdDSA with `did:jwk` holder binding. RS\*/PS\*/ES\* keys
  and `jku`/`x5u`/`x5c`/`crit` headers are rejected.
- Proof audience is validated against `policy.audience` before any JWKS lookup.

## Testing

```sh
cargo test -p registry-platform-oid4vci
```

## License

Apache-2.0.
