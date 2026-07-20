# registry-platform-oid4vci

OID4VCI protocol constants, metadata types, offer and token wire types, and
holder-proof validation helpers for Registry Stack issuers.

## What it provides

- `CredentialIssuerMetadata` and `CredentialConfigurationMetadata` for issuer
  discovery.
- `CredentialConfigurationMetadata::sd_jwt_vc()` for `dc+sd-jwt` metadata.
- `CredentialOffer::pre_authorized_code()` and the pre-authorized token request
  wire types.
- `validate_proof_jwt` for validating structure, `typ`, signature, audience,
  nonce, and time bounds.
- `ProofValidationPolicy::credential_endpoint` for configuring proof checks.
- `consume_validated_proof_nonce_once` for binding a validated proof to a
  required replay-store consume operation.
- Credential and protocol error response types.

The crate supplies protocol primitives. Registry Notary defines the public 1.0
profile: registry-backed issuer-initiated pre-authorized code, `dc+sd-jwt`,
EdDSA or ES256 issuer signing, and EdDSA `did:jwk` holder proof. It has no public
nonce route and returns no next nonce from the credential endpoint.

## Specification reference

- [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- Proof JWT type: `openid4vci-proof+jwt`
- Wallet grant:
  `urn:ietf:params:oauth:grant-type:pre-authorized_code`
- Credential format: `dc+sd-jwt`

## Security notes

- Proof nonce consumption is a caller responsibility. `validate_proof_jwt`
  checks the expected nonce but does not mutate replay state. Call
  `consume_validated_proof_nonce_once` with a correctness-state replay store.
- Registry Notary accepts only EdDSA proof JWTs with `did:jwk` holder binding.
  ES256 holder keys and `jku`, `x5u`, `x5c`, or `crit` headers are rejected.
- Proof audience is validated before issuer or holder key use.
- A transaction code is required by default. If a caller deliberately builds a
  bearer offer without one, its lifetime must be no more than 300 seconds and
  redemption must remain single-use and rate limited.

## Testing

```sh
cargo test --locked -p registry-platform-oid4vci
```

## License

Apache-2.0.
