# Registry Notary SD-JWT VC Conformance Profile

Registry Notary currently issues one credential format: SD-JWT VC using the
current digital credential media type.

This profile is intentionally narrow. It documents the credential contract that
Registry Notary can test and support today, and it names adjacent ecosystem
features that are not yet part of the product surface.

## Supported Credential Format

| Field | Value |
| --- | --- |
| Credential media type | `application/dc+sd-jwt` |
| Compact JWT `typ` header | `dc+sd-jwt` |
| Signing algorithm | `EdDSA` |
| Issuer key type | `OKP/Ed25519` |
| Holder binding DID method | `did:jwk` |
| Credential status methods | none |

Registry Notary rejects credential profile format aliases such as
`sd_jwt_vc` and `application/vc+sd-jwt`. Operator configuration must use the
wire media type `application/dc+sd-jwt`.

## Issuer-Signed JWT Header

Issued credentials use a compact issuer-signed JWT as the first component of
the SD-JWT value. The protected header has these Registry Notary invariants:

- `alg` is `EdDSA`.
- `typ` is `dc+sd-jwt`.
- `kid` is the configured credential profile `issuer_kid`, or the derived
  fallback `{issuer}#evidence-issuer`.

Only Ed25519 private JWK issuer keys are supported. Adding ES256, RS256, PS256,
or other algorithms requires a separate design and test pass.

## Issuer-Signed JWT Payload

Registry Notary sets these payload claims:

- `iss`: credential profile issuer.
- `sub`: holder DID for holder-bound credentials, otherwise the evaluation
  subject reference.
- `iat`: evaluation issue instant supplied by the caller.
- `exp`: `iat + credential_profile.validity_seconds`.
- `vct`: credential profile verifiable credential type URI.
- `jti`: generated credential identifier.
- `id`: same generated credential identifier as `jti`.
- `_sd`: sorted disclosure digest list.
- `cnf`: holder confirmation for holder-bound credentials.

For citizen-facing holder-bound credentials, `sub` is the holder DID. Registry
Notary does not claim that the holder DID is the same identifier as the civil
or registry subject.

## Holder Binding

When a credential profile requires holder proof of possession:

- `holder_binding.mode` is `did`.
- `holder_binding.proof_of_possession` is `required`.
- `holder_binding.allowed_did_methods` must contain only `did:jwk`.
- The issuance request must provide a holder DID and proof payload accepted by
  the server holder-proof validator.
- The issued credential includes `cnf.kid` equal to the holder DID.
- The issued credential includes `cnf.jwk` with the public holder JWK only.

Registry Notary does not support `did:key`, `did:web`, CWT proof, or mDoc
holder binding in this profile.

## Disclosures

Each evaluated claim result becomes one selectively disclosable claim. The
disclosure payload contains:

- `claim_id`
- `version`
- `value`
- `satisfied`
- `subject_type`
- `issued_at`

The issuer-signed JWT stores disclosure digests in sorted order. The raw
compact SD-JWT value is returned separately from the issuer-signed JWT and
disclosure list so callers can verify or present the pieces without reparsing
the whole credential.

## Discovery

`/.well-known/evidence-service` exposes a `credential_capabilities` object with
the same constants listed in this profile:

- supported credential media types;
- SD-JWT VC JWT `typ`;
- signing algorithms;
- issuer key types;
- holder binding methods;
- configured credential profiles;
- unsupported adjacent features.

The metadata is Registry Notary capability metadata. It is not a claim of full
OpenID4VCI issuer conformance.

## Explicit Non-Support

The following features are out of scope for the current profile:

- `application/vc+sd-jwt` compatibility alias;
- JSON-LD Verifiable Credential issuance;
- Data Integrity proofs;
- external status-list or revocation-list profiles;
- mDoc/mDL;
- CWT proof binding;
- full OpenID4VCI issuer behavior.

These features require separate compatibility, lifecycle, and security design
before implementation.
