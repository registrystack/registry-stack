# Registry Notary SD-JWT VC conformance profile

> **Page type:** Standards conformance · **Product:** Registry Notary · **Layer:** credential · **Audience:** integrator

Adoption mode: profiled. Registry Notary issues a constrained SD-JWT VC profile
(`application/dc+sd-jwt`, EdDSA over Ed25519, `did:jwk` holder binding); it does
not claim full SD-JWT VC or OpenID4VCI conformance.

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
| Signing algorithm | `EdDSA` or `ES256` |
| Issuer key type | `OKP/Ed25519` or `EC/P-256` |
| Holder binding DID method | `did:jwk` |
| Credential status methods | Default: none. Optional IETF Token Status List `status_list` when `credential_status.enabled = true`, with `uri` at `/v1/credentials/{credential_id}/status` and `idx: 0`. Aggregated status lists and external revocation-list profiles are not supported. |

Registry Notary rejects credential profile format aliases such as
`sd_jwt_vc` and `application/vc+sd-jwt`. Operator configuration must use the
wire media type `application/dc+sd-jwt`.

## Issuer-Signed JWT Header

Issued credentials use a compact issuer-signed JWT as the first component of
the SD-JWT value. The protected header has these Registry Notary invariants:

- `alg` is `EdDSA`.
- `typ` is `dc+sd-jwt`.
- `kid` is the `kid` on the credential profile's configured signing key.

Only Ed25519 EdDSA signing keys are supported. Local JWK keys are supported for
development and tests; PKCS#11 keys are available behind the optional server
feature.

Signing key configuration examples are documented in
[signing-key-provider.md](signing-key-provider.md).

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
- issuer signing key types;
- holder binding methods;
- configured credential profiles;
- unsupported adjacent features.

The metadata is Registry Notary capability metadata. It is not a claim of full
OpenID4VCI issuer conformance.
The route is authenticated by default; clients use the same configured Notary
API key, bearer token, or OIDC credential they use for claim evaluation. Public
discovery for verifiers and wallets is limited to the issuer JWKS, OID4VCI
issuer metadata, and SD-JWT VC type-metadata routes.

When OID4VCI is enabled, Registry Notary serves SD-JWT VC Type Metadata at the
well-known location derived from each configured HTTPS `vct`. Per the SD-JWT VC
Type Metadata convention, a consumer dereferences an HTTPS `vct` by inserting
`/.well-known/vct` between the host and the path, so the metadata is served at
`GET /.well-known/vct/{vct_path}`.

- **Matching.** The handler strips the `/.well-known/vct` prefix and reconstructs
  the candidate `vct` as `https://{host}/{vct_path}`, then matches it exactly
  against a configured credential configuration. The route uses a trailing-wildcard
  capture, so nested configured paths such as
  `/.well-known/vct/credentials/dhis2/health-status/v1` are supported, not only two
  segments.
- **Direct dereference.** The bare `GET /credentials/{vct_path}` route is also
  served for consumers that dereference the `vct` directly.
- **Auth and prefixes.** Both routes are public (no authentication) and expect
  path-prefix deployments to strip the issuer prefix before forwarding to Notary,
  while preserving the external host and scheme.
- **Not found.** Both return `404` when OID4VCI is disabled or the reconstructed
  absolute URL does not exactly match a configured credential configuration `vct`.
- **Document contents.** The Type Metadata document includes the exact configured
  `vct`, display metadata, and one claim metadata entry for the OID4VCI
  configuration's `claim_id`. Notary-issued claim results are always selectively
  disclosable, so claim metadata uses `sd: "always"`. If the claim declares
  semantic bindings, the claim metadata also includes the Notary extension
  `registry_notary_semantics`; this labels the claim with external terms such as
  PublicSchema URIs but does not change the Notary claim-result payload shape.
- **CORS.** Browser-based wallets from configured self-attestation wallet origins
  receive CORS headers on the `/.well-known/vct/...` metadata surface.

## Verification

Registry Notary ships a verifier compatibility harness that exercises the
`verify_sd_jwt_vc` path in `registry-notary-client` against a committed set of
golden fixtures. The harness requires no secret material and no network access.

Run the harness:

```
cargo test -p registry-notary-server --test sd_jwt_vc_verifier_compat
```

Or with `cargo-nextest`:

```
cargo nextest run -p registry-notary-server sd_jwt_vc_verifier_compat
```

Fixture files live under `tests/fixtures/sd_jwt_vc/`. To regenerate them using
the server issuance path:

```
cargo run -p xtask -- gen-sd-jwt-vc-fixtures
```

The fixture set covers one valid credential, one valid holder-bound credential,
and seven negative variants: unsupported algorithm, wrong `kid`, wrong `vct`,
missing `cnf` when holder binding is required, malformed disclosure, expired
credential, and holder proof mismatch. Each negative fixture is asserted against
its exact error code from the verifier API.

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
