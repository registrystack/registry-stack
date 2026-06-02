# OID4VCI Wallet Interop Guide

> **Page type:** How-to · **Product:** Registry Notary · **Layer:** credential · **Audience:** integrator

This guide describes the implemented OpenID4VCI wallet facade for Registry
Notary adopters. It focuses on what wallet and platform teams need to configure
and test. It does not try to freeze the broader REST API design.

## Use Case

Use the OID4VCI facade when a citizen wallet should request a Registry Notary
SD-JWT VC directly. The wallet holds an access token from an authorization
server, proves control of a holder key, and receives a short-lived credential
for a configured claim.

The facade is intentionally narrow:

- Credential format is `dc+sd-jwt`.
- Issued VC media type is `application/dc+sd-jwt`.
- Proof type is JWT.
- Supported proof algorithm is `EdDSA`.
- Supported holder binding method is `did:jwk`.
- Issuance is backed by self-attestation policy and configured evidence claims.

It is not a full OpenID4VCI issuer product. It is an interoperability facade for
Registry Notary's current SD-JWT VC issuance path.

## Prerequisites

The wallet facade requires server-side OID4VCI and self-attestation
configuration before any wallet can request a credential. Self-attestation is
the policy gate that prevents a wallet from using any valid token to request
another person's credential. The operator who runs Notary owns these settings;
this guide assumes they are already in place.

For the full configuration, including the `auth.oidc`, `self_attestation`, and
`oid4vci` blocks and their constraints, see the
[operator configuration reference](operator-config-reference.md). For the policy
gate that binds a request to the token subject, see the
[self-attestation operator guide](self-attestation-operator-guide.md).

## Wallet Flow

The current wallet-facing flow is:

1. Wallet discovers issuer metadata.
2. Wallet obtains or receives a credential offer for a configured credential.
3. Wallet obtains an OIDC access token from the configured authorization server.
4. Wallet requests a nonce when nonce support is enabled.
5. Wallet sends a credential request with `format: "dc+sd-jwt"` and a JWT proof.
6. Notary validates the access token, subject binding, self-attestation policy,
   nonce and proof, then reads the source and issues the SD-JWT VC.

The credential request should not carry a raw subject id as a free-form wallet
choice. The subject comes from the OIDC token claim configured in
`self_attestation.subject_binding` and must match the Notary request context.

## Metadata And Offers

Issuer metadata is derived from `oid4vci` and the configured credential
configurations. Wallets should verify that metadata advertises:

- `credential_issuer` equal to the public issuer URL.
- Authorization servers matching the wallet's token issuer.
- Credential endpoint matching the configured HTTPS endpoint.
- Credential configurations for the expected credential ids.
- `format: dc+sd-jwt`.
- `proof_signing_alg_values_supported: [EdDSA]`.
- `cryptographic_binding_methods_supported: [did:jwk]`.
- `vct` equal to a public HTTPS URL served by the Notary.

For SD-JWT VC wallet interoperability, the Notary serves public Type Metadata at
each configured `vct` URL. A wallet can `GET` the `vct` without authentication.
The response is `application/json`, returns `404` when OID4VCI is disabled or no
configured `vct` matches, and includes:

- `vct`: the exact absolute URL requested by the wallet.
- `name` and `display[].locale`/`display[].name`.
- `claims[].path` using the configured OID4VCI `claim_id`.
- `claims[].display[].locale`/`claims[].display[].label`.
- `claims[].sd: "always"`, because Notary emits evaluated claim results as
  selectively disclosable SD-JWT disclosures.

Credential offers are intentionally lightweight. They tell the wallet which
credential configuration to request and which issuer metadata to use. If more
than one credential configuration is enabled, wallet tests should explicitly
select the intended configuration.

## Nonce Policy

Enable nonce support for real wallet interop:

```yaml
oid4vci:
  nonce:
    enabled: true
    ttl_seconds: 300
  nonce_endpoint: https://notary.example.gov/oid4vci/nonce
```

Nonce TTL must be between 1 and 600 seconds. When nonce is enabled,
`nonce_endpoint` is required.

For multiple credential configurations, the nonce request should identify the
credential configuration. That keeps a nonce from being reused across a
different credential configuration.

Use Redis replay storage for nonce-backed wallet traffic when more than one
process can receive requests.

## Credential Request

The wallet credential request uses:

```json
{
  "format": "dc+sd-jwt",
  "credential_configuration_id": "birth_record_sd_jwt",
  "proof": {
    "proof_type": "jwt",
    "jwt": "<holder-proof-jwt>"
  }
}
```

The proof JWT should demonstrate holder control of a `did:jwk` key and be fresh
within `oid4vci.proof.max_age_seconds`, allowing only
`max_clock_skew_seconds` of clock difference.

Notary rejects unsupported formats, unsupported proof algorithms, stale proofs,
replayed nonces, subject-binding mismatches, claims outside the allow-list, and
credential profiles outside the allow-list.

## Credential Response

Successful responses contain the issued SD-JWT VC:

```json
{
  "format": "dc+sd-jwt",
  "credential": "<sd-jwt-vc>",
  "c_nonce": "<optional-next-nonce>",
  "c_nonce_expires_in": 300
}
```

Wallets should store the credential as SD-JWT VC and verify:

- Issuer key resolves from Notary JWKS.
- `vct` matches the requested credential configuration.
- Holder binding is the wallet's `did:jwk`.
- Expiry is short and within deployment policy.
- Optional status URL is handled according to verifier policy.

The response does not need to echo every request field. Wallet tests should
assert the credential content, not just the response envelope.

## Compatibility Checklist

For each wallet product or SDK:

- Can it parse issuer metadata with `dc+sd-jwt` credential configurations?
- Can it request or accept a credential offer for a specific configuration id?
- Can it obtain an access token with the configured audience and scopes?
- Does the access token carry the subject-binding claim Notary expects?
- Can it generate a JWT proof using EdDSA and a `did:jwk` holder key?
- Does it include and refresh nonces according to issuer responses?
- Does it accept short-lived credentials?
- Does it preserve SD-JWT disclosures without logging them?
- Can it display status-free credentials and status-bearing credentials?
- Does it fail clearly on `invalid_token`, proof failure, nonce replay, and
  subject mismatch?

Record the wallet name, version, supported draft/profile behavior, and any
configuration overrides in your deployment notes.

## Security And Privacy Notes

- Notary validates token and policy before source reads.
- Subject binding is exact; do not use normalization that could join different
  civil identifiers.
- `allowed_wallet_origins` must be exact HTTPS origins and must not include
  wildcards.
- Access tokens, proof JWTs, holder keys, SD-JWT disclosures, source rows, and
  raw subject ids must not be logged.
- In-process rate limits are a guardrail, not the only public-edge protection.
  Use gateway and identity-provider controls as well.
- A holder DID can become a correlation handle if reused widely. Wallets should
  follow their privacy model for pairwise or purpose-specific keys.

## Troubleshooting

| Symptom | Likely cause | Check |
| --- | --- | --- |
| Metadata route is unavailable | `oid4vci.enabled` is false or self-attestation is disabled | Expanded config and startup logs |
| Config fails validation | OID4VCI references a claim or credential profile outside self-attestation allow-lists | `credential_configurations`, `self_attestation.allowed_claims`, `self_attestation.credential_profiles` |
| Wallet token rejected | Audience, issuer, client id, scope, or algorithm mismatch | `auth.oidc`, `oid4vci.accepted_token_audiences`, wallet token header and claims |
| Subject mismatch | Token claim does not exactly match the requested subject context | `self_attestation.subject_binding` and identity-provider claims |
| Nonce rejected | Nonce expired, reused, or from another configuration | Nonce TTL, replay store, credential configuration id |
| Proof rejected | Unsupported alg, wrong holder binding, stale proof, or clock skew | Wallet proof JWT and `oid4vci.proof` |
| Credential issued but wallet cannot verify | JWKS, issuer DID, `kid`, or `vct` mismatch | Signing key config and credential profile |
| Works with one process but fails in active-active | In-memory replay store | Use Redis replay storage |
