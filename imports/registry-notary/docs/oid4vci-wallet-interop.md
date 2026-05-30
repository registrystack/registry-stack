# OID4VCI Wallet Interop Guide

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

OID4VCI requires all of these pieces:

- `auth.mode: oidc`.
- `self_attestation.enabled: true`.
- A reviewed subject-binding token claim.
- At least one claim in `self_attestation.allowed_claims`.
- At least one credential profile in `self_attestation.credential_profiles`.
- A credential profile with `holder_binding.mode: did`,
  `proof_of_possession: required`, and `allowed_did_methods: [did:jwk]`.
- `oid4vci.enabled: true`.
- A public HTTPS `credential_issuer` and endpoint URLs.
- A replay store appropriate for the deployment. Use Redis for multi-instance
  or public wallet traffic.

Self-attestation is the policy gate that prevents a wallet from using any valid
token to request another person's credential.

## Configuration Example

```yaml
auth:
  mode: oidc
  oidc:
    issuer: https://idp.example.gov
    jwks_uri: https://idp.example.gov/.well-known/jwks.json
    audiences:
      - registry-notary-wallet
    allowed_clients:
      - citizen-wallet
    scope_map:
      openid:
        - registry_notary:self_attest

self_attestation:
  enabled: true
  requires_auth_mode: oidc
  subject_binding:
    token_claim: civil_id
    claim_source: access_token
    request_field: subject_id
    id_type: UIN
    normalize: exact
  citizen_clients:
    allowed_client_ids:
      - citizen-wallet
    allowed_audiences:
      - registry-notary-wallet
  token_policy:
    required_acr_values:
      - urn:example:loa:substantial
    assurance_claim_source: access_token
    max_auth_age_seconds: 600
    max_access_token_lifetime_seconds: 900
    max_evaluation_age_seconds: 300
    max_credential_validity_seconds: 600
    max_clock_leeway_seconds: 60
  allowed_operations:
    evaluate: true
    render: false
    issue_credential: true
    batch_evaluate: false
  allowed_purposes:
    - wallet_credential_issuance
  allowed_claims:
    - birth-record-exists
  allowed_formats:
    - application/dc+sd-jwt
  allowed_disclosures:
    - value
    - redacted
  scope_policy: required
  required_scopes:
    - registry_notary:self_attest
  allowed_wallet_origins:
    - https://wallet.example.gov
  credential_profiles:
    - birth_record_sd_jwt
  rate_limits:
    mode: in_process
    invalid_token_per_client_address_per_minute: 20
    per_principal_per_minute: 30
    subject_mismatch_per_principal_per_hour: 5
    per_holder_per_hour: 20
    credential_issuance_per_principal_per_hour: 10

oid4vci:
  enabled: true
  credential_issuer: https://notary.example.gov
  authorization_servers:
    - https://idp.example.gov
  accepted_token_audiences:
    - registry-notary-wallet
  credential_endpoint: https://notary.example.gov/oid4vci/credential
  offer_endpoint: https://notary.example.gov/oid4vci/credential-offer
  nonce_endpoint: https://notary.example.gov/oid4vci/nonce
  nonce:
    enabled: true
    ttl_seconds: 300
  authorization:
    require_pkce_method: S256
  proof:
    max_age_seconds: 300
    max_clock_skew_seconds: 60
  credential_configurations:
    birth_record_sd_jwt:
      claim_id: birth-record-exists
      credential_profile: birth_record_sd_jwt
      format: dc+sd-jwt
      scope: birth_record
      vct: https://notary.example.gov/credentials/birth-record/v1
      display_name: Birth record attestation
```

The `credential_configurations` entry must be consistent with both the claim and
the credential profile:

- `claim_id` exists in `evidence.claims`.
- `claim_id` is allowed by `self_attestation.allowed_claims`.
- `credential_profile` exists in `evidence.credential_profiles`.
- `credential_profile` is allowed by `self_attestation.credential_profiles`.
- The claim references the credential profile.
- The profile allows the claim.
- `format` is `dc+sd-jwt`.
- `vct` matches the credential profile `vct`.

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
