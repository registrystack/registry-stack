# OID4VCI wallet interoperability

> **Page type:** How-to · **Product:** Registry Notary · **Layer:** credential · **Audience:** operator, integrator

Registry Notary exposes an issuer-initiated pre-authorized code flow for
issuing registry-backed `dc+sd-jwt` credentials to holder wallets. A
credential configuration can also select the digitally authenticated
representative ceremony for one registry-proven relationship. Identity-provider
and wallet inputs authorize and bind the flow; they do not become evidence.

## Supported 1.0 profile

The wallet facade supports:

- registry-backed claims whose exact compiler-pinned Relay execution is stored
  in a Notary transaction;
- bounded closed object and array claims from direct Relay outputs;
- `dc+sd-jwt` credentials;
- EdDSA or ES256 issuer signing, selected by the credential profile;
- EdDSA JWT holder proof with `did:jwk` binding;
- an issuer-initiated pre-authorized code grant;
- a representative-authenticated target-selection ceremony when explicitly
  configured;
- one credential per immediate response.

It does not support wallet-facing authorization-code grants, a public nonce
route, response next nonces, ES256 holder proof, credential issuance from
caller-provided evidence, EUDI or HAIP profiles, PAR, DPoP, or wallet
attestation.

The eSignet authorization code used during the browser callback is internal to
Notary's identity-provider login. The wallet never receives or redeems it.

## Topology and prerequisites

Deploy one Notary for each Relay authority. Notary owns its transaction,
pre-authorized code, proof replay, evaluation, audit, and credential-status
state. Use the Notary-owned PostgreSQL schema for production or multiple
instances. In-memory state is for explicit local single-process use only.

Before enabling the wallet facade:

- configure the Relay connection and compile the claim consultation pins;
- configure `subject_access` for the identity-provider binding claim;
- bind every OID4VCI configuration to one mutually valid registry-backed claim
  and credential profile;
- configure separate signing keys for identity-provider client assertions,
  Notary access tokens, and credentials;
- expose HTTPS issuer, callback, token, credential, and Type Metadata URLs;
- set the Notary state backend and rate limits.

See the [operator configuration reference](operator-config-reference.md) and
[credential issuance migration](credential-issuance-migration.md). For a
representative flow, use
[representative credential issuance](representative-credential-issuance.md).

## Create an offer from a registrar evaluation

An authorized registry client can create an offer after it evaluates the
authoritative record through `POST /v1/evaluations`. This path does not use the
citizen browser or identity-provider callback.

Generated projects admit registrar OIDC clients explicitly:

```yaml
oid4vci:
  public_base_url: https://notary.example.gov
  registrar_clients: [opencrvs-registrar]
```

Registryctl keeps these clients on the same pinned authorization server and
JWKS as the citizen client, but requires the Notary `public_base_url` as the
machine resource audience. The signed `JWT` access token needs a stable `sub`
that matches the evaluation owner, an admitted `azp` or `client_id`,
`registry_notary:credential_offer_create`, the selected credential
configuration's scope, and exact Registry Notary `authorization_details`.
Those details must permit `create_credential_offer` for the target, complete
claim set, value disclosure, claim-result format, purpose, service, and
machine access mode. Identify the target with the evaluated primary
identifier's scheme and value. When an entity has only a top-level
`target.id`, use the reserved authorization `id_type` value `id`; this keeps
typed identifiers distinct from the untyped top-level ID.

An admitted registrar client with the machine resource audience needs only
the access token; citizen userinfo and ID-token assurance are not required.
Any citizen client or citizen audience signal still selects the citizen path,
so mixed client/audience tokens cannot retain machine authority. A
Notary-issued wallet access token is not accepted.

Send only the stored evaluation identifier and configured credential type:

```http
POST /oid4vci/offers HTTP/1.1
Host: notary.example.gov
Authorization: Bearer <machine-client-token>
Idempotency-Key: <stable-retry-key>
Content-Type: application/json

{
  "evaluation_id": "<evaluation-id>",
  "credential_configuration_id": "birth_certificate_sd_jwt"
}
```

The request cannot contain a target, purpose, claim value, Relay result, or
provenance. Registry Notary reloads those values from the fresh caller-owned
evaluation and active reviewed configuration. It rejects denied, stale,
incompletely provenanced, mismatched, foreign, or already consumed evaluations before
creating an issuance transaction.

A successful response is:

```json
{
  "credential_offer_uri": "<sensitive-openid-credential-offer-uri>",
  "tx_code": "<separate-numeric-pin>",
  "expires_at": "2026-07-29T12:05:00Z"
}
```

Registrar-created offers always require `tx_code`, independent of the citizen
self-service transaction-code setting. The offer URI describes that
requirement but never contains the numeric PIN. The API separates the two
values but does not create a second communications channel. The registrar
integration must deliver the PIN separately from the QR code, link, message,
or device that carries the offer URI.

Treat the complete response as secret-adjacent. Every response uses
`Cache-Control: no-store` and `Pragma: no-cache`. Do not log the response,
offer URI, transaction code, target, raw evaluation values, or holder
identifiers.

Use the same `Idempotency-Key` only for an exact retry of the same request.
An exact retry returns the stored response and does not mint a second
transaction. Reusing the key for another request, using another key for an
evaluation already reserved for issuance, or racing two requests returns
`409`. A client-scoped quota can return `429`. Retry a lost response with the
original key; do not start another evaluation or invent a second key.
Exact replays, known idempotency conflicts, and consumed-evaluation preflights
do not call the signer. A genuinely new attempt consumes client quota before
signer work, so signer failures still count toward abuse protection.

The wallet then redeems the offer through `/oid4vci/token` and
`/oid4vci/credential`. The pre-authorized code, access token, proof nonce,
holder proof, and credential remain bound to the same immutable transaction.

## Check the citizen browser flow

1. Open this URL in the citizen's browser:

   ```text
   https://notary.example.gov/oid4vci/offer/start?credential_configuration_id=<id>
   ```

2. Complete the configured identity-provider login.
3. After the callback succeeds, scan or paste the rendered
   `openid-credential-offer://` URI into the wallet.
4. Enter the separately displayed numeric PIN when the wallet asks for the
   `tx_code`.
5. Confirm that the wallet redeems the offer at `/oid4vci/token` and calls
   `/oid4vci/credential` with an EdDSA `did:jwk` proof.
6. Verify the returned credential with the issuer JWKS and the expected holder
   binding.

A successful check establishes all of these observations:

- issuer metadata is reachable at
  `/.well-known/openid-credential-issuer`;
- Type Metadata is reachable at `/.well-known/vct/{vct_path}`;
- metadata advertises `dc+sd-jwt`, `did:jwk`, EdDSA holder proof, and the
  configured EdDSA or ES256 issuer algorithm;
- metadata has a `/oid4vci/token` endpoint and no nonce endpoint;
- the offer contains exactly the
  `urn:ietf:params:oauth:grant-type:pre-authorized_code` grant;
- the default offer contains a numeric `tx_code` description;
- the token response supplies the proof nonce bound to that transaction;
- the credential response has no next-nonce fields;
- the SD-JWT VC has the expected `iss`, `vct`, EdDSA `did:jwk` holder binding,
  and registry-backed disclosures.

```mermaid
sequenceDiagram
    autonumber
    actor Citizen
    participant Browser
    participant Notary as Registry Notary
    participant IdP as Identity provider
    participant Relay as Registry Relay
    participant Wallet

    Citizen->>Browser: Open offer start URL
    Browser->>Notary: Start configured credential transaction
    Notary-->>Browser: Redirect to identity provider
    Browser->>IdP: Authenticate citizen
    IdP-->>Browser: Return internal authorization code
    Browser->>Notary: Callback with code and state
    Notary->>IdP: Exchange code and validate subject
    Notary->>Relay: Execute compiler-pinned consultation
    Relay-->>Notary: Typed registry evidence
    Notary-->>Browser: Render pre-authorized offer and PIN
    Citizen->>Wallet: Transfer offer and enter PIN
    Wallet->>Notary: Redeem pre-authorized code and PIN
    Notary-->>Wallet: Access token and proof nonce
    Wallet->>Notary: Submit EdDSA did:jwk proof
    Notary-->>Wallet: Holder-bound dc+sd-jwt
```

## Transaction code modes

The secure default is:

```yaml
oid4vci:
  pre_authorized_code:
    enabled: true
    pre_authorized_code_ttl_seconds: 300
    tx_code:
      required: true
      input_mode: numeric
      length: 6
```

Codes are short-lived and single-use. Wrong PIN attempts are bounded per offer,
and invalid-code attempts are rate limited per client address.

Some wallet versions, including the Walt compatibility profile, cannot present
a transaction code. Make that weaker mode explicit:

```yaml
oid4vci:
  pre_authorized_code:
    enabled: true
    pre_authorized_code_ttl_seconds: 300
    tx_code:
      required: false
```

The TTL must be no more than 300 seconds in this mode. An offer without a PIN is
bearer credential material until redemption. A person who steals the
unredeemed offer can use it during that window. Keep the offer out of logs,
analytics, screenshots, browser synchronization, and support messages. The
code remains single-use and redemption remains rate limited.

## Metadata and Type Metadata

Issuer metadata is derived from active Notary configuration. Wallets should
assert exact values rather than infer capability from permissive schema fields:

- `credential_issuer` equals the configured public issuer;
- `token_endpoint` equals the Notary token endpoint;
- every credential configuration has `format: dc+sd-jwt`;
- `cryptographic_binding_methods_supported` is exactly `[did:jwk]`;
- JWT `proof_signing_alg_values_supported` is exactly `[EdDSA]`;
- the issuer algorithm is exactly the active profile algorithm;
- `vct` is the configured public HTTPS identifier;
- no nonce endpoint is advertised.

Notary serves Type Metadata at both the configured `vct` URL and the
`/.well-known/vct/{vct_path}` form used by wallets. It describes each projected
claim and its selective-disclosure behavior. `status` is a reserved top-level
claim and cannot be projected as a selectively disclosable value.

For a direct structured Relay output, each claim also includes the namespaced
`registry_notary_value_schema` member. The member publishes the exact closed
recursive value contract, including required object fields, item schemas, and
byte and item bounds. It does not define nested disclosure. A top-level object
or array claim is one SD-JWT disclosure: the holder discloses or withholds the
complete value.

## Credential request and response

The wallet sends one proof using either the supported single-proof shape or the
single-entry proof-array shape. Multiple proofs and mixed shapes are rejected.
The proof must be fresh, have the Notary issuer as audience, contain the
transaction-bound nonce from the token response, use EdDSA, and identify the
holder as `did:jwk`.

The response contains the immediate credential in its compatibility envelope.
It does not return a new proof nonce. The wallet or verifier should check:

- issuer signature and configured issuer algorithm;
- expected `vct` and credential lifetime;
- exact EdDSA `did:jwk` holder binding;
- SD-JWT disclosure hashes;
- live status when the credential contains a status claim.

For a status-bearing credential, verification fails closed on an unavailable,
untrusted, malformed, expired, suspended, revoked, or otherwise invalid status
response. Status retrieval is restricted to the configured exact HTTPS trusted
origin.

## Security invariants

- Notary creates the offer only after the identity binding and registry-backed
  evaluation succeed, or after an authorized registrar selects an existing
  fresh caller-owned registry-backed evaluation.
- In representative mode, the relationship proof runs before its dependent
  credential claims. Offer and token expiry cannot exceed proof expiry.
- The credential endpoint reloads the stored transaction and verifies the
  active claim, profile, purpose, contract hash, Relay ULID, acquisition time,
  and claim provenance before signer access.
- Wallet input cannot select a free-form subject or replace stored evidence.
- The credential endpoint performs no new Relay consultation. Representative
  lifecycle changes after issuance require credential revocation.
- Pre-authorized codes, access tokens, proof nonces, and transaction bindings
  are time bounded and replay protected.
- Identity-provider codes, wallet grants, access tokens, proof JWTs, subjects,
  registry rows, and disclosures must not appear in logs.

## Compatibility evidence

Record the wallet and verifier product, exact version, configuration override,
artifact digest, and observed result for every external run. Local source tests
cover EdDSA and ES256 issuer variants with an EdDSA `did:jwk` holder. External
wallet, verifier, OIDF, EUDI, or HAIP conformance remains candidate-only until a
frozen candidate artifact and immutable evidence are published.

## Troubleshooting

| Symptom | Likely cause | Check |
| --- | --- | --- |
| OID4VCI routes are unavailable | The facade or pre-authorized flow is disabled | Expanded config and startup diagnostics |
| Configuration is rejected | A claim lacks a Relay consultation, a profile binding is one-sided, or delegated issuance lacks the representative ceremony | Claim evidence mode, representative policy, profile bindings, and OID4VCI projections |
| Offer is not rendered | Identity binding, Relay execution, or stored transaction creation failed | Sanitized audit records and Relay availability |
| Wallet asks for a different grant | Wallet does not support issuer-initiated pre-authorized code | Wallet version and imported offer |
| PIN is rejected | Wrong, expired, replayed, or locked offer | Offer age and rate-limit diagnostics |
| Wallet cannot send a PIN | Compatibility profile needs explicit bearer-offer mode | `tx_code.required: false` and TTL no more than 300 seconds |
| Proof is rejected | Unsupported algorithm or binding, stale proof, wrong audience, or nonce mismatch | Wallet proof header and claims |
| Credential is denied after token redemption | Stored registry transaction is missing, stale, or does not match active compiler pins | Re-run the browser journey under one project generation |
| Wallet cannot verify | Issuer JWKS, `kid`, algorithm, `vct`, holder binding, or status mismatch | Active signing profile and verifier diagnostics |
| Multiple instances disagree | In-memory correctness state is in use | Install and select Notary-owned PostgreSQL state |
