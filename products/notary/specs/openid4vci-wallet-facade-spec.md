# OpenID4VCI wallet facade specification

Status: normative Registry Stack 1.0 profile.

Adoption mode: profiled OpenID4VCI subset.

## Purpose

Registry Notary exposes a narrow wallet facade for issuing holder-bound
`dc+sd-jwt` credentials from registry-backed evidence. The facade adapts the
Notary transaction and issuance model to wallets without creating a second
source-free credential trust surface.

Source-free `self_attested` claims remain available for evaluation. They cannot
authorize or produce credentials through either the Notary API or OID4VCI.

## Trust and topology

The actors and trust boundaries are:

| Actor | Responsibility |
| --- | --- |
| Citizen browser | Completes the identity-provider login and receives the rendered offer |
| Holder wallet | Redeems the pre-authorized code, proves control of an Ed25519 `did:jwk`, and stores the credential |
| Identity provider | Authenticates the citizen and returns the configured subject-binding claim to Notary |
| Registry Notary | Authorizes the transaction, stores its state, validates wallet proof, and issues the credential |
| Registry Relay | Executes the compiler-pinned registry consultation that supplies issuance evidence |

An authority deploys one Notary for each Relay authority. Notary owns its
correctness state, including transaction, pre-authorized code, replay,
evaluation, audit, and credential-status records. Production and multi-instance
deployments use the Notary-owned PostgreSQL schema.

The identity provider's authorization code is an internal browser-to-Notary
authentication input. It is never a wallet grant. The only wallet-facing grant
is an issuer-initiated pre-authorized code.

## Supported profile

Registry Stack 1.0 supports:

- credential format `dc+sd-jwt` and media type `application/dc+sd-jwt`;
- issuer signing with `EdDSA` or `ES256`, selected in the credential profile;
- JWT holder proof using `EdDSA` and the `did:jwk` binding method;
- issuer-initiated pre-authorized code offers;
- an optional numeric transaction code, enabled by default;
- immediate credential responses;
- registry-backed evidence with exact compiler-pinned Relay execution
  provenance;
- status-bearing credentials whose status is verified fail closed.

Registry Stack 1.0 does not claim:

- wallet-facing OAuth authorization-code issuance;
- source-free or self-attested credential issuance;
- a public nonce endpoint or credential-response next nonce;
- ES256 holder proof;
- PAR, DPoP, wallet attestation, EUDI Wallet, or HAIP conformance;
- deferred or batch issuance;
- mDoc, JSON-LD, `vc+sd-jwt`, or CWT proof support;
- delegated or representative credential issuance.

## Public routes

When OID4VCI and the pre-authorized flow are enabled, Notary exposes:

- `GET /.well-known/openid-credential-issuer`
- `GET /.well-known/vct/{vct_path}`
- `GET /credentials/{vct_path}`
- `GET /oid4vci/offer/start`
- `GET /oid4vci/offer/callback`
- `POST /oid4vci/token`
- `POST /oid4vci/credential`

`GET /oid4vci/credential-offer` and `POST /oid4vci/nonce` are not part of the
1.0 contract. The credential response does not return `c_nonce` or
`c_nonce_expires_in`.

## Issuance sequence

1. The citizen opens `GET /oid4vci/offer/start` in a browser.
2. Notary starts an identity-provider authorization-code login using PKCE.
3. The provider returns its code to `GET /oid4vci/offer/callback`.
4. Notary exchanges and validates that code, derives the configured subject,
   creates a registry transaction, executes the exact compiler-pinned Relay
   consultation, and stores the resulting evaluation provenance.
5. Only after those checks succeed, Notary renders an
   `openid-credential-offer://` URI containing a single-use pre-authorized code.
6. The wallet redeems the code at `POST /oid4vci/token`, including `tx_code`
   when the offer requires one.
7. Notary returns a short-lived access token and one proof nonce.
8. The wallet calls `POST /oid4vci/credential` with that access token and an
   EdDSA `did:jwk` proof.
9. Notary consumes the proof nonce, reloads the bound transaction and stored
   evaluation, verifies their exact provenance against the active compiled
   contract, and signs the credential.

No wallet request can choose a free-form subject or substitute a different
claim, profile, purpose, contract hash, Relay ULID, acquisition time, or
provenance record.

## Metadata

Issuer metadata is generated from the active configuration. Each credential
configuration advertises exactly:

- `format: dc+sd-jwt`;
- its configured HTTPS `vct`;
- `cryptographic_binding_methods_supported: [did:jwk]`;
- JWT proof with `proof_signing_alg_values_supported: [EdDSA]`;
- the issuer algorithm selected by its signing profile, `EdDSA` or `ES256`.

Metadata includes Notary's `/oid4vci/token` endpoint while the flow is enabled.
Offers contain only
`urn:ietf:params:oauth:grant-type:pre-authorized_code`. Metadata does not
advertise a nonce endpoint.

## Transaction code policy

`oid4vci.pre_authorized_code.tx_code.required` defaults to `true`. A required
transaction code is displayed separately from the offer URI. Missing and wrong
codes fail, repeated wrong attempts lock the offer, and invalid-code attempts
are rate limited.

Set `required: false` only when a wallet cannot present a transaction code. The
Walt compatibility profile uses this explicit setting. Without a transaction
code, the offer is bearer credential material until redemption, so:

- `pre_authorized_code_ttl_seconds` must be no more than 300 seconds;
- codes remain single-use;
- invalid redemption attempts remain rate limited;
- the offer URI must be protected from logs, screenshots, browser history,
  analytics, and unintended sharing;
- a stolen unredeemed offer can be redeemed by its holder within the bounded
  lifetime.

## Credential and status requirements

The issued SD-JWT VC contains issuer, subject, type, lifetime, holder binding,
and registry-backed disclosures derived from the stored transaction. The
top-level `status` claim is reserved by Notary and cannot be configured as a
selectively disclosable claim.

When a credential contains `status.status_list`, client verification must:

- fetch the signed status-list JWT only from the configured exact HTTPS trusted
  origin;
- validate its signature, issuer, type, index, and lifetime;
- require the indexed value to be valid;
- fail closed for missing, malformed, untrusted, unavailable, suspended,
  revoked, or expired status.

Status-free profiles remain explicit profile choices.

## Error and replay behavior

Pre-authorized codes, access tokens, proof nonces, and transaction bindings are
short-lived and single-use where applicable. A replay, expired artifact, wrong
transaction code, unsupported algorithm, unsupported binding, missing stored
evaluation, or provenance mismatch fails without credential issuance.

Errors must not expose raw identity-provider codes, wallet grants, access
tokens, proof JWTs, subject identifiers, registry rows, disclosures, or signing
keys.

## Evidence and conformance

Source tests cover the complete browser callback, offer, token, credential, and
client-verification path for EdDSA and ES256 issuer keys with an EdDSA
`did:jwk` holder. Tests also cover replay, tampering, source-free denial,
unsupported holder profiles, route removal, and status failure behavior.

External wallet, verifier, OIDF suite, or ecosystem conformance is claimed only
from a frozen candidate artifact with recorded product versions and immutable
evidence. Until that evidence is published, those rows remain candidate-only.
