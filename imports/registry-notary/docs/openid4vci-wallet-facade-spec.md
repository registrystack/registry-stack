# OpenID4VCI Wallet Facade Spec

## Goal

Add an optional OpenID4VCI issuer facade for Registry Witness so citizen
self-attestation credentials can be downloaded by standards-oriented wallets
such as Inji Wallet and Walt Wallet.

The facade must be wallet-neutral. Inji and Walt are validation clients, not
special cases. eSignet remains the citizen identity provider. Registry Witness
remains the authorization, subject-binding, source-read, audit, and credential
issuance authority.

```text
Wallet
  -> OpenID4VCI issuer metadata and credential offer
  -> eSignet citizen authentication
  -> Witness OpenID4VCI credential endpoint
  -> Witness self-attestation guard
  -> Registry Relay/source read
  -> Witness SD-JWT VC issuance
```

## Background

Registry Witness already supports citizen self-attestation through its custom
API surface:

1. `POST /claims/evaluate`
2. `POST /credentials/issue`

That shape is practical for scripts and portals, but wallets generally expect
OpenID4VCI:

1. Fetch issuer metadata from `/.well-known/openid-credential-issuer`.
2. Authenticate the citizen through an authorization server.
3. Submit an access token and wallet proof JWT to a credential endpoint.
4. Receive a credential response in the advertised format.

Witness can already issue `application/dc+sd-jwt` credentials, but its holder
proof is currently stricter and more Witness-specific than the standard
OpenID4VCI proof JWT most wallets generate. The facade therefore needs to adapt
the protocol without weakening the existing Witness `/credentials/issue`
contract.

## Actors

| Actor | Responsibility |
| --- | --- |
| Citizen wallet | Discovers issuer metadata, launches citizen authentication, signs holder proof, stores the credential |
| eSignet | Authenticates the citizen and provides the verified subject-binding claim |
| Registry Witness | Publishes OpenID4VCI facade, validates token and proof, enforces self-attestation policy, issues credential |
| Registry Relay/source | Supplies configured civil registry facts after Witness authorization |
| Registry Platform | Provides reusable cryptographic, OpenID4VCI, SD-JWT, OIDC, and test-fixture primitives |
| Registry Lab | Orchestrates the optional demo, scripts, artifacts, and wallet smoke checks |

## User Story

A citizen opens a wallet, scans or follows a credential offer for
`person_is_alive_sd_jwt`, authenticates with eSignet, and receives a
holder-bound SD-JWT VC proving `person-is-alive` for their own bound civil
identifier.

The citizen must not be able to request another person's claim, choose an
arbitrary subject in the credential request, bypass self-attestation policy, or
cause a registry source read before subject binding succeeds.

## Non-Goals

- Full OpenID4VCI feature coverage.
- Pre-authorized code flow in V1.
- Deferred credential issuance.
- Batch credential issuance.
- mDoc, JSON-LD, `vc+sd-jwt`, or CWT proof support.
- Wallet-specific custom APIs.
- Delegation, guardianship, representative access, or multi-subject flows.
- Proving that the wallet holder DID is the same identifier as the civil
  subject.
- Changing the existing `/claims/evaluate` and `/credentials/issue` protocol.

## Protocol Surface

The facade is disabled by default and enabled by explicit Witness config.

### `GET /.well-known/openid-credential-issuer`

Returns issuer metadata for configured citizen self-attestation credentials.

Required V1 fields:

- `credential_issuer`
- `authorization_servers`
- `credential_endpoint`
- `nonce_endpoint`
- `credential_configurations_supported`

The metadata must not expose internal registry source names, source URLs,
source credentials, raw civil identifiers, or operator-only policy details.

Example:

```json
{
  "credential_issuer": "http://127.0.0.1:4325",
  "authorization_servers": ["http://localhost:8088/v1/esignet"],
  "credential_endpoint": "http://127.0.0.1:4325/oid4vci/credential",
  "nonce_endpoint": "http://127.0.0.1:4325/oid4vci/nonce",
  "credential_configurations_supported": {
    "person_is_alive_sd_jwt": {
      "format": "dc+sd-jwt",
      "scope": "person-is-alive",
      "vct": "https://registry.example.gov/credentials/person-is-alive",
      "cryptographic_binding_methods_supported": ["did:jwk"],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["EdDSA"]
        }
      },
      "claims": {
        "person-is-alive": {
          "display": [
            {
              "name": "Person is alive",
              "locale": "en"
            }
          ]
        }
      },
      "display": [
        {
          "name": "Civil status attestation",
          "locale": "en"
        }
      ]
    }
  }
}
```

`format` uses the OpenID4VCI credential format identifier expected by wallets.
Witness still issues the wire credential media type documented in the SD-JWT VC
profile.

### `GET /oid4vci/credential-offer`

Returns a credential offer for a configured credential configuration id.

V1 supports:

- query parameter `credential_configuration_id`;
- JSON response containing the offer object and deep-link URL;
- plain-text URL response when `Accept: text/plain` is supplied.

The offer must not include a subject id. The subject is derived only from the
verified eSignet token at credential issuance time.

Example response:

```json
{
  "credential_offer": {
    "credential_issuer": "http://127.0.0.1:4325",
    "credential_configuration_ids": ["person_is_alive_sd_jwt"],
    "grants": {
      "authorization_code": {
        "issuer_state": "..."
      }
    }
  },
  "url": "openid-credential-offer://?credential_offer=..."
}
```

### `POST /oid4vci/nonce`

Returns a nonce for wallet proof JWT replay protection.

Example response:

```json
{
  "c_nonce": "...",
  "c_nonce_expires_in": 300
}
```

The endpoint is public in V1 but rate-limited. It does not accept or return a
subject id. The nonce is later consumed by `POST /oid4vci/credential`.

### `POST /oid4vci/credential`

Accepts a wallet credential request and returns an OpenID4VCI credential
response.

Example request:

```json
{
  "credential_configuration_id": "person_is_alive_sd_jwt",
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJ..."
  }
}
```

Processing order is security-sensitive:

1. Parse and validate bearer token without logging token material.
2. Verify the token using the existing OIDC/eSignet policy.
3. Classify the request as citizen self-attestation.
4. Validate OpenID4VCI credential configuration id.
5. Validate the wallet proof JWT and consume nonce when required.
6. Extract the configured subject-binding claim from verified claims or
   verified UserInfo. UserInfo is a network call and must happen only after the
   proof is valid.
7. Construct the internal subject from the verified binding claim.
8. Run the same self-attestation subject-binding guard used by
   `/claims/evaluate`.
9. Only then read the configured registry source.
10. Issue the configured SD-JWT VC profile.
11. Return the credential response.

The request body must not contain a subject id in V1. If a wallet or malicious
client supplies one through an extension field, the request is denied.

Example response:

```json
{
  "credential": "eyJ...~WyI...~",
  "format": "dc+sd-jwt",
  "credential_configuration_id": "person_is_alive_sd_jwt",
  "c_nonce": "...",
  "c_nonce_expires_in": 300
}
```

V1 targets a pragmatic compatibility profile: OpenID4VCI Draft 13 response
fields for Inji-style clients plus a dedicated nonce endpoint for Final-style
clients. If a wallet rejects this profile, the compatibility smoke must record
the exact field mismatch before any wallet-specific workaround is added.
Each live wallet smoke must record the wallet product, version or commit, and
the OpenID4VCI draft/profile behavior observed during the run.

## Configuration

Add an optional top-level Witness block:

```yaml
oid4vci:
  enabled: true
  credential_issuer: http://127.0.0.1:4325
  authorization_servers:
    - http://localhost:8088/v1/esignet
  accepted_token_audiences:
    - http://127.0.0.1:4325
  credential_endpoint: http://127.0.0.1:4325/oid4vci/credential
  offer_endpoint: http://127.0.0.1:4325/oid4vci/credential-offer
  nonce_endpoint: http://127.0.0.1:4325/oid4vci/nonce
  nonce:
    enabled: true
    ttl_seconds: 300
  authorization:
    require_pkce_method: S256
  credential_configurations:
    person_is_alive_sd_jwt:
      claim_id: person-is-alive
      credential_profile: civil_status_sd_jwt
      format: dc+sd-jwt
      scope: person-is-alive
      vct: https://registry.example.gov/credentials/person-is-alive
      display_name: Person is alive
      proof_signing_alg_values_supported:
        - EdDSA
      cryptographic_binding_methods_supported:
        - did:jwk
```

Validation rules:

- `oid4vci.enabled = true` requires `self_attestation.enabled = true`.
- Each credential configuration must reference an allowed self-attestation
  claim.
- Each credential configuration must reference an allowed self-attestation
  credential profile.
- `format` must be `dc+sd-jwt` in V1.
- `proof_signing_alg_values_supported` must contain only supported algorithms.
- `cryptographic_binding_methods_supported` must contain only `did:jwk` in V1.
- `credential_issuer`, `credential_endpoint`, and `offer_endpoint` must be
  absolute URLs.
- `nonce_endpoint` must be configured when `nonce.enabled = true`.
- `accepted_token_audiences` must be non-empty when `oid4vci.enabled = true`;
  the lab default is `credential_issuer`.
- `accepted_token_audiences` must be matched against verified token claims, not
  against runtime `Host` or `X-Forwarded-Host` headers.
- Public metadata URLs must be consistent with the configured listener or
  operator-supplied external base URL.
- HTTPS is required outside loopback/dev configurations. Plain HTTP is allowed
  only for loopback lab URLs.
- The `oid4vci` config block must deserialize with `#[serde(default)]` so
  existing configs continue to load when the facade is absent.
- Cross-block validation must be implemented as a dedicated
  `validate_oid4vci_cross_block()` path or equivalent, not scattered across
  route handlers.

## Security Invariants

- The facade is disabled by default.
- The facade requires OIDC/eSignet authentication.
- The subject used for evaluation is derived only from verified token claims or
  verified UserInfo.
- The wallet request cannot choose a subject.
- Subject binding succeeds before any source read.
- A request for another subject is denied before any source read.
- A credential configuration id maps to exactly one configured claim and one
  configured credential profile.
- The wallet proof binds the credential to a wallet-controlled key.
- Holder binding does not prove holder-equals-civil-subject.
- No raw token, raw civil id, holder private key, source credential, or source
  row appears in logs, audit events, script artifacts, or error bodies.
- Existing `/claims/evaluate` and `/credentials/issue` behavior remains
  unchanged unless self-attestation config already changes it.

## V1 Trust And Privacy Boundaries

V1 is a practical wallet interoperability feature. It must not overclaim
production wallet-ecosystem trust.

V1 validates:

- the citizen's current OIDC/eSignet token;
- the configured citizen subject-binding claim or verified UserInfo claim;
- the token audience against configured `oid4vci.accepted_token_audiences`;
- the requested credential configuration id;
- the wallet's proof of possession for the key used as the credential holder;
- the configured self-attestation claim and credential profile policy.

V1 does not validate:

- that the wallet application is certified by any external scheme;
- that the holder key is hardware-backed or stored in a secure element;
- that a wallet instance has not been revoked by a wallet provider;
- issuer access certificates, trusted lists, or external ecosystem trust
  anchors;
- credential status or revocation after issuance;
- delegated authority between the citizen and another civil subject.

Privacy boundaries:

- Offers and metadata must not contain civil identifiers.
- The credential request must not contain a civil subject id.
- Audit events and lab artifacts must contain only hashed or bounded
  identifiers.
- Holder-bound credentials should use the holder DID as the credential subject
  in V1, not the raw civil subject id.
- Stable civil identifiers must not appear in credential payloads unless a
  credential profile explicitly requires them and the privacy impact is
  reviewed.
- V1 should prefer short-lived credentials and re-issuance over long-lived
  linkable credentials.

## Holder Proof Compatibility

OpenID4VCI wallets normally produce a standard proof JWT. Witness currently
requires a custom holder proof on `/credentials/issue` that binds additional
internal values such as `evaluation_id`, `credential_profile`, disclosure hash,
and claim set.

V1 must keep the existing strict proof for `/credentials/issue` and add a
separate OpenID4VCI proof validator for `/oid4vci/credential`.

The OpenID4VCI validator must:

- accept `proof_type = jwt`;
- require `typ = openid4vci-proof+jwt`;
- reject `alg = none` and any algorithm not explicitly configured;
- accept holder public key material from either an embedded public JWK or a
  `kid` that is a `did:jwk` reference;
- reject private key material such as JWK `d`;
- reject remote or ambiguous key references such as `jku`, `x5u`, `x5c`, or
  unsupported `kid` values;
- reject unrecognized `crit` headers;
- require `alg = EdDSA` in V1;
- require `aud = oid4vci.credential_issuer`;
- require `iat` within configured clock skew;
- when `exp` is present, reject stale or overlong proofs;
- when `exp` is absent, enforce a maximum proof age from `iat` using the same
  configured proof lifetime ceiling;
- require a nonce when nonce enforcement is enabled;
- reject nonce replay;
- derive one canonical holder DID from either accepted key representation;
- produce a holder id suitable for the existing SD-JWT issuance profile;
- produce bounded audit metadata without raw proof JWT material.

The facade may translate the validated OpenID4VCI proof into the internal
holder request used by Witness issuance. Wallets must not be asked to include
Witness-specific proof claims in V1.

## Nonce Lifecycle

Nonce handling is mandatory when `oid4vci.nonce.enabled = true`.

- Witness is the nonce minting authority.
- `POST /oid4vci/nonce` returns `c_nonce` and `c_nonce_expires_in`.
- `POST /oid4vci/credential` may also return `c_nonce` and
  `c_nonce_expires_in` for Draft 13 clients that expect the next nonce in the
  credential response.
- A nonce is bound to the configured credential issuer and credential
  configuration id. It may additionally be bound to a hashed token subject when
  the subject is already available.
- The nonce store persists only keyed hashes, not raw nonce values.
- Nonce consume is atomic: if the nonce is missing, expired, already consumed,
  bound to a different issuer, or bound to a different credential
  configuration, the request is denied without issuing a credential.
- If nonce enforcement is enabled and the nonce store is unavailable, the
  request fails closed.
- If nonce enforcement is disabled for a dev-only profile, proof replay tests
  must be skipped with an explicit reason and the metadata must not advertise a
  nonce endpoint.

## Access Token Policy

The OpenID4VCI facade must not accept any valid citizen token merely because it
was signed by eSignet.

- The access token issuer, signature, algorithm, expiry, not-before, and clock
  skew are validated by the configured OIDC policy.
- The access token audience must match one of
  `oid4vci.accepted_token_audiences`.
- Audience validation uses configured values only. Runtime `Host`,
  `X-Forwarded-Host`, and forwarded scheme headers are not trusted for this
  decision.
- The token must authorize the requested credential configuration through the
  configured self-attestation scope policy or an equivalent configured
  authorization detail.
- A token valid for another client, relying party, or resource server is denied
  even if the subject-binding claim is present.
- Access-token and subject-binding failures may have distinct internal audit
  denial codes, but they must not expose a subject-existence oracle on the wire.

## UserInfo Binding Policy

When the subject-binding claim is sourced from UserInfo:

- UserInfo must be fetched only from the configured issuer's UserInfo endpoint;
- the request must use the same verified access token;
- the response must be signed when configured by the issuer profile;
- `userinfo.sub` must equal the verified access-token `sub`;
- the required binding claim must be present exactly once;
- missing, unreachable, unsigned-when-required, ambiguous, or mismatched
  UserInfo fails closed;
- the implementation must never fall back to a weaker claim source after
  UserInfo failure.

## What Belongs In Registry Platform

The wallet facade creates reusable standards and crypto surface. These pieces
belong in `registry-platform` rather than being implemented only inside
Witness:

### `registry-platform-oid4vci`

New crate or module for OpenID4VCI primitives:

- issuer metadata structs;
- credential offer structs and URL encoding;
- credential request and response structs for the supported V1 subset;
- proof JWT parser and validator;
- proof validation policy type;
- validated holder proof output type;
- nonce claim validation helpers;
- negative test vectors for malformed proof, wrong audience, stale proof,
  unsupported algorithm, missing key, and replayed nonce.

The crate must not know about Witness claim ids, registry subjects, Relay
sources, or self-attestation policy. It validates protocol and cryptographic
facts only.

The proof validator should reuse existing signature parsing, audience, lifetime,
and holder-confirmation helpers from `registry-platform-sdjwt` where practical
instead of reimplementing them.

### `registry-platform-sdjwt`

Extend or reuse existing SD-JWT utilities for:

- `did:jwk` holder key extraction;
- holder confirmation construction;
- issuer media type and compact JWT `typ` constants where reusable;
- wallet-proof test fixture generation.

The existing Witness-specific holder proof validator remains available. The
OpenID4VCI proof validator must be a separate API so callers cannot
accidentally relax `/credentials/issue`.

### `registry-platform-crypto`

Use or add shared helpers for:

- JWK parsing and thumbprint-safe validation;
- base64url encoding/decoding;
- Ed25519 signature verification;
- DID method validation for `did:jwk`;
- a standalone `parse_did_jwk()` helper that returns public key material and
  rejects private, malformed, or unsupported DID documents.

### `registry-platform-oidc`

Use the shared OIDC verifier for eSignet access-token validation when it is
available in the target branch. If Witness keeps its current verifier in V1,
that is explicit V1 debt and must be listed in the implementation note.
Signed UserInfo validation should reuse the platform OIDC UserInfo verifier
when available rather than introducing a third verifier.

### `registry-platform-testing`

Add reusable test fixtures:

- mock OpenID4VCI wallet proof signer;
- mock issuer metadata assertions;
- mock eSignet/OIDC token helper if not already covered;
- golden metadata and credential-offer examples.

## What Belongs In Registry Witness

Witness owns product policy and runtime behavior:

- `oid4vci` config schema and validation against `self_attestation`;
- axum routes;
- mapping from credential configuration id to claim id and credential profile;
- eSignet subject-binding extraction;
- UserInfo fetch integration when configured;
- self-attestation guard reuse;
- internal evaluate and issue orchestration;
- audit event shape and redaction;
- nonce storage for V1 if no shared platform storage abstraction exists;
- error mapping to safe client responses.

Witness must not move registry domain types into platform only to support this
facade.

## What Belongs In Registry Lab

Registry Lab owns optional demo orchestration:

- generated Witness config with `oid4vci.enabled = true`;
- `just oid4vci-offer`;
- `just oid4vci-smoke`;
- optional `just wallet-walt` once a Walt Wallet API target is available;
- optional `just wallet-inji` once Mimoto/Inji local config is stable;
- narrated artifacts under `output/oid4vci-citizen-attestation/`;
- docs that explain what happened without printing secrets.

The default `just quick` path must not require Inji, Walt, eSignet, or the
OpenID4VCI facade.

## Auditability

Every allow and deny decision on the facade must emit bounded audit context.

Required audit fields:

- `protocol = openid4vci`;
- `access_mode = self_attestation`;
- credential configuration id;
- credential profile;
- claim id;
- result status;
- denial code when denied;
- hashed principal;
- hashed subject binding;
- hashed holder id when available;
- correlation id;
- source-read count;
- proof validation result class, without raw proof values.

The audit record must allow an operator to prove:

- metadata was served for a configured credential;
- the credential endpoint used a citizen token;
- subject binding happened before source read;
- successful issuance was tied to self-attestation mode;
- another-subject attempts were denied before source read;
- proof failures did not issue credentials;
- identifiers were redacted or hashed.

## Error Model

V1 uses separate internal audit denial codes and external wire errors. Error
bodies must be generic enough to avoid subject probing.

Required internal denial codes:

- `oid4vci.disabled`;
- `oid4vci.unknown_credential_configuration`;
- `oid4vci.invalid_request`;
- `oid4vci.invalid_token`;
- `oid4vci.subject_binding_denied`;
- `oid4vci.proof_required`;
- `oid4vci.proof_invalid`;
- `oid4vci.proof_replay`;
- `oid4vci.unsupported_format`;
- `oid4vci.policy_denied`;
- `oid4vci.rate_limited`;

Required wire mapping:

| Internal denial code | HTTP status | Client-visible error | Notes |
| --- | --- | --- | --- |
| `oid4vci.disabled` | 404 or 403 | `invalid_request` | Do not reveal hidden routes in hardened deployments |
| `oid4vci.unknown_credential_configuration` | 400 | `unsupported_credential_type` | No source read |
| `oid4vci.invalid_request` | 400 | `invalid_request` | Includes malformed JSON and extension fields that try to supply subject |
| `oid4vci.invalid_token` | 401 | `invalid_token` | Includes expired, wrong issuer, wrong audience, and missing token |
| `oid4vci.subject_binding_denied` | 401 or 403 | `invalid_token` or `access_denied` | Must collapse with generic auth denial on the wire to avoid subject probing |
| `oid4vci.proof_required` | 400 | `invalid_proof` | Include `c_nonce` when appropriate |
| `oid4vci.proof_invalid` | 400 | `invalid_proof` | Include `c_nonce` when appropriate |
| `oid4vci.proof_replay` | 400 | `invalid_proof` | Never reveal whether the nonce was seen before |
| `oid4vci.unsupported_format` | 400 | `unsupported_credential_type` | No source read |
| `oid4vci.policy_denied` | 403 | `access_denied` | Generic denial body |
| `oid4vci.rate_limited` | 429 | `temporarily_unavailable` | Include `Retry-After` when practical |

The exact enum names must be implemented from the selected OpenID4VCI
compatibility profile. Internal `oid4vci.*` codes are for audit and tests, not
the public wire contract.

## Wallet Compatibility Targets

### Inji

Inji Wallet should use the same facade through issuer metadata and the
credential endpoint. Inji/Mimoto configuration may need to add this issuer and
point its authorization server to eSignet.

No Inji Wallet code change should be required for V1. If one is required, that
is a compatibility finding and should be documented before patching.

### Walt

Walt should be tested through credential offer ingestion. The preferred smoke
target is a Walt Wallet API call that consumes the generated
`openid-credential-offer://` URL and receives the credential.

No Walt code change should be required for V1.

Registry Lab keeps the operational wallet test procedure in
`registry-lab/docs/wallet-interop-testing.md`. That guide defines the Walt API
curl shape, the Inji/Mimoto configuration path, required topology, and evidence
to capture for passed or blocked wallet runs.

## Later Version Candidates

The following items are intentionally out of V1. They should be considered only
after the wallet-neutral facade is working end to end with at least one real
wallet or wallet API.

### Production Issuer Trust

- issuer access certificates;
- trusted issuer lists or trust anchors;
- issuer metadata signing if required by the target ecosystem;
- operational key rotation and trust-rollover procedures;
- conformance checks for the selected wallet ecosystem profile.

### Wallet Instance Trust

- wallet instance attestation;
- certified wallet/provider allow-lists;
- hardware-backed key or secure-element attestation;
- wallet instance revocation checks;
- richer holder-binding methods beyond `did:jwk`.

### Credential Lifecycle

- credential status and revocation;
- re-issue and refresh flows;
- update notification flows;
- deletion and withdrawal semantics;
- longer-lived credentials with lifecycle controls.

### Protocol Coverage

- pre-authorized code flow;
- deferred credential issuance;
- batch issuance;
- additional credential formats such as mDoc or JSON-LD;
- additional proof types such as CWT proof;
- high-assurance interoperability profile testing.

### Disclosure Policy

- embedded disclosure policy in issuer metadata;
- relying-party class restrictions;
- verifier trust roots for future presentation flows;
- wallet-side policy hints for when the credential is presented.

## Definition Of Done

The feature is complete only when every item below is true:

- `oid4vci.enabled` is disabled by default.
- With `oid4vci.enabled = false`, the new well-known, offer, and credential
  routes are unavailable or return the configured disabled response.
- With `oid4vci.enabled = true`, `GET /.well-known/openid-credential-issuer`
  returns metadata containing `credential_issuer`, `authorization_servers`,
  `credential_endpoint`, `nonce_endpoint`, and
  `credential_configurations_supported`.
- Metadata contains `person_is_alive_sd_jwt` mapped to `dc+sd-jwt`,
  `person-is-alive`, and the configured credential profile.
- Metadata contains credential-level display data and a snapshot/allow-list test
  proves it contains no source URL, source credential name, internal route, raw
  subject id, or operator-only field.
- `GET /oid4vci/credential-offer` returns a valid offer for
  `person_is_alive_sd_jwt`.
- The offer includes `grants.authorization_code` with bounded `issuer_state`.
- The offer does not contain a subject id, raw civil identifier, source URL, or
  operator-only field.
- Demo authorization requests use PKCE `S256`. If a target IdP or wallet cannot
  exercise PKCE in the automated smoke, the gap is documented with the exact
  command and observed behavior.
- `POST /oid4vci/nonce` returns `c_nonce` and `c_nonce_expires_in` when nonce
  enforcement is enabled.
- Nonces are stored only as keyed hashes or one-way hashes with a deployment
  secret.
- Nonces are bound to credential issuer and credential configuration id.
- Nonces are consumed atomically.
- Nonce-store unavailability fails closed when nonce enforcement is enabled.
- `POST /oid4vci/credential` accepts a standard OpenID4VCI JWT proof.
- `POST /oid4vci/credential` rejects the existing Witness-specific proof when
  it is not a valid OpenID4VCI proof.
- `POST /oid4vci/credential` validates a current eSignet/OIDC bearer token.
- Access tokens with wrong audience are denied.
- Audience validation uses configured `accepted_token_audiences`, not runtime
  `Host` or `X-Forwarded-Host`.
- Tokens valid for another relying party or resource server are denied.
- The credential endpoint derives the subject only from the verified eSignet
  binding claim or verified UserInfo.
- When UserInfo is used, `userinfo.sub == access_token.sub` is required.
- UserInfo failures fail closed and do not fall back to weaker subject-binding
  claim sources.
- The proof JWT is validated before any UserInfo network call.
- The credential request body cannot supply, override, or influence the subject.
- Subject override attempts through JSON body, nested JSON body, arrays, query
  parameters, headers, duplicated parameters, and unknown extension fields are
  denied.
- The facade denies unknown credential configuration ids.
- The facade denies unsupported formats.
- The facade denies missing proof.
- The facade denies wrong proof audience.
- The facade denies stale or overlong proof lifetime.
- The facade denies replayed nonce or proof when nonce enforcement is enabled.
- The facade denies unsupported proof algorithms.
- The facade denies missing `typ`, unexpected `typ`, `alg = none`, unsupported
  `crit`, private JWK `d`, `jku`, `x5u`, `x5c`, and remote key lookup.
- The facade denies missing or unsupported holder key material.
- The issued credential's `cnf.jwk` is the public key derived from the submitted
  proof JWT.
- Reusing a holder DID across credentials is documented as a linkability risk.
- A valid request for the bound citizen succeeds and returns a `dc+sd-jwt`
  credential response.
- A malicious request cannot fetch a claim for `NID-1002` when the token binds
  to `NID-1001`.
- Another-subject attempts are denied before any registry source read.
- All source reads happen only after OIDC validation, credential configuration
  validation, proof validation, and self-attestation subject binding.
- Zero-source-read claims are proven by a mock source read counter or structured
  audit field assertion, not by log text.
- The issued credential remains compatible with the existing Witness SD-JWT VC
  profile.
- The existing `/claims/evaluate` and `/credentials/issue` tests still pass.
- The facade does not relax the existing strict `/credentials/issue` holder
  proof validator.
- A boundary test posts an OpenID4VCI-shaped proof to `/credentials/issue` and
  receives the strict endpoint's holder-proof error.
- Audit events include `protocol = openid4vci`, `access_mode =
  self_attestation`, credential configuration id, credential profile, denial
  code when applicable, and hashed identifiers only.
- Civil subject hashes use the existing keyed audit hasher, not a raw digest.
- Offers and metadata contain no civil subject identifier.
- The issued V1 credential does not expose the raw civil subject id unless the
  credential profile explicitly requires it.
- Any credential profile that exposes a raw civil subject id requires an
  explicit config flag and a documented privacy-impact note.
- Documentation states that V1 validates wallet key possession, not certified
  wallet authenticity or wallet revocation state.
- No raw access token, ID token, UserInfo response, proof JWT, civil id, holder
  private key, source credential, or source row appears in logs, audit events,
  or lab artifacts.
- Redaction tests use a structured allow-list of permitted audit/log fields and
  deny unknown sensitive fields; they do not rely only on substring searches.
- Config validation tests cover `serde(default)` for absent `oid4vci`, missing
  `self_attestation`, unknown claims, unknown credential profiles, bad URLs,
  non-loopback HTTP, missing accepted audiences, missing nonce endpoint, bad
  algorithm lists, and bad binding methods.
- Focused unit tests cover metadata generation, offer generation, valid proof,
  invalid proof, wrong audience, stale proof, replay, unsupported algorithm,
  unknown credential configuration, disabled facade, wire error mapping, every
  internal denial code, and subject override rejection.
- Integration tests cover a successful citizen issuance and an attempted
  other-subject request with zero source reads.
- Registry Lab has an optional narrated smoke command that writes metadata,
  offer, successful credential response, denied response, audit excerpt, and
  transcript artifacts.
- Existing Registry Lab default commands still work without enabling the
  OpenID4VCI facade.
- A Walt-compatible offer smoke has either passed against a live Walt Wallet API
  or is documented as blocked with the exact command, missing dependency, and a
  scripted partial-path test that still passed. The artifact records the Walt
  version or image tag.
- An Inji/Mimoto compatibility smoke has either passed or is documented with
  the exact command, incompatible request/response field, and a scripted
  partial-path test that still passed. The artifact records the Inji Wallet,
  Mimoto, and Certify versions or commits used.
- The implementation has passed code review for each wave before the next wave
  begins.

## Verification Commands

The final implementation must run the closest practical set of checks:

```sh
# registry-platform
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# registry-witness
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# registry-lab
just generate
just build
just up
just smoke
just quick
just citizen-self-attestation
just oid4vci-smoke
OID4VCI_ENABLED=false just smoke
```

If a live wallet check is available:

```sh
just wallet-walt
just wallet-inji
```

Any skipped command must be reported with the exact blocker.

## Implementation Waves And Parallel Work Plan

Each wave ends with review, focused tests, and a short integration note before
the next wave begins. The parent agent remains responsible for coordination,
conflict resolution, final integration, and verification.

### Wave 1: Platform Protocol Primitives

Parallel workers:

- Worker A: implement `registry-platform-oid4vci` metadata, offer, nonce,
  request, response, and wire-error structs with serialization tests.
- Worker C: add or extend SD-JWT, crypto, and testing helpers for `did:jwk`,
  `parse_did_jwk()`, EdDSA verification reuse, and wallet proof signing.
- Worker B starts after Worker A and Worker C have landed their APIs:
  implement OpenID4VCI proof JWT validation, nonce policy checks, and negative
  fixtures.
- Reviewer: check standards alignment, API boundaries, and that Witness domain
  policy did not leak into platform.

Exit criteria:

- platform unit tests pass;
- metadata, offer, nonce, wire-error, and proof negative tests pass;
- public APIs are documented;
- reviewer signs off before Witness integration starts.

### Wave 2: Witness Facade Routes

Parallel workers:

- Worker A: add `oid4vci` config schema and cross-block validation.
- Worker B: add metadata and offer routes.
- Worker C: add credential endpoint orchestration using existing
  self-attestation guards.
- Worker D: own audit schema/type changes and denial-code definitions only;
  Worker C wires them into `api.rs` to avoid overlapping route edits.
- Reviewer: check auth order, subject-binding order, audit redaction, and that
  `/credentials/issue` proof validation was not weakened.

Exit criteria:

- focused Witness route and config tests pass;
- successful issuance integration test passes;
- other-subject denial proves zero source reads;
- wire errors map from internal denial codes without leaking subject-binding
  detail;
- reviewer signs off before lab work starts.

### Wave 3: Registry Lab Demo And Artifacts

Parallel workers:

- Worker A: add generated optional Witness config and `just oid4vci-smoke`.
- Worker B: add narrated smoke script and artifact report.
- Worker C: add Walt offer smoke if local Walt API is available.
- Worker D: add Inji/Mimoto compatibility config notes and smoke if stable.
- Reviewer: run the demo from a clean lab state and check that output teaches
  the flow without leaking secrets.

Exit criteria:

- default lab still works with the facade disabled;
- new smoke writes all required artifacts;
- at least one wallet-neutral client smoke passes;
- live wallet gaps are documented with exact blockers.

### Wave 4: Final Hardening Review

Parallel workers:

- Security reviewer: threat-model the facade against subject probing, token
  confusion, proof replay, source-read ordering, and audit leakage.
- Interop reviewer: compare metadata, offer, and credential responses against
  Inji and Walt expectations.
- Test reviewer: inspect unit and integration coverage against the Definition
  Of Done.

Exit criteria:

- every Definition Of Done item is checked off or marked blocked with evidence;
- all required verification commands pass or have documented blockers;
- no partially implemented behavior remains hidden behind docs or scripts;
- release notes identify the facade as optional and disabled by default.
