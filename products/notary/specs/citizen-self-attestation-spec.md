# Citizen Self-Attestation Spec

> **Status: Archived (2026-05-31).** Kept as a design record. The load-bearing
> config and format details below have been reconciled to the shipped code; for
> current behavior see the code and docs/. Do not treat the broader design
> narrative as current.
>
> **Supersession note (2026-06-22).** The archived V1 non-goal for delegated
> access no longer describes the delegated self-attestation work. Current
> operator guidance lives in `docs/self-attestation-operator-guide.md`; the
> OID4VCI facade still rejects delegated attestation transaction tokens.

Current status: implemented for evaluation, render, credential issuance, batch
denial, rate-limit guard, and OpenID4VCI facade integration in 0.3.0. External
wallet and lab smoke coverage remains separate from the in-repo implementation
status.

## Goal

Add an optional Registry Notary mode that lets an authenticated citizen request
configured attestations about themself and receive a holder-bound credential,
without changing the default machine-client evidence-verification model.

This feature is intentionally stricter than ordinary Notary evaluation:

```text
Default mode:
  authorized client asks Notary about a target

Citizen self-attestation mode:
  authenticated citizen asks Notary about the target bound to their own token
```

The first version should support self-service claim evaluation and SD-JWT VC
issuance for one target at a time. It must not grant raw Registry Relay row
access, arbitrary target lookup, batch lookup, or delegated access.

## Background

Registry Notary already owns claim evaluation, disclosure policy, source
lookup, provenance, audit, and SD-JWT VC issuance. It can authenticate callers
with static credentials, and it has an OIDC auth mode that verifies bearer JWTs
and maps token scopes to Notary scopes.

The missing piece for citizen-facing use is not token verification alone. A
valid citizen token proves the caller authenticated, but it does not prove the
caller may request attestations for an arbitrary evaluation target.
Self-attestation therefore needs an explicit subject-binding policy that
compares the request target identifier with claims in the verified OIDC token
before any Relay consultation occurs.

## V1 User Story

V1 is deliberately small:

1. A citizen authenticates through a trusted OIDC issuer.
2. The issuer returns a JWT access token with a verified stable
   subject-binding claim.
3. The citizen calls `POST /v1/evaluations` for exactly one `target`
   identifier.
4. Notary verifies the token, scopes, allow-lists, and exact subject binding
   before reading any source.
5. Notary returns a configured claim result.
6. If requested, the citizen calls `POST /v1/credentials` for the same
   evaluation and supplies holder DID proof.
7. Notary issues a short-lived, holder-bound SD-JWT VC.

The citizen cannot request arbitrary target identifiers, raw Relay rows, batch
evaluation, delegated access, or claims outside the configured allow-list.

Holder binding does not prove that the holder DID belongs to the civil subject.
V1 proves only that an authenticated citizen token was bound to the requested
subject and that the issued credential is bound to the holder key presented in
the issuance request.

## Threat Model

V1 must be reviewed against at least these threats:

| Threat | Control |
| --- | --- |
| Citizen asks about another person | Exact subject binding before Relay consultations |
| Citizen probes whether another id exists | Subject mismatch denied before Relay consultations, generic denial body, rate limiting |
| Machine token is reused as citizen token | Self-attestation requires configured OIDC scopes or client policy distinct from machine access |
| JWT claim tampering or algorithm confusion | Strict issuer, audience, token type, signature, algorithm, expiry, and key validation |
| OIDC token lacks a trustworthy subject-binding claim | Config validation and deployment review require a verified stable token claim |
| Scope escalation | Self-attestation uses a narrow dedicated scope plus an internal derived consultation policy after all citizen guards pass |
| Holder proof replay | Existing holder proof replay protection and short proof lifetime |
| Holder DID is assumed to equal the citizen | V1 does not make that claim; holder binding and subject binding are separate controls |
| Credential presented after source state changes | Short credential validity and optional status checks when enabled |
| Audit or artifact leaks citizen identifiers | Redaction, bounded audit context, and non-disclosure tests |
| Excessive request volume or enumeration attempts | Per-principal and per-client rate limits for self-attestation paths |

Threat modeling can stay lightweight, but the final design review should cover
STRIDE for API and trust-boundary risks, plus LINDDUN-style privacy risks around
linkability, detectability, and disclosure.

## Requirements

- Self-attestation must be disabled by default.
- When disabled, existing Notary API behavior, config, and tests must remain
  unchanged.
- Self-attestation must require OIDC authentication. Static credentials are not
  sufficient for citizen self-service.
- A self-attestation request must be allowed only when the server-derived
  subject from a configured verified-token claim is used as the requester and
  target context.
- Subject binding must run before Relay consultations, claim evaluation, rendering, or
  credential issuance.
- Self-attestation must allow only configured claims, formats, disclosures, and
  operations.
- Self-attestation v1 must reject `/v1/batch-evaluations`.
- Credential issuance must remain holder-bound when the selected credential
  profile requires holder binding. For citizen-facing SD-JWT VC issuance, the
  recommended v1 profile requires `holder_binding.mode = did:jwk` and
  `proof_of_possession = required`, matching the current holder-proof
  validator. Broader DID method support requires a separate validator and proof
  support review.
- The feature must not expose Relay source credentials, raw Relay rows, or
  Notary-to-Relay workload credentials to the citizen.
- Audit events must identify the caller by the existing redacted principal hash
  path and must add enough bounded context to distinguish self-attestation from
  machine-client evaluation.
- Every self-attestation allow or deny decision must be auditable without
  recording raw citizen identifiers, raw tokens, holder private material, or
  Relay outputs.
- Self-attestation paths must have rate limits that bound subject probing,
  repeated denial attempts, and credential issuance attempts.
- Self-attestation credentials remain short-lived by default. Optional
  `RegistryNotaryCredentialStatus` may be enabled separately and must not be
  treated as a complete revocation or refresh lifecycle.

## Non-Goals

- Delegated access such as parent, guardian, legal representative, or consented
  third-party access.
- Account recovery, identity proofing, or identity linking outside the verified
  OIDC token claims.
- User-interface flows, wallet UX, or browser redirect handling.
- Changing Registry Relay authorization or giving citizens direct Relay row
  access.
- Proving that the wallet holder DID belongs to the civil subject.
- Trusting unverified request body fields as evidence of identity.
- Cross-subject, batch, or backfill workflows.

## Proposed Config

Add an optional top-level `self_attestation` block. Keeping it top-level avoids
mixing citizen access policy with ordinary evidence claim definitions:

```yaml
self_attestation:
  enabled: true
  requires_auth_mode: oidc
  subject_binding:
    token_claim: "https://id.example.gov/claims/national_id"
    request_field: SubjectId
    id_type: national_id
    normalize: exact
    allow_sub_as_civil_id: false
  citizen_clients:
    allowed_client_ids:
      - citizen-portal
    allowed_audiences:
      - registry-notary-citizen
  token_policy:
    required_acr_values:
      - urn:example:loa:substantial
    max_auth_age_seconds: 900
    max_access_token_lifetime_seconds: 900
    max_evaluation_age_seconds: 600
    max_credential_validity_seconds: 600
    max_clock_leeway_seconds: 60
  allowed_operations:
    evaluate: true
    render: true
    issue_credential: true
    batch_evaluate: false
  allowed_purposes:
    - citizen_self_attestation
  allowed_claims:
    - date-of-birth
    - civil-status
    - person-is-alive
  allowed_formats:
    - application/vnd.registry-notary.claim-result+json
    - application/dc+sd-jwt
  allowed_disclosures:
    - predicate
    - value
  scope_policy: required
  required_scopes:
    - self_attestation
  allowed_wallet_origins:
    - https://wallet.example.gov
  credential_profiles:
    - civil_status_sd_jwt
  rate_limits:
    mode: in_process
    invalid_token_per_client_address_per_minute: 20
    per_principal_per_minute: 10
    subject_mismatch_per_principal_per_hour: 5
    per_holder_per_hour: 10
    credential_issuance_per_principal_per_hour: 5
```

The OIDC auth block remains responsible for issuer validation, JWKS, accepted
audiences, token type, principal claim, and scope mapping:

```yaml
auth:
  oidc:
    issuer: https://id.example.gov
    jwks_url: https://id.example.gov/oauth/v2/keys
    audiences:
      - registry-notary
    scope_claim: scope
    scope_map:
      self_attestation:
        - self_attestation
```

The exact `scope_map` input form should follow the current Notary OIDC config
model. The important invariant is that a citizen token yields only the narrow
self-attestation permission. It must not directly receive machine-client source
scopes such as `civil_registry:evidence_verification`.

For shared IdPs, V1 defaults to requiring both a configured citizen client or
audience and a configured self-attestation scope. `scope_policy` may be set to
`optional` or `disabled` only when the issuer/client/audience, assurance, and
subject-binding checks are the deployment's primary citizen authorization
boundary. A self-attestation scope without an allowed citizen client or audience
is denied. An allowed citizen client or audience without the self-attestation
scope is denied when `scope_policy = required`, accepted only when the token
omits scope and `scope_policy = optional`, and ignored when
`scope_policy = disabled`. None of these cases may fall back to machine-client
authorization once classified as self-attestation.

After access-mode classification, subject binding, operation allow-list, claim
allow-list, disclosure allow-list, and format allow-list pass, Notary may
derive an internal evaluation capability for the selected claim only. That
derived capability is scoped to `access_mode = self_attestation` and must not
authorize raw Relay access, batch evaluation, or machine-client evaluation.

The derived capability must be represented as a typed runtime authorization
value, not as ad hoc scopes:

```rust
enum EvaluationCapability {
    Machine { scopes: BTreeSet<String> },
    SelfAttestation {
        claim_id: String,
        subject_binding_hash: Hashed<SubjectBinding>,
    },
}
```

Runtime Relay consultations for citizen requests must require
`EvaluationCapability::SelfAttestation` and must reject arbitrary claim ids or
machine-only consultation operations by type.

## Token Requirements

Self-attestation is safe only when the OIDC issuer supplies a subject-binding
claim that the deployment trusts as a stable identifier for the source registry.
Good examples are `national_id`, `civil_person_id`, or a namespaced claim such
as `https://id.example.gov/claims/national_id`.

Weak login identifiers such as email address, phone number, display name, or an
opaque pairwise `sub` are not enough unless the deployment explicitly treats
that claim as the registry subject identifier or adds a separate trusted
identity-linking step. Identity-linking is out of scope for v1.

OIDC validation must require:

- exact issuer match;
- accepted audience;
- accepted token type;
- signature validation against the configured JWKS;
- an allow-list of signing algorithms;
- expiration and not-before checks with bounded leeway no greater than
  `self_attestation.token_policy.max_clock_leeway_seconds`;
- `exp` and `iat` claims for self-attestation tokens;
- rejection when `exp - iat` exceeds
  `self_attestation.token_policy.max_access_token_lifetime_seconds`;
- rejection when `iat` is unreasonably far in the future;
- allowed-client or allowed-audience checks for every self-attestation
  deployment;
- scope extraction through the configured `scope_claim` and `scope_map`.

The verifier must ignore JWT header key-discovery parameters such as `jku`,
`x5u`, `x5c`, and embedded `jwk`. Signing keys must come only from the
configured `jwks_uri` after issuer configuration validation. The verifier must
reject unknown `kid` values, ambiguous key matches, incompatible `kty` or `crv`
for the selected algorithm, `alg = none`, and any algorithm not in
`allowed_algorithms`. Production `jwks_uri` values must use HTTPS and must not
allow localhost, private address ranges, redirects to unapproved hosts, or
non-HTTP(S) schemes.

For the external adopter story, confirm whether the issuer emits an algorithm
Notary accepts. Current Notary OIDC defaults are expected to be EdDSA-only.
The V1 adopter story should use an EdDSA dev issuer. Zitadel RS256 support should
be a separate implementation ticket that adds RSA key-size validation before
broadening `allowed_algorithms`. RSA keys smaller than 2048 bits must be
rejected.

## OIDC Assurance Requirements

The subject-binding claim must be identity-proofed for the registry purpose.
Deployments must document why the configured token claim is authoritative for
the selected source registry and claim set.

When the issuer supports assurance metadata, self-attestation should require:

- allowed citizen `client_id` or `azp` values;
- an accepted citizen audience when the issuer is shared with machine clients;
- `acr` values that meet the deployment's identity-proofing requirement;
- bounded authentication freshness through `max_auth_age_seconds` and
  `auth_time`.

Configured assurance policy fails closed. If
`self_attestation.token_policy.required_acr_values` is non-empty, a missing or
unaccepted `acr` claim denies the request. If
`self_attestation.token_policy.max_auth_age_seconds` is configured, a missing
`auth_time` claim denies the request. If the issuer cannot provide the required
assurance metadata, the deployment must either leave the corresponding policy
unset and record that accepted risk in the design review, or use a different
issuer.

## Verified Claims Context

Subject binding is not implementable if verified token claims disappear after
authentication. V1 therefore extends `EvidencePrincipal` with a typed optional
`BoundedVerifiedClaims` context produced by the OIDC verifier.
Static-credential principals have no verified-claims context and cannot enter
self-attestation mode.

`BoundedVerifiedClaims` is not a raw JWT JSON map. It contains only allow-listed
claims needed by self-attestation policy:

- issuer;
- audience;
- client id or `azp`, when present;
- token type;
- bounded scopes;
- `sub` as a bounded login subject, not as a civil identifier by default;
- configured subject-binding claim name as `ConfigMetadata`;
- configured subject-binding claim value as a bounded string before hashing;
- `acr`, when present;
- `auth_time`, when present;
- `exp`, `iat`, and `nbf`, when present.

The raw access token, raw JWT header, full claims object, and unrecognized
claims must not be stored on `EvidencePrincipal`, written to audit, or passed to
Relay clients. The subject-binding value is used only long enough to run
the exact comparison and compute the stored keyed hash.

Relay must not receive citizen OIDC tokens or `BoundedVerifiedClaims`. V1 Relay
consultations use only the Notary-to-Relay workload credential plus
`EvaluationCapability::SelfAttestation`.

## Subject Binding

V1 supports exact equality between one verified token claim and the server
derived target identifier:

```text
principal.verified_claims[token_claim] == derived.target.identifiers[configured_scheme].value
derived.target.identifiers[configured_scheme].scheme == subject_binding.id_type
```

The token claim should be:

- a namespaced string-valued custom claim such as
  `https://id.example.gov/claims/national_id`;
- a string-valued claim supplied by a verified identity provider action or
  identity-linking service.

`sub` is a login subject, not a civil identifier. Production deployments must
not use `token_claim: sub` unless `subject_binding.allow_sub_as_civil_id = true`
is explicitly configured and the deployment documents that `sub` is
authoritative for the selected registry subject. Config validation must reject
`token_claim: sub` when this flag is absent or false. The external adopter demo,
currently maintained in Solmara Lab, should use a namespaced custom claim.

The configured token-claim name must be a bounded string matching
`[A-Za-z0-9_:/\.\-]+`. This intentionally permits URL-shaped namespaced claims
while rejecting control characters and other log or config injection hazards.

The request must fail closed when:

- the token claim is missing;
- the token claim is not a string;
- the configured target identifier value is empty;
- the configured target identifier scheme does not match
  `subject_binding.id_type`;
- normalization is unsupported;
- the normalized values do not match.

V1 should support only `normalize: exact`. Later versions may add explicit
normalizers such as case folding or punctuation removal, but those should be
named, tested, and jurisdiction-specific.

V1 derives the self-attestation requester and target from the configured
subject-binding token claim. The config surface for `subject_binding.request_field`
is retained as a compatibility label for the derived target identifier, not as a
caller-controlled request field.
Self-attestation requests must be rejected if they include conflicting
caller-supplied identity context, including query parameters, headers, arrays of
items, per-claim target overrides, `on_behalf_of`, or body fields that could
override the configured token-bound subject.

## Runtime Behavior

### Access Mode Selection

When `self_attestation.enabled = true`, Notary must classify every OIDC caller
into exactly one access mode before authorization: `machine_client` or
`self_attestation`.

A request is `self_attestation` when the token comes from a configured citizen
client, citizen audience, citizen issuer policy, or has any configured
self-attestation scope. To be authorized, a self-attestation request must have
an allowed citizen client or audience. Scope handling is controlled by
`self_attestation.scope_policy`: `required` requires every configured
`required_scopes` entry; `optional` requires those scopes only when the verified
token carries any scope signal; `disabled` ignores OAuth scopes for the
self-attestation decision. A self-attestation-classified request must never fall
back to machine-client authorization. If any self-attestation guard fails, the
request is denied before Relay consultations.

A request is `machine_client` only when it satisfies existing machine-client
authentication and does not match configured citizen client, audience, issuer,
or scope policy. If classification is ambiguous, the request fails closed before
Relay consultations.

### Evaluation

For `POST /v1/evaluations`:

1. Authenticate the bearer token through the configured OIDC verifier.
2. Classify the request as `machine_client` or `self_attestation`.
3. Build the `EvidencePrincipal` and optional `BoundedVerifiedClaims` from the
   verified token.
4. If the request is classified as `self_attestation`, evaluate the
   self-attestation guard.
5. Reject the request before any Relay consultation if subject binding, claim
   allow-list, disclosure allow-list, or format allow-list fails.
6. Continue through the existing claim evaluation pipeline.

The guard placement is part of the contract. In
`crates/registry-notary-server/src/api/evaluations.rs::evaluate`, the self-attestation
guard must run after request parsing, authentication, principal construction,
and claim selection, but before calling the runtime evaluation path or any code
that can invoke a Relay client. Denials from this guard still
write bounded audit events and rate-limit state.

The response body should stay compatible with the existing evaluate response.
The audit path should record that this was a self-attestation decision using a
bounded event attribute, not by logging raw subject identifiers.

### Rendering

For rendering an existing evaluation:

1. Require the stored evaluation to match the current authorization tuple:
   principal hash, access mode, issuer, and client or audience when present.
2. If the stored evaluation was created through self-attestation, require the
   current request to classify as `self_attestation`.
3. Require a currently valid citizen token. Notary must not reuse or store the
   original evaluation token.
4. Re-check that the current verified token still satisfies subject binding and
   hashes to the stored subject-binding hash.
5. Re-apply the self-attestation operation, claim, disclosure, and format
   allow-lists.
6. Do not re-read sources solely to render an already stored result.

### Credential Issuance

For `POST /v1/credentials`:

1. Require the stored evaluation to match the current authorization tuple:
   principal hash, access mode, issuer, and client or audience when present.
2. If the stored evaluation was created through self-attestation, require the
   current request to classify as `self_attestation`.
3. Require a currently valid citizen token. Notary must not reuse or store the
   original evaluation token.
4. Re-check that the current verified token still satisfies subject binding and
   hashes to the stored subject-binding hash.
5. Require the evaluation age to be less than
   `self_attestation.token_policy.max_evaluation_age_seconds`.
6. Require the selected credential profile to be in the self-attestation
   allow-list when the evaluation was created in self-attestation mode.
7. Preserve existing profile checks for allowed claims and disclosure.
8. Preserve existing holder proof checks. Citizen-facing profiles should require
   proof of possession.
9. Issue the same SD-JWT VC response shape used by the current endpoint.

### Batch Evaluation

`POST /v1/batch-evaluations` must return a stable authorization error for
self-attestation principals in v1. Batch can be revisited only after an explicit
delegation and subject-list policy exists.

### Discovery

The public evidence service discovery document should expose only a coarse
self-attestation capability summary when enabled:

```json
{
  "self_attestation": {
    "enabled": true
  }
}
```

Authenticated discovery for a principal with self-attestation scope may expose
bounded operational details:

```json
{
  "self_attestation": {
    "enabled": true,
    "allowed_claim_ids": ["person-is-alive"],
    "allowed_formats": ["application/vnd.registry-notary.claim-result+json", "application/dc+sd-jwt"],
    "credential_profile_ids": ["civil_status_sd_jwt"]
  }
}
```

Discovery must not expose raw token-claim names, internal source names, source
scopes, upstream URLs, or other IdP internals unless explicitly approved for
that deployment.

Deployments must decide whether self-attestation discovery is public or
authenticated. V1 defaults detailed self-attestation discovery to authenticated
principals only. Public discovery should expose only coarse capability flags.
Detailed claim names and credential profiles should require an authenticated
principal with self-attestation scope unless the deployment explicitly approves
public disclosure. Public discovery must not expose `subject_id_type` in v1.

### Browser And Wallet Origin Policy

The first lab story may use CLI or script-driven calls and avoid browser CORS
entirely. If Notary is called directly from a browser wallet or portal, CORS
must be disabled by default and enabled only with an exact
`allowed_wallet_origins` allow-list. Wildcard origins must not be used with
credentials. Preflight failures should be generic and must not disclose
self-attestation policy details.

### Credential Freshness

V1 credentials are short-lived attestations over the source state observed at
evaluation time. Credential profiles used for self-attestation should set a
short `validity_seconds` appropriate for the claim. V1 does not require
credential status, source change notifications, or automatic refresh. Optional
`RegistryNotaryCredentialStatus` can be enabled separately, but it is not a
complete long-lived citizen credential lifecycle by itself.

V1 citizen-facing credential validity must not exceed
`self_attestation.token_policy.max_credential_validity_seconds`, with a
recommended ceiling of 600 seconds for the external adopter story.

### Purpose Policy

Self-attestation purpose comes from the selected claim profile, not from a
citizen-supplied request field. Each self-attestation-enabled claim profile must
declare a fixed bounded purpose id that is included in
`self_attestation.allowed_purposes` and validated at config-load. Missing or
unallowed purpose values fail at config validation, or before Relay consultations if a
runtime profile lookup fails. Audit records store only the bounded purpose id,
not free-form citizen text.

### Stored Evaluation Privacy Boundary

Evaluations created through self-attestation must persist immutable bounded
metadata:

- `access_mode = self_attestation`;
- issuer;
- audience or client id when available;
- principal hash;
- subject id type;
- subject-binding claim name;
- subject-binding value hash using the audit hasher or an equivalent keyed
  hasher;
- requested claim set content hash;
- disclosure mode;
- result format;
- `delegation_chain = []` for v1;
- self-attestation policy version or policy hash;
- creation time and evaluation expiration.

The self-attestation `policy_hash` is a canonical JSON hash over only the
policy that can change authorization or disclosure for the stored evaluation:
`subject_binding`, the selected claim profile entry, allowed disclosures,
allowed formats, allowed credential profiles relevant to the selected profile,
the profile purpose id, and the credential validity ceiling. Rate-limit,
discovery, CORS, and unrelated claim/profile config are excluded so operational
tuning does not invalidate otherwise valid in-flight evaluations.

The requested claim set hash is a deterministic content hash over configured
claim identifiers. It is not an identity pseudonym and is intentionally
independent of audit-key rotation so render and credential issuance can verify
that the requested claims did not change.

Rotating the audit hasher key invalidates in-flight self-attestation
evaluations because principal and subject-binding hashes can no longer be
recomputed. This is acceptable in v1 because
`max_evaluation_age_seconds <= 600`. No key-id or multi-key verification
mechanism is in scope for v1.

Render and credential issuance for a self-attestation evaluation must verify:

- the stored `access_mode` is `self_attestation`;
- the current principal hash matches the stored principal hash;
- the current issuer, audience, and client id are compatible with the stored
  authorization tuple;
- the current target identifier scheme matches the stored identifier scheme;
- the current verified token contains the configured subject-binding claim;
- the normalized token subject-binding value hashes to the stored
  subject-binding value hash;
- the requested render format or credential profile remains allowed by current
  policy;
- policy tightening fails closed.

A machine-client evaluation must not be rendered or used for citizen credential
issuance unless a separate migration or delegation design explicitly permits it.
Raw subject identifiers must not be stored unless already permitted by the
existing redaction policy.

### Data Minimization For Responses And Credentials

Each self-attestation claim profile must declare the exact fields allowed in
evaluation responses and credential payloads. Predicate disclosure should be
preferred over raw value disclosure when it satisfies the use case.

Citizen-facing SD-JWT VC profiles must not include raw registry identifiers,
source row keys, internal provenance fields, full names, dates of birth,
addresses, or other civil attributes unless the claim profile explicitly
requires them and the field is documented as necessary.

For v1 citizen self-attestation, the credential subject identifier should be
the holder DID proven during issuance. Credential subject identifiers must never
contain raw `subject.id`, raw registry identifiers, or the bound subject hash
directly. If a profile later needs a pairwise subject identifier distinct from
the holder DID, it must derive that identifier per `(issuer, holder DID,
claim_profile)` and keep it unlinkable to the civil subject id outside Notary.
Citizen credential profiles should use random credential identifiers, short
validity, and no civil identifier in credential subject identifiers unless
explicitly required by the claim. Audit should record `credential_id_hash`
rather than raw `credential_id` for citizen credentials.

## Policy Model

The implementation should not infer self-attestation solely from `auth.mode =
oidc`. OIDC may also be useful for agency or machine clients. The access-mode
classifier determines whether a request is `self_attestation`; once it does, the
request may continue only when all of the following are true:

- `self_attestation.enabled = true`;
- auth mode is OIDC;
- the verified principal comes from an allowed citizen client or audience;
- scope policy is satisfied: `required` means all configured
  `self_attestation.required_scopes` are present, `optional` means they are
  required only when the verified token carries a scope signal, and `disabled`
  means scopes are not part of the self-attestation decision;
- the request operation is listed as allowed;
- the requested claims, disclosure, format, and credential profile are allowed;
- the subject binding check passes.

V1 does not support scope-only citizen classification for a shared IdP. Citizen
and machine OIDC clients must be separated by client id, audience, or issuer
policy. The dedicated self-attestation scope remains the default policy, but it
can be explicitly relaxed for IdPs such as eSignet that do not emit a useful
OAuth `scope` claim in the access token.

## Errors

Self-attestation failures should use Problem Details through the existing
Evidence error response path. Add stable internal error codes for at least:

| Condition | Suggested code |
| --- | --- |
| Feature disabled for caller | `self_attestation.disabled` |
| Operation not allowed | `self_attestation.operation_denied` |
| Claim not allowed | `self_attestation.claim_denied` |
| Disclosure not allowed | `self_attestation.disclosure_denied` |
| Format not allowed | `self_attestation.format_denied` |
| Credential profile not allowed | `self_attestation.profile_denied` |
| Token claim missing | `self_attestation.subject_claim_missing` |
| Subject mismatch | `self_attestation.subject_mismatch` |
| Rate limited | `self_attestation.rate_limited` |
| Invalid token | `self_attestation.invalid_token` |
| Assurance denied | `self_attestation.assurance_denied` |
| Batch denied | `self_attestation.batch_denied` |

These detailed codes are internal audit codes unless explicitly marked public.
For callers, pre-consultation self-attestation denials should use one generic Problem
Details shape, for example HTTP `403` with public code
`self_attestation.denied`, without raw identifiers, token claim names,
configured claim names, profile names, or normalization details. Public
responses may expose only coarse remediation-safe reasons, such as
authentication required, malformed request, rate limited, or self-attestation
denied.

Malformed requests should remain `400`, rate-limit denials should use a generic
`429` body, and missing or invalid credentials should remain an authentication
failure.

JWT validation failures caused by unsupported algorithms, rejected keys,
unknown `kid`, excessive token lifetime, or issuer and audience mismatch should
use an authentication failure externally, but the internal audit or diagnostic
code must distinguish them from truly missing credentials.

## Rate Limiting And Anti-Enumeration

Self-attestation must include rate limiting even though subject binding blocks
Relay consultations. The goal is to reduce probing, noisy mismatch attempts, and
credential spam.

Rate-limit checks must run before Relay consultations and credential issuance. V1 uses
in-Notary in-process buckets for the single-process lab and for basic local
protection. Keys are derived from the existing `AuditKeyHasher` or an
equivalent service-held keyed hasher.

The in-process limiter is not a cross-replica abuse control. Hour-window,
distributed, or production-grade limits require a gateway or shared rate-limit
service with contract tests proving the limits and generic denial bodies are
enforced. If the configured rate limiter is unavailable, self-attestation
requests must fail closed unless the deployment explicitly configures a local
emergency fallback.

The enforcement order is fixed: unauthenticated client-address limits run
before OIDC verification or JWKS fetch; authenticated per-principal limits run
immediately after token verification; subject-mismatch and credential-issuance
buckets run before Relay consultations or issuance.

V1 must provide at least:

- a per-principal limit for all self-attestation requests;
- a per-OIDC-client limit when client id is available;
- a stricter per-principal limit for `subject_mismatch` denials;
- a per-client-address fallback limit for unauthenticated or invalid-token
  requests;
- a per-holder-id-hash limit for credential issuance;
- a credential issuance limit per principal;
- stable error responses that do not reveal whether the requested subject id
  exists in any upstream registry.

V1 intentionally omits a separate per-bound-subject hour bucket because exact
subject binding makes it redundant with the per-principal bucket for legitimate
self-only flows. Delegated access may add a per-bound-subject bucket in a later
design.

When more than one bucket applies, all applicable buckets are checked as one
atomic decision. If every bucket has remaining capacity, all applicable buckets
are consumed. If any bucket is over limit, the request is denied and no bucket
is consumed for that denied attempt except the specific denial bucket used to
track repeated failures, such as `subject_mismatch`.

Rate-limit decisions must be auditable with bounded metadata. Rate-limit keys
for authenticated requests must be derived from existing principal hashes or
HMACs using a service-held secret. Subject mismatch buckets must not include raw
requested subject ids. If subject-specific bucketing is used, it must use a
keyed hash of the requested subject id and id type with bounded retention.
Credential issuance must be limited by principal and holder id hash.

Rate-limit state must have explicit TTLs, must not be exported to lab artifacts,
and must avoid high-cardinality metrics labels containing principal, subject,
token, or holder data.

## Auditability

Self-attestation must be auditable as a policy decision, not just as a generic
HTTP request. The audit record should let an operator answer:

- who called, using the existing keyed `principal_id_hash`;
- which operation was attempted;
- whether the request was treated as self-attestation or machine-client access;
- whether subject binding passed or failed;
- which configured policy denied the request, if any;
- which claim set was requested, using the existing bounded claim hash;
- whether a credential was issued;
- which credential profile was used, when issuance succeeds or fails after
  profile selection;
- which holder binding mode was requested, without logging holder private
  material or holder proofs;
- which request/correlation id links the Notary audit event to upstream Relay
  audit events.

Audit events must remain tamper-evident through the existing chained audit
envelope. If the audit sink cannot write, the request must fail closed through
the existing `audit.write_failed` path.

Audit redaction must be enforced by type, not only by convention. New
self-attestation audit fields should use typed wrappers such as:

- `Hashed<T>` for principal, subject, holder, and credential identifiers;
- `Bounded<N>` for correlation ids, purpose ids, claim names, and other bounded
  strings;
- `ConfigMetadata` for policy field names such as the token-claim name;
- explicit enums for `AccessMode`, `DenialCode`, and holder binding mode.

`EvidenceAuditEvent` must grow first-class fields for the spec-required audit
context before the evaluation guard is implemented:

- `access_mode`;
- `denial_code`;
- `correlation_id`;
- `credential_profile`;
- `holder_binding_mode`;
- `rate_limit_bucket`;
- `policy_version` or `policy_hash`.

The schema must not expose a generic `String` slot for token claim values,
subject ids, holder material, access tokens, source rows, or SD-JWT
disclosures.

### Event Coverage

At minimum, the implementation must emit auditable records for:

| Event | Required audit context |
| --- | --- |
| Successful self-attestation evaluation | `access_mode = self_attestation`, operation, decision, principal hash, claim hash, evaluation id, row/source count, correlation id |
| Subject-binding denial | `access_mode = self_attestation`, operation, decision, principal hash, denial code, token-claim name, request field, correlation id |
| Claim, format, disclosure, operation, or profile denial | `access_mode = self_attestation`, operation, decision, principal hash, denial code, claim hash when available, correlation id |
| Batch denial | `access_mode = self_attestation`, operation, decision, principal hash, denial code, requested subject count when available, correlation id |
| Rate-limit denial | `access_mode = self_attestation`, operation, decision, principal hash when available, denial code, rate-limit bucket, correlation id |
| Successful credential issuance | `access_mode = self_attestation`, operation, decision, principal hash, evaluation id, credential profile, holder binding mode, credential id or credential id hash, correlation id |
| Credential issuance denial | `access_mode = self_attestation`, operation, decision, principal hash, evaluation id when available, denial code, credential profile when available, holder binding mode when available, correlation id |

The token-claim name is safe to record because it is configuration metadata. The
token-claim value is not safe to record unless separately hashed with the audit
hasher. Caller-supplied or derived subject ids, OIDC `sub`, civil id, access
token, holder proof, SD-JWT disclosures, Relay outputs, Relay source
credentials, and raw Relay response bodies must not appear in audit records, logs, metrics, Problem
Details, or generated lab artifacts.

For pre-authentication or invalid-token rate-limit denials, `access_mode` may be
`unknown` because the request has not been classified. Once OIDC verification
has succeeded, rate-limit denial audit events must propagate the classified
`access_mode`.

### Correlation

Notary should preserve a privacy-safe incoming `x-request-id` or equivalent
correlation header in audit context and pass the same bounded correlation value
to upstream source requests. This lets operators trace:

```text
citizen request -> Notary self-attestation decision -> Relay consultation
```

without exposing citizen identifiers. If no request id is supplied, Notary may
generate one, but it must not derive it from the subject id or token contents.

Incoming correlation ids must be validated before audit or upstream
propagation. If the supplied value is missing, too long, contains unsafe
characters, resembles a token, or contains likely PII patterns, Notary must
replace it with a generated opaque id and may record only that replacement
occurred. Generated ids must be random or UUID-like and must not derive from
token claims, subject ids, holder material, source data, or request bodies.

### Audit Verification

Implementation tests must verify both positive audit coverage and
non-disclosure:

- successful self-attestation evaluation writes a chained audit record with
  `access_mode = self_attestation`;
- subject mismatch denial writes a chained audit record before returning;
- the audit record contains the configured token-claim name but not the token
  claim value;
- credential issuance writes profile and holder binding metadata without
  logging the holder proof or SD-JWT disclosures;
- audit sink failure replaces the otherwise authorized response with
  `audit.write_failed`;
- fixture tokens, civil identifiers, Relay source credentials, holder proofs,
  and raw Relay output values are absent from audit JSONL, service logs, metrics, Problem
  Details, and lab artifacts.

## Security Invariants

- A citizen token must never authorize evaluation for a different subject unless
  a future delegated-access policy explicitly says so.
- The subject-binding token claim must come from the verified JWT, not from a
  client-supplied header or request body field.
- The subject-binding check must run before any Relay consultation.
- `sub` should not be treated as a civil identifier unless the deployment
  explicitly configures `token_claim: sub` and
  `subject_binding.allow_sub_as_civil_id = true`.
- Scope authorization is necessary but not sufficient; the subject-binding
  check is mandatory for self-attestation.
- Citizen tokens must not directly carry machine-client Relay consultation scopes. Relay
  consultations for citizen requests must be authorized through an internal derived
  `EvaluationCapability::SelfAttestation` after all citizen guards pass.
- Holder proof binds a credential to a holder key. It does not replace the
  subject-binding check.
- Holder proof does not prove the holder DID belongs to the citizen or civil
  subject in v1.
- Relay must not receive citizen access tokens or verified token
  claim context.
- Audit, logs, metrics, and Problem Details must not contain raw citizen
  identifiers unless the existing audit redaction policy explicitly allows it.
- Self-attestation mode must not loosen claim profile allow-lists, disclosure
  allow-lists, internal derived consultation checks, or
  evaluation-to-principal binding.

## Compatibility

Existing deployments that do not configure `self_attestation` should observe no
behavior change.

Existing machine-client OIDC deployments should continue to work. They should
not be forced into self-attestation unless their token scopes or client policy
match the self-attestation classifier. If a deployment shares one issuer across
machine and citizen clients, client or audience separation is required.

Existing static-credential deployments should be rejected at config validation
time if they enable `self_attestation`.

## Review Checklist

Before implementation begins, review the spec with these lenses:

- Threat modeling: STRIDE for API trust boundaries and LINDDUN for privacy
  risks.
- OAuth/OIDC: issuer, audience, token type, JWKS, algorithm allow-list, client
  allow-list, expiry, and scope mapping.
- JWT: algorithm confusion, `kid` or remote-key injection, accepted algorithms,
  and claim tampering.
- BOLA/IDOR: every request body or stored evaluation reference must be bound to
  the authenticated principal and self-attestation subject.
- Scope minimization: citizen scopes must be narrower than machine-client
  evidence scopes and should not imply raw row access.
- Sensitive data exposure: responses, errors, audit, logs, metrics, and lab
  artifacts must not disclose raw identifiers, tokens, holder proofs, SD-JWT
  disclosures, source rows, or upstream response bodies.

## Implementation Plan

### Stage 0: Design Freeze

- Add this spec and review it against the current OIDC, evaluation, render, and
  credential issuance paths.
- Confirm `self_attestation` is a top-level config block.
- Confirm the lab uses an EdDSA dev issuer and tracks Zitadel RS256 support as
  a separate algorithm-hardening ticket.
- Confirm the demo uses a namespaced custom subject-binding claim.
- Complete the review checklist above and record accepted risks.

Definition of Done:

- Spec reviewed with security and product questions resolved or tracked.
- Config shape selected.
- Error code names finalized.
- Stored self-attestation metadata shape finalized for `StoredEvaluation`.
- `EvidencePrincipal` extension with `BoundedVerifiedClaims` selected as the
  verified-claims transport.
- `EvaluationCapability` selected as the runtime representation for machine versus
  self-attestation Relay consultations.
- Canonical `policy_hash` input fields finalized.
- Audit event coverage, redaction requirements, and correlation behavior
  reviewed against the existing chained audit pipeline.
- Threat model, token requirements, rate limits, discovery output, and
  credential freshness rules accepted for v1.

### Stage 1: Config And Policy Types

- Add self-attestation config structs, validation, and defaults.
- Add `AccessMode`, `EvaluationCapability`, `BoundedVerifiedClaims`, and typed
  audit wrappers such as `Hashed<T>`, `Bounded<N>`, and `ConfigMetadata`.
- Extend `EvidenceAuditEvent` with the fields required by this spec before
  implementing the evaluation guard.
- Validate that `enabled = true` requires `auth.mode = oidc`.
- Validate non-empty `subject_binding.token_claim` and `allowed_claims`.
- Validate `scope_policy`; when it is `required` or `optional`,
  `required_scopes` must be non-empty, and when it is `disabled`,
  `required_scopes` must be empty.
- Validate supported `request_field` enum values. V1 should accept only
  `SubjectId`.
- Validate supported normalizers. V1 should accept only `exact`.
- Validate `allow_sub_as_civil_id = true` when `token_claim = sub`; otherwise
  reject `sub` as a subject-binding claim.
- Validate token claim name charset with `[A-Za-z0-9_:/\.\-]+`.
- Validate rate-limit config when present and apply secure defaults when absent.
- Validate token policy, citizen client/audience policy, and allowed purpose
  config when self-attestation is enabled.
- Validate cross-block OIDC policy: when scope policy is not `disabled`,
  `required_scopes` must map only to self-attestation scope, citizen client or
  audience policy must be present, citizen tokens must not map to machine-client
  Relay consultation scopes, clock leeway must be bounded, and configured credential
  profiles must respect the 600-second citizen validity ceiling.
- Validate each self-attestation claim profile has a fixed bounded purpose id
  that appears in `self_attestation.allowed_purposes`.

Definition of Done:

- Unit tests cover disabled default, valid enabled config, static-auth
  rejection, missing token claim config, unsupported request field, unsupported
  normalizer, and empty allow-lists.
- Unit tests cover invalid rate-limit values and default rate-limit behavior.
- Unit tests cover invalid token lifetime, missing citizen client/audience
  policy, and missing purpose policy.
- Unit tests cover cross-block config failures for scope-map privilege
  escalation, excessive leeway, missing wallet-origin allow-list when browser
  CORS is enabled, and credential validity above 600 seconds.
- Unit tests cover `token_claim: sub` rejected unless
  `allow_sub_as_civil_id = true`, invalid token-claim charset, unsupported
  request-field enum values, and missing claim-profile purpose id.
- Audit schema tests prove required self-attestation fields can be represented
  without raw token, subject, holder, or source values.
- Serialization round-trip keeps disabled config compact and enabled config
  explicit.

### Stage 2: OIDC Token Claim Access

- Preserve the verified token claims needed by self-attestation policy after
  OIDC verification.
- Extend `EvidencePrincipal` with typed bounded verified-token context.
- Keep static credentials free of token-claim context.

Definition of Done:

- Tests prove `sub` and custom string claims are available to policy checks.
- Tests prove missing or non-string custom claims fail closed.
- Tests prove issuer, audience, token type, expiry, and signing algorithm
  validation fail closed for citizen tokens.
- Tests prove configured `required_acr_values` fail closed when `acr` is
  missing or unaccepted.
- Tests prove configured `max_auth_age_seconds` fails closed when `auth_time`
  is missing or too old.
- Tests prove `jku`, `x5u`, embedded `jwk`, unknown `kid`, `alg = none`, and
  excessive token lifetime fail closed.
- No raw token or full claims object is logged.

### Stage 3: Evaluation Guard

- Add a self-attestation guard before Relay consultations in evaluate.
- Place the guard in `api/evaluations.rs::evaluate` after request parsing, authentication,
  principal construction, and claim selection, but before the runtime evaluation
  path or any Relay consultation.
- Add `EvaluationCapability` to the runtime evaluation context with
  `Machine { scopes }` and `SelfAttestation { claim_id, subject_binding_hash }`
  variants.
- Enforce subject binding, operation, claims, disclosure, format, and required
  scopes.
- Mark stored evaluations with immutable self-attestation metadata.
- Classify each OIDC request into exactly one access mode before authorization.

Definition of Done:

- A valid self-attestation request evaluates one configured claim.
- Citizen tokens never receive direct Relay consultation scopes; Relay consultations use only the
  internal derived `EvaluationCapability::SelfAttestation` after all guards pass.
- Relay consultations reject arbitrary claim ids and machine-only operations
  when the capability is `SelfAttestation`.
- Ambiguous citizen or machine-client classification fails closed.
- A supplied identity-context mismatch returns a stable denial before any source
  read.
- A subject mismatch writes a self-attestation denial audit event without raw
  target identifiers.
- A claim outside the allow-list is denied before any Relay consultation.
- A missing self-attestation scope is denied when `scope_policy = required`.
- With `scope_policy = optional`, a token with no scope signal may proceed, but
  a token with a scope signal that omits the configured self-attestation scope
  is denied.
- With `scope_policy = disabled`, a token with no self-attestation scope may
  proceed only through the allowed citizen client/audience, assurance, and
  subject-binding checks.
- Caller-supplied `target`, `requester`, `relationship`, or `on_behalf_of`
  values that conflict with the token-derived self context are rejected.
- Missing or unallowed purpose values fail before Relay consultations.
- Subject mismatch and repeated denial attempts are rate limited without source
  reads.
- A successful self-attestation evaluation writes a chained audit event with
  `access_mode = self_attestation`, claim hash, evaluation id, source count, and
  correlation id.
- Correlation ids are validated and unsafe caller-supplied values are replaced.
- Discovery advertises only bounded self-attestation capability metadata.
- Existing machine-client evaluate tests remain green.

### Stage 4: Render And Credential Guard

- Re-apply self-attestation policy for render.
- Re-apply self-attestation policy for credential issuance.
- Require credential profile allow-list for self-attestation issuance.
- Preserve existing holder DID proof behavior.

Definition of Done:

- A valid self-attestation evaluation can render only allowed formats.
- A valid self-attestation evaluation can issue an SD-JWT VC with holder proof.
- Render and credential issuance re-check stored `access_mode`,
  principal hash, subject id type, subject-binding hash, policy hash, and
  evaluation age using a currently valid citizen token.
- Credential issuance without required holder proof fails.
- Credential issuance audit records include credential profile and holder
  binding mode, but not holder proof, SD-JWT disclosures, or raw holder key
  material.
- Credential profiles used by self-attestation enforce short validity in tests
  or config validation.
- Citizen credential payload tests verify no raw registry identifiers,
  unnecessary civil attributes, or raw `subject.id` are included by default.
- Citizen credential subject identifiers are the holder DID in v1, or are
  derived per `(issuer, holder DID, claim_profile)` if a profile explicitly
  requires a pairwise subject distinct from the holder DID; they never expose
  the bound subject hash directly.
- A different principal cannot render or issue from the stored evaluation.
- A disallowed credential profile fails.

### Stage 5: External Adopter Story

- Add an optional story in the external adopter repository, currently Solmara
  Lab, that provisions a citizen-capable OIDC
  token with a namespaced custom subject-binding claim from an EdDSA dev issuer.
- Configure a Notary instance with `self_attestation.enabled = true`.
- Demonstrate a citizen token requesting an attestation for itself.
- Demonstrate a denied request for a different subject.
- Demonstrate holder-bound SD-JWT VC issuance.

Definition of Done:

- The story produces non-secret artifacts for token claims, successful
  evaluation, subject-mismatch denial, and credential issuance.
- The story never writes raw access tokens, client secrets, Relay source credentials, or
  full registry rows to artifacts.
- The story verifies audit artifacts link the citizen request, Notary decision,
  and Relay consultation by correlation id without exposing raw citizen
  identifiers.
- The story demonstrates in-Notary subject mismatch rate limiting and
  documents that production hour-window or cross-replica enforcement requires a
  gateway or shared limiter.
- The story remains optional so Registry Stack release checks do not depend on
  an external citizen IdP setup.

## Resolved V1 Decisions

- Self-attestation lives in top-level `self_attestation`.
- The target identifier scheme is mandatory and must match configured
  `subject_binding.id_type`.
- `subject_binding.request_field` is an enum, and v1 accepts only
  `SubjectId`.
- The external adopter demo uses a namespaced custom subject-binding claim, not
  `sub`.
- `token_claim: sub` requires `allow_sub_as_civil_id = true`; otherwise config
  validation rejects it.
- The first adopter story uses an EdDSA dev issuer. Zitadel RS256 support is a
  separate hardening ticket requiring RSA minimum key-size enforcement.
- Citizen-facing credential validity is capped at 600 seconds in v1.
- Rate limiting starts with in-Notary in-process buckets keyed through
  `AuditKeyHasher`; hour-window or cross-replica enforcement requires a gateway
  or shared limiter.
- Per-bound-subject rate limiting is omitted in v1 because self-only binding
  makes it redundant with per-principal limits.
- Citizen self-attestation requires both a configured citizen client or audience
  and a configured self-attestation scope.
- Future delegation is represented as `delegation_chain = []` in v1. Any
  non-empty delegation chain requires a separate design.

## Deployment Questions Before Implementation

- Is there a gateway in front of Notary in the target deployment, and can it
  enforce production hour-window or cross-replica rate limits?
- Which production IdPs, if any, must be supported beyond the EdDSA dev issuer
  used by the lab story?
- What retention expectations apply to rate-limit state and audit artifacts?
- Will any Relay client need citizen context? V1 says no; Relay clients
  receive only `EvaluationCapability::SelfAttestation` and existing Relay workload
  credentials.
- What does "wallet" mean in the lab story: CLI holder proof, browser wallet,
  mobile wallet, or portal-mediated issuance?
- How should existing API-key deployments migrate if they want citizen
  self-attestation? V1 requires OIDC and leaves existing API-key deployments
  unchanged unless they enable this feature.

## Parallel Implementation Waves

The implementation should be run in short waves with disjoint worker ownership.
Each worker must assume other workers are active in the codebase, avoid
reverting unrelated edits, and return: scope handled, files changed, tests
added or updated, commands run, results, blockers, and residual risks.

Code review is required at the end of every wave. A reviewer must check the
diff against this spec, confirm the wave Definition of Done, inspect audit and
privacy non-disclosure paths, and verify that no "partially implemented" item
is being carried forward without an explicit blocker.

### Global Definition of Done

The feature is done only when all of the following are true:

- Self-attestation is disabled by default and existing static-credential and
  machine-client OIDC behavior remain unchanged in tests.
- Enabling `self_attestation` requires OIDC, a top-level config block, a
  namespaced subject-binding claim, `SubjectId` request-field enum,
  mandatory target identifier scheme, allowed citizen client or audience, and
  self-attestation scope.
- `EvidencePrincipal` carries typed `BoundedVerifiedClaims`; raw JWTs, raw
  claim maps, access tokens, and unrecognized claims are not stored, logged, or
  passed to Relay clients.
- Every OIDC request is classified as exactly one access mode before
  authorization, and ambiguous citizen or machine classification fails closed.
- Configured assurance policy fails closed when `acr` or `auth_time` is missing
  or unacceptable.
- The self-attestation guard runs in `api/evaluations.rs::evaluate` before any runtime
  evaluation or Relay consultation.
- Citizen tokens never receive direct machine-client Relay consultation scopes; Relay
  consultations use only `EvaluationCapability::SelfAttestation` after all citizen guards
  pass.
- Stored evaluations include immutable self-attestation metadata, including
  `access_mode`, principal hash, issuer, client or audience, subject-binding
  hash, subject id type, canonical policy hash, evaluation expiration, and
  `delegation_chain = []`.
- Render and credential issuance re-check the stored authorization tuple,
  subject-binding hash, policy, credential profile, holder proof, and evaluation
  age using a currently valid citizen token.
- Audit events use typed redaction wrappers and can represent every required
  self-attestation field without generic raw identifier strings.
- Logs, metrics, audit JSONL, Problem Details, adopter artifacts, and credential
  payloads pass non-disclosure tests for tokens, civil identifiers, holder
  proofs, SD-JWT disclosures, source rows, and raw Relay responses.
- In-Notary rate limits run before Relay consultations and issuance, use keyed hashes,
  apply atomic multi-bucket semantics, audit bounded denial context, and fail
  closed when unavailable unless an explicit emergency fallback is configured.
- Citizen-facing credentials are holder-bound, do not claim holder-equals-
  subject, use holder DID as the v1 credential subject identifier, and have
  validity no greater than 600 seconds.
- The optional external adopter story demonstrates success, subject mismatch denial,
  rate limiting, holder-bound issuance, and audit correlation without writing
  secrets or raw registry rows.
- Focused tests, relevant package tests, lint or formatting checks, and the
  closest practical build command pass. Any skipped check names the exact
  reason and residual risk.

### Wave 1: Foundations

Parallel workers:

- Worker A owns config types, validation, defaults, and serialization tests.
- Worker B owns `AccessMode`, `EvaluationCapability`, `BoundedVerifiedClaims`, and
  OIDC claim extraction.
- Worker C owns audit schema fields and typed redaction wrappers.
- Worker D reviews the wave for config cross-block failures, JWT hardening, and
  audit non-disclosure.

Wave 1 is done when config validation, verified-claim transport, and audit
schema support are merged with tests and no evaluation path behavior has changed
unless self-attestation is enabled.

### Wave 2: Evaluation Guard And Rate Limits

Parallel workers:

- Worker A owns `api/evaluations.rs::evaluate` guard placement and access-mode
  classification.
- Worker B owns subject-binding, allow-list, fixed claim-profile purpose, and
  alternate-subject rejection tests.
- Worker C owns in-Notary rate-limit buckets, keyed rate-limit identifiers,
  and rate-limit audit events.
- Worker D reviews for BOLA, consultation-before-guard regressions, and generic
  external denial bodies.

Wave 2 is done when valid self-attestation evaluates one allowed claim, all
pre-consultation denials happen before Relay consultations, rate limits are enforced, and
existing machine-client evaluation tests remain green.

### Wave 3: Stored Evaluation, Render, And Issuance

Parallel workers:

- Worker A owns stored evaluation metadata and migration-compatible model
  changes.
- Worker B owns render policy re-checks.
- Worker C owns credential issuance policy re-checks, holder proof enforcement,
  credential freshness, and credential payload minimization.
- Worker D reviews for principal collision, stale evaluation reuse, holder
  confusion, and credential disclosure risks.

Wave 3 is done when render and issuance cannot be performed by a different
principal, access mode, subject-binding hash, client, audience, or stale
evaluation, and credential issuance works only for allowed profiles with holder
proof and the v1 holder-DID credential subject identifier.

### Wave 4: External Adopter And End-To-End Review

Parallel workers:

- Worker A owns the optional external adopter EdDSA issuer story and fixtures.
- Worker B owns non-secret artifact generation and audit correlation checks.
- Worker C owns documentation and operator notes for gateway rate limits,
  wallet origin policy, and Zitadel RS256 follow-up.
- Worker D performs final review across the full diff and verifies the Global
  Definition of Done.

Wave 4 is done when the adopter story demonstrates the full happy path and negative
paths, all artifacts are non-secret, audit linkage works by correlation id, and
the final reviewer signs off that no spec requirement remains partial.
