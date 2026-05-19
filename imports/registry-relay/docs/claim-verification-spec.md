# Claim Verification Spec

Status: draft, reviewed

This document specifies a proposed claim-verification surface for `registry-relay`.
It is intentionally separate from the existing id-based verify endpoint.

## Purpose

The existing endpoint:

```http
GET /datasets/{dataset_id}/{entity}/verify?{primary_key}=<value>
```

answers a narrow existence question:

```text
Does this registry contain a record with this identifier?
```

The claim-verification feature answers a richer question:

```text
Do these submitted facts match registry facts under a configured ruleset?
```

Example use cases:

- A benefits service submits known birth facts and asks whether they match the civil registry before continuing its own case workflow.
- A resident service confirms that submitted identity facts match registry facts before routing a request to a separate certificate-issuance process.
- A relying party submits facts extracted from an existing document and asks whether they match the registry.

## Endpoint

Use a new `POST` resource endpoint:

```http
POST /datasets/{dataset_id}/{entity}/claim-verifications
```

Rationale:

- The caller sends structured data in the request body.
- Personal data must not appear in URLs, proxy logs, browser history, or cache keys.
- The existing `GET /verify` route remains a backward-compatible id existence check.
- The richer feature has distinct semantics and should not be hidden behind the same route shape.
- The route is a noun resource: the caller creates a verification event and receives its result.

## HTTP Contract

Plain JSON response:

```http
POST /datasets/civil_registry/birth_record/claim-verifications HTTP/1.1
Content-Type: application/json
Accept: application/json
Authorization: Bearer <token>
Data-Purpose: service-intake-check
```

Signed JWT response:

```http
POST /datasets/civil_registry/birth_record/claim-verifications HTTP/1.1
Content-Type: application/json
Accept: application/vnd.registry-relay.claim-verification+jwt
Authorization: Bearer <token>
Data-Purpose: service-intake-check
```

Header names are case-insensitive. The implementation may read `data-purpose`; examples use `Data-Purpose` for readability.

`Data-Purpose` follows the existing project convention. It is required when the target entity config requires purpose headers. When present, it participates in the binding hash and signed receipt as `purpose_declared`.

If `Accept` is omitted, is `*/*`, or does not negotiate to a configured signed media type, the handler returns plain JSON. This matches the existing provenance negotiation behavior.

The v1 signed media type is `application/vnd.registry-relay.claim-verification+jwt`. Do not use `application/vc+jwt` for v1 claim-verification receipts. The v1 receipt is a server-to-server JWT attesting to the claim-to-registry comparison, not an official source credential and not a holder-presentable verifiable credential. A future holder-presentable profile may add `application/vc+jwt` or a separate credential-issuance endpoint without changing this v1 receipt contract.

All responses from this endpoint must include:

```http
Cache-Control: no-store
Vary: Authorization, Accept
```

Implementations must enforce a maximum request body size. The initial limit should be no more than 64 KiB. Larger bodies return `413 internal.payload_too_large`.

## Request Body

### Minimal Claim Verification

Use this shape when the caller has facts to verify, but does not already hold an external evidence artifact.

```json
{
  "ruleset": "birth-facts-match-v1",
  "claims": {
    "given_name": "Camille",
    "family_name": "Durand",
    "date_of_birth": "1992-04-18",
    "place_of_birth": "Lyon",
    "parent_1_given_name": "Marie",
    "parent_1_family_name": "Durand",
    "parent_2_given_name": "Antoine",
    "parent_2_family_name": "Durand"
  }
}
```

### Targeted Claim Verification

Use `subject.id` when the caller already knows the target registry id and wants to verify facts against that specific record.

```json
{
  "ruleset": "birth-facts-match-v1",
  "subject": {
    "id": "birth-record-123"
  },
  "claims": {
    "given_name": "Camille",
    "family_name": "Durand",
    "date_of_birth": "1992-04-18",
    "place_of_birth": "Lyon"
  }
}
```

Targeted calls are more sensitive because they support confirmation attacks against known ids. They require ruleset opt-in, an additional principal permission, and stricter rate limits than untargeted verification.

### External Evidence Verification

Use `evidence` only when the caller is verifying external documents or artifacts they already hold. It is metadata about where the submitted claims came from. It is not the registry record being verified.

`evidence` is an array to support multi-document cases without changing the wire shape later.

```json
{
  "ruleset": "birth-document-facts-match-v1",
  "claims": {
    "given_name": "Camille",
    "family_name": "Durand",
    "date_of_birth": "1992-04-18",
    "place_of_birth": "Lyon"
  },
  "evidence": [
    {
      "type": "birth_certificate",
      "issuer_country": "FR",
      "issued_by": "Ville de Lyon",
      "issued_at": "2024-09-02",
      "document_number": "1992-LYON-004812"
    }
  ]
}
```

If a resident is asking a separate service to issue a birth certificate and does not already have a source document, omit `evidence`.

The server must not treat `evidence` as registry-confirmed document authenticity unless a ruleset explicitly verifies evidence-specific fields against an authoritative source. Evidence is otherwise provenance for the caller-submitted claims only.

## Field Semantics

`ruleset`

The configured verification logic to apply. It defines required fields, normalization, matching rules, candidate lookup, ambiguity handling, diagnostics, signed-output behavior, and authorization. A ruleset does not make the caller's policy or eligibility decision.

`subject.id`

Optional known registry identifier. If present, verification targets that specific record. If absent, the registry attempts to find one matching record using the configured ruleset.

`claims`

The facts submitted by the caller. These are compared against registry data. The response must not echo the full claim by default.

`evidence`

Optional array of metadata objects about external documents or artifacts that produced the claims. It is present only when the caller already holds such artifacts. Raw evidence is not logged and is not returned by default.

## Plain JSON Response

HTTP `200` is used only for a completed verification comparison. It is not used for malformed requests, missing fields, unauthorized rulesets, or unknown rulesets.

### Match

```json
{
  "verification_id": "01J5K8M0000000000000000ABC",
  "decision": "match",
  "ruleset": "birth-facts-match-v1",
  "checked_at": "2026-05-17T10:30:00Z",
  "ingest_version": "01J5K8M0000000000000000000",
  "claim_hash": "hmac-sha256:4a1f9c2b8d7e0f..."
}
```

### Mismatch

```json
{
  "verification_id": "01J5K8M0000000000000000ABD",
  "decision": "mismatch",
  "ruleset": "birth-facts-match-v1",
  "checked_at": "2026-05-17T10:30:00Z",
  "ingest_version": "01J5K8M0000000000000000000",
  "claim_hash": "hmac-sha256:4a1f9c2b8d7e0f..."
}
```

### Ambiguous Match

```json
{
  "verification_id": "01J5K8M0000000000000000ABE",
  "decision": "ambiguous",
  "ruleset": "birth-facts-match-v1",
  "checked_at": "2026-05-17T10:30:00Z",
  "ingest_version": "01J5K8M0000000000000000000",
  "claim_hash": "hmac-sha256:4a1f9c2b8d7e0f..."
}
```

`decision` is the state machine. There is no separate `verified` boolean in JSON responses. Callers should treat `decision == "match"` as verified.

`ingest_version` may be `null` when the underlying resource has no ready ingest version. If the resource is configured but failed ingest or is mid-reload, the endpoint should return `503 schema.resource_unavailable` instead of guessing against stale or missing data.

When `evidence` is present, the response also includes an HMAC-bound evidence digest:

```json
{
  "verification_id": "01J5K8M0000000000000000ABF",
  "decision": "match",
  "ruleset": "birth-document-facts-match-v1",
  "checked_at": "2026-05-17T10:30:00Z",
  "ingest_version": "01J5K8M0000000000000000000",
  "claim_hash": "hmac-sha256:4a1f9c2b8d7e0f...",
  "evidence_hash": "hmac-sha256:9f14a0d2bc331e..."
}
```

## Decision Values

Initial `200` decision values:

```text
match
mismatch
ambiguous
```

Meanings:

| Decision | Meaning |
| --- | --- |
| `match` | Exactly one candidate registry record matched the submitted claims under the ruleset. |
| `mismatch` | No candidate registry record matched, or the targeted record did not match. |
| `ambiguous` | More than one candidate registry record matched, so Registry Relay cannot produce a single-record attestation. |

`ambiguous` returns `200`, not `3xx`, because it is not an HTTP redirect or alternative-resource negotiation. It is a completed domain decision.

Decision values are append-only. New values may be added in later versions, but existing values must not be repurposed.

`insufficient_claims`, `ruleset_not_allowed`, and unknown rulesets are Problem Details errors, not decisions.

## Ambiguity And Timing Disclosure

`ambiguous` can itself disclose sensitive information, for example that a family-name and date-of-birth collision exists. Each ruleset must define:

```yaml
expose_ambiguous: false
```

When `expose_ambiguous` is `false`, the handler collapses ambiguous outcomes into `mismatch`.

The implementation must avoid observable timing differences between `match`, `mismatch`, and `ambiguous` branches. Rulesets should use bounded candidate lookup, uniform normalization work, and response padding or jitter where needed. Field diagnostics must not change timing behavior in a way that reveals hidden match candidates.

## Optional Diagnostics

Field-level diagnostics are policy-controlled and off by default for sensitive registries.

```json
{
  "verification_id": "01J5K8M0000000000000000ABG",
  "decision": "mismatch",
  "ruleset": "birth-facts-match-v1",
  "checked_at": "2026-05-17T10:30:00Z",
  "ingest_version": "01J5K8M0000000000000000000",
  "claim_hash": "hmac-sha256:4a1f9c2b8d7e0f...",
  "field_results": {
    "given_name": "match",
    "family_name": "match",
    "date_of_birth": "match",
    "place_of_birth": "mismatch"
  }
}
```

`field_results` keys are caller-submitted claim field names after ruleset validation. Values are small status enums, not registry values.

The endpoint must not return canonical registry values unless the caller has explicit row-read or certificate-issuance authorization. Audit middleware must scrub diagnostics and forbid canonical values, hidden candidate ids, and raw submitted fields from logs.

Even when field diagnostics are disabled, `match`, `mismatch`, and `ambiguous` are diagnostic. Use `expose_ambiguous: false` for high-sensitivity rulesets.

## Binding Hashes

`claim_hash` binds the verification result to the submitted verification input without repeating private data.

Because civil-registry claim spaces can be brute-forced offline, `claim_hash` must be an HMAC, not a bare digest. The response prefix is:

```text
hmac-sha256:<hex>
```

Requirements:

- Canonicalize hashed material with RFC 8785 JSON Canonicalization Scheme, also called JCS.
- Use HMAC-SHA-256 with a server-side secret loaded from the platform secret store.
- Bind `dataset_id`, `entity`, `ruleset`, normalized `claims`, optional `subject.id`, `Data-Purpose`, and all evidence items when present.
- Include a `verification_id` in the hashed material.
- Use a stable `binding_key_id` internally so old audit records can be interpreted after key rotation.
- Do not include bearer credentials, transport-only headers other than `Data-Purpose`, or audit-only metadata.
- Do not log the raw material used to compute the HMAC.

Suggested canonical material:

```json
{
  "version": 1,
  "verification_id": "01J5K8M0000000000000000ABC",
  "dataset_id": "civil_registry",
  "entity": "birth_record",
  "ruleset": "birth-facts-match-v1",
  "purpose": "service-intake-check",
  "subject": {
    "id": "birth-record-123"
  },
  "claims": {
    "date_of_birth": "1992-04-18",
    "family_name": "Durand",
    "given_name": "Camille",
    "place_of_birth": "Lyon"
  },
  "evidence": []
}
```

`evidence_hash` is returned when `evidence` is present. It is computed over the RFC 8785 canonicalized evidence array plus `verification_id`, `dataset_id`, `entity`, `ruleset`, and `Data-Purpose`, using the same HMAC key family.

The HMAC output lets the server bind and correlate decisions safely, but independent third parties cannot recompute the value without the secret. If external recomputation is required for a future workflow, that workflow needs a separate disclosure protocol, not a bare hash in this endpoint.

## Signed JWT Receipt Response

When the caller sends `Accept: application/vnd.registry-relay.claim-verification+jwt` and signed receipts are enabled, the response body is a compact JWS:

```text
eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDp3ZWI6ZGF0YS5leGFtcGxlLmdvdiNrZXktMSJ9...
```

The response `Content-Type` is `application/vnd.registry-relay.claim-verification+jwt`.

For v1 this spec treats the signed output as a server-to-server JWT receipt. It is not a holder-presentable credential and does not use the VC-JWT media type. A holder-presentable version would need a holder DID, `cnf`, or a verifiable-presentation wrapper and is out of scope for v1.

The JWT must be audience-bound to the authenticated caller:

- `aud` is the caller principal id, client id, or configured relying-party audience.
- `sub` is the same caller-bound subject unless a ruleset defines a stricter subject.
- Relying parties must validate `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, and `jti`.

Decoded JWT payload shape:

```json
{
  "iss": "did:web:data.example.gov",
  "sub": "client:intake-service",
  "aud": "client:intake-service",
  "iat": 1779013800,
  "nbf": 1779013800,
  "exp": 1779014100,
  "jti": "urn:registry-relay:claim-verification:01J5K8M0000000000000000ABC",
  "receipt_type": "registry-relay.claim-verification.v1",
  "verification_id": "01J5K8M0000000000000000ABC",
  "dataset": "civil_registry",
  "entity": "birth_record",
  "decision": "match",
  "ruleset": "birth-facts-match-v1",
  "purpose_declared": "service-intake-check",
  "checked_at": "2026-05-17T10:30:00Z",
  "claim_hash": "hmac-sha256:4a1f9c2b8d7e0f...",
  "evidence_hash": "hmac-sha256:9f14a0d2bc331e..."
}
```

The signed receipt attests to the verification comparison and binds it to the submitted input through HMAC values. It does not include the full claim by default and must not be presented as an official source credential.

The v1 receipt intentionally avoids VC-specific fields such as `@context`, `type: VerifiableCredential`, `credentialSubject`, and `credentialStatus`. Short `exp` windows are the revocation mechanism for the receipt.

SD-JWT VC is out of scope for v1.

## Signing And Verification Requirements

JOSE header requirements:

```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "did:web:data.example.gov#key-1"
}
```

Requirements:

- Implementations must support `EdDSA` with Ed25519 keys.
- Verifiers must reject `alg: none`.
- `kid` must identify a concrete DID verification method listed under `assertionMethod`.
- Do not use semantic placeholders such as `#issuance` unless that exact verification method is published in the DID Document.
- ES256 may be added later for EUDI compatibility, but it is not required for v1.

`did:web` resolution for verification must be HTTPS-only, reject private and loopback IP ranges, use bounded timeouts, and cache DID Documents for at least the longest possible signed receipt validity window. These controls should match the SSRF posture of the existing JWKS fetcher.

## Privacy Rules

Default responses must not echo the full claim data.

Responses should include:

- verification id
- decision
- ruleset
- checked timestamp
- ingest version
- claim HMAC
- evidence HMAC when evidence was supplied

Responses should avoid:

- raw registry row data
- corrected canonical values
- full submitted claim echo
- hidden match candidates
- detailed mismatch reasons unless allowed by policy

The raw request body and raw claims must not appear in application logs, traces, OpenTelemetry attributes, metrics labels, panic messages, or Problem Details `instance` URIs. Audit records may include `verification_id`, `claim_hash`, `evidence_hash`, `ruleset`, `decision`, and `purpose`, but not raw claims or raw evidence.

Audit retention policy must treat `claim_hash` and `evidence_hash` as sensitive correlation identifiers. HMAC key rotation should preserve the ability to interpret retained audit records without allowing offline rainbow-table attacks.

This prevents the endpoint from becoming a data-enrichment or probing API.

## Authorization

Use a scope distinct from the current id-based existence check.

Scope suffix:

```text
claim_verification
```

Example entity access config:

```yaml
access:
  metadata_scope: civil_registry:metadata
  read_scope: civil_registry:rows
  verify_scope: civil_registry:verify
  claim_verification_scope: civil_registry:claim_verification
  aggregate_scope: civil_registry:aggregate
```

This keeps permissions separate:

| Scope suffix | Allows |
| --- | --- |
| `verify` | Id-based existence checks. |
| `claim_verification` | Submitted-claims matching. |
| `rows` | Row content access. |
| `metadata` | Schema, catalog, dataset, and OpenAPI visibility. |
| `aggregate` | Aggregate discovery and execution. |

Runtime authorization order:

1. Authenticate the caller.
2. Check the entity-level `claim_verification_scope`.
3. Check the requested ruleset's allowlist against the principal.
4. If `subject.id` is present, check the targeted-verification permission.
5. Only then evaluate whether the ruleset exists and is enabled.

This order avoids ruleset enumeration. Unknown and disallowed rulesets both return `403 claim_verification.ruleset_not_allowed` to callers who are not authorized to know the ruleset catalog.

Ruleset allowlists may be expressed as principal ids, client ids, scopes, or a ruleset-specific scope:

```text
civil_registry:claim_verification:birth-facts-match-v1
```

## Ruleset Configuration

Rulesets are deployment-configured, entity-scoped verification profiles. A ruleset should define:

- Required claim fields.
- Optional claim fields.
- Candidate lookup fields.
- Normalization rules, such as case folding, whitespace trimming, date parsing, and accent handling.
- Match mode. V1 supports `normalized_exact` only.
- Whether `subject.id` is allowed, required, or forbidden.
- Whether `evidence` is allowed, required, or forbidden.
- Whether field-level diagnostics can be returned.
- Whether ambiguous outcomes are exposed or collapsed to mismatch.
- Which scopes or principals may use the ruleset.
- Whether signed receipts are allowed and which audiences may receive them.

Example sketch:

```yaml
claim_verification:
  rulesets:
    birth-facts-match-v1:
      required_claims:
        - given_name
        - family_name
        - date_of_birth
        - place_of_birth
      optional_claims:
        - parent_1_given_name
        - parent_1_family_name
        - parent_2_given_name
        - parent_2_family_name
      candidate_lookup:
        - date_of_birth
        - family_name
      normalization:
        names: unicode_casefold_trim
        dates: iso_date
      match_mode: normalized_exact
      subject_id: optional
      evidence: optional
      diagnostics: none
      expose_ambiguous: false
      allow:
        scopes:
          - civil_registry:claim_verification:birth-facts-match-v1
      signed_receipts:
        enabled: true
        audiences:
          - client:intake-service
```

This is a proposed shape, not an implementation commitment. V1 rejects unsupported match modes rather than silently degrading them. Fuzzy matching, probabilistic scoring, phonetic matching, and manual-review workflows are future profiles, not v1 behavior.

## Schema Discovery

OpenAPI in this project is hand-assembled and cannot usefully describe every per-ruleset `claims` shape as a static schema. The endpoint's OpenAPI request schema will necessarily be broad, likely `additionalProperties: true`.

To make code generation and validation practical, add a ruleset schema discovery endpoint before broad rollout:

```http
GET /datasets/{dataset_id}/{entity}/claim-verification-rulesets
GET /datasets/{dataset_id}/{entity}/claim-verification-rulesets/{ruleset}
```

These endpoints should be metadata and authorization filtered.

## Relationship To Certificate Issuance

This endpoint verifies claims. It does not issue a birth certificate document by itself.

Recommended split:

```http
POST /datasets/{dataset_id}/{entity}/claim-verifications
POST /datasets/{dataset_id}/{entity}/certificates
```

`claim-verifications` says whether submitted facts match.

`certificates` issues or returns a certificate artifact, with stronger authorization and audit requirements.

## Error Handling

Use the existing RFC 9457 Problem Details envelope and stable `code` field.

Suggested new or reused codes:

| Condition | HTTP status | Code |
| --- | --- | --- |
| Missing credential | `401` | `auth.missing_credential` |
| Invalid credential | `401` | `auth.invalid_credential` |
| Missing `claim_verification` scope | `403` | `auth.scope_denied` |
| Missing purpose header | `400` | `auth.purpose_required` |
| Request body too large | `413` | `internal.payload_too_large` |
| Unknown dataset | `404` | `schema.unknown_dataset` |
| Unknown entity | `404` | `schema.unknown_resource` |
| Resource unavailable | `503` | `schema.resource_unavailable` |
| Malformed request body | `400` | `claim_verification.invalid_request` |
| Required claim missing or invalid | `400` | `claim_verification.insufficient_claims` |
| Ruleset not allowed or hidden | `403` | `claim_verification.ruleset_not_allowed` |

Do not return `404 claim_verification.unknown_ruleset` to unauthorized callers. It allows ruleset enumeration. Operators may expose a `404` for unknown rulesets only after the caller has passed both entity-level and ruleset-catalog authorization checks.

## Implementation Notes

This feature is not a small extension of the current `EntityQueryEngine::verify_exists` path.

Known implementation work:

- Add a ruleset execution engine. The current query engine supports exact-match filtering; normalization, candidate disambiguation, ambiguity handling, and timing controls are new work. Fuzzy matching is explicitly deferred outside v1.
- Add optional config structs for `claim_verification`. Existing config structs use `deny_unknown_fields`, so YAML support must be added before any example config can parse.
- Add `claim_verification_scope` with a default-deny migration path so existing configs do not break.
- Add RFC 8785 JCS support. Pick a crate or implement carefully; this choice is load-bearing for reproducible HMAC material.
- Extend the existing provenance signing infrastructure with a signed-receipt profile and audience-bound JWT payload.
- Update hand-assembled OpenAPI and add ruleset schema discovery to avoid unusable client generation.
- Add audit body-redaction support for POST bodies. Existing query redaction is not enough for this endpoint.

## Open Questions

- Should field diagnostics use simple statuses or structured reason codes?
- Should the endpoint support async workflows for registries that require manual review?
- Which crate or internal implementation should provide RFC 8785 JCS?

## Implementation Plan

Implement in waves so each slice has a bounded review surface, focused tests, and a clear definition of done. Workers may run in parallel only when their file ownership is disjoint. No worker may revert or reformat unrelated changes, and each worker must list changed files and verification commands in their handoff.

### Review Cadence

Every wave has three review gates:

1. Design review before coding starts, confirming scope, touched files, migration posture, and test plan.
2. Code review before merge, focused on correctness, privacy, auth boundaries, timing/leak risks, and test coverage.
3. Validation review after tests pass, checking the wave's definition of done against the spec and confirming no partial TODO path remains.

Cross-wave integration happens only after all workers in the wave have passed code review. If one worker uncovers a contract change, pause integration and update this spec before continuing.

### Wave 0: Scaffolding And Threat Model

Goal: confirm implementation scaffolding against the v1 product decisions: custom signed JWT receipt media type, audience-bound JWT payload, and normalized-exact ruleset execution.

Parallel ownership:

- Worker A owns signed-output implementation details: receipt payload builder, registered claims, DID method requirements, and accepted algorithms.
- Worker B owns canonicalization and HMAC decisions: RFC 8785 crate choice, HMAC key config shape, key rotation metadata, and audit retention implications.
- Worker C owns route and config migration decisions: endpoint path, config structs, default-deny behavior, and compatibility with existing YAML.

Definition of done:

- No open question blocks the v1 route, media type, hash binding, receipt payload, or normalized-exact matching model.
- Spec examples and implementation plan agree on route, media type, decision values, hash format, and scope names.
- A checklist exists for required tests and threat-model assertions.
- Design review records no unresolved blocker.

### Wave 1: Config, Models, And Error Taxonomy

Goal: make the new feature parseable and representable without exposing an HTTP route yet.

Parallel ownership:

- Worker A owns config structs and YAML parsing for `claim_verification`, including `claim_verification_scope` with default-deny migration.
- Worker B owns request and response model types, decision enums, validation helpers, and Problem Details error variants.
- Worker C owns documentation and examples for minimal, targeted, and evidence-bearing requests.

Definition of done:

- Existing configs parse unchanged.
- New example configs with one ruleset parse and reject invalid rulesets deterministically.
- Error codes are stable and covered by taxonomy tests.
- Unit tests cover required claims, invalid evidence shapes, missing purpose, hidden rulesets, and targeted-call permission checks at the model/config layer.
- Code review confirms no route or query behavior changed yet.

### Wave 2: Binding Hashes And Audit Redaction

Goal: implement safe request binding before matching logic or signed output exists.

Parallel ownership:

- Worker A owns RFC 8785 canonicalization and HMAC helpers, including test vectors.
- Worker B owns secret loading, `binding_key_id`, rotation metadata, and failure modes.
- Worker C owns POST-body redaction in audit, tracing, error reporting, and metrics.

Definition of done:

- `claim_hash` and `evidence_hash` use HMAC-SHA-256 over RFC 8785 canonical material.
- Hashed material binds `verification_id`, `dataset_id`, `entity`, `ruleset`, `Data-Purpose`, normalized claims, optional `subject.id`, and evidence when present.
- Raw claims and raw evidence cannot appear in audit records, logs, traces, metrics labels, or Problem Details `instance` URIs.
- Tests include deterministic HMAC vectors, evidence ordering behavior, missing secret failure, redaction assertions, and no raw-body leakage.
- Security review confirms no bare hash of civil-registry claims is emitted.

### Wave 3: Ruleset Engine MVP

Goal: implement the first ruleset execution path with normalized exact matching only.

Parallel ownership:

- Worker A owns ruleset validation and normalization primitives.
- Worker B owns candidate lookup and exact-match execution through the existing query engine.
- Worker C owns ambiguity handling, `expose_ambiguous`, timing-risk mitigation hooks, and rate-limit integration points.

Definition of done:

- MVP supports required claims, optional claims, normalized exact comparison, optional `subject.id`, and evidence policy checks.
- No fuzzy matching ships in this wave.
- `match`, `mismatch`, and `ambiguous` are the only successful decisions.
- `insufficient_claims`, hidden rulesets, missing scope, missing purpose, and unavailable resources return Problem Details, not decisions.
- Tests cover match, mismatch, ambiguous exposed, ambiguous collapsed to mismatch, targeted record mismatch, missing required claim, hidden ruleset, and resource unavailable.
- Review confirms the endpoint cannot be used to recover canonical registry values.

### Wave 4: HTTP Route And OpenAPI

Goal: expose the plain JSON endpoint and document it accurately.

Parallel ownership:

- Worker A owns the Axum route, request body limits, headers, auth ordering, and response headers.
- Worker B owns OpenAPI additions and ruleset schema discovery endpoints.
- Worker C owns end-to-end route tests and demo client examples.

Definition of done:

- `POST /datasets/{dataset_id}/{entity}/claim-verifications` returns plain JSON for omitted `Accept`, `Accept: */*`, and `Accept: application/json`.
- Responses include `Cache-Control: no-store` and `Vary: Authorization, Accept`.
- Request bodies over the configured limit return `413 internal.payload_too_large`.
- Ruleset discovery is metadata and authorization filtered.
- OpenAPI is broad but accurate, and discovery endpoint docs explain per-ruleset validation.
- Integration tests cover auth ordering, no ruleset enumeration, purpose binding, body limit, response headers, and OpenAPI visibility.

### Wave 5: Signed JWT Receipts

Goal: add signed server-to-server receipt output after plain JSON behavior is stable.

Parallel ownership:

- Worker A owns the signed-receipt profile, payload builder, and provenance signing integration.
- Worker B owns `aud`, `sub`, `iss`, `iat`, `nbf`, `exp`, `jti`, `kid`, and algorithm validation.
- Worker C owns third-party verification tests, DID document expectations, and negative verification cases.

Definition of done:

- `Accept: application/vnd.registry-relay.claim-verification+jwt` returns a compact JWS only when signed receipts and ruleset policy allow it.
- Signed payload contains `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`, `receipt_type`, `verification_id`, `dataset`, `entity`, `decision`, `ruleset`, `purpose_declared`, `checked_at`, `claim_hash`, and optional `evidence_hash`.
- `kid` points to a concrete assertion method such as `#key-1`.
- Verifiers reject `alg: none`, wrong audience, expired receipts, unknown key ids, and tampered payloads.
- The signed receipt contains HMAC values and decision metadata, not raw claims or raw evidence.
- Third-party JOSE verification tests pass independently of internal signer code.

### Wave 6: Hardening, Performance, And Rollout

Goal: prove the feature is safe enough for demo and production-like workloads.

Parallel ownership:

- Worker A owns privacy and abuse tests: probing resistance, ambiguity disclosure, diagnostics scrubbing, and rate limits.
- Worker B owns performance tests: bounded candidate lookup, request size, timing variance measurement, and load tests.
- Worker C owns operator docs, migration notes, demo config, and rollout checklist.

Definition of done:

- Focused unit, integration, provenance, OpenAPI, audit, and config tests pass.
- Broader lint, typecheck, and build commands pass.
- Performance tests show bounded candidate lookup and no obvious timing branch leak across `match`, `mismatch`, and collapsed `ambiguous` for configured fixtures.
- Operator docs explain secrets, HMAC key rotation, audit retention, rate limits, diagnostics policy, and ruleset authoring.
- Rollout checklist includes feature flag or config gate, demo fixture coverage, rollback behavior, and monitoring signals.
- Final review confirms every v1 requirement in this spec is implemented or explicitly deferred with a tracked issue and no silent placeholder path.
