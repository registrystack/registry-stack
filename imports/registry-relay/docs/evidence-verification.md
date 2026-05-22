# Evidence Verification Guide

Evidence verification lets an authorized caller submit claims and check whether those submitted facts match registry facts through a declared evidence offering. It produces a verification receipt or attestation of that comparison; it does not issue official source credentials or decide eligibility for a service or benefit.

The public surface is offering-first:

```http
GET /metadata/evidence-offerings
GET /metadata/evidence-offerings/{offering_id}
POST /evidence-offerings/{offering_id}/verifications
```

The metadata routes describe what evidence can be checked, which authority offers it, the evidence type, assurance metadata, permitted purpose metadata, and the request schema. The `POST` route creates a verification event for one Relay-native offering whose metadata declares `access.kind: registry-relay-verification`. Offerings with `access.kind: evidence-server` are published for discovery; clients evaluate those claims by calling the advertised Evidence Server endpoint directly. Do not put claim data in URLs, query strings, cache keys, or proxy-visible paths.

Common uses:

- A benefits service checks submitted birth facts against the registry before continuing its own case workflow.
- A resident service confirms that submitted identity facts match registry facts before routing a request to a separate certificate-issuance process.
- A relying party submits facts extracted from a document and asks whether the registry facts agree.

## Discovery

List visible offerings:

```http
GET /metadata/evidence-offerings HTTP/1.1
Authorization: Bearer <token>
Accept: application/json
```

Fetch one offering:

```http
GET /metadata/evidence-offerings/birth_record_facts HTTP/1.1
Authorization: Bearer <token>
Accept: application/json
```

Metadata visibility follows dataset metadata scopes. Discovery does not execute a check and does not grant row, aggregate, or evidence-verification access.

## Create A Verification

Plain JSON is the default response:

```http
POST /evidence-offerings/birth_record_facts/verifications HTTP/1.1
Content-Type: application/json
Accept: application/json
Authorization: Bearer <token>
Data-Purpose: https://data.example.gov/purposes/service-intake-check
```

Signed receipts use a custom JWT media type:

```http
POST /evidence-offerings/birth_record_facts/verifications HTTP/1.1
Content-Type: application/json
Accept: application/vnd.registry-relay.evidence-verification+jwt
Authorization: Bearer <token>
Data-Purpose: https://data.example.gov/purposes/service-intake-check
```

If `Accept` is omitted, is `*/*`, or does not negotiate to a configured signed media type, Registry Relay returns plain JSON.

Every evidence-verification response includes:

```http
Cache-Control: no-store
Vary: Authorization, Accept
```

Request bodies are capped at 64 KiB. Larger bodies return `413 internal.payload_too_large`.

Header names are case-insensitive. Examples use `Data-Purpose`, but `data-purpose` is equivalent. Values must be absolute IRIs. When an offering declares `policy.purpose`, the submitted purpose must match one of those IRIs. When present, `Data-Purpose` participates in the HMAC binding material and appears in signed receipts as `purpose_declared`.

## Request Body

Every request sends submitted claims for the selected offering:

```json
{
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

The offering's configured verification binding controls required fields, normalization, candidate lookup, matching, ambiguity handling, diagnostics, signed output, and authorization for the submitted-claim check. An offering does not make the caller's policy or eligibility decision.

`claims` contains the facts submitted by the caller. These are compared with registry data. Responses do not echo the submitted claims.

Do not use evidence verification as a generic script runner. For v1, checks are deterministic `normalized_exact` comparisons over configured registry fields. Domain-specific predicates should be represented as explicit fields, materialized views, or adapter-owned facts, then exposed through an evidence offering. That keeps audit, repeatability, and authorization reviewable.

## Targeted Verification

Use `subject.id` when the caller already knows the target registry id and wants to verify facts against that specific record:

```json
{
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

Targeted calls are more sensitive because they can be used for confirmation attacks against known ids. They require offering opt-in and the caller must have the targeted evidence-verification permission.

## Evidence

Use `evidence` only when the caller already holds an external document or artifact that produced the submitted claims. Evidence describes where the submitted facts came from. It is not the registry record being verified.

`evidence` is an array so callers can describe multi-document cases without changing the request shape later.

```json
{
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

Evidence is not treated as independently validated document authenticity unless a future offering explicitly verifies evidence-specific fields against an authoritative source. In v1, evidence is reflected only through `evidence_hash`.

## Plain JSON Response

HTTP `200` means Registry Relay completed the verification comparison. Malformed requests, missing claims, hidden offerings, unauthorized offerings, and missing purpose headers return Problem Details instead.

Match example:

```json
{
  "verification_id": "01J5K8M0000000000000000ABC",
  "decision": "match",
  "dataset_id": "civil_registry",
  "entity": "birth_record",
  "evidence_offering": "https://data.example.gov/evidence-offerings/birth-record-facts",
  "evidence_type": "https://data.example.gov/evidence-types/birth-record-facts",
  "issuing_authority": {
    "id": "civil_registry_authority",
    "name": "Civil Registry Authority",
    "country": "FR"
  },
  "checked_at": "2026-05-17T10:30:00Z",
  "ingest_version": "01J5K8M0000000000000000000",
  "claim_hash": "hmac-sha256:4a1f9c2b8d7e0f..."
}
```

Mismatch and ambiguous responses have the same shape with `decision: "mismatch"` or `decision: "ambiguous"`.

When evidence is supplied, the response also includes `evidence_hash`:

```json
{
  "verification_id": "01J5K8M0000000000000000ABF",
  "decision": "match",
  "dataset_id": "civil_registry",
  "entity": "birth_record",
  "evidence_offering": "https://data.example.gov/evidence-offerings/birth-document-facts",
  "evidence_type": "https://data.example.gov/evidence-types/birth-certificate",
  "checked_at": "2026-05-17T10:30:00Z",
  "ingest_version": "01J5K8M0000000000000000000",
  "claim_hash": "hmac-sha256:4a1f9c2b8d7e0f...",
  "evidence_hash": "hmac-sha256:9f14a0d2bc331e..."
}
```

There is no separate `verified` boolean. `decision` is the caller state machine.

`ingest_version` may be `null` when the entity has no ready ingest version. If the resource is configured but not ready, Registry Relay returns `503 schema.resource_unavailable`.

## Decisions

Initial successful decisions:

| Decision | Meaning |
| --- | --- |
| `match` | Exactly one candidate registry record matched the submitted claims under the offering's binding. |
| `mismatch` | No candidate registry record matched, or the targeted record did not match. |
| `ambiguous` | More than one candidate registry record matched, so Registry Relay cannot produce a single-record attestation. |

`ambiguous` uses `200` because it is a completed domain result, not an HTTP redirect.

Decision values are append-only. Generated clients should tolerate new string values in later versions.

Treat `ambiguous` as sensitive: it can disclose that submitted facts collide with more than one hidden record. Author high-sensitivity offerings with bounded candidate lookup fields and keep field diagnostics disabled.

## Claim And Evidence Hashes

`claim_hash` binds the verification result to the submitted input without repeating private data. It is an HMAC, not a plain SHA-256 digest:

```text
hmac-sha256:<hex>
```

The HMAC material includes:

- `verification_id`
- `claim_salt`
- `binding_key_id`
- `dataset_id`
- `entity`
- evidence offering IRI
- `Data-Purpose`, when present
- optional `subject.id`
- normalized claim values
- evidence items, when present

Registry Relay derives an offering-scoped HMAC subkey from `claim_verification.binding_key_env`, then canonicalizes the HMAC material with deterministic JSON key ordering before signing it with HMAC-SHA-256. The per-event `claim_salt` prevents a repeated submission from producing a reusable cross-event claim hash.

`evidence_hash` is returned only when `evidence` is supplied. It is computed with the same HMAC key family and binds the evidence array to the verification event.

The HMAC key is loaded from `claim_verification.binding_key_env`. The environment value is encoded as:

```text
hex:<64-or-more-lowercase-hex-chars>
```

The decoded key must be at least 32 bytes and must remain stable across process restarts. Generate one with:

```sh
printf 'hex:%s\n' "$(openssl rand -hex 32)"
```

Treat `claim_hash` and `evidence_hash` as sensitive correlation identifiers in audit retention policies.

## Signed JWT Receipts

When the caller sends `Accept: application/vnd.registry-relay.evidence-verification+jwt` and receipt signing is enabled, Registry Relay returns a compact JWS. Enable this by turning on provenance and adding `application/vnd.registry-relay.evidence-verification+jwt` to `provenance.accepted_media_types`; strict receipt requests return `406` when that profile is not enabled.

```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImV2aWRlbmNlLXZlcmlmaWNhdGlvbi1yZWNlaXB0K2p3dCIsImtpZCI6ImRpZDp3ZWI6ZGF0YS5leGFtcGxlLmdvdiNrZXktMSJ9...
```

The `Content-Type` is:

```text
application/vnd.registry-relay.evidence-verification+jwt
```

This is a server-to-server signed JWT receipt for the evidence verification. It is not an official source credential, is not a holder-presentable Verifiable Credential, and does not use `application/vc+jwt`. A future holder-presentable profile can be added separately without changing this v1 receipt.

Decoded payload shape:

```json
{
  "iss": "did:web:data.example.gov",
  "sub": "did:web:data.example.gov",
  "aud": "client:intake-service",
  "iat": 1779013800,
  "nbf": 1779013795,
  "exp": 1779014100,
  "jti": "urn:registry-relay:evidence-verification:01J5K8M0000000000000000ABC",
  "receipt_type": "relay-verification-receipt",
  "verification_id": "01J5K8M0000000000000000ABC",
  "decision": "match",
  "requirement": "https://data.example.gov/requirements/prove-birth-facts",
  "evidence_offering": "https://data.example.gov/evidence-offerings/birth-record-facts",
  "evidence_type": "https://data.example.gov/evidence-types/birth-record-facts",
  "issuing_authority": {
    "id": "civil_registry_authority",
    "name": "Civil Registry Authority",
    "country": "FR"
  },
  "jurisdiction": { "country": "FR" },
  "level_of_assurance": "substantial",
  "dataset": "civil_registry",
  "entity": "birth_record",
  "purpose_declared": "https://data.example.gov/purposes/service-intake-check",
  "checked_at": "2026-05-17T10:30:00Z",
  "claim_salt": "0123456789abcdef0123456789abcdef",
  "claim_hash": "hmac-sha256:4a1f9c2b8d7e0f...",
  "evidence_hash": "hmac-sha256:9f14a0d2bc331e...",
  "disclaimer": "Registry Relay evidence-verification receipts attest only to a registry comparison event. They are not official source credentials and do not decide eligibility."
}
```

Receipts include HMAC values and verification metadata, not raw claims, raw evidence, official source documents, or service eligibility decisions.

JOSE header example:

```json
{
  "alg": "EdDSA",
  "typ": "evidence-verification-receipt+jwt",
  "kid": "did:web:data.example.gov#key-1"
}
```

Verifiers should check `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, `kid`, and `alg`. `alg: none` is never valid. EdDSA with Ed25519 is supported in v1.

When resolving `did:web` issuer material, verifiers should use HTTPS, bounded timeouts, and cache DID Documents for at least the longest signed-receipt validity window. Do not resolve private or loopback network targets.

## Authorization

Evidence verification uses a scope distinct from metadata, rows, and aggregates:

```text
evidence_verification
```

Example entity access config:

```yaml
access:
  metadata_scope: civil_registry:metadata
  read_scope: civil_registry:rows
  evidence_verification_scope: civil_registry:evidence_verification
  aggregate_scope: civil_registry:aggregate
```

Runtime checks happen in this order:

1. Authenticate the caller.
2. Find the configured offering and bound entity without revealing hidden or unauthorized offerings.
3. Check the entity-level `evidence_verification_scope`.
4. Check the offering binding's allowlist against the caller.
5. If `subject.id` is present, check the targeted-verification permission.
6. Evaluate the binding only after authorization passes.

This order avoids dataset, entity, and offering enumeration.

## Configuration

Top-level secret configuration:

```yaml
claim_verification:
  binding_key_id: civil-registry-v1
  binding_key_env: CLAIM_VERIFICATION_BINDING_KEY
```

Entity-level binding example:

```yaml
claim_verification:
  rulesets:
    birth-facts-match-v1:
      mode: normalized_exact
      required_claims:
        - given_name
        - family_name
        - date_of_birth
        - place_of_birth
      candidate_lookup:
        - date_of_birth
        - family_name
      match_fields:
        given_name: given_name
        family_name: family_name
        date_of_birth: date_of_birth
        place_of_birth: place_of_birth
      allow_subject_id_targeting: false
      diagnostics: false
      expose_ambiguous: false
      scope: civil_registry:evidence_verification
```

The portable metadata manifest declares each public evidence offering and references the binding by name:

```yaml
evidence_offerings:
  - id: birth_record_facts
    iri: https://data.example.gov/evidence-offerings/birth-record-facts
    title: Birth record facts
    evidence_type: birth_record_facts
    entity: birth_record
    lookup_keys: [family_name, date_of_birth]
    access:
      kind: registry-relay-verification
      conforms_to: registry_relay:evidence-verification-v1
      ruleset: birth-facts-match-v1
```

V1 supports `normalized_exact` only. Unsupported match modes are rejected during config validation.

Diagnostics are disabled in v1. The endpoint does not return corrected registry values, hidden candidate ids, or field-level mismatch reasons.

## Privacy And Audit

Default responses avoid:

- raw registry row data
- corrected canonical values
- full submitted claim echo
- hidden match candidates
- detailed mismatch reasons

The raw request body, raw claims, and raw evidence should not appear in application logs, traces, OpenTelemetry attributes, metrics labels, panic messages, or Problem Details `instance` URIs.

Audit records may include `verification_id`, `claim_hash`, `evidence_hash`, offering id, `decision`, and `purpose`, but not raw claims or raw evidence.

## Errors

Errors use the existing RFC 9457 Problem Details envelope and stable `code` field.

| Condition | HTTP status | Code |
| --- | --- | --- |
| Missing credential | `401` | `auth.missing_credential` |
| Invalid credential | `401` | `auth.invalid_credential` |
| Missing `evidence_verification` scope | `404` or `403` | Hidden or binding-specific denial |
| Missing purpose header | `400` | `auth.purpose_required` |
| Purpose is not an absolute IRI | `400` | `evidence_verification.purpose_invalid` |
| Purpose is outside the offering allowlist | `403` | `evidence_verification.purpose_not_allowed` |
| Request body too large | `413` | `internal.payload_too_large` |
| Resource unavailable | `503` | `schema.resource_unavailable` |
| Malformed request body | `400` | `evidence_verification.invalid_request` |
| Required claim missing or invalid | `400` | `evidence_verification.insufficient_claims` |
| Offering not visible, not allowed, or not configured | `404` | `offering.not_found` |

## Current Boundaries

Evidence verification checks submitted claims against registry facts and can produce a verification receipt or attestation. It does not issue a birth certificate or other official source credential, and it does not decide whether the caller should grant a benefit, service, or entitlement.

Recommended API split:

```http
POST /evidence-offerings/{offering_id}/verifications
POST /datasets/{dataset_id}/{entity}/certificates
```

Evidence verification says whether submitted facts match registry facts for a declared offering. Any endpoint that issues an official document artifact belongs outside this evidence-verification surface and needs separate authorization, audit, and product semantics.

V1 intentionally does not include fuzzy matching, probabilistic scoring, phonetic matching, field diagnostics, manual review workflows, SD-JWT VC, or holder-presentable Verifiable Credentials.
