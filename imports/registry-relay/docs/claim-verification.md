# Claim Verification Guide

Claim verification lets an authorized caller submit facts and ask whether those facts match an authoritative registry record under a configured ruleset.

It is separate from the existing id-based verify endpoint:

```http
GET /datasets/{dataset_id}/{entity}/verify?{primary_key}=<value>
```

`GET /verify` answers "does this id exist?" Claim verification answers "do these submitted facts match the registry?" without returning the registry row.

Common uses:

- A benefits service checks birth facts before granting eligibility.
- A resident requests a birth certificate by submitting identifying facts.
- A relying party submits facts extracted from a document and asks whether the registry agrees.

## Endpoint

Create a verification event with:

```http
POST /datasets/{dataset_id}/{entity}/claim-verifications
```

The route is a `POST` because callers send structured personal data in the body. Do not put claim data in URLs, query strings, cache keys, or proxy-visible paths.

Plain JSON is the default response:

```http
POST /datasets/civil_registry/birth_record/claim-verifications HTTP/1.1
Content-Type: application/json
Accept: application/json
Authorization: Bearer <token>
Data-Purpose: benefits-eligibility
```

Signed receipts use a custom JWT media type:

```http
POST /datasets/civil_registry/birth_record/claim-verifications HTTP/1.1
Content-Type: application/json
Accept: application/vnd.registry-relay.claim-verification+jwt
Authorization: Bearer <token>
Data-Purpose: benefits-eligibility
```

If `Accept` is omitted, is `*/*`, or does not negotiate to a configured signed media type, Registry Relay returns plain JSON.

Every claim-verification response includes:

```http
Cache-Control: no-store
Vary: Authorization, Accept
```

Request bodies are capped at 64 KiB. Larger bodies return `413 internal.payload_too_large`.

Header names are case-insensitive. Examples use `Data-Purpose`, but `data-purpose` is equivalent.

## Request Body

Every request selects a ruleset and sends submitted claims:

```json
{
  "ruleset": "birth-certificate-request-v1",
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

`ruleset` names the configured verification policy. It controls required fields, normalization, candidate lookup, matching, ambiguity handling, diagnostics, signed output, and authorization.

`claims` contains the facts submitted by the caller. These are compared with registry data. Responses do not echo the submitted claims.

## Targeted Verification

Use `subject.id` when the caller already knows the target registry id and wants to verify facts against that specific record:

```json
{
  "ruleset": "birth-certificate-request-v1",
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

Targeted calls are more sensitive because they can be used for confirmation attacks against known ids. They require ruleset opt-in and the caller must have the targeted-verification permission.

## Evidence

Use `evidence` only when the caller already holds an external document or artifact that produced the submitted claims. Evidence describes where the submitted facts came from. It is not the registry record being verified.

```json
{
  "ruleset": "birth-certificate-document-v1",
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

If a resident is requesting a birth certificate and does not already have the certificate, omit `evidence`.

Evidence is not treated as independently certified document authenticity unless a future ruleset explicitly verifies evidence-specific fields against an authoritative source. In v1, evidence is reflected only through `evidence_hash`.

## Plain JSON Response

HTTP `200` means Registry Relay completed the verification decision. Malformed requests, missing claims, hidden rulesets, unauthorized rulesets, and missing purpose headers return Problem Details instead.

Match example:

```json
{
  "verification_id": "01J5K8M0000000000000000ABC",
  "decision": "match",
  "dataset_id": "civil_registry",
  "entity": "birth_record",
  "ruleset": "birth-certificate-request-v1",
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
  "ruleset": "birth-certificate-document-v1",
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
| `match` | Exactly one eligible registry record matched the submitted claims under the ruleset. |
| `mismatch` | No eligible registry record matched, or the targeted record did not match. |
| `ambiguous` | More than one eligible registry record matched, so no verification can be certified. |

`ambiguous` uses `200` because it is a completed domain result, not an HTTP redirect.

Decision values are append-only. Generated clients should tolerate new string values in later versions.

Rulesets default to collapsing ambiguous results into `mismatch` with:

```yaml
expose_ambiguous: false
```

This avoids disclosing that a collision exists for a sensitive set of submitted facts.

## Claim And Evidence Hashes

`claim_hash` binds the verification decision to the submitted input without repeating private data. It is an HMAC, not a plain SHA-256 digest:

```text
hmac-sha256:<hex>
```

The HMAC material includes:

- `verification_id`
- `binding_key_id`
- `dataset_id`
- `entity`
- `ruleset`
- `Data-Purpose`, when present
- optional `subject.id`
- normalized claim values
- evidence items, when present

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

When the caller sends `Accept: application/vnd.registry-relay.claim-verification+jwt` and receipt signing is enabled, Registry Relay returns a compact JWS:

```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImNsYWltLXZlcmlmaWNhdGlvbi1yZWNlaXB0K2p3dCIsImtpZCI6ImRpZDp3ZWI6ZGF0YS5leGFtcGxlLmdvdiNrZXktMSJ9...
```

The `Content-Type` is:

```text
application/vnd.registry-relay.claim-verification+jwt
```

This is a server-to-server signed JWT receipt. It is not a holder-presentable Verifiable Credential and does not use `application/vc+jwt`. A future holder-presentable profile can be added separately without changing this v1 receipt.

Decoded payload shape:

```json
{
  "iss": "did:web:data.example.gov",
  "sub": "client:benefits-service",
  "aud": "client:benefits-service",
  "iat": 1779013800,
  "nbf": 1779013795,
  "exp": 1779014100,
  "jti": "urn:registry-relay:claim-verification:01J5K8M0000000000000000ABC",
  "receipt_type": "registry-relay.claim-verification.v1",
  "verification_id": "01J5K8M0000000000000000ABC",
  "dataset": "civil_registry",
  "entity": "birth_record",
  "decision": "match",
  "ruleset": "birth-certificate-request-v1",
  "purpose_declared": "benefits-eligibility",
  "checked_at": "2026-05-17T10:30:00Z",
  "claim_hash": "hmac-sha256:4a1f9c2b8d7e0f...",
  "evidence_hash": "hmac-sha256:9f14a0d2bc331e..."
}
```

Receipts include HMAC values and decision metadata, not raw claims or raw evidence.

JOSE header example:

```json
{
  "alg": "EdDSA",
  "typ": "claim-verification-receipt+jwt",
  "kid": "did:web:data.example.gov#key-1"
}
```

Verifiers should check `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, `kid`, and `alg`. `alg: none` is never valid. EdDSA with Ed25519 is supported in v1.

## Authorization

Claim verification uses a scope distinct from id-based verify:

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
  bulk_export_scope: civil_registry:bulk_export
```

Runtime checks happen in this order:

1. Authenticate the caller.
2. Check the entity-level `claim_verification_scope`.
3. Check the requested ruleset's allowlist against the caller.
4. If `subject.id` is present, check the targeted-verification permission.
5. Evaluate the ruleset only after authorization passes.

This order avoids dataset, entity, and ruleset enumeration. Hidden, unknown, or unauthorized rulesets return `403 claim_verification.ruleset_not_allowed`.

## Configuration

Top-level secret configuration:

```yaml
claim_verification:
  binding_key_id: civil-registry-v1
  binding_key_env: CLAIM_VERIFICATION_BINDING_KEY
```

Entity-level ruleset example:

```yaml
claim_verification:
  rulesets:
    birth-certificate-request-v1:
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
      scope: civil_registry:claim_verification:birth-certificate-request-v1
```

V1 supports `normalized_exact` only. Unsupported match modes are rejected during config validation.

Diagnostics are disabled in v1. The endpoint does not return corrected registry values, hidden candidate ids, or field-level mismatch reasons.

## Ruleset Discovery

OpenAPI cannot statically describe every per-ruleset `claims` object. Use the discovery routes to fetch caller-visible rulesets and broad JSON Schemas:

```http
GET /datasets/{dataset_id}/{entity}/claim-verification-rulesets
GET /datasets/{dataset_id}/{entity}/claim-verification-rulesets/{ruleset}
```

Discovery is authorization-filtered. Responses include:

```http
Cache-Control: no-store
Vary: Authorization, Accept
```

Unknown entities, hidden rulesets, unknown rulesets, and callers without the required claim-verification scope all return:

```text
403 claim_verification.ruleset_not_allowed
```

This keeps the discovery routes from becoming an enumeration surface.

## Privacy And Audit

Default responses avoid:

- raw registry row data
- corrected canonical values
- full submitted claim echo
- hidden match candidates
- detailed mismatch reasons

The raw request body, raw claims, and raw evidence should not appear in application logs, traces, OpenTelemetry attributes, metrics labels, panic messages, or Problem Details `instance` URIs.

Audit records may include `verification_id`, `claim_hash`, `evidence_hash`, `ruleset`, `decision`, and `purpose`, but not raw claims or raw evidence.

## Errors

Errors use the existing RFC 9457 Problem Details envelope and stable `code` field.

| Condition | HTTP status | Code |
| --- | --- | --- |
| Missing credential | `401` | `auth.missing_credential` |
| Invalid credential | `401` | `auth.invalid_credential` |
| Missing `claim_verification` scope | `403` | `claim_verification.ruleset_not_allowed` |
| Missing purpose header | `400` | `auth.purpose_required` |
| Request body too large | `413` | `internal.payload_too_large` |
| Resource unavailable | `503` | `schema.resource_unavailable` |
| Malformed request body | `400` | `claim_verification.invalid_request` |
| Required claim missing or invalid | `400` | `claim_verification.insufficient_claims` |
| Ruleset not allowed, hidden, or unknown | `403` | `claim_verification.ruleset_not_allowed` |

## Current Boundaries

Claim verification verifies submitted facts. It does not issue a birth certificate or other certificate document by itself.

Recommended API split:

```http
POST /datasets/{dataset_id}/{entity}/claim-verifications
POST /datasets/{dataset_id}/{entity}/certificates
```

`claim-verifications` says whether facts match. A future `certificates` endpoint can issue a document artifact with stronger authorization and audit requirements.

V1 intentionally does not include fuzzy matching, probabilistic scoring, phonetic matching, field diagnostics, manual review workflows, SD-JWT VC, or holder-presentable Verifiable Credentials.
