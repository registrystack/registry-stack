# ADR: Audit Pseudonym Redesign

## Status

Accepted for the audit pseudonym follow-up design freeze.

## Context

Registry Notary audit events need stable enough references for security review,
incident response, and lawful investigation without storing raw identity
attributes or creating cross-context correlation handles. The evidence request
subject model also introduces non-person targets, self-attestation, provider
matching, and federation pairwise subject hashes, so audit pseudonyms need an
explicit domain model before implementation changes land.

This ADR defines only design artifacts. It does not change Rust code, tests, API
schemas, or runtime configuration.

## Decision

Audit pseudonyms are HMAC-SHA-256 values over Notary-owned canonical JSON inputs
using the shared `registry-platform-audit` audit reference hash primitive.
Serialized audit fields use the platform hash encoding, currently
`hmac-sha256:<digest>`. The pseudonym class and version are bound inside the
platform HMAC domain-separated input rather than exposed as raw
personal-data-bearing fields.

```text
hmac-sha256:<digest>
```

The HMAC key is an audit-only secret. It must not be reused for federation
pairwise subject hashes, cookies, source credentials, replay identifiers,
credential signing, or request signing.

### Versioned Hash Domains

Every pseudonym is bound to a versioned hash domain. Notary passes the domain id
as the `class` argument to
`AuditKeyHasher::audit_reference_hash(class, scope, canonical_input)`, and also
includes it in the canonical JSON input so offline reviewers can identify which
normalization rules were used.

| Domain id | Event use | Purpose |
| --- | --- | --- |
| `matched-reference-v1` | routine successful or policy-denied evaluations after a provider match | Link audit events for the same matched requester or target within the same purpose scope without exposing source identifiers. |
| `matching-attempt-v1` | optional no-match repeat-probe detection | Short-lived, purpose-scoped correlation of failed matching attempts when explicitly enabled by deployment policy. |
| `investigation-reference-v1` | elevated investigation or abuse-response events | Separately authorized handle for incident review, never emitted by routine evaluation paths. |

The platform hash primitive frames the HMAC input as:

```text
registry-platform:audit-reference:v1 || len(class) || class || len(scope) || scope || len(canonical_input) || canonical_input
```

Changing canonical input fields, normalization, retention behavior, or key
scope requires a new domain id. Implementations may continue reading prior
domains through their configured retention period, but new writes must use the
current domain.

### Canonical Identifier Input

The HMAC input is the UTF-8 bytes of a JSON Canonicalization Scheme object.
For each entity being pseudonymized, the canonical object is:

```json
{
  "pseudonym_version": 1,
  "hash_domain_id": "matched-reference-v1",
  "role": "target",
  "entity_type": "person",
  "purpose_scope": "https://purpose.example.gov/social-protection/service-delivery",
  "identifiers": [
    {
      "role": "target",
      "entity_type": "person",
      "scheme": "national_id",
      "issuer": "",
      "country": "",
      "value": "NID-1001",
      "purpose_scope": "https://purpose.example.gov/social-protection/service-delivery",
      "pseudonym_version": 1
    }
  ]
}
```

Canonicalization rules:

- `role` is the evidence request role being pseudonymized, for example
  `requester`, `target`, `relationship_subject`, or `source_record`.
- `entity_type` is the request entity type, for example `person`, `parcel`,
  `animal`, `business`, `license`, or a profile-defined value.
- `purpose_scope` is the normalized policy purpose used for the evaluation when
  available. Non-evaluation audit paths that cannot recover the original
  purpose use the explicit empty string as an `unspecified` scope and should be
  migrated to a concrete purpose when stored evaluation metadata carries it.
- Each identifier includes `role`, `entity_type`, `scheme`, `issuer`,
  `country`, `value`, `purpose_scope`, and `pseudonym_version`.
- Missing `issuer` and `country` are canonicalized to explicit empty strings,
  not omitted or represented as null.
- `scheme`, `issuer`, `country`, `value`, `role`, `entity_type`, and
  `purpose_scope` are normalized by the same profile-specific matching rules
  that produced the matched reference. If a profile cannot define stable
  normalization for a field, that field must not be used as a durable
  pseudonym input.
- `identifiers` are sorted lexicographically by this tuple:
  `role`, `entity_type`, `scheme`, `issuer`, `country`, `value`,
  `purpose_scope`, `pseudonym_version`.
- Duplicate identifier objects are removed after normalization and before
  sorting.
- Raw names, dates of birth, animal ear tags, parcel ids, and national
  identifiers must never appear in serialized audit events or logs. They may
  appear only inside the in-memory HMAC input during pseudonym generation.

### No-Match Behavior

Pure no-match failures do not emit a durable attribute-derived entity
pseudonym. Routine no-match audit events record request metadata, profile,
purpose, requester authentication context, match status, and redacted failure
reason only.

If a deployment needs repeat-probe detection, it must explicitly enable the
`matching-attempt-v1` domain with all of these controls:

- a dedicated matching-attempt key distinct from the routine audit key;
- retention no longer than the configured abuse-detection window;
- purpose scope included in the canonical input;
- no federation handle, matched-reference pseudonym, or investigation
  pseudonym derived from the same no-match input;
- operator documentation that the handle is for abuse detection, not subject
  identity.

If repeat-probe correlation is disabled, no no-match event contains a
long-lived pseudonym derived from target attributes.

### Retention, Key Rotation, And Erasure

Audit pseudonym keys are versioned and referenced by key id in protected audit
metadata. Key ids are not secrets. Rotation creates a new active key id for new
events while previous key ids remain available only until the longest retention
period for events written under those keys expires.

Retention classes:

- `matched-reference-v1`: follows the routine audit retention period for the
  deployment and purpose scope.
- `matching-attempt-v1`: expires at the shorter of the routine audit retention
  period or the configured abuse-detection window.
- `investigation-reference-v1`: expires under the case or legal-hold policy
  that authorized the investigation event. When no legal hold exists, it must
  not outlive routine audit retention.

Erasure is implemented by deleting or disabling the key material for affected
key ids after the required retention period, legal hold, and hash-chain
verification window end. This crypto-shreds the pseudonym value because stored
audit records keep only the HMAC output and non-secret key id. Hash-chain
checkpoints can still prove record order and tamper evidence after crypto-
shredding, but they cannot recover or relink shredded pseudonyms.

When an individual erasure request applies to audit records that must remain
for statutory integrity, operators should prefer subject-specific key scoping
only when the deployment has designed that model up front. Otherwise the system
must document the limit clearly: erasing one subject's pseudonym may require
waiting until the retention period for a shared audit key ends.

### Federation Pairwise Alignment

Federation pairwise subject hashes and audit pseudonyms are intentionally
different handles:

- federation uses federation-only pairwise secrets and federation domains;
- audit uses audit-only secrets and the audit domains in this ADR;
- federation inputs include peer audience and profile for cross-peer and
  cross-profile unlinkability;
- audit inputs include role, entity type, purpose scope, and canonical matched
  identifiers for local audit correlation;
- neither handle is accepted as input for deriving the other.

Federated evaluations may store both a federation response reference and a local
audit pseudonym in the serving Notary's audit trail, but the values must be
computed independently with separate keys and domain separators. Tests for the
implementation follow-up must prove that the same source subject produces
different, non-interchangeable values for federation and audit.

## Consequences

- Implementations get deterministic matched-reference audit correlation without
  retaining raw identifiers.
- No-match events are private by default and require an explicit short-lived
  abuse-detection configuration before any attribute-derived handle is emitted.
- Operators must manage audit pseudonym keys as retention and erasure controls,
  not only as generic application secrets.
- Federation remains aligned with the pairwise subject hash design while
  preserving separate domains, secrets, and review boundaries.

## Implementation Follow-Up

The implementation follow-up must add tests that compare serialized audit
events and logs against representative raw values, including names, dates of
birth, national identifiers, parcel ids, and animal ear tags. It must also add
focused tests for stable identifier ordering, explicit empty `issuer` and
`country`, no-match behavior, key rotation metadata, and federation/audit handle
separation.
