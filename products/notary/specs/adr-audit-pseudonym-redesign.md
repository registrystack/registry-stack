# ADR: Audit Pseudonym Redesign

> **Status: Archived (2026-05-31).** Kept as a design record. The load-bearing
> config and format details below have been reconciled to the shipped code; for
> current behavior see the code and docs/. Do not treat the broader design
> narrative as current.

## Status

Accepted for the audit pseudonym follow-up design freeze.

## Context

Registry Notary audit events need stable enough references for security review,
incident response, and lawful investigation without storing raw identity
attributes or creating cross-context correlation handles. The evidence request
subject model also introduces non-person targets, self-attestation, provider
matching, and federation pairwise subject hashes, so audit pseudonyms need an
explicit domain model before implementation changes land.

This ADR originated as a design artifact. The design has since been implemented
in shipped Rust (audit pseudonym hashing, tests, and the related API and runtime
paths), so it no longer stands apart from the code.

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
| `matching-attempt-v1` | failed evaluation attempts | Purpose-scoped correlation of failed matching attempts without retaining raw identifiers. |
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

The durable matched-reference pseudonym hashes the matched `handle` string
returned by the matching step, not a raw-identifier array. For the matched
entity being pseudonymized, the canonical object is:

```json
{
  "class": "matched-reference-v1",
  "version": 1,
  "role": "target",
  "entity_type": "person",
  "purpose_scope": "https://purpose.example.gov/social-protection/service-delivery",
  "handle": "ref-1001"
}
```

The raw-identifier-array path is the `matching-attempt-v1` class. It produces a
purpose-scoped keyed pseudonym for a failed attempt when the request contains a
target or requester identifier. The canonical input exists only in memory and
the serialized audit record contains only the HMAC result.

Canonicalization rules:

- `role` is the evidence request role being pseudonymized, for example
  `requester`, `target`, `relationship_subject`, or `source_record`.
- `entity_type` is the request entity type, for example `person`, `parcel`,
  `animal`, `business`, `license`, or a profile-defined value.
- `purpose_scope` is the normalized policy purpose used for the evaluation when
  available. Non-evaluation audit paths that cannot recover the original
  purpose use the explicit empty string as an `unspecified` scope and should be
  migrated to a concrete purpose when stored evaluation metadata carries it.
- `handle` is the stable matched-reference handle produced by the matching
  step. It is normalized by the same profile-specific matching rules that
  produced the matched reference. If a profile cannot define stable
  normalization for the handle, it must not be used as a durable pseudonym
  input.
- Raw names, dates of birth, animal ear tags, parcel ids, and national
  identifiers must never appear in serialized audit events or logs. They may
  appear only inside the in-memory HMAC input during pseudonym generation.

### Failed-Attempt Behavior

Failed single and batch evaluation attempts use `matching-attempt-v1` when the
request includes a target or requester identifier. The pseudonym is scoped by
role, entity type, and purpose, and uses a separate domain from matched
references. An entity without a usable identifier produces no pseudonym.

Routine audit records include request metadata, purpose, authentication
context, value-free outcome and error codes, and the keyed pseudonym. They do
not include raw identifiers, claim values, consultation inputs, or consultation
outputs. The pseudonym is an audit correlation handle, not subject identity and
not an input to federation or investigation handles.

### Retention, Key Rotation, And Erasure

Audit pseudonym keys are versioned and referenced by key id in protected audit
metadata. Key ids are not secrets. Rotation creates a new active key id for new
events while previous key ids remain available only until the longest retention
period for events written under those keys expires.

Retention classes:

- `matched-reference-v1`: follows the routine audit retention period for the
  deployment and purpose scope.
- `matching-attempt-v1`: follows the routine audit retention period for the
  deployment and purpose scope.
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
- Failed-attempt events remain value-free while supporting purpose-scoped
  correlation through a distinct keyed pseudonym domain.
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
