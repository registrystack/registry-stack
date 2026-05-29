# Evidence Offering Refactor Spec

Status: historical draft. The implemented Relay contract now publishes
evidence-offering metadata only and delegates claim/evidence execution to
Registry Notary. See [evidence-verification.md](evidence-verification.md) and
[api.md](api.md) for the current behavior.

This document specifies a refactor that makes Registry Relay simpler and more
standards-based by replacing the public verification story with evidence
offerings.

The intent is to keep Registry Relay small:

- publish standards-shaped metadata about datasets and evidence offerings;
- execute controlled checks or access operations for declared offerings;
- avoid becoming an Evidence Broker, Data Service Directory, policy engine, or
  eligibility decision service.

The current endpoint-oriented verification model is not considered a stable
compatibility constraint. No production users depend on it yet. Implementers
should optimize for a clean evidence-offering design, not migration comfort:
old routes, old config names, old docs, and old code paths may be removed when
they make the service harder to understand or maintain.

## Standards Anchor

The implementation must stay aligned with these standards and profiles:

- DCAT 3 and DCAT-AP/BRegDCAT-AP for catalogue, dataset, distribution, data
  service, access rights, conformance, and applicable legislation metadata.
- CPSV-AP for public service metadata and service-to-output relationships.
- CCCEV for requirement, criterion, evidence type, evidence, and information
  concept semantics.
- ODRL 2.2 for descriptive policy Offers attached to datasets or offerings.
- SHACL and JSON Schema for data shape publication and validation hints.
- OpenAPI for the operational REST contract.
- OOTS architecture concepts for the boundary between Evidence Broker, Data
  Service Directory, Semantic Repository, Evidence Provider, and Data Service.

References:

- DCAT 3: https://www.w3.org/TR/vocab-dcat-3/
- ODRL Information Model 2.2: https://www.w3.org/TR/odrl-model/
- ODRL Vocabulary and Expression 2.2: https://www.w3.org/TR/odrl-vocab/
- CPSV-AP 3.2.0: https://semiceu.github.io/CPSV-AP/releases/3.2.0/
- CCCEV releases: https://interoperable-europe.ec.europa.eu/collection/semic-support-centre/solution/core-criterion-and-core-evidence-vocabulary/releases
- OOTS Technical Design Documents hub: https://ec.europa.eu/digital-building-blocks/sites/spaces/OOTS/pages/617087010/Technical+Design+Documents
- OOTS TDD Chapter 1, Introduction and High-Level Architecture: https://ec.europa.eu/digital-building-blocks/sites/x/MIvFO
- OOTS TDD Chapter 3, Common Services: https://ec.europa.eu/digital-building-blocks/sites/x/K4vFO
- OOTS TDD Chapter 4, Evidence Exchange: https://ec.europa.eu/digital-building-blocks/sites/x/L4vFO
- OOTS TDD Chapter 5, Data Models: https://ec.europa.eu/digital-building-blocks/sites/x/LYvFO
- OOTS Common Services API hub: https://oots.pages.code.europa.eu/tdd/apidoc/
- OOTS EB `get-requirements`: https://oots.pages.code.europa.eu/tdd/apidoc/evidence-broker/latest/get-requirements/
- OOTS EB `get-evidence-types`: https://oots.pages.code.europa.eu/tdd/apidoc/evidence-broker/latest/get-evidence-types/
- OOTS DSD `find-data-services`: https://oots.pages.code.europa.eu/tdd/apidoc/data-services-directory/latest/find-data-services/
- OOTS SR `get-asset-metadata`: https://oots.pages.code.europa.eu/tdd/apidoc/semantic-repository/latest/get-asset-metadata/
- OOTS Semantic Repository content root: https://sr.oots.tech.ec.europa.eu/
- OOTS Evidence Explorer: https://oots.pages.code.europa.eu/evidence-explorer/ee-app/#/home

## Product Boundary

Registry Relay is a metadata publisher and evidence data-service gateway.

Registry Relay may publish:

- requirements;
- evidence types;
- evidence offerings;
- issuing authority descriptors;
- public service relationships;
- dataset, entity, field, schema, and policy metadata;
- controlled access or verification operations for one declared offering.

Registry Relay must not decide:

- which evidence type satisfies a procedure requirement across providers;
- which provider a requester should choose for a country or region;
- whether a caller has legal basis outside Relay's configured authorization;
- whether the data is sufficient for a benefit, permit, subsidy, or service
  decision;
- whether a dataset is globally authoritative outside the declared offering.

Those decisions belong to Atlas, an Evidence Broker, a Data Service Directory,
or an external governance process.

## Current Problem

The current public verification surface is dataset/entity/ruleset first:

```http
GET /datasets/{dataset_id}/{entity}/verify?{primary_key}=<value>
POST /datasets/{dataset_id}/{entity}/claim-verifications
GET /datasets/{dataset_id}/{entity}/claim-verification-rulesets
GET /datasets/{dataset_id}/{entity}/claim-verification-rulesets/{ruleset}
```

This exposes implementation details as the public contract:

- callers must know dataset IDs and entity names before they know what evidence
  is being requested;
- claim-verification rulesets are presented as discoverable domain concepts;
- `GET /verify` is an existence check but can be misread as official evidence
  verification;
- the response does not carry the semantic chain from requirement to evidence
  type to provider to access route;
- Atlas must infer too much from generic catalogue metadata.

## Core Decision

The public model should be evidence-offering first.

Replace the public verification story with:

```http
GET /metadata/evidence-offerings
GET /metadata/evidence-offerings/{offering_id}
POST /evidence-offerings/{offering_id}/verifications
```

The existing claim-verification engine may be reused internally for matching,
normalization, ambiguity handling, HMAC binding, no-store responses, and signed
receipts only where reuse keeps the implementation smaller and clearer. It
must no longer be the primary public discovery model, and it should be deleted
or collapsed into the evidence-offering execution path if retaining a separate
engine creates parallel concepts.

Rulesets become implementation bindings behind an evidence offering.

## Public Concepts

`Requirement`

A criterion or information requirement that a procedure or use case needs to
satisfy. It should be modelled using CCCEV-compatible semantics. JSON-LD output
should use `cccev:Requirement` or a more specific CCCEV subclass such as
`cccev:InformationRequirement` or `cccev:Criterion` only when the manifest makes
that specificity explicit.

`EvidenceType`

A reusable type of evidence that can prove one or more requirements. It should
be modelled using CCCEV-compatible semantics and linked to information concepts
or schemas where available.

`EvidenceOffering`

A provider-specific declaration that a dataset/entity/access route can provide
or verify a specific evidence type under stated policy and procedure contexts.
`EvidenceOffering` is a Registry Relay extension term. It is not a CCCEV, DCAT,
CPSV-AP, or OOTS class. If emitted in JSON-LD, it must use a configured Relay
vocabulary prefix, not a standards namespace.

`IssuingAuthority`

The public organization or authority legally responsible for the evidence. This
is provider metadata, not a global authority verdict. CCCEV does not define an
`EvidenceProvider` class; JSON-LD output should represent the organization as a
`foaf:Agent` or `org:Organization` and relate concrete evidence through
CCCEV-compatible issuer/provider predicates such as `cccev:isIssuedBy`,
`cccev:isCreatedBy`, or `cccev:isProvidedBy` where applicable.

`AccessRoute`

The concrete Relay operation that can serve or verify the offering. For v1 this
is a Registry Relay REST route. Future access kinds may point to OOTS/eDelivery,
OGC API, SP DCI, or another profile without changing the evidence model.

The issuing authority and access route must remain distinct. The issuing
authority is analogous to the OOTS DSD `sdg:Publisher`; the access route is
analogous to the OOTS DSD `sdg:AccessService`. One issuing authority may publish
multiple access routes.

## Portable Metadata Manifest

Add top-level requirement and evidence type sections to the portable metadata
manifest:

```yaml
requirements:
  - id: farmer_status_requirement
    iri: https://demo.example.gov/requirements/farmer-status
    title: Registered farmer status
    description: Applicant must be registered as a farmer.
    rdf_type: cccev:Criterion
    procedure_contexts:
      - https://demo.example.gov/procedures/agricultural-subsidy-application

evidence_types:
  - id: farmer_registration_evidence
    iri: https://demo.example.gov/evidence-types/farmer-registration
    title: Farmer registration evidence
    description: Evidence that the applicant is registered as a farmer.
    proves:
      - farmer_status_requirement
    information_concepts:
      - https://demo.example.gov/concepts/national-id
      - https://demo.example.gov/concepts/farmer-registration-date
      - https://demo.example.gov/concepts/farm-type
```

Add dataset-scoped evidence offerings:

```yaml
datasets:
  - id: farmer_registry
    title: Farmer Registry
    evidence_offerings:
      - id: farmer_registration_evidence_offering
        iri: https://demo.example.gov/evidence-offerings/farmer-registration
        title: Farmer registration evidence from the Ministry of Agriculture
        evidence_type: farmer_registration_evidence
        issuing_authority:
          id: ministry_agriculture
          iri: did:web:agriculture.demo.example.gov
          name: Ministry of Agriculture
          country: ZZ
        jurisdiction:
          country: ZZ
        level_of_assurance: substantial
        entity: farmer
        lookup_keys:
          - national_id
        procedure_contexts:
          - https://demo.example.gov/procedures/agricultural-subsidy-application
        access:
          kind: registry-relay-verification
          conforms_to: registry-relay-verification:v1
          ruleset: farmer-status-match-v1
        policy:
          purpose:
            - https://demo.example.gov/purpose/agricultural-subsidy-eligibility
```

Manifest `id` values are local Relay handles and must use the existing
lowercase identifier pattern `^[a-z][a-z0-9_]*$`. JSON-LD output must not emit
those local IDs as IRIs. It must use the explicit `iri` when configured, or mint
stable IRIs from the catalog base URL using documented path rules such as
`{base_url}/metadata/requirements/{id}`,
`{base_url}/metadata/evidence-types/{id}`, and
`{base_url}/metadata/evidence-offerings/{id}`.

The exact JSON-LD term mapping may use CCCEV terms directly where the chosen
version supports them. If a needed concept is not expressible in CCCEV, use a
documented Relay extension term under a configured vocabulary prefix and keep it
out of the standard namespace. In particular, `evidence_types[].proves` is a
Relay convenience in the manifest. Standards-shaped JSON-LD should map it
through CCCEV Evidence Type List semantics, using `cccev:hasEvidenceTypeList`
from the Requirement and `cccev:specifiesEvidenceType` from the Evidence Type
List to the Evidence Type, rather than inventing a direct standard predicate.

`procedure_contexts` is a Relay-local advisory hint, not an OOTS field.
OOTS's analog is a single `procedure-id` from the EU-level Procedures-CodeList
in the Semantic Repository. Manifest values should be IRIs or codes from that
codelist when the offering maps onto an SDG Annex II procedure, and may be free
identifiers for non-SDG or Relay-only procedures. On CPSV-AP-aware JSON-LD
output, link public services to requirements with `cpsv:holdsRequirement` where
supported by the selected profile, rather than emitting a Relay-invented
`procedureContext` predicate.

## Validation

Manifest validation must reject:

- duplicate requirement IDs;
- duplicate evidence type IDs;
- duplicate evidence offering IDs, globally or within a dataset;
- local IDs that do not match `^[a-z][a-z0-9_]*$`;
- an evidence type `proves` reference that does not point to a declared
  requirement;
- an offering `evidence_type` reference that does not point to a declared
  evidence type;
- an offering `entity` that does not exist in the same dataset;
- a `lookup_keys` field that does not exist on the referenced entity;
- an empty issuing authority ID, name, or country;
- an unsupported access kind;
- a verification access binding without a configured ruleset name;
- unresolved compact IRIs in concept, purpose, issuing authority, legislation,
  policy, profile, and LoA/conformance fields;
- offering metadata that copies runtime-only details such as source paths,
  table IDs, physical columns, API keys, backend URLs, or SQL.

Validation must preserve the current split:

- portable metadata describes meaning and public standard evidence;
- runtime config describes physical sources, scopes, filters, secrets, and
  execution behavior.

Pure manifest validation in `registry-manifest-core` can check only
metadata-internal rules: duplicate IDs, unresolved compact IRIs, missing
manifest references, entity/field references inside a dataset, and unsupported
metadata enum values. Cross-boundary validation belongs in runtime config
validation after both manifest and runtime config are loaded. That second pass
must reject offering ruleset bindings that do not exist on the referenced
entity, missing evidence-verification scopes, and scope names that are not in
the runtime scope allowlist.

## Public Metadata Output

`GET /metadata/catalog`

The catalog JSON must include:

- top-level `requirements`;
- top-level `evidence_types`;
- dataset-level `evidence_offerings`.

This output is for pragmatic clients and Atlas. It must be stable, deterministic,
and authorization-filtered by the caller's metadata scopes.

`GET /metadata/dcat/bregdcat-ap`

The JSON-LD output must include evidence-related nodes in `@graph` by default
without inventing a proprietary source-of-truth flag. Use JSON-LD `@included`
only when a concrete downstream validator or profile requires it.

The renderer should use:

- `dcat:Dataset` for datasets;
- `dcat:Distribution` and `dcat:DataService` for Relay access surfaces;
- `cpsv:PublicService` where the manifest declares related services;
- CCCEV-compatible nodes for requirements and evidence types;
- `odrl:Offer` for policy metadata;
- `dcatap:applicableLegislation` only when explicitly configured.

`dcatap:applicableLegislation` should be rendered as typed legal-resource nodes
where the selected DCAT-AP/BRegDCAT-AP profile requires that shape, not as an
untyped source-of-truth assertion.

Do not emit:

- `odrl:Agreement` unless a future accepted agreement feature exists;
- Dataspace Protocol contract negotiation or transfer process claims;
- OOTS Evidence Broker or Data Service Directory claims;
- a Relay-specific authority or source-of-truth predicate.

All catalog, BRegDCAT-AP, and dedicated evidence-offering renderers must apply
the same offering visibility filter. A caller that cannot see an offering
through `GET /metadata/evidence-offerings` must not be able to enumerate it
through `/metadata/catalog` or `/metadata/dcat/bregdcat-ap`.

`GET /metadata/evidence-offerings`

Returns a filtered list of offerings visible to the caller. Each item must
include enough metadata for Atlas or another client to display:

- offering ID and title;
- requirement IDs;
- evidence type ID;
- issuing authority;
- dataset ID and entity;
- procedure contexts;
- `verification_request_schema_url`, a URL to the existing schema-document
  convention such as `/metadata/schema/{dataset_id}/{entity}/schema.json`, not
  an inline schema blob;
- policy and purpose hints;
- access kind;
- links to related metadata documents.

This endpoint may accept query-string filters such as `procedure_context`,
`evidence_type`, and `country`. The filters intentionally resemble OOTS
Evidence Broker and Data Service Directory discovery concepts so an OOTS-aware
Atlas can reason about Relay offerings using familiar terms. Registry Relay is
still not an EB or DSD: it lists only offerings published by the current Relay
instance under the caller's metadata scope, does not federate across providers,
and does not implement the ebRS/RegRep transport. Consumers must not treat this
endpoint as an OOTS Common Service.

The endpoint returns the full filtered set without pagination, matching the
existing `/metadata/*` list endpoints. If offering counts grow substantially,
add cursor-based pagination matching the entity collection pattern.

Authorization-filtered metadata responses must include:

```http
Cache-Control: private
Vary: Authorization
```

The same cache-control retrofit should be considered for the existing
authorization-filtered `/metadata/*` routes, but that broader cleanup is not a
blocker for adding offerings.

`GET /metadata/evidence-offerings/{offering_id}`

Returns one offering visible to the caller. Unknown, hidden, or unauthorized
offerings must return:

```http
HTTP/1.1 404 Not Found
Content-Type: application/problem+json
```

The Problem Details body must use code `offering.not_found`. The `detail`
string must not vary between unknown, hidden, and unauthorized offerings.

Route naming is intentionally split: `/metadata/*` routes are discovery and
metadata publication; `/evidence-offerings/{id}/verifications` is an execution
route that creates a verification event.

## Verification Endpoint

Add:

```http
POST /evidence-offerings/{offering_id}/verifications
```

This endpoint creates a verification event for one declared evidence offering.
It answers:

```text
Do the submitted claims or subject identifiers satisfy this evidence offering's
configured verification binding?
```

It does not answer:

```text
Is the applicant eligible for the program?
Which provider should I choose?
Is this evidence accepted by another jurisdiction?
```

### Request

The body should be based on the existing claim-verification request shape, minus
public ruleset selection:

```json
{
  "subject": {
    "id": "farmer-123"
  },
  "claims": {
    "national_id": "DEMO-123",
    "given_name": "Camille",
    "family_name": "Durand"
  },
  "evidence": [{
    "type": "application-form",
    "issued_by": "Benefits Portal"
  }]
}
```

The offering chooses the internal ruleset. The caller must not select arbitrary
rulesets through this endpoint.

### Response

Plain JSON response:

The endpoint returns `200 OK`. The `verification_id` is an opaque correlation
handle for audit and receipt matching. Relay does not provide a
`GET /verifications/{id}` retrieval endpoint.

```json
{
  "verification_id": "01J5K8M0000000000000000ABC",
  "decision": "match",
  "checked_at": "2026-05-21T10:30:00Z",
  "requirement": "https://demo.example.gov/requirements/farmer-status",
  "evidence_type": "https://demo.example.gov/evidence-types/farmer-registration",
  "evidence_offering": "https://demo.example.gov/evidence-offerings/farmer-registration",
  "issuing_authority": {
    "id": "ministry_agriculture",
    "iri": "did:web:agriculture.demo.example.gov",
    "name": "Ministry of Agriculture",
    "country": "ZZ"
  },
  "jurisdiction": {
    "country": "ZZ"
  },
  "level_of_assurance": "substantial",
  "dataset_id": "farmer_registry",
  "entity": "farmer",
  "claim_hash": "hmac-sha256:4a1f9c2b8d7e0f...",
  "ingest_version": "01J5K8M0000000000000000000"
}
```

Decisions remain append-only:

| Decision | Meaning |
| --- | --- |
| `match` | Exactly one candidate registry record matched under the offering binding. |
| `mismatch` | No candidate registry record matched, or the targeted record did not match. |
| `ambiguous` | More than one candidate matched and the offering permits disclosure. |

Ambiguity disclosure is suppressed by default: multiple matches return
`mismatch` unless the offering explicitly enables `ambiguous`. Enabling
ambiguity disclosure is a governance decision requiring privacy review, not a
routine developer toggle.

The endpoint must include:

```http
Cache-Control: no-store
Vary: Authorization, Accept
```

The request body limit remains 64 KiB unless a documented operational reason
requires a smaller limit.

Repeat POSTs create independent verification events with distinct
`verification_id` and signed receipt identifiers. Callers that need retry-safety
must deduplicate outside Relay unless a future version specifies
`Idempotency-Key` semantics.

Validation and error responses must not include raw claim values. Error messages
may reference field names and error types only.

### Signed Receipts

Signed receipts are optional, disabled by default, and enabled per offering. If
retained, the media type must clearly identify the receipt as a Relay
verification receipt, not an official source credential:

```http
application/vnd.registry-relay.evidence-verification+jwt
```

Callers request the signed receipt from the same POST endpoint with:

```http
Accept: application/vnd.registry-relay.evidence-verification+jwt
```

If the caller strictly requests that media type and receipt signing is not
enabled for the offering, return `406 Not Acceptable`. If signing is enabled but
the signer is temporarily unavailable, return `503 Service Unavailable`. If the
caller did not strictly request the JWT media type, fall back to the plain JSON
response.

The signed payload must include:

- `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, and `jti`;
- `receipt_type` with value `relay-verification-receipt`;
- `verification_id`;
- `decision`;
- `requirement`;
- `evidence_type`;
- `evidence_offering`;
- `issuing_authority`;
- `jurisdiction`, with ISO 3166-1 alpha-2 `country` and optional
  `admin_unit_level_1` when declared;
- `level_of_assurance`, when declared;
- `dataset`;
- `entity`;
- `purpose_declared`, when present;
- `checked_at`;
- `claim_hash`;
- `evidence_hash`, when evidence is supplied;
- `disclaimer` with value "This token records that a verification check was
  executed. It does not attest that the subject holds any status or right."

The receipt `sub` must not be the citizen subject identifier. Use Relay's
service identity or an opaque non-reversible per-verification token. The `aud`
claim must be bound to the original caller's client ID, and receipts must not be
forwarded to parties not listed in `aud`.

The receipt does not assert ODRL duty discharge. ODRL fulfilment semantics are
out of scope for v1. Future versions may issue a receipt as a JAdES-signed
eSeal under eIDAS Regulation (EU) 910/2014; v1 uses a plain JWT. This receipt
is not an OOTS Evidence Response, which is exchanged through OOTS evidence
exchange channels rather than this Relay endpoint.

Relay decisions (`match`, `mismatch`, `ambiguous`) describe the matching outcome
inside the offering's binding. They do not map onto OOTS Evidence Error or DSD
error codelists. A future OOTS bridge would translate Relay decisions and
operational failures into the appropriate OOTS exception model; this contract
intentionally does not.

Replay prevention is the relying party's responsibility in v1. Signed receipts
must use a short expiration window, recommended at 5 minutes.

Do not use `application/vc+jwt` for this receipt unless the project explicitly
adds a holder-presentable Verifiable Credential issuance profile with separate
semantics and tests.

## Endpoint Removal

Because there are no production users, the implementation must prefer removal
over compatibility shims. Treat the refactor as a breaking cleanup, not a
deprecation exercise.

Remove from the public docs, OpenAPI, Bruno demo collection, and default demo:

```http
GET /datasets/{dataset_id}/{entity}/verify
GET /datasets/{dataset_id}/{entity}/claim-verification-rulesets
GET /datasets/{dataset_id}/{entity}/claim-verification-rulesets/{ruleset}
```

Remove by default:

```http
POST /datasets/{dataset_id}/{entity}/claim-verifications
```

Keeping this route requires a concrete internal caller or test need documented
in the implementation PR. If kept, it must be behind an internal feature flag or
explicit internal route namespace and must not appear in public OpenAPI, README,
demo docs, Bruno examples, or Atlas-facing examples.

Replace the old `verify_scope` and `claim_verification_scope` names in demos,
docs, and public examples with `evidence_verification_scope` or the final
offering-scope spelling chosen during implementation. Temporary aliases for old
names may be used only inside the migration PR to convert fixtures and tests;
they must not survive the Definition of Done and must not be documented as
supported external configuration.

Removed routes should return `404 Not Found`. Do not add `Sunset`,
`Deprecation`, redirect, or compatibility response shims.

## Authorization And Privacy

Authorization is offering-scoped:

- metadata visibility follows existing metadata-scope filtering;
- verification execution requires the offering's configured verification scope;
- verification execution is rate-limited per caller and offering, with
  configurable burst and sustained limits;
- callers cannot enumerate hidden offerings or hidden verification bindings;
- unknown, hidden, and unauthorized offering IDs return `404 Not Found` with
  Problem Details code `offering.not_found` and an invariant `detail` string
  after authentication.

Privacy rules from claim verification still apply:

- do not log raw claims;
- do not log raw evidence;
- do not echo full submitted claims in responses;
- bind request material into HMAC hashes;
- treat claim and evidence hashes as sensitive correlation identifiers;
- require `Data-Purpose` when the offering or entity requires purpose tracking;
- include `Data-Purpose` in the hash and signed receipt when present.

`Data-Purpose` values must be IRIs. When purpose tracking is mandatory, the
offering config must declare an allowlist of acceptable purpose IRIs.
Submissions outside that list are rejected with a documented Problem Details
code.

HMAC keys must be scoped at least per offering. Prefer per-caller-per-offering
keys so the same submitted facts do not produce the same hash for different
callers. Short-value fields such as national identifiers must be bound with a
per-request salt included in the hash material and returned in the response.
Operators must document key rotation cadence and key-retirement behavior.

Claim and evidence hashes must not be emitted to structured logs, distributed
traces, or error outputs unless that store is access-controlled to the same
authorization level as the verification endpoint. Hashes must not be forwarded
to third-party observability vendors without explicit data processing
agreements.

Audit logs for verification events must capture caller identity, offering ID,
timestamp, decision, purpose, and operational status without raw claims or raw
evidence. The audit stream must be append-only and tamper-evident for
PII-adjacent verification events.

## Demo Requirements

The demo must include at least three evidence-offering scenarios.

### Farmer Subsidy Happy Path

- Requirement: registered farmer status.
- Evidence type: farmer registration evidence.
- Provider: Ministry of Agriculture.
- Dataset/entity: `farmer_registry.farmer`.
- Lookup key: `national_id`.
- Procedure context: agricultural subsidy application.
- Expected result: one complete offering and one successful verification path.

Demo national IDs must use a prefix or structure that is formally invalid in
all EU Member State national identifier formats and must never be derived from
or resemble real identifiers. The demo should keep the `DEMO-` style prefix or
an equivalent synthetic-only structure.

### Disability Benefit Federated Or Ambiguous Path

- Requirement: disability status.
- Evidence type: disability registration evidence.
- Provider: national or regional disability authority.
- Dataset/entity: `disability_registry` entity.
- Expected result: offering metadata can express provider selection or missing
  selection attributes such as region.

### False Positive Dataset

- A dataset such as social registry or education registry contains a field like
  `disability_status`.
- It does not declare an evidence offering for disability registration.
- Atlas and Relay metadata must not classify it as an evidence provider for
  disability status.

## Atlas Contract

Atlas should consume Relay metadata as published facts, not as final
eligibility decisions.

The intended chain is:

```text
Need -> Requirement -> Evidence Type -> Evidence Offering -> Issuing Authority -> Access Route
```

Relay must publish enough metadata for Atlas to classify routes as:

- complete;
- missing issuing authority;
- missing access route;
- missing policy;
- ambiguous provider or issuing-authority selection;
- data-bearing but not evidence-offering.

Relay must not publish Atlas classifications back into its own metadata.

## Implementation Plan

1. Add manifest structs and deserializers for requirements, evidence types,
   issuing authorities, evidence offerings, jurisdiction, level of assurance,
   and offering access bindings in `registry-manifest-core`. Do this before
   adding the new YAML fields anywhere, because the manifest structs use
   `#[serde(deny_unknown_fields)]`.
2. Add compiled metadata structs and deterministic ordering. Extend
   `CompiledMetadata::filter()` or add a sibling so filtered metadata removes
   offerings whose backing entity is hidden before deciding whether a dataset is
   visible.
3. Add pure manifest validation in `registry-manifest-core`: duplicate IDs,
   local ID shape, manifest cross references, missing entity and lookup-field
   references inside the dataset, compact IRI expansion, access-kind enum
   validation, and runtime/metadata separation.
4. Add cross-boundary runtime validation after both runtime config and metadata
   manifest are loaded: referenced rulesets exist, offering execution scopes are
   configured, purpose allowlists are valid, rate-limit config is valid, and
   the runtime scope allowlist accepts `evidence_verification` or the chosen
   offering-scope spelling.
5. Regenerate and migrate all demo `*.metadata.yaml` files in the same change
   that enables the new YAML fields. Run `cargo test --test demo_configs_load`
   before merging any PR that touches demo manifests.
6. Require the split-manifest path for evidence offerings in v1. Inline runtime
   metadata synthesized by `manifest_from_runtime` does not create offerings.
7. Render requirements, evidence types, and offerings in `/metadata/catalog`.
8. Render conservative JSON-LD evidence nodes in BRegDCAT-AP output, preferably
   in `@graph`, with CCCEV/CPSV/ODRL/DCAT terms only where those terms are
   valid.
9. Add metadata endpoints for evidence offerings, including cache headers,
   filtering, `offering.not_found` Problem Details, and schema URL output.
10. Add `POST /evidence-offerings/{offering_id}/verifications` and route it
    through the existing claim-verification execution engine where appropriate.
11. Add `EVIDENCE_VERIFICATION_RECEIPT_MEDIA_TYPE` and a sibling signing path
    in the receipt/provenance layer if signed receipts remain in scope. Extend
    or copy the existing claim-verification receipt tests for the new payload
    and media type.
12. Update the hand-written OpenAPI generator: add the new evidence-offering
    metadata and verification paths, remove the legacy verify and ruleset
    discovery paths, and update operation IDs and components.
13. Audit and rewrite the Bruno collection. Direct verification calls should
    target the new offering endpoint. Scope-boundary tests should remain but
    be audited for the new scope spelling.
14. Rewrite the old endpoint tests as evidence-offering tests instead of
    deleting coverage. At minimum, update route tests, signed receipt tests,
    and third-party verification/receipt tests so the new endpoint has
    equivalent coverage.
15. Remove or hide low-level verification and ruleset discovery endpoints from
    public docs and demo flows.
16. Update demo manifests with farmer, disability, and false-positive
    scenarios.
17. Update golden fixtures, README, API docs, configuration docs, ops docs, and
    development docs.

## Definition Of Done

The refactor is done only when all of the following are true.

### Metadata Model

- Portable metadata manifests parse `requirements`, `evidence_types`, and
  dataset-level `evidence_offerings`.
- The model uses standards-compatible names and IRIs where available.
- Any Relay extension terms are namespaced, documented, and not emitted as
  CCCEV, CPSV, DCAT, ODRL, or OOTS terms.
- Local manifest IDs match `^[a-z][a-z0-9_]*$`, and JSON-LD output emits
  explicit or minted IRIs rather than local handles.
- Evidence offerings require split portable metadata manifests in v1.
- Runtime-only fields cannot appear in the portable metadata manifest.
- Unused legacy verification structs, config fields, route handlers, and docs
  are removed instead of retained for hypothetical compatibility.

### Validation

- Invalid cross references are rejected with deterministic validation errors.
- Duplicate IDs are rejected.
- Missing entities, missing lookup fields, missing rulesets, and unsupported
  access kinds are rejected.
- Compact IRIs are expanded or rejected consistently with the existing metadata
  validation behavior.
- Cross-boundary runtime validation rejects missing offering rulesets, invalid
  evidence-verification scopes, invalid purpose allowlists, and invalid
  rate-limit settings.
- Demo manifests validate through the normal config and metadata loaders.

### Metadata Output

- `/metadata/catalog` includes filtered requirements, evidence types, and
  evidence offerings.
- `/metadata/dcat/bregdcat-ap` emits standards-shaped JSON-LD without claiming
  Evidence Broker, Data Service Directory, ODRL Agreement, DSP contract, or
  source-of-truth semantics.
- `/metadata/evidence-offerings` and
  `/metadata/evidence-offerings/{offering_id}` exist, are authorization-filtered,
  and do not leak hidden offering existence.
- Authorization-filtered evidence-offering metadata responses include
  `Cache-Control: private` and `Vary: Authorization`.
- Catalog and BRegDCAT-AP renderers apply the same offering visibility filter as
  the dedicated evidence-offering endpoints.
- Unknown, hidden, and unauthorized offering detail responses return
  indistinguishable `404 application/problem+json` responses with code
  `offering.not_found`.
- Golden fixtures assert the new output shape.

### Verification Output

- `POST /evidence-offerings/{offering_id}/verifications` executes the offering's
  configured binding without caller-selected rulesets.
- The response returns `200 OK` and includes requirement, evidence type,
  offering, issuing authority, jurisdiction, level of assurance when declared,
  dataset, entity, decision, hashes, checked time, and ingest version.
- Repeat POSTs are independent verification events unless a future
  idempotency-key feature is specified.
- Ambiguity disclosure is suppressed by default and requires explicit
  governance approval to enable.
- Raw claims and raw evidence are not returned or logged.
- Validation errors mention field names and error types only, not raw claim
  values.
- Responses include `Cache-Control: no-store` and `Vary: Authorization, Accept`.
- Signed receipts, if enabled, use the evidence-verification receipt media type
  and include the evidence semantic chain, caller-bound audience, non-citizen
  subject, short expiry, receipt type, disclaimer, jurisdiction, and LoA where
  declared.
- Rate limiting, audit logging, HMAC key scoping, key rotation, per-request
  salt, and hash logging boundaries are implemented according to this spec.

### Removed Or Hidden Surfaces

- `GET /datasets/{dataset_id}/{entity}/verify` is removed from public OpenAPI,
  README, demo docs, and Bruno collections.
- Claim-verification ruleset discovery endpoints are removed from public
  OpenAPI, README, demo docs, and Bruno collections.
- Dataset/entity claim verification is removed unless the implementation PR
  documents a concrete internal caller or test need. If retained, it is internal
  only and absent from public OpenAPI, README, demo docs, Bruno collections, and
  Atlas-facing examples.
- Tests are updated so old endpoint coverage does not preserve the old product
  model by accident.
- Removed routes return 404 without soft-deprecation or compatibility shims.

### Standards Compliance

- DCAT/BRegDCAT-AP output remains valid for catalog, dataset, distribution, data
  service, policy, applicable legislation, and shape graph publication.
- CPSV public service output remains a public service relation, not provider
  selection logic.
- CCCEV concepts are used only for requirement/evidence semantics.
- Evidence offering is emitted only as a Relay extension term, never as a
  CCCEV, CPSV-AP, DCAT, ODRL, or OOTS class.
- Requirement-to-evidence-type output uses CCCEV Evidence Type List semantics or
  an explicitly documented Relay extension, not an invented direct standard
  predicate.
- ODRL output remains an Offer unless an accepted agreement is explicitly
  modelled in a separate feature.
- OOTS terms are used only as architecture guidance unless the implementation
  actually conforms to the relevant OOTS interface.
- SHACL and JSON Schema outputs remain generated from entity metadata and do
  not encode runtime authorization behavior.

### Demo Acceptance

- The farmer subsidy demo resolves to a complete evidence offering and a
  successful verification path.
- The disability demo can show either multiple possible providers or an explicit
  missing selection attribute.
- The false-positive dataset contains relevant-looking fields but is not emitted
  as an evidence offering.
- Atlas can render the chain from need to requirement to evidence type to
  issuing authority to Relay route using only Relay metadata and its own
  discovery logic.

### Verification Commands

Before completion, run the relevant project checks:

```sh
cargo fmt --check
cargo test -p registry-manifest-core
cargo test --test demo_configs_load
cargo test --test catalog_entity
cargo test --test config_metadata_bindings
cargo test
```

If the implementation changes OpenAPI, docs examples, or generated fixtures,
also run the project-specific generation or validation commands documented in
`docs/development.md` and update the committed outputs.

If an external SEMIC or SHACL validator is available in the environment, run the
documented DCAT/BRegDCAT-AP validation command. If it is not available, record
the skipped validator and reason in the final implementation report.

## Non-Goals

- No Evidence Broker implementation.
- No Data Service Directory implementation.
- No eDelivery implementation.
- No OOTS lifecycle management interface.
- No ODRL policy enforcement engine.
- No DSP contract negotiation or transfer process.
- No eligibility or benefit-decision engine.
- No fuzzy identity matching in v1.
- No AI-based field or provider inference inside Registry Relay.
