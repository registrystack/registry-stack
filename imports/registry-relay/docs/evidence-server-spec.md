# Evidence Server Specification

Status: draft

This document specifies a standalone Evidence Server that computes configured
claims from registry data and renders them as evidence artifacts. It is written
as the target architecture for extracting evidence generation concerns from
Registry Relay without requiring existing registries to change their native
data systems.

The Evidence Server is not a registry, ETL platform, data warehouse, or
eligibility casework system. It is a configurable service that answers
reviewable claim questions over registry data, enforces disclosure policy, and
returns only the result shape the caller is allowed to receive.

Version 0 product shape:

```text
configure claims
  -> evaluate from registry data
  -> filter to an authorized view
  -> render evidence
  -> optionally issue an SD-JWT VC credential
```

Everything else in this document is either support for that path or an explicit
extension profile.

## Goals

- Compute claims from existing registry data without making source registries
  implement evidence-specific APIs.
- Support boolean, scalar, date, categorical, structured, and derived claims.
- Support single-subject evaluation and bounded inline batch evaluation.
- Publish the list of claims, operations, source connectors, and output formats
  enabled by configuration.
- Render claim results as canonical JSON, CCCEV-aligned evidence, SD-JWT VC, or
  future formats.
- Issue SD-JWT VC credentials from already evaluated claim results when issuer
  configuration is present.
- Enforce selective disclosure by design.
- Use source metadata to validate claim configuration, map source fields,
  preserve semantics in rendered artifacts, and detect drift.
- Allow explicit CCCEV and OOTS profiles without making either profile the core
  computation model.
- Support decentralized deployment where each registry or authority can operate
  its own Evidence Server.
- Preserve enough issuer and result metadata for later federation, without
  requiring federation execution in version 0.
- Keep DCI and Registry Data API as the preferred source integration paths,
  with extra connectors only for cases that cannot reasonably use those
  contracts.

## Non-Goals

- Do not require CRVS, farmer, tax, or other source registries to change their
  existing data model.
- Do not build a general ETL tool, replicated registry index, or unrestricted
  query engine.
- Do not expose raw registry records unless an explicit claim and disclosure
  policy allows that field-level value.
- Do not make benefit, subsidy, permit, or service eligibility decisions unless
  those decisions are explicitly configured as claims.
- Do not silently scan complete registries to implement search.
- Do not make CCCEV, SD-JWT VC, or any other output format the internal domain
  model.
- Do not recompute claims during rendering or credential issuance in version 0.
- Do not claim OOTS wire compatibility from the core REST evaluation API.
  OOTS compatibility requires an explicit adapter or profile.
- Do not replace the OOTS Evidence Broker, Data Service Directory, Semantic
  Repository, eDelivery exchange, preview journey, or record-matching layer.

## Standards Positioning

The Evidence Server core is broader than CCCEV and different from OOTS.

CCCEV is a semantic vocabulary for requirements, criteria, constraints,
information concepts, evidence types, evidence, supported values, and reference
frameworks. The Evidence Server can render CCCEV-aligned artifacts and use
CCCEV terms in discovery metadata, but CCCEV does not define this server's
REST operations, authorization model, connector contract, batching, search,
federation, audit records, selective disclosure, or credential lifecycle.

OOTS is primarily an evidence discovery and bilateral evidence exchange
architecture. Its Common Services, including the Evidence Broker, Data Service
Directory, and Semantic Repository, serve operational metadata that supports
evidence exchange. They are not a claim-computation API over citizen or
business data.

The Evidence Server can serve a local Data Service or authority that
participates in an OOTS-style exchange, but it is not by itself an OOTS
Evidence Broker, Data Service Directory, Semantic Repository, record-matching
service, eDelivery gateway, or user preview and approval journey.

References:

- OOTS Technical Design Documents:
  https://ec.europa.eu/digital-building-blocks/sites/spaces/OOTS/pages/617087010/Technical+Design+Documents
- OOTS API hub: https://oots.pages.code.europa.eu/tdd/apidoc/
- CCCEV 2.1.0: https://semiceu.github.io/CCCEV/releases/2.1.0/

## Core Concepts

`ClaimDefinition`

A configured capability that describes one claim the server can compute. A
claim definition declares its subject type, input requirements, value type,
source bindings, computation rule, supported operations, disclosure policy, and
output formats.

Examples:

- `date-of-birth`
- `farmed-land-size`
- `farmer-under-4ha`
- `tax-compliant-for-year`
- `born-in-district`

`ClaimResult`

The canonical internal result of computing one claim for one subject. A claim
result contains the computed value or predicate result, metadata about how it
was computed, source references, disclosure state, and audit identifiers. The
claim result is not tied to CCCEV, SD-JWT VC, or any other renderer. It is an
internal object and can contain fields that are never returned to callers.

`ClaimResultView`

A disclosure-filtered view of one or more internal claim results. The host
constructs a `ClaimResultView` after authorization and disclosure policy are
applied and before any renderer runs. Renderers receive only
`ClaimResultView`, not raw internal `ClaimResult` values.

`ClaimResultFragment`

A future plugin return value. Plugins are not part of version 0. A fragment
contains only the fields a trusted plugin is allowed to contribute: computed
value, value type, unit, derived-from references, selected source references,
structured diagnostics, or a stable plugin error code. The host promotes a
fragment into a full `ClaimResult` by adding subject, claim definition,
identity mapping, authorization, disclosure, evaluation id, timestamps, audit
metadata, and renderer eligibility.

`EvidenceArtifact`

A rendered artifact produced from one or more disclosure-filtered claim result
views. Evidence artifacts may be canonical JSON, CCCEV-aligned JSON-LD,
SD-JWT VC, or another configured format.

`SourceConnector`

An adapter that fetches registry data from a source system. Initial connectors
should support DCI and Registry Data API. Custom connectors are allowed, but the
preferred integration path is to adapt unusual registries into DCI or Registry
Data API outside the Evidence Server.

`Registry Data API`

A simple registry consultation API optimized for source systems to expose data
records and provenance, not for evidence services to express output artifacts.
It is the default non-DCI source contract.

`Plugin`

An optional future named and versioned computation unit implemented as a
compiled Rust component and bound to a claim definition in configuration.
Plugins are used only when extraction and CEL predicates are insufficient.
Plugins are not implemented in version 0.

`DisclosureProfile`

A policy-controlled output view over a claim result. Examples include exact
value, predicate-only, redacted value with provenance, or signed credential.

`Federated Evidence Server`

An Evidence Server that calls another Evidence Server as a source of claim
results rather than calling raw registries directly. Federation execution is an
extension profile after version 0.

`OOTSProfile`

An optional binding that describes how a claim or rendered artifact participates
in OOTS discovery or exchange. The profile maps local claim semantics to OOTS
and CCCEV concepts, but it does not make the core `/claims/*` REST API an OOTS
wire protocol. OOTS wire exchange is an extension profile after version 0.

`ReleaseAuthorization`

A profile-specific authorization state proving that an evidence artifact may be
released to a requester. OOTS-profiled flows may require preview and approval
before release. Local non-OOTS flows may use different authorization policy.

## Architecture

The Evidence Server has three core layers:

```text
source registries
  -> source connectors
  -> claim computation
  -> claim results
  -> renderers and issuers
  -> evidence artifacts
```

Source registries remain domain systems such as CRVS, farmer registries, tax
registries, social registries, or business registries. They return whatever
their supported source API returns. The Evidence Server maps those responses
into claim computation inputs only for configured claims.

Claim computation must be independent from output rendering. A farm-size claim
is computed once as a `ClaimResult`; then renderers decide whether to emit
canonical JSON, CCCEV, SD-JWT VC, or another artifact.

## Deployment Modes

### Local Authority Mode

An Evidence Server runs beside one authority or registry domain.

```text
Farmer Registry -> Farmer Evidence Server -> relying parties
Tax Registry -> Tax Evidence Server -> relying parties
CRVS -> CRVS Evidence Server -> relying parties
```

The server computes domain claims close to the source data and exposes only
configured results. This is the preferred privacy-preserving deployment for
sensitive registries.

### Aggregator Mode

An Evidence Server composes claims from other Evidence Servers.

```text
Farmer Evidence Server
Tax Evidence Server
CRVS Evidence Server
  -> Program Evidence Server
  -> program eligibility claim or evidence artifact
```

The aggregator should compose signed or otherwise authenticated claim results,
not raw registry data. For example, `eligible-for-input-subsidy` may depend on
`age-over-18`, `farmer-under-4ha`, and `tax-compliant`.

### Embedded Demo Mode

A Registry Relay demo may fake local authority, Registry Data API, or ID Mapper
behavior to exercise the protocol before those services exist independently.
The spec should not require production deployments to use Registry Relay.

## Claim Definitions

A claim definition declares what the server can compute and under which
conditions.

```yaml
id: farmed-land-size
title: Farmed land size
version: 2026-05
subject_type: person
value:
  type: number
  unit: hectare
inputs:
  - name: subject_id
    type: string
source_bindings:
  farmer:
    connector: registry_data_api
    connection: farmer_registry_api
    dataset: farmer_registry
    entity: farmer
    lookup:
      input: subject_id
      field: national_id
      op: eq
      cardinality: one
    fields:
      total_farmed_area:
        path: total_farmed_area
        type: number
        unit: hectare
        required: true
rule:
  type: extract
  field: farmer.total_farmed_area
operations:
  evaluate:
    enabled: true
  batch_evaluate:
    enabled: true
    max_subjects: 1000
disclosure:
  default: redacted
  downgrade: default
  allowed:
    - value
    - redacted
formats:
  - application/vnd.evidence-server.claim-result+json
  - application/ld+json; profile="cccev"
  - application/dc+sd-jwt
oots:
  enabled: false
```

A derived predicate can depend on another claim:

```yaml
id: farmer-under-4ha
title: Farmer with less than four hectares
version: 2026-05
subject_type: person
value:
  type: boolean
inputs:
  - name: subject_id
    type: string
depends_on:
  - farmed-land-size
rule:
  type: cel
  expression: "claims.farmed_land_size.value < 4"
  bindings:
    claims:
      type: object
      fields:
        farmed_land_size:
          claim: farmed-land-size
          type: claim_result_view
operations:
  evaluate:
    enabled: true
  batch_evaluate:
    enabled: true
    max_subjects: 1000
disclosure:
  default: predicate
  allowed:
    - predicate
    - value
formats:
  - application/vnd.evidence-server.claim-result+json
  - application/ld+json; profile="cccev"
  - application/dc+sd-jwt
credential_profiles:
  - farmer_status_sd_jwt
cccev:
  requirement_type: information_requirement
oots:
  enabled: true
  requirement: https://example.gov/requirements/small-farmer
  reference_framework: https://example.gov/frameworks/agricultural-subsidy
  evidence_type_classification: https://example.gov/evidence-classifications/farmer-status
  evidence_type_list: https://example.gov/evidence-type-lists/agriculture
  jurisdictions:
    - country_code: ZZ
  distributed_as:
    - format: application/ld+json
      conforms_to: https://semiceu.github.io/CCCEV/releases/2.1.0/
    - format: application/xml
      conforms_to: https://example.gov/oots/edm-profile
  languages:
    - en
  authentication_level_of_assurance: substantial
```

The `oots` block is optional. It should be present only when a deployment wants
to expose or render the claim through an OOTS or OOTS-like profile.

Do not equate a `ClaimDefinition` with an OOTS `EvidenceType` by default. A
claim may map to a CCCEV `InformationRequirement`, `Criterion`, or
`Constraint`. A claim may reference a CCCEV `InformationConcept` to describe the
value shape or semantic binding without being an `InformationConcept` itself. A
`ClaimResult` may render as CCCEV `Evidence` with `SupportedValue`. A rendered
`EvidenceArtifact` should be registered or advertised as an OOTS evidence type
only when governance says that artifact is legally and operationally acceptable
evidence for the target procedure.

### Identifiers And Versions

Claim ids are stable lowercase identifiers unique within one Evidence Server.
Federated claim references include an issuer URL plus claim id and version.

Version 0 uses calendar versions in `YYYY-MM` form, such as `2026-05`. A later
profile may allow SemVer, but one deployment must not mix version schemes in the
same claim namespace. Version ranges are reserved for federation and use exact
versions in version 0 unless a trust policy defines a compatible range syntax.

Version 0 subject types are:

| Subject type | Status |
| --- | --- |
| `person` | Required for version 0. |
| `business` | Reserved until a business registry profile is implemented. |
| `household` | Reserved until a household registry profile is implemented. |

Additional subject types must be registered in deployment configuration and
must define identity mapping, disclosure, audit, and connector semantics before
they appear in discovery.

### Source Bindings

Every claim definition must declare how request inputs bind to source data. The
claim engine does not infer datasets, entities, fields, relationships, or lookup
keys from a connector name alone.

The public subject API uses `subject.id`. Claim definitions may name their
internal input `subject_id`; unless a claim declares a different mapping,
`subject.id` binds to the `subject_id` input before source lookup.

`source_bindings` identify:

- connector type;
- deployment connection id;
- dataset and entity or the connector-equivalent resource name;
- lookup input, field, operator, and expected cardinality;
- fields the claim may read, including type, unit, required flag, and optional
  semantic term;
- relationships the claim may traverse, when a later version allows them.

Version 0 source bindings should read already-materialized fields. For example,
`farmed-land-size` should extract `total_farmed_area` from a farmer record. It
should not sum parcel records unless the source already exposes that value or a
later version explicitly enables aggregate/plugin computation.

Deployment-level connection configuration holds base URLs and credentials. Claim
definitions reference connections by id and must not contain secrets.

```yaml
connections:
  farmer_registry_api:
    connector: registry_data_api
    base_url: https://registry-relay.example.gov
    auth_profile: farmer_registry_service

auth_profiles:
  farmer_registry_service:
    type: oauth2_client_credentials
    token_url: https://idp.example.gov/oauth/token
    client_id: evidence-server
    client_assertion_env: FARMER_REGISTRY_CLIENT_ASSERTION
    scopes:
      - farmer_registry:metadata
      - farmer_registry:rows

credential_profiles:
  farmer_status_sd_jwt:
    format: application/dc+sd-jwt
    issuer: did:web:farmer.example.gov
    issuer_key_ref: vault://evidence-server/keys/farmer-status-2026-05
    vct: https://farmer.example.gov/credentials/farmer-status/v1
    validity: P90D
    holder_binding:
      mode: did
      proof_of_possession: required
      allowed_did_methods:
        - did:web
        - did:jwk
    allowed_claims:
      - farmer-under-4ha
    disclosure:
      allowed:
        - predicate
```

Connection and issuer configuration must not contain inline secret material.
Use secret references only, such as environment variable names, `vault://`
URIs, `op://` references, or deployment-specific secret-manager references.

### Rule Types

Version 0 valid `rule.type` values are:

| Rule type | Status | Meaning |
| --- | --- | --- |
| `extract` | Required | Return one configured source field as the claim value. |
| `exists` | Required | Return whether a configured source record or relationship exists. |
| `cel` | Required | Evaluate a CEL expression over declared bindings. |
| `plugin` | Extension | Call a trusted compiled Rust component. |
| `aggregate` | Reserved | Compute over multiple records when a later profile defines aggregation. |

Version 0 uses CEL for predicates. CEL expressions are compiled at config load
time against declared bindings and allowlisted functions. They may reference
request inputs, extracted fields, dependent claim values, and host-provided
context such as evaluation date. They must not access network, filesystem,
environment, clocks, random values, or undeclared fields.

Evidence Server should reuse the `cel-mapping` expression runtime semantics
instead of defining a second CEL dialect. Version 0 should use
`cel-mapper-core` standalone expression evaluation for CEL parsing,
evaluation, JSON/CEL conversion, missing-value semantics, security limits,
allowlisted helpers, and preview diagnostics.

If the current `cel-mapper-core` public API cannot expose all Evidence Server
root bindings directly, Wave 1 should first extend `cel-mapper-core` with a
small reusable expression API. That API must accept a host-provided root binding
map, enforce security limits, and return structured diagnostics. The extension
is acceptable only if it stays generic and does not make PublicSchema behavior
leak into Evidence Server. Split a lower-level crate only if keeping the API in
`cel-mapper-core` would couple Evidence Server to PublicSchema mapping
documents, `property_mappings`, output writers, or ETL behavior. Evidence
Server must not work around the limitation by inventing different expression
syntax.

Evidence Server CEL adopts the `cel-mapping` root binding style. A rule may use
these root objects:

| Root binding | Meaning |
| --- | --- |
| `source` | Source values made available by this claim's `source_bindings`, keyed by binding id. |
| `claims` | Dependent `ClaimResultView` values, keyed by declared local alias. |
| `ctx` | Host-provided context such as purpose, requester class, subject reference, evaluation date, locale, and timezone. |
| `vars` | Claim-config constants. |
| `meta` | Explicitly allowed non-sensitive metadata such as source freshness, source version, or connector profile. |

CEL binding declarations define root object fields. Dots in CEL expressions are
field access, not identifier characters. For example,
`claims.farmed_land_size.value` means:

```yaml
bindings:
  claims:
    type: object
    fields:
      farmed_land_size:
        claim: farmed-land-size
        type: claim_result_view
```

Implementations must not declare a binding literally named
`claims.farmed_land_size`.

Version 0 allowed CEL features:

| Feature | Status |
| --- | --- |
| Boolean operators | Allowed: `&&`, `||`, `!`. |
| Comparison operators | Allowed: `==`, `!=`, `<`, `<=`, `>`, `>=`. |
| Arithmetic | Allowed for numbers: `+`, `-`, `*`, `/`, `%`. |
| Membership | Allowed for configured arrays and maps. |
| Field access | Allowed only on declared object fields. |
| `has()` | Allowed for declared optional fields. |
| `size()` | Allowed with configured maximum input length. |
| String normalization | Allowed only through host-provided allowlisted functions. |
| Regex matching | Disabled in version 0. |
| Comprehensions | Disabled in version 0 unless an implementation-specific review enables bounded forms. |
| Time functions | Disabled except host-provided evaluation date or time values. |

SPARQL is not the version 0 predicate language. A source connector may use
SPARQL internally when the source is an RDF graph or semantic repository, but
the claim rule remains `extract`, `exists`, or `cel` over host-provided values.

Aggregation is not part of version 0 unless the source exposes a materialized
aggregate field. Complex computation belongs upstream in the registry/source
adapter or in a later plugin-enabled extension.

Config must not become a hidden general-purpose programming language. Logic
that is not expressible as extraction, existence, or a reviewable CEL predicate
is out of scope for core version 0.

### Plugin Extension

Plugins are an extension point, not part of version 0. The core product should
be usable without plugin execution. Plugin ABI details are documented later
under `Plugin Extension Profile` so v0 implementers can focus on `extract`,
`exists`, and `cel`.

## Claim Value Types

Supported value types:

| Type | Example |
| --- | --- |
| `boolean` | `true` for `farmer-under-4ha` |
| `number` | `5` with unit `hectare` |
| `date` | `1990-04-12` |
| `string` | `compliant` |
| `object` | `{ "country": "ZZ", "district": "north" }` |
| `array` | List of configured simple or object values |

Each value type may define disclosure variants. For example, `date-of-birth`
may allow exact date, age, over-threshold, born-before-date, or redacted.

## Disclosure Profiles

Version 0 uses one disclosure enum across configuration, requests, results, and
rendering:

| Profile | Meaning |
| --- | --- |
| `value` | Return the computed value when policy allows exact disclosure. |
| `predicate` | Return only the predicate result or derived boolean. |
| `redacted` | Return no value, only allowed metadata and provenance summary. |

The API must reject unknown disclosure profiles with
`request.invalid`. It must reject known profiles that are forbidden for the
claim or caller with `claim.disclosure_not_allowed`, unless the claim
definition explicitly allows downgrade.

Version 0 API requests must use only `value`, `predicate`, or `redacted`.
Labels such as `minimal` are not API values and must be rejected with
`request.invalid`. If a client-facing UI wants those labels, it must map them
before calling the API. The suggested UI-side mapping is:

| UI label | API profile |
| --- | --- |
| `minimal` | Claim definition default |
| `exact` | `value` |
| `proof` | `predicate` |
| `none` | `redacted` |

The canonical internal `ClaimResult` may contain the full computed value and
internal source metadata. Before any renderer runs, the host must construct a
`ClaimResultView` that contains only fields allowed by the effective disclosure
profile. Renderers must not receive raw internal `ClaimResult` values.

Each claim is evaluated at the requested disclosure profile when both claim
configuration and caller authorization allow it. If the requested profile is
known but not allowed for a specific claim, the server either rejects that claim
with `claim.disclosure_not_allowed` or downgrades to a configured fallback
profile only when the claim definition explicitly allows downgrade. Downgraded
claim results must include the effective `disclosure` value and may include a
non-sensitive `disclosure_reason` such as `policy_downgrade`.

Version 0 claim definitions use `disclosure.downgrade: default` to allow
downgrade to the claim's default profile. If `downgrade` is absent or `none`,
the server rejects a forbidden requested profile instead of downgrading.

Valid `disclosure.downgrade` values:

| Value | Meaning |
| --- | --- |
| `deny` | Return `claim.disclosure_not_allowed`. This is the default when omitted. |
| `default` | Return the claim definition's default disclosure profile when it is narrower than the requested profile. |
| `redacted` | Return the `redacted` profile. |
| `coarsen` | Return a configured coarser value, such as date to year or number to integer. |
| `bucket` | Return a configured bucket, such as age range or land-size range. |

`coarsen` and `bucket` require explicit per-claim configuration. Renderers must
receive only the already-coarsened or already-bucketed `ClaimResultView`; they
must not perform downgrade decisions themselves.

Rendered artifacts must never expand beyond the `ClaimResultView` unless a
fresh authorization check creates a broader view from the internal result.

## Source Connectors

Version 0 source connectors:

- `dci`
- `registry_data_api`

The version 0 DCI connector supports the SP DCI synchronous registry access
pattern already represented by Registry Relay, including generic named-registry
sync lookup and the disability status/details/support routes. CRVS is also an
explicit first-domain target for civil-registration claims such as date of
birth, birth place, birth registration existence, and age predicates. If a CRVS
DCI wire profile is unavailable in the first implementation, CRVS claims use
Registry Data API or a generic DCI sync lookup binding and the connector
documents that profile gap.

The version 0 Registry Data API connector consumes the existing Registry
Relay-native route surface:

- `GET /datasets`
- `GET /datasets/{dataset_id}`
- `GET /metadata`
- `GET /metadata/catalog`
- `GET /metadata/datasets`
- `GET /metadata/datasets/{dataset_id}`
- `GET /metadata/datasets/{dataset_id}/entities`
- `GET /metadata/datasets/{dataset_id}/entities/{entity}`
- `GET /metadata/datasets/{dataset_id}/entities/{entity}/schema`
- `GET /metadata/datasets/{dataset_id}/entities/{entity}/shacl`
- `GET /datasets/{dataset_id}/{entity}` with declared filters only
- `GET /datasets/{dataset_id}/{entity}/{id}`
- `GET /datasets/{dataset_id}/{entity}/{id}/{relationship}`

Registry Data API subject lookup uses the current entity collection route with
configured filters and limits, or the record-id route when the subject ID is
already the registry record ID. Version 0 does not add a generic `POST /query`
unless Registry Relay itself adopts that route.

The connector contract must support:

- fetching one record or record set for a subject identifier;
- querying by explicitly supported fields for configured subject lookup;
- fetching related records needed by a configured claim;
- exposing source metadata when the source provides it;
- returning source record references;
- returning retrieval time and source version metadata when available;
- mapping source errors into stable Evidence Server errors;
- applying connector-specific downstream authentication.

Custom connectors are possible but are not the default product path. The
Evidence Server should not become the place where every registry's data model is
normalized into a universal warehouse.

## Source Metadata Awareness

The Evidence Server may consume source registry metadata when a connector can
provide it. Metadata is useful as a contract and validation layer, not as the
source of business logic.

Source metadata may include:

- JSON Schema;
- JSON-LD contexts;
- SHACL shapes;
- DCAT, CCCEV, or CPSV metadata;
- DCI profile metadata;
- code lists and controlled vocabularies;
- unit vocabularies;
- administrative geography vocabularies;
- authority, jurisdiction, provenance, and source-version metadata.

Registry Data API sources must provide JSON Schema or equivalent field metadata,
entity IDs, field IDs, value types, access scopes, authority, jurisdiction, and
source freshness or version when available. JSON-LD contexts, SHACL,
CCCEV/DCAT/CPSV mappings, code lists, unit vocabularies, and ODRL-like policy
metadata are optional enrichments that enable stronger validation and better
rendering.

The Evidence Server should use source metadata to:

- validate claim configuration at startup or reload;
- confirm that configured source fields exist and have compatible types;
- confirm units and code lists used by claim rules;
- bind source fields to semantic terms used in rendered artifacts;
- populate CCCEV, JSON-LD, SD-JWT VC, and discovery metadata;
- detect source schema or semantic drift before unsafe claims are served;
- help federated Evidence Servers understand what a claim means.

Metadata must not replace explicit claim rules. A connector may report that a
field maps to `schema:birthDate`, but the `date-of-birth` claim definition must
still bind that field and declare how it is disclosed. A connector may report a
land-area unit, but the `farmer-under-4ha` claim definition must still declare
the threshold, unit, and predicate.

If metadata and claim configuration conflict, the server should fail validation
or disable the affected claim. It must not silently coerce source semantics into
the configured claim. Examples of unsafe conflicts include:

- a date claim bound to a source field that is no longer date-shaped;
- a land-size claim configured for hectares when the source now reports acres;
- a code-list claim whose configured accepted values are no longer present;
- a renderer configured to emit an IRI that conflicts with the source concept.

When a claim is disabled or rejected because of metadata drift, the server must
emit an operator-visible signal. The audit or health record should include
`affected_claim_id`, `conflict_reason`, source binding id, field or semantic
identifier, detected source version when available, and whether the claim is
disabled or only the reload failed.

Source metadata is optional. The server can run with explicit claim bindings
and trusted connector configuration when a registry does not publish rich
metadata. Deployments with high-quality metadata should get stronger validation,
better standards output, better discovery, and earlier drift detection.

## Identity And Record Matching

Version 0 assumes one common subject identifier supplied by the caller:

```json
{
  "subject": {
    "type": "person",
    "id": "123456789"
  }
}
```

The architecture must reserve an ID Mapper step:

```text
caller subject id
  -> id mapper
  -> record matcher, when needed
  -> registry-specific subject id
  -> source connector
```

The ID Mapper may initially be faked by a Registry Relay demo. Production
federation should support pairwise or registry-specific identifiers where
required by privacy, law, or source-system design.

The version 0 demo mapper is an explicit identity mapper named
`common_subject_id`. It accepts the caller subject id and returns the same id to
the source connector. This is deliberately not a production mapper; it exists so
the code path has a stable extension point before pairwise, registry-local, or
record-matching mappers are added.

Identity handling is an extension point, not a hard-coded national ID
assumption. Future deployments may use:

- one common subject ID;
- registry-local IDs;
- pairwise pseudonymous IDs;
- DIDs or other holder-controlled identifiers;
- eIDAS identity attributes;
- additional attributes required for record matching;
- consent or mandate references;
- re-authentication context when the source or profile requires it.

ID mapping and record matching must be auditable. A claim result should record
which mapper, matcher, profile, and version were used, without exposing
alternate identifiers or matching attributes unless allowed by disclosure
policy.

OOTS-profiled deployments must not rely on the v0 common-ID shortcut as the
long-term identity model. They should provide an identity and record-matching
adapter capable of accepting the profile's required identity attributes,
additional attributes, re-authentication evidence, and matching result state.

Production readiness note: version 0 can demonstrate the ID Mapper boundary
with one common subject id and a demo mapper, but a production multi-registry or
OOTS-style deployment is not ready without a production ID Mapper, record
matching policy, pairwise or registry-specific identifier handling where
required, and documented audit controls for cross-registry linkage.

## Operations

Version 0 uses the unprefixed routes below while the API is draft. The first
stable breaking change should introduce a path prefix such as `/v1` or an
equivalent media-type version. Discovery must advertise the active API version
and base URLs.

Format selection uses this precedence:

1. A request body `format` field, when present.
2. The HTTP `Accept` header.
3. The claim or deployment default when `Accept` is absent or `*/*`.

The selected format must be configured for every requested claim and authorized
for the caller. If body `format` and `Accept` conflict, the body field wins only
when the `Accept` header permits it. Otherwise the server returns
`claim.format_not_supported` with HTTP `406`.

### Discovery

```http
GET /.well-known/evidence-service
GET /claims
GET /claims/{claim_id}
GET /formats
```

Discovery returns only capabilities visible to the authenticated caller.

`GET /.well-known/evidence-service` should describe service identity, issuer
metadata, supported auth methods, federation metadata, and API base URLs.

Example:

```json
{
  "service_id": "https://farmer.example.gov/evidence",
  "api_version": "0",
  "base_url": "https://farmer.example.gov/evidence",
  "issuer": {
    "id": "https://farmer.example.gov",
    "name": "Farmer Evidence Server"
  },
  "auth": {
    "methods": [
      "oauth2_bearer"
    ],
    "audience": "https://farmer.example.gov/evidence"
  },
  "operations": {
    "evaluate": true,
    "batch_evaluate": true,
    "render": true,
    "credential_issue": true
  },
  "formats_url": "/formats",
  "claims_url": "/claims",
  "batch": {
    "max_inline_subjects": 100,
    "idempotency_window": "PT24H"
  }
}
```

`GET /claims` returns configured claim definitions filtered by authorization.

`GET /claims/{claim_id}` returns one claim definition, including value type,
inputs, supported operations, disclosure profiles, formats, and policy metadata.

`GET /formats` returns configured renderer and issuer formats.

Example:

```json
{
  "formats": [
    {
      "id": "application/vnd.evidence-server.claim-result+json",
      "kind": "claim_result",
      "status": "enabled"
    },
    {
      "id": "application/ld+json; profile=\"cccev\"",
      "kind": "renderer",
      "status": "enabled"
    },
    {
      "id": "application/dc+sd-jwt",
      "kind": "credential",
      "status": "enabled"
    }
  ]
}
```

### Evaluate One Subject

Question: for this subject, compute these claims.

```http
POST /claims/evaluate
Content-Type: application/json
Accept: application/vnd.evidence-server.claim-result+json
Authorization: Bearer <token>
Data-Purpose: https://example.gov/purposes/input-subsidy-eligibility
```

```json
{
  "subject": {
    "type": "person",
    "id": "123456789"
  },
  "claims": [
    "date-of-birth",
    "farmed-land-size",
    "farmer-under-4ha"
  ],
  "disclosure": "predicate"
}
```

Response:

```json
{
  "evaluation_id": "01JZ0000000000000000000001",
  "computed_at": "2026-05-22T00:00:00Z",
  "claim_results": [
    {
      "result_id": "01JZ0000000000000000000003",
      "claim_id": "farmed-land-size",
      "claim_version": "2026-05",
      "value_type": "number",
      "disclosure": "redacted",
      "disclosure_reason": "policy_downgrade",
      "value": null,
      "provenance": {
        "source_count": 1,
        "computed_by": "farmer-evidence-server"
      }
    },
    {
      "result_id": "01JZ0000000000000000000004",
      "claim_id": "farmer-under-4ha",
      "claim_version": "2026-05",
      "value_type": "boolean",
      "value": false,
      "disclosure": "predicate",
      "derived_from": [
        "farmed-land-size"
      ],
      "provenance": {
        "source_count": 1,
        "computed_by": "farmer-evidence-server"
      },
      "predicate": {
        "op": "lt",
        "threshold": 4,
        "unit": "hectare"
      }
    }
  ]
}
```

This is the external canonical JSON response. It is not the full internal
`ClaimResult`. By default, external responses must not expose raw source record
references, downstream connector identifiers, alternate subject identifiers,
requester identifiers, or audit-only purpose details. Those fields may exist in
internal state and audit records, but a renderer may include them externally
only when a claim's disclosure policy and the caller's authorization explicitly
allow that disclosure.

`provenance` is the external projection of internal source metadata. Version 0
allows only non-sensitive summary fields by default: `source_count`,
`computed_by`, `computed_at`, `source_authority`, and `freshness` when policy
allows them. Raw `record_ref`, connector id, downstream URL, registry-local
subject id, and source payload references are internal unless explicitly
authorized for the caller and format.

`source_count` is the number of source bindings or federated evidence results
that contributed to the claim result after duplicate internal records are
collapsed according to connector policy. `computed_by` is the Evidence Server
service identifier, not the downstream registry id and not a human operator.

### Batch Evaluate

Question: for these subjects, compute these claims.

```http
POST /claims/batch-evaluate
```

```json
{
  "subjects": [
    {
      "type": "person",
      "id": "123456789"
    },
    {
      "type": "person",
      "id": "987654321"
    }
  ],
  "claims": [
    "farmer-under-4ha"
  ],
  "disclosure": "predicate",
  "prefer": "inline"
}
```

Version 0 batch `prefer` values are `inline` and `auto`. Because background
jobs are deferred, `auto` behaves as `inline` in version 0. If a request
exceeds the configured inline
subject limit, the server returns `batch.too_large` rather than creating a
background job. Clients should send an `Idempotency-Key` header for batch
submissions. Idempotency keys are scoped to authenticated client id, route,
normalized request body hash, purpose, and deployment. They must not be global
across callers. The server must
deduplicate matching batch requests for at least the discovery-advertised
idempotency window.

Batch responses must support partial failure. One subject failing due to source
unavailability, authorization, ambiguity, or missing data must not hide results
for other subjects unless the whole request violates policy.

Inline batch responses use one item per input subject, in input order:

```json
{
  "batch_id": "01JZ0000000000000000000005",
  "status": "completed",
  "claims": [
    "farmer-under-4ha"
  ],
  "items": [
    {
      "input_index": 0,
      "subject_ref": "request.subjects[0]",
      "evaluation_id": "01JZ0000000000000000000007",
      "status": "succeeded",
      "claim_results": [
        {
          "result_id": "01JZ0000000000000000000006",
          "claim_id": "farmer-under-4ha",
          "claim_version": "2026-05",
          "value_type": "boolean",
          "value": true,
          "disclosure": "predicate"
        }
      ],
      "errors": []
    },
    {
      "input_index": 1,
      "subject_ref": "request.subjects[1]",
      "evaluation_id": "01JZ0000000000000000000008",
      "status": "failed",
      "claim_results": [],
      "errors": [
        {
          "code": "source.not_found",
          "title": "Source record not found",
          "retryable": false
        }
      ]
    }
  ],
  "summary": {
    "succeeded": 1,
    "failed": 1
  }
}
```

`subject_ref` is an input reference, not a raw subject identifier. Version 0
uses the exact form `request.subjects[N]`, where `N` equals `input_index`.
A deployment may echo raw subject identifiers only when the caller is
authorized for that disclosure.

Whole-request failures are reserved for malformed JSON, unsupported claims or
operations that apply to the entire request, missing or invalid client
authentication, missing required purpose for the whole request, too many input
subjects, unsupported disclosure profile, unsupported format, or policy denial
for the caller to use batch evaluation at all. Per-subject source errors,
missing records, ambiguity, and subject-specific authorization failures belong
in item `errors`. Production record-matching failures are part of a later
identity extension.

Batch item errors must not reveal whether a claim is unknown or merely hidden
from the caller. `claim.not_found` means unknown or not visible to this caller.

Each successful batch item should have an `evaluation_id` that can be rendered
under the same binding rules as single-subject evaluation. `batch_id` is a
response handle, not a render handle.

### Render Evidence

```http
POST /evidence/render
```

```json
{
  "evaluation_id": "01JZ0000000000000000000001",
  "format": "application/ld+json; profile=\"cccev\"",
  "claims": [
    "farmer-under-4ha"
  ],
  "disclosure": "predicate"
}
```

Rendering converts existing claim results into a requested artifact format.
Renderers must not recompute claims unless the request explicitly asks for a
fresh evaluation.

Response:

```json
{
  "artifact_id": "artifact_01JZ0000000000000000000009",
  "evaluation_id": "01JZ0000000000000000000001",
  "format": "application/ld+json; profile=\"cccev\"",
  "disclosure": "predicate",
  "claims": [
    "farmer-under-4ha"
  ],
  "artifact_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015",
  "binding": {
    "requester": "program-system",
    "purpose": "https://example.gov/purposes/input-subsidy-eligibility",
    "expires_at": "2026-05-23T00:00:00Z"
  },
  "artifact": {
    "@context": [
      "https://semiceu.github.io/CCCEV/releases/2.1.0/context/cccev.jsonld"
    ],
    "type": "Evidence",
    "supportsValue": [
      {
        "value": true
      }
    ]
  }
}
```

An `evaluation_id` is bound to the original requester, subject inputs, claim
IDs, claim versions, purpose, consent or legal-basis references, disclosure
profile, selected format set, source snapshot or freshness metadata, and
expiration time. The default expiration is configurable and should be 24 hours
from `computed_at` unless deployment policy requires a shorter period.
Rendering by `evaluation_id` must re-check the current caller's authorization
and must not render a broader disclosure profile, additional claims, or a more
sensitive format than the evaluation permits.

If a caller requests broader disclosure, additional claims, a different purpose,
or an expired evaluation, the server must require a fresh evaluation or return
`release.authorization_invalid`, `claim.disclosure_not_allowed`, or
`claim.format_not_supported` as appropriate. Render responses must include the
rendered artifact hash or equivalent binding metadata so preview and release
tokens can be tied to the exact artifact.

### Issue Credential

Credential issuance should be separate from rendering:

```http
POST /credentials/issue
```

```json
{
  "evaluation_id": "01JZ0000000000000000000001",
  "format": "application/dc+sd-jwt",
  "claims": [
    "farmer-under-4ha"
  ],
  "holder": {
    "binding": "did",
    "id": "did:web:wallet.example.gov:holders:123",
    "proof": "<holder-proof-jwt>"
  },
  "disclosure": "predicate"
}
```

If configured, a successful response should return credential metadata and the
credential artifact:

```json
{
  "credential_id": "vc_01JZ0000000000000000000010",
  "format": "application/dc+sd-jwt",
  "issuer": "did:web:farmer.example.gov",
  "expires_at": "2026-08-22T00:00:00Z",
  "credential": "<sd-jwt-vc-compact>"
}
```

Issuance adds credential lifecycle concerns such as issuer identity, signing
keys, holder binding, validity period, credential status, revocation, and
selective disclosure.

`POST /credentials/issue` issues only from an existing `evaluation_id` in
version 0. It must not recompute claims. It must construct a `ClaimResultView`
with the requested disclosure, verify that the requested claims and format are
allowed by the original evaluation binding, then sign that view with the
configured issuer.

If issuer configuration is missing for the requested claim and format, the route
must return `credential.issuer_not_configured`. A deployment may omit the route
only when discovery marks `credential_issue` as `false` and no SD-JWT VC format
is advertised as enabled.

`evaluation_id` is a server-side render and issuance handle. It must be scoped
to the original authenticated client, purpose, subject inputs, claim ids, claim
versions, disclosure profile, source freshness, and expiry. A caller cannot use
another caller's `evaluation_id`, even if the opaque value is guessed or leaked.

Issued credentials must not contain `evaluation_id`. The response may include a
server-side `credential_id`, but the signed SD-JWT VC must use a per-credential
opaque identifier and must not embed an evaluation handle that could link the
same subject across verifiers.

Version 0 SD-JWT VC issuance requirements:

- JOSE header includes `typ: "dc+sd-jwt"`, `alg`, and `kid`.
- Issuer-signed payload includes `iss`, `iat`, `exp`, `vct`, and configured
  claim content.
- Selectively disclosable claims are represented through `_sd_alg`, `_sd`
  digest arrays, and per-claim disclosures with fresh random salts.
- Salt generation uses a cryptographically secure random source and never
  reuses salts across credentials or claim disclosures.
- Holder binding modes are `none` or `did`.
- Version 0 supports only `did:jwk` holder identifiers. `did:web`, bare JWK
  holder binding, and other DID methods are deferred.
- When holder binding mode is `did`, the credential includes `cnf.kid` set to
  the holder `did:jwk` identifier. Verifiers for the v0 profile resolve the
  holder key from that `did:jwk` value.
- Version 0 issuance proof-of-possession is an Evidence Server issuance JWT,
  not an SD-JWT KB-JWT. The holder signs an EdDSA JWT with the `did:jwk` key and
  binds it to the Evidence Server audience, `evaluation_id`,
  `credential_profile`, disclosure profile, and claim ids before issuance.
- The issuance JWT must include `sub`, `aud`, `exp`, `iat`, `jti`,
  `evaluation_id`, `credential_profile`, `disclosure`, and `claims`. The server
  rejects stale or future `iat` values and treats `jti` as a replay key scoped to
  the authenticated requester, evaluation, credential profile, and holder.
- SD-JWT `kb+jwt`, `sd_hash`, presentation nonce handling, and verifier-facing
  key-bound presentation checks are deferred to a future presentation-verifier
  flow.
- Issuer keys are referenced by `issuer_key_ref`; inline private keys are
  forbidden.
- The issuer publishes or exposes a JWKS or DID document with the active `kid`
  values and a documented key-rotation process.
- Issuer key configuration records activation, deactivation, and compromised-key
  handling. The server must stop issuing with disabled keys and keep enough
  public key history for verifiers to validate unexpired credentials.
- The `vct` value is an HTTPS URL or governance-approved registry identifier
  that resolves to credential type metadata for deployments that advertise
  interoperable SD-JWT VC issuance.

## Internal Claim Result Model

Internal claim results should use this logical shape:

```json
{
  "claim_id": "farmer-under-4ha",
  "claim_version": "2026-05",
  "subject": {
    "type": "person",
    "id": "123456789"
  },
  "value_type": "boolean",
  "value": false,
  "computed_at": "2026-05-22T00:00:00Z",
  "expires_at": "2026-05-23T00:00:00Z",
  "method": {
    "type": "cel",
    "definition_ref": "claims/farmer-under-4ha@2026-05"
  },
  "derived_from": [
    "farmed-land-size"
  ],
  "sources": [
    {
      "connector": "registry_data_api",
      "registry": "farmer_registry",
      "record_ref": "farmer-record-123",
      "source_version": "2026-05-21",
      "retrieved_at": "2026-05-22T00:00:00Z"
    }
  ],
  "identity_mapping": {
    "mapper": "demo-id-mapper",
    "version": "2026-05"
  },
  "disclosure": {
    "profile": "value",
    "redactions": []
  },
  "audit": {
    "evaluation_id": "01JZ0000000000000000000001",
    "requester": "program-system",
    "purpose": "https://example.gov/purposes/input-subsidy-eligibility"
  }
}
```

`derived_from` may use local claim ids for same-server dependencies. Federated
dependencies use objects containing `issuer`, `claim`, `version`, `result_id`
or `artifact_hash` when available, and the configured local dependency `ref`.
External responses may collapse these details to local claim ids unless the
caller is authorized to see federation metadata.

Rendered artifacts receive a disclosure-filtered `ClaimResultView`, not this
internal shape. The internal audit record may retain more detail than the
returned artifact, but must be protected according to local data protection
rules.

## Selective Disclosure

Selective disclosure is enforced before rendering. The server must check:

- caller identity;
- requested claim;
- requested subject or subject set;
- declared purpose;
- legal basis or consent reference when required;
- requested disclosure profile;
- requested output format;
- operation type.

For example, a caller may be allowed to receive:

```json
{
  "claim_id": "farmer-under-4ha",
  "value": true
}
```

while not being allowed to receive:

```json
{
  "claim_id": "farmed-land-size",
  "value": 3.2,
  "unit": "hectare"
}
```

Disclosure policy applies even if a downstream connector can fetch the raw
value. Downstream registry credentials must never determine what the caller can
see.

## Authentication And Authorization

Authentication has two separate directions.

### Client To Evidence Server

Recommended version 0 client authentication:

- OAuth2 or OpenID Connect bearer access tokens;
- audience bound to the Evidence Server;
- scopes or roles mapped to Evidence Server permissions;
- optional mTLS or private-key JWT for high-trust server-to-server clients.

Authorization must be claim-aware and disclosure-aware. A valid token is not
enough. Policy must decide whether the caller can:

- discover the claim;
- evaluate the claim;
- batch evaluate the claim;
- request the subject or subject set;
- use the declared purpose;
- receive the requested disclosure profile;
- receive the requested output format;
- issue or receive a signed credential.

Requests should carry a purpose:

```http
Data-Purpose: https://example.gov/purposes/input-subsidy-eligibility
```

`Data-Purpose` is the primary purpose carrier. Batch requests may also include
body `purpose` for easier replay and audit correlation. If both are present,
they must be identical after normalization. Mismatch returns
`auth.purpose_mismatch`; neither value wins.

Purpose binding is an accountability and authorization input, not a complete
technical guarantee about downstream use. Deployments must configure allowed
purpose URIs and reject unknown purposes rather than implicitly accepting any
caller-provided URI. Each accepted purpose URI should resolve, through local
policy documentation or an internal registry, to a documented data-use
description.

When the deployment requires consent or legal-basis references, requests carry
them in the body:

```json
{
  "subject": {
    "type": "person",
    "id": "123456789"
  },
  "claims": [
    "farmer-under-4ha"
  ],
  "purpose": "https://example.gov/purposes/input-subsidy-eligibility",
  "consent_ref": "consent_abc"
}
```

### Evidence Server To Source Registries

Downstream authentication is connector-specific and independent from caller
authentication.

Supported modes:

| Mode | Use |
| --- | --- |
| Local service credentials | Evidence Server is trusted by a local registry or authority. |
| Delegated on-behalf-of access | Evidence Server exchanges the caller token for a registry-scoped token. |
| Connector-owned legacy credentials | Connector uses API keys, static tokens, or legacy auth for compatibility. |

Local authority deployments should prefer service credentials, mTLS, or another
internal trust mechanism between the Evidence Server and its source registry.

Delegated on-behalf-of access is useful when the source registry needs to
authorize by original caller or consent context. It requires more identity
infrastructure and should be supported by the architecture but not required for
every source in version 0.

Connector-owned legacy credentials are compatibility mode. They must be stored
securely, redacted from logs, and scoped as narrowly as the source permits.

Source connection authentication is configured outside claim definitions. A
claim names a `connection`; the connection names an `auth_profile`; the auth
profile references secret material through environment variables or a secret
manager reference. Claim definitions must remain portable and secret-free.

### Evidence Server To Evidence Server

Federated calls use the same client authentication model. An aggregator
authenticates to a domain Evidence Server as a client:

```text
Program Evidence Server -> Farmer Evidence Server
```

Federated responses should be signed when the aggregator is expected to rely on
them or pass them onward. The aggregator must preserve issuer, claim definition
version, computed time, and disclosure metadata.

## Federation Extension

Federation execution is not part of version 0. The version 0 service should
preserve issuer, result, source, signature, and freshness metadata in a way that
allows a later federation extension to compose claims without exchanging raw
registry data.

When federation is implemented, Evidence Servers should federate through
claims, capabilities, and signed results, not through shared raw registry data.

A composed claim definition may depend on claims from other issuers:

```yaml
id: eligible-for-input-subsidy
version: 2026-05
subject_type: person
value:
  type: boolean
depends_on:
  - ref: crvs.age-over-18
    issuer: https://crvs.example.gov
    claim: age-over-18
    version: 2026-05
    freshness: P30D
    signature_required: true
    trust_policy: https://example.gov/trust/crvs
  - ref: farmer.farmer-under-4ha
    issuer: https://farmer.example.gov
    claim: farmer-under-4ha
    version: 2026-05
    freshness: P30D
    signature_required: true
    trust_policy: https://example.gov/trust/farmer
  - ref: tax.tax-compliant-for-year
    issuer: https://tax.example.gov
    claim: tax-compliant-for-year
    version: 2026-05
    freshness: P30D
    signature_required: true
    trust_policy: https://example.gov/trust/tax
rule:
  type: cel
  expression: "claims.crvs_age_over_18.value && claims.farmer_under_4ha.value && claims.tax_compliant_for_year.value"
  bindings:
    claims:
      type: object
      fields:
        crvs_age_over_18:
          ref: crvs.age-over-18
          type: claim_result_view
        farmer_under_4ha:
          ref: farmer.farmer-under-4ha
          type: claim_result_view
        tax_compliant_for_year:
          ref: tax.tax-compliant-for-year
          type: claim_result_view
```

Federated dependencies must be fully qualified. The local `ref` is the name used
inside the composed rule and must be unique within the claim definition's
`depends_on` list. It is not a global namespace. The dependency must also
declare issuer, claim id, version or version range, freshness requirement, trust
policy, and whether a signature is required. The aggregator must reject stale,
unsigned, untrusted, or wrong-version dependency results before evaluating the
composed rule.

Production federation trust policies must define the accepted signature format
such as JWS or COSE, JWKS or key discovery location, key max age, rotation
rules, revocation or distrust checks, and fail-closed behavior when trust policy
or key status cannot be reached. Version 0 may demonstrate federation metadata
without production key rotation only when the deployment clearly marks it as a
demo or local test profile.

Evidence Server federation signatures are JWS or COSE. They are not OOTS
eDelivery signatures and do not interoperate with OOTS XML-DSig evidence
exchange without an explicit OOTS adapter.

Federated search is sensitive and remains outside version 0. A future search
extension requires:

- compatible or mappable subject identifiers;
- purpose and authorization at each participating server;
- result cardinality controls;
- rate limits;
- audit records at each server;
- a policy for raw, pseudonymous, or pairwise subject IDs.

## Plugin Extension Profile

Plugins are not part of version 0. They are reserved for cases where extraction,
existence checks, and CEL predicates are not expressive enough.

When a later deployment enables plugins, they use an in-process Rust trait
unless that deployment adds a stronger sandbox. The trait is versioned and
loaded only from configured, trusted code compiled with the service or provided
through a reviewed deployment package.

Logical signature:

```text
evaluate(inputs, sources, context) -> ClaimResultFragment
```

Inputs:

- normalized subject reference;
- request inputs allowed by the claim definition;
- source records fetched by configured source connectors;
- dependent claim results named in the claim definition;
- purpose, requester, evaluation time, and claim definition version;
- disclosure profile requested, for validation only.

Outputs:

- claim value or predicate result;
- value type and unit when applicable;
- derived-from references;
- source references selected from connector-provided references;
- diagnostics allowed for internal audit;
- stable plugin error code when evaluation fails.

Logical fragment shape:

```json
{
  "value_type": "number",
  "unit": "hectare",
  "value": 3.2,
  "derived_from": [
    "farmer.total_farmed_area"
  ],
  "sources": [
    {
      "source_binding": "farmer",
      "record_ref": "farmer-record-123"
    }
  ],
  "diagnostics": {
    "calculation_profile": "farmed_land_size.v1"
  }
}
```

Diagnostics are structured key-value metadata for internal audit only. They
must not contain secrets, raw source values, subject identifiers, connector
credentials, or values that disclosure policy would otherwise hide. The host
decides whether diagnostics are written to audit records.

Plugins must:

- be deterministic for the same inputs, source records, and context;
- declare an ABI version and plugin version;
- avoid network access, filesystem access, environment reads, clocks, random
  values, and process spawning;
- finish within the configured timeout;
- return structured errors that map to Evidence Server error codes;
- never bypass disclosure policy or write audit records directly.

The host is responsible for source access, identity mapping, authorization,
disclosure, rendering, and audit. Plugins compute claim fragments only. A plugin
that needs external data must declare that data as a source binding so the host
can fetch and audit it.

Version 0 plugin isolation is review-time and deployment-time trust only. An
in-process Rust plugin is trusted host code, not an OS sandbox. The obligations
above are normative contracts for reviewed plugins, but the runtime cannot
prevent a malicious or unsafe plugin from reading process memory, exhausting
resources, or using unexpected system interfaces. Production deployments that
need untrusted plugin execution must add process isolation, Wasm isolation,
seccomp, or an equivalent sandbox before enabling third-party plugins.

## OOTS And CCCEV Profiles

Version 0 supports CCCEV rendering. OOTS wire exchange is an extension profile.
The Evidence Server should support OOTS and CCCEV through explicit profiles,
not through implicit claims of compatibility.

### Mapping Rules

Recommended mappings:

| Evidence Server concept | CCCEV or OOTS mapping |
| --- | --- |
| `ClaimDefinition` | CCCEV `InformationRequirement`, `Criterion`, or `Constraint` |
| `ClaimResult` | CCCEV `Evidence` with `SupportedValue` |
| `EvidenceArtifact` | Candidate OOTS evidence only when accepted by governance |
| `SourceConnector` | Local Data Service implementation detail |
| `/claims/evaluate` | Local REST computation API, not OOTS evidence exchange |
| `/claims/search` | Non-OOTS local or national capability unless separately profiled |

A `ClaimDefinition` may reference CCCEV `InformationConcept` for value shape,
semantic meaning, or expected value expression. It should not be rendered as an
`InformationConcept` when the artifact is describing requested data to be proven
by evidence.

An OOTS profile should include enough metadata to support Evidence Broker,
Data Service Directory, and Semantic Repository alignment where relevant:

- requirement;
- reference framework;
- evidence type classification;
- evidence type list;
- country code and jurisdiction;
- supported `DistributedAs` formats;
- `ConformsTo` references;
- language;
- authentication level of assurance, using the OOTS
  `AuthenticationLevelOfAssurance` field name where applicable;
- issuing or responsible authority;
- procedure context;
- preview and release requirements.

The first OOTS claim binding requires requirement, reference framework, country
or jurisdiction, language, evidence type classification, distributed format,
`ConformsTo`, issuing or responsible authority, and authentication level of
assurance. Full OOTS EDM request and response details belong to the OOTS
adapter, not the core REST API. For OOTS deployments, `ConformsTo` IRIs are
governed semantic repository identifiers or registry-assigned persistent URLs,
not ad hoc deployment-local examples.

`cccev.requirement_type: information_requirement` is a local CCCEV mapping hint,
not an OOTS DSD field. OOTS DSD fields must use the OOTS profile's own
vocabulary and lifecycle rules.

Version 0 accepts `AuthenticationLevelOfAssurance` values `low`,
`substantial`, and `high`, aligned with eIDAS terminology. OOTS deployments may
map these to governed OOTS URIs where the applicable profile requires URIs.

### OOTS Adapter Boundary

An OOTS adapter is responsible for translating between Evidence Server
operations and the OOTS evidence exchange model. It should not expose
`POST /claims/evaluate` as if that route were itself the OOTS wire protocol.

The adapter may:

- discover configured claims and renderable artifacts;
- map OOTS evidence requests to claim evaluation requests;
- invoke identity and record-matching adapters;
- prepare preview artifacts;
- enforce release authorization;
- render OOTS EDM-compatible responses;
- return OOTS-profiled evidence errors;
- preserve OOTS correlation, requester, provider, procedure, and evidence
  metadata.

The first OOTS adapter implementation should support one evidence request, one
evidence response, and one evidence error path for a single profile. Until that
adapter exists, the core service exposes only OOTS profile metadata and must not
claim OOTS wire compliance.

The adapter must not replace the OOTS Evidence Broker, Data Service Directory,
Semantic Repository, eDelivery exchange, or cross-border governance process.

### Preview And Release Authorization

Some profiles, including OOTS-style flows, may require preview and approval
before evidence is released. The core Evidence Server should support this as an
optional release policy, not as a universal requirement.

Suggested release states:

| State | Meaning |
| --- | --- |
| `computed` | Claim results exist but no release decision has been made. |
| `preview_available` | A disclosure-controlled preview artifact can be shown. |
| `release_authorization_required` | The artifact cannot be released yet. |
| `release_authorized` | A valid approval or release token exists. |
| `released` | The artifact was released to the requester. |
| `release_denied` | Release was denied or expired. |

Release authorization should be bound to the requester, subject, purpose,
claim, disclosure profile, artifact format, artifact hash, audience, and
expiration time. The audience must include the issuing Evidence Server URL and
the authorized requester client id. Approval tokens must expire within the
evaluation freshness window and fail closed when replayed by a different caller
or for a broader disclosure than the one approved.

### OOTS Identity Preparation

The OOTS profile should not assume that one common ID is enough. It should be
able to pass identity attributes, additional attributes, re-authentication
context, and record-matching outcomes into claim evaluation without exposing
those details in the returned artifact unless disclosure policy permits it.

The claim result should preserve enough non-disclosed metadata for audit:

- identity profile used;
- mapper and matcher versions;
- matching confidence or result code, if available;
- whether additional attributes were required;
- whether re-authentication was required;
- whether the source registry accepted or rejected the match.

OOTS and production record-matching extensions may use additional errors such
as:

| Code | Meaning |
| --- | --- |
| `identity.record_match_required` | Profile requires record matching before evaluation. |
| `identity.record_match_failed` | Record matching could not resolve the subject. |

## Output Formats

Initial formats:

- canonical claim-result JSON;
- CCCEV-aligned JSON-LD;
- SD-JWT VC.

Format support is per deployment and per claim. A claim may support JSON and
CCCEV but not SD-JWT VC if issuer keys, credential status, holder binding, or
revocation are not configured.

CCCEV output should be a projection from claim results into CCCEV-compatible
concepts through `ClaimResultView`. It must not become the internal claim
model.

SD-JWT VC output should be handled by the credential issuer layer. It must honor
disclosure policy and should expose only claims approved for credential
issuance.

Version 0 includes SD-JWT VC credential issuance when issuer configuration is
present. The configuration includes issuer DID or key reference, credential type
(`vct`), allowed Evidence Server claims for that credential type, validity
period, holder-binding option, and disclosure policy. The allowed-claims setting
is an application policy. Actual SD-JWT VC selective disclosure must be
represented in the credential type metadata and credential claims according to
the selected SD-JWT VC profile. Credential status and revocation are deferred
until a later credential lifecycle extension.

`allowed_claims` belongs to credential profile configuration, not to an
individual `ClaimDefinition`. This allows two credential profiles to project
different subsets or disclosure profiles over the same claim definitions.

## Errors

Errors should use Problem Details with stable error codes. Initial codes:

| Code | Meaning |
| --- | --- |
| `request.invalid` | Request body, query, or header value is malformed. |
| `claim.not_found` | Claim is unknown or hidden from the caller. |
| `claim.operation_not_supported` | Claim does not support the requested operation. |
| `claim.disclosure_not_allowed` | Caller cannot receive the requested disclosure profile. |
| `claim.format_not_supported` | Requested format is not configured for the claim. |
| `subject.invalid` | Subject type or identifier is malformed. |
| `identity.mapping_failed` | ID Mapper could not map the subject. |
| `source.unavailable` | Source registry or connector is unavailable. |
| `source.ambiguous` | Source lookup returned multiple records where one was required. |
| `source.not_found` | Required source record was not found. |
| `auth.purpose_required` | Deployment or claim requires a purpose. |
| `auth.purpose_mismatch` | Header and body purpose values do not match. |
| `auth.consent_required` | Deployment or claim requires a consent reference. |
| `batch.too_large` | Inline batch request exceeds the configured version 0 limit. |
| `release.authorization_required` | Artifact release requires preview approval or another release token. |
| `release.authorization_invalid` | Release token is missing, expired, or not bound to this request. |
| `credential.issuer_not_configured` | Credential issuance was requested without issuer config. |

HTTP status should distinguish transport and policy errors from completed claim
results. For example, a valid `farmer-under-4ha` computation that returns
`false` is a successful claim result, not an HTTP error.

Initial status and retry semantics:

| Code | HTTP status | Retryable | May appear in batch item |
| --- | --- | --- | --- |
| `request.invalid` | 400 | No | No |
| `claim.not_found` | 404 | No | Yes |
| `claim.operation_not_supported` | 400 | No | Yes |
| `claim.disclosure_not_allowed` | 403 | No | Yes |
| `claim.format_not_supported` | 406 | No | No |
| `subject.invalid` | 400 | No | Yes |
| `identity.mapping_failed` | 422 | No | Yes |
| `source.unavailable` | 503 | Yes | Yes |
| `source.ambiguous` | 409 | No | Yes |
| `source.not_found` | 404 | No | Yes |
| `auth.purpose_required` | 400 | No | No |
| `auth.purpose_mismatch` | 400 | No | No |
| `auth.consent_required` | 400 | No | No |
| `batch.too_large` | 413 | No | No |
| `release.authorization_required` | 403 | No | No |
| `release.authorization_invalid` | 403 | No | No |
| `credential.issuer_not_configured` | 501 | No | No |

Batch item errors use the same `code`, `title`, and `retryable` fields. The
HTTP status of an inline batch response is `200` when the batch operation
completed and at least one item was evaluated or failed as an item result.

## Audit And Privacy

Every evaluation, batch, render, and issuance event should produce an audit
record that can answer:

- who called the service;
- which claim definitions and versions were used;
- which subject or subject set was requested;
- which purpose, legal basis, or consent reference was provided;
- which source connectors and source references were used;
- which disclosure profile was returned;
- which output format was returned;
- whether the result was signed;
- which downstream services were called;
- which errors or partial failures occurred.

Audit logs must not print secrets, raw credentials, or unrestricted source
records. Subject identifiers are PII and must be pseudonymized in logs by
default. The pseudonymization salt or key must be scoped at least per
tenant or per deployment, according to the deployment's tenancy model, and
rotated on a documented schedule. Plaintext subject identifiers may be logged
only when operator policy explicitly allows it with a documented legal basis and
access control. Sensitive claim values should be redacted or hashed in logs
unless operator policy explicitly permits secure value logging.

When one evaluation queries multiple registries for the same subject, audit
records must preserve enough internal detail to reconstruct which registries
were queried for that `evaluation_id`. Operator policy should cap the number of
claims or registries evaluated for one subject in a configured time window when
cross-registry linkage risk is high.

## Migration Glossary

Registry Relay evidence verification and the Evidence Server use similar words
for different concepts. Implementations must keep these terms distinct during
extraction.

| Registry Relay evidence verification | Evidence Server |
| --- | --- |
| `evidence offering` | Source or migration input that may map to a `ClaimDefinition` |
| caller-submitted `claims` | Submitted facts to compare against registry facts |
| verification `decision` | Match, mismatch, or ambiguous comparison result |
| `claim_hash` | HMAC binding for submitted facts in a verification receipt |
| `evidence_hash` | HMAC binding for caller-held evidence metadata |

In the Evidence Server, a `ClaimDefinition` is a configured registry-backed
question, and a `ClaimResult` is the computed answer. Do not reuse the
Registry Relay meaning of `claims` as caller-submitted facts inside the Evidence
Server API. When migrating existing evidence offerings, map submitted-fact
verification to explicit claim definitions only where the semantics match.

## Relationship To Registry Relay

Registry Relay currently publishes protected registry consultation APIs,
metadata, evidence offerings, SP DCI adapters, and evidence verification
receipts. The standalone Evidence Server should take over claim computation and
multi-format evidence generation when those concerns outgrow a single registry
gateway.

Registry Relay can still play useful roles:

- source registry consultation API;
- Registry Data API implementation;
- DCI adapter host;
- demo ID Mapper;
- metadata publisher for registry datasets and offerings;
- embedded demo environment for the Evidence Server protocol.

Current Registry Relay evidence offerings and verification routes remain in
place during extraction. A compatibility adapter may map compatible evidence
offerings to `ClaimDefinition` entries, but verification-only flows should stay
verification-only unless their semantics match computed registry-backed claims.
Current routes should not be removed until the Evidence Server reproduces the
relevant demo flows.

The extraction should avoid moving CCCEV code wholesale into a standalone
service as the internal model. Instead, introduce the canonical `ClaimResult`
boundary and make CCCEV one renderer.

## Version 0 Scope

Version 0 should include:

- claim discovery;
- format discovery;
- single-subject evaluation;
- bounded inline batch evaluation with partial failures;
- DCI connector;
- Registry Data API connector;
- source metadata validation when connectors expose metadata;
- one common subject ID with reserved ID Mapper boundary;
- simple predicates;
- CEL predicate execution;
- canonical JSON renderer;
- CCCEV renderer;
- SD-JWT VC credential issuance from existing evaluations when issuer
  configuration is present;
- explicit OOTS profile metadata in claim definitions when configured, without
  implementing OOTS wire compliance in the core REST API;
- authentication and authorization model;
- audit records.

Version 0 may defer:

- subject search;
- background jobs;
- federation execution;
- full federated search;
- pairwise identifier protocols;
- production OOTS record-matching adapter;
- OOTS EDM and eDelivery adapter implementation;
- preview and release approval UI;
- general-purpose aggregation in config;
- credential status and revocation;
- production ID Mapper implementation;
- approved indexed search;
- non-DCI custom connector SDK;
- plugin execution for complex computation.

Deferred items must be tracked in a small implementation register with owner,
reason, exposure state, revisit trigger, and whether discovery hides the
feature or exposes a stable not-supported error. Version 0 also defers
load/performance targets beyond basic smoke and focused tests; production
performance budgets should be added before wide deployment.

Version 0 is suitable for demos, local pilots, and implementation hardening. It
is not production-ready for multi-registry, search, federation, or OOTS-style
deployments unless the operator adds the relevant extension, a production ID
Mapper, record-matching adapter where required, production federation trust
policy where federation is used, operational monitoring for disabled claims,
and documented audit/privacy controls.

## Definition Of Done For Version 0

Version 0 is done when the core path works end to end from configuration,
through registry lookup and claim evaluation, through disclosure filtering,
through rendering or credential issuance, and into audit records.

The version 0 done path is:

```text
claim config
  -> source connector
  -> ClaimResult
  -> ClaimResultView
  -> canonical JSON, CCCEV, or SD-JWT VC
  -> audit record
```

### Required Capabilities

Discovery:

- `GET /.well-known/evidence-service` advertises service identity, API version,
  enabled operations, auth audience, format URL, claim URL, and inline batch
  limit.
- Version 0 discovery advertises the identity mapping boundary as
  `common_subject_id` with `production_mapper: false`.
- `GET /claims` and `GET /claims/{claim_id}` return only claims visible to the
  authenticated caller.
- `GET /formats` returns canonical JSON, CCCEV JSON-LD, and SD-JWT VC status.

Evaluation:

- `POST /claims/evaluate` computes these fixture claims:
  `date-of-birth`, `farmed-land-size`, and `farmer-under-4ha`.
- `date-of-birth` is served through the DCI connector or CRVS-profiled DCI
  fixture.
- `farmed-land-size` is served through the Registry Data API connector.
- `farmer-under-4ha` is a CEL claim derived from `farmed-land-size`.
- The `extract`, `exists`, and `cel` rule paths are implemented.
- The CEL implementation reuses `cel-mapping` expression runtime semantics,
  preferably through `cel-mapper-core` standalone evaluation, and enforces the
  explicit version 0 feature allowlist.
- Every successful evaluation creates an internal `ClaimResult`, then an
  authorized `ClaimResultView` before any renderer or issuer receives data.

Batch:

- `POST /claims/batch-evaluate` is inline only in version 0.
- Batch evaluation computes `farmer-under-4ha` for multiple subjects.
- Batch responses preserve input order, include one item per input subject, and
  include per-item `evaluation_id` values for successful items.
- One subject failure does not hide successful results for other subjects.
- Requests above the configured inline limit return `batch.too_large`.
- Repeated batch requests with the same `Idempotency-Key` deduplicate within
  the configured window.

Rendering:

- Canonical JSON rendering works for one scalar claim and one boolean claim.
- CCCEV JSON-LD rendering works from the same `ClaimResultView`.
- `POST /evidence/render` renders only from an existing `evaluation_id`.
- Rendering enforces the original binding and cannot widen disclosure, claims,
  purpose, requester, or format.

Credential issuance:

- `POST /credentials/issue` signs an SD-JWT VC from an existing
  `evaluation_id`.
- Credential issuance signs only an authorized `ClaimResultView`.
- Credential issuance cannot recompute claims.
- Credential issuance returns `credential.issuer_not_configured` when issuance
  is requested for a claim or format without issuer configuration.
- SD-JWT VC issuer config includes issuer key reference, `vct`, allowed claims,
  validity period, holder-binding mode, and disclosure policy.
- SD-JWT VC issuance constructs `_sd_alg`, `_sd`, salted disclosures, JOSE
  `typ: "dc+sd-jwt"`, `kid`, `vct`, and holder binding according to the
  configured credential profile.

Security, metadata, and audit:

- Authentication gates discovery, evaluation, batch, rendering, and credential
  issuance.
- Authorization is claim-aware, purpose-aware, format-aware, and
  disclosure-aware.
- Source metadata validates the `farmed-land-size` field type and unit.
- A metadata conflict disables or rejects the affected claim and emits an
  operator-visible signal.
- Audit records are emitted for evaluation, batch evaluation, rendering,
  issuance attempts, source errors, authorization failures, and partial
  failures.
- Audit records pseudonymize subject identifiers by default and never contain
  secrets, bearer tokens, connector credentials, unrestricted source records, or
  forbidden claim values.
- External canonical JSON responses do not expose internal-only source refs,
  alternate subject IDs, requester IDs, or audit-only purpose details unless
  explicitly authorized.

Extension boundaries:

- The ID Mapper boundary exists and is exercised by a demo or test mapper, but
  production ID mapping is not required in version 0.
- OOTS profile fields can be declared in claim configuration and surfaced in
  discovery metadata, but the core REST API does not claim OOTS wire
  compliance.
- Search, background jobs, plugin execution, federation execution, production
  ID mapping, production record matching, OOTS EDM exchange, and credential
  revocation/status are not exposed as implemented version 0 capabilities.

### Required Tests

Version 0 must include focused tests for:

- discovery filtering by caller authorization;
- format discovery with SD-JWT VC enabled and issuer missing states;
- successful `date-of-birth` evaluation through DCI or CRVS-profiled DCI;
- successful `farmed-land-size` evaluation through Registry Data API;
- successful `farmer-under-4ha` CEL evaluation;
- successful inline batch evaluation;
- partial batch failure;
- batch input order and per-item `evaluation_id`;
- batch too large returning `batch.too_large`;
- batch idempotency with `Idempotency-Key`;
- unknown or hidden claim;
- unsupported operation;
- unauthorized claim evaluation;
- forbidden disclosure profile;
- missing or invalid purpose when required;
- source record not found;
- source ambiguity where one record is required;
- metadata conflict disabling or failing a claim;
- CEL expression validation and execution;
- CEL root binding semantics aligned with `cel-mapping`, including `source`,
  `claims`, `ctx`, `vars`, and `meta`;
- CEL rejection for undeclared fields or disallowed functions;
- CEL rejection for regex matching in version 0;
- canonical JSON rendering;
- CCCEV rendering from a `ClaimResultView`;
- render-by-`evaluation_id` binding denial for broader disclosure;
- render-by-`evaluation_id` positive rendering for an authorized format;
- disclosure downgrade to default or redacted profile where configured;
- disclosure denial where downgrade is `deny`;
- credential issuance from an existing evaluation;
- credential issuance denial when issuer configuration is missing;
- credential issuance denial when requested claims, format, purpose, requester,
  or disclosure exceed the original evaluation binding;
- credential issuance proof-of-possession enforcement when holder binding is
  `jwk` or `did`;
- credential artifact does not contain `evaluation_id`;
- ID Mapper demo roundtrip;
- OOTS metadata surfaced in discovery without OOTS wire-compliance claims;
- deferred routes or features hidden from discovery or returning stable
  not-supported errors;
- audit record content assertions for caller, purpose, claim ids, source
  connectors, pseudonymized subject reference, and absence of secrets or
  unrestricted source records.

### Not Done If

Version 0 is not done if any of these are true:

- CCCEV, SD-JWT VC, or an OOTS model is the internal computation model.
- A renderer recomputes claims instead of consuming `ClaimResultView`.
- An external canonical JSON response exposes internal-only source references,
  alternate subject identifiers, requester identifiers, or audit-only purpose
  details without explicit authorization.
- Rendering an existing evaluation can broaden disclosure, claims, purpose, or
  format.
- Downstream registry credentials allow the caller to see more than disclosure
  policy permits.
- Search, background jobs, plugin execution, federation execution, production
  record matching, or OOTS EDM exchange appear as implemented version 0
  capabilities.
- Unsupported search silently scans a full registry.
- Search is presented as an OOTS Common Services or evidence-exchange
  operation.
- OOTS compatibility is implied without an explicit OOTS adapter or profile.
- Batch evaluation fails the whole request because one subject has a source,
  authorization, ambiguity, or missing-data error.
- Source metadata conflicts are ignored or silently coerced.
- Audit logs contain raw secrets, bearer tokens, connector credentials, or
  unrestricted source records.
- Any v0 deferred item is described as implemented without a working API,
  configuration, documentation, and focused tests.
- Complex computation is required from a plugin to satisfy a version 0 claim.
- Credential issuance recomputes claims instead of using an existing
  `evaluation_id`.
- SD-JWT VC issuance is advertised as enabled but cannot sign the required
  fixture credential from an existing evaluation.
- The issued SD-JWT VC omits required SD-JWT VC structures such as `_sd_alg`,
  `_sd`, salted disclosures, `typ: "dc+sd-jwt"`, `kid`, or `vct`.

## Remaining Open Questions

- Which current Registry Relay evidence offerings should be migrated first as
  examples, and which should stay as verification-only flows?
- Which SD-JWT VC credential status and revocation model should be added after
  the first issuance implementation?
- Which OOTS EDM request and response shapes should the first adapter support
  after the core v0 service is implemented?

## Code Location

The Evidence Server should start inside the existing Rust workspace as separate
crates, not inside the `registry-relay` binary's `src/api` tree. This keeps the
implementation close enough to reuse current metadata, auth, and demo assets
while keeping extraction to a separate repository possible later.

Recommended workspace layout:

```text
crates/evidence-core/
crates/evidence-server/
```

Wave 0 must add these crates to the workspace `members` list before feature
work starts.

`crates/evidence-core` owns:

- `ClaimDefinition`;
- `ClaimResult`;
- `ClaimResultView`;
- `EvidenceArtifact`;
- simple predicates;
- CEL predicate evaluation;
- extension plugin traits after version 0;
- source connector traits;
- renderer traits;
- metadata validation;
- shared error codes.

`crates/evidence-server` is both a library and a binary crate. The library owns
the service assembly and protocol client implementations so tests and demos can
reuse them without depending on a running process. The binary owns process
startup, configuration file loading, server binding, and shutdown.

`crates/evidence-server` owns:

- Axum routes;
- configuration loading;
- authentication and authorization wiring;
- audit wiring;
- DCI connector implementation;
- Registry Data API connector implementation;
- inline batch handling;
- credential issuance wiring;
- OpenAPI and API examples.

Registry Relay should get only thin compatibility or demo adapters, such as a
Registry Data API source implementation and an evidence-offering-to-claim
mapping adapter. Claim computation code should not be added to
`src/api/evidence_offerings.rs`; doing so would keep the evidence-generation
responsibility inside Registry Relay instead of extracting it.

Pure connector traits and shared value types belong in `evidence-core`.
Connector implementations that require HTTP clients, auth wiring, retries, or
Axum-adjacent configuration belong in the `evidence-server` library unless they
prove reusable enough to move into a separate connector crate later.

If Registry Relay needs to implement a source adapter during migration, it
should depend on `evidence-core` for connector traits and shared types. It
should not depend on the `evidence-server` binary or service assembly.

## Implementation Plan

Implementation should proceed in waves with parallel workers on disjoint
surfaces. Each wave closes only after code review, focused tests, docs or
examples, and the relevant definition-of-done items are satisfied. A feature is
not complete when its route exists; it is complete when the configured behavior
works end to end, denies unsafe requests, emits audit records, and has focused
tests.

### Wave 0: Contracts And Skeleton

- Worker A owns workspace setup, `crates/evidence-core`,
  `crates/evidence-server`, service startup, config loading, and route
  skeletons.
- Worker B owns domain types: `ClaimDefinition`, `ClaimResult`,
  `ClaimResultView`, `EvidenceArtifact`, disclosure profiles, error codes, and
  audit event shapes.
- Worker C owns fixture config and sample data for `date-of-birth`,
  `farmed-land-size`, and `farmer-under-4ha`.
- Worker D owns API examples and initial OpenAPI or route documentation.
- Review gate: reviewers check naming, crate boundaries, route shape, and that
  CCCEV, SD-JWT VC, OOTS, plugins, search, and federation are not internal
  computation models.
- Done gate: workspace members exist, draft routes compile, discovery returns
  config-backed claims and formats, Problem Details errors are stable, examples
  match schemas, and route smoke tests pass.

### Wave 1: Evaluation And Connectors

- Worker A owns `extract` and `exists` evaluation.
- Worker B owns CEL validation and execution using the `cel-mapping` expression
  runtime boundary. If `cel-mapper-core` does not expose arbitrary root
  bindings, Worker B owns adding that reusable API there. Worker B splits a
  lower-level expression crate only if the clean `cel-mapper-core` extension
  would force Evidence Server to depend on PublicSchema-specific mapping
  behavior.
- Worker C owns the Registry Data API connector and `farmed-land-size` fixture.
- Worker D owns the DCI connector and `date-of-birth` or CRVS existence fixture.
- Review gate: reviewers trace each fixture from request input, through source
  binding, connector lookup, rule execution, `ClaimResult`, and audit event.
- Done gate: the three fixture claims evaluate successfully, connector errors
  map to stable Evidence Server errors, CEL rejects undeclared fields and
  disallowed functions, metadata validates the land-size type and unit, and
  metadata drift disables or rejects the affected claim with an operator-visible
  signal.

### Wave 2: Disclosure, Rendering, And Auth

- Worker A owns authentication, purpose validation, and claim/format/disclosure
  authorization.
- Worker B owns `ClaimResultView` construction and disclosure downgrade or
  denial behavior.
- Worker C owns canonical JSON rendering from `ClaimResultView`.
- Worker D owns CCCEV JSON-LD rendering from `ClaimResultView`.
- Review gate: reviewers attempt disclosure widening through evaluate and
  render, including broader claim sets, broader disclosure, different purpose,
  different requester, and unsupported format.
- Done gate: renderers never receive raw `ClaimResult`, render-by-evaluation id
  succeeds for authorized requests, render-by-evaluation id fails for widened
  requests, canonical JSON and CCCEV render from the same view, and audit
  records avoid secrets, raw source records, and forbidden claim values.

### Wave 3: Inline Batch And Credential Issuance

- Worker A owns inline batch evaluation, input ordering, partial failure, batch
  size limits, and idempotency.
- Worker B owns SD-JWT VC issuer key infrastructure: `issuer_key_ref`, `kid`,
  JWKS or DID-document publication path, and key rotation metadata.
- Worker C owns SD-JWT VC credential assembly: `typ: "dc+sd-jwt"`, `_sd_alg`,
  `_sd`, salted disclosures, `vct`, validity, and omission of `evaluation_id`
  from the signed artifact.
- Worker D owns credential authorization, holder binding, proof-of-possession,
  issuer-missing errors, and audit coverage for batch, render, and issuance
  attempts.
- Review gate: reviewers test abuse cases for batch partial failure, repeated
  idempotent requests, credential issuance without issuer configuration,
  credential issuance with widened claims or disclosure, and downstream
  credential overreach.
- Done gate: inline batch returns per-subject results and errors without hiding
  successful items, `batch.too_large` works, idempotency works, issuance signs
  only an authorized `ClaimResultView` from an existing evaluation, issuance
  never recomputes claims, holder proof-of-possession is enforced when
  configured, SD-JWT VC structures are present, and all required batch and
  issuance tests pass.

### Wave 4: Extension Boundaries And Release Candidate

- Worker A owns ID Mapper demo boundary and result metadata.
- Worker B owns OOTS profile metadata in configuration and discovery, without
  OOTS wire exchange.
- Worker C owns explicit disabled or not-exposed behavior for deferred features:
  search, background jobs, plugin execution, federation execution, production
  record matching, and credential revocation/status.
- Worker D owns final docs, OpenAPI or API reference, release checklist, and CI
  hardening.
- Review gate: reviewers perform architecture, security/privacy, and code
  reviews focused on regressions, missing tests, incomplete DoD items, and
  accidental exposure of deferred features.
- Done gate: every required v0 capability and test is checked off, deferred
  features are hidden from discovery or clearly marked unsupported, no "Not Done
  If" condition is true, and the repository's focused tests plus relevant lint,
  typecheck, build, and documentation checks pass.

### Review Cadence

- Each worker opens small, focused changes that touch only its owned surface.
- No wave closes until another worker or reviewer has reviewed the code and
  the implementation has passing focused tests for that wave.
- Cross-surface integration happens at the end of each wave, not only at the
  end of the project.
- Reviewers explicitly check the definition of done, not just code style.
- Any partially implemented behavior must be disabled, hidden from discovery,
  or listed as a deferred blocker with the exact reason.
