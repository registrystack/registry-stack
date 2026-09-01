# Relay V2 Product Concept

Status: Approved product direction
Date: 2026-08-10
Basis: Registry Stack `origin/main` at the start of the Relay V2 exploration

Directional inputs: the written GovStack Digital Registries specification and
API Design Guide as inspected on 2026-08-09. Both are early drafts that Relay
can help improve. They are design inputs, not conformance authorities. The
legacy Digital Registries OpenAPI is explicitly excluded because it does not
represent the current written model.

## Executive position

Relay V2 publishes one existing authoritative Registry as governed,
semantically interoperable, read-only registry resources.

SQLite is the first source adapter, not the product identity. The product is the registry contract and the compiler that turns that contract into a controlled API, semantic and governance metadata, validation artifacts, and auditable runtime behavior.

The concise promise is:

> Give Relay an authoritative SQLite database and a registry contract. Relay produces a protected registry API whose meaning, disclosure, authorization, provenance, and documentation agree by construction.

Relay V2 follows the method that made Evidence tractable: a narrow product boundary, sealed compiler-produced artifacts, deterministic runtime behavior, explicit security invariants, coequal acceptance fixtures, and generated contracts checked for drift.

## What the product accepts and produces

An adopter supplies:

- an authoritative SQLite database or reviewed SQLite views;
- a small registry contract describing resources and their source bindings;
- deployment configuration for token issuers, authentication, audit, and limits;
- optional curated mappings to external vocabularies and privacy frameworks.

Relay produces:

- a read-only registry API over explicitly declared resources;
- ordinary JSON, equivalent JSON-LD, and opt-in GeoJSON Point representations;
- OpenAPI, JSON Schema, SHACL shapes, contexts, codelists, and discovery metadata;
- derived Consultation capabilities and a concise standards-alignment note;
- generated local semantics when the adopter has no existing vocabulary work;
- controlled disclosure, safe requester minimization, and access decisions;
- versioned provenance and value-free audit events;
- reproducible validation, fixture, and change-impact reports.

All outputs derive from one compiled contract. Tables and columns never become public merely because they exist in SQLite.

## Runtime and adopter tooling

Relay V2 has an explicit runtime and tooling pair:

| Component | Responsibility |
|---|---|
| `relay` | Authoritative contract compilation, validation, serving, access decisions, disclosure planning, artifact semantics, and fixture evaluation. |
| `relayctl` | Project scaffolding, SQLite inspection, semantic and classification starter generation, validation orchestration, artifact generation, fixture runs, change-impact reporting, and deployment packaging. |

The new adopter-tooling crate is `registry-relayctl` and its binary is `relayctl`.

`relayctl` and `relay` use the same Relay compiler and fixture library. `relayctl`
may own authoring-only workflows, but it must not invoke a second compiler,
parse human CLI output, or implement a second interpretation of Relay
semantics. A frozen subprocess protocol is unnecessary until a consumer other
than the in-tree tooling needs one.

Relay V2 was scoped to leave the earlier `registryctl` adopter tool untouched: it depends on nothing in that tool and provides no compatibility layer through it. `registryctl` and the Relay 1.0 runtime it authored for were retired in v0.19.0, after this concept was approved, so `relayctl` is now the only Relay adopter tool.

The intended authoring lifecycle is:

```text
init -> inspect -> check -> generate -> test -> diff -> package
```

Inspection is schema-only by default. Any future value sampling must be explicit, local, bounded, and value-free in its output. Generated semantics and classifications are suggestions until reviewed.

## Core product features

### Contract-first registry publication

A Relay deployment describes exactly one Registry. The Registry has a globally
stable identifier, name, Registry Authority, optional operator, authoritative
scope, base URI, authored standards-alignment targets, resources, operations,
and optional pre-aggregated statistical datasets. Compiler-owned binding
profile versions are derived metadata, not authored alignment targets. The
Registry Authority is accountable for the Registry in its declared scope. It
is not automatically the same party as the privacy controller, publisher, or
technical operator.

A Relay resource is a governed Record type or collection within that Registry,
not a table and not a second Registry. It has a stable identity, semantic class,
identifier strategy, declared properties, a reviewed source view, compiled
operations, disclosure profiles, and access rules. Its enumeration posture is
derived from those compiled operations rather than authored separately.

The source schema and public schema are deliberately separate. One table may support several resources, several tables may feed one reviewed view, and unconfigured database objects remain invisible.

The compiler rejects incomplete or inconsistent contracts before serving. It also detects drift in live databases and never silently widens the public contract.

### Native Registry Record context

Every resource declares governed `datasetIdentifier` and
`entityTypeIdentifier` values beside its `id`. Every successful JSON or
JSON-LD response carries this non-selectable homogeneous context once in
response `meta`:

- `registryIdentifier`;
- `datasetIdentifier`;
- `entityTypeIdentifier`.

Every returned Record carries:

- `recordIdentifier`;
- `revisionIdentifier`;
- `lifecycleState`;
- `schemaReference`;
- `semanticModelReference`;
- `authorityIdentifier`;
- `recordedAt`;
- `domainData`, containing only the authorized and requested domain properties.

The pair `(registryIdentifier, recordIdentifier)` identifies a Record. The
record identifier is stable and cannot be reassigned. JSON-LD adds a derived
global `@id` and the resource semantic class as `@type`, but neither replaces
or changes the authoritative record identifier. Records do not duplicate the
three response-level context identifiers. GeoJSON remains under its separate
media profile and shape.

Record identifier, record revision, lifecycle state, and recorded time are
explicitly bound from the reviewed source view. Registry identity, authority,
schema, and semantic-model references come from the governed contract.
`recordedAt` is the authoritative revision-recorded time, never Relay startup,
snapshot, or response time. Source, contract, operation, disclosure, response,
and Record revisions remain distinct concepts.

Relay can validate current identifiers and compare successive synthetic
snapshots, but a single current SQLite file cannot prove that an institution
has never reassigned an identifier. `relayctl` therefore records the reviewed
identifier lifecycle policy and can compare successive fixture snapshots as
alignment evidence. The institutional guarantee remains named as such.

### Registry API families

API families are external capability and trust groupings. They are not crates,
services, URL prefixes, or an invitation to implement every family.

Relay V2 implements only the capabilities actually compiled for a Registry.
Registry Core resources support these Consultation patterns:

- identifier read maps to `consultation.retrieve`;
- collection list maps to `consultation.list`;
- named exact lookup maps to a constrained `consultation.search` profile.

Exact lookup is not Record Match. Relay returns no candidates, confidence, or
matching explanation. Family and pattern identifiers are attached to compiled
operations and generated into capability discovery. They are not repeated in
an independently authored capability list and do not appear in route names.

An explicitly declared pre-aggregated statistical dataset compiles the
Aggregate Data `statistical-dataflow` pattern. `statisticalDatasets` remains
separate from Record resources and format-neutral: it governs a snapshot view,
dimensions, one annual, quarterly, monthly, or daily time dimension, one
measure, attributes, publication facts, classification, exactly one fixed
access rule, and query bounds. A required `bindings.sdmx` selects a one-way
binding. It does not turn the authoring contract into an SDMX DSD and does not
add access profiles.

The compiler derives stable dataflow and DSD identities, exact dataflow and
datastructure package artifacts, and an aligned SDMX read subset. The only
routes are keyed data, its omitted-key alias, dataflow structure, and
datastructure structure. Queries accept compiled dimension equality and the
bounded time constraints of that subset. Relay executes only compiler-owned
bound SQLite predicates whose parameter storage classes match the declared
component types. SDMX-JSON preserves declared string and number types;
SDMX-CSV is an equivalent wire representation. Relay never infers a dataset
from arbitrary rows or performs caller-directed aggregation.

The binding implements the SDMX REST 2.2.2 read subset with SDMX-JSON,
SDMX-CSV, and Structure JSON 2.1.0. Those versions are compiler-owned profile
metadata, not adopter-authored `alignmentTargets`. Digest-locked official JSON
schemas validate generated outputs only through explicit temporary fetch or an
external cache; upstream schema bytes are not vendored. This is an alignment
claim for a narrow read subset, not full SDMX conformance.

Relay V2 does not claim Provisioning, Evidence, Write, Notification, another
Aggregate Data pattern, Access Transparency, or Identity Federation. `relayctl` is offline
authoring tooling, not a Provisioning API. Internal audit is not an Access
Transparency service. OAuth protection and optional Mint issuance are not
Identity Federation. Registry Evidence remains a separate product.

The draft Digital Registries target is recorded as an `alignmentTarget`, and
the generated mapping is `alignmentEvidence`. Relay does not claim GovStack
certification, Digital Registries conformance, or the future Base Registry
profile. A deployment advertises only the Consultation or statistical-dataflow
patterns it actually compiles.

### Semantic by default, without an expert prerequisite

Relay always has a basic semantic model, but adopters do not need JSON-LD or SHACL expertise to begin.

Authoring tooling can generate a stable local vocabulary from the reviewed resource definition and SQLite schema:

- local class and property IRIs;
- datatypes and cardinalities;
- identifier and codelist candidates;
- labels, descriptions, codelist candidates, JSON-LD context, SHACL, and JSON Schema.

Generated semantics are marked as local and generated. They make no automatic claim of equivalence with SEMIC, PublicSchema, schema.org, or another external vocabulary. Curated mappings are optional, versioned, and state their relation strength, such as exact, close, broad, narrow, or related.

The progression is therefore:

1. generated local semantics;
2. curated local semantics;
3. optional alignment with external profiles.

Relay uses semantics during compilation and serialization. They are not a decorative catalog attachment and are never fetched or inferred at runtime.

### Classification and privacy processing

Classification belongs primarily to the published property. Its SQLite column or view column is the source binding. This matters because published properties can be derived, renamed, combined, or reused in different disclosures.

Every reviewed source-view column also has a technical handling classification.
A simple property binding inherits its property's handling unless the source is
explicitly more restrictive. Registry Core, selector, row-binding, revision,
filter, and order columns that are not published properties declare their own
classification. Hidden columns remain classified and auditable even though
they are never serialized. The compiler rejects an unclassified reviewed
column and applies the most restrictive source and output handling to the
operation.

The model distinguishes:

- domain meaning: what the property represents;
- privacy category: whether it is personal, identifying, sensitive, derived, or another governed category;
- institutional classification: the operator's own classification scheme;
- technical handling: the controls Relay must enforce.

Classification entries carry a scheme, value, provenance, status, and version. Generated classifications are suggestions until reviewed. Unclassified published properties fail the production profile.

A resource may declare reviewed classification defaults and properties or
hidden columns declare only exceptions. Defaults are expanded during
compilation, so the effective classification remains complete without
repeating the same four values on every column.

Classification is monotonic for security: uncertainty or a more restrictive classification may reduce availability, but metadata changes never expand access automatically.

The initial technical handling vocabulary is ordered: `public`, `internal`,
`confidential`, and `restricted`. `public` may be anonymously released only by
an explicitly public operation. Every non-public level requires authentication,
an operation scope, `no-store`, and durable value-free audit. `confidential`
and `restricted` also prevent public classification and processing metadata;
`restricted` cannot be exposed through collection listing. Purpose and
authority-to-row binding remain explicit reviewed access constraints rather
than being guessed from a classification label. The compiler applies the most
restrictive effective handling level across the selected Record properties and
rejects any weaker operation or metadata posture.

[Data Privacy Vocabulary 2.3](https://w3c-cg.github.io/dpv/2.3/dpv/) is a strong optional governance profile. Domain vocabularies describe what a registry fact means; DPV describes why and how it is processed, the parties and recipients involved, the applicable purpose and legal context, and the technical or organisational measures associated with disclosure.

Relay may generate an optional DPV starter from the registry contract and let
adopters curate it. A DPV document is a governance sidecar, not a prerequisite
for serving a valid Registry or a runtime policy input.

DPV remains a semantic projection, not Relay's policy language. Relay executes its small typed access contract, never arbitrary RDF, DPV rules, ODRL, or remote vocabulary content. DPV 2.3 is a W3C Community Group report rather than a W3C Recommendation, so the profile and vocabulary digest must be pinned and upgraded deliberately.

### Schema-only identification and reviewed access profile governance

Relay keeps one classification model. `semanticTerm` describes meaning;
`privacy`, `institutional`, and `handling` describe the Registry Authority's
governance context; `status` is `suggested`, `uncertain`, or `reviewed`; and
`provenanceRef` identifies the review evidence. Identification proposes
candidates for that model. It neither changes runtime authorization nor creates
a second generic tag model.

`relayctl inspect` and `relayctl generate` identify only from observed SQLite
schema, declared types, key metadata, codelist bindings, authored roles, and a
digest-pinned embedded core rule pack. They do not read source values. A
candidate records its source and view, source column, suggested property,
semantic term and technical role, privacy candidates, matched rule identifiers
and versions, pack identity, categorical confidence (`exact`, `strong`,
`weak`, or `conflict`), and non-reviewed status. A conflict is `uncertain`; a
generated result never self-approves.

Generation writes deterministic, value-free review inputs beneath its output
directory at these fixed paths:

- `generated/reports/identification-report.json`
- `generated/reports/classification-inventory.json`
- `generated/reports/access-profile-report.json`
- `generated/reports/contextual-review-findings.json`
- `generated/governance/classification-review-starter.yaml`

After review, a generated project copies the accepted report to
`reports/identification-report.json`. The governed reviewed input is
`governance/classification-review.yaml`, named
by the existing `classifications.provenanceRef`. Its closed sidecar has
`apiVersion: relay.registrystack.org/classification-review/v1`,
`kind: ClassificationReview`, `registryIdentifier`,
`classificationInventoryDigest`, `method` (`generated`, `imported`, or
`manual`), `reviewer`, `reviewDate`, `status`, and `rationaleRef`. A
`generated` review also has `generatedIdentification` with `reportRef`,
`reportDigest`, and `rulePack: {id, version, digest}`. Production compilation
refuses a missing, non-reviewed, stale, or digest-mismatched sidecar. Manual
and imported review are first-class and do not require a generated report. A
relevant contract, schema, source-column, or classification change invalidates
review; a rule-pack change does so only when that pack informed it.

Every property has its own output classification. Every processed source
column has its own reviewed source-column classification. The compiler derives
processing handling from every Registry Core, output, transform input,
selector, filter, order, and row-binding column, and disclosure handling from
properties serializable by the access profile. Source processing controls,
authentication, audit, and cache use the processing floor even when a reviewed
output has lower disclosure handling. Anonymous publication cannot transform a
non-public source: a public access profile must read a reviewed pre-derived
public SQLite view column.

Only two finite deterministic transforms are in this profile. `partial-string`
accepts a reviewed string and emits Relay's fixed `***` marker plus a bounded
Unicode-scalar prefix or suffix; a value no longer than the configured reveal
length emits only `***`. `date-precision` accepts a reviewed canonical `date`
or `date-time` and emits `year` or `year-month`. Null, incompatible,
non-canonical, or oversized required inputs fail closed without values; an
optional null omits the property. A transformed value has its own property,
semantic term, datatype, and classification. Hashing, pseudonyms, encryption,
regular-expression replacement, caller-defined masks or expressions,
geographic and numeric transforms, codelist remapping, and any dynamic policy
engine are not part of this release.

### Registry operations and safe requester minimization

A resource compiles only the operations its publisher declares: collection
listing, identifier read, named exact lookup, and named Point-bbox search. A
resource may expose any appropriate subset. Lists and named searches remain
separate operations with independent access profiles and scopes.

Collection queries use publisher-defined, typed, camelCase filter parameters
directly in the query string, for example `status=ACTIVE`. Version one supports
exact equality. Any non-empty subset of declared filters is valid; the contract
separately declares whether an unfiltered request is allowed. `pageSize`,
`cursor`, `fields`, `accessProfile`, `formatProfile`, and `bbox` are reserved names. Filters in query strings are
limited to non-personal selectors. Relay binds their values as SQL parameters.
Transforms are response-only: a transformed property cannot be a filter or
fixed-order key because doing so would compare or order its undisclosed raw
input. A Registry that needs that query shape exposes a separately reviewed
pre-derived source property.
Callers cannot introduce source columns, joins, operators, expressions,
arbitrary sorting, or SQL.

Named exact lookups define their complete required inputs, row boundary, result shape, and maximum of one result. Sensitive selectors belong in a bounded request body rather than a URL. Lookup outcomes are deliberately non-enumerating and are subject to tighter limits and audit.

The selected access profile's disclosure profile supplies the maximum property
set. A caller may request a non-empty subset of those published properties, or
receive the complete selected profile when no subset is requested.
This is a one-way minimization control:

- it can remove top-level data properties but never add a property, select a source column, change a derivation, or bypass a row boundary;
- canonical envelope properties needed to identify and interpret the response remain present;
- property ordering and serialization remain contract-defined rather than caller-defined;
- unknown, duplicate, or otherwise invalid selections fail safely;
- Relay may read the complete fixed reviewed projection so it can validate the
  authoritative Record before disclosure. Unrequested and hidden columns are
  never serialized. Physical column-read minimization is an optimization, not
  a Version one correctness contract.

This is not dynamic attribute authorization. An operation has a finite ordered
map of reviewed access profiles, exactly one `defaultAccessProfile`, and one
access rule plus one disclosure profile per access profile. An absent
`accessProfile` selects that sole declared default. A supplied access profile
is authorized exactly as requested: denial, an invalid bearer, or an unknown
identifier never falls back to another profile. A syntactically valid unknown
name and a scope-hidden name receive the same `resource.not_found` response, so
callers cannot enumerate the finite map. Within the selected profile,
requester-selected `fields` can only disclose less and never lower the
operation's compiled handling level, authentication, audit, quota, metadata,
or cache posture. Caller-dependent or tag-derived profiles remain out of
scope.

### HTTP contract

The initial public binding is deliberately small:

```text
GET  /health
GET  /ready
GET  /openapi.json
GET  /v2
GET  /v2/resources?pageSize=...&cursor=...
GET  /v2/resources/{resource}
GET  /v2/resources/{resource}/records?pageSize=...&cursor=...&status=...&accessProfile=...&fields=...&formatProfile=...
GET  /v2/resources/{resource}/records/{recordIdentifier}?accessProfile=...&fields=...&formatProfile=...
POST /v2/resources/{resource}/lookups/{lookup}?accessProfile=...&fields=...&formatProfile=...
GET  /v2/resources/{resource}/searches/{search}?bbox=...&pageSize=...&cursor=...&accessProfile=...&fields=...&formatProfile=...
GET  /v2/artifacts/{artifactIdentifier}
GET  /sdmx/v2/data/dataflow/{agency}/{dataflow}/{version}/{key}
GET  /sdmx/v2/data/dataflow/{agency}/{dataflow}/{version}
GET  /sdmx/v2/structure/dataflow/{agency}/{dataflow}/{version}?references=none
GET  /sdmx/v2/structure/datastructure/{agency}/{datastructure}/{version}?references=none
```

`GET /v2` is the Registry service-metadata document. It publishes the Registry
identifier, name, Authority, operator, authoritative scope, product and API
binding versions, pinned authored alignment targets, derived visible
capabilities, and links to resources and artifacts. Registry identity is public;
resource, operation, schema, semantic, classification, and processing details
remain subject to their compiled visibility. Treating this service document as
an unpaginated collection is a recorded API-guide linter limitation, not a
reason to hide the first-class Registry.

Only compiled operations and visibility-appropriate metadata routes exist.
Record path identifiers are opaque and URL-safe. Personal or compound
selectors belong only in bounded named-lookup bodies. The lookup POST is a
naturally idempotent bounded consultation and returns at most one Record.

Lists use `pageSize`, `cursor`, and the envelope
`{items, pageInfo: {nextCursor}, meta}`. `nextCursor` is nullable. Ordering is
contract-defined with the Record identifier as a unique tie-breaker. The
client-opaque authenticated-encrypted cursor binds the contract and source
revisions, dataset, entity type, response profile, representation, operation,
selected access profile and disclosure profile, filters, order, selected
fields, authorization context, and expiry. Every page is
reauthorized. Encryption prevents its filter and keyset-order state from
bypassing field minimization. Callers treat it as an uninterpreted continuation
token and cannot choose an order or replay a cursor across access profiles.

Single-record reads and resolved lookups use `{data, meta}`. `data` contains
the Record core fields and `domainData`; `meta` contains the homogeneous
Registry, dataset, and entity-type context. `fields` is a documented Relay
extension: a non-empty, duplicate-free comma-separated list of public property
keys. A property key is the contract's URL-safe camelCase name, not a source
column or semantic IRI. Exactly one `fields` parameter is accepted; empty
members, whitespace, repeats, and duplicate keys are invalid. It only narrows
the selected access profile's `domainData`; Registry Record context cannot be
removed, and response ordering remains contract-defined rather than
request-defined. A field outside the selected access profile is rejected
before source access.

Ordinary JSON is the default. `application/ld+json` adds the shared Registry
Record context followed by the generated operation context, plus a derived
global `@id`, while preserving all Registry Record identifiers and
the same selected domain values. The operation context defines only Relay-owned
extensions and selected domain terms; it never redefines a shared Registry
Record term. Responses vary on `Accept`; unsupported wire
formats receive `406 format.unsupported`. Where caching is allowed, the strong ETag hashes
the exact response bytes, including the selected access profile, wire format, and field
subset, and supports `If-None-Match` with `304`. Only a public access profile
with a public processing floor over a snapshot and `pageInfo.nextCursor` absent
or null may be cacheable. Every cacheable public response includes
`Vary: Accept, Authorization` so an anonymous `200` cannot satisfy a request
carrying an invalid bearer. A response containing a non-null continuation
cursor, and every non-public or unversioned-live response, is `no-store` and
emits no ETag.

### Bounded Point profile

A resource may make one existing property its `primaryGeometry`. That property
uses `type: point`, the exact CRS84 identifier, and a strict `source` containing
only reviewed `longitudeColumn` and `latitudeColumn` carriers. It remains an
ordinary classified, selectable domain property. Its carrier columns are
processing inputs only and never become response metadata or independent
properties.

The resource may separately declare a named `point-bbox` search. The operation
requires one finite, ordered, non-wrapping CRS84
`bbox=west,south,east,north`, applies the contract's longitude and latitude
span limits, and owns its pagination, ordering, and finite access profiles.
List access neither accepts `bbox` nor grants access to the named search.

When the selected access profile discloses the primary geometry,
`Accept: application/geo+json` returns an RFC 7946 Feature or
FeatureCollection. `formatProfile=rfc7946` is the default and
`formatProfile=jsonfg` adds only bounded JSON-FG conformance and feature-type
metadata. Feature `properties` plus `geometry` carry exactly the same governed
disclosure as ordinary JSON. Omitting the primary geometry through `fields`
produces `geometry: null`. This profile does not claim OGC API Features
conformance and adds no generic geometry abstraction, CQL2, EDR, tiles,
reprojection, spatial joins, or dynamic spatial extension.

### Bounded statistical-dataflow profile

The SDMX routes in the HTTP contract section exist only for a compiled
`bindings.sdmx`. Data uses the frozen SDMX media types and supports a keyed
route plus the identical omitted-key alias. Structure reads expose only the
exact generated dataflow and DSD artifacts. Schema, availability, history, and
structure-maintenance routes do not exist. There are no placeholder responses
that promise those future surfaces.

The dataflow's one fixed access decision, metadata visibility, snapshot cache
posture, source revision, query ceiling, and audit gates apply identically to
data and structure routes. A protected dataflow without its scope is concealed
as `404 resource.not_found`; a known flow with a failed purpose or authority
binding is `403 aggregate-data.denied`. Attempt and terminal audit events
distinguish data from structure and bind the exact JSON or CSV bytes while
remaining free of query values, observations, authority values, and source rows.

The packaged deployment contains the full generated OpenAPI 3.1 contract. The
unauthenticated `/openapi.json` endpoint serves a deterministic safe public
projection and omits protected resources, selector shapes, and operator-only
metadata. Protected resource metadata and referenced artifacts use the same
compiled operation gate as the Record that links them. Relay never generates
caller-specific OpenAPI at request time.

Every `schemaReference` is a permitted-access-profile schema: Registry Core is
required, while a selectable `domainData` property is validated when present.
A separate operator validation schema and SHACL shape describe the complete
source Record and preserve source requiredness. `semanticModelReference` points
to the generated local vocabulary/model, not merely the JSON-LD context. The
context is linked separately in `meta`. The context expands response `data` and
`items` as RDF graph containers, nests `domainData` properties without a
transport predicate, and applies the same IRI and datatype constraints emitted
in the bound SHACL shape. Compilation fails unless every audience
that can receive a Record can also retrieve safe projections of the exact
schema and semantic model referenced by that Record.

Errors remain Registry Stack RFC 9457 problems with stable Registry Stack
`code` values and `https://id.registrystack.org/problems/...` type URIs. Relay
does not adopt draft GovStack BB codes or problem namespaces. V2 accepts W3C
Trace Context; every Problem `traceId` is the effective valid or server-created
trace ID as 32 lowercase hexadecimal characters. Caller-supplied `tracestate`
is never propagated because Relay cannot establish that vendor state is
value-free. Unknown, hidden, and ambiguous lookup outcomes use the same `404`
status, problem code, fixed detail, schema, cache and security headers,
differing only in independently generated trace correlation. A selected
malformed source Record, including invalid input to a compiled transform,
fails closed atomically as `503 source.unavailable`. Problems
never echo selectors, identifiers, source values, SQL, paths, tokens, or policy
internals.

### Derived enumeration posture

Every resource has one enumeration posture derived from its compiled list
operation:

- `public` requires a public list operation;
- `protected` requires a scope-protected list operation;
- `none` forbids a list operation.

The compiler validates these operation combinations. Discovery reports the
posture visible to the current caller, so a protected list appears as `none` to
a caller who cannot see that capability. This caller-relative view does not
change the resource's compiled maximum or create an additional policy input.

Read and named exact-lookup operations are declared independently with their
own access rules and disclosure profiles. This lets a resource expose protected
read plus exact lookup without pretending it is an enumerable collection.
Exact lookup is the preferred operation for registries containing people or
sensitive entities. Sensitive selectors belong in a bounded request body
rather than a URL. Caller-controlled SQL, joins, expressions, projection
expressions, and arbitrary sorting are never accepted.

Reviewed SQLite views are the source disclosure boundary. They exclude internal
columns, normalize public values, delink identifiers, implement reviewed
derivations, and expose only intended source bindings. Relay never accepts
caller-created projections. A request may only narrow the authorized compiled
disclosure profile described in the Registry operations and safe requester
minimization section.

### Small, explainable access decisions

The initial access model combines:

- a strictly verified OAuth 2.0 JWT access token when the operation is protected;
- one explicit access rule for each finite access profile, with an exact scope when protected;
- optional trusted purpose;
- optional authority-to-row binding from the resolved principal or a verified claim;
- the selected disclosure profile.

Purpose comes from, or is constrained by, verified authority. A caller header never creates authority. Principal binding is a compiler-declared equality boundary injected by Relay and cannot be replaced by caller filters.

The resource posture and contract define the maximum compiled operation set. Token scopes can only narrow it. Separate scopes for list, read, named lookup, and their finite access profiles allow an issuer to give a client exact-lookup access without collection or identifier-read access. A valid principal without the selected scope receives the same concealed `resource.not_found` outcome as an unknown operation. Conversely, no token can enable an operation or access profile the resource did not compile. Relay does not maintain a client registry; the trusted issuer registers clients and assigns scopes.

Each request produces a typed access decision followed by a typed disclosure plan. The plan contains the authorized operation and access profile, row constraints, selected disclosure profile, and any requester-selected property subset. This architectural seam keeps authentication, authorization, row constraints, query construction, and serialization separate. Version one uses static reviewed disclosure plans and does not require a general PDP, CEL, dynamic masking, per-client field permissions, or tag-based ABAC.

### Token issuers and optional Registry Mint

Relay is an OAuth 2.0 resource server. Protected operations accept a narrow
registered JWT access-token profile with strict issuer, audience, subject or
client, time, token identifier, algorithm, key, type, and scope validation.
Version one configures at most one trusted issuer per Registry deployment. Its
exact token `iss` value is distinct from its key transport: the deployment
chooses exactly one OIDC discovery URL or direct JWKS URL, and that transport
may use a different authority from the trusted issuer. Discovery metadata must
declare the trusted issuer exactly. Direct JWKS uses the configured trusted
issuer as the token-identity boundary, so its key endpoint is an operator-owned
out-of-band trust decision. Existing canonical discovery URLs may derive the
trusted issuer only from the canonical discovery suffix. Multi-issuer selection
waits for demonstrated deployments.

The token may come from an institution's existing identity provider or authorization server. Registry Mint is an optional issuer for machine-to-machine deployments that do not have one. Relay has no production runtime dependency on Mint and does not need to know which conforming issuer produced a token.

Mint issues product-neutral, registered scopes and audiences for Relay, with optional authority-controlled purpose and row-binding claims. Mint writes that authority server-side rather than copying authority from a caller. The real-router acceptance journey exercises the same Relay verifier and access-decision path used with an external issuer. This is an interoperability profile between two independent products, not a special Mint authentication mode in Relay.

Public operations may explicitly allow anonymous access. They still use the same compiled disclosure, validation, bounds, provenance, and audit model appropriate to public publication.

### Unsigned responses and Evidence composition

Relay V2 registry responses are not signed. TLS protects transport, access tokens protect controlled operations, and provenance, revisions, and tamper-evident audit support accountability. An ETag, source digest, or contract revision is useful integrity and cache metadata, but is not presented as a signature.

When a relying party needs a portable signed assertion with minimum disclosure, that remains Evidence's job. Evidence may use a Relay-protected exact lookup as an ordinary fixed HTTP source. The products compose without moving assertion signing or verification into Relay.

### Trust, visibility, and failure boundaries

A deployment names the Registry Authority, privacy controller, registry
publisher, Relay operator, token issuer, recipient classes, and audit owner.
One Relay process serves exactly one Registry in one administrative trust
domain. A Registry may contain several related resources under the same
authority and authoritative scope. Multi-registry hosting and multi-tenant
policy isolation are outside the initial core.

Registry service identity is public. Other discovery and governance metadata is
`public`, `operation-bound`, or `operator-only`. Operation-bound artifacts use
the same static access gate as the operation whose Record links them; separate
operation profiles receive separate safe artifacts where necessary.
Operator-only artifacts stay in the sealed package and CLI and are never
mounted. Semantic transparency must not accidentally publish sensitive schema,
selector, classification, or processing details.

Each Registry may publish one deterministic Registry Discovery provider
description through the existing public artifact route. The contract authors
only jurisdictions; compilation derives service identity, endpoint, public
roles, conformance, and capability identifiers. Protected-only operations
contribute no capability identifiers. Each exact public semantic-class and
operation-family pair is a separate binding identity, so JSON-LD or index
processing cannot combine capabilities from different resources. Source,
selector, access-policy,
credential, signing, audit, and runtime fields are outside the closed profile.

Exact lookup returns a stable unresolved outcome for no match, ambiguous match,
or a Record hidden by policy. A selected malformed source Record fails as
`source.unavailable`. Syntactically invalid requests receive a bounded public
error without echoing values. Relay never skips, coerces, or partially releases
an invalid selected source Record to keep a response successful.

`relayctl package` compiles and validates a complete contract revision and seals
the compiled Registry plus every artifact digest. Startup verifies that closed
package, recompiles the captured inputs to require exact equality with the
packaged runtime plan, and activates the packaged artifacts without regenerating
them. Relay never mixes revisions, falls back to a previous interpretation
silently, or hot-reloads a partially valid contract.

### SQLite source profiles

Relay supports two explicit SQLite profiles:

- snapshot: read-only immutable access, stable file identity and digest, no uncheckpointed sidecars, exact source revision, and digest verification before and after every statement execution;
- live read-only: another trusted process may update the database, while Relay keeps a fixed registry contract, uses a consistent read transaction per request, and verifies schema fingerprints when the SQLite schema changes.

Snapshot mode provides stronger reproducibility and provenance, but is optional. The deployment must make the captured file immutable outside Relay, preferably through a read-only mount; per-execution digest checks detect drift but cannot exclude a privileged writer that changes and restores bytes entirely between both checks. Live mode never claims the exact historical reproducibility of a captured snapshot. In both modes the Relay process has read-only operating-system and SQLite access, even though a trusted publisher may hold separate write access to a live database.

Snapshot responses identify the captured source digest and may support lists,
cursors, and validators. Version one live sources are deliberately unversioned:
they support read and exact lookup only, are always `no-store`, emit no ETag,
make no reproducibility claim, and carry `sourceRevision` with `profile: live`,
`status: unversioned`, and `value: null`. Publisher-owned revisions, live
pagination, and live caching are deferred until a real registry requires them.

### Audit, provenance, and change evidence

Every data request, including anonymous public access, durably records either a
refusal before returning or a pre-source attempt followed by a terminal
release, unresolved, or source-failed outcome. Audit is a source-access and response-release
gate. An event identifies the Registry, resource, operation, access-rule
revision, purpose when present, applied row-boundary kind, access profile,
disclosure profile, selected property identifiers or their digest, transform
identifiers, effective handling levels,
contract revision, and snapshot or live-source revision. Anonymous public
events use an explicit anonymous principal kind and no synthetic person
identifier. Audit contains no tokens, selector values, source values, response
values, or raw subject identifiers.

Audit covers requests processed by Relay. A permitted public shared-cache hit
does not reach Relay and therefore cannot create a Relay audit event; the
safeguards matrix names that observability boundary rather than implying
end-to-end access transparency.

The declared processing description, compiled access decision, and audit event share stable identifiers. This connects intended governance to enforcement and observed use without turning every audit event into RDF.

Authoring tooling compares contract revisions and highlights newly exposed
properties, relaxed classifications, wider enumeration or operation access,
removed row bindings, expanded purposes or scopes, changed source views, and
semantic mapping changes. Git and CI remain the review workflow; Relay does not
implement an approval portal.

### Safeguards evidence

Relay maintains a small evidence matrix:

```text
safeguard principle
-> concrete mechanism
-> enforcement point
-> negative test
-> generated or audit evidence
-> institutional responsibility outside Relay
```

This supports implementation evidence for the [Universal DPI Safeguards Framework](https://www.dpi-safeguards.org/framework), especially privacy by design, security by design, protection during use, transparency, evidence-led evolution, and open assets. Exact-lookup confinement, property-level classification, safe requester minimization, metadata visibility, value-free audit, and change-impact review provide concrete mechanisms rather than compliance labels. This is not certification and does not create lawful basis, inclusion practice, independent oversight, or remedy.

## Product boundary

Relay V2 is:

- a governed semantic registry publisher;
- a protected read-only API over existing authoritative data;
- a compiler and runtime for explicit registry contracts;
- a source of portable semantic, governance, alignment, verification, and audit evidence.

Relay V2 is not:

- a generic SQLite REST generator;
- a write API or registry administration system;
- a query language, SQL proxy, data lake, warehouse, or ETL platform;
- an RDF store, SPARQL endpoint, or inference engine;
- a general policy engine, PDP, consent service, or entitlement workflow;
- an automatic legal classifier or data-loss-prevention scanner;
- a credential or signed-assertion issuer;
- a grievance, eligibility, case-management, or identity-matching system;
- a multi-source analytics or interoperability-protocol suite;
- an extension, mode, or command group of the earlier `registryctl`.

PostgreSQL and other source adapters, SpatiaLite, richer geometry types, richer
semantic profiles, and additional registry protocols are later profiles.
Version one does not introduce a generic storage or geometry trait before
another concrete need proves either abstraction.

## Reuse from `registry-platform-*`

Relay V2 should reuse mature product-neutral primitives directly and avoid inheriting the current Relay product surface through them.

### Direct reuse

| Platform crate | Relay V2 use |
|---|---|
| `registry-platform-authcommon` | Strict bearer parsing and secret-safe authentication helpers. |
| `registry-platform-oidc` | OIDC discovery or direct JWKS transport, JWKS caching, and strict JWT access-token verification for one trusted issuer. Exactly one transport is configured; its authority never changes token `iss` validation. Add only missing product-neutral claim checks required by Relay V2; multi-issuer selection is deferred. |
| `registry-platform-httpsec` | Security headers, narrow CORS, request limits, and RFC 9457 problem responses extended by Relay with its stable code and trace ID. |
| `registry-platform-audit` | Tamper-evident envelopes, durable sinks, chain verification, redaction, and pseudonymization primitives. Relay V2 owns its event vocabulary and does not inherit old consultation semantics. |
| `registry-platform-config` | Environment expansion, secret references, and optional signed governed-bundle verification. Relay still owns compilation of the registry contract. |
| `registry-platform-canonical-json` | Deterministic revision, profile, and artifact digests. |
| `registry-platform-buildinfo` | Consistent binary and release identity. |
| `registry-platform-testing` | Mock OIDC, audit assertions, HTTP/security integration fixtures, and non-leak testing. |

### Selective or indirect reuse

- `registry-platform-crypto` is useful for signed configuration, digests, and pseudonymization support, but Relay V2 does not sign registry responses.
- `registry-platform-httputil` is used indirectly by OIDC. Relay's SQLite-only version has no general outbound data-source boundary.
- The retired `registry-platform-ops` crate was not reused; Relay owns its fixed readiness and audit behavior.
- Registry Mint is an optional conforming token issuer, not a platform dependency. Any wider audience, scope, purpose, or binding support belongs in Mint's own product-neutral token profile.

### Do not reuse in the initial core

- The retired `registry-platform-pdp` model was not reused: its broad context, ODRL, redaction, assurance, consent, jurisdiction, and credential-format model is outside the small Relay V2 access decision.
- `registry-platform-sdjwt`: signed assertions remain Evidence's responsibility.
- existing Relay API-key, state-plane, hot-reload, destination, materialization, policy, aggregate, and protocol-specific machinery.
- the retired and removed `registryctl` crate, commands, project model, or compatibility surface.

### Registry Manifest boundary

The Relay authoring contract is a strict Relay-owned `RegistryContract`. A
future portability command may compile it one way into a
`registry-manifest/v1` projection. Relay V2 does not need that projection to
compile, package, or serve. It is not a strict Registry Manifest profile because
Manifest intentionally does not own source columns, access rules, filters,
disclosure, classification, purpose, row binding, or runtime limits.

Relay access and execution fields must not be added to Registry Manifest. The
projection carries only portable registry, dataset, entity, property,
identifier, codelist, semantic, and service metadata that Manifest already
owns. The current Manifest entity and dataset model already provides titles and
descriptions; any future Manifest change must be narrowly portable and useful
outside Relay.

## What to extract from Evidence

The immediate product-neutral extraction is a hardened SQLite foundation named
`registry-platform-sqlite`.

Evidence already proves important snapshot behavior in its bundle and SQLite source code: stable file capture, digest and identity checks, sidecar refusal, immutable read-only opening, SQLite authorization, engine limits, progress cancellation, bounded concurrency, typed values, and value-free failures.

The extracted crate should own:

- safe snapshot and live read-only open profiles;
- snapshot identity, digest, and sidecar validation;
- live schema fingerprint support;
- defensive SQLite configuration and authorizer primitives;
- step, time, value, row, response, and concurrency bounds;
- safe error classification and typed row-reading helpers.

Evidence keeps its product semantics:

- one reviewed statement per source;
- the `evidence_extract` publication metadata contract and maximum age;
- selector-to-parameter binding;
- match, no-match, and ambiguous outcomes;
- fixed fact schemas, requirement derivation, and assertion construction.

Relay keeps its product semantics:

- resource and property bindings;
- format-neutral statistical dataset and one-way binding compilation;
- enumeration posture, operation access, and disclosure plans;
- identifier, predefined filter, named lookup, safe property selection, and pagination behavior;
- semantics, classifications, DPV processing descriptions, and registry serialization.

Other Evidence work should be reused as method before it is reused as code:

- atomic sealed-package verification and activation;
- closed artifact sets and deterministic revisions;
- value-free adopter diagnostics;
- fixed public problem classes;
- coequal acceptance definitions;
- security invariant and test traceability matrices;
- generated-contract drift checks;
- source-product neutrality checks;
- fail-closed release and audit gates.

No general contract compiler, policy evaluator, semantic model, or runtime pipeline should be extracted until two products have independently proven the same abstraction.

## Initial delivery shape

The first coherent Relay V2 release should contain:

1. the `relay` runtime with a concise authoring contract and offline compiler;
2. a separate `relayctl` for scaffolding, inspection, generation, testing, diffing, and packaging;
3. one first-class Registry per deployment and mandatory Registry Core context on every Record;
4. generated Consultation capability discovery and a concise Digital Registries alignment note;
5. generated local semantics, JSON-LD, JSON Schema, SHACL, full packaged OpenAPI, and safe public OpenAPI;
6. property classification with provenance and the `public`, `internal`, `confidential`, and `restricted` handling levels;
7. derived public, protected, or absent enumeration with independently compiled list, read, named-lookup, and named Point-bbox search operations;
8. `pageSize` and client-opaque authenticated-encrypted cursor lists, direct predefined equality filters, and safe caller selection of fewer properties than the selected access profile;
9. strict OAuth JWT access-token verification, operation scopes, trusted purpose, optional authority row binding, and an optional conforming Mint issuer;
10. snapshot and live read-only SQLite profiles, including useful unversioned live read and lookup deployments;
11. deterministic disclosure plans, bounded queries, stable `404` lookup outcomes, atomic activation, and Registry Stack problems;
12. unsigned registry responses with truthful Record, source, and contract revisions;
13. tamper-evident attempt, refusal, and pre-release audit gates;
14. fixture, schema-drift, contract-drift, change-impact, and security-safeguard checks.
15. snapshot-only pre-aggregated statistical dataflows with generated exact
    dataflow and DSD artifacts and the bounded SDMX read profile.

This is enough to establish Relay as a governed semantic registry publisher rather than a database API. Additional storage engines, richer geometry, policy, and protocol profiles can then be judged against that identity.

## Definition of Done and coequal acceptance registries

The detailed [Relay V2 Definition of Done](DEFINITION-OF-DONE.md) is the completion contract. Every required row must pass on one revision; one working SQLite endpoint or registry is not completion.

Four coequal acceptance deployments prevent the runtime from inheriting one
registry domain. They are four separate Registries exercised as independently
instantiated one-Registry services over real loopback HTTP, plus one packaged
real-process start, request, stop, and restart smoke:

- a sensitive social assistance registry proves exact-lookup-only consultation, trusted purpose, row binding, protected classification, and live SQLite;
- a public business registry proves deterministic list and identifier read, predefined filters, public semantic alignment, snapshot reproducibility, and caching;
- a protected civil-event registry proves separate read and lookup scopes,
  operation-specific disclosures, optional conforming Mint tokens,
  unversioned-live truthfulness, and the ordinary protected-source boundary a
  future Evidence integration can use.
- a labour-statistics registry proves separate format-neutral statistical
  datasets, snapshot-only bounded reads, fixed public and protected access,
  typed SQLite predicates, typed SDMX-JSON values, equivalent CSV, exact
  generated dataflow and DSD artifacts, and distinct value-free audit surfaces.

All four must use the same compiler, SQLite executor,
disclosure planner, serializers, access-decision types, audit vocabulary,
problem model, and adopter workflow. Focused parameterized compiler and runtime
tests prove that state cannot cross resource or statistical-dataset boundaries
without adding a fifth deployment project.
Production Rust and public generic contracts contain no social, business, or
civil-registration or labour-statistics domain branches.

The [Relay V2 Configuration Examples](CONFIGURATION-EXAMPLES.md)
exercise these four definitions and define the intended Version 1 authoring
shape. The generated schema makes their constraints precise.

## Decisions fixed for Version 1

- Relay owns a strict registry contract. A Registry Manifest projection is a later portability artifact, not the Relay execution contract.
- One contract and process serves one Registry, which may contain several resources.
- Registry Core context is mandatory and requester field selection can narrow only `domainData`.
- Lists use `pageSize`, `cursor`, `items`, and `pageInfo.nextCursor`; predefined filters are direct camelCase equality parameters. A named Point-bbox search owns its bounded `bbox` query and independent access profiles.
- Named exact lookup remains a bounded POST action and maps to constrained Consultation Search, not Record Match.
- `statisticalDatasets` is separate from resources, snapshot-only,
  format-neutral, and has one fixed access rule, required `bindings.sdmx`, one
  time granularity, and only the bounded dataflow read and structure routes.
- Each operation has finite reviewed access profiles, an explicit sole default,
  and access-profile-owned access plus disclosure. Dynamic, caller-derived
  entitlement variants are deferred.
- Handling levels are `public`, `internal`, `confidential`, and `restricted`; purpose and row binding are separate explicit constraints.
- Snapshot SQLite is valuable but optional. Unversioned live sources are `no-store` and do not compile paginated lists.
- A deployment configures at most one issuer in Version one. Responses are unsigned. Registry Mint is optional, never a Relay runtime dependency, and may be paired when it emits the same standard token profile.
- Registry Stack problem codes and type URIs remain canonical. GovStack compatibility is a later profile, not a core wire mode.
- The written GovStack drafts inform alignment. Their legacy OpenAPI does not.

## Deliberate future gaps

- caller-derived maximum disclosure entitlements, tag-based ABAC, external PDP,
  or per-profile quotas;
- publisher-owned live revisions, live pagination, and live caching;
- multi-issuer selection and a frozen `relay`/`relayctl` subprocess protocol;
- Registry Manifest, DPV, safeguards, and machine-readable GovStack alignment projections;
- formal GovStack conformance or a compatibility flag translating wire conventions;
- a Digital Registries family beyond Consultation or another Aggregate Data
  pattern beyond the compiled statistical dataflow;
- SDMX schema and availability routes, history, structure maintenance, dynamic
  aggregation, arbitrary operators, and large-result streaming;
- additional sources, SpatiaLite, generic or non-Point geometry, reprojection,
  and OGC API Features routes;
- dynamic masking, a general PDP, write operations, notification, access-history publication, and response signing.
