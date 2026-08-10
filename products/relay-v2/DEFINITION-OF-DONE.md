# Relay V2 Definition of Done

Status: Approved acceptance contract
Date: 2026-08-10
Product direction: [Relay V2 Product Concept](CONCEPT.md)
Configuration design probes: [Relay V2 Configuration Examples](CONFIGURATION-EXAMPLES.md)

GovStack Digital Registries and API Design Guide drafts are directional inputs.
The legacy Digital Registries OpenAPI is not an acceptance artifact. This DoD
requires a concise alignment note and intentional-difference records, not a
GovStack conformance or certification claim.

## Completion rule

Relay V2 is done only when every required row below passes on the same revision. A working SQLite endpoint, one successful registry, generated OpenAPI, or a green subset of tests is not completion.

The social, business, and civil-event registries are coequal acceptance definitions. None is the architectural seed, a privileged demo, or a later generality check. Production code, public schemas, routes, and CLI behavior remain registry-domain neutral.

No required behavior may remain as a stub, TODO, undocumented manual step, disabled test, or follow-up issue. Additional storage engines, SpatiaLite, GeoJSON, general policy evaluation, response signing, dynamic masking, and other future profiles are outside this Definition of Done.

## Coequal acceptance definitions

| Registry | Required shape | What it must prove |
|---|---|---|
| Social assistance enrolment | Live SQLite, exact lookup only, limited and caseworker representations, partial-string transform, trusted purpose, authority-to-row binding, external authorization server | A sensitive person-related registry can answer a bounded consultation without enumeration, selector disclosure, or domain-specific runtime behavior. |
| Business registration | Snapshot SQLite, public default plus protected registrar representations, predefined exact filters, pagination, public semantics | A genuinely public register can isolate a protected representation while its reviewed pre-derived public view remains discoverable and cacheable. |
| Civil event registration | Live SQLite, registrar and supervisory representations over protected identifier read and named exact lookup, date-precision transform, no list | A CRVS-shaped event register can prove exact lookup and representation scope separation without exposing a collection, coupling Relay to Mint, or moving signed assertions into Relay. |

Each definition must pass offline fixture evaluation and the real HTTP runtime
as its own one-Registry deployment. All three must use the same compiler,
access-decision types, SQLite executor, disclosure planner, serializers, audit
vocabulary, and problem model. Focused parameterized compiler and runtime tests
prove in-process resource isolation without adding a fourth deployment project.

## Definition of Done

| Area | Done when |
|---|---|
| Product boundary | One `relay` runtime and one separate `relayctl` implement the initial product. Relay is a read-only governed registry publisher, not a SQL proxy, write API, policy engine, credential issuer, or signed-assertion service. The existing `registryctl` is unchanged and unused by Relay V2. |
| Governed contract | A concise, closed, versioned authoring contract defines resources, optional pre-aggregated statistical datasets, source views, identifiers, properties or statistical components, finite representations or publication bindings, operations, semantics, classifications, access rules, bounds, and metadata visibility. Each Record operation has one `defaultRepresentation`; each ordered `representations` entry owns exactly one `access` rule and `disclosureProfile`, while query shape remains operation-owned. Unknown fields are rejected. A deployment file may bind paths, listeners, one issuer, secrets, and audit storage but cannot override governed behavior. |
| Registry identity | One contract and process describes exactly one Registry with a globally stable `registryIdentifier`, name, Registry Authority, optional operator, authoritative scope, base URI, and pinned authored or compiler-derived alignment targets. Resources are Record types within that Registry. Authority, controller, publisher, and operator remain distinct roles even when one institution fills several. |
| Registry Core | Every returned Record contains non-selectable `registryIdentifier`, `recordIdentifier`, `revisionIdentifier`, `lifecycleState`, `schemaReference`, `semanticModelReference`, `authorityIdentifier`, `recordedAt`, and selected `domainData`. Record identifier, revision, lifecycle, and recorded time are source-bound; recorded time is never Relay observation time. The Registry and Record identifier pair is stable, and the contract names the institution's identifier-lifecycle policy without claiming Relay can prove non-reassignment from one current database. |
| Family capabilities | Each compiled operation carries a derived family and pattern: read is `consultation.retrieve`, list is `consultation.list`, named exact lookup is constrained `consultation.search`, and an explicitly declared pre-aggregated statistical view is `aggregate-data.statistical-dataflow`. Capability discovery is generated from operations rather than separately authored. Relay makes no claim for Record Match, another Aggregate Data pattern, or the Provisioning, Evidence, Write, Notification, Access Transparency, or Identity Federation families. |
| Compilation and activation | The shared compiler validates the complete contract before packaging, produces one deterministic compiled Registry and contract revision, and seals them with every artifact digest. Before listening, Relay verifies the closed package, recompiles the captured contract, observed schemas, and governed files to prove that the packaged runtime plan is identical, and deterministically rederives every generated artifact solely to exact-compare it with the packaged artifact set. Activation uses the verified packaged bytes. Incomplete semantics, unclassified published properties, invalid source bindings, schema drift, conflicting operations, unsafe access rules, or package inconsistency prevent packaging or readiness. There is no partial activation, runtime merge, silent fallback, or hot reload. |
| Domain neutrality | Production Rust, public configuration schemas, routes, CLI options, and generated generic contracts contain no social-registry, business-registry, CRVS, birth, death, household, benefit, company, or acceptance-fixture-specific type, branch, feature, or operation. Such terms appear only in examples, fixtures, and explanatory documentation. |
| SQLite source boundary | Snapshot and live read-only profiles use one hardened SQLite boundary with OS and engine read-only enforcement, defensive authorizer rules, bound values, consistent per-request transactions, schema fingerprints, and step, time, row, cell, response, queue, and concurrency limits. Writes, schema changes, control statements, attachment, extension loading, and unreviewed SQL are impossible through the public contract. |
| Snapshot profile | A deployment-bound snapshot is captured outside the contract package, bound to its exact file identity and digest, refuses unsafe sidecars or path replacement, opens immutably, verifies exact bytes before and after each statement execution, and releases no rows under a stale source revision. The deployment keeps the file externally immutable, preferably on a read-only mount. Identical governed package and snapshot inputs produce identical revisions and generated artifacts. Snapshot mode is supported but not required for a deployment. |
| Live profile | A live database is opened read-only while a separately trusted publisher may update it. Each response uses one consistent read transaction and verifies the expected schema fingerprint. Version one live sources compile read and exact lookup only, always return `sourceRevision: {profile: live, status: unversioned, value: null}`, use `no-store`, and emit no ETag. Publisher-owned revisions, live pagination, and live caching are deferred. |
| Closed operation model | Resources compile only declared list, identifier-read, and named exact-lookup operations. A list's operation-owned query shape determines whether enumeration is permitted; absence of list means no enumeration. Collection filters are direct publisher-defined camelCase query parameters, typed, non-personal, and exact-equality only. Transformed properties cannot be filters or fixed-order keys; queryable derived values must be reviewed pre-derived source properties. Any non-empty subset of declared filters is valid, and the contract separately permits or forbids unfiltered access. `pageSize`, `cursor`, `fields`, and `representation` are reserved. Lookups have complete bounded body inputs and exactly zero or one disclosed result. Callers cannot add SQL, source columns, joins, expressions, operators, paths, projection expressions, sort orders, or page traversal. |
| Statistical datasets and optional SDMX binding | An adopter defines a reviewed pre-aggregated SQLite view in format-neutral statistical terms: ordered dimensions, one explicit time dimension, one explicit measure, optional observation attributes, concepts, controlled vocabularies, publication time, classification, access, and query bounds. `bindings.sdmx` explicitly selects the Version one output binding; `sdmx: {}` derives stable agency, dataflow, DSD, and concept-scheme identities, while experienced publishers may override those identifiers and one shared version. Relay derives the fixed SDMX REST, JSON, and CSV alignment targets so adopters cannot repeat or contradict implementation versions. Processing handling covers every consulted source column, including hidden authority binding; disclosure handling covers only emitted statistical components. The successful route set is canonical SDMX REST data plus exact dataflow and DSD structure reads under `/sdmx/v2`. It supports bounded exact dimension constraints, bounded time ranges, `TIME_PERIOD` or `AllDimensions` observation layout, and JSON or CSV negotiation. It returns `204` for no observations and refuses duplicate dimension tuples or a result above the compiled ceiling rather than truncating. Schema and availability route shapes are reserved with uniform value-free `501`; history, maintenance, arbitrary operators, dynamic aggregation, and streaming are outside this binding. |
| Representation selection and requester minimization | Every operation has a finite ordered `representations` map and exactly one explicit `defaultRepresentation`. If any representation is public, the default must be public so omission is truthful in public OpenAPI and anonymous clients never select a hidden protected default. The direct `representation` parameter accepts exactly one non-empty compiled identifier; absence selects the default. Relay authenticates a supplied bearer before selection and authorizes only the selected representation. Malformed, repeated, or empty selection is `400 request.representation_invalid`; a syntactically valid unknown name, an anonymous explicit request for a protected name, and a valid principal without the selected representation scope receive the same concealed `404 resource.not_found` outcome; purpose or row-binding denial after scope selection is `403 consultation.denied`. No request falls back to another representation or reaches source access after refusal. `fields` may select only a non-empty duplicate-free subset of that selected profile. Registry Core remains present. Unknown, internal, source-column, cross-profile, or malformed field selections fail before source access and cannot change predicates, bindings, transforms, validation, authorization, effective handling, audit, quota, metadata, or cache posture. |
| HTTP and pagination | Business routes are under `/v2`; `/health`, `/ready`, and `/openapi.json` are unversioned. `GET /v2` publishes safe first-class Registry service metadata and visible derived capabilities. Lists accept bounded `pageSize` and a client-opaque, authenticated-encrypted `cursor` and return `{items, pageInfo: {nextCursor}, meta}` with nullable `nextCursor`. Cursor confidentiality prevents filters and keyset-order values from bypassing field minimization; integrity binds revisions, operation, selected representation and disclosure profile, filters, fixed order, field set, authorization context, and expiry; each page is reauthorized. Single reads and resolved lookups return `{data, meta}`. No caller sorting exists. |
| Query and serialization minimization | Relay may read the complete fixed reviewed projection so it can validate the authoritative Record before disclosure. Unrequested and hidden columns are never serialized. Required null, wrong type, noncanonical value, transform-input failure, or size failure releases nothing and returns value-free `503 source.unavailable` for read, list, and lookup. Ordinary JSON and JSON-LD disclose the same Registry Core identity and selected domain values with deterministic property order. JSON-LD adds the generated context, a derived `@id`, and the resource semantic class as `@type` without replacing `recordIdentifier`. Cacheable responses require a public selected representation, public processing handling, and a snapshot; their strong ETag binds exact selected-profile bytes, `Vary: Accept, Authorization`, `If-None-Match`, and `304`. Other responses are `no-store` and have no ETag. |
| Semantic contract | Every resource and property has a stable local semantic identity, datatype, cardinality, label, and description. `relayctl` can generate reviewed starter semantics, JSON-LD context, permitted-representation JSON Schema and SHACL, full-record validation schema and SHACL, and codelist scaffolding without requiring prior semantic-web expertise. The representation artifacts require Registry Core and validate selectable domain properties only when present; full-record artifacts retain source requiredness. `semanticModelReference` resolves to the generated vocabulary/model and the context is linked separately. Generated suggestions are visibly non-authoritative until accepted. |
| External semantic alignment | Optional mappings to SEMIC, PublicSchema, schema.org, or another profile are curated, relation-qualified, versioned, and digest-pinned. Relay fetches no vocabulary and performs no inference at request time. Mapping changes appear in change-impact reports and cannot silently widen disclosure. |
| Identification, classification, and review | The existing axes remain exact: `semanticTerm`, `privacy`, `institutional`, `handling`, `status`, and `provenanceRef`. `relayctl` identification is offline, schema-only, deterministic, explainable, and value-free; it reads no source values and no candidate self-approves. Every property and every processed source-view column has an effective reviewed classification. `sourceColumnClassifications` is explicit and complete for every multiply-bound column. The reviewed `ClassificationReview` at `classifications.provenanceRef` digest-binds Registry identity and the classification inventory; generated review additionally binds its accepted report and exact rule pack. Missing, suggested, uncertain, stale, or tampered review fails production compilation. Manual and imported review remain first-class. |
| Processing versus disclosure handling | Resource defaults reduce repetition; compilation expands defaults and explicit overrides before validation. For Records, processing handling is the maximum across Registry Core, direct output, transform input, selector, filter, order, and row-binding source columns; disclosure handling is the maximum across serializable properties for the selected representation. For statistical datasets, processing handling is the maximum across every consulted component and row-binding source column; disclosure handling is the maximum across emitted dimensions, time, measure, and attributes. Authentication, audit, cache, source controls, and public eligibility use processing handling. A public output may not process a non-public raw column; publishers create a reviewed pre-derived public view column when that is appropriate. Handling is one of ordered `public`, `internal`, `confidential`, or `restricted`; non-public processing requires authentication, scope, `no-store`, and durable value-free audit, and restricted data cannot be listed. Purpose and row binding remain explicit access constraints. |
| Authentication and issuers | Relay acts as an OAuth 2.0 JWT resource server for protected operations and Version one configures exactly one issuer per Registry deployment. Relay strictly verifies issuer, audience, token type, algorithm, key, time, client or subject, token identifier, and scope claims. Invalid credentials and omitted credentials on a protected default operation return safe registry-wide `401` responses. An anonymous explicit request for a protected representation and a valid principal lacking the selected operation or representation scope receive the same `404 resource.not_found` as an unknown resource or operation; after the scope selects the representation, insufficient purpose or authority returns `403 consultation.denied`. Anonymous access exists only on representations explicitly compiled as public. |
| Operation authorization | List, read, and named lookup use distinct registered scopes that are unique across the Registry contract. Trusted purpose and authority-to-row binding are optional compiled constraints and can come only from the resolved principal or a direct verified scalar claim. Caller filters or headers never create authority. A lookup-only client cannot enumerate or perform identifier reads, even when another client can use those operations on the same deployment. |
| Optional Mint pairing | Relay accepts a conforming token from an external authorization server without Mint. A Mint deployment may be paired when it emits the same Relay audience, operation scopes, and optional authority claims from server-side grants. Relay has no Mint runtime dependency or Mint-specific authentication branch. Mint changes and a Mint integration journey do not block the core Relay V1 acceptance path. |
| Lookup containment | Sensitive selectors use a bounded request body, are bound rather than rendered, and never appear in URLs, errors, logs, metrics, traces, audit, or responses. No match, ambiguity, policy-hidden record, and unknown or protected identifier share one `404` outcome with the same Registry Stack problem type, code, detail, schema, and headers. Only independently generated trace correlation may differ. An invalid selected source row is a value-free `503 source.unavailable`; invalid request syntax is a value-free bounded request error. Rate and concurrency limits make consultation abuse observable and bounded. |
| Validation and failure | Every selected row and transform input is validated before release. Relay never skips, coerces, truncates, or partially releases an invalid row to preserve success. Errors use the fixed Registry Stack status/code catalog and derived type URIs plus `traceId`, exactly the 32-lowercase-hex trace ID of the effective valid or server-generated W3C Trace Context. Caller-supplied `tracestate` is never propagated. Problems contain no field-error array, SQL, paths, schema internals, selector values, source values, token material, or subject identifiers. Draft GovStack error namespaces are not used. Required audit or other release-gate failure prevents disclosure. |
| Unsigned response boundary | Relay responses are not signed. TLS and access-token verification protect the live exchange, while revisions, ETags, provenance, and tamper-evident audit support accountability without being described as signatures. Evidence can consume a fixed Relay lookup when a portable signed minimum-disclosure assertion is required. |
| Audit and provenance | Every public or protected data request processed by Relay durably records either a refusal before returning or a pre-source attempt followed by one terminal release, unresolved, or source-failed outcome. Durable audit gates source access and response release. Events carry stable identifiers for Registry, resource, operation, access-rule revision, optional purpose, row-boundary kind, representation, disclosure profile, selected-property set or digest, processing handling, disclosure handling, transform identifiers, contract revision, and truthful source revision. Terminal audit covers exact held selected-profile bytes before release. Anonymous calls record an anonymous principal kind. Audit contains no tokens, selector values, source values, response values, SQL, or raw subject identifiers. The safeguards report names public shared-cache hits as outside Relay observation. |
| Metadata visibility and per-profile artifacts | Registry service identity is public. Other resource, capability, OpenAPI, semantic, classification, processing, and operational metadata is `public`, `operation-bound` behind the same static gate as the operation and representation whose Record links it, or `operator-only` in package/CLI with no HTTP route. Public metadata never inventories a protected representation identifier, profile schema, SHACL shape, JSON-LD context, semantic model, classification, processing description, or OpenAPI path. The package contains every profile's artifacts and full OpenAPI; `/openapi.json` is a deterministic safe public projection. Compilation fails if any successful Record audience cannot resolve a safe operation-bound projection of its exact profile schema and semantic model. |
| Freshness and caching | Snapshot and live responses expose truthful, profile-specific revision and cache behavior. Every public snapshot response uses `Cache-Control: public, no-cache`, a strong exact-byte ETag, and revalidation. Every non-public or live response is `no-store`. `Vary: Authorization` prevents an anonymous cached `200` from serving a request with an invalid bearer. No response implies a stable cross-request snapshot, and field subsets cannot collide. |
| Generated contracts | OpenAPI 3.1, JSON Schema, SHACL, JSON-LD contexts, codelists, SDMX dataflow and DSD structure metadata, and capability discovery are generated reproducibly from the compiled contract. SDMX structures reference derived concept-scheme and codelist identities without adding separate Version one concept or codelist routes. Full and public OpenAPI projections have drift checks. No artifact is generated from the obsolete Digital Registries OpenAPI. |
| Standards alignment | A concise maintained note pins the reviewed Digital Registries and API Design Guide drafts, maps adopted concepts and Consultation patterns, and records intentional gaps and rejected rules. It uses alignment language only, never conformance or certification. Machine-readable alignment reports, GovStack linting, Registry Manifest projection, and DPV generation are later optional tooling. |
| `relayctl` adopter journey | An adopter can initialize a project; inspect SQLite schema without values; generate either Record starters or a statistical starter by explicitly naming the view, time column, measure column, and any columns that are observation attributes rather than dimensions; generate starter semantics, deterministic identification, classification inventory, processed-versus-disclosed report for Records and statistical datasets, contextual findings, and a review sidecar starter; validate, generate artifacts, run fixtures, inspect a semantic/classification/representation diff, and package a deployment without editing Rust. The statistical starter uses format-neutral terms, marks every suggestion for review, and selects SDMX with an empty binding instead of requiring SDMX identifiers. Generated output defaults below `generated/{reports,governance}`. A generated-review project copies its accepted report to `reports/identification-report.json` and binds it from `governance/classification-review.yaml`; imported and manual projects need no generated report. `relayctl` uses the same Relay compiler and fixture library as `relay` and implements no second product semantics. |
| Change impact and safeguards | A contract diff identifies new properties or statistical datasets, wider operations, filters, or statistical query bounds, changed statistical components or binding identities, relaxed classification, changed disclosure profiles, removed row bindings, expanded scopes or purposes, changed metadata visibility, source-view changes, and semantic mapping changes. Each applicable DPI safeguard is linked to a concrete mechanism, enforcement point, negative test, evidence artifact, and named institutional responsibility. No certification claim is generated. |
| Operability | Unauthenticated `/health` reports only liveness and `/ready` reports only ability to serve the compiled Registry, each as minimal `application/json` on `200`, `no-store`, and safe Registry Stack Problem `503` on failure. Neither exposes Registry or source details. Startup, shutdown, bounded concurrency, audit durability, issuer-key refresh, source unavailability, schema drift, and live publisher replacement have documented and tested behavior. Relay emits structured value-free lifecycle logs and bounded request outcomes using only a fixed method class, route template, status, latency, and trace identifier. Version one has no `/metrics` route or in-process metrics registry; operators derive aggregate metrics outside Relay from these logs and durable audit without protected values or high-cardinality subject labels. |
| Verification evidence | Focused positive, negative, boundary, and non-disclosure tests pass for every security-sensitive behavior. Formatting, package check, Clippy with warnings denied, package tests, workspace tests, dependency policy, contract drift, exposure inventory, source neutrality, config-key-path, and reproducible-generation gates pass on one revision. CI path selection is itself tested for every new owning path. |
| Stop boundary | Version 1 contains no generic storage trait before a second adapter, SpatiaLite or GeoJSON path, general search language, fuzzy or Record Match behavior, dynamic aggregation, generic statistical operators, historical or maintenance SDMX, streaming, dynamic masking, caller-dependent maximum entitlement profile, PDP, consent workflow, response signing, credential lifecycle, multi-source analytics, runtime vocabulary fetch, RDF store, SPARQL, hot reload, write API, registry administration, formal GovStack compatibility mode, or compatibility work in `registryctl`. |

## Required acceptance coverage

The executable labour-statistics example additionally proves public discovery,
schema-valid dataflow and DSD structure metadata, explicit schema and
availability deferral, positional and named dimension filters, bounded time
ranges, both observation layouts, SDMX-JSON and SDMX-CSV negotiation,
deterministic snapshot ETags including `304`, no-result `204`, explicit paging,
duplicate-observation refusal across every page, too-broad refusal, unsupported
feature refusal, and value-free audit. Compiler and runtime negatives pin
protected scope, purpose, and verified-claim row binding without introducing
dynamic component entitlements.

A compact scenario table binds the three journeys below to executable tests. A
separate security-invariant matrix names threats, enforcement points, and
negative tests. Non-security prose does not require one machine-readable row
per sentence.

### Cross-registry path

The three coequal Registry journeys prove adopter-facing behavior. Shared
product-neutral kernel and multi-resource tests prove security invariants that
do not need to be repeated with domain-specific fixtures.

For each of the three coequal registries:

1. the example compiles through the same closed configuration types;
2. Registry identity, authority, scope, alignment targets, and derived Consultation capabilities are correct;
3. offline fixtures and the real HTTP service return the same semantic result;
4. every returned Record has valid Registry Core context, and `recordedAt` and `revisionIdentifier` come from the source view;
5. ordinary JSON and JSON-LD are data-equivalent after removing the JSON-LD `@id` and `@type`; every returned Record validates against the exact generated permitted-representation JSON Schema, its operation/representation binding resolves the corresponding generated SHACL artifact, and the actual JSON-LD response expands to an RDF graph whose class, IRI nodes, predicates, and datatypes match that SHACL shape and the compiled model;
6. default and explicitly requested representations, plus at least two valid `domainData` subsets within a selected representation, succeed while Registry Core remains complete;
7. an unknown property, source-column name, cross-profile property, duplicate property, malformed selection, malformed/repeated representation, unknown representation, and denied selected representation fail without source or value leakage or fallback;
8. invalid selected source rows fail the whole response closed with value-free `503 source.unavailable`; every Registry proves at least one such refusal, and the coequal suite covers wrong type, missing required value, extra unexpected value, and excessive size;
9. restarting with identical inputs reproduces the same compiled contract and generated artifacts;
10. a schema or governed-contract change is detected and cannot silently widen the active API;
11. full packaged OpenAPI, safe public OpenAPI, per-profile semantic, schema, SHACL, JSON-LD, classification, processing, codelist, and capability artifacts reproduce byte for byte.
12. schema-only identification reports, classification inventories, processed-versus-disclosed representation reports, contextual findings, and review-sidecar staleness/tamper refusals are deterministic and value-free.

Shared security acceptance additionally proves that:

1. a response and its emitted value-free audit correlate through trace and request-operation identifiers and agree on Registry, resource, compiled operation, contract, selected representation and disclosure profile, selected properties, processing/disclosure handling, row-boundary kind, and truthful source revision;
2. audit never records response bytes, response digests, Record identifiers, raw subject identifiers, or fixture canaries;
3. Problems do not contain fixture canaries, trace headers carry only Relay-validated fixed identifiers, and operational log dimensions cannot contain request paths, identifiers, query values, headers, bodies, selectors, or principals;
4. adopter reports and generated or packaged artifacts pass fixture-canary scans.

Raw source databases are governed inputs rather than diagnostic output. Relay
does not claim that a test framework's own failure renderer is a protected
product surface. Metrics, when deployed, are derived externally from the fixed
value-free operational log dimensions.

### Social registry cases

- exact match, no match, ambiguity, policy-hidden row, and invalid selected row;
- correct purpose and service-area row binding, missing purpose, wrong purpose, missing binding, and wrong binding;
- lookup scope succeeds while list and identifier read are absent regardless of token scope;
- limited is the default and uses `partial-string`; entitled caseworker selection returns its own profile, purpose, and row binding, while a wrong scope, purpose, or binding does not fall back;
- the social journey proves ordinary `partial-string` output; focused transform and real-router tests prove null, wrong-type, and overlong refusal plus the fixed `***` result for a short input, without exposing raw input in JSON, JSON-LD, audit, report, or problem output;
- selectors and internal person, household, and service-area binding columns remain absent from every response and diagnostic surface;
- live update within the compatible schema appears under a truthful later Record revision without mixing rows inside one response;
- the deployment advertises constrained `consultation.search` only and makes no Base Registry or Record Match claim.

### Business registry cases

- anonymous paginated list and identifier read over a captured snapshot;
- `pageSize`, first page, cursor page, and nullable `pageInfo.nextCursor` behavior;
- no filter when allowed, each declared direct camelCase exact filter, a subset of declared filters, unknown filter, unsupported operator, and attempted arbitrary sort;
- deterministic ordering and pagination with no duplicate or missing record across the unchanged snapshot;
- public field subset, JSON-LD context, SEMIC mapping artifact, SHACL, and codelist validation;
- public default list/read can request only public representations; protected registrar representation metadata, schema, SHACL, JSON-LD, processing, and OpenAPI are absent from public discovery;
- a public representation reads only the reviewed pre-derived public view, never a non-public raw column, and a profile-bound cursor or ETag cannot cross into another representation;
- snapshot digest, path replacement, unsafe sidecar, write attempt, and schema mismatch failures.
- `consultation.list` and `consultation.retrieve` discovery with no unsupported family claim.

### Civil-event registry cases

- protected identifier read and named exact verification lookup, with collection listing absent;
- registrar and supervisory representations are selected explicitly, are independently scoped, and never fall back; neither read nor lookup scope can synthesize the other;
- the civil journey proves `date-precision` (`year` and `year-month`) with distinct output terms/types; focused transform and real-router tests reject null, noncanonical, incompatible, and oversized source values with value-free source failure;
- the external-issuer path is complete; a later optional Mint pairing must traverse the same verifier and access-decision path;
- no match, ambiguity, and a jurisdiction-hidden row collapse to the unresolved lookup outcome; an invalid event record or transform input fails as value-free `503 source.unavailable`, while wrong purpose and wrong jurisdiction binding retain their distinct governed refusal behavior;
- the fixed Relay lookup remains an ordinary protected HTTP source contract
  suitable for a future Evidence integration, without adding signing behavior
  to Relay; a real Evidence pairing is a separate non-blocking journey.
- the same Registry Core fields remain present under both operation-specific disclosure profiles.
- no list route exists, including when a caller asks for a representation identifier.

### Classification-review methods

- Social assistance uses `generated` review: its accepted
  `reports/identification-report.json` and exact core-pack digest bind the
  classification-review sidecar.
- Business registration uses `imported` review and remains valid without an
  identification report.
- Civil event uses `manual` review and remains valid without an identification
  report.
- Missing, stale, deterministic-report-mismatched, sidecar-tampered, or
  generated-pack-mismatched review is refused before production compilation.

### Cross-product and neutrality cases

- three independently instantiated one-Registry services exercise real loopback
  HTTP without sharing authority, contract, source, or audit state, and one
  packaged deployment passes a real-process start, request, stop, and restart
  smoke test;
- parameterized multi-resource compiler and runtime tests prove that contract, query, disclosure, audit, limit, and response state do not cross resource boundaries;
- a repository boundary check rejects acceptance-domain terms and branches from production code and generic public schemas;
- the same hardened SQLite executor serves snapshot and live profiles without domain-specific SQL paths;
- a token minted for Evidence, another Relay audience, or an undeclared operation is rejected;
- a public operation in a focused multi-resource test does not weaken a protected resource in that same process;
- full packaged OpenAPI contains all operations while public OpenAPI omits every protected selector and operator-only artifact;
- unknown, protected, ambiguous, and policy-hidden lookup outcomes are identical except for trace
  correlation, while a selected malformed source row fails closed as `503 source.unavailable`;
- the alignment note records the deferred same-operation entitlement variant and every unimplemented family without a conformance claim;
- every security invariant has a named threat, enforcement point, expected result, and exact executable negative-test traceability.

## Completion evidence

Before the product can be called complete, the repository must contain and CI must invoke:

- a compact scenario table for the three acceptance definitions;
- a security-invariant matrix paired with executable negative-test traceability;
- reproducible generators and drift checks for public and semantic artifacts;
- generated Consultation capabilities plus a maintained Digital Registries and API Design Guide alignment note;
- source-product-neutrality and protected-value canary scans;
- focused runtime, `relayctl`, shared-SQLite, issuer, audit, and serialization tests;
- the applicable package and workspace formatting, check, Clippy, test, and dependency-policy gates;
- one local end-to-end journey for each coequal registry using synthetic SQLite data and no external credentials.

Optional live demos may supplement this evidence but never replace deterministic local fixtures and tests.
