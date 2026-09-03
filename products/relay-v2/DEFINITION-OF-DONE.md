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

The social, business, civil-event, and labour-statistics registries are
coequal acceptance definitions. None is the architectural seed, a privileged
demo, or a later generality check. Production code, public schemas, routes,
and CLI behavior remain registry-domain neutral.

No required behavior may remain as a stub, TODO, undocumented manual step, disabled test, or follow-up issue. Additional storage engines, SpatiaLite, generic or non-Point geometry, general policy evaluation, response signing, dynamic masking, and other future profiles are outside this Definition of Done.

## Coequal acceptance definitions

| Registry | Required shape | What it must prove |
|---|---|---|
| Social assistance enrolment | Live SQLite, exact lookup only, limited and caseworker access profiles, partial-string transform, trusted purpose, authority-to-row binding, external authorization server | A sensitive person-related registry can answer a bounded consultation without enumeration, selector disclosure, or domain-specific runtime behavior. |
| Business registration | Snapshot SQLite, public and protected access profiles, predefined exact filters, separate list and named Point-bbox search rights, pagination, public semantics | A genuinely public register can isolate protected access while a classified CRS84 Point remains governed, selectable, bounded, discoverable, and cacheable. |
| Civil event registration | Live SQLite, registrar and supervisory access profiles over protected identifier read and named exact lookup, date-precision transform, no list | A CRVS-shaped event register can prove exact lookup and access profile scope separation without exposing a collection, coupling Relay to Mint, or moving signed assertions into Relay. |
| Labour statistics | Snapshot SQLite, separate format-neutral statistical datasets, one fixed access rule per dataset, bounded typed queries, required SDMX binding | A pre-aggregated statistical publication can expose only the aligned dataflow read subset with exact generated dataflow and DSD artifacts, typed JSON and CSV, and no generic analytics or domain-specific runtime behavior. |

Each definition must pass offline fixture evaluation and the real HTTP runtime
as its own one-Registry deployment. All four must use the same compiler,
access-decision types, SQLite executor, disclosure planner, serializers, audit
vocabulary, and problem model. Focused parameterized compiler and runtime tests
prove in-process resource and statistical-dataset isolation without adding a
fifth deployment project.

## Definition of Done

| Area | Done when |
|---|---|
| Product boundary | One `relay` runtime and one separate `relayctl` implement the initial product. Relay is a read-only governed registry publisher, not a SQL proxy, write API, policy engine, credential issuer, or signed-assertion service. The retired `registryctl` adopter tool and its Relay V1 runtime are absent from current `main`; neither owns a Relay V2 product command or supported editor-launch path. |
| Governed contract | A concise, closed, versioned authoring contract defines Record resources and separately declared pre-aggregated statistical datasets, source views, properties or statistical components, finite access profiles for Record operations, one fixed access for each statistical dataset, semantics, classifications, bounds, bindings, and metadata visibility. Unknown fields are rejected. A deployment file may bind paths, listeners, one issuer, secrets, and audit storage but cannot override governed behavior. |
| Registry identity | One contract and process describes exactly one Registry with a globally stable `registryIdentifier`, name, Registry Authority, optional operator, authoritative scope, base URI, and pinned authored alignment targets. Compiler-owned binding profile versions are derived and cannot be authored as `alignmentTargets`. Authority, controller, publisher, and operator remain distinct roles even when one institution fills several. |
| Registry Record context | Every JSON and JSON-LD consultation response contains non-selectable `registryIdentifier`, `datasetIdentifier`, and `entityTypeIdentifier` exactly once in response `meta`. Every returned Record contains `recordIdentifier`, `revisionIdentifier`, `lifecycleState`, `schemaReference`, `semanticModelReference`, `authorityIdentifier`, `recordedAt`, and selected `domainData`, without duplicating the response context. Resource dataset and entity-type identifiers are required governed values and are never inferred. Record identifier, revision, lifecycle, and recorded time are source-bound; recorded time is never Relay observation time. The Registry and Record identifier pair is stable, and the contract names the institution's identifier-lifecycle policy without claiming Relay can prove non-reassignment from one current database. |
| Family capabilities | Each compiled operation carries a derived family and pattern: read is `consultation.retrieve`, list is `consultation.list`, named exact lookup plus named Point-bbox search are constrained `consultation.search`, and an explicitly bound statistical dataset is `aggregate-data.statistical-dataflow`. Capability discovery is generated rather than separately authored. Relay makes no claim for Record Match, another Aggregate Data pattern, or the Provisioning, Evidence, Write, Notification, Access Transparency, or Identity Federation families. |
| Statistical dataset contract | `statisticalDatasets` remains separate from `resources` and format-neutral. Every dataset uses a snapshot source, declares dimensions, one time component with required `granularity` in `annual`, `quarterly`, `monthly`, or `daily`, one measure, attributes, publication facts, reviewed classifications, bounded query limits, exactly one `access`, required `bindings.sdmx`, and explicit `metadataVisibility.statisticalDatasets`. `accessProfiles` is rejected. |
| SDMX read binding | The binding exposes only keyed data, the omitted-key alias for the same operation, exact dataflow structure, and exact datastructure structure routes. It implements the aligned SDMX REST 2.2.2 read subset and emits SDMX-JSON, SDMX-CSV, and Structure JSON 2.1.0. Schema, availability, history, and structure-maintenance routes and placeholders do not exist. This is not a full SDMX conformance claim. |
| Statistical query and values | Component constraints compile to exact bound SQLite predicates with the declared storage classes. Key/query overlap, unsupported operators, duplicate constraints, invalid periods, unreviewed codelist values, duplicate observation keys, and result ceilings fail closed. SDMX-JSON dimensions and attributes retain strings and numeric measures retain numbers; CSV contains the equivalent observations. Relay never aggregates rows. |
| SDMX artifacts and profile validation | Every bound dataset produces one canonical dataflow artifact and one canonical DSD artifact in the sealed package, and the structure routes serve those exact bytes. The maintained profile lock pins the official REST, JSON, and CSV sources plus exact external schema digests. Its validator fetches schemas only with an explicit option into a temporary directory or uses an external cache, validates outputs, then discards fetched bytes. Upstream schema bytes are never committed. |
| Compilation and activation | The shared compiler validates the complete contract before packaging, produces one deterministic compiled Registry and contract revision, and seals them with every artifact digest. Before listening, Relay verifies the closed package, recompiles the captured contract, observed schemas, and governed files to prove that the packaged runtime plan is identical, and deterministically rederives every generated artifact solely to exact-compare it with the packaged artifact set. Activation uses the verified packaged bytes. Incomplete semantics, unclassified published properties, invalid source bindings, schema drift, conflicting operations, unsafe access rules, or package inconsistency prevent packaging or readiness. There is no partial activation, runtime merge, silent fallback, or hot reload. |
| Domain neutrality | Production Rust, public configuration schemas, routes, CLI options, and generated generic contracts contain no social-registry, business-registry, CRVS, birth, death, household, benefit, company, or acceptance-fixture-specific type, branch, feature, or operation. Such terms appear only in examples, fixtures, and explanatory documentation. |
| SQLite source boundary | Snapshot and live read-only profiles use one hardened SQLite boundary with OS and engine read-only enforcement, defensive authorizer rules, bound values, consistent per-request transactions, schema fingerprints, and step, time, row, cell, response, queue, and concurrency limits. Writes, schema changes, control statements, attachment, extension loading, and unreviewed SQL are impossible through the public contract. |
| Snapshot profile | A deployment-bound snapshot is captured outside the contract package, bound to its exact file identity and digest, refuses unsafe sidecars or path replacement, opens immutably, verifies exact bytes before and after each statement execution, and releases no rows under a stale source revision. The deployment keeps the file externally immutable, preferably on a read-only mount. Identical governed package and snapshot inputs produce identical revisions and generated artifacts. Snapshot mode is supported but not required for a deployment. |
| Live profile | A live database is opened read-only while a separately trusted publisher may update it. Each response uses one consistent read transaction and verifies the expected schema fingerprint. Version one live sources compile read and exact lookup only, always return `sourceRevision: {profile: live, status: unversioned, value: null}`, use `no-store`, and emit no ETag. Publisher-owned revisions, live pagination, and live caching are deferred. |
| Closed operation model | Resources compile only declared list, identifier-read, named exact-lookup, and named Point-bbox search operations. Lists and searches remain independent operations. A Point search requires exactly one finite, ordered, non-wrapping CRS84 `bbox`, enforces compiled span limits, and owns its access profiles, pagination, and fixed order. Collection filters are direct publisher-defined camelCase query parameters, typed, non-personal, and exact-equality only. Transformed properties cannot be filters or fixed-order keys. `pageSize`, `cursor`, `fields`, `accessProfile`, `formatProfile`, and `bbox` are reserved. Callers cannot add SQL, source columns, joins, expressions, operators, paths, projection expressions, sort orders, or page traversal. |
| Access profile selection and requester minimization | Every operation has a finite ordered `accessProfiles` map and exactly one explicit `defaultAccessProfile`. If any access profile is public, the default must be public so omission is truthful in public OpenAPI and anonymous clients never select a hidden protected default. The direct `accessProfile` parameter accepts exactly one non-empty compiled identifier; absence selects the default. Relay authenticates a supplied bearer before selection and authorizes only the selected access profile. Malformed, repeated, empty, or retired `representation` selection is `400 request.access_profile_invalid`; `representation` is never an alias. A syntactically valid unknown name, an anonymous explicit request for a protected name, and a valid principal without the selected access profile scope receive the same concealed `404 resource.not_found` outcome; purpose or row-binding denial after scope selection is `403 consultation.denied`. No request falls back to another access profile or reaches source access after refusal. `fields` may select only a non-empty duplicate-free subset of that selected profile. Registry Core remains present. Unknown, internal, source-column, cross-profile, or malformed field selections fail before source access and cannot change predicates, bindings, transforms, validation, authorization, effective handling, audit, quota, metadata, or cache posture. |
| HTTP and pagination | Business routes are under `/v2`; `/health`, `/ready`, and `/openapi.json` are unversioned. `GET /v2` publishes safe first-class Registry service metadata and visible derived capabilities. Lists accept bounded `pageSize` and a client-opaque, authenticated-encrypted `cursor` and return `{items, pageInfo: {nextCursor}, meta}` with nullable `nextCursor`. Cursor confidentiality prevents filters and keyset-order values from bypassing field minimization; integrity binds dataset, entity type, response profile, representation, revisions, operation, selected access profile and disclosure profile, filters, fixed order, field set, authorization context, and expiry; each page is reauthorized. Single reads and resolved lookups return `{data, meta}`. No caller sorting exists. |
| Relying-party client boundary | `registry-relay-http-contract` owns the fixed route and Problem Details inventory used by `registry-relay-client` and its Node and Python bindings. The client is a consumer only: it must not generate deployment OpenAPI, dynamically derive or invent routes, paginate or retry automatically, or add server behavior. Its offline contract checks and source-neutrality scan run with the Relay product gates. |
| Query and serialization minimization | Relay validates the complete fixed reviewed Record before disclosure. Unrequested fields and Point carrier columns are never serialized. Invalid required values, transforms, or coordinates release nothing and return value-free `503 source.unavailable`. Ordinary JSON and JSON-LD disclose the same Registry Core identity and selected domain values. A selected `primaryGeometry` property may also serialize as RFC 7946 GeoJSON or bounded JSON-FG under `application/geo+json`; Feature `properties` plus `geometry` preserve the same disclosure, and an omitted geometry becomes `null`. `formatProfile` selects serialization only and never access. Cacheable responses require a public selected access profile, public processing handling, a snapshot, and an absent or null `pageInfo.nextCursor`; their strong ETag binds exact bytes and format. Other responses are `no-store`. |
| Semantic contract | Every resource and property has a stable local semantic identity, datatype, cardinality, label, and description. `relayctl` can generate reviewed starter semantics, JSON-LD context, permitted-access-profile JSON Schema and SHACL, full-record validation schema and SHACL, and codelist scaffolding without requiring prior semantic-web expertise. The access-profile artifacts require Registry Core and validate selectable domain properties only when present; full-record artifacts retain source requiredness. `semanticModelReference` resolves to the generated vocabulary/model and the context is linked separately. Generated suggestions are visibly non-authoritative until accepted. |
| External semantic alignment | Optional mappings to SEMIC, PublicSchema, schema.org, or another profile are curated, relation-qualified, versioned, and digest-pinned. Relay fetches no vocabulary and performs no inference at request time. Mapping changes appear in change-impact reports and cannot silently widen disclosure. |
| Identification, classification, and review | The existing axes remain exact: `semanticTerm`, `privacy`, `institutional`, `handling`, `status`, and `provenanceRef`. `relayctl` identification is offline, schema-only, deterministic, explainable, and value-free; it reads no source values and no candidate self-approves. Every property and every processed source-view column has an effective reviewed classification. `sourceColumnClassifications` is explicit and complete for every multiply-bound column. The reviewed `ClassificationReview` at `classifications.provenanceRef` digest-binds Registry identity and the classification inventory; generated review additionally binds its accepted report and exact rule pack. Missing, suggested, uncertain, stale, or tampered review fails production compilation. Manual and imported review remain first-class. |
| Processing versus disclosure handling | Resource defaults reduce repetition; compilation expands defaults and explicit overrides before validation. Processing handling is the maximum across Registry Core, direct output, transform input, selector, filter, Point carrier, order, and row-binding source columns. Disclosure handling is the maximum across serializable properties for the selected access profile. Carrier columns require explicit reviewed classification and never become independent metadata or output. Authentication, audit, cache, source controls, and public eligibility use processing handling. Handling is one of ordered `public`, `internal`, `confidential`, or `restricted`; non-public processing requires authentication, scope, `no-store`, and durable value-free audit, and restricted data cannot be listed. Purpose and row binding remain explicit access constraints. |
| Authentication and issuers | Relay acts as an OAuth 2.0 JWT resource server for protected operations and Version one configures exactly one issuer per Registry deployment. Relay strictly verifies issuer, audience, token type, algorithm, key, time, client or subject, token identifier, and scope claims. Invalid credentials and omitted credentials on a protected default operation return safe registry-wide `401` responses. An anonymous explicit request for a protected access profile and a valid principal lacking the selected operation or access profile scope receive the same `404 resource.not_found` as an unknown resource or operation; after the scope selects the access profile, insufficient purpose or authority returns `403 consultation.denied`. Anonymous access exists only on access profiles explicitly compiled as public. |
| Operation authorization | List, read, named lookup, and named search use distinct registered scopes that are unique across the Registry contract. Trusted purpose and authority-to-row binding are optional compiled constraints and can come only from the resolved principal or a direct verified scalar claim. Caller filters, `bbox`, or headers never create authority. A search-only client cannot synthesize list or identifier-read access. |
| Optional Mint pairing | Relay accepts a conforming token from an external authorization server without Mint. A Mint deployment may be paired when it emits the same Relay audience, operation scopes, and optional authority claims from server-side grants. Relay has no Mint runtime dependency or Mint-specific authentication branch. Mint changes and a Mint integration journey do not block the core Relay V2 Version 1 acceptance path. |
| Lookup containment | Sensitive selectors use a bounded request body, are bound rather than rendered, and never appear in URLs, errors, logs, metrics, traces, audit, or responses. No match, ambiguity, policy-hidden record, and unknown or protected identifier share one `404` outcome with the same Registry Stack problem type, code, detail, schema, and headers. Only independently generated trace correlation may differ. An invalid selected source row is a value-free `503 source.unavailable`; invalid request syntax is a value-free bounded request error. Rate and concurrency limits make consultation abuse observable and bounded. |
| Validation and failure | Every selected row and transform input is validated before release. Relay never skips, coerces, truncates, or partially releases an invalid row to preserve success. Errors use the fixed Registry Stack status/code catalog and derived type URIs plus `traceId`, exactly the 32-lowercase-hex trace ID of the effective valid or server-generated W3C Trace Context. Caller-supplied `tracestate` is never propagated. Problems contain no field-error array, SQL, paths, schema internals, selector values, source values, token material, or subject identifiers. Draft GovStack error namespaces are not used. Required audit or other release-gate failure prevents disclosure. |
| Unsigned response boundary | Relay responses are not signed. TLS and access-token verification protect the live exchange, while revisions, ETags, provenance, and tamper-evident audit support accountability without being described as signatures. Evidence can consume a fixed Relay lookup when a portable signed minimum-disclosure assertion is required. |
| Audit and provenance | Every public or protected data request processed by Relay durably records either a refusal before returning or a pre-source attempt followed by one terminal release, unresolved, or source-failed outcome. Durable audit gates source access and response release. Statistical data and structure use distinct surface identifiers; JSON and CSV use distinct wire-format identifiers, and terminal events bind the exact held bytes. Audit contains no tokens, selectors, component constraints, query values, source or response values, SQL, raw subject identifiers, or hidden authority values. |
| Metadata visibility and per-profile artifacts | Registry service identity is public. One deterministic Registry Discovery provider description derives identity, endpoint, roles, conformance, and only public capability identifiers from the compiled Registry plus explicitly authored jurisdictions, is sealed in the package, and is served anonymously through `/v2/artifacts/discovery-description`. Each exact public semantic-class and operation-family pair has a distinct derived binding identity, so graph processing and multi-filter search cannot create a false cross-resource capability pair. Protected-only Registries publish one service binding with empty capability sets. The description never contains protected operations, access profiles, scopes, source bindings, columns, selectors, credentials, signing material, audit state, or runtime-only configuration. Record metadata follows its access-profile visibility, and statistical metadata follows the explicit `metadataVisibility.statisticalDatasets` gate plus the dataset's one fixed access rule. Public metadata never inventories a protected access profile or protected statistical binding. The package contains every governed artifact and full OpenAPI; `/openapi.json` is a deterministic safe public projection. |
| Freshness and caching | Snapshot and live responses expose truthful, profile-specific revision and cache behavior. Every public snapshot response whose `pageInfo.nextCursor` is absent or null uses `Cache-Control: public, no-cache`, a strong exact-byte ETag, and revalidation. A response containing a non-null continuation cursor, and every non-public or live response, is `no-store` and emits no ETag. `Vary: Authorization` prevents an anonymous cached `200` from serving a request with an invalid bearer. No response implies a stable cross-request snapshot, and field subsets cannot collide. |
| Generated contracts | OpenAPI 3.1, the Registry Discovery provider description, access-profile and full-record JSON Schema, conditional GeoJSON response schemas, SHACL, JSON-LD contexts, codelists, capability discovery, and exact statistical dataflow and DSD structure artifacts are generated reproducibly from the compiled contract. An undisclosed Point remains in full-record semantic and validation artifacts but is omitted from the selected access-profile response artifacts. Full and public OpenAPI projections, provider-publication bytes, and SDMX profile outputs have drift or schema-validation checks. No artifact is generated from the obsolete Digital Registries OpenAPI. |
| Standards alignment | A concise maintained note pins the reviewed Digital Registries and API Design Guide drafts and the aligned SDMX read-profile sources, maps adopted Consultation and statistical-dataflow patterns, and records intentional gaps. It uses alignment language only, never full conformance or certification. Machine-readable GovStack alignment, Registry Manifest projection, and DPV generation are later optional tooling. |
| `relayctl` adopter journey | An adopter can initialize a project, inspect a SQLite schema without values by default, generate starter semantics, deterministic identification, classification inventory, processed-versus-disclosed access-profile report, contextual findings, and a review sidecar starter; validate, generate artifacts, run fixtures, inspect a semantic/classification/access profile diff, and package a deployment without editing Rust. Generated output defaults below `generated/{reports,governance}`. A generated-review project copies its accepted report to `reports/identification-report.json` and binds it from `governance/classification-review.yaml`; imported and manual projects need no generated report. `relayctl` uses the same Relay compiler and fixture library as `relay` and implements no second product semantics. |
| Editor authoring | `relayctl tooling editor` writes collision-safe, version-matched JSON Schemas and project-local YAML mappings for VS Code and Zed, while `relayctl tooling language-server` hosts the same bounded language server as the standalone binary and `evidencectl`. A Relay V2 root is declared only by a regular `registry.yaml`. The server runs the shared Relay V2 parser and authoring compiler against the complete in-memory project, including unsaved buffers, without opening SQLite, source rows, sockets, or secret values. It reports the compiler's stable semantic diagnostics and provides definitions, references, symbols, completion, and hover for governed sources, Record resources, statistical datasets, properties and components, disclosure and access profiles, operations, runtime source bindings, and governed-file references. VS Code activates and discovers nested Relay V2 roots; VS Code, Zed, and the installer select only `evidencectl` or `relayctl`, and an older `evidencectl` cannot hide a matching `relayctl`. Generated schemas are derived from the same strict Rust types `relayctl check` reads and are drift-checked. Focused Rust, protocol, Node, Zed, installer, acceptance-project, and CI-selection tests prove the complete path. |
| Change impact and safeguards | A contract diff identifies new properties, wider operations or filters, relaxed classification, changed disclosure profiles, removed row bindings, expanded scopes or purposes, changed metadata visibility, source-view changes, and semantic mapping changes. Each applicable DPI safeguard is linked to a concrete mechanism, enforcement point, negative test, evidence artifact, and named institutional responsibility. No certification claim is generated. |
| Operability | Unauthenticated `/health` reports only liveness and `/ready` reports only ability to serve the compiled Registry, each as minimal `application/json` on `200`, `no-store`, and safe Registry Stack Problem `503` on failure. Neither exposes Registry or source details. Startup, shutdown, bounded concurrency, audit durability, issuer-key refresh, source unavailability, schema drift, and live publisher replacement have documented and tested behavior. Relay emits structured value-free lifecycle logs and bounded request outcomes using only a fixed method class, route template, status, latency, and trace identifier. Version one has no `/metrics` route or in-process metrics registry; operators derive aggregate metrics outside Relay from these logs and durable audit without protected values or high-cardinality subject labels. |
| Verification evidence | Focused positive, negative, boundary, and non-disclosure tests pass for every security-sensitive behavior. Formatting, package check, Clippy with warnings denied, package tests, workspace tests, dependency policy, contract drift, exposure inventory, source neutrality, config-key-path, and reproducible-generation gates pass on one revision. CI path selection is itself tested for every new owning path. |
| Stop boundary | Version 1 contains no generic storage or geometry trait, SpatiaLite, GeoPackage decoding, non-Point geometry, OGC API Features routes, CQL2, EDR, tiles, reprojection, spatial joins, general search language, fuzzy or Record Match behavior, SDMX schema or availability routes, history, structure maintenance, dynamic aggregation, arbitrary statistical operators, dynamic masking, caller-dependent maximum entitlement profile, PDP, consent workflow, response signing, credential lifecycle, multi-source analytics, runtime vocabulary fetch, RDF store, SPARQL, hot reload, write API, registry administration, formal GovStack or SDMX conformance claim, or compatibility work for retired Relay V1 projects. |

## Required acceptance coverage

A compact scenario table binds the four journeys below to executable tests. A
separate security-invariant matrix names threats, enforcement points, and
negative tests. Non-security prose does not require one machine-readable row
per sentence.

### Cross-registry path

The four coequal Registry journeys prove adopter-facing behavior. Shared
product-neutral kernel and multi-resource tests prove security invariants that
do not need to be repeated with domain-specific fixtures.

For each coequal Record registry:

1. the example compiles through the same closed configuration types;
2. Registry identity, authority, scope, alignment targets, and derived Consultation capabilities are correct;
3. offline fixtures and the real HTTP service return the same semantic result;
4. every JSON and JSON-LD response has exact Registry, dataset, and entity-type context in `meta`, every returned Record has valid Registry Core fields without duplicating that context, and `recordedAt` and `revisionIdentifier` come from the source view;
5. ordinary JSON and JSON-LD are data-equivalent after removing the JSON-LD `@id` and `@type`; every returned Record validates against the exact generated permitted-access-profile JSON Schema, its operation/access profile binding resolves the corresponding generated SHACL artifact, and the actual JSON-LD response expands to an RDF graph whose class, IRI nodes, predicates, and datatypes match that SHACL shape and the compiled model;
6. default and explicitly requested access profiles, plus at least two valid `domainData` subsets within a selected access profile, succeed while Registry Record context remains complete;
7. an unknown property, source-column name, cross-profile property, duplicate property, malformed selection, malformed/repeated access profile, unknown access profile, and denied selected access profile fail without source or value leakage or fallback;
8. invalid selected source rows fail the whole response closed with value-free `503 source.unavailable`; every Registry proves at least one such refusal, and the coequal suite covers wrong type, missing required value, extra unexpected value, and excessive size;
9. restarting with identical inputs reproduces the same compiled contract and generated artifacts;
10. a schema or governed-contract change is detected and cannot silently widen the active API;
11. full packaged OpenAPI, safe public OpenAPI, per-profile semantic, schema, SHACL, JSON-LD, classification, processing, codelist, and capability artifacts reproduce byte for byte.
12. schema-only identification reports, classification inventories, processed-versus-disclosed access-profile reports, contextual findings, and review-sidecar staleness/tamper refusals are deterministic and value-free.

Shared security acceptance additionally proves that:

1. a response and its emitted value-free audit correlate through trace and request-operation identifiers and agree on Registry, resource, compiled operation, contract, selected access profile and disclosure profile, selected properties, processing/disclosure handling, row-boundary kind, and truthful source revision;
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
- a separate public premises resource with one classified, selectable CRS84
  `type: point` property assembled from reviewed longitude and latitude
  carriers and referenced by `primaryGeometry`;
- exact inclusive named `bbox` search, required-bbox enforcement, boundary
  inclusion, malformed, out-of-range, oversize, and antimeridian refusal,
  deterministic pagination, and cursor rejection when operation, bbox, access
  profile, wire format, or format profile changes;
- protected list and protected search rights use distinct scopes, while denied
  or unknown protected search access profiles remain concealed;
- equivalent governed JSON, JSON-LD, RFC 7946 GeoJSON, and JSON-FG responses,
  including a requested field subset that omits geometry;
- GeoJSON is refused for a resource or selected profile without disclosed
  primary geometry, and invalid coordinates fail atomically without values;
- `pageSize`, first page, cursor page, and nullable `pageInfo.nextCursor` behavior;
- no filter when allowed, each declared direct camelCase exact filter, a subset of declared filters, unknown filter, unsupported operator, and attempted arbitrary sort;
- deterministic ordering and pagination with no duplicate or missing record across the unchanged snapshot;
- public field subset, JSON-LD context, SEMIC mapping artifact, SHACL, and codelist validation;
- public default list/read can request only public access profiles; protected registrar access profile metadata, schema, SHACL, JSON-LD, processing, and OpenAPI are absent from public discovery;
- a public access profile reads only the reviewed pre-derived public view, never a non-public raw column, and a profile-bound cursor or ETag cannot cross into another access profile;
- snapshot digest, path replacement, unsafe sidecar, write attempt, and schema mismatch failures.
- `consultation.list` and `consultation.retrieve` discovery with no unsupported family claim.

### Civil-event registry cases

- protected identifier read and named exact verification lookup, with collection listing absent;
- registrar and supervisory access profiles are selected explicitly, are independently scoped, and never fall back; neither read nor lookup scope can synthesize the other;
- the civil journey proves `date-precision` (`year` and `year-month`) with distinct output terms/types; focused transform and real-router tests reject null, noncanonical, incompatible, and oversized source values with value-free source failure;
- the external-issuer path is complete; the optional Mint pairing traverses the same verifier and access-decision path through the Relay client;
- no match, ambiguity, and a jurisdiction-hidden row collapse to the unresolved lookup outcome; an invalid event record or transform input fails as value-free `503 source.unavailable`, while wrong purpose and wrong jurisdiction binding retain their distinct governed refusal behavior;
- the fixed Relay lookup remains an ordinary protected HTTP source contract
  suitable for a future Evidence integration, without adding signing behavior
  to Relay; a real Evidence pairing is a separate non-blocking journey.
- the same Registry Record context and core fields remain present under both operation-specific disclosure profiles.
- no list route exists, including when a caller asks for an access profile identifier.

### Labour-statistics registry cases

- both format-neutral datasets compile only from snapshot views, each with one
  fixed access and required `bindings.sdmx`, while `accessProfiles` and authored
  SDMX alignment targets are rejected;
- dataflow and DSD structure routes serve the exact corresponding generated
  package artifacts; no schema, availability, history, or maintenance route is
  advertised or implemented;
- keyed data and its omitted-key alias produce the same governed operation;
  key/query overlap and an over-broad request fail before release;
- exact bound SQLite predicates preserve declared component storage classes,
  SDMX-JSON preserves string and number types, and SDMX-CSV contains the same
  observations;
- invalid source codes and duplicate observation keys fail atomically as
  value-free source failures;
- the fixed protected-dataflow mapping is missing credential `401
  auth.missing_credential`, missing scope `404 resource.not_found`, and failed
  purpose or authority binding `403 aggregate-data.denied`; structure and
  unknown-flow concealment use `404 resource.not_found`;
- data and structure have distinct value-free audit surface identifiers, JSON
  and CSV have distinct wire-format identifiers, attempt audit failure prevents
  SQLite execution, and terminal audit binds exact held bytes;
- generated data and structure JSON validate against the digest-locked official
  schemas using explicit temporary fetch or an external cache, and generated CSV
  passes the frozen 2.1.0 profile check without vendored schema bytes.

### Classification-review methods

- Social assistance uses `generated` review: its accepted
  `reports/identification-report.json` and exact core-pack digest bind the
  classification-review sidecar.
- Business registration uses `imported` review and remains valid without an
  identification report.
- Civil event uses `manual` review and remains valid without an identification
  report.
- Labour statistics uses `manual` review and remains valid without an
  identification report.
- Missing, stale, deterministic-report-mismatched, sidecar-tampered, or
  generated-pack-mismatched review is refused before production compilation.

### Cross-product and neutrality cases

- four independently instantiated one-Registry services exercise real loopback
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

- a compact scenario table for the four acceptance definitions;
- a security-invariant matrix paired with executable negative-test traceability;
- reproducible generators and drift checks for public and semantic artifacts;
- generated Consultation and statistical-dataflow capabilities plus a maintained Digital Registries, API Design Guide, and SDMX profile alignment note;
- source-product-neutrality and protected-value canary scans;
- an independently tested fixed Relay client route and problem inventory, plus
  offline native-package construction smokes for its Node and Python bindings;
- focused runtime, `relayctl`, editor-integration, shared-SQLite, issuer, audit, and serialization tests;
- the applicable package and workspace formatting, check, Clippy, test, and dependency-policy gates;
- one local end-to-end journey for each coequal registry using synthetic SQLite data and no external credentials.

Optional live demos may supplement this evidence but never replace deterministic local fixtures and tests.
