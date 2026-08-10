# Relay V2 Implementation Plan

Status: Approved implementation plan
Date: 2026-08-10
Product direction: [Relay V2 Product Concept](CONCEPT.md)
Acceptance contract: [Relay V2 Definition of Done](DEFINITION-OF-DONE.md)
Configuration probes: [Relay V2 Configuration Examples](CONFIGURATION-EXAMPLES.md)

## Delivery rule

Implementation starts from the latest `origin/main` in a dedicated worktree.
Relay V2 is added beside the maintained Relay V1. The existing
`crates/registry-relay`, its release artifacts, and `crates/registryctl` remain
unchanged except where a workspace-wide shared-platform dependency requires
ordinary lockfile or CI routing updates. `registryctl` receives no V2 command,
compatibility shim, deprecation, or migration work.

The product is complete only when the full Relay V2 Definition of Done passes
for the social, business, and civil-event acceptance deployments on one
revision. Milestones may merge independently when their own boundary is
complete and green, but no partial milestone is described as Relay V2 complete.

## Target architecture

### Owning packages

| Package | Boundary |
|---|---|
| `registry-relay-v2` | New library and final `relay` binary. Owns the strict Relay contract, compiler, generated artifacts, fixture kernel, access and disclosure plans, wire formats, HTTP service, and Relay event/problem vocabularies. It has no dependency on Relay V1. |
| `registry-relayctl` | New `relayctl` binary. Owns authoring presentation and orchestration only. It links the shared Relay compiler library and never reimplements its rules. |
| `registry-platform-sqlite` | New product-neutral SQLite security boundary shared by Evidence and Relay. It is SQLite-specific, not a generic storage abstraction. |
| `products/relay-v2` | Canonical concept, contract schemas, examples, fixtures, generated artifacts, compact scenario and security traceability, alignment note, and drift scripts. |

`registry-relay-v2` is an internal coexistence name. Its shipped command is
`relay` from the first milestone. V1 retains the `registry-relay` package name
until its separately governed retirement.

### Runtime structure

The runtime crate is organized by responsibility rather than registry domain:

```text
contract -> compile -> immutable CompiledRegistry -> artifacts
                                      |
request -> authentication -> AccessDecision -> DisclosurePlan
                                      |
                       generated SQLite plan -> validated Record
                                      |
                   JSON or JSON-LD -> release audit -> HTTP bytes
```

The HTTP service and offline fixtures call the same compiled kernel. Production
code contains no social, business, company, benefit, household, birth, death,
or CRVS branch. There is one compiled Registry and one administrative trust
domain per process, with any number of related resources under that Registry.

## Frozen interfaces

### Governed and deployment inputs

`RegistryContract` is strict YAML with duplicate and unknown keys rejected. It
owns:

- contract identity and version;
- one Registry identifier, name, Registry Authority, optional operator,
  authoritative scope, base URI, identifier-lifecycle policy, and pinned
  alignment targets;
- reviewed SQLite sources and views;
- resources, Registry Core source bindings, URL-safe camelCase property keys,
  published properties, datatypes, source requiredness, codelists, labels,
  descriptions, and local semantic IRIs;
- compiled list, read, named exact-lookup, or named Point-bbox search operations; query shape remains
  operation-owned while each operation declares one `defaultAccessProfile`
  and finite ordered `accessProfiles` with access-profile-owned `access` and
  `disclosureProfile`; list presence derives the enumeration posture;
- direct typed equality filters, explicit unfiltered permission, fixed ordering,
  page bounds, lookup selectors, and query limits;
- reusable disclosure profiles whose `properties` lists are selected only by a
  compiled access profile; callers may narrow only the selected profile with
  `fields`, never cross profiles;
- privacy, institutional, and `public`/`internal`/`confidential`/`restricted`
  technical handling classifications for every published property and reviewed
  source-view column, including status, provenance, and version, with reviewed
  resource defaults expanded before validation;
- operation scopes, verified-purpose constraints, authority-to-row bindings,
  optional processing sidecars, and metadata visibility.

Every resource binds `recordIdentifier`, `revisionIdentifier`,
`lifecycleState`, and `recordedAt` to reviewed source-view columns. Registry,
authority, schema, and semantic-model references derive from the contract.
Version 1 supports only `string`, `boolean`, `integer`, RFC 3339 `date`, RFC
3339 `date-time`, and `controlled-code` domain properties. Every reviewed view
column must be accounted for as a Record binding, public property, filter,
order key, selector, or row binding. Extra columns fail
compilation. There is no authored SQL and no generic source-adapter trait.

A one-to-one property column inherits that property's classification unless an
explicit source classification is more restrictive. Every non-property Record
Core, selector, row-binding, revision, filter, and order column declares its own
classification. Unclassified reviewed columns fail production compilation.

Every source pins `expectedSchemaFingerprint`. Snapshot source revision is the
captured file digest. Version one live sources are unversioned and report
`{profile: live, status: unversioned, value: null}` in response and audit. They
compile read and exact lookup only. Publisher revisions and live pagination are
not part of the Version one contract.

`sourceRequired` governs validation of the complete authoritative source
Record. It does not make a property mandatory in every requester-minimized
access profile. The compiler emits separate full-record validation and
permitted access-profile artifacts. The latter requires Registry Core and
validates selectable `domainData` properties when present; the former preserves
source requiredness and full SHACL cardinality.

The spatial profile is deliberately closed. `primaryGeometry` has one name,
semantic term, classification, requiredness, exact CRS84 identifier, and two
reviewed SQLite source columns, `longitudeColumn` and `latitudeColumn`. It
serializes only a validated GeoJSON Point. A named `point-bbox` search sets
maximum longitude and latitude spans in whole degrees, requires exactly one
`bbox`, and owns its order, pagination, and access profiles. Lists do not
accept `bbox`, and a list scope cannot synthesize a search. JSON and JSON-LD
are wire formats for every selected access profile; GeoJSON is derived only
when that profile discloses the primary geometry, with
`formatProfile=rfc7946` or `formatProfile=jsonfg` selecting its serialization profile.
Because bbox is a collection-query selector, its primary geometry must have
effective `privacy: non-personal` classification.
There is no storage abstraction, dynamic SQLite extension, GeoPackage parser,
SpatiaLite dependency, generic geometry, or reprojection hidden behind these
fields.

`RelayRuntime` is a separate strict deployment file. It binds listener,
`packagePath`, SQLite paths, at most one issuer and audience, secrets, cursor
key, audit sink, timeouts, concurrency, quotas, and
shutdown.
It cannot add or weaken a resource, operation, disclosure, access rule,
classification, semantic mapping, or metadata visibility decision.
Audit sink and integrity key are mandatory. There is no `failClosed` switch;
durable refusal, source-access, and response-release gating cannot be disabled
by deployment configuration.

The shared compiler library's packager, exposed as `relayctl package`, is the
only production packaging path. It creates a deterministic sealed directory
with:

```text
relay-package.json
registry.yaml
governed/...
compiled/registry.json
generated/openapi.full.yaml
generated/openapi.public.json
generated/artifacts/...
```

`relay-package.json` is canonical JSON containing `packageVersion`,
`packageRevision`, `contractRevision`, the expected SQLite schema fingerprint,
the generated-artifact inventory and operation bindings, and for every relative
regular file its path, size, SHA-256 digest, media type, visibility, and
generated/authored status. `compiled/registry.json` is the canonical compiled
runtime plan produced by the shared compiler.
References cannot escape the directory and symlinks are rejected. The runtime
file, sealed package tree, and their ancestry must be owned by root or the
Relay service user and must not be writable by another account; only a
root-owned sticky directory is accepted as a shared ancestor. Production
packages exclude fixtures and SQLite data. Snapshot and live database paths are
deployment bindings; Relay captures a snapshot digest or explicitly reports an
unversioned live source. Snapshot execution verifies the captured digest before
and after every statement; operators still provide external immutability,
preferably a read-only mount, because no process can exclude a privileged
change-and-restore entirely between those checks. `relay serve --runtime <file>` resolves the sealed
package only from the runtime's `packagePath`; it never accepts a mutable
authoring project or loose contract file.

The complete governed file closure is captured into memory with file count,
size, path, symlink, and permission bounds before parsing. Canonical typed
inputs produce `contractRevision`. Compilation and artifact generation are
atomic packaging operations. Startup verifies canonical compiled bytes, source
schema bindings, governed-file and artifact digests, and operation-artifact
bindings. It recompiles the captured inputs solely to require exact equality
with the packaged runtime plan, then activates the packaged artifacts without
regenerating them. There is no hot reload, partial activation, overlay,
fallback, or remote vocabulary fetch.

Registry Manifest projection is deferred portability tooling. Source columns,
access rules, scopes, disclosure, classifications, processing constraints, and
limits remain Relay-owned and never enter Manifest.

### Identification, review, and governed access-profile increment

The compiler owns the closed access-profile model and never receives
caller-authored transforms or policy expressions. It validates exactly one
`defaultAccessProfile` against each finite operation map; compiles access,
disclosure, processing handling, disclosure handling, transform inventory, and
artifact identity per access profile; and carries operation query shape,
filters, selectors, order, pagination, and quotas outside that map.

`sourceColumnClassifications` remains resource-owned. The compiler requires an
explicit complete reviewed classification for a transformed or multiply-bound
column, accounts for all Registry Core and hidden processing columns, and
rejects a public access profile that processes a non-public column. It accepts
only `partial-string` and `date-precision`: their pure implementation is
separate from parsing, SQL, authorization, and serialization. The marker is
the fixed Relay constant `***`; output types are `string`, `year`, or
`year-month` as applicable.

Identification is a `relayctl` offline workflow over observed schema and the
embedded digest-pinned core pack, never source values. `generate` emits the
four fixed report paths under `generated/reports/` and the starter under
`generated/governance/`. A `ClassificationReview` sidecar is enforced only by
the governed compilation path. Generated review binds an accepted copied report
and rule pack; imported and manual review bind only the inventory and review
authority. The compiler's artifact and package paths carry every profile for
operator review while public projection includes only public-visible profile
artifacts.

`relayctl check --explain` returns the compiler-owned canonical operation
explanation. `generate` writes the same bytes to
`reports/operation-explanation.json`. It lists operation paths, query
capabilities and categorical reasons, access profiles, processed columns,
disclosure, transforms, wire formats, and cache posture without source values
or allowed authorization-claim values.

The HTTP layer parses `accessProfile` once before source access, authenticates
any supplied bearer before public default selection, authorizes the exact
profile, then narrows `fields` within it. Cursor and public ETag construction
include profile identity and transform inventory. Protected, non-public
processing, and live responses are `no-store`. Audit adds access profile,
disclosure, selected properties, both handling levels, and transform IDs, but
no values; terminal audit gates the exact serialized bytes.

### Shared compiler and tooling boundary

`registry-relay-v2` exposes one library API for parsing, compilation, schema
inspection, generation, fixture evaluation, change classification, and
packaging. Both binaries use it directly:

- `relay` owns `serve` and runtime diagnostics;
- `relayctl` owns `init`, `inspect`, `check`, `generate`, `test`, `diff`, and
  `package` authoring workflows.

Diagnostics use stable value-free codes and package-relative locations. A
best-effort `--json` rendering supports CI, but it is not a frozen inter-process
protocol in Version one. `relayctl` does not spawn `relay`, parse human output,
or reimplement compiler rules. A process protocol can be added later if an
external consumer needs one.

### Registry Core and response shapes

Every successful Record has:

```json
{
  "registryIdentifier": "urn:example:registry:businesses",
  "recordIdentifier": "B-00142",
  "revisionIdentifier": "17",
  "lifecycleState": "ACTIVE",
  "schemaReference": "https://registry.example/v2/artifacts/business.schema.json",
  "semanticModelReference": "https://registry.example/v2/artifacts/business.vocabulary.jsonld",
  "authorityIdentifier": "urn:example:authority:registrar",
  "recordedAt": "2026-08-01T10:30:00Z",
  "domainData": {}
}
```

The Registry and Record identifier pair is authoritative. JSON-LD adds a
derived global `@id` and the resource semantic class as `@type` but retains
both identifiers. Lifecycle values come from
the resource's governed codelist. `recordedAt` is source-owned and is never
Relay observation time.

Single read and resolved lookup responses use `{data, meta}`. Lists use:

```json
{
  "items": [],
  "pageInfo": {"nextCursor": null},
  "meta": {}
}
```

Every Record data response `meta` uses this compact vocabulary. Serialization
is deterministic for validators, but member order is not a client contract:

```json
{
  "operationIdentifier": "registeredBusiness.list",
  "family": "consultation",
  "pattern": "list",
  "accessProfile": "public-register",
  "disclosureProfile": "public-register",
  "contractRevision": "sha256:...",
  "sourceRevision": {
    "profile": "snapshot",
    "status": "versioned",
    "value": "sha256:..."
  },
  "selectedFields": ["registrationNumber", "legalName"],
  "links": {
    "self": "https://registry.example/v2/resources/registered-business/records",
    "context": "https://registry.example/v2/artifacts/business.context.jsonld",
    "schema": "https://registry.example/v2/artifacts/business.schema.json",
    "semanticModel": "https://registry.example/v2/artifacts/business.vocabulary.jsonld"
  }
}
```

`family` is always `consultation`; `pattern` is `retrieve`, `list`, or
`search`. A named Point-bbox operation is `search`; a list remains `list`.
`sourceRevision.status` is `versioned` or `unversioned`; `value` is
null only for unversioned live data. `selectedFields` is always present in
contract order, including when the caller omitted `fields`. No other member is
nullable. `semanticModelReference` points to the local vocabulary/model while
`links.context` points to the JSON-LD context. `meta` contains no selector,
row-binding value, raw principal, token, SQL, or protected source value.

Where caching is allowed, a strong ETag hashes the exact response bytes, so
field subsets and access profiles have different ETags. `Vary: Accept,
Authorization`, `If-None-Match`, and `304` are part of the GET contract.
Non-public and unversioned-live responses are `no-store` and emit no ETag.

`fields` is a comma-separated, non-empty, duplicate-free list of public
property keys matching `^[a-z][A-Za-z0-9]*$`. Exactly one `fields` query
parameter is allowed; whitespace, empty members, repeats, semantic IRIs, and
source columns are invalid. It changes only `domainData`, preserves contract
order rather than request order, and is validated before source access. Hidden
columns may still be read for
predicates, binding, complete row validation, and truthful revisions, but are
never serialized.

Narrowing fields never lowers the operation's compiled handling level,
authentication, durable audit, quota, metadata visibility, or cache posture.

A named lookup body is exactly:

```json
{"selectors":{"caseReference":"C-123","personReference":"P-456"}}
```

The top level contains only `selectors`; that object contains exactly the
compiled selector keys. Duplicate or unknown members, missing keys, nulls,
wrong scalar types, coercion, normalization, and extra nesting are rejected.
`fields` remains in the query string and never appears in the body.

For `application/ld+json`, each response carries `@context` and each Record adds
a derived `@id` plus its resource semantic class as `@type`. The generated
context maps response `data` and `items` to JSON-LD `@graph`, aliases
`domainData` to `@nest`, maps its property keys to their semantic IRIs, coerces
Registry Core and domain values to the same IRI or XML Schema datatypes used by
the bound SHACL shape, and maps transport-only `meta` and `pageInfo` to null so
they do not become domain triples. Ordinary JSON retains the shapes above
without `@context`, `@id`, or `@type`.

When the selected access profile discloses the resource's primary
geometry, `application/geo+json` returns an RFC 7946
Feature for a single Record and FeatureCollection for a list or named search. Feature
`properties` carries Registry Core and selected non-spatial domain fields;
`geometry` is the selected Point or `null` when the requester omitted it.
Together they preserve the ordinary governed disclosure. The default
`formatProfile=rfc7946` has no JSON-FG additions. `formatProfile=jsonfg` adds only bounded
JSON-FG conformance and feature-type metadata from the same compiled operation.

### HTTP binding and capabilities

The initial routes are:

```text
GET  /health
GET  /ready
GET  /openapi.json
GET  /v2
GET  /v2/resources?pageSize=...&cursor=...
GET  /v2/resources/{resource}
GET  /v2/resources/{resource}/records?pageSize=...&cursor=...&<declaredFilter>=...&accessProfile=...&fields=...&formatProfile=...
GET  /v2/resources/{resource}/records/{recordIdentifier}?accessProfile=...&fields=...&formatProfile=...
POST /v2/resources/{resource}/lookups/{lookup}?accessProfile=...&fields=...&formatProfile=...
GET  /v2/resources/{resource}/searches/{search}?bbox=...&pageSize=...&cursor=...&accessProfile=...&fields=...&formatProfile=...
GET  /v2/artifacts/{artifactIdentifier}
```

`GET /v2` returns the closed service document
`{registryIdentifier, name, authority, operator, authoritativeScope, product,
apiBinding, alignmentTargets, capabilities, links}`. `product` and `apiBinding`
each contain `name` and `version`; each visible capability identifies its family, pattern,
resource identifier, operation, access profile, default posture, disclosure and semantic references, wire
formats, optional bounded spatial query, and route. Capability, OpenAPI, and explanation surfaces
use `accessProfileIdentifier` and `isDefault` for the same finite profile identity.
`operator` is present and nullable when the Registry has not named one.

`GET /v2/resources` returns `{items, pageInfo, meta}` where each item contains
`resourceIdentifier`, title, description, semantic class, enumeration posture,
visible capabilities, and links, and metadata `meta` contains only
`registryIdentifier`. `GET /v2/resources/{resource}` returns the same resource
object under `{data, meta}`. These metadata envelopes have their own generated
schemas and do not use Record response metadata. Artifact routes
return their declared media type directly rather than a JSON envelope.

`GET /v2` is public Registry service metadata. Its generated schema contains
Registry identifier, name, Authority, operator, authoritative scope, product
and API binding versions, pinned standards and CFR alignment targets, visible
derived Consultation capabilities, and links. Resource and operation details
remain visibility-gated. The maintained alignment note records any intentional
API-guide difference.

Only configured data operations exist. Metadata and artifact responses obey
compiled visibility. `{recordIdentifier}` is opaque, URL-safe, and not a
personal selector. Named lookup bodies are strict, size-bounded, and naturally
idempotent; the query reads at most two rows to distinguish one result from an
unresolved condition.

Operation-bound metadata is exposed only when the caller satisfies the same
static scope, purpose, and authority-claim gate as the operation whose Record
links it. Separate operation profiles receive separate safe artifacts where
necessary. An inaccessible protected resource, operation, or artifact uses the
same `resource.not_found` response as an unknown one and performs no source
query.

Metadata visibility has three executable meanings:

- `public`: mounted for anonymous GET;
- `operation-bound`: mounted behind the referencing operation's static gate;
- `operator-only`: present only in the sealed package and `relay`/`relayctl`
  output, never mounted on the HTTP router.

Registry service identity remains public. Capability visibility derives from
the operations included in resource metadata; it is not configured separately.

List filters are direct declared camelCase query parameters, exact-equality
only, non-personal, unique, and cannot be named `pageSize`, `cursor`,
`fields`, `accessProfile`, `formatProfile`, or `bbox`. Any non-empty subset of declared filters is
valid. A named Point-bbox search requires exactly one
`bbox=minLon,minLat,maxLon,maxLat` predicate. It is finite, CRS84-range-checked,
inclusive, non-wrapping, and bounded by compiled spans before source access. A
list rejects `bbox`. The operation
explicitly declares whether the empty subset is allowed with `allowUnfiltered`.
Transformed properties are response-only and fail compilation when named as a
filter or fixed-order key. A queryable derived value must be a separately
reviewed pre-derived source property.
`pageSize` is bounded by the operation default and maximum. Ordering is fixed
with `recordIdentifier` as the unique tie-breaker.
The client-opaque authenticated-encrypted cursor binds contract and source revisions, operation,
selected access profile and disclosure profile, filters or bbox, fixed order,
fields, wire format, format profile, authorization-relevant context, and
expiry. Every page
is reauthorized. Authenticated encryption prevents filters and keyset-order
values from bypassing field minimization. A caller cannot sort, name a source
column, add an operator, or traverse an uncompiled page.

The first page accepts `pageSize`, `fields`, `accessProfile`, `formatProfile`,
and the complete declared query shape. A continuation request supplies exactly
one `cursor` and may repeat only the same `accessProfile`; the cursor restores the immutable query
context. Repeating or changing first-page parameters with a cursor is
`query.cursor_invalid`.

Version 1 accepts one deployment quota with `requestsPerMinute` and `burst`.
Relay maintains one bucket per compiled operation, shared by all of that
operation's access profiles. The state is bounded and in-process, so the
declared deployment profile is one Relay replica per Registry. A multi-replica deployment must put
a trusted ingress or shared limiter in front that enforces the same ceilings;
distributed rate-limit state is outside the initial runtime.

Compiled operations derive their capability mapping:

- read: `consultation.retrieve`;
- list: `consultation.list`;
- named exact lookup and named Point-bbox search: constrained `consultation.search`.

The generated capability inventory includes Registry identity and authority,
alignment targets, API binding version, operation and resource IDs, pattern
IDs, schema and semantic links, and metadata visibility. It makes no other
family claim and never calls exact lookup Record Match.

For every compiled operation, the compiler proves that each audience allowed a
successful Record can resolve safe projections of the exact
`schemaReference` and `semanticModelReference` embedded in it. Making either
mandatory artifact less visible than its Record is a compile error.

The package contains the full generated OpenAPI 3.1 YAML contract as
operator/package material; it is never mounted on the public router. Public
`/openapi.json` returns `application/json` and is a deterministic safe
projection from the same compiled model, omitting protected resources, lookup
shapes, and operator-only artifacts. It is public, revalidation-cacheable with
a strong ETag, and not filtered per caller. A drift test proves that every
public path is identical in the full artifact and that omissions follow only
compiled visibility. The public projection is reviewed against the maintained
API-guide alignment note; the full artifact is separately validated for
internal completeness. Protected discovery comes through operation-bound
resource and artifact routes.

### Errors, traces, caching, and rate limits

V2 problems contain RFC 9457 `type`, `title`, `status`, fixed safe `detail`,
Registry Stack `code`, and W3C `traceId`. Type URIs remain under
`https://id.registrystack.org/problems/registry-relay/` followed by the code
with dots changed to slashes; draft GovStack BB namespaces and codes are not
used. The service accepts `traceparent`, returns the effective context, and
creates one only when the input is absent or invalid. Every Problem `traceId`
is exactly the effective W3C trace ID as 32 lowercase hexadecimal characters.
Caller-supplied `tracestate` is never propagated because Relay cannot establish
that vendor state is value-free. Audit and server logs use the same trace ID.

No match, ambiguity, policy-hidden record, and unknown or protected identifier
return the same `404` problem and headers. Only independently generated trace
correlation may differ. An invalid selected source row is an authoritative
source failure and returns the value-free `503 source.unavailable` problem.
Malformed requests, credentials, insufficient authority, unsupported wire
format, body size, quota, internal failure, source failure, and audit
failure use stable separate Registry Stack codes without reflecting input
values. Problems are `no-store`.
`401` includes `WWW-Authenticate`; Relay-owned `429` includes a coarse
`Retry-After`. Version one does not freeze a successful-response `RateLimit`
header contract.
For non-public route space, an unauthenticated request receives the same generic
`401` whether the named resource exists or not. After authentication,
visibility-hidden metadata uses the same `resource.not_found` `404` as unknown
metadata.

Version 1 does not negotiate `Accept-Language`. Protocol titles and fixed
problem details are English; semantic and vocabulary artifacts preserve the
language-tagged labels authored in the contract. The alignment note records
response-language negotiation as a future compatibility gap.

The Version 1 public taxonomy is fixed as follows. Titles are the title-cased
code meaning and details are exactly the generic text shown. No field-level
error array is emitted.

| Condition | Status | Code | Fixed detail |
|---|---:|---|---|
| Malformed JSON, query syntax, or lookup body | 400 | `consultation.invalid_request` | `the consultation request is invalid` |
| Invalid, empty, repeated, unknown, or non-public `fields` selection | 400 | `request.fields_invalid` | `field selection is invalid` |
| Malformed, empty, or repeated `accessProfile` selection | 400 | `request.access_profile_invalid` | `access profile selection is invalid` |
| Undeclared filter | 400 | `filter.unknown_field` | `filter is not declared for this operation` |
| Invalid filter value or combination | 400 | `filter.invalid_value` | `filter value is invalid` |
| Malformed, expired, stale, or differently bound cursor | 400 | `query.cursor_invalid` | `cursor is invalid for this query` |
| Missing credential on a protected operation | 401 | `auth.missing_credential` | `a bearer access token is required` |
| Invalid credential | 401 | `auth.invalid_credential` | `bearer access token validation failed` |
| Valid credential without the selected operation or access-profile scope | 404 | `resource.not_found` | `the requested resource was not found` |
| Insufficient purpose or row authority after scope selection | 403 | `consultation.denied` | `the consultation is not permitted` |
| Unknown or visibility-hidden resource, artifact, operation, or access profile | 404 | `resource.not_found` | `the requested resource was not found` |
| Unknown, hidden, ambiguous, or policy-hidden Record outcome | 404 | `consultation.unresolved` | `the requested record was not resolved` |
| Unsupported response `Accept` or `formatProfile` | 406 | `format.unsupported` | `the requested format is not supported` |
| Request body too large | 413 | `internal.payload_too_large` | `request body exceeds the configured limit` |
| Request URI too long | 414 | `internal.uri_too_long` | `request URI exceeds the configured limit` |
| Unsupported request body media type | 415 | `request.media_type_unsupported` | `request body must use application/json` |
| Relay consultation quota exhausted | 429 | `consultation.rate_limited` | `the consultation quota is exhausted` |
| Unhandled failure | 500 | `internal.unhandled` | `the request could not be served` |
| Source unavailable, schema drifted, invalid selected row, or invalid transform input | 503 | `source.unavailable` | `the authoritative source is unavailable` |
| Durable audit unavailable | 503 | `audit.unavailable` | `required audit is unavailable` |
| Service not ready or unhealthy | 503 | `service.not_ready` | `the service is not ready` |
| Request deadline exceeded | 504 | `internal.timeout` | `request exceeded the configured timeout` |

`/health` and `/ready` are unauthenticated and declared with OpenAPI
`security: []`. Their `200 application/json` bodies are respectively
`{"status":"ok"}` and `{"status":"ready"}`. Both are `no-store` and reveal no
Registry, source, issuer, or audit detail. A responding but unhealthy or
unready process returns the `service.not_ready` `503` Problem.

The serving process writes structured lifecycle events and one bounded outcome
event per HTTP request. Request events contain only the fixed method class,
fixed route template, status, bounded latency, and effective trace identifier;
they never contain raw paths, query strings, headers, bodies, selectors,
Record identifiers, or principal identifiers. Version one adds no `/metrics`
route or in-process metrics registry. Operators derive aggregate service
metrics outside Relay from these value-free logs and the durable audit stream.

Every public snapshot response uses
`Cache-Control: public, no-cache`, a strong exact-byte ETag, revalidation, and
`304`. Non-public and live responses are `no-store` and emit no ETag. Live
sources compile read and lookup only, never paginated list.
SQLite path replacement fails closed until restart.

### Authentication, authorization, and audit

Protected operations accept only a registered JWT access-token profile:

- exact configured issuer and one exact configured audience;
- `typ=at+jwt`, configured asymmetric algorithm, and issuer-selected key;
- required valid `exp`, `iat`, `nbf`, bounded `jti`, and a bounded lifetime;
  Relay stores no token replay state and makes no replay-prevention or
  single-use claim;
- principal resolved in order from `sub`, `client_id`, then `azp`, with a
  malformed higher-priority claim failing rather than falling through;
- one exact selected-access-profile scope plus any compiled purpose and row-binding claim.

The deployment has at most one issuer verification configuration. Its exact
issuer is checked before its keys can authorize the token. A missing bearer is
allowed only for an explicitly public default access profile. An anonymous
explicit request for a protected access profile is concealed like an unknown
profile; an invalid bearer is never treated as anonymous. Caller purpose
headers are rejected. Purpose and
row authority come only from verified claims assigned by the authorization
server. Every protected operation scope is non-empty and unique across the
Registry contract. Missing selected-access-profile scope is concealed as
`resource.not_found` before source access. An authority row binding explicitly selects either the
resolved principal or one direct verified scalar claim. Relay injects its
hidden typed equality predicate; caller filters cannot satisfy or replace it.

Every data operation, including public release, uses durable value-free audit
as a release gate:

1. append the attempt before source access;
2. append any refusal before returning it;
3. validate the selected row and transforms before serialization;
4. append a source-failed outcome before returning a source failure;
5. serialize successful bytes and append the release outcome before those exact bytes leave the process.

Audit sink failure returns `503` and prevents source access or response release
at the relevant gate. Events contain stable Registry, resource, operation,
access profile, access-rule, processing, disclosure, transform,
selected-property, handling, contract, and truthful source revision identifiers. They contain no token, selector, SQL,
path, source or response value, or raw principal identifier.

Registry Mint is optional. Relay production crates do not depend on Mint. A
Mint deployment may be paired after core V1 when its server-side client grants
can emit Relay's standard audience, scope, optional purpose, and optional
binding claims. Mint never copies requested authority from the caller. This
pairing uses the same verifier and decision path and does not block Relay V1.

The initial machine-to-machine profile is OAuth client credentials at the
authorization server followed by this JWT access token at Relay. Mutual-TLS
client identity and formal GovStack inter-BB security conformance are deferred;
deployment TLS remains mandatory.

## Milestones

### 0. Canonical contracts and gates

- Import the approved concept, DoD, examples, and this plan into
  `products/relay-v2`; add one compact three-registry scenario table and one
  machine-readable security-invariant matrix.
- Freeze the authored contract vocabulary, Registry Core response, problem
  taxonomy, capability mapping, metadata visibility, token claim profile,
  audit event schema, and expected generated-artifact inventory.
- Add source-neutrality, protected-value canary, and artifact reproducibility
  scripts before runtime behavior grows.

Gate: schemas and examples parse; every security row has an owner, enforcement
point, and planned test ID; no Digital Registries OpenAPI is used.

### 1. Shared SQLite security kernel

- Add `registry-platform-sqlite` with closed value-free errors, snapshot
  capture, immutable read-only open, authorizer, typed results, statement and
  pool limits, cancellation recovery, and fixture-only materialization.
- Move the generic hardened implementation and primitive tests from Evidence.
  Keep Evidence's statement, `evidence_extract`, freshness, source binding,
  response, revision, and error semantics in Evidence.
- Add a behavior-preserving Evidence adapter as a separately reviewable
  checkpoint. Relay compiler work may proceed in parallel once the small
  platform boundary is frozen; Evidence migration must be green before release,
  not before the first Relay slice.

Gate: focused platform tests and CI routing tests. When the Evidence adapter
lands, run its frozen source tests and contract/source-neutrality scripts. Run
one workspace Rust gate because the root workspace changed.

### 2. Relay compiler and deterministic artifacts

- Add `registry-relay-v2` with strict contract/runtime types, closure capture,
  diagnostics, source catalog validation, compiled operations, access rules,
  disclosures, Registry Core, classifications, and immutable revisions.
- Extend `registry-platform-sqlite` with live read-only binding only now that
  Relay is its first consumer: WAL support, a sealed multi-statement read
  transaction, canonical per-transaction schema fingerprint verification,
  same-file update visibility, and path-replacement refusal. No raw connection
  crosses the platform boundary.
- Generate SQL only from reviewed view and column identifiers. Compile a fixed
  query plan for every list, read, and lookup operation.
- Implement the shared offline fixture kernel now: bounded SQLite execution,
  complete Record validation, disclosure, field narrowing, JSON/JSON-LD
  serialization, revisions, and audit-event construction without HTTP.
- Generate local semantic IRIs, JSON Schema, SHACL, JSON-LD context, codelists,
  capability discovery, and full/public OpenAPI.
- Expose compilation, inspection, generation, fixture, diff, and package
  functions through the shared library API.

Gate: compiler and live-platform tests, offline kernel and fixture tests for all
three contracts, byte-reproducible artifacts and packages, unsafe or incomplete
contracts failing before evaluation, and explicit full/public OpenAPI drift
tests.

### 3. `relayctl` adopter workflow

- Add `registry-relayctl` with `init`, `inspect`, `check --explain`, `generate`, `test`,
  `diff`, and `package`.
- Call the shared Relay compiler and fixture library directly for schema
  inspection, checking, generation, fixtures, semantic diff, and packaging.
- Keep inspection schema-only by default. Generate local semantics,
  classifications, processing, and lifecycle-policy starters as visibly
  unreviewed suggestions. A production check rejects unreviewed suggestions.
- Present the authoritative shared-library diff report for security and meaning
  changes, including newly exposed properties, operations, filters, relaxed
  handling, removed bindings, expanded purposes, metadata visibility, source
  views, Record context, and semantic mappings. `relayctl` adds no diff rules.

Gate: command tests against the shared compiler, deterministic packages,
value-free diagnostics, and one complete authoring journey per acceptance
Registry. No `registryctl` file or command changes.

### 4. HTTP service over the compiled kernel

- Mount the already-proven offline kernel behind HTTP and add ETags, cursors,
  list/read/lookup/named-search routes, Registry service metadata, resource metadata,
  artifacts, health, readiness, and safe public OpenAPI.
- Implement exact-lookup collapse, request and concurrency quotas, cursor
  reauthorization, schema drift refusal, live transaction consistency, and
  classification-aware caching.
- Keep route construction hardcoded from compiled operation kinds. Contract
  data chooses which routes exist but cannot supply arbitrary paths or SQL.

Gate: focused route, cursor, access-profile, wire-format, caching, source-boundary, and
non-disclosure integration tests plus generated OpenAPI validation and drift.
The maintained alignment note is reviewed here. A draft GovStack linter is not
a Version one gate.

### 5. Security and release gates

- Use one issuer through the existing supported OIDC discovery path. Add only
  the strict duplicate-member, exact issuer, algorithm, key, audience, token
  type, time, principal, and scope behavior Relay actually needs.
- Complete exact scope confinement,
  trusted purpose, row binding, metadata visibility, W3C Trace Context, stable
  Registry Stack problems, and durable attempt/refusal/release audit ordering.
- Add named negative tests for token parsing and issuer selection, operation
  confinement, public/invalid-bearer behavior, lookup non-enumeration, field
  monotonicity, quotas, audit failures, metadata visibility, and protected-value
  canaries.
- Run an explicit security-invariant review before accepting this milestone.

Gate: every security traceability row executes, unknown/protected/unresolved
responses match except trace correlation, audit failures prevent release, and
no credential, selector, record, SQL, path, or raw principal canary appears in
any diagnostic surface.

### 6. Coequal acceptance and product composition

- Materialize the social, business, and civil-event examples as separate
  synthetic deployment projects and run each through `relayctl`, offline
  fixtures, and a real local `relay` process.
- Use focused parameterized compiler/runtime tests for multi-resource state
  isolation instead of a fourth deployment project.
- Record the standard token contract Mint must emit. Mint grant changes and a
  full Mint pairing are a later independently deliverable integration.
- Record Relay's named lookup as an ordinary protected HTTP source contract for
  a future Evidence integration. A real Evidence pairing remains a separate,
  non-blocking integration journey; Evidence remains the signer and adds no
  Relay authorization model.
- Complete the three-registry scenario table, security matrix,
  source-neutrality checks, and concise alignment note. Record the deferred
  same-operation entitlement variant rather than simulating support.

Gate: every DoD row and three acceptance definitions pass on one revision with
no external credentials. Optional live demos may supplement but never replace
local deterministic evidence.

### 7. Release boundary

Historic Registry Stack releases and their published manifests are immutable.
Relay V2 artifact, image, SBOM, and provenance publication belongs to the next
unused release train after runtime acceptance, using new artifact identities
rather than overloading V1 Relay or `registryctl` keys. A standalone V2 image
contract and generic source/gate inventory may prepare that work without
claiming a historic release published Relay V2. This is a release ownership
boundary, not unfinished runtime behavior.

Gate: the runtime acceptance revision passes its focused source and
gate-inventory checks. The owning future release train runs release
validation, source-model, reproducibility, SBOM, and provenance checks when it
publishes the artifacts.

## Verification policy

Run the smallest relevant package tests while iterating. Group broader and
advanced checks at the milestones above:

- platform and Evidence full compatibility at the SQLite extraction boundary;
- contract, schema, security, OpenAPI, and generated-artifact review when those
  interfaces freeze;
- all coequal acceptance projects only after the runtime path is complete;
- the full workspace Rust and dependency suite once at final integration, plus
  earlier only when a shared platform/root change makes it materially
  necessary; release and reproducibility publication checks belong to the next
  unused release train.

Formatters are check-only until the owning patch is ready. OpenAPI and semantic
artifacts are always regenerated by canonical commands, never hand-edited.
Optional demos, broad documentation sweeps, formal GovStack ceremonies, and
future compatibility profiles do not block focused implementation milestones.

## Explicitly deferred

- caller-dependent maximum disclosure entitlements within one operation;
- a GovStack compatibility flag, BB problem namespace, or formal conformance;
- any Digital Registries family other than the three declared Consultation
  patterns;
- publisher-owned live revisions, live pagination, and live caching;
- multi-issuer selection, new authorization-server discovery modes, and Mint
  grant changes;
- a frozen `relay`/`relayctl` subprocess protocol;
- Registry Manifest, DPV, safeguards, and machine-readable GovStack alignment
  projections;
- Registry multi-tenancy, generic storage traits, PostgreSQL, SpatiaLite,
  GeoPackage decoding, generic geometry, relationships, nested properties,
  arrays, decimals, search language,
  fuzzy matching, and Record Match;
- dynamic masking, general PDP, consent workflow, writes, notification,
  aggregate computation, principal-facing access history, response signing,
  and credential lifecycle;
- any change to `registryctl`.
