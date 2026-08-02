# Trusted request-adapter reference

Status: Implemented Version 1 adopter reference

This is the adopter entry point for the implemented Version 1 trusted
request-adapter model. Source-adapter Rhai is part of the reviewed, immutable
deployment bundle with Evidence YAML, schemas, codelists, and fixtures. Scripts
may render bounded query pairs and one JSON body, extract closed facts, and
derive declared values. Rust retains transport, credentials, authorization,
validation, evidence construction, signing, and audit authority.

All values in this reference are invented. It contains no live credentials,
tokens, responses, or demo-subject identifiers.

The concise colleague-review contract is
[`ADAPTER-API.md`](ADAPTER-API.md). This README explains the design rationale
and provider examples around that Version 1 API.

## Authoring a new adapter

Follow this order. Do not begin with scripts before confirming that the
provider can satisfy the Version 1 request and cardinality boundary.

1. Check the [provider prerequisites](deployment-projects/CONFIG.md#provider-prerequisites).
   Confirm fixed-origin HTTPS access, JSON responses, bounded one-request
   lookup, and reliable distinction among zero, one, and multiple matches.
2. Declare each closed [selector profile](deployment-projects/CONFIG.md#selector-profiles).
   Choose exact scalar fields, bounds, and one authorized value origin for each
   authority path. Possessing a selector never grants authority.
3. Declare the [source and request](deployment-projects/CONFIG.md#source),
   including honest acquisition posture, fixed origin and method, credentials,
   preparation limits, and the response projection Rhai is allowed to see.
4. Write `prepare/2` using only source-required authorized selectors and closed
   parameters. Verify exact logical query order and JSON body shape against
   [`RequestParts`](ADAPTER-API.md#output-from-prepare).
5. Write `extract/2` and a closed fact schema. Map provider cardinality to only
   `match`, `no_match`, or `ambiguous`; never select a candidate or hide a
   provider protocol inconsistency.
6. Declare the [requirement and concepts](deployment-projects/CONFIG.md#requirements-and-concepts),
   including legal reference frameworks, validity, timezone where time matters,
   disclosure family, and exact Supported Value constraints.
7. Write `derive/3`. Declare only the authorized selector fields it needs and
   return the exact [`DerivedConceptValue`](ADAPTER-API.md#output-from-derive)
   set. Keep requester, audience, authority, and transport logic out of it.
8. Write sanitized [fixtures](deployment-projects/FIXTURES.md) covering positive,
   false-as-success, boundary, no-match, ambiguity, missing data, protocol
   failure, privacy canaries, and exact request transport.
9. Run `evidence check --runtime <absolute-runtime-yaml>` to validate the
   complete immutable bundle and runtime bindings.
10. Run `evidence evaluate --runtime <absolute-runtime-yaml> --fixture
    <bundle-relative-fixture-path>` for every referenced fixture before
    deployment.
11. Promote the same reviewed bundle through staging and production using
    environment-specific runtime files and secret mounts. Follow the complete
    [authoring and promotion workflow](deployment-projects/CONFIG.md#authoring-and-promotion-workflow).

The complete projects under
[`deployment-projects/`](deployment-projects/README.md) are maintained
executable references, not pseudoconfiguration.

Offline evaluation proves request materialization, extraction, derivation,
output validation, Evidence construction, ephemeral signing and verification,
and privacy expectations. It does not start HTTP, authenticate a deployment
JWT, resolve deployment source credentials, write audit, or contact a provider.
Use package and HTTP-path tests for those boundaries and staging for the actual
identity, credential, private-CA, source, audit, and signing bindings.

## Design conclusion

Use a trusted script to render provider-specific query parameters and a JSON
body. Do not give that script request-execution authority.

```text
validate and authorize selectors in Rust
    -> durably accept the access-attempt audit
    -> prepare(source_required_selectors, adapter_parameters)
    -> validate RequestParts in Rust
    -> resolve credentials in Rust
    -> execute one fixed request in Rust
    -> parse and bound the response in Rust
    -> extract(response, adapter_parameters)
    -> validate LookupResult in Rust
    -> derive(facts, declared_authorized_selectors, evaluation_context)
    -> validate minimum-disclosure values in Rust
```

Preparation and extraction use fresh script state. Extraction does not receive
the selector bundle or the prepared request. The requirement-specific
derivation receives only the authorized roles and fields declared by its
closed selector-input contract so it can evaluate reviewed relational
semantics against uniquely resolved authoritative facts.
This supports exact parent-reference membership and other governed
deterministic comparisons without giving the source adapter a broad candidate
set or turning Rust into an identity matcher.

This removes the growing YAML placement and interpolation vocabulary. YAML
continues to declare fixed authority, authentication, resource limits, script
paths, and reviewed non-secret constants. The preparation script expresses the
provider's repeated query parameters or nested JSON shape. A new HTTP JSON API
normally needs another reviewed script plus fixtures, not another Rust request
operation or a larger public connector DSL.

## What to learn from connector systems

### Airbyte

Airbyte usefully separates a requester, authentication, pagination, response
selection, and transformation. That decomposition makes each connector concern
reviewable and independently testable. It also demonstrates the failure mode
of a declarative connector language: once arbitrary request and response shapes
must be represented in YAML, request options, selectors, interpolations,
paginators, partition routers, transformations, and custom-component escape
hatches accumulate.

Evidence should keep the component separation but not reproduce the component
catalog. Version 1 needs exactly one evidence-data request, not streams,
partitions, cursor state, pagination, incremental synchronization, discovery,
or retries that create additional evidence reads.

Useful references:

- [Airbyte low-code CDK overview](https://docs.airbyte.com/platform/connector-development/config-based/low-code-cdk-overview)
- [Airbyte requester](https://docs.airbyte.com/platform/connector-development/config-based/understanding-the-yaml-file/requester)
- [Airbyte record selector](https://docs.airbyte.com/platform/connector-development/config-based/understanding-the-yaml-file/record-selector)
- [Airbyte custom components](https://docs.airbyte.com/platform/connector-development/config-based/advanced-topics/custom-components)

### n8n

n8n distinguishes declarative REST nodes from programmatic nodes whose
`execute()` method reads parameters, builds requests, performs I/O, and maps
responses. The attractive part for Evidence is the authoring model: central
transport defaults, separately defined credentials, and small operation-owned
request mappings.

Evidence must not copy the authority of an n8n programmatic node. The adapter
cannot choose a URL, inject authorization, follow a response-provided next URL,
or perform the request.

Useful references:

- [n8n node-building approaches](https://docs.n8n.io/connect/create-nodes/plan-your-node/choose-a-node-building-style/)
- [n8n starter request defaults](https://github.com/n8n-io/n8n-nodes-starter/blob/master/nodes/GithubIssues/GithubIssues.node.ts)
- [n8n operation routing](https://github.com/n8n-io/n8n-nodes-starter/blob/master/nodes/GithubIssues/resources/issue/getAll.ts)
- [n8n credential separation](https://github.com/n8n-io/n8n-nodes-starter/blob/master/credentials/GithubIssuesApi.credentials.ts)

### Vector VRL and Redpanda Connect Bloblang

VRL provides the strongest execution model to copy: compile at startup, operate
on one input, expose no host or network access, keep state local to an
invocation, and make fallible operations explicit. Bloblang provides the best
mapper mental model: the script constructs a new result document rather than
mutating an external source. Evidence supplies isolated per-invocation copies;
local nested mutation is permitted but cannot escape that invocation. Both
systems support direct input-to-output fixture tests.

Evidence must use a curated Rhai surface. General Bloblang, JavaScript, or
Python capabilities such as environment access, files, clocks, randomness,
plugins, counters, and network helpers are outside this adapter ABI.

Useful references:

- [Vector Remap Language](https://vector.dev/docs/reference/vrl/)
- [Vector configuration unit tests](https://vector.dev/docs/reference/configuration/unit-tests/)
- [Bloblang mapping model](https://docs.redpanda.com/connect/guides/bloblang/about/)
- [Redpanda Connect mapping tests](https://docs.redpanda.com/connect/configuration/unit_testing/)

## Version 1 ABI

One reviewed source definition uses two scripts with separate inputs, entry
points, and result validators. Each requirement has one derivation script:

```text
prepare(authorized_selectors, adapter_parameters) -> RequestParts
extract(source_response, adapter_parameters) -> LookupResult
derive(facts, declared_authorized_selectors, evaluation_context)
    -> array<DerivedConceptValue>
```

`authorized_selectors` contains only complete selector profiles that Rust has
already resolved, validated, and authorized. It has this conceptual shape:

```json
{
  "subject": {
    "profile": "person-demographics-v1",
    "values": {
      "given_name": "Synthetic",
      "family_name": "Subject",
      "birth_date": "2000-02-29"
    }
  }
}
```

`adapter_parameters` is trusted, non-secret, startup-only data. It contains
provider field identifiers, fixed program or event identifiers, fixed
projection declarations, and other constants needed by both directions of the
adapter. It contains no credentials or runtime authorization context. A closed
schema validates its exact keys, types, and bounds at startup.

Each source also declares closed `selectorInputs`: permitted roles, profiles,
and fields, but no query/body placements. Rust intersects that declaration
with the already-authorized request and passes only the fields required by the
selected adapter profile. The script never receives the complete Evidence
request or surplus authorized selector fields.

The derivation has its own closed `selectorInputs`, independent of source
request inputs. This distinction lets a source request resolve a child record
using the child's reference while derivation receives only the candidate
parent reference needed to compare with the complete parent-reference set. The
candidate reference need not be sent to the source, and the child selector
need not be exposed to derivation.

`RequestParts` is a closed result:

```text
RequestParts {
  query: ordered list of {name: string, value: string},
  body: null or one JSON value
}
```

The ordered query-pair list is intentional. It preserves repeated parameters
such as DHIS2 `filter` without inventing map-to-array encoding rules.

Rust rejects every other result member, including:

```text
url, origin, path, method, headers, credentials, authentication,
timeout, redirect, retry, pagination, next_request, source
```

Rust also rejects empty query names, CR or LF, unsupported Rhai values,
non-finite numbers, excessive nesting, excessive collections, too many query
pairs, and an oversized normalized request. Query names and values remain
logical raw strings; Rust percent-encodes both exactly once while preserving
pair order and repetition.

## Script capability surface

Trusting the deployment bundle changes the review model, not the execution
boundary. Preparation needs a small additional set of deterministic language
operations so that provider request formats can be expressed without growing a
second YAML interpolation language:

- bounded string concatenation;
- bounded literal replacement for provider-specific escaping;
- bounded array construction and append;
- map construction, indexing, membership, and length;
- integer arithmetic and integer, string, and exact JSON-type comparisons;
- local functions within the same startup-compiled script.

The preparation engine still exposes no environment, filesystem, network,
logger, clock, randomness, dynamic evaluation, imports, modules, plugins, or
credential handles. Rust applies global operation, call-depth, expression-
depth, string, array, map, input, and output limits independently of any checks
written in the script.

Version 1 permits statically named same-file helper functions but forbids
function pointers, data-derived
dispatch, anonymous functions, closures, interpolated strings, raw string
literals, and block or `if` expressions in operand position. It should
not enable Rhai's full standard package.

## Rust-owned request policy

The source definition still fixes:

- HTTPS origin;
- HTTP method;
- normalized path;
- whether a query and/or JSON body is permitted;
- generic Basic, static Bearer, or OAuth client-credentials authentication;
- permitted content type and core-owned headers;
- one evidence-data request;
- denied redirects;
- timeout;
- maximum response bytes;
- per-source concurrency;
- acquisition posture;
- adapter script and parameters.

The trusted script owns provider semantics inside the permitted query/body. A
generic runtime cannot know that `pageSize`, `limit`, or a provider-specific
filter means what the provider documents. That guarantee comes from the
reviewed adapter, exact request fixtures, and mock contract, just as it comes
from reviewed fixed YAML today. Rust still enforces the bounds it can know:
one request, no page traversal, fixed transport authority, bounded output, and
bounded response parsing.

## Reference layouts

The paired references use the same Version 1 ABI:

```text
dhis2-tracker/
  source.yaml
  prepare.rhai
  extract.rhai
  parameters.schema.yaml
  facts.schema.yaml
  prepare-input.json
  expected-request-parts.json
  response-match.json
  response-malformed-count.json
  expected-lookup-result.json

opencrvs-event-search/
  source.yaml
  prepare.rhai
  extract.rhai
  parameters.schema.yaml
  facts.schema.yaml
  prepare-input.json
  expected-request-parts.json
  response-match.json
  response-malformed-count.json
  expected-lookup-result.json
```

Each `response-malformed-count.json` is a negative fixture. Its fractional
provider count must produce `source_protocol_error`, never `match` or
`ambiguous`.

The focused source YAML files are small conformance fragments rather than full
deployment bundles. `selectorInputs` is the placement-free Version 1 source
input contract. The configuration and executable fixture vocabularies are defined in
[`deployment-projects/CONFIG.md`](deployment-projects/CONFIG.md) and
[`deployment-projects/FIXTURES.md`](deployment-projects/FIXTURES.md).

## DHIS2 reference

The DHIS2 example exercises the collection endpoint rather than a dynamic URL.
The preparation script supports two closed, separately authorized profiles:

- one tracked-entity UID rendered as `trackedEntities`;
- one compound selector rendered as repeated exact attribute `filter` pairs.

The example fixes the program, organisation-unit boundary, field projection,
page one, and a page size of two. Rust sends one request and never follows a
page. The extraction script interprets `pager`, `trackedEntities`, and nested
attributes, returning only `no_match`, `ambiguous`, or one status fact.

The provider, not Evidence, evaluates the attribute filters. The script does
not compare returned candidates to the selector values.

DHIS2 documents the tracked-entity collection, attribute filters, `fields`, and
pagination in the [Tracker API 2.43](https://docs.dhis2.org/en/develop/using-the-api/dhis-core-version-243/tracker.html).

## OpenCRVS reference

The deployment-shaped OpenCRVS project uses a uniquely resolved registered
birth event as an authoritative record. It demonstrates three independent
requirements:

- adult status from the event date;
- whether a separately authorized candidate reference is one of the complete
  registered-parent references on that event; and
- the bounded set of registered parents as audience-scoped entity references.

Preparation sends only the child's configured tracking ID. Extraction
validates zero, one, or ambiguous event cardinality and
returns only the facts required by the selected source. For the relationship
source those facts are a complete bounded parent-reference set. The
relationship derivation declares the child reference for returned-record
binding and the candidate-parent reference for exact membership. The
identification derivation converts each raw source
reference to an opaque `EntityReferenceSeed`; Rust then produces
audience-scoped references. Raw parent references do not leave the evaluation
pipeline.

The fact schema also requires `relationship_set_complete: true`, an exact
reference namespace, and a versioned relationship-set contract identifier.
Derivation validates all three before it can return `false` or emit parent
references. Bundle review must establish that absence of each configured
parent slot means authoritatively absent, rather than omitted or unavailable.

OpenCRVS event declarations are country-configured. The example parameterizes
the exact declaration field identifiers that hold stable parent references.
An operator must replace those illustrative field identifiers with fields
whose uniqueness, namespace, completeness, and parent-role meaning are
governed for that deployment. If the country configuration contains only
names and dates, it may use a separately reviewed deterministic attribute rule
and an accurately named concept, or it may expose a governed decision facade.
Evidence must not silently treat a fuzzy search hit as legal parentage.

The reference deliberately calls the portable assertion
`registered-parent-relationship`. A jurisdiction may rename it to
`legal-parent-relationship` only when its law and data governance establish
that the configured record fields and exact matching rule carry that meaning.
Similarly, `registered parent` does not silently mean biological parent,
guardian, or current parental responsibility.

Primary implementation references:

- [OpenCRVS SearchQuery schema](https://github.com/opencrvs/opencrvs-core/blob/ff6a21ae39d16cc113714346ccf73bb76a23e2fb/packages/commons/src/events/EventIndex.ts)
- [OpenCRVS Event Search route](https://github.com/opencrvs/opencrvs-core/blob/ff6a21ae39d16cc113714346ccf73bb76a23e2fb/packages/events/src/router/event/index.ts)
- [Farajaland birth advanced-search configuration](https://github.com/opencrvs/opencrvs-farajaland/blob/4865495d28e3a62d8ee979503fb8139b41439c2c/src/events/birth/advancedSearch.ts)
- [OpenCRVS client query construction](https://github.com/opencrvs/opencrvs-core/blob/ff6a21ae39d16cc113714346ccf73bb76a23e2fb/packages/client/src/v2-events/features/events/Search/utils.ts)

A signed negative is valid only after the child event was uniquely resolved,
the configured parent-reference fields were present and complete, and exact
membership returned false. Zero events, multiple events, absent relationship
fields, malformed declaration data, or a source that does not guarantee a
complete parent set stop before derivation. They never become `false`.

OpenCRVS Event Search currently returns an EventIndex result that can include a
broader country-configured declaration. The reference's extended JSON Pointer
projection is client-side pruning before Rhai, not provider-side field
selection. The broader record therefore crosses the wire and enters bounded
JSON parsing even when extraction receives only the event date or two parent
references. This is honest `record-transformed` compatibility, not
field-projected acquisition. A governed decision endpoint or provider-side
result projection is preferable where available.

The reference also reflects OpenCRVS's current client bootstrap, which places
the client identifier and secret in the token endpoint query string. This
placement applies only to the token request; Rust sends the resulting access
token to `/events/search` in the `Authorization: Bearer` header. Query-string
bootstrap can expose credentials to upstream URL logs, proxies, or tracing.
Use a safer provider-supported placement when available and require complete
token-URL stripping and redaction locally. External provider logging remains a
deployment risk that this adapter design cannot eliminate.

For the simpler adult-status compatibility case, the same preparation ABI can
render the already tested tracking-ID request:

```json
{
  "query": {
    "type": "and",
    "clauses": [
      {
        "eventType": "birth",
        "status": {"type": "exact", "term": "REGISTERED"},
        "trackingId": {"type": "exact", "term": "<authorized selector>"}
      }
    ]
  },
  "limit": 2,
  "offset": 0
}
```

The full deployment-shaped configuration and scripts are under
[`deployment-projects/opencrvs-family-evidence/`](deployment-projects/opencrvs-family-evidence/).

## Required adapter tests

Every preparation adapter should have tests in these groups.

### Startup contract

- The script compiles at startup.
- `prepare`, `extract`, and `derive` exist with the approved arities.
- The bundle contract version selects the supported adapter ABI; a source does
  not declare an independent version unless coexistence is later required.
- Parameters and result schemas are closed.
- Function pointers, anonymous functions, closures, interpolated strings, raw
  string literals, block or `if` expressions in operand position, and top-level
  executable statements are rejected.

### Exact preparation fixtures

- Sanitized ordinary and hostile-character inputs map structurally to their
  normalized `RequestParts` fixtures.
- Repeated query keys and order are preserved.
- Object-member order and fixture whitespace are ignored; query-pair order is
  significant.
- The same input produces byte-equivalent normalized transport output
  repeatedly.
- Missing or unknown roles, profiles, fields, or parameters fail closed.
- No failure includes a selector value.

### Output boundary

- URL, path, method, header, credential, retry, or next-request members fail.
- Excessive depth, string size, collection size, query-pair count, and body
  size fail.
- Unsupported or non-JSON values fail.
- A preparation failure occurs after the durable access-attempt audit but
  before credential acquisition and source access.

### Encoding and injection

- `&`, `=`, `%`, `+`, `/`, `:`, `,`, Unicode, empty strings, and CR/LF are
  covered.
- Rust percent-encodes every query name and value exactly once.
- Selector content cannot change origin, path, method, headers, or the number
  of requests.
- Credential fields cannot be overwritten through query or body data.

### Execution and extraction

- Exactly one request reaches the sanitized mock.
- Redirect, timeout, response-size, and concurrency limits remain Rust-owned.
- Zero, one, two, and provider totals above two map safely.
- No second page or response-provided URL is followed.
- Malformed envelopes, wrong container types, fractional counts, integers
  outside the signed 64-bit range, and count inconsistencies fail as
  `source_protocol_error` or before script invocation, as specified.
- Facts exist only on a unique match.
- Relationship negatives require schema-validated completeness, namespace, and
  relationship-set contract facts; missing or mismatched facts stop without a
  signed boolean.

### Privacy and resource bounds

- Preparation receives no credentials, requester identity, authority object,
  audit handle, logger, filesystem, environment, clock, randomness, or network.
- Extraction receives no selectors or prepared request.
- Derivation receives only validated facts, its declared authorized selector
  inputs, and the closed evaluation context.
- A derivation cannot access an authorized role or field omitted from its
  `selectorInputs` declaration.
- Every invocation has fresh state.
- Operation, call-depth, collection, string, and output limits terminate
  expensive scripts with a safe typed error.
- No test failure artifact prints raw selectors, source facts, credentials, or
  tokens.

Deployment-specific decisions remain bundle review inputs rather than open ABI
questions. In particular, operators must identify the exact provider fields
that carry stable and complete relationship references, document their legal
meaning, and encode that agreement in source parameters, the fact schema,
requirement parameters, and fixtures.
