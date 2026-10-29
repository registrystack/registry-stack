# Adapter: Live Translation Facade

Status: concept, direction accepted 2026-10-30; engine model revised the same
night into a bounded port of Apache Camel (decisions D7 to D15, taken under
delegation and pending Jeremi's confirmation). The crate trio is scaffolded;
no engine code exists yet. This document is the plan of record for the
product's shape, boundaries, and verification. Decisions are recorded in
section 16.

## Executive summary

The Adapter exposes a standard registry API over systems that already hold
data (DHIS2, OpenCRVS, bespoke REST services) without changing their native
APIs. It translates requests and responses live, supporting reads and writes
where the underlying system allows them. It is a translator, not a registry:
it holds no records and decides nothing. Why a call is allowed is the
adapter's own access profile; what happens after a write is the source
system's native process.

The engine is a port of Apache Camel's core to Rust, bounded for a
minimum-disclosure stack. We copy what Camel got right instead of inventing a
parallel vocabulary: the Exchange and Message model, routes authored in
Camel's YAML DSL shape, the enterprise integration pattern processors under
their Camel names with their documented options, defaults, and semantics,
route templates as the unit of reuse (Kamelets), the contract-first REST DSL
as the facade, Camel's error handler, redelivery policy, and exception
clauses, and its testing idiom of intercepting endpoints. Every divergence
from Camel is forced by boundedness, security, or the declared-model
disclosure rule, and is written down in the port table (section 8.10). The port
covers Camel's broad concept set, not only what today's packs exercise: the
engine is a reusable integration piece, and packs for systems not yet named
should find the patterns they need already ported.

The house rule the Base Registry Engine set still holds: the runtime has no
built-in model of any source system. Everything a source system is arrives as
configuration: a pack of route templates and endpoint declarations, written
and validated without touching Rust. A new deployment writes a project file
that instantiates those templates. A new facade contract (a GovStack profile
later) is a new profile artifact.

## 1. Product thesis

Institutions do not lack registries; they lack one agreed way to read and
write the registries they already run. Replacing DHIS2 or OpenCRVS is not on
the table, and every bespoke integration so far has been a one-off. The
adapter makes the integration itself a reviewed, versioned artifact: a pack
of Camel-style route templates that maps a declared model onto a source
system's real API, executed by one bounded engine that owns security,
retries, audit, and contract validation. The same engine serves every pack;
the same pack serves every deployment of that source system; a new
deployment writes only a project file.

## 2. Target deployments

- A ministry running DHIS2 as its health information system, fronting
  tracked entity data for a social protection or case-management consumer.
- A civil registration office running OpenCRVS, exposing registration data
  and, later, registration actions to authorized programs.
- An institution with a bespoke REST or GraphQL system, authoring its own
  pack with implementer staff who do not write Rust.

## 3. Goals

- Live translation of requests and responses; no data copying, no warehouse,
  no scheduled batch in v1.
- Reads and writes (create, update, partial update) where the source system
  allows them, with idempotency and honest failure reporting.
- A per-deployment generated OpenAPI document that states exactly what the
  deployment serves.
- New source systems, and new facade contracts, as configuration artifacts
  validated offline by `adapterctl check`; adding a pack changes no Rust.
- Camel parity for every pattern the engine implements: someone who knows
  Camel reads a pack and predicts its behavior from the Camel documentation,
  except where the port table says otherwise.
- Response compatibility with Registry Record v1, so consumers of Base
  Registry Engine output can read adapter output.
- One native binary, PostgreSQL for the audit journal and the idempotency
  store, deployment story identical to the rest of the stack.

## 4. Non-goals (v1)

- The GovStack Registry Building Block profile (later artifact, plus a
  conformance mode; section 7).
- Message brokers, streaming, scheduled synchronization, batch ingestion,
  polling consumers, and every asynchronous exchange (InOnly).
- SOAP, XML, JDBC, and other envelopes beyond HTTP/JSON REST and HTTP/JSON
  GraphQL (they arrive as compiled-in components, section 8.9, only when a
  real adopter needs one).
- An identity correlation store (source-native identifiers pass through).
- Compensation, rollback, sagas, or transactions across upstream calls
  (section 9).
- Dynamic plugin loading; dlopen-style extension; Java, XML, or Simple.
- BReg governance machinery: proposals, review lifecycle, evidence
  consumption, timers, MCP, statistics, spatial queries.
- `registry-breg-client` compatibility (Record v1 response shape
  compatibility is promised; BReg's opaque authorization handles are not
  replicated).
- Anonymous serving: the facade authenticates every caller.

## 5. Design principles

### 5.1 Translation, not custody

The adapter never stores a record. It holds configuration, audit journal
entries (metadata, digests, outcomes), and idempotency entries (section 9,
the one place a response body is retained, for a bounded window), and
nothing else. The source system remains the system of record and keeps its
native administrative surface.

### 5.2 The declared model is the disclosure boundary

A deployment declares its record types and fields. The facade can only
return what the declaration names, in the shape the facade profile defines,
validated against a closed schema generated from the declaration. A route
that produces an undeclared field fails the exchange; nothing is silently
stripped. A pack cannot widen disclosure; a script cannot smuggle a field
past validation. This is the property that makes a read-write proxy
acceptable in a minimum-disclosure stack: the standard API is the
minimization contract.

### 5.3 System knowledge is configuration

Nothing about DHIS2 or OpenCRVS is compiled in. A pack is a reviewed,
versioned artifact: endpoint declarations, route templates, code maps, and
scripts at declared seams. Engine capabilities grow only under the
two-system rule: a capability is added when a second real system needs it,
otherwise it is pack logic. Components compiled into the engine are named for
mechanisms (`http`, `graphql`), never for products.

### 5.4 Port Camel by default; diverge deliberately and in writing

Where the engine needs a pattern Apache Camel documents, it ports that
pattern: Camel's name, Camel's options, Camel's defaults, Camel's documented
behavior, with the Camel 4.x documentation page as the reference and a
conformance test that restates it (section 13.2). We do not rename,
re-scope, or re-default a documented pattern. A divergence exists only when
boundedness, security, or the disclosure rule forces it, and the port table
records each one with its reason. A capability Camel does not have (the
disclosure check, budgets, write resume) is an addition, marked as such.

Two spelling rules reconcile Camel with `products/platform/CONFIG-CONVENTIONS.md`:

- Configuration keys follow CFG-NAME. A Camel option whose name already
  conforms is kept verbatim (`maximumRedeliveries`, `backOffMultiplier`,
  `stopOnException`, `aggregationStrategy`). One that does not is respelled
  to the convention with the same meaning and default, and the port table
  shows both names (Camel `redeliveryDelay` of 1000 ms becomes
  `retryDelaySeconds: 1` under CFG-NAME-5; `timePeriodMillis` becomes
  `timePeriodMilliseconds` under CFG-NAME-4).
- Values the engine places on the exchange are not configuration keys and
  keep Camel's names verbatim: `CamelSplitIndex`, `CamelSplitSize`,
  `CamelSplitComplete`, `CamelLoopIndex`, `CamelHttpResponseCode`,
  `CamelDuplicateMessage`, `CamelExceptionCaught`, `CamelFilterMatched`.

### 5.5 Bounded by construction

Camel trusts its route author; this engine cannot. Every construct that can
repeat is bounded in the artifact (`loop` and `split` carry mandatory
maxima), the route call graph is acyclic, and `adapterctl check` computes a
static worst-case upstream call count for every bound operation and refuses
one above its declared budget. The runtime enforces the same budgets again.
Errors that guard the boundary (budget exhaustion, disclosure violation,
egress refusal) cannot be caught by any route.

### 5.6 Bounded scripts at declared seams

Scripts are Rhai, executed by `registry-platform-script` with budgets, no
I/O, and precompiled entrypoints, exactly as Evidence, Messaging,
Coordinator, and BReg already run theirs. Rhai is the engine's replacement
for Camel's Simple language and its `bean` and `process` processors. Scripts
read a declared view of the exchange and return a value; they never see
credentials (credentials never enter the exchange) and never construct URLs
(the `http` component builds every request from its declared template).

### 5.7 One contract artifact per deployment

The generated OpenAPI document is the exposed truth: it contains exactly the
operations the deployment binds, no more (D6). Callers learn what exists
today, not what a profile family could someday offer.

## 6. Artifact model

| Artifact | Kind | Registered format | Contains |
|---|---|---|---|
| Facade profile | Authored, versioned, maintained by us | `AdapterProfile` | Operation set by id, methods and paths, envelopes, problem codes and problem schema, parameterized parts. First: `breg-records` v1 |
| Adapter pack | Authored, versioned, reviewed | `AdapterPack` | Per source system, Kamelet-style: endpoint declarations (component, auth kind, tested upstream versions), route templates with typed template parameters, internal `direct:` routes, code maps, script references (own files, digest-pinned), required engine capabilities |
| Adapter project | Authored, top-level | `AdapterProject` | Declared record types and fields, profile and pack references pinned by version and digest, `templatedRoutes` instantiating pack templates, bindings of concrete contract operations to route ids, access profiles |
| Runtime config | Operator | `AdapterRuntimeConfig` | Environment bindings: endpoint base URLs and TLS, secret references, `allowedPrivateCidrs`, listener, database, OIDC, audit retention, from platform shared blocks |
| Fixture suite | Authored, per pack | `AdapterFixture` | Recorded upstream exchanges with expected facade responses, each with provenance (section 13.3) |
| Generated outputs | Build artifacts | read-back, drift-gated | Per-deployment facade OpenAPI and computed schemas, emitted by `adapterctl compile` into the built package |

Projects reference packs and profiles as plain identifiers (CFG-ID-3),
resolved and digest-checked by `adapterctl check` (CFG-ID-4). Packs declare
the engine capabilities they require (components, languages, EIPs); the ctl
refuses a pack the binary cannot run, and the runtime refuses at startup with
a bounded problem. Access profiles live in the project because they are
reviewed deployment policy; the OIDC issuer that authenticates callers lives
in the runtime config because it is environment.

## 7. Facade contract and dynamic payloads

The facade contract is an artifact, not engine code. A profile declares the
operation set (`records.search`, `records.get`, `records.create`,
`records.update`, `records.patch`) with paths, methods, envelopes, and problem
codes, and declares which parts are parameterized by the deployment. The
`breg-records` v1 profile mirrors the Base Registry Engine's public read
surface (`/v1/records/{type}`, `/v1/records/{type}/{record_id}`) plus write
operations, with responses in Registry Record v1 shape through
`registry-record`. The adapter depends on `registry-record` and never on the
`registry-breg` runtime.

Payload content is dynamic: request and response schemas and search
parameters are computed per deployment from the declared model, the same way
BReg's compiler computes its per-package OpenAPI from a registry project. The
compiled contract is concrete per record type: one concrete operation per
(profile operation, record type) pair the project binds.

Serving follows Camel's contract-first REST DSL (section 8.8): the generated
OpenAPI document is the specification the consumer reads at startup; every
concrete operation dispatches to the route its binding names; request
validation against the contract is always on; an operation with no route is
a startup failure (Camel's default `missingOperation` behavior, fixed). Since
the generated contract holds only bound operations (D6), the two rules
coincide: the deployment serves exactly its contract.

Route output is checked twice. `adapterctl check` validates every fixture's
facade response against the generated schema, and the runtime validates the
final exchange body of every route against the closed per-operation result
schema before the engine wraps it in the Record v1 envelope. Fixture values
are checked against declared field types at check time (CFG-VAL-9).

`adapterctl compile` emits the deployment's concrete OpenAPI document into the
built package, held byte-identical by a drift gate. When the GovStack profile
lands it may require its full operation set, served by a conformance mode
that fails a deployment whose contract is incomplete; that mode arrives with
the profile, not before.

## 8. Engine: a bounded Camel core

### 8.1 Crates and module layout

- `registry-adapter-core`: source-neutral model, wire DTOs, `adapter.*`
  problem codes, the route definition model (every EIP, component,
  expression language, and error-handling definition in the port table, as
  reader types), and the pure authoring checks. No I/O.
- `registry-adapter`: runtime. The Camel core lives in modules named for
  Camel's concepts: `exchange`, `route`, `processor` (one submodule per EIP),
  `component` (`direct`, `http`, `graphql`, `rest`), `language`,
  `errorhandler`, `notifier` (the journal), `idempotent`. It serves the
  facade and owns security. Reuses `registry-platform-script`, `-oidc`,
  `-httputil`, `-httpsec`, `-ratelimit`, `-audit`, `-config`, `-yaml`.
- `registry-adapterctl`: authoring and operator tooling; the `adapterctl`
  binary: `check`, `compile`, `fixtures replay`, `verify --live`.

The upstream transport is `registry-platform-httputil`'s
`FixedDestinationPolicy` (opaque templated requests, DNS pinning, mTLS and
private CAs, the explicit private-CIDR allowlist); the facade's server side is
`registry-platform-httpsec`, as Evidence does. The EIP processors
(redelivery, circuit breaker, throttle) are adapter-local: under the
two-system rule they have one consumer, and they move into a platform crate
only when a second product needs them. This program changes no Evidence
crate and no platform crate other than `products/platform` registration.

### 8.2 Exchange and Message

Ported from Camel's `Exchange` and `Message`. An exchange has an
`exchangeId`, a pattern (always InOut in v1), one message (headers and body),
exchange properties, and an exception slot. Headers are a bounded,
case-insensitive map as in Camel. The body is a size-bounded JSON value once
unmarshalled; the `http` and `graphql` components marshal and unmarshal JSON
themselves (divergence: Camel requires explicit `marshal` and `unmarshal`
steps; our components speak exactly one data format, so the step would be
noise).

What enters the exchange is declared. The `rest` consumer places only the
bound operation's validated path, query, and body parameters on it; the
`http` component copies upstream response headers onto it only where the
endpoint declares them (Camel's `HeaderFilterStrategy`, ported as an
allowlist). Credentials, base URLs, and secrets never enter the exchange.

### 8.3 Routes and the YAML DSL

There is no Camel runtime, no JVM, and no Camel YAML file: packs and
projects are our own platform YAML formats (`AdapterPack`,
`AdapterProject`), read by `registry-platform-yaml` with our envelope,
closed schema, digest pins, and offline check (section 12). Inside that
format, the route content follows the structure of Camel's YAML DSL, so a
Camel reader recognizes it. A step is an externally tagged union (CFG-ID-7)
keyed by the Camel EIP name, as Camel's YAML DSL writes it:

```yaml
routes:
  - id: fetchTrackedEntity
    from: { uri: "direct:fetchTrackedEntity" }
    steps:
      - to:
          uri: "http:tracker"
          parameters:
            httpMethod: GET
            path: "/api/tracker/trackedEntities/{id}"
            pathParameters: { id: { header: recordId } }
            query: { program: { constant: "{{program}}" }, fields: { constant: "*" } }
      - choice:
          when:
            - jsonpath: "$.inactive"
              steps:
                - setBody: { constant: null }
          otherwise:
            steps:
              - setBody: { rhai: { file: scripts/tracked-entity.rhai, entrypoint: toRecord } }
```

Divergences, all for boundedness: one route has one `from`; `from` URIs are
`direct:` only (the `rest` consumer dispatches to them, section 8.8); the
route call graph through `direct:` is acyclic and its depth is bounded; every
`loop` and `split` declares its maximum; inline code is refused (CFG-EMBED-1),
so `rhai` always names a digest-pinned file.

### 8.4 Route templates and Kamelets: the pack model

A pack is a catalog of Camel route templates, the role Kamelets play for
Camel. A template declares typed parameters (`name`, `type`, `required`,
`defaultValue`, `description`; divergence: Camel parameters are untyped
strings, ours are typed and checked under CFG-VAL-9) and a route body that
references them as `{{name}}` placeholders, Camel's template syntax, including
`{{?name}}` for an optional parameter. A project instantiates templates with
Camel's `templatedRoute` (`routeTemplateRef`, `routeId`, `parameters`).
Placeholders resolve at instantiation, during `adapterctl check` and at
startup, never per request; a template parameter can only carry authored
values (field mappings, program identifiers, code-map names), never
environment values, which reach the engine only through endpoint ids
resolved in the runtime config.

A template omits `from`; the instantiated route's `from` is
`direct:<routeId>` (divergence: Camel templates carry their own `from`; ours
are always bound by the contract). Packs may also carry ordinary internal
routes for shared sub-flows (`direct:` targets of `to` and `enrich`).

### 8.5 Expression languages

Expressions are externally tagged by language, as in Camel
(`setBody: { jsonpath: "$.instances" }`):

- `constant`, `header`, `exchangeProperty`: Camel's built-in languages,
  inline.
- `jsonpath`: RFC 9535 JSONPath, inline, as Camel's `camel-jsonpath`
  language but on the IETF standard rather than Jayway's dialect
  (divergence). Inline JSONPath needs the CFG-EMBED-1 amendment listed in
  Increment 0: a selector is a query, like the inline regular expressions
  that rule already admits, not code.
- `rhai`: a digest-pinned script file and entrypoint, through
  `registry-platform-script`. This replaces Camel's Simple language,
  Groovy, JavaScript, and `bean` (divergence: not ported).

A predicate is an expression whose result is a boolean; a non-boolean result
is an error, never a truthiness guess (divergence: Camel coerces).

### 8.6 Processors

Ported EIPs and their key options, Camel defaults unless the port table says
otherwise. Section 8.10 is the authoritative list.

- Message transformation: `setBody`, `transform`, `setHeader`,
  `setProperty`, `removeHeader`, `removeProperty`, `script` (runs an
  expression for effect on properties without changing the body, as Camel's
  `script` EIP).
- Routing: `to` (send to an endpoint; static URI, no `toD`), `choice` with
  `when` and `otherwise` (first matching predicate wins), `filter` (nested
  steps run only on match; `CamelFilterMatched` is set; the route continues
  after the filter either way), `stop`, `validate` (a failing predicate
  raises the `validation` class).
- Splitting and aggregation: `split` (`expression`, `aggregationStrategy`
  default returns the original message, `stopOnException` default false,
  `CamelSplitIndex`, `CamelSplitSize`, `CamelSplitComplete`, plus the
  current Camel failure accounting `errorThreshold`, `maxFailedRecords`, and
  `CamelSplitResult`; `parallelProcessing`, `streaming`, and `timeout` not
  ported; mandatory `maximumItems`), `loop` (`expression` count or `doWhile`
  predicate, `copy` default false, `CamelLoopIndex`; mandatory
  `maximumIterations`), `enrich` (`uri`, `aggregationStrategy` default
  replaces the body with the resource reply, `aggregateOnException` default
  false; failure propagates to the error handler, so a record is never
  served without its enrichment unless the pack handles the failure).
- Aggregation strategies, compiled in and named after Camel's built-ins:
  `useLatest`, `useOriginal`, `groupedBody`; plus two additions for JSON
  bodies, marked as such: `jsonArrayAppend` (`from`, `into`, `uniqueBy`;
  a duplicate `uniqueBy` value raises `aggregation.duplicate`) and
  `jsonMerge` (`from`, `into`). A custom strategy is a `rhai` entrypoint over
  the old and new bodies, Camel's custom `AggregationStrategy` bean in our
  form.
- Resilience: `circuitBreaker` with resilience4j semantics and defaults
  (section 8.7), `onFallback`; `throttle` (Camel 4: `mode` TotalRequests
  default or ConcurrentRequests, limit expression, `timePeriodMilliseconds`
  default 1000, `rejectExecution` default false; divergence: a waiting
  exchange waits at most until its deadline, then raises
  `throttle.rejected`).
- Idempotency: `idempotentConsumer` (section 9).

Pagination is not an EIP and gets none: it is `loop` with `doWhile` over the
upstream cursor, an `enrich` per page with `jsonArrayAppend` and `uniqueBy`,
so duplicate and shifting pages fail the exchange instead of merging
silently.

### 8.7 Error handling

Ported from Camel's error handler, redelivery policy, exception clauses, and
`doTry`. Camel's Java exception hierarchy becomes a closed hierarchy of error
classes, matched the way Camel matches exceptions: the closest class in the
hierarchy wins, across the error and its cause; `onWhen` narrows a clause.

```
upstream
  upstream.http          HttpOperationFailedException: status outside okStatusCodeRange (CamelHttpResponseCode set)
  upstream.timeout
  upstream.connection
  upstream.malformed     body not JSON, or over the depth bound
  upstream.tooLarge
  upstream.redirect      redirects are never followed
breaker.open             CallNotPermittedException
throttle.rejected        ThrottlerRejectedExecutionException
validation               PredicateValidationException
conversion.unmapped      NoTypeConversionAvailableException: a code map has no entry
aggregation.duplicate
script                   script error inside its budget
```

Uncatchable, terminal, journaled (an addition with no Camel equivalent):
`budget.exhausted`, `disclosure.violation`, `egress.refused`,
`script.budgetExceeded`. No `onException` or `doCatch` may name them;
`adapterctl check` refuses a clause that does.

- `errorHandler`: `defaultErrorHandler` (Camel's default: no redelivery,
  the error propagates to the caller) and `noErrorHandler`. The Dead Letter
  Channel is not a configurable endpoint: every exhausted exchange is always
  journaled (divergence: the journal is the fixed dead letter).
- Redelivery policy, on the error handler or an `onException` clause:
  `maximumRedeliveries` (default 0, so attempts are one plus this),
  `retryDelaySeconds` (Camel `redeliveryDelay`, default 1 s),
  `useExponentialBackOff` (default false), `backOffMultiplier` (default 2),
  `maximumRetryDelaySeconds` (Camel `maximumRedeliveryDelay`, default 60 s),
  `useCollisionAvoidance` (default false), `collisionAvoidanceFactor`
  (default 0.15), `retryWhile`. `delayPattern` is not ported. Redelivery is
  per failing endpoint send, as in Camel. Divergence for writes: `check`
  refuses `maximumRedeliveries > 0` over a `to` whose `httpMethod` is not
  safe, unless that endpoint operation declares `idempotentUpstream: true`
  (a reviewed claim, for example DHIS2 creates with client-supplied UIDs).
- `onException`: `exception` (classes), `onWhen`, `handled`, `continued`,
  redelivery options, nested steps. `handled: true` ends the exchange with the
  clause's result; the clause sets `CamelHttpResponseCode` and a body that
  must validate against the profile's problem schema with a code from the
  profile's problem code list, so translated detail is declared and a raw
  upstream body cannot pass. `continued: true` resumes the route at the step
  after the failure. An unhandled upstream error surfaces as
  `adapter.upstream.unmapped` (502) with no upstream content.
- `doTry`, `doCatch` (with `onWhen`), `doFinally`: ported as in Camel.
- `circuitBreaker`: resilience4j semantics and defaults, per EIP node,
  process-local state (as in Camel; replicas have independent breakers):
  `failureRateThreshold` 50, `slidingWindowType` count-based,
  `slidingWindowSize` 100, `minimumNumberOfCalls` 100,
  `openStateWaitSeconds` (resilience4j `waitDurationInOpenState`, 60 s),
  `maximumHalfOpenCalls` (resilience4j
  `permittedNumberOfCallsInHalfOpenState`, 10),
  `automaticTransitionFromOpenToHalfOpenEnabled` false,
  `slowCallRateThreshold` 100, `slowCallDurationThresholdSeconds` 60. Each
  default is confirmed against the cited resilience4j and Camel pages when
  the conformance test is written; a default the docs contradict is
  corrected here, not in code. Divergence: a rejected call always raises
  `breaker.open` (Camel's `throwExceptionWhenHalfOpenOrOpenState: false`
  default lets the message continue unchanged, which would answer with the
  request echoed); `onFallback` runs on failure and on rejection, and its
  output is validated like any route output.

### 8.8 Components

- `direct`: synchronous in-process call to another route, Camel's
  semantics; depth bounded.
- `rest`: the facade consumer, ported from Camel's contract-first REST DSL
  (`rest().openApi()`): the generated OpenAPI is the specification; every
  concrete operation dispatches to its bound route; `clientRequestValidation`
  is always on; unmatched requests answer 404 or 405 as in Camel; a missing
  route fails startup (Camel's `missingOperation` default; `ignore` and
  `mock` are not ported). Authentication, authorization (section 10), and the
  envelope are engine-owned on `registry-platform-httpsec`.
- `http`: producer on `FixedDestinationPolicy`. `uri: "http:<endpointId>"`
  names an endpoint declared in the pack and bound to a base URL in the
  runtime config. Parameters: `httpMethod`, `path` (a template whose
  `{name}` segments are filled from `pathParameters` expressions and
  percent-encoded by the engine as single segments), `query` (name to
  expression, engine-encoded), `body` (expression, marshalled to JSON),
  `throwExceptionOnFailure` (default true), `okStatusCodeRange` (default
  `200-299`). Divergence: Camel builds dynamic requests from the
  `CamelHttpPath` and `CamelHttpQuery` headers or `toD`; ours are structured
  and encoded by the engine so no expression can change the origin or inject
  a path. Authentication to the upstream is endpoint-declared and injected at
  send time from secret references.
- `graphql`: producer, Camel's `camel-graphql` shape (`query` as a
  digest-pinned `queryFile`, `operationName`, `variables` expression) over
  the same transport; a GraphQL `errors` array raises `upstream.http`-class
  errors with the declared detail only. Arrives in Increment 3.
- Not ported: every other component, including `log` (value leakage) and
  `mock` outside the test harness (section 13.3).

### 8.9 Component escalation ladder

1. Declarative pack: route templates, endpoints, code maps, `jsonpath`.
2. Pack plus `rhai` seams for logic expressions cannot carry.
3. WASM component (`registry-platform-script` wasm profile): ships as data,
   no engine rebuild, third parties can author them.
4. Compiled-in Rust component, feature-gated, for new protocol envelopes
   only.

Each rung is used only when the one below demonstrably fails; security stays
engine-side at every rung (credential custody, egress allowlist, size caps,
audit, response validation); no dynamic loading in v1; components are named
for mechanisms, never products.

### 8.10 The Camel port table

Every row is the contract for one concept: the Camel 4.x page that defines
its semantics, our form, and what differs. `products/adapter/scripts/check-port-table.py`
holds this table to the code (section 13.2): each ported row names a
conformance test module that exists and passes, and every EIP, component,
or language key the core schema accepts has a row. Inc is the increment that
delivers the row.

| Camel concept | Reference (camel.apache.org) | Our form | Divergence | Inc |
|---|---|---|---|---|
| Exchange, MEP | `manual/exchange.html`, `manual/exchange-pattern.html` | `exchange` module; InOut only | InOnly not ported | 1 |
| Message | `manual/message.html` | Bounded case-insensitive headers, JSON body | Components marshal JSON themselves | 1 |
| HeaderFilterStrategy | `manual/header-filter-strategy.html` (component docs) | Declared header allowlist per endpoint | Allowlist, not denylist | 1 |
| Route, YAML DSL | `manual/routes.html`, `components/next/others/yaml-dsl.html` | `routes` in packs, externally tagged steps | `direct:` `from` only; acyclic; bounded depth | 0 |
| Route template, templatedRoute | `manual/route-template.html` | `routeTemplates` in packs, `templatedRoutes` in projects | Typed parameters; no `from` in templates | 0 |
| Kamelet catalog | `camel-kamelets/next/index.html` | The pack as a reviewed catalog of templates | Not Kubernetes resources; digest-pinned | 0 |
| Property placeholders | `manual/using-propertyplaceholder.html` | `{{name}}`, `{{?name}}` for template parameters only | No environment placeholders in authored files | 0 |
| REST DSL contract-first | `manual/rest-dsl-openapi.html` | `rest` consumer over the generated OpenAPI | Validation always on; `missingOperation` fail only | 1 |
| `direct` | `components/next/direct-component.html` | `direct:<routeId>` | Depth bound | 1 |
| `http` | `components/next/http-component.html` | `http:<endpointId>` on `FixedDestinationPolicy` | Structured, engine-encoded path and query; no redirects | 1 |
| `graphql` | `components/next/graphql-component.html` | `graphql:<endpointId>` | Query from a pinned file only | 3 |
| Languages | `components/next/languages/constant-language.html`, `header-language.html`, `exchangeProperty-language.html`, `jsonpath-language.html` | `constant`, `header`, `exchangeProperty`, `jsonpath` | RFC 9535, not Jayway | 1 |
| Simple, bean, process | `components/next/languages/simple-language.html` | `rhai` files | Not ported; Rhai replaces them | 1 |
| `to` | `components/next/eips/to-eip.html` | `to` | No `toD` | 1 |
| `setBody`, `transform` | `components/next/eips/setBody-eip.html`, `transform-eip.html` | Same | None | 1 |
| `setHeader`, `setProperty`, `removeHeader`, `removeProperty` | `components/next/eips/setHeader-eip.html` and siblings | Same | Header names bounded | 1 |
| `script` | `components/next/eips/script-eip.html` | Same | Rhai only | 1 |
| Content-Based Router | `components/next/eips/choice-eip.html` | `choice`, `when`, `otherwise` | Predicates must be boolean | 1 |
| Message Filter | `components/next/eips/filter-eip.html` | `filter` | Predicates must be boolean | 1 |
| `validate` | `components/next/eips/validate-eip.html` | `validate` | None | 1 |
| `stop` | `components/next/eips/stop-eip.html` | `stop` | None | 1 |
| Splitter | `components/next/eips/split-eip.html` | `split` | Mandatory `maximumItems`; no parallel or streaming | 1 |
| Loop | `components/next/eips/loop-eip.html` | `loop` | Mandatory `maximumIterations` | 1 |
| Content Enricher | `components/next/eips/enrich-eip.html` | `enrich` | Static URI only; no `pollEnrich` | 1 |
| Aggregation strategies | `components/next/eips/aggregate-eip.html` (strategies section) | `useLatest`, `useOriginal`, `groupedBody`, `rhai` | Additions: `jsonArrayAppend`, `jsonMerge` | 1 |
| Default error handler | `manual/defaulterrorhandler.html`, `manual/error-handler.html` | `errorHandler: defaultErrorHandler`, `noErrorHandler` | Dead letter is always the journal | 1 |
| Redelivery policy | `manual/error-handler.html` (redelivery) | Options in 8.7 | CFG-NAME spelling; write-safety refusal | 1 |
| Exception clause | `manual/exception-clause.html` | `onException` | Closed class hierarchy; uncatchable boundary errors | 1 |
| Try, catch, finally | `manual/try-catch-finally.html` | `doTry`, `doCatch`, `doFinally` | Uncatchable boundary errors | 1 |
| Circuit Breaker | `components/next/eips/circuitBreaker-eip.html`, `resilience4j-eip.html` | `circuitBreaker`, `onFallback` | Rejection always raises; fallback on rejection | 1 |
| Throttler | `components/next/eips/throttle-eip.html` | `throttle` | Waits bounded by the deadline | 1 |
| Idempotent Consumer | `components/next/eips/idempotentConsumer-eip.html` | `idempotentConsumer` over the PostgreSQL store | Duplicates replay the recorded response | 2 |
| Type Converter | `manual/type-converter.html` | Code maps; `conversion.unmapped` on a miss | Explicit tables, no converter chains | 1 |
| Event Notifier | `manual/event-notifier.html` | The audit journal's event kinds (section 11) | Synchronous, value-free, before the response | 1 |
| Testing: mock, intercept | `components/next/mock-component.html`, `manual/advice-with.html` | Fixture replay intercepts `http` and `graphql` sends | Test harness only | 0 |

Each reference is a path under `https://camel.apache.org/`; the stream that
writes a row's conformance test confirms the page and corrects the path here
if Camel has moved it.

Not ported, deliberately: Java and XML DSLs, the code-first REST DSL, Simple,
`bean`, `process`, `toD`, `wireTap`, `multicast`, `recipientList`,
`routingSlip`, `dynamicRouter`, `loadBalance`, `pollEnrich`, the stateful
`aggregate` EIP and aggregation repositories, `resequencer`, `delay`,
`sample`, `log`, `saga`, transactions and UnitOfWork, `threads` and parallel
processing, streaming, brokers and the rest of the component library, route
controllers, hot reload, JMX, Camel K, Quarkus, and Spring runtimes. Adding
one later is a port-table row and a conformance test, not an invention.

## 9. Writes, idempotency, and failure semantics

The profile carries create, update, and partial-update operations; a project
binds them per record type, optionally. A write is a route like any other: a
DHIS2 create is one `to` POST whose import summary the route reads with
`choice` and `validate`; an OpenCRVS registration is the source's real
process (draft, declare), several `to` steps in sequence.

- Every route bound to a write operation must be wrapped in
  `idempotentConsumer`; `check` refuses one that is not. Options ported from
  Camel: `expression` (the caller's `Idempotency-Key` header), `eager`
  (default true), `removeOnFailure` (default true), `completionEager`
  (default false). Divergences, from HTTP idempotency semantics and the BReg
  precedent in `crates/registry-breg/src/idempotency.rs`: the key is
  namespaced by caller identity and concrete operation, and bound to the
  request digest (same key, different body, is a 422); a duplicate replays
  the recorded facade response instead of being dropped (`skipDuplicate` is
  not ported); a duplicate arriving while the first is in flight answers 409.
- The idempotency store is PostgreSQL, separate from the audit journal. It is
  the only place the adapter retains a response body: the exact facade
  response, for the key's retention window, then erased by a supervised
  sweep, as BReg's store does. This is a data-minimization decision (D12)
  and carries a security review note.
- `removeOnFailure` before any upstream effect removes the key, as in Camel.
  A failure after a non-safe `to` has been sent keeps the key in a failed
  state and replays the recorded problem; it never re-executes a sent effect.
- Write resume (an addition with no Camel equivalent; Increment 3, where
  OpenCRVS needs it): a multi-step write declares, on each non-safe `to`,
  `resumeBindings`, the source-native identifiers (by `jsonpath`, typed as
  identifiers, bounded length) a later step needs. A same-key retry after a
  failure at step k skips steps 1 to k-1, restores their resume bindings,
  and continues at k. Only declared identifiers are stored, never other
  values. Until Increment 3 lands, a pack with more than one non-safe `to` in
  a write route is refused.
- Batch acceptance (DHIS2 import summaries): success requires full
  acceptance; partial acceptance maps to a bounded 409 problem carrying the
  counts alone (imported, updated, ignored, rejected), never the raw
  upstream summary.
- Conflicts (DHIS2 import conflicts, GraphQL error arrays) map through
  `onException` to bounded 409 problem codes with declared detail only.
- No compensation and no rollback across upstream calls. Recovery is the
  source system's native process surface; the adapter reports exactly where
  a sequence stopped.
- Unknown upstream errors never leak: they surface as
  `adapter.upstream.unmapped`, and mapping totality is tested (section 13).
- Open (D16): a write the source accepts but has not finished (an OpenCRVS
  declaration entering its validation queue, a DHIS2 asynchronous import
  job) has no defined facade outcome yet. The profile must define it before
  Increment 2 starts, for example a 202 with a pollable status or an
  explicit accepted record state; until then such a route is refused.

## 10. Authorization and secrets

Every facade call is authenticated (OIDC via the platform block) and
authorized by the adapter's own access profiles: named bindings of scopes to
concrete facade operations and record types, declared in the project. The
adapter inherits no authorization from any product and grants none to any
source. Upstream credentials live only as `secret:` references in the
runtime config, injected by the `http` and `graphql` components at send time;
the exchange, scripts, packs, diagnostics, and the audit journal never see
them.

## 11. Audit and data minimization

The audit journal is Camel's event notifier, ported as a synchronous,
value-free PostgreSQL journal written before the response is sent. Event
kinds follow Camel's: `exchangeCreated`, `exchangeSending` and
`exchangeSent` (endpoint id, method, path template, status, duration,
response size and digest), `exchangeRedelivery`, `exchangeFailureHandled`,
`exchangeCompleted`, `exchangeFailed` (error class, problem code). Each row
carries the exchange id, the concrete operation, the caller identity, and the
route id. It records no bodies: no request payloads, no response payloads,
no field values, no filled query strings. Retention follows the shared
`audit.retentionDays` block. The idempotency store (section 9) is the one
retained body and has its own retention. Diagnostics are value-free
(CFG-SEC-3); the conformance corpus marker test proves it.

## 12. Configuration formats

All artifacts are read through `registry-platform-yaml` under the rules of
`products/platform/CONFIG-CONVENTIONS.md`: envelopes, one reader, closed
schemas generated from Rust types and drift-gated, editor mapping, conformance
corpus membership, mandatory offline check, `adapter.*` diagnostic codes.

Formats registered at `v1alpha1`: `AdapterProfile` (profile),
`AdapterPack` (pack), `AdapterProject` (project), `AdapterRuntimeConfig`
(runtime), `AdapterFixture` (fixture). The authored/operator split matches
the artifact split: packs, projects, profiles, and fixtures are authored
(hence deterministic, no environment values, no secrets); the runtime file
binds the environment, with substitution and secret references there and
only there.

Rules with consequences for packs:

- Code lives in its own file, referenced by relative path and pinned by
  digest (CFG-EMBED-1): Rhai scripts and GraphQL query files. No inline
  scripts. Inline `jsonpath` selectors require the amendment Increment 0
  makes to CFG-EMBED-1.
- The step union is externally tagged by Camel EIP name (CFG-ID-7); every
  variant refuses unknown keys.
- The universal 1 MiB document bound (CFG-YAML-6) applies, so the code-map
  member is designed so its content can move to a digest-pinned data file
  without a format change when a deployment's option sets outgrow it.

Increment 0 includes the platform change adding the `Adapter` prefix and
`adapter` product token to the conventions tables (CFG-ENV-2, CFG-ENV-3,
CFG-DIAG-3), the five kinds in `products/platform/config-formats.yaml`, and
the CFG-EMBED-1 amendment.

## 13. Quality verification

### 13.1 Gates

- `products/adapter/scripts/check-contracts.sh`: `cargo fmt --check`,
  `cargo clippy` with `-D warnings` over the adapter crates, unit and
  conformance tests, schema regeneration drift, generated OpenAPI drift, CLI
  catalog drift, fixture replay for every maintained pack and example,
  `check-port-table.py`, the config-conventions lint and conformance corpus
  participation through the platform gate.
- `products/adapter/scripts/test-postgres.sh`: the journal and idempotency
  suites on a disposable database with the `postgres-test` feature; it
  starts and removes its own loopback container when no database URL is
  given. A suite that skips because its URL is absent is not verification.
- Root gates for every change: `cargo check --locked --workspace
  --all-targets`, `python3 .github/scripts/test_ci_changes.py`,
  `cargo deny check` when dependencies change.

### 13.2 Camel conformance suite

One test module per ported port-table row, under
`crates/registry-adapter/tests/camel_<concept>.rs` (core-only rows under
`crates/registry-adapter-core/tests/`). Each module restates the cited Camel
page's documented behavior as cases: every option's default, every exchange
property the page names, ordering and matching rules (closest exception
match, first matching `when`, filter continuation), and the behavior at each
documented edge (split with no strategy returns the original message, enrich
with no strategy replaces the body, loop with `copy: false` chains bodies,
default error handler does not redeliver). Each case's doc comment cites the
page. A divergence row has a case asserting our behavior and naming the
divergence. `check-port-table.py` parses section 8.10 and fails when a row's
module is missing or empty, when a schema key has no row, or when a row is
marked delivered by an increment that has not landed.

### 13.3 Pack conformance: fixture replay

Every maintained pack ships recorded upstream exchanges with expected facade
responses. `adapterctl fixtures replay` (and `check`) run them offline the
way Camel tests do: every `http` and `graphql` send is intercepted
(`interceptSendToEndpoint` with `skipSendToOriginalEndpoint`) and answered
from the fixture in order; the outgoing request must match the recorded
method, path, query, and body digest; the facade response must equal the
expected one byte for byte and validate against the generated schema; error
fixtures must map to the expected problem codes.

Provenance is mandatory and honest: each fixture records `kind` (`captured`
from a running instance, or `documented`, synthesized from the source's
published API documentation), the upstream version, and the reference (the
instance version string, or the documentation URL). A pack declares its
tested versions. A fixture without provenance fails check. A `documented`
fixture never claims capture.

### 13.4 Engine fault injection

An in-process upstream double (a scripted HTTP server) drives: timeouts,
connection resets, 5xx storms, malformed JSON, oversized bodies, slow
trickle, redirect attempts, and pagination sequences with duplicate or
shifting pages. These tests prove the ported semantics against their
declarations: redelivery honors `maximumRedeliveries`, the declared delay,
exponential backoff, and collision avoidance bounds; the circuit breaker
moves CLOSED, OPEN, HALF_OPEN at the declared thresholds and admits
`maximumHalfOpenCalls` trials; the throttler enforces the declared mode and
rate; exhausted exchanges land in the journal with the terminal problem code.

### 13.5 Property tests

- Disclosure: no response escapes the declared model, across a generated
  corpus of models and route outputs.
- Idempotency: a replayed key produces the identical facade response and
  exactly one upstream effect, including under injected failure.
- Mapping totality: every declared upstream error class maps to a problem
  code; unknown upstream errors produce the bounded unmapped problem, never
  a leaked body.
- Pagination convergence: no duplicates or omissions across synthetic page
  sequences, including empty pages and page drift.
- Route determinism: the same upstream transcript produces byte-identical
  facade responses.
- Budget exhaustion: exceeding calls, bytes, or the deadline yields the
  bounded problem with a complete journal and no partial response body.
- Static bound soundness: the runtime upstream call count of any exchange
  never exceeds `check`'s computed worst case for its operation.
- Split accounting: with `stopOnException: false` and failure thresholds,
  every item is accounted in `CamelSplitResult`; with `stopOnException:
  true`, the response names the failing item's class without values.
- Write resume (Increment 3): failure at step k journals steps 1 to k-1;
  same-key replay resumes at k with exactly one upstream effect per step.

### 13.6 Contract tests

The runtime serves exactly the generated OpenAPI: every documented route
answers, every undocumented route is refused with 404 or 405. Record v1
responses match `registry-record` serialization goldens and the shape of
BReg's generated per-package OpenAPI (`products/breg/generated/`).

### 13.7 Security tests

Egress allowlist: any call outside the declared base is refused and
journaled, including redirects. Private-address upstreams are expected, not
blocked: government DHIS2 and OpenCRVS instances sit on internal networks.
The platform's fixed-destination policy already decides this correctly;
private CIDRs are reachable only when the runtime config declares them
explicitly (`allowedPrivateCidrs`, bounded count), and plain HTTP stays
confined to those addresses. No expression can alter the origin or inject a
path segment. Uncatchable errors cannot be handled by any `onException` or
`doCatch`. Secrets never appear in the exchange, scripts, diagnostics, or
audit. Script budgets terminate runaway loops. Response size caps are
enforced. Diagnostics are value-free, asserted by the corpus marker. The
idempotency store's retention sweep erases expired bodies.

### 13.8 Quality attributes

- Translation overhead: p99 at or under 20 ms excluding upstream time,
  measured in paired before/after local runs; local numbers are directional
  only and never cited as evidence.
- Memory bounded by `maximumResponseBytes` and the aggregation caps.
- Observability: per-operation structured metrics (mapped and unmapped
  errors, redeliveries, breaker state) and the queryable journal.

## 14. Delivery increments and definition of done

`DELIVERY-PLAN.md` decomposes each increment into streams with runnable
acceptance commands.

- Increment 0, formats and the route model: the platform registration and
  CFG-EMBED-1 amendment; the core model for profiles, packs (endpoints,
  route templates, internal routes, code maps), projects (record types,
  templated routes, bindings, access profiles), runtime config, and fixtures,
  with every Increment 1 step, language, and error-handling definition in the
  port table as reader types; the static checks (reference resolution,
  template instantiation and parameter typing, acyclic bounded route graph,
  mandatory maxima, static worst-case call bound, write-safety refusals,
  uncatchable-class refusal, digest pins); `adapterctl check`; generated
  schemas; corpus examples; `check-port-table.py`.
- Increment 1, the read engine: the Camel core for every Increment 1
  port-table row with its conformance module; the `rest`, `direct`, and
  `http` components; the facade with OIDC and access profiles; `adapterctl
  compile` and the generated OpenAPI; the event-notifier journal on
  PostgreSQL with `test-postgres.sh`; fixture replay; `verify --live`; the
  `dhis2-tracker` pack serving `records.search` and `records.get`; fault
  injection, read property tests, contract and security tests.
- Increment 2, DHIS2 writes: `idempotentConsumer` and the idempotency store
  with replay and retention; write-safety checks live; DHIS2 create and
  update routes with import-summary and conflict mapping; write fixtures;
  write property tests.
- Increment 3, the second system: the `graphql` component; write resume; the
  `opencrvs` pack, reads first, then writes (draft, declare). Before this
  increment starts, the stream confirms which API the current OpenCRVS
  release exposes; if it is not GraphQL, the `graphql` component waits for a
  system that needs it (two-system rule) and the pack uses `http`.
- Later: the GovStack profile and conformance mode; the WASM rung when a
  real pack needs it.

Definition of done for the program, every item verified by a command in
`DELIVERY-PLAN.md`, never by assertion:

1. Every port-table row marked for Increments 0 to 3 has its conformance
   module, green, and `check-port-table.py` passes.
2. An adopter with a DHIS2 instance and a project file serves Record v1
   search, get, create, and update through the adapter, proven over the
   upstream double and by fixture replay, with the generated OpenAPI
   byte-stable and the journal answering every query section 11 promises.
3. The `opencrvs` pack serves reads and writes from the same engine binary.
   The commits that add each pack change no `.rs` file; any engine change a
   pack needed landed in its own commit with its own port-table row.
4. Every gate in 13.1 exists and is green from a clean shell; every property
   test in 13.5 runs in the default suite (or the PostgreSQL suite for the
   stores); the security tests in 13.7 run in `check-contracts.sh`.
5. Every fixture carries honest provenance; the morning report states how
   many are `captured` and how many `documented`.
6. A review report per increment and a final multi-expert review are
   recorded under `products/adapter/reviews/`, with every finding either
   fixed or listed as open.

## 15. Credit and licensing

The exchange model, the route and route-template model, the YAML DSL shape,
the enterprise integration pattern processors, the contract-first REST DSL,
the error handler, redelivery, and exception-clause semantics, the event
notifier, and the endpoint-interception testing idiom follow Apache Camel
(Apache License 2.0), and the pattern vocabulary follows the Enterprise
Integration Patterns book of Hohpe and Woolf. Circuit breaker semantics and
defaults follow resilience4j (Apache License 2.0) as Camel uses it. The
config-first facade over legacy health systems follows the OpenHIE
interoperability layer tradition; connector manifest versioning follows the
Airbyte and Singer practice. The Rust precedent consulted is rust-camel
(Apache 2.0, pre-release): its Tower-native rendering of EIP patterns, its
retry policy shape, and its error dispositions inform section 8. It is not a
dependency: it is a general-purpose route framework with code-first
components, where this product is a bounded facade whose system knowledge is
configuration. No Camel code is copied (it is Java). The port table cites
Camel's documentation rather than reproducing it; if documentation text or
tables are ever lifted, the Camel LICENSE and NOTICE ship beside them, and
the product documentation credits Camel and the EIP book regardless.

## 16. Recorded decisions

| ID | Decision | Date, status |
|---|---|---|
| D1 | Facade is the `breg-records` v1 profile artifact, parameterized by the declared model; GovStack later as a second profile | 2026-10-30, accepted |
| D2 | Packs and profiles are maintained artifacts under `products/adapter/` | 2026-10-30, accepted |
| D3 | v1 scope is reads plus DHIS2 writes; OpenCRVS writes follow as their own increment | 2026-10-30, accepted |
| D4 | Source-native identifiers pass through; no correlation store in v1 | 2026-10-30, accepted |
| D5 | Product name and token: `Adapter`, `adapter` (`AdapterPack`, `AdapterProject`, `AdapterRuntimeConfig`, `adapter.*` codes) | 2026-10-30, accepted |
| D6 | The generated OpenAPI contains only bound operations; a conformance mode arrives with the GovStack profile | 2026-10-30, accepted |
| D7 | The engine is a bounded port of Camel's route model: authored YAML DSL routes, Camel EIP names, options, defaults, and semantics; it replaces the earlier bespoke call-plan vocabulary (`call`, `map`, `normalize`, `paginate`, `iterate`) | 2026-10-30, under delegation, pending Jeremi |
| D8 | Packs are Kamelet-style catalogs of route templates; projects instantiate them with `templatedRoutes`; a deployment writes no routes | 2026-10-30, under delegation, pending Jeremi |
| D9 | The facade is Camel's contract-first REST DSL over the generated OpenAPI, with validation always on and `missingOperation` fail only | 2026-10-30, under delegation, pending Jeremi |
| D10 | Expression languages are `constant`, `header`, `exchangeProperty`, `jsonpath` (RFC 9535, inline, via a CFG-EMBED-1 amendment), and `rhai` (files only), which replaces Simple | 2026-10-30, under delegation, pending Jeremi |
| D11 | Camel semantics, platform spelling: CFG-NAME wins on key spelling, Camel names are kept where they conform, exchange property names stay verbatim | 2026-10-30, under delegation, pending Jeremi |
| D12 | The idempotency store retains the exact facade response for its retention window, separate from the value-free audit journal (BReg precedent); security review note required | 2026-10-30, under delegation, pending Jeremi |
| D13 | Redelivery, circuit breaker, and throttle processors are adapter-local under the two-system rule; the earlier Increment 1 platform stream that would have added them to `registry-platform-httputil` is dropped | 2026-10-30, under delegation, pending Jeremi |
| D14 | Write resume is an addition, deferred to Increment 3 where OpenCRVS needs it; until then a write route with more than one non-safe send is refused | 2026-10-30, under delegation, pending Jeremi |
| D15 | Fixture provenance distinguishes `captured` from `documented`; overnight fixtures are `documented` unless a real instance was run | 2026-10-30, under delegation, pending Jeremi |
| D16 | Facade outcome for a write the source accepted but has not completed | open, Jeremi to decide before Increment 2 |
