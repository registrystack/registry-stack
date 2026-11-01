# Adapter: live facade and governed ingestion

Status: concept, direction accepted 2026-10-30; engine model then revised
into a bounded port of Apache Camel (decisions D7 to D15; section 16
records the status of each). The engine exists and serves the read
operations of the `breg-records` profile (search, get, and read-only POST
reads) over the compiled contract, with wrapped cursors and the value-free
journal; the write operations and the remaining ported EIP set are
contract-only until their increments land (section 8.10 carries the
per-concept status). The ingestion-job mode (section 17) is a contract
amendment of 2026-10-31, restated on 2026-11-01 to the accepted
governed-ingestion design; its amendments are marked `[ingestion]` where
they change accepted wording, the decisions it leaves open are listed in
section 17.6, and section 17.7 states what is built and what may be
claimed. This document is the plan of record for the
product's shape, boundaries, and verification. Decisions are recorded in
section 16.

## Executive summary

The Adapter connects systems through reviewed integration definitions. It
has two modes. A **live facade** exposes a standard registry API over
systems that already hold data (DHIS2, OpenCRVS, bespoke REST services)
without changing their native APIs: it translates requests and responses
live, supporting reads and writes where the underlying system allows them.
An **ingestion job** `[ingestion]` is the exception for the cases where
the receiver must own the record, such as registration into a registry:
it reads a source through a reviewed pack route, finds new and changed
items, and hands each one to exactly one destination, either one BReg
operation through the maintained BReg client or a signed event to
Coordinator. The job keeps each item's identity and the source position,
never its payload; the source stays the buffer. The adapter enforces
integration policy in both modes; it is not a registry, and the called
systems retain domain decisions and authoritative records. Why a call is
allowed is the adapter's own access profile; what happens after a write is
the source system's native process.

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

- Live translation of requests and responses. `[ingestion]` Ingestion jobs
  keep each item's identity and the source position, never a payload, a
  retained captured item, or a stored prepared attempt: a retry re-reads
  the source (section 17.4). The adapter is still no warehouse. A pass is
  started by the job's interval trigger, by a CronJob running one bounded
  pass, or by an operator; a trigger decides only when a pass starts and
  carries no data into it.
- Reads and writes (create, update, partial update) where the source system
  allows them, with idempotency and honest failure reporting.
- A per-deployment generated OpenAPI document that states exactly what the
  deployment serves.
- New source systems, and new facade contracts, as configuration artifacts
  validated offline by `adapterctl check`; adding a pack changes no Rust.
- Camel parity for every pattern the engine implements: someone who knows
  Camel reads a pack and predicts its behavior from the Camel documentation,
  except where the port table says otherwise.
- The exposed API, envelope included, is a profile artifact, never Rust.
  The first profile, `breg-records` v1, answers in Registry Record v1 shape
  so consumers of Base Registry Engine output can read adapter output;
  other target APIs (GovStack, a ministry's own contract) are further
  profile files served by the same binary.
- One native binary, PostgreSQL for the audit journal and the idempotency
  store, deployment story identical to the rest of the stack.

## 4. Non-goals (v1)

- The GovStack Registry Building Block profile (later artifact, plus a
  conformance mode; section 7).
- Message brokers, streaming, and every asynchronous exchange (InOnly).
  `[ingestion]` Source-driven ingestion jobs are admitted with the stated
  limits of section 17: one bounded page per read, one pass at a time per
  job, and no broker as an engine pattern. A queue enters later as a job
  source, acknowledged only after the destination accepts, and hooks enter
  later as a pass trigger on a separate ingress whose body is never trusted
  or stored; neither is built, and checks refuse the hook trigger until it
  is.
- SOAP, XML, and other envelopes beyond HTTP/JSON REST and HTTP/JSON
  GraphQL (they arrive as compiled-in components, section 8.9, only when a
  real adopter needs one). `[ingestion]` Local files and read-only SQL are
  admitted source mechanisms on that same condition: a named adopter or,
  for the file source, the reviewed fixture journeys of section 17, with
  the two-system exception of section 5.3.
- An identity correlation store on the facade (source-native identifiers
  pass through). `[ingestion]` An ingestion job's item table holds, for its
  own items only, the source key and the reference its destination
  returned (a Proposal ID, an Action receipt, or a Coordinator Run ID). It
  resolves no identity: a lookup is a Coordinator workflow's work. The
  facade keeps passing native identifiers and gains no store.
- Compensation, rollback, sagas, or transactions across upstream calls
  (section 9).
- Dynamic plugin loading; dlopen-style extension; Java, XML, or Simple.
- BReg governance machinery: proposals, review lifecycle, evidence
  consumption, timers, MCP, statistics, spatial queries. `[ingestion]`
  Still true in the ingestion mode: a direct job requests one BReg
  operation per item (an immediate Action, or a Proposal start and submit)
  and implements none of BReg's review, application, or governance
  machinery. Delivery is not approval, and approval is not application:
  review and application are seen in BReg and the review provider, never
  reported by the job.
- `registry-breg-client` compatibility (Record v1 response shape
  compatibility is promised; BReg's opaque authorization handles are not
  replicated). `[ingestion]` This stays true for the facade's response
  shape. Separately, the direct destination (section 17.3) uses
  `registry-breg-client` behind an off-by-default feature under the
  dependency gate; that is a client use, not a replication of BReg's
  contract, and no other product's client is linked.
- Anonymous serving: the facade authenticates every caller.

## 5. Design principles

### 5.1 Translation, not custody

The facade never stores a record. It holds configuration, audit journal
entries (metadata, digests, outcomes), and idempotency entries (section 9,
the one place a response body is retained, for a bounded window), and
nothing else. The source system remains the system of record and keeps its
native administrative surface. `[ingestion]` An ingestion job keeps
identity and progress, not payloads (section 17.4): its item table holds
each item's source key, a digest of its projection, a change sequence, a
status with the destination's code, and the destination's reference, and
never the item's values. There is no sealed custody, no vault, no retained
captured item, and no stored prepared attempt: the source is the buffer,
and a retry re-reads it. The one place a job writes payloads is the bulk
hand-off file an operator imports with `bregctl data import`, which is in
the operator's custody. The adapter still keeps no registry, no warehouse,
and no analytical copy of any source.

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
mechanisms (`http`, `graphql`), never for products. `[ingestion]` Two
scoped exceptions, both still open for confirmation in section 17.6:

1. **Job source components.** `file`, `sftp`, and read-only `postgres`
   enter the engine as job-only mechanisms (section 17.2), refused by
   `check` in every facade route. Kobo and a local file fixture are one
   real system and one fixture, which does not satisfy the two-system rule
   on its own; the exception is explicit because the product's range
   across sources is the stated reason to build them, source independence
   (protocol, transport, and data format separated, section 17.1) is the
   property the rule protects, and a file fixture is the cheapest proof
   that nothing is Kobo-specific. If the exception is refused, the
   components wait for the second real system.
2. **The BReg client for the direct destination.** Adapter otherwise links
   no other product's types. The one exception is
   `registry-adapter-connectors`: it alone links a product client, and
   only `registry-breg-client`, behind an off-by-default cargo feature,
   and holds the parked BReg connector for the direct destination
   (section 17.3). It is a client, not an engine capability: it lives
   outside the facade binary, never adds route vocabulary, and the rung 4
   rule ("new protocol envelopes only") keeps governing engine
   components. No other product client enters, and no Scheduling or
   Document Store connector is planned. Coordinator is reached only
   through its published signed-event contract; no Adapter crate links a
   Coordinator crate.

### 5.4 Port Camel by default; diverge deliberately and in writing

Where the engine needs a pattern Apache Camel documents, it ports that
pattern: Camel's name, Camel's options, Camel's defaults, Camel's documented
behavior, with the Camel 4.x documentation page as the reference and a
conformance test that restates it (section 13.2). We do not rename,
re-scope, or re-default a documented pattern. A divergence exists only when
boundedness, security, or the disclosure rule forces it, and the port table
records each one with its reason. A capability Camel does not have (the
disclosure check, budgets, write resume) is an addition, marked as such.

The reference is pinned: Apache Camel release tag `camel-4.23.0` (commit
`b2329103df8f5d1edfca2ad262be09e3be95ee68`). The port table cites
camel.apache.org paths as readable pointers, but the authoritative text is
the documentation and source at that tag: the same pages as AsciiDoc under
`docs/` and `components/*/src/main/docs/`, and the Java that implements
them. Where a page is silent, ambiguous, or gone, the source decides, and
Camel's own unit tests at the tag are the first source of conformance
cases. We port behavior, not code: contributors read the Java to learn the
semantics and write idiomatic Rust, never a line-by-line translation.
`[ingestion]` When a conformance case is adapted from a Camel unit test,
the case names the upstream test class and method, the port record lists
every upstream test ported or recorded as inapplicable, and any adapted
material keeps the Apache-2.0 attribution and exact provenance the license
notice in section 15 requires; NOTICE handling for adapted code is
confirmed before the first release that ships an adaptation. Moving the pin
is a reviewed change that re-checks every row whose cited source changed
between the two tags.

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
  `CamelDuplicateMessage`, `CamelExceptionCaught`, `CamelLoopSize`.

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
| Facade profile | Authored, versioned, maintained by us | `AdapterProfile` | Operation set by id, methods and paths, request and response envelope templates, pagination parameters, the problem envelope and the `problems` list mapping error classes to problems (section 8.11.6), parameterized parts. First: `breg-records` v1 |
| Adapter pack | Authored, versioned, reviewed | `AdapterPack` | Per source system, Kamelet-style: endpoint declarations (component, auth kind, tested upstream versions), route templates with typed template parameters, internal `direct:` routes, code maps, script references (own files, digest-pinned), required engine capabilities |
| Adapter project | Authored, top-level | `AdapterProject` | A `project` block (ProjectIdentity `id` and `version`, CFG-ENV-6), declared record types and fields, profile and pack references pinned by version and digest, `templatedRoutes` instantiating pack templates, bindings of concrete contract operations to route ids, access profiles |
| Runtime config | Operator | `AdapterRuntimeConfig` | Environment bindings: endpoint base URLs and TLS, secret references (credentials and the cursor key `cursorKeyRef`), `allowedPrivateCidrs`, listener, database, OIDC, audit retention, from platform shared blocks |
| Ingestion job definition `[ingestion]` | Authored, versioned, reviewed | `AdapterJob` | A named job: its identity, the pack and source route it runs (whose scan, recovery, and edit declarations the pack carries), the projection (the declared fields the destination needs, and what the item digest covers), its triggers, and the job profile (section 17.2 limits, explicit and bounded). The destination binding arrives with the destination increments of section 17.3. `adapterctl job check` checks it against the pack; the job compiler (section 17.2) compiles it with no listener, database, or OIDC issuer |
| Ingestion job runtime config `[ingestion]` | Operator | `AdapterJobRuntimeConfig` | The job's environment bindings, conventionally `job-runtime.yaml`: endpoint base URLs, TLS, and secret references for the endpoints every mode shares, the job source bindings (a file directory with its read options, a PostgreSQL connection), the job store, and `allowedPrivateCidrs`. It states none of the facade's members (listener, database, OIDC, allowed clients, audit, idempotency, cursor custody) |
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

The facade contract is an artifact, not engine code, and nothing about any
one target API is compiled in (D17). A profile declares its operation set
with paths, methods, request and response envelopes, pagination parameters,
and problem codes, and declares which parts are parameterized by the
deployment. Facade operation paths are single-brace `{name}` templates,
the facade HTTP path template of Camel's REST DSL (`rest get /{id}`) and
OpenAPI path templating, while `{{name}}` is the pack layer's substitution
syntax (Camel property placeholders, the port table in section 8.10); the
profile check resolves each `{name}` in an operation path against that
operation's path parameters. An operation names, among its path
parameters, the one carrying the record type (`recordTypeParameter`) and,
exactly when the operation declares a path parameter beyond that one, the
one carrying the record identifier (`recordIdParameter`; for
`breg-records`, the get, update, and patch operations); the facade places
the `recordId` input of section 8.11.1 where `recordIdParameter` is
declared, and no rule reads meaning from a parameter's position.
`adapterctl compile` substitutes the bound record type into the path, so
the contract carries concrete paths (`/v1/records/persons`), as BReg's
per-package OpenAPI does. An operation also declares its `successStatus`
(default 200; the `breg-records` create answers 201, as BReg does). The first profile, `breg-records` v1, is a starting target, not
the only one: it mirrors the Base Registry Engine's public read surface
(`/v1/records/{type}`, `/v1/records/{type}/{record_id}`, operations
`records-search` and `records-get`) plus write operations
(`records-create`, `records-update`, `records-patch`), answering in
Registry Record v1 shape.
GovStack, or a contract a ministry already publishes, is another profile
file.

An envelope is a JSON template in the profile with slots from a closed
vocabulary the engine fills: `record` (one validated route result),
`records` (the validated result list), `recordType`, `recordId`,
`nextCursor`, `requestId`, and, in the problem envelope, `problemCode`,
`problemTitle`, `problemDetail`, optional whole-value `problemData`, and
`status`. Request envelopes name where the
writable record sits in an incoming body; pagination parameters name the
cursor and page-size query parameters and their bounds. The profile's
`problems` list declares each problem a caller can receive (`code`,
`status`, `title`, and the error `classes` it answers, section 8.11), so a
pack raises error classes and never names a profile's problem codes or
builds a problem body. `adapterctl check` refuses an unknown slot, a
response envelope without its result slot, a problem envelope without its
code slot, and a profile under which some error class resolves to no
problem or to more than one. The engine owns the mechanism (filling slots,
encoding cursors, setting the status); the profile owns every name and
shape a caller sees. Section 8.11 is the contract between the three: what
the facade places on the exchange, what a route hands back, and how errors
become problems.

This keeps three artifacts independent: a pack knows a source system and
produces records in the project's declared model; a profile knows a target
API; a project binds one to the other. The same DHIS2 pack serves a
`breg-records` deployment and a later GovStack deployment unchanged. The
adapter's only link to BReg is test-time: `registry-record` is a
dev-dependency whose serialization goldens prove the `breg-records`
profile's envelope byte-compatible (section 13.6); the adapter never
depends on the `registry-breg` runtime. `[ingestion]` The one runtime
exception is `registry-adapter-connectors` (section 17.3): it depends on
`registry-breg-client` and no other product client, is compiled only
behind an off-by-default cargo feature, and is linked by no facade
binary; the dependency gate of section 17.5 proves that separation
mechanically. The facade's response-shape promise
above is unchanged.

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
schema before the engine places it in the profile's envelope. Fixture values
are checked against declared field types at check time (CFG-VAL-9).

`adapterctl compile` emits the deployment's concrete OpenAPI document into the
built package, held byte-identical by a drift gate: by default
`<project-dir>/generated/openapi.json`, pretty-printed with sorted keys and
a trailing newline so its diff is the contract review, for any project
directory and not only the repository's. Key order is canonicalized
explicitly wherever bytes are digested or emitted: `serde_json`'s
`preserve_order` feature is enabled in the runtime's dependency graph
(through `rhai`), so no digest or generated output relies on map iteration
order, and the compile output is identical with the feature on or off. One concrete operation per bound
(profile operation, record type) pair, `operationId`
`<operation>.<recordType>`. A parameterized part is a deployment value the
contract cannot know, so the schema types it as a string, never as the
stand-in literal. When the GovStack profile
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
  `-httputil`, `-ratelimit`, `-resilience`, `-config`, `-yaml`,
  `-authcommon`, `-crypto`, and `-canonical-json`.
- `registry-adapterctl`: authoring and operator tooling; the `adapterctl`
  binary: `check`, `compile`, `fixtures replay`, `verify --live`.

The upstream transport is `registry-platform-httputil`'s
`FixedDestinationPolicy` (opaque templated requests, DNS pinning, mTLS and
private CAs, the explicit private-CIDR allowlist). The Axum facade uses the
shared OIDC verifier and keeps its profile-shaped problems and freshly
minted request IDs inside the Adapter. Its PostgreSQL audit journal owns
the durable release gate; it does not use the platform's file audit writer.
The generic
mechanisms under the resilience processors are built in platform crates from
the start (D13): the rolling-window limiter in `registry-platform-ratelimit`,
and the circuit breaker state machine and redelivery delay computation in
`registry-platform-resilience`. Neither knows an exchange, a route, or an
error class. The `throttle` and `circuitBreaker` processors and the redelivery
loop stay in the adapter with their Camel semantics and written divergences.
This program changes no Evidence crate; its platform changes are these
primitives, additive constructors accepted in review, and `products/platform`
registration.

### 8.2 Exchange and Message

Ported from Camel's `Exchange` and `Message`. An exchange has an
`exchangeId`, a pattern (always InOut in v1), one message (headers and body),
exchange properties, and an exception slot. Headers are a bounded,
case-insensitive map as in Camel. The body is a size-bounded JSON value once
unmarshalled; the `http` and `graphql` components marshal and unmarshal JSON
themselves (divergence: Camel requires explicit `marshal` and `unmarshal`
steps; our components speak exactly one data format, so the step would be
noise).

Split and loop metadata (`CamelSplitIndex`, `CamelSplitSize`,
`CamelSplitComplete`, `CamelSplitResult`, `CamelLoopIndex`, and
`CamelLoopSize`) lives in exchange properties, as at the pinned Camel tag.
These names have no header aliases and authored steps or aggregation
results cannot overwrite them.

What enters the exchange is declared. The `rest` consumer places only the
bound operation's validated inputs on it, under the closed names of section
8.11.1; the `http` component copies upstream response headers onto it only
where the endpoint declares them, and sends exchange headers upstream only
where the endpoint's `requestHeaders` allowlist names them (Camel's
`HeaderFilterStrategy`, ported as two allowlists, section 8.11.4).
Credentials, base URLs, and secrets never enter the exchange, and no
expression or header can carry them out.

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
  - id: fetch-tracked-entity
    from: { uri: "direct:fetch-tracked-entity" }
    steps:
      - to:
          uri: "http:tracker"
          parameters:
            httpMethod: GET
            path: "/api/tracker/trackedEntities/{{id}}"
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
- Conversion: `convertBodyTo` and `convertHeaderTo` with Camel's options
  (`type`, `name`, `toName`, `mandatory` default true; `charset` not
  ported), plus `convertPropertyTo` with `convertHeaderTo`'s options, an
  addition because routes carry intermediate values in properties where
  Camel 4 uses variables, which are not ported. Divergence: `type` names a
  code map, `codeMap:<id>`, never a Java type. A code map maps an
  `ExternalId` key to one JSON scalar; lookup is exact and case-sensitive
  over a string input. As in Camel (`ConvertBodyTest.testConvertNullBody`),
  a null or absent input passes through unchanged whatever `mandatory`
  says; any other non-string input, or a miss, raises
  `conversion.unmapped`, and with `mandatory: false` a miss leaves the
  target absent. Rhai scripts reach the same lookup through
  `code_map(id, key)`. Every typed conversion reference is a literal id that
  resolves, and `check` refuses a declared map no typed conversion step
  references. A `code_map` call used only inside a script does not exempt a
  declared map from that unused-map refusal.
- Routing: `to` (send to an endpoint; static URI, no `toD`; an `http` send
  may follow an origin-pinned link through `httpUri`, section 8.11.5),
  `choice` with `when` and `otherwise` (first matching predicate wins),
  `filter` (nested steps run only on match; the route continues after the
  filter either way; `statusPropertyName`, absent by default, names an
  exchange property that records the boolean outcome, as Camel 4's
  `FilterProcessor` does; Camel 4 sets no fixed filter property), `stop`, `validate` (a
  failing predicate raises the `validation` class), `throwException`
  (raises a declared catchable error class with a constant message, section
  8.11.6).
- Splitting and aggregation: `split` (`expression`, `aggregationStrategy`
  default `use-original` with `propagateException: true`, so the original
  message returns and an item failure is raised after every item has run,
  as `Splitter` does; `stopOnException` default false,
  `CamelSplitIndex`, `CamelSplitSize` (set before the first item; our split
  does not stream), `CamelSplitComplete`, plus the
  current Camel failure accounting `errorThreshold` (a ratio in 0 to 1,
  stopping once the failure ratio reaches it) and `maxFailedRecords`
  (stopping once failures reach it), each exclusive with
  `stopOnException`, and `CamelSplitResult`, set only when one of the two
  is configured; `parallelProcessing`, `streaming`, `timeout`, `group`, and
  `onPrepare` not ported; divergence: the expression must yield a JSON
  array, where Camel also splits maps and strings; mandatory
  `maximumItems`), `loop` (`expression` count or `doWhile`
  predicate, `copy` default false, `CamelLoopIndex`, `CamelLoopSize` for a
  count loop; mandatory `maximumIterations`; the `doWhile` predicate is
  evaluated on the current exchange before every iteration, the first
  included, so a false predicate runs no iteration, and a count of zero
  or less runs none either, as `LoopProcessor` does at the pinned tag), `enrich` (`uri`, `aggregationStrategy` default
  replaces the body with the resource reply, `aggregateOnException` default
  false; failure propagates to the error handler, so a record is never
  served without its enrichment unless the pack handles the failure).
- Aggregation strategies, compiled in and named after Camel's built-ins:
  `use-latest`, `use-original` (`propagateException`, default true),
  `grouped-body` (skips null bodies; an empty split yields an empty
  array); plus two additions for JSON
  bodies, marked as such: `json-array-append` (`from`, `into`, `uniqueBy`;
  a duplicate `uniqueBy` value raises `aggregation.duplicate`) and
  `json-merge` (`from`, `into`). A custom strategy is a `rhai` entrypoint over
  the old and new bodies (named `oldExchange` and `newExchange`), Camel's
  custom `AggregationStrategy` bean in our form.
- Resilience: `circuitBreaker` with resilience4j semantics and defaults
  (section 8.7), `onFallback`; `throttle` (Camel 4: `mode` TotalRequests
  default or ConcurrentRequests, limit expression, `timePeriodMilliseconds`
  default 1000, `rejectExecution` default false; divergence: a waiting
  exchange waits at most until its deadline, then raises
  `throttle.rejected`).
- Pack guidance for both resilience processors: state belongs to the EIP
  node and is shared by every bound operation and `direct:` call that reaches
  that node for the process lifetime. Replicas have independent state, so a
  pack must not use either processor as a per-caller quota or assume a
  deployment-wide shared state.
- Idempotency: `idempotentConsumer` (section 9).

Pagination is not an EIP and gets none. The facade side is the
continuation contract of section 8.11.2: the route reads
`AdapterContinuation` and sets `AdapterNextContinuation`; the engine owns
the caller-facing cursor. Two upstream shapes cover the sources seen so far:

- One facade page per upstream page (the default, and the cheapest bound):
  one `to` whose query or `httpUri` comes from `AdapterContinuation`, then a
  `setProperty` of `AdapterNextContinuation` from the upstream's cursor,
  offset, or next link, absent on the last page.
- Several upstream pages per facade page: `loop` with `doWhile` over a
  property holding the upstream cursor, seeded before the loop so the
  predicate holds before the first fetch, an `enrich` per page with
  `json-array-append`, `uniqueBy`, and `properties` (which carries the next
  cursor or link out of the reply, section 8.11.7), so duplicate and
  shifting pages fail the exchange instead of merging silently; the loop's
  `maximumIterations` bounds the calls, and reaching it raises
  `loop.maximum-iterations-reached` unless the route stops earlier and hands
  the remainder back as `AdapterNextContinuation`.

### 8.7 Error handling

Ported from Camel's error handler, redelivery policy, exception clauses, and
`doTry`. Camel's Java exception hierarchy becomes a closed hierarchy of error
classes. One failed exchange carries one `RouteFailure` class; the closest
declared ancestor of that class wins, and `onWhen` narrows a clause. This
single-class failure is a bounded divergence from Camel's cause-chain match.

```
upstream
  upstream.http                      HttpOperationFailedException: status outside okStatusCodeRange (CamelHttpResponseCode set)
  upstream.timeout
  upstream.connection
  upstream.malformed                 body not JSON, or over the depth bound
  upstream.too-large
  upstream.redirect                  redirects are never followed
breaker.open                         CallNotPermittedException
throttle.rejected                    ThrottlerRejectedExecutionException
loop.maximum-iterations-reached      a doWhile loop still true at maximumIterations
validation                           PredicateValidationException
conversion.unmapped                  NoTypeConversionAvailableException: a code map has no entry
aggregation.duplicate
script                               script error inside its budget
outcome                              raised by a pack (throwException), never by the engine
  outcome.not-found                  the source has no such record
  outcome.conflict                   the source refused the write as conflicting
  outcome.invalid-request            the source refused the request as malformed for it
  outcome.rejected                   the source refused the write for its own reasons
```

Class names are kebab-case segments joined by dots. The `outcome` branch is
an addition: it is how a pack says what a source meant (a 404, an import
summary with status ERROR inside a 200) in profile-neutral terms, and the
profile decides the problem a caller sees (section 8.11.6).

Uncatchable, terminal, journaled (an addition with no Camel equivalent):
`budget.exhausted`, `credential.rejected` (the upstream refused the
deployment's credential after the single token refresh of section 10.2; it
sits outside `upstream` so no clause for `upstream` matches it),
`disclosure.violation`, `egress.refused`, `script.budget-exceeded`. No
`onException` or `doCatch` may name them, and `adapterctl check` refuses a
clause that does. A `RouteFailure` carrying one of them fires no clause.

Facade classes, raised by the `rest` consumer outside any route, so neither
catchable nor raisable: `facade.unauthenticated`, `facade.forbidden`,
`facade.invalid-request` (contract validation), `facade.invalid-cursor`
(a cursor that fails section 8.11.2, answered 400), `facade.not-found` (no
record path matched), `facade.method-not-allowed`,
`facade.unsupported-media-type` (a request `Content-Type` the operation does
not accept), `facade.not-acceptable` (no acceptable response media type in
`Accept`),
`facade.conflict` (an idempotency key in flight, section 9),
`facade.idempotency-mismatch` (same key, different body). They exist so the
profile maps them like every other class: every response a caller receives
is in the profile's shape.

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
  (default 0.15). The defaults and the delay computation are
  `RedeliveryPolicy` at the pinned tag: the multiplier applies only with
  `useExponentialBackOff` and a multiplier above 1, and collision avoidance
  varies the delay by plus or minus the factor
  (`RedeliveryPolicy.calculateRedeliveryDelay`). The order is Camel's:
  the first delay is `retryDelaySeconds`, each later one the previous delay
  (times the multiplier when backing off), then the collision variance, then
  the `maximumRetryDelaySeconds` cap, so the cap bounds the varied delay.
  During redelivery the exchange carries Camel's `CamelRedelivered`,
  `CamelRedeliveryCounter`, and `CamelRedeliveryMaxCounter` headers, readable
  by `retryWhile` and `onWhen`, and sent upstream only if listed like any
  engine header (section 8.11.4).
  `delayPattern` is not ported. Redelivery is
  per failing top-level endpoint send. It reaches only an `http` or `graphql`
  `to` that is a direct child of the route's step list (token requests sit
  outside it per section 10.2), never a `to: direct:` send. An endpoint send
  inside a nested processor body runs once and bubbles its failure to the
  enclosing top-level step; in particular, a send inside `throttle` runs bare
  from the route's redelivery policy. A matching clause may still handle that
  bubbled failure, except for the wholly bare breaker rule below. This
  top-level and endpoint-type scope is a declared
  divergence from Camel, which retries from the point of failure without
  either restriction (camel.apache.org/manual/error-handler.html,
  camel.apache.org/manual/exception-redelivery.html).
- `retryWhile`, as in Camel an option of an `onException` clause
  (`OnExceptionDefinition`) and of the default error handler
  (`DefaultErrorHandlerDefinition`), not of the redelivery policy:
  redelivery continues while the predicate is true. Divergence:
  `maximumRedeliveries` remains the hard cap, where Camel lets `retryWhile`
  replace it, so `maximumUpstreamCalls` stays a check-time guarantee; `check`
  refuses `retryWhile` with `maximumRedeliveries` 0. A `retryWhile` that
  raises ends redelivery, as in Camel.
  Divergence for writes: `check`
  refuses `maximumRedeliveries > 0` over a `to` whose `httpMethod` is not
  safe, unless that endpoint operation declares `idempotentUpstream: true`
  (a reviewed claim, for example DHIS2 creates with client-supplied UIDs).
- `onException`: `exception` (classes), `onWhen`, `handled`, `continued`,
  redelivery options, nested steps. Matching keeps Camel's class-specificity
  rule inside the bounded single-class model: the clause whose
  class is the closest ancestor of the one raised `RouteFailure` class wins;
  equally specific clauses keep declaration order, and a subclass clause
  never matches a superclass failure. The absence of a cause-chain walk is
  the bounded divergence stated above.
  An `onWhen` that raises means the clause does not match, as in Camel.
  Clauses are route-scoped; Camel's global and `routeConfiguration` scopes
  are not ported.
  Without an explicit clause policy, a clause with nested output steps
  uses zero redeliveries; an outputless clause inherits the route policy,
  as `ExceptionPolicy.createRedeliveryPolicy` does at the pinned tag.
  `handled: true` ends the exchange successfully with the clause's result,
  which is validated against the operation's result schema like any route
  output (an empty search page, a fallback record). To translate an error
  instead, the clause ends with `throwException`: as in Camel, an error
  raised inside an exception clause is not handled again and becomes the
  exchange's failure, which the profile maps to a problem (section 8.11.6;
  Camel wraps clause steps in `FatalFallbackErrorHandler` to stop the
  recursion). Camel keeps the original error as suppressed; the Adapter's
  returned `RouteFailure` carries only the clause's error, while the journal
  records the original handling event and the final class.
  Divergence: a `direct:` route called from a clause is inside the clause,
  so its errors are not handled again either, where Camel lets the callee's
  own error handler fire the clause a second time
  (`OnExceptionRecursionTest.testRecursionDirect`).
  A clause never builds a problem body or sets `CamelHttpResponseCode`.
  `continued: true` resumes the route at the step after the failure. An
  unhandled error surfaces as the profile's problem for its class, with no
  upstream content; the profile's mapping for the `upstream` root is the
  catch-all for source failures.
- `doTry`, `doCatch` (with `onWhen`), `doFinally`: ported as in Camel
  (`doTry-eip.adoc`, `TryProcessor`). A `doTry` without either a catch or
  a finally clause is refused before serving, as Camel 4.23's `TryReifier`
  requires; an explicitly empty finally clause is valid. Inside a `doTry` block the route error
  handler is not in use: no `onException` clause and no redelivery applies
  to the block's steps. An error no `doCatch` matches, or one raised in a
  `doCatch` or `doFinally`, leaves the `doTry` and fails the exchange; an
  error raised in `doFinally` while another is pending is kept as
  suppressed, and the original wins (`FinallyProcessor`,
  `DoTryEdgeCasesTest.testDoFinallyThrowsKeepsOriginal`). A `doCatch`
  `onWhen` that raises fails the exchange with that error, with the original
  journaled separately as suppressed rather than attached as a cause. A
  `to: direct:` inside the block calls a route that
  keeps its own error handling, as in Camel.
- `circuitBreaker`: resilience4j semantics and defaults, per EIP node,
  process-local state (as in Camel; replicas have independent breakers):
  `failureRateThreshold` 50, `slidingWindowType` count-based,
  `slidingWindowCalls` (resilience4j `slidingWindowSize`) 100,
  `minimumNumberOfCalls` 100,
  `openStateWaitSeconds` (resilience4j `waitDurationInOpenState`, 60 s),
  `maximumHalfOpenCalls` (resilience4j
  `permittedNumberOfCallsInHalfOpenState`, 10),
  `automaticTransitionFromOpenToHalfOpenEnabled` false,
  `slowCallRateThreshold` 100, `slowCallDurationThresholdSeconds` 60.
  With automatic transition disabled, an elapsed open wait stays OPEN
  until the next guarded call. When enabled, passive state observation
  reflects HALF_OPEN without admitting a trial. The primitive derives
  this elapsed transition when observed; it starts no timer task and
  exposes no transition-event or half-open-timeout surface.
  Optional `recordException` and `ignoreException` are unique, non-empty
  lists from the closed Adapter error-class hierarchy. A named parent covers
  its descendants. With `recordException`, a non-matching catchable failure
  counts as success and continues the exchange; an `ignoreException` match
  takes precedence, counts as neither success nor failure, and continues the
  exchange. Neither continuation runs `onFallback`; both journal the consumed
  failure. Boundary and facade-only classes are refused in either list, so an
  uncatchable failure always counts as failure and propagates. Each
  default is confirmed against the cited resilience4j and Camel pages when
  the conformance test is written; a default the docs contradict is
  corrected here, not in code. Divergence: a rejected call always raises
  `breaker.open` (Camel's `throwExceptionWhenHalfOpenOrOpenState: false`
  default lets the message continue unchanged, which would answer with the
  request echoed); `onFallback` runs on a recorded failure and on rejection,
  and its output is validated like any route output. The guarded steps and
  fallback run bare: the route error handler does not wrap the breaker block
  or its steps. A recorded error escaping a breaker without `onFallback`
  therefore reaches no `onException` clause or route redelivery and surfaces
  as the profile's problem for its class.

### 8.8 Components

- `direct`: synchronous in-process call to another route, Camel's
  semantics; depth bounded.
- `rest`: the facade consumer, ported from Camel's contract-first REST DSL
  (`rest().openApi()`): the generated OpenAPI is the specification; every
  concrete operation dispatches to its bound route; `clientRequestValidation`
  is always on; unmatched requests answer 404 or 405 as in Camel; a missing
  route fails startup (Camel's `missingOperation` default; `ignore` and
  `mock` are not ported). Authentication and authorization (section 10) are
  engine-owned on Axum with shared OIDC verification; the envelope is the
  profile's template, filled by the engine.
- `http`: producer on `FixedDestinationPolicy`. `uri: "http:<endpointId>"`
  names an endpoint declared in the pack and bound to a base URL in the
  runtime config. Parameters: `httpMethod`, `path` (an origin-relative
  template, starting with `/`, appended to the endpoint's base path, whose
  `{{name}}` segments are filled from `pathParameters` expressions and
  percent-encoded by the engine as single segments; every placeholder is
  bound and every binding is used), or instead of `path`, `httpUri` (an
  expression yielding an absolute link the source returned, pinned to the
  endpoint's origin, section 8.11.5); `query` (name to expression,
  engine-encoded; not allowed with `httpUri`), `body` (expression,
  marshalled to JSON), `throwExceptionOnFailure` (default true),
  `okStatusCodeRange` (default `200-299`; a comma-separated list of status
  codes and inclusive ranges inside 100 to 599, as Camel writes it).
  Request headers go out only through the endpoint's `requestHeaders`
  allowlist (section 8.11.4). Divergence: Camel builds dynamic requests from
  the `CamelHttpPath`, `CamelHttpQuery`, and `CamelHttpUri` headers or
  `toD`; ours are structured and encoded by the engine, and the one dynamic
  form, `httpUri`, is checked against the origin, so no expression can
  change the origin or inject a path. Authentication to the upstream is one
  of the closed kinds of section 10.2, declared on the endpoint and injected
  at send time, after the header allowlist has been applied. A send's
  safety comes from its method; a `POST` whose endpoint operation declares
  `safeUpstream: true` (a reviewed claim, as for FHIR `POST _search`)
  counts as safe for the write-safety rules. A read operation (a facade
  `get` or `search` binding) reaches only safe sends: `check` refuses a
  non-safe `http` send, or a GraphQL mutation, anywhere in its route
  closure.
  Each `http` and `graphql` endpoint declares `attemptTimeoutMilliseconds`
  (1 to 10000, the whole outbound attempt, the platform destination's
  frozen ceiling on one operation, as in Messaging; a value above it is
  refused, never shortened) and `maximumResponseBytes` (1 to 1048576),
required and without default, spelled as CFG-NAME-5 and Evidence spell
them; the runtime binding may lower either, never raise it. `[ingestion]`
The job profile (section 17.2) resolves these ceilings under the platform
caps: the 10-second attempt ceiling is platform-frozen and holds for job
sends too (a page that cannot fit within it is a deployment sizing error,
and acquisition reads one page per bounded step), while a job route's
response bound may be raised explicitly up to the platform's 16 MiB
response-body cap; the facade bounds above are unchanged. A `POST`
  send carries a body; one without a body is refused. Divergence: Camel's `connectTimeout`, `responseTimeout`, `soTimeout`,
  and `connectionRequestTimeout` collapse into the one attempt timeout, and
  the facade deadline still bounds the total. A body over the bound raises
  `upstream.too-large`. A 3xx raises `upstream.redirect` whatever
  `okStatusCodeRange` says and is never followed; `upstream.http` covers
  every other status outside the range. As with Camel's
  `HttpOperationFailedException`, a failed response keeps its status in
  `CamelHttpResponseCode` and its body as the exchange body when that body
  is JSON within the bound, so a clause can read a source's error detail;
  the `Location` value and the status text are not kept. An empty body is
  JSON `null`; a non-JSON body raises `upstream.malformed`, also under
  `throwExceptionOnFailure: false`. A `path` whose filled and encoded
  destination exceeds the URL bound fails before a send as
  `outcome.not-found`; caller-supplied record identifiers do not become an
  internal egress problem. An evaluated `httpUri` over the same bound is
  instead the uncatchable `egress.refused`, because it is a source-supplied
  absolute destination.
- `graphql`: producer, Camel's `camel-graphql` shape (`query` as a
  digest-pinned `queryFile`, `operationName`, `variables` expression) over
  the same transport, with no `httpMethod`, `path`, `pathParameters`, or
  `query`; `check` parses the query file and requires the named operation.
  A send is safe only when that operation is a GraphQL `query`; a
  `mutation` is non-safe under every write-safety rule. The reply's `data`
  member is the body. A GraphQL `errors` array raises `upstream.http`-class
  errors with the declared detail only (divergence: Camel leaves errors in
  the body; partial data with errors fails the exchange). Arrives in
  Increment 3.
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
| HeaderFilterStrategy | `components/next/http-component.html` (its headerFilterStrategy option; the former manual page is gone) | `responseHeaders` and `requestHeaders` allowlists per endpoint (section 8.11.4) | Allowlists, not denylists; credential, cookie, host, and hop-by-hop headers can never be allowlisted | 1 |
| Route, YAML DSL | `manual/routes.html`, `components/next/others/yaml-dsl.html` | `routes` in packs, externally tagged steps | `direct:` `from` only; acyclic; bounded depth | 0 |
| Route template, templatedRoute | `manual/route-template.html` | `routeTemplates` in packs, `templatedRoutes` in projects | Typed parameters; no `from` in templates | 0 |
| Kamelet catalog | `camel-kamelets/next/index.html` | The pack as a reviewed catalog of templates | Not Kubernetes resources; digest-pinned | 0 |
| Property placeholders | `manual/using-propertyplaceholder.html` | `{{name}}`, `{{?name}}` for template parameters only | No environment placeholders in authored files | 0 |
| REST DSL contract-first | `manual/rest-dsl-openapi.html`, `manual/rest-dsl.html` | `rest` consumer over the generated OpenAPI; facade inputs on the exchange under closed names (section 8.11.1) | Validation always on; `missingOperation` fail only; profile-neutral input names, not the caller's parameter names; caller headers never enter | 1 |
| `direct` | `components/next/direct-component.html` | `direct:<routeId>`, sharing the exchange (section 8.11.7) | Depth bound; no redelivery of a `to: direct:` send | 1 |
| `http` | `components/next/http-component.html` | `http:<endpointId>` on `FixedDestinationPolicy`; `httpUri` for an origin-pinned link | Structured, engine-encoded path and query; `httpUri` pinned to the endpoint origin and base path; no redirects | 1 |
| HTTP authentication | `components/next/http-component.html` (authentication options) | `authentication` on the pack endpoint, credentials bound in the runtime config (section 10.2) | Closed kinds; secret references only; the token endpoint is a fixed destination too; `basic` is sent preemptively, with no challenge round trip; no NTLM, no Digest, no query-placed keys | 1 |
| `graphql` | `components/next/graphql-component.html` | `graphql:<endpointId>` | Query from a pinned file only; `errors` fail the exchange; a mutation is non-safe | 3 |
| Languages | `components/next/languages/constant-language.html`, `header-language.html`, `exchangeProperty-language.html`, `jsonpath-language.html` | `constant`, `header`, `exchangeProperty`, `jsonpath` | RFC 9535, not Jayway; singular-query result rule (section 8.11.8); header reads bounded to known headers | 1 |
| Simple, bean, process | `components/next/languages/simple-language.html` | `rhai` files with the script ABI of section 8.11.3 | Not ported; Rhai replaces them; scripts see a read-only exchange view | 1 |
| `to` | `components/next/eips/to-eip.html` | `to` | No `toD`; `httpUri` is the only dynamic form | 1 |
| `setBody`, `transform` | `components/next/eips/setBody-eip.html`, `transform-eip.html` | Same | None | 1 |
| `setHeader`, `setProperty`, `removeHeader`, `removeProperty` | `components/next/eips/setHeader-eip.html` and siblings | Same | Header names bounded; `Camel`- and `Adapter`-prefixed engine headers and credential headers cannot be set or removed | 1 |
| Throw Exception | `components/next/eips/throwException-eip.html` | `throwException` (`exceptionType` names a catchable class, `message` a constant) | Closed classes, not Java types; no message expression; inside an exception clause it ends the exchange | 1 |
| `script` | `components/next/eips/script-eip.html` | Same | Rhai only | 1 |
| Content-Based Router | `components/next/eips/choice-eip.html` | `choice`, `when`, `otherwise` | Predicates must be boolean | 1 |
| Message Filter | `components/next/eips/filter-eip.html` | `filter`, with `statusPropertyName` | Predicates must be boolean | 1 |
| `validate` | `components/next/eips/validate-eip.html` | `validate` | None | 1 |
| `stop` | `components/next/eips/stop-eip.html` | `stop` | None | 1 |
| Splitter | `components/next/eips/split-eip.html` | `split` | Mandatory `maximumItems`; no parallel or streaming; a piece whose failure the accounting counted is left out of the merged result where Camel folds it with its exception cleared; `CamelSplitResult` carries the three counts only, the per-item failures map dropped for the value-free contract | 1 |
| Loop | `components/next/eips/loop-eip.html` | `loop`; `doWhile` tested before each iteration (`LoopProcessor`) | Mandatory `maximumIterations`; under `copy` an error restores the exchange as it stood before the failed iteration, where Camel copies the failed iteration's own results back | 1 |
| Content Enricher | `components/next/eips/enrich-eip.html` | `enrich`, the resource send on a copy of the exchange (section 8.11.7) | Static URI only; no `pollEnrich`; strategies merge bodies and named `properties` only | 1 |
| Aggregation strategies | `components/next/eips/aggregate-eip.html` (strategies section) | `use-latest`, `use-original`, `grouped-body`, `rhai` | Additions: `json-array-append`, `json-merge` | 1 |
| Default error handler | `manual/defaulterrorhandler.html`, `manual/error-handler.html` | `errorHandler: defaultErrorHandler`, `noErrorHandler` | Dead letter is always the journal | 1 |
| Redelivery policy | `manual/error-handler.html` (redelivery) | Options in 8.7 | CFG-NAME spelling; write-safety refusal; top-level `http` and `graphql` sends only, nested sends run once | 1 |
| Exception clause | `manual/exception-clause.html` (hub) with `exception-redelivery.html`, `exception-handling-patterns.html`, `exception-advanced.html` | `onException` | One raised class, no cause-chain walk; uncatchable boundary errors; a handled clause answers with a success body, problems come from the profile; `handled` and `continued` are booleans where Camel takes predicates | 1 |
| Try, catch, finally | `manual/try-catch-finally.html` | `doTry`, `doCatch`, `doFinally` | Uncatchable boundary errors | 1 |
| Circuit Breaker | `components/next/eips/circuitBreaker-eip.html`, `resilience4j-eip.html`, `resilience4jConfiguration-eip.html` | `circuitBreaker`, `onFallback`, `recordException`, `ignoreException` | Rejection always raises; fallback on recorded failure and rejection; ignored and non-recorded failures continue and are journaled as consumed; guarded steps and fallback run bare; options flattened, `slidingWindowCalls` for `slidingWindowSize` (CFG-NAME-4) | 1 |
| Throttler | `components/next/eips/throttle-eip.html` | `throttle` | Waits bounded by the deadline; its nested body runs bare from route redelivery | 1 |
| Idempotent Consumer | `components/next/eips/idempotentConsumer-eip.html` | `idempotentConsumer` over the PostgreSQL store | Duplicates replay the recorded response | 2 |
| Type Converter | `manual/type-converter.html`, `components/next/eips/convertBodyTo-eip.html`, `convertHeaderTo-eip.html` | `convertBodyTo`, `convertHeaderTo`, `convertPropertyTo` (addition) with `type: codeMap:<id>`; Rhai `code_map`; `conversion.unmapped` on a miss | Explicit tables of scalar values, no converter chains, no `charset` | 1 |
| Event Notifier | `manual/event-notifier.html` | The audit journal's event kinds (section 11) | Synchronous, value-free, before the response | 1 |
| `file` (job source) `[ingestion]` | `components/next/file-component.html` | `file:<endpointId>` read through the job-only `pollEnrich` step (section 17.2); `noop` strategy forced; `include`, `sortBy`, `doneFileName`, `readLock` restricted to none or changed, `maxMessagesPerPoll` where they apply | Read-only always: `delete`, `move`, `rename`, `markerFile`, and the `fileLock` strategy are not ported (each writes or locks the source); base directory fixed in runtime configuration, traversal and symlink escape refused; a delivered file is identified by namespace plus content digest, never by name or modification time alone | 4 |
| `sftp` (job source) `[ingestion]` | `components/next/sftp-component.html` | `sftp:<endpointId>` through the same read step, sharing the `file` decoders | Host key pinned, secret references only; complete files detected through a ready manifest or completed-name handover; interrupted transfers and replaced same-name files handled by digest identity; no source writes; lands only after the SSH dependency review (section 17.6) | 4 |
| SQL (read-only job source) `[ingestion]` | `components/next/sql-component.html` | `postgres:<endpointId>` send with a digest-pinned `queryFile`, as `graphql` pins its query; named parameters only | Fixed named parameterized read-only queries only, each with a root `ORDER BY` so offset pages neither skip nor repeat rows; read-only transaction enforced with statement timeout, bounded fetch, and cancellation; declared snapshot or incremental semantics; no user-supplied SQL; Camel's `onConsume` progress updates not ported (they write the source), so progress tracking is original work | 4 |
| CSV data format `[ingestion]` | `components/next/dataformats/csv-dataformat.html` | A decoder selected on a `file` or `sftp` endpoint, not an `unmarshal` step; option names and defaults from `CsvDataFormat` | No type inference: leading zeros, quoted multiline fields, empty versus null, oversized rows, and malformed rows are deterministic; a bad row is reported per item; one read returns a bounded page whose `next` holds the file digest and position | 4 |
| JSONL decoder `[ingestion]` | None; an addition under section 5.4 | One bounded JSON value per line, selected on a `file` or `sftp` endpoint; the same paging contract as CSV | An addition, not a port: Camel has no JSONL data format; a malformed line is reported per item and the remaining lines continue | 4 |
| `pollEnrich` (job only) `[ingestion]` | `components/next/eips/pollEnrich-eip.html` | A job-only read step over a static URI (`file:<endpointId>`, `sftp:<endpointId>`) with a mandatory timeout | Refused by `check` in every facade route; no dynamic endpoint expression, no `consumerSendTo`; one bounded page per read under the job profile | 4 |
| Testing: mock, intercept | `components/next/mock-component.html`, `manual/advice-with.html`, `components/next/eips/intercept.html` | Fixture replay intercepts `http` and `graphql` sends | Test harness only | 0 |

Each reference is a path under `https://camel.apache.org/`; the change that
adds a row's conformance test confirms the page and corrects the path here
if Camel has moved it.

Not ported, deliberately: Java and XML DSLs, the code-first REST DSL, Simple,
`bean`, `process`, `toD`, `wireTap`, `multicast`, `recipientList`,
`routingSlip`, `dynamicRouter`, `loadBalance`, the stateful
`aggregate` EIP and aggregation repositories, `resequencer`, `delay`,
`sample`, `log`, `saga`, transactions and UnitOfWork, `threads` and parallel
processing, streaming, brokers and the rest of the component library, route
controllers, hot reload, JMX, Camel K, Quarkus, and Spring runtimes.
`[ingestion]` `pollEnrich` moves from this list to a job-only row above:
the facade still never polls, and a job route's read step is bounded and
static-URI only. FTPS stays out until a named adopter needs it and plain
FTP is unsupported (any exception needs an independently authenticated
encrypted channel). Adding
one later is a port-table row and a conformance test, not an invention.

### 8.11 The exchange contract

Sections 7 and 8.2 say what may enter and leave an exchange; this section
says exactly where, so that a pack written against it runs under any
profile. The source-shape fixtures
(`products/adapter/fixtures/source-shapes/`) showed that without it a pack
could pass `check` and still not be executable: it had to guess where the
caller's inputs sit, how a page hands back a cursor, what a script
receives, and how to report a not-found without naming a profile's codes.

#### 8.11.1 Facade inputs

As in Camel's REST DSL, the `rest` consumer turns the validated request
into headers and a body, but under closed, profile-neutral names, so a
pack never learns a profile's path or parameter names:

| Input | On the exchange | Present for |
|---|---|---|
| Record type | header `recordType` | every operation |
| Record identifier | header `recordId` | get, update, patch |
| Page size | header `pageSize`, an integer inside the profile's bounds, the profile's default when absent; the sealed cursor binds the effective page size, so an omitted `pageSize` on a continued request reuses the cursor's and a different one is refused with `facade.invalid-cursor` | search |
| Filters | property `AdapterFilters`, an object from declared field name to typed value, holding only the filters the caller sent; a search binding declares the fields it filters on (`filters`), the contract offers exactly those as typed equality query parameters, and any other query parameter is refused by request validation, so a route never silently ignores a filter; a filter never reuses the bound operation's cursor, page-size, or path parameter name (`adapter.project.filter-parameter-collision`), so one caller-facing name means one thing; in this slice every filter a binding declares is required, and a request missing one is refused with `facade.invalid-field` (422) | search |
| Continuation | property `AdapterContinuation`, absent on the first page (8.11.2) | search |
| Request record | the body, extracted through the profile's request envelope and validated against the declared model | create, update, patch |
| Idempotency key | header `Idempotency-Key`, the one caller header that enters | write operations, read by `idempotentConsumer` |

Reads start with a `null` body. No other caller header, cookie, query
parameter, or token ever enters the exchange (section 10.1). These headers
and properties are read-only: `check` refuses a `setHeader`,
`removeHeader`, `setProperty`, or `removeProperty` naming them, except
`AdapterNextContinuation`, which exists to be set.

#### 8.11.2 Continuation

The route owns the upstream position; the engine owns the caller's cursor.

- A search route that can return more sets property
  `AdapterNextContinuation` to a JSON value (an upstream cursor, an offset,
  an origin-pinned next link, or an object of these), at most 2 KiB
  serialized. Absent or `null` at the end of the route means the last page.
- The engine encodes it as the opaque `nextCursor` slot of section 7 with
  authenticated encryption under the runtime secret `cursorKeyRef`, bound
  to the concrete operation, the binding id, the caller's subject, the
  deployment the runtime serves (the deployment digest, a SHA-256 over
  the project, profile, and pack bytes the runtime loaded, so a redeploy
  that changes route meaning invalidates outstanding cursors), a digest
  of the filters and page size, and an expiry (`cursorTtlSeconds`, default
  900). An optional `previousCursorKeyRef` keeps cursors valid across one
  key rotation.
- On the next request the engine verifies and decrypts the cursor and
  places the value as `AdapterContinuation`. A cursor that fails
  authentication, has expired, or was minted for another operation,
  caller, or filter set raises `facade.invalid-cursor` before any route
  step runs.
- Details: `cursorKeyRef` resolves to exactly 32 bytes or the runtime
  refuses to start, and `previousCursorKeyRef` only decrypts; the caller's
  subject is the authenticated issuer and `sub`; the filter digest is
  SHA-256 over the RFC 8785 canonical JSON of the validated facade inputs
  without the cursor, plus the page size; `cursorTtlSeconds` is bounded 60
  to 86400; the cursor is verified after authentication and authorization,
  so an unauthenticated caller with a forged cursor gets
  `facade.unauthenticated`; an oversize cursor raises
  `facade.invalid-cursor`.
- Algorithm: XChaCha20-Poly1305 with a random 192-bit nonce, keyed by
  HKDF-Expand of `cursorKeyRef` under a domain label, with the binding in
  the associated data so a mismatch is an authentication failure, and a
  version byte on the wire. The module documentation records the reason
  (random-nonce safety under one long-lived key, the same choice as Base
  Registry Engine's cursor). ChaCha20-Poly1305 is not FIPS-approved; the
  cursor is an engine-internal token only this engine opens, and a
  deployment that requires approved algorithms for internal tokens needs
  AES-256-GCM with per-cursor subkeys, a wire-version change.

The caller can therefore neither read nor forge an upstream position, and
a next link the source returned comes back to the route only as the route
handed it out, still subject to 8.11.5. This is security-sensitive (it
carries source state through the caller) and needs review notes.

#### 8.11.3 Script ABI

Every `rhai` entrypoint receives one argument, `exchange`, a read-only map
`#{ body, headers, properties }`: `body` is the current body, `headers` the
current headers with lowercased names, `properties` the current
properties. JSON maps to Rhai as objects to maps, arrays to arrays, strings
to strings, integers to `i64`, other numbers to `f64`, booleans to `bool`,
and `null` to `()`; the reverse on return. A number outside `i64` that is
not integral stays `f64`; an integer outside `i64` raises `script`. Typed
template parameters keep their type when instantiated into a script
argument or expression.

What an entrypoint returns depends on its slot:

| Slot | Returns |
|---|---|
| `setBody`, `transform`, an expression value (`setHeader`, `setProperty`, `query`, `body`, `pathParameters`, `httpUri`, `split` expression, `loop` count) | the value |
| A predicate (`when`, `filter`, `validate`, `onWhen`, `retryWhile`, `doWhile`) | a `bool`; anything else raises `script` |
| `script` EIP | a map of property names to values, set on the exchange; the body is unchanged |
| A custom aggregation strategy (`split`, `enrich`) | `fn(oldExchange, newExchange)`, with `oldExchange` as `()` on the first call of a split, returning `#{ body, properties }` (`body` required; `properties` names the property writes, an absent selection clearing) |

`oldExchange` and `newExchange` carry Camel's own
`AggregationStrategy.aggregate` names: `new` alone is a reserved word in
the pinned engine, so the shorter spelling cannot compile.

Each script file is its own compilation unit: an entrypoint may call
functions defined in the same file only, and `check` refuses a call to a
function the file does not define (no `import`, no shared prelude). Budgets
are `registry-platform-script`'s; exceeding one raises the uncatchable
`script.budget-exceeded`.

#### 8.11.4 Headers on the wire

The endpoint declares two allowlists, Camel's `HeaderFilterStrategy` in
both directions:

- `responseHeaders`: upstream response headers copied onto the exchange,
  read by `header` under their declared names.
- `requestHeaders`: exchange headers sent upstream on every send to the
  endpoint, by name (`Accept`, `Prefer`, `If-None-Exist`). A header in the
  list that is absent from the exchange is not sent. Camel engine headers
  and the facade inputs of 8.11.1 are never sent unless listed.

Never allowlistable in either list: `Authorization`, `Proxy-Authorization`,
`Cookie`, `Set-Cookie`, `Host`, `Content-Length`, `Transfer-Encoding`,
`Connection`, `Upgrade`, `TE`, `Trailer`, `Keep-Alive`, `Expect`, the hop-by-hop
`Proxy-*` headers, and the endpoint's own apiKey header. Credentials are
injected after the allowlist is applied, so no exchange header can replace
or shadow one. Header names are RFC 9110 tokens, compared without case.
The same names are refused as a `static-api-key` `headerName` (section
10.2); a key sent in `Authorization` is the `static-authorization` kind.
`requestHeaders` also refuses the names the platform transport owns on a
request: `Content-Type`, which belongs to the body codec, and the
forwarding, encoding, and signing headers. `responseHeaders` refuses
`Camel*` names, the facade inputs of 8.11.1 (an upstream value never
stands in for a validated caller input), and the
authentication-challenge, infrastructure, and tracing headers the
transport owns on a response. A name listed twice, compared without case,
is refused, and a list holds at most the transport's 32 names. `check`
and the runtime's filter build refuse the same names, so a pack that
passes `check` never fails on these rules at load.

On a send, an exchange value that is not a strict RFC 9110 field value, or
exceeds the transport's value bound, raises the uncatchable
`egress.refused`; it is never trimmed or re-encoded. An exchange that holds
two entries for one listed name (compared without case) also raises
`egress.refused`: neither is picked, where Camel's `HttpProducer` would join
them. A declared response header the upstream repeats, or sends with a
value that is not visible ASCII, raises `upstream.malformed`. Errors name
the list position, never the value.

A `header` expression may read only a facade input header, a declared
response header, a Camel engine header the engine sets
(`CamelHttpResponseCode` and the redelivery headers), or a header an
earlier step set. Split and loop metadata is read through exchange-property
expressions. Because `to: direct:` shares the
exchange (section 8.11.7), "an earlier step" reaches across it both ways:
after a `to: direct:` step the caller may read any header the target route
sets, transitively through its own `direct:` calls; and a target route may
read a header that every one of its call sites sets before the call. An
`enrich` resource route runs on a copy, so its headers never come back.
`check` refuses any other read, so a pack cannot depend on a header that is
never there.

#### 8.11.5 Origin-pinned links

Sources page and link by URL (FHIR `link[relation=next]`, HAL, JSON:API).
Camel follows such a link with `toD` or the `CamelHttpUri` header; ours is
the `httpUri` parameter on an `http` send, exactly one of `path` and
`httpUri`, with no `query` beside it. At send time the engine parses the
value as an absolute URL and refuses it with the uncatchable
`egress.refused` unless its scheme, host, and port equal the endpoint's
configured origin, its path stays under the endpoint's base path after
normalization, it carries no userinfo or fragment, and it fits the URL
length bound. The link is parsed once and the parsed value is what the
engine sends, never a reparse; a link the parser would silently repair
(tabs, newlines, `\` read as `/`, a missing `//`) or whose path is not
canonical under the transport's fixed-destination rule is refused rather
than rewritten, and a trailing-dot host is a different host. The query
string the source wrote is sent as written. `toD` stays not ported;
redirects stay unfollowed.

#### 8.11.6 Errors become problems

A pack never writes a problem body and never names a profile's problem
code; it raises error classes and the profile decides what the caller sees.

- `throwException` (Camel's Throw Exception EIP): `exceptionType` names a
  catchable class of section 8.7, typically an `outcome.*` class;
  `message` is an optional constant of at most 512 UTF-8 bytes, which fills the profile's
  `problemDetail` slot when the problem's envelope has one. Raised inside a
  route it is handled by the route's clauses like any error; raised inside
  an `onException` clause it is the exchange's final failure.
  Optional `data` is an expression supplying only the resolved profile
  problem's declared `dataFields`. The data is a closed object of at most
  16 required scalar fields and at most 2048 serialized JSON bytes. It
  fills the optional whole-value `{{?problemData}}` member. Unknown,
  missing, mistyped, undeclared, or oversized data becomes a value-free
  `disclosure.violation`; it never falls back into `problemDetail`.
- The profile's `problems` list maps classes to problems: each entry has
  `code`, `status`, `title`, and `classes`. The problem for an error is the
  entry whose class is closest to the error's class, by the rule of 8.7,
  uncatchable and facade classes included. `check` requires every class in
  the hierarchy to resolve to exactly one entry, so listing the roots is
  enough and nothing is ever unmapped; it refuses a class listed twice, an
  unknown class, and a status outside 400 to 599.
  The authored status governs route/profile failures. Facade admission
  failures retain their fixed engine statuses, including 422 for invalid
  fields and idempotency mismatch. Their code and title still come from
  the closest profile problem. Correlated problem schemas include only
  that authored status and the fixed class/status pairs that resolve to
  the same problem; another code's status or data shape is not admitted.
- The engine fills the problem envelope from the resolved entry. The
  journal records the class and the code.
  Problem data stays out of logs and the journal. Profiles using data
  publish correlated per-problem schemas, so a code cannot admit another
  problem's data shape. Other failures may omit the optional data member.

This replaces the earlier rule that an exception clause sets
`CamelHttpResponseCode` and a profile-shaped body; that rule made every
pack profile-specific, which D17 forbids.

#### 8.11.7 `direct:` and `enrich`

- `to: direct:<routeId>` runs the target route on the same exchange, as
  Camel's `direct` does: body, headers, and properties flow in and come back
  changed. Errors raised in the target are offered first to the target's
  own clauses; an unhandled error propagates unchanged to the caller's
  clauses. A `to: direct:` send is never redelivered (divergence: Camel's
  default error handler would redeliver it; ours redelivers endpoint sends
  only, so the target's own sends carry their redelivery).
- `enrich` runs its resource send on a copy of the exchange and merges the
  reply back through its strategy. The built-in strategies merge bodies
  only, and properties set by the resource route are discarded, unless the
  strategy names them: `json-array-append` and `json-merge` accept
  `properties`, a map from property name to a JSONPath on the reply, so a
  pagination loop carries the next cursor or link out of each page.

#### 8.11.8 JSONPath results

A singular query (RFC 9535 section 2.3.5, a path of name and index
selectors only) yields its one value, or absent when nothing matches. Any
other query yields the node list as a JSON array, empty when nothing
matches. Absent raises `validation` where a value is required (`setBody`,
a `pathParameters` entry). As a predicate, a singular query must yield a
boolean, and absent counts as `false`, the one place absence has a meaning;
`check` refuses a non-singular query as a predicate. Media types counted as
JSON are `application/json` and any `application/*+json`.

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
  namespaced by verified issuer, subject, acting client, logical deployment
  (`runtime.id`), and concrete operation. The request digest binds the exact
  project/profile/pack revision and request bytes (same key, different body
  or artifact revision, is a 422); a duplicate replays
  the recorded facade response instead of being dropped (`skipDuplicate` is
  not ported); a duplicate arriving while the first is in flight answers 409.
- The idempotency store is PostgreSQL, separate from the audit journal. It is
  the only place the adapter retains a response body: the exact facade
  response, for a retention window the deployment configures, then erased
  by a supervised sweep, as BReg's store does. This is a data-minimization decision (D12)
  and carries a security review note.
  Deployment identifiers must remain stable across artifact upgrades and
  distinct for deployments sharing a database. The logical-deployment
  migration refuses any legacy artifact-namespaced entries, preserving
  their responses and spent keys for operator reconciliation. It never
  clears opaque legacy keys or treats them as fresh work.
  Exact response replay preserves the original Adapter-minted response
  request ID in its body and header. Each physical retry has a fresh journal
  attempt ID. A response-custody upgrade that cannot recover a legacy
  response's original ID refuses migration while that replayable custody
  remains; it neither invents an ID nor erases a spent key.
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
  a write route is refused. `[ingestion]` D14 is unchanged for routes: an
  ingestion hand-off is never a route with non-safe sends. A source route
  only reads. The direct destination sends one BReg operation per item
  through the BReg client outside the route engine (a Proposal's start and
  submit under two command keys derived from the same item), and the job
  has no steps, branches, or waits, so no ingestion path lifts this rule
  by hiding an import inside a route.
- Batch acceptance (DHIS2 import summaries): success requires full
  acceptance; partial acceptance maps to a bounded 409 problem carrying the
  counts alone (imported, updated, ignored, rejected), never the raw
  upstream summary.
- Conflicts (DHIS2 import conflicts, GraphQL error arrays) are raised as
  `outcome.conflict` or `outcome.rejected` (`throwException`, directly or
  from an `onException` clause), and the profile maps them to its bounded
  problems with declared detail only (section 8.11.6).
- No compensation and no rollback across upstream calls. Recovery is the
  source system's native process surface; the adapter reports exactly where
  a sequence stopped.
- Unknown upstream errors never leak: they surface as the profile's
  problem for their class, at worst the one for the `upstream` root, with
  no upstream content; `check` proves every class maps (section 8.11.6)
  and mapping totality is tested (section 13).
- A write the source accepts but has not finished (an OpenCRVS declaration
  entering its validation queue, a DHIS2 asynchronous import job) answers in
  one of two ways, chosen by configuration (D16): a 202 with a status link
  the profile defines, or a bounded wait for completion. The exact keys, and
  what a wait answers when its bound expires, are settled in Increment 2.
  Until that lands such a route is refused.

## 10. Authorization and secrets

### 10.1 Facade callers

Every facade call is authenticated (OIDC bearer tokens via the platform
block, as every Registry Stack product) and authorized by the adapter's own
access profiles: named bindings of scopes to concrete facade operations and
record types, declared in the project. No API keys, no Basic, no anonymous
calls on the facade. The adapter inherits no authorization from any product
and grants none to any source. The caller's token is never forwarded
upstream: upstream calls run under the deployment's own credential for that
source, or without a source credential only under the explicit anonymous
HTTPS admission in section 10.2. The journal records which caller asked
(D19).
The runtime config's required, non-empty `allowedClients` list names the
OAuth clients the deployment admits; a token from any other client is
refused even when its scopes match an access profile (D33).

Client admission is not record-level authorization. The facade serves
trusted machine clients only: any admitted client with a matching scope
sees every record the deployment's configured source access reaches, because
the scopes gate operations and record types, not individual records.
Record-level authorization is planned, not built; until it is, admitting
a client means trusting it with the full reach of the deployment
credential.

### 10.2 Upstream authentication

Sources authenticate in different ways, so the pack endpoint declares one
`authentication` kind from a closed list, and the runtime config binds its
credentials as `secret:` references. The kinds and their fields are the ones
Evidence already ships for fixed sources (`SourceAuthentication` in
`registry-evidence`), spelled identically, so an operator who configured an
Evidence source configures an adapter endpoint the same way:

| Kind | Sends | Typical source |
|---|---|---|
| `none` | Nothing; requires an explicit runtime `credential: {type: none}` and is admitted only for numeric loopback, an endpoint with an mTLS client identity over HTTPS, or a fixed HTTPS source carrying `anonymousHttps: operator-approved` | Tests, mTLS-only sources, reviewed public APIs |
| `basic` | `Authorization: Basic` from `usernameRef` and `passwordRef` | DHIS2 user accounts |
| `static-authorization` | `Authorization: <scheme> <token>` from `tokenRef`, `scheme` defaulting to `Bearer` | DHIS2 personal access tokens (`ApiToken`), static bearer tokens |
| `static-api-key` | One declared header (`headerName`) from `valueRef`; reserved header names refused | Gateways keyed by an API-key header |
| `oauth2-client-credentials` | Bearer token from the RFC 6749 client-credentials grant with a shared secret (`credentialPlacement`, `scope`, `audience`, `resource`, bounded cache) | OpenCRVS-style integration clients, Keycloak-fronted APIs |
| `oauth2-private-key-jwt` | Bearer token from the client-credentials grant authenticated by an RFC 7523 signed assertion | SMART on FHIR Backend Services, high-assurance gateways |

Orthogonal to the kind, the runtime config may give an endpoint a private CA
and an mTLS client identity, which `FixedDestinationPolicy` already
supports; mutual TLS therefore combines with any kind. A matching pack
`authentication.type: none` and explicit runtime `credential.type: none` may
also reach a fixed non-loopback HTTPS source only when that same binding says
`anonymousHttps: operator-approved`. The acknowledgement is a named operator
decision, not a boolean; omission stays closed. It is refused on HTTP or with
any other authentication pairing. It is harmlessly redundant on an admitted
`none` plus mTLS HTTPS binding. TLS certificate verification, the fixed
destination policy, facade authentication, and the rule that caller tokens
never travel upstream remain unchanged. The private CA takes Evidence's shape:
`outboundTls.trustProfiles.<id>.caBundleFile` in the runtime config, named by
the endpoint binding's `tlsTrustProfile` (a CA bundle is not a secret).
Field bounds follow Evidence: `scheme` 1 to 32 HTTP token bytes,
`headerName` at most 64 bytes, `tokenEndpoint` without query or fragment,
`clientAssertionAudience` 1 to 512 non-blank bytes, and Evidence's bounds
and validators on `scope`, `audience`, and `resource`.

Rules:

- The token endpoint of an OAuth2 kind is itself a fixed destination bound
  in the runtime config, never derived from a response. Token requests are
  engine sends outside `maximumUpstreamCalls`, bounded separately: at most
  two per endpoint per exchange.
- The token request goes through the endpoint's own outbound client: the
  same trust profile, as in Evidence, and the same mTLS identity (Evidence
  has no client identity; this half is the adapter's own rule).
- Key material loads when the deployment loads: a client identity, a CA
  bundle, or a signing key that cannot be read refuses startup, never the
  first caller's request.
- Token responses are read as Evidence reads them: `token_type` must be
  `Bearer` (any case); a missing `expires_in` takes the operator's
  `assumedLifetimeSeconds` and, without one, fails as a credential error;
  the lifetime is anchored when the request is sent, not when the reply
  arrives; the cache is clamped to `maximumCacheSeconds`; unknown members
  are ignored; refresh is single-flight.
- Under the `basic-header` placement the client id and secret are base64
  encoded as written, without the form-encoding step of RFC 6749 section
  2.3.1, as Evidence does. A strict server mis-decodes a secret containing
  `%`, `+`, or non-ASCII bytes; such a client uses the `form-body` placement.
- For an OAuth2 kind, an upstream 401 invalidates the cached token and the
  send is repeated once with a fresh one (safe for writes too: a 401 means
  the request was not processed). A 401 after that, or any 401 under a
  static kind, raises the uncatchable `credential.rejected` (section 8.7): a
  route cannot repair a credential, and a fallback must not mask one. A 403
  stays `upstream.http`, since it answers about the request, not the
  credential. The 401 rule holds whatever `okStatusCodeRange` and
  `throwExceptionOnFailure` say, and `adapterctl check` refuses an
  `okStatusCodeRange` that covers 401 on an endpoint whose kind is not
  `none`.
- Tokens and secrets live in zeroizing buffers inside the `http` and
  `graphql` components only; the exchange, scripts, packs, fixtures,
  diagnostics, and the audit journal never see them. The journal records the
  endpoint's kind and token-request outcomes, never a value.
- Fixture replay intercepts the token endpoint like any other send, so packs
  are replayable without a credential.
- `none` never falls back from a failed Basic, static, or OAuth credential.
  The acknowledgement selects no destination and supplies no credential; the
  binding's fixed `baseUrl` and normal TLS trust remain authoritative.

Not ported: Camel's NTLM and Digest methods, API keys in the query string
(they leak into upstream and proxy access logs), and caller token exchange
(D19). The implementation is adapter-local over
`registry-platform-httputil` primitives; Evidence and the adapter are then
two systems sharing one credential shape, the trigger for lifting it into a
platform crate in a later, separately reviewed change, not in this program.

## 11. Audit and data minimization

The audit journal is Camel's event notifier, ported as a synchronous,
value-free PostgreSQL journal written before the response is sent. Event
kinds follow Camel's: `exchangeCreated`, `exchangeSending` and
`exchangeSent` (endpoint id, method, path template, status, duration,
response size and digest), `exchangeRedelivery`, `exchangeFailureHandled`,
`breakerRefused` (closed breaker state), `breakerFallback` (closed error
class and fixed authentication-event metadata), `exchangeCompleted`, and
`exchangeFailed` (error class, problem code). A
verified caller's refused call is one `callRefused` row (the 403 of an
access profile and the 404 of a wrong record type, D34), so probing is
auditable; a 401 is logged and not journaled, because no verified caller
exists to name. Each row carries the exchange id, the concrete operation, the caller identity, the
route id, and `occurred_at` (`timestamptz NOT NULL`, from the runtime clock
at the event, indexed for retention deletes). It records no bodies: no request payloads, no response payloads,
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
(runtime), `AdapterFixture` (fixture), and, experimental with governed
ingestion (section 17), `AdapterJob` (job) and `AdapterJobRuntimeConfig`
(job-runtime, file `job-runtime.yaml`). The authored/operator split matches
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
page. Each case that restates behavior the page leaves unstated also cites
the source file at the pinned tag (section 5.4), and a case adapted from a
Camel unit test names that test class and method, for example
`camel-4.23.0:core/camel-core/src/test/java/org/apache/camel/processor/SplitterTest.java#testSplitterWithAggregationStrategy`.
A divergence row has a case asserting our behavior and naming the
divergence. `check-port-table.py` parses section 8.10 and fails when a row's
module is missing or empty, when a schema key has no row, or when a row is
marked delivered by an increment that has not landed.

### 13.3 Pack conformance: fixture replay

Every maintained pack ships recorded upstream exchanges with expected facade
responses; each fixture entry names the facade operation it exercises.
`adapterctl fixtures replay` (and `check`) run them offline the
way Camel tests do: every `http` and `graphql` send is intercepted
(`interceptSendToEndpoint` with `skipSendToOriginalEndpoint`) and answered
from the fixture in order; the outgoing request must match the recorded
method, path, query, and body digest; the facade response must equal the
expected one byte for byte and validate against the generated schema; error
fixtures must map to the expected problem codes.

A token request matches by endpoint, method, and path alone, because replay
runs without a credential. A recorded token exchange carries no credential
header or body (`adapter.fixture.credential-recorded`), and the token in
its reply is a synthetic value that a captured recording must replace
before it is committed (section 10.2). `fixtures replay` executes the route
interpreter through an offline transcript transport and shares the facade's
disclosure and response rendering. It reports `drive: completed` only after
the ordered sends and expected facade result match, with no unexpected or
leftover exchanges. No live credential, source, listener, database, or
journal is used. Writes report `writesSimulated` and
`journalDurability: not-run`; PostgreSQL suites establish durable write
behavior separately. Replay cursors use a fixed synthetic context with the
production codec; live cursor sealing continues to use fresh randomness.

Provenance is mandatory and honest: each fixture records `type` (`captured`
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
- Mapping totality: every error class resolves to exactly one profile
  problem; unknown upstream errors produce the profile's problem for their
  class, never a leaked body.
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
answers, every undocumented route is refused with 404 or 405. Responses
under the `breg-records` profile match `registry-record` serialization
goldens and the shape of BReg's generated per-package OpenAPI
(`products/breg/generated/`). A second, deliberately different test profile
in the corpus (other paths, other envelope, other pagination names) is
served by the same binary over the same pack, proving the target API is
configuration.

### 13.7 Security tests

Egress allowlist: any call outside the declared base is refused and
journaled, including redirects. Private-address upstreams are expected, not
blocked: government DHIS2 and OpenCRVS instances sit on internal networks.
The platform's fixed-destination policy already decides this correctly;
private CIDRs are reachable only when the runtime config declares them
explicitly (`allowedPrivateCidrs`, bounded count), and plain HTTP stays
confined to those addresses. No expression can alter the origin or inject a
path segment; an `httpUri` off the endpoint's origin or base path is
refused and journaled. Only allowlisted headers leave the engine, and no
exchange header can replace an injected credential. A continuation cursor
that is tampered with, expired, replayed by another caller, or replayed
with other filters is refused before any route step runs. Uncatchable
errors cannot be handled by any `onException` or `doCatch`, and an
`RouteFailure` carrying an uncatchable class fires no clause. Secrets never appear in the exchange, scripts, diagnostics, or
audit. Every upstream authentication kind of section 10.2 is exercised over
the double, including token caching, the single retry after a 401, token
endpoint failure, and a marker secret proven absent from the journal,
diagnostics, and fixtures; the facade refuses a missing, expired,
wrong-audience, or wrong-scope token. Script budgets terminate runaway loops. Response size caps are
enforced. Diagnostics are value-free, asserted by the corpus marker. The
idempotency store's retention sweep erases expired bodies.
The anonymous-HTTPS proof uses a local synthetic TLS source: omission refuses
a non-mTLS public origin, the named acknowledgement sends no source credential
or caller-token header, and an untrusted certificate completes no HTTP
request.

### 13.8 Quality attributes

- Translation overhead: p99 at or under 20 ms excluding upstream time,
  measured in paired before/after local runs; local numbers are directional
  only and never cited as evidence.
- Memory bounded by `maximumResponseBytes` and the aggregation caps.
- Observability: per-operation structured metrics (errors by class and
  problem code, redeliveries, breaker state) and the queryable journal.

## 14. Delivery increments and definition of done

The Adapter lands in increments, each with runnable acceptance commands.

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
- Increment 1, the read engine: the exchange contract of section 8.11
  (facade inputs, continuation, script ABI, header allowlists,
  origin-pinned links, profile problem mapping) in the model, the checks,
  and the runtime; the Camel core for every Increment 1 port-table row with
  its conformance module; the `rest`, `direct`, and
  `http` components; the facade with OIDC and access profiles; `adapterctl
  compile` and the generated OpenAPI; the event-notifier journal on
  PostgreSQL with `test-postgres.sh`; fixture replay; `verify --live`; the
  `dhis2-tracker` pack serving `records-search` and `records-get`; fault
  injection, read property tests, contract and security tests.
- Increment 2, DHIS2 writes: `idempotentConsumer` and the idempotency store
  with replay and retention; write-safety checks live; DHIS2 create and
  update routes with import-summary and conflict mapping; write fixtures;
  write property tests.
- Increment 3, the second system: the `graphql` component; write resume; the
  `opencrvs` pack, reads first, then writes (draft, declare). Before this
  increment starts, the current OpenCRVS release's API is confirmed; if it
  is not GraphQL, the `graphql` component waits for a system that needs it
  (two-system rule) and the pack uses `http`.
- Increment 4 `[ingestion]`, governed-ingestion components: the engine
  boundary and job profile (section 17.2), the item contract, the job-only
  read step, the `file` source and the CSV and JSONL decoders, the
  read-only `postgres` source, the `kobotoolbox` and `odk-central` packs,
  the job host with its item table, pass, triggers, and operator surface
  (sections 17.2 to 17.4), the parked BReg connector for the direct
  destination (section 17.3), and the dependency gate (section 17.5). The
  direct and Coordinator destinations, and the mapping they run, follow in
  the steps section 17.7 orders. Every component lands feature-gated and
  unclaimed: it is claimed nowhere until the drill named in section 17.7
  has run it.
- Later: the GovStack profile and conformance mode; the WASM rung when a
  real pack needs it.

Definition of done for the program, every item verified by a command,
never by assertion:

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
5. Every fixture carries honest provenance, and the count of `captured` and
   `documented` fixtures is reported.
6. The exposed API is configuration: the test profile of section 13.6
   serves over the `dhis2-tracker` pack with no Rust change and no pack
   change, errors included (the pack names no profile problem code), and
   no adapter crate names a `breg-records` path, operation, or field
   outside tests.
7. Every upstream authentication kind of section 10.2 has a conformance
   test over the double, and the maintained packs and source-shape fixtures
   between them use at least four distinct kinds (DHIS2 `basic` and
   `static-authorization`, OpenCRVS's confirmed kind, and the OAuth2 kinds
   in the source-shape fixtures).
8. Every source-shape fixture under `products/adapter/fixtures/source-shapes/`
   passes `check`, holds its committed contract under `compile --check`, and
   replays its fixtures.

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
`[ingestion]` Conformance cases adapted from Camel's own unit tests are
behavioral adaptations, not copies: each names its upstream test class and
method (section 13.2), the port record lists every upstream test ported or
excluded, and NOTICE material is confirmed before the first release that
ships an adaptation, per section 5.4.

## 16. Recorded decisions

These principles were accepted on 2026-10-30; the status column names the
one that decides a row.

- P1, Camel behaviour, our format: port Camel's semantics and names exactly;
  platform configuration rules win only on spelling and file layout.
- P2, closed at every trust boundary: anything crossing a boundary is an
  explicit allowlist and everything else is refused; security beats Camel
  fidelity.
- P3, the profile owns the outward contract: packs state what happened at the
  source; only the profile decides what the caller sees.
- P4, the engine owns sensitive state: it stays in the engine, bounded by time
  and purpose, with a security review note.
- P5, shared mechanism early, features on need: a generic mechanism with no
  product semantics goes straight into a shared crate when that costs little;
  the two-system rule still decides what the engine compiles in, and a feature
  waits for a real source that needs it.
- P6, real proof before more breadth: prefer one route proven end to end over
  wider coverage; only captured source behaviour counts as proof.

| ID | Decision | Date, status |
|---|---|---|
| D1 | Facade is the `breg-records` v1 profile artifact, parameterized by the declared model; GovStack later as a second profile | 2026-10-30, accepted |
| D2 | Packs and profiles are maintained artifacts under `products/adapter/` | 2026-10-30, accepted |
| D3 | v1 scope is reads plus DHIS2 writes; OpenCRVS writes follow as their own increment | 2026-10-30, accepted |
| D4 | Source-native identifiers pass through; no correlation store in v1 | 2026-10-30, accepted |
| D5 | Product name and token: `Adapter`, `adapter` (`AdapterPack`, `AdapterProject`, `AdapterRuntimeConfig`, `adapter.*` codes) | 2026-10-30, accepted |
| D6 | The generated OpenAPI contains only bound operations; a conformance mode arrives with the GovStack profile | 2026-10-30, accepted |
| D7 | The engine is a bounded port of Camel's route model: authored YAML DSL routes, Camel EIP names, options, defaults, and semantics; it replaces the earlier bespoke call-plan vocabulary (`call`, `map`, `normalize`, `paginate`, `iterate`) | 2026-10-30, accepted (P1) |
| D8 | Packs are Kamelet-style catalogs of route templates; projects instantiate them with `templatedRoutes`; a deployment writes no routes | 2026-10-30, accepted (P1) |
| D9 | The facade is Camel's contract-first REST DSL over the generated OpenAPI, with validation always on and `missingOperation` fail only | 2026-10-30, accepted (P1) |
| D10 | Expression languages are `constant`, `header`, `exchangeProperty`, `jsonpath` (RFC 9535, inline, via a CFG-EMBED-1 amendment), and `rhai` (files only), which replaces Simple | 2026-10-30, accepted |
| D11 | Camel semantics, platform spelling: CFG-NAME wins on key spelling, Camel names are kept where they conform, exchange property names stay verbatim | 2026-10-30, accepted (P1) |
| D12 | The idempotency store retains the exact facade response for a deployment-configured retention window, separate from the value-free audit journal (BReg precedent); security review note required | 2026-10-30, accepted |
| D13 | The generic mechanisms under redelivery, circuit breaker, and throttle are built in platform crates from the start: the rolling-window limiter in `registry-platform-ratelimit`, the breaker state machine and redelivery delay computation in `registry-platform-resilience`. The processors and the redelivery loop stay in the adapter | 2026-10-30, accepted (P5) |
| D14 | Write resume is an addition, deferred to Increment 3 where OpenCRVS needs it; until then a write route with more than one non-safe send is refused | 2026-10-30, accepted (P5) |
| D15 | Fixture provenance distinguishes `captured` from `documented`; fixtures are `documented` unless a real instance was run | 2026-10-30, accepted (P6) |
| D16 | A write the source accepted but has not completed answers a 202 with a status link or a bounded wait, chosen by configuration; the keys and the bound's expiry are settled in Increment 2 | 2026-10-30, accepted |
| D17 | The exposed API, envelope included, is wholly a profile artifact (envelope templates over a closed slot vocabulary); `breg-records` v1 is the first target, not a built-in; `registry-record` is a dev-dependency for goldens only | 2026-10-30, accepted |
| D18 | Upstream authentication is a closed list of six kinds with Evidence's `SourceAuthentication` shape and spelling (section 10.2), plus orthogonal mTLS; adapter-local in this program, lifted to the platform later | 2026-10-30, accepted (P2) |
| D19 | The facade caller's token is never forwarded or exchanged upstream; upstream calls use the deployment's per-source credential, and per-user upstream authority waits for a source that requires it | 2026-10-30, accepted (P2) |
| D20 | The exchange contract (section 8.11) is part of the format: facade inputs arrive under closed, profile-neutral names; no caller header enters except `Idempotency-Key` on writes; scripts receive a read-only `#{body, headers, properties}` view and return per slot | 2026-10-30, accepted (P2) |
| D21 | Packs raise error classes and never name problem codes; an `outcome` branch and Camel's `throwException` carry source meaning; the profile's `problems` list maps every class, uncatchable and facade classes included, to exactly one problem; a handled clause answers with a success body | 2026-10-30, accepted (P3) |
| D22 | The facade cursor is engine-owned authenticated encryption under a runtime-config key (`cursorKeyRef`), bound to operation, binding, caller, filters, and expiry; the route sees only `AdapterContinuation` and sets `AdapterNextContinuation`; security review note required | 2026-10-30, accepted (P4) |
| D23 | Sources that page by URL use `httpUri`, an origin-pinned and base-path-pinned link checked at send time (`egress.refused` otherwise); `toD` stays not ported | 2026-10-30, accepted (P2) |
| D24 | Request headers leave only through the endpoint's `requestHeaders` allowlist; credential, cookie, host, and hop-by-hop headers are never allowlistable; credentials are injected after filtering | 2026-10-30, accepted (P2) |
| D25 | `direct:` shares the exchange and its sends are not redelivered; `enrich` runs on a copy and only strategy-named `properties` come back | 2026-10-30, accepted (P1) |
| D26 | A `POST` counts as safe only under a reviewed `safeUpstream: true` operation claim; a GraphQL send's safety comes from its parsed operation type | 2026-10-30, accepted (P2) |
| D27 | Exception matching uses the closest declared ancestor of the single `RouteFailure` class, with declaration order breaking equal-specificity ties; uncatchable classes fire no clause. The absence of Camel's cause-chain walk is a bounded divergence | 2026-10-30, corrected 2026-10-31 to the delivered single-class failure model (P1) |
| D28 | `AdapterProject` carries a `project` block (`id`, `version`) as CFG-ENV-6 requires, rather than a top-level `id` | 2026-10-30, accepted (P1) |
| D29 | Increment 1 builds the `records-get` route end to end first; the remaining read features then build over it | 2026-10-30, accepted (P6) |
| D30 | Increment 1's gate requires `captured` DHIS2 fixtures for get, missing, and search page, taken from a real server | 2026-10-30, accepted (P6) |
| D31 | Circuit breaker and throttle stay in Increment 1 as its last slice | 2026-10-30, accepted (P6) |
| D32 | No declarative field map until a real source needs one; field mapping stays in routes and scripts. `[ingestion]` KoboToolbox is that source, recorded 2026-10-31. The ingestion mapping stays a script: one pure interface that returns an operation input or a refusal with diagnostics, in Rhai on `registry-platform-script`, run in the job for the direct destination and in a Coordinator Function for events (section 17.3) | 2026-10-30, accepted (P5); ingestion note accepted 2026-11-01 |
| D33 | The runtime config requires a non-empty `allowedClients` list on the facade, as Messaging does; scopes alone leave the issuer's mint policy as the only client gate | 2026-10-30, accepted |
| D34 | A verified caller's refused call is a `callRefused` journal row; a 401 is logged only | 2026-10-30, accepted |
| D35 | After the real proof (P6), the facade contract is authored as a closed subset of OpenAPI with `x-` extensions for slots and problems, as Camel's contract-first REST DSL takes OpenAPI as input; until then `AdapterProfile` stands. Confidence is medium until a real ministry or GovStack specification has been tried | 2026-10-30, accepted |
| D36 | Plain HTTP to an address inside `allowedPrivateCidrs` is allowed for every authentication kind, including credential-bearing ones; the operator's explicit declaration is the consent, and `adapterctl check` agrees with the runtime load | 2026-10-30, accepted |
| D37 | Beyond the existing numeric-loopback and HTTPS+mTLS admissions, a configured source may use no application credential when pack and runtime both explicitly say `none` and the fixed HTTPS binding carries `anonymousHttps: operator-approved`; absence keeps that additional path closed, TLS verification and facade authentication remain mandatory, and no failed credential kind falls back to anonymous | 2026-10-31, accepted |
| D38 `[ingestion]` | Job source components `file`, `sftp`, and read-only `postgres` enter under the explicit two-system exception of section 5.3, job-only and refused in facade routes; `registry-adapter-connectors` alone links a product client, only `registry-breg-client` behind an off-by-default feature, for the direct destination | 2026-10-31, proposed; restated 2026-11-01; open in section 17.6 |
| D39 `[ingestion]` | The job profile keeps the platform-frozen 10-second per-attempt ceiling for HTTP and GraphQL sends and may raise a job endpoint's response bound up to the platform's 16 MiB cap; facade ceilings are unchanged | 2026-10-31, resolved against the platform caps of `registry-platform-httputil` |

## 17. Governed ingestion `[ingestion]`

Applied 2026-10-31 as a contract amendment and restated on 2026-11-01 to
the accepted governed-ingestion design. The adapter reads in place by
default. An ingestion job copies a record only when the receiver must own
it, such as registration into a registry; Evidence checks and data-space
reads stay read paths, served by a live facade or by Evidence's own
acquisition, never by an ingestion job. The useful outcome is an
accountable path from source input to the intended product operation,
including refusals, corrections, outages, and conflicting changes.
Delivery is not approval, and approval is not application: a job reports
what its destination accepted and nothing more. Section 17.7 states what
is built, the order in which the rest follows, and the claim rule: nothing
in this section is claimed until the drill named there has run it.

### 17.1 Ownership, rules, and source independence

| Part | Owns | Boundary |
|---|---|---|
| Source (Kobo, files, a database, a queue) | Its data and its edits; it is also the buffer a retry reads again | Source data is not registry authority |
| Adapter ingestion job | Reading the source, comparing items, mapping for the direct destination, handing off, the source position, and the job's status | Holds a source credential and, per destination, a BReg credential or a signing key; no other product's client or credential; no steps, branches, waits, or business timers |
| Coordinator, when used | Admission, one Run per item, lookup, choice, waits, recovery of its own commands, reaching a person | No product depends on it |
| BReg | Record and Action contracts, authorization, Proposals, application, receipts, bulk runs | Rechecks every operation under its own policy; an ingestion grant is never an approval grant |
| Review provider, such as Casework | Review policy, assessment, and decisions | Does not bypass BReg's application checks |
| Institution | Meaning of the form, matching rules, review policy, operating responsibility | Authored in the deployment, not compiled into the adapter |

Status keeps each observation separate: the job reports an item read,
accepted by the destination, refused with a code, or held for an operator.
Review and application are seen in BReg and the review provider, or in the
Coordinator Run that follows them. A timeout proves neither failure nor the
absence of an effect.

Six rules govern the mode:

1. **Read in place by default.** Copy a record only when the receiver must
   own it.
2. **One owner per concern.** The job reads, maps for the direct
   destination, and hands off. BReg and the review provider own authority,
   review, and application; Coordinator owns lookups, choices, waits, and
   reaching a person. The job has no steps, branches, or waits.
3. **Products stand alone.** The adapter may hold BReg's client and a BReg
   credential, and no other product's. No Adapter crate links a
   Coordinator crate; the Coordinator destination is Coordinator's
   published signed-event contract, tested against a fixture receiver.
   Bulk loads end in a file.
4. **Identity and progress, not payloads.** The source is the buffer, and
   the position moves only after the destination accepts.
5. **The pass is the only unit of work.** Triggers decide only when a pass
   starts; hook bodies are untrusted; a queue is a source.
6. **Direct only for one operation.** An item goes direct only when it maps
   to exactly one BReg operation with no lookup; everything else goes to
   Coordinator, and a refusal never falls back to another path.

Source protocol, transport, and data format are separate. CSV is a format,
SFTP is a transport, PostgreSQL is a database connector, and KoboToolbox
is an application API. A CSV file received by SFTP uses the same decoder
and the same mapping as an identical local CSV file. Every source takes
one shape: a job route, called with a cursor, that returns the item
contract of section 17.2. `http` and `postgres` fit as sends; `file` and
`sftp` fit through the job-only read step. `check` refuses all three job
components in every facade route, so the facade gains no file or SQL path.

Sources arrive in order. The KoboToolbox JSON API comes first, as the thin
slice, through a reviewed pack over HTTP; its stable key, edit order, and
record cap are unprobed hypotheses until a controlled deployment confirms
them. ODK Central reuses the Kobo pattern. Read-only SQL (PostgreSQL
first), local CSV and JSONL, and SFTP come second: read-only identity,
reviewed parameterized queries, statement timeouts, and bounded fetches
for SQL, where a timestamp watermark alone is no change feed; declared
encoding, quoting, and null rules for files, with leading zeros kept,
files identified by content digest and rows by a declared business key,
never by position; host-key verification and a completed-file convention
for SFTP. Hooks and a queue come third. A hook is a trigger: it starts a
pass early or joins one already running, the pass re-reads the source,
and the hook body is never trusted or stored; hooks arrive on a separate
ingress with their own authentication per source and never weaken the
facade's OIDC, and the interval trigger stays as reconciliation because
hooks are lossy. A queue is a source that holds data until acknowledged:
a message is acknowledged, or an offset committed, only after the
destination accepts the item, and a refused message goes to the broker's
dead-letter path, so the broker remains the buffer. DHIS2 stays a
live-facade source.

### 17.2 Engine boundary, job profile, item contract, read step

The route interpreter already runs without a facade profile through
`run_route` and its siblings. A job compiler separates the deployment
assembly: it loads a pack, an `AdapterJob` definition, and an
`AdapterJobRuntimeConfig` (the job's own runtime file, distinct from the
facade's `AdapterRuntimeConfig`), and exposes the job's source route as a runnable program with no
listener, no database requirement, no OIDC issuer, and no inbound Record
shape. The interpreter is not rewritten, no fake request is invented, and
the exchange starts with a null body and the job cursor under a closed
property name, bounded by the job profile's page deadline. The engine
boundary is the `crates/registry-adapter/src/engine` module, the
listener-free engine the job runs and the facade links; until it becomes
its own crate, the dependency gate of section 17.5 holds that line at
import level.

The job profile is explicit and bounded, separate from the facade
ceilings of section 8.8, which are unchanged. Under the platform caps of
`registry-platform-httputil` (D39): a job send's per-attempt timeout stays
at or below the platform-frozen 10 seconds, and a job endpoint's
`maximumResponseBytes` may be raised up to the platform's 16 MiB
response-body cap. The profile also bounds what the facade never sees: the
page deadline of one route run, the read size and page size of the read
step, and the row and field limits of the decoders. Every read has a
count, byte, and deadline bound, tested at the edge.

The item contract is a core type: `{items: [{key, revision?, value}],
next}`. `key` is the source's stable identifier for the item inside the
job's namespace; a job chooses a non-personal key where the source has
one, such as Kobo's `_id`. `revision` is the observed source version when
the source reports one reliably. `value` is a projection of the fields the
destination needs, shaped by the reviewed source route; it is not the
captured source item, and a whole form never travels because a destination
needed two of its fields. `next` is the resumption cursor, absent at the
end of a finite scan. An ongoing scan holds its place at the tail with a
cursor on every page, so a rescan of it ends at its first empty page.

A source route declares its contract: whether the scan is `finite` or
`ongoing`; the recovery semantics of `next`, from a closed set
(`exact-replay`, where a replayed cursor re-reads the same bytes, such as
a file digest and position, and `key-deduplicated`, where upstream pages
may shift between reads and the consumer deduplicates by key); and how
edits are found. The position only moves forward, so a source declares
whether an edit moves an item past the position (`ordered`) or needs a
periodic read from the first page (`rescan`, with a declared delay between
60 seconds and one day). Kobo declares `rescan` until a probe shows
otherwise. `check` enforces the declaration; the job entry validates every
produced page against the contract shape and bounds before it is
returned. A source route is bound by no facade operation and is not
callable through `direct:`.

The job declares its projection: the dotted field list the destination
needs. The pass picks exactly those fields from each `value` at hand-off,
a missing field as `null`, so nothing outside the declared list reaches a
destination. The item digest covers the projected fields by default
(`digestOf: projection`); a job may declare `digestOf: value` to digest
the route's whole `value` together with the sorted declared field list
instead, so a field-list edit still changes every digest. The store records the projection
declaration's own digest beside the items, so a changed field list is
visible.

The job keeps one row per item, and nothing else about it:

| Column | Meaning |
|---|---|
| Key | The source's stable identifier, under the job's namespace |
| Last digest | A plain `sha256:` digest of the digest basis, with no secret |
| Sequence | Counts changes to the item from 1, so a revert from B back to A is a change |
| Status and code | `pending` (handed off, answer not yet recorded), `acknowledged` (accepted by the destination), or `refused` with the destination's item-scoped code; `held` for an operator arrives with the destinations of section 17.3 |
| Reference | What the destination returned: a Proposal ID, an Action receipt, or a Coordinator Run ID |

Beside the rows, the job's state holds its source position, its lease,
and the schedule and outcome of its last pass. The table holds no payload,
so a dump of it identifies items but exposes no answers. It is protected
like any operational database, with no digest secret and no per-row
encryption.

A trigger decides only when a pass starts and carries no data into it.
The interval trigger ports Camel's scheduled-poll options (delay, initial
delay, greedy, and idle and error backoff) with their defaults. The hook
trigger is contract-only: checks refuse it
(`adapter.job.trigger-hook-unserved`) until the hook ingress of section
17.1 is built.

The read step is a bounded port of Camel's `pollEnrich`: a job-only step
over a static URI (`file:<endpointId>`, `sftp:<endpointId>`) with a
mandatory timeout, one bounded page per read. This keeps every source one
route shape: a job route whose steps poll or send and whose final body is
the item page. It is refused by `check` in every facade route. The
alternative form, a job-route `from: file:`, is recorded as rejected: it
would give the engine a second consumer model beside `rest` for no gain,
and the port table row records the choice.

### 17.3 The pass, the two destinations, and mapping

A **pass** is the only unit of work: one bounded read from the saved
position, a comparison, the hand-offs, and a saved position. It works in
this order:

1. Take the job's lease, so one job runs one pass at a time.
2. Read one page from the saved position.
3. For each item, compare the digest with its row. A new item, or a
   changed digest, writes the row as `pending` and hands off. A `pending`
   row with the same digest hands off again with the same identity. An
   unchanged settled row is skipped.
4. Record the destination's answer: accepted with its reference, or
   refused with its code for an item-scoped refusal.
5. Any answer that describes the deployment rather than the item
   (authentication, a held deployment, an unavailable service) stops the
   pass with the position unchanged.
6. When every item on the page is settled, acknowledge the page to the
   source if it is a queue, then save the position.

**One stop rule.** A schema or policy change can refuse every item alike,
which would run the position to the end of the source. So a job declares
how many consecutive refusals with one code stop the pass with the
position unchanged (20 by default). Status names the code, and `rescan`
retries refused items on request.

**Changed items.** An item that changes after a first hand-off is
revised, and a `pending` row counts as possibly accepted, because a lost
response may hide a real effect. A revised item never becomes a second
registration: the job either holds it for an operator or, when the job
names a Coordinator receiver for revisions, sends it there as a `revised`
event so that a workflow can reach a person. Automatic correction of
submitted, approved, or applied work is out of scope.

The pass hands each item to its destination through one seam. The
destination answers in one of three ways: accepted, with its reference;
refused, with an item-scoped code; or stop, with a deployment-scoped code.
Every hand-off of the same item carries the same identity, derived from
the job, the item key, and the item's sequence.

There are exactly two destinations, chosen per job by what its items
need:

| | Direct to BReg | Signed event to Coordinator |
|---|---|---|
| Use when | The item maps to one BReg operation with no lookup: an immediate Action, or a Proposal start and submit | The item needs a lookup, a choice between operations, a wait, a person, or a write outside BReg |
| Adapter holds | `registry-breg-client` behind a feature, and a BReg credential | A signing key; no product client and no Coordinator crate |
| Mapping runs | In the job, as a Rhai script on `registry-platform-script` | In the workflow, as a Rhai Function on the same engine |
| Retry identity | Command keys derived from the job, the item key, and its sequence | An event ID derived from the same three |
| Accepted means | BReg committed the Action, or the Proposal is submitted | Coordinator admitted the event and opened a Run |
| Follow-up | None in the job; review and application are seen in BReg and the review provider | The workflow follows the outcome with `wait-for` and reaches a person when needed |
| Parts to run | Adapter job, BReg, and a review provider if the Action needs one | Adapter job, Coordinator, BReg, and a review provider |

**Direct to BReg.** The job maps the item, prepares the BReg request, and
sends it under keys derived from the item, so a lost response is recovered
by sending the same request again and BReg replays its receipt. The job
stores no prepared attempt: a retry re-reads the source, re-maps, and
resends. If the item changed, or the mapping now produces different bytes,
BReg answers `idempotency.key-reused` and the item is held for an
operator, which is the safe direction. A Proposal uses two command
identities, start and submit, derived from the same item key and
sequence; the start receipt returns the Proposal ID that submit needs.
The receipt horizon falls on the job: BReg keeps a receipt for
`retention.receiptRetentionDays` (7 days by default), after which an exact
repeat answers `410 idempotency.expired` and is never executed. A
`pending` row older than that is held for manual reconciliation; BReg does
not serve the setting, so the job declares the expected horizon and status
warns as pending rows age toward it. The direct path is only for new work
that needs no target resolution. BReg has no external-key upsert, and its
lookup answers `lookup.unresolved` alike for no match, two matches, and a
hidden record, so "no match, so create" is unsafe: a form that corrects
existing households needs a lookup, and therefore Coordinator.

`registry-adapter-connectors` holds a parked BReg connector for the direct
destination. It is the only crate that links a product client, and the
only client it links is `registry-breg-client`, behind an off-by-default
feature. While parked it is linked by no facade binary and no job path,
and its operation set is not part of this contract.

**Signed event to Coordinator.** One signed event per item, in the
platform's `HookEnvelope` format signed with `sign_v1`, admits one Run of a
reviewed workflow through `workflow.eventTriggers`. Admission and Run
commit together, and a repeat of the same event recovers the same Run. The
workflow maps, resolves the target, calls one typed operation such as
`breg.submit-proposal/v1`, and follows the outcome with `wait-for`.
Coordinator recovers its own commands; the job tracks only the admission.
No Adapter crate links a Coordinator crate, and the destination's tests
run against a fixture receiver.

**Never a fallback.** A refusal from one destination never falls back to
the other, and a denied Proposal never falls back to a direct write: the
item is refused or held, and a person decides.

**Bulk.** A bulk load is a third hand-off, not a destination: the job
writes a bounded file with its digest and item count, and an operator
runs `bregctl data import`. The job never launches another product's CLI,
and that file is the one place a job writes payloads, in the operator's
custody.

**Mapping.** One interface, run where the destination is:

```text
map(item, context) -> input | refusal(diagnostics)
```

The interface is pure. Its context (business date, locale, code-system
versions) is explicit, and it has no network, file, clock, or credential
access. It runs in Rhai on `registry-platform-script` under that crate's
published limits (D32), and its output is validated against the
operation's input schema before a request is prepared. A missing answer
never clears a registry field. A mapping never selects a person, approves
a change, or emits SQL. Diagnostics name the rule and the field, never the
value.

**Corrections and reaching a person.** A source edit after a first
hand-off never overwrites reviewed or applied work. In BReg, changes
requested leave the Proposal `submitted` with the turn on the party, and
an officer corrects and resubmits there; terminal Proposals are never
reopened, and a correction starts new work against current state. In the
direct destination, a person sees held items in job status and works in
BReg. In the Coordinator destination, a workflow reaches staff through a
review request, or stops a Run so that it needs attention. Source deletion
is reported by `rescan` as items not seen, and never selects a cancel or a
tombstone.

### 17.4 Custody, operator surface, and packaging

The job keeps no payload at rest, so there is nothing to seal and no vault
to run. Its controls, each against a stated threat:

| Control | Threat | Cost |
|---|---|---|
| No payload in the item table | A dump or backup exposes personal data | A retry needs the source; a source that deletes early loses the item |
| Field projection | A whole form reaches BReg, Coordinator, or their operators | One declared field list |
| Narrow grants | An ingestion credential approves or applies | BReg Start, Submit, and Get, or one Action; no Apply, no List |
| Signed events, Coordinator destination only | A forged event starts a Run | One rotatable signing key; a clock within 30 seconds |
| Value-free logs and status | Personal data reaches log aggregation | None |

The operator surface is the companion executable's commands: `check`
compiles a job the way a pass would; `pass` runs one bounded pass, the
shape a CronJob drives, or loops on the job's interval trigger; `status`
counts the item table's statuses and refusal codes, says whether a pass is
overdue, and says why the last pass stopped; `inspect` goes from an item
to its destination reference; and `rescan` runs one pass from the first
page, in which unchanged items skip by digest and refused items retry. A
preview pass delivers nothing, writes nothing, and records what a
destination would have received. Every output is value-free.

The mode packages as one native companion executable on PostgreSQL. For a
small IT team, a direct job adds one binary, one database, one source
credential, and one BReg credential. A Coordinator job swaps the BReg
credential for a signing key and a clock within 30 seconds of
Coordinator's.

Four properties are never cut: the position moves only after acceptance,
the same item sends the same identity, no payload is at rest, and
diagnostics are value-free. Out of scope by name: attachments, automated
Revise and Rebase, write-back to the source, automatic deletions, fuzzy
matching, multi-source merges, and a graphical operations application. If
a chosen form needs attachments or matching, the pilot scope changes
rather than gaining a stub.

### 17.5 Dependency gate

`products/adapter/scripts/check_dependency_direction.py` reads Cargo's
resolved graph with every feature enabled. It proves that the engine
crates (`registry-adapter`, `registry-adapter-core`,
`registry-adapter-job`, and `registry-adapterctl`) reach shared platform
primitives and nothing else of the workspace, that no Adapter crate links
a Coordinator crate, and that `registry-adapter-connectors` reaches
exactly `registry-breg-client`, behind its off-by-default feature, is
reached by no other workspace crate, and never reaches a product runtime,
adopter tooling, supporting service, binding, or database crate. Inside
`registry-adapter`, it holds the engine boundary at import level: no file
under `src/engine` names a facade module or a dependency only the facade
links. It follows Coordinator's gate in shape and is named beside it in
the root `AGENTS.md` gate table.

### 17.6 Open decisions

1. **The two-system exception (D38).** `file`, `sftp`, and `postgres`
   enter as job-only mechanisms before a second real system demands them.
   If refused, the components wait and the mode narrows to `http` sources
   and reviewed packs.
2. **The BReg client exception.** Admitting `registry-breg-client`,
   behind a feature, as the one exception to the rule that the adapter
   never links another product's types, is a contract amendment still to
   be confirmed.
3. **The SSH dependency (for `sftp`).** No SSH library is in `Cargo.lock`,
   and the always-on `aws-lc-rs` FIPS posture makes a new cryptographic
   dependency a reviewed decision. The `sftp` component lands only after a
   dependency review against `deny.toml` and the FIPS posture note; until
   then the job compiler refuses an `sftp` source.
4. **The queue.** Kafka is preferred if a Rust client exists that passes
   the FIPS posture, since `rdkafka` links `librdkafka` and OpenSSL;
   otherwise RabbitMQ through `lapin` over `rustls`. The dependency review
   comes before any queue code.
5. **The direct connector's operation set.** Which BReg operations the
   parked connector exposes is pending; until then this contract names
   none.

Unproved and recorded as such: Kobo's stable key, edit order, and record
cap come from documentation, not a probe, so the cost of `rescan` is
unknown; BReg's item-scoped refusal codes for the direct destination, and
whether its Proposal client's recovery works without a stored prepared
attempt, are unchecked.

### 17.7 Build status, sequence, and claims

Built, each part feature-gated or off the default path and claimed
nowhere: the engine boundary and job compiler; the job profile; the item
contract and source declarations; the read step; the `file` source with
the CSV and JSONL decoders (feature `job-file`) and the read-only
`postgres` source (feature `job-postgres`); the `kobotoolbox` and
`odk-central` packs with documented fixtures; the job host
(`registry-adapter-job`) with its item table, pass, stop rule, interval
trigger, rescan, preview pass, value-free status and inspect, and a
loopback-only fixture destination for tests; the parked BReg connector;
and the dependency gate. Not built: the direct destination, the
Coordinator destination, the mapping run in the job, the `held` status,
the bulk file, the `sftp` source, the hook ingress, and the queue source.

| Step | Deliverable | Gate |
|---|---|---|
| 0 | Both destinations on the thin slice, against real binaries and the deployment's real review policy: a fixture script that starts and submits a Proposal through `registry-breg-client` with derived keys, and one that signs an event into a workflow using `breg.submit-proposal/v1` and `wait-for` | Each reaches a submitted Proposal, a repeat recovers the same Proposal or Run, and the comparison records parts, operator steps, and recovery; it also settles whether the Kobo form is new-only, which can go direct, or needs a lookup, which needs Coordinator |
| 1 | Engine boundary: job compiler and entry point without the facade's listener or journal, a job profile, the contract amendments | Existing Adapter suites stay green; a route runs with no listener |
| 2 | Walking skeleton: one Kobo form, item table, pass, interval trigger, the destination step 0 chose | One submission reaches a submitted Proposal on real binaries and PostgreSQL |
| 3 | Recovery and corrections: lost responses, crash points, position rules, reverts, revised items, the stop rule | The recovery scenarios below pass |
| 4 | The drill: a controlled Kobo deployment and one review provider, ending applied or explicitly failed | Every scenario below passes in a recorded drill |
| 5 | SQL, files, and SFTP into the same destinations | No source logic in the pass |
| 6 | Hooks as a trigger, then the queue as a source | Their scenarios below |

**Claim rule.** Components may be built ahead of their step. Each stays
feature-gated and claimed nowhere, on the site, in a deck, or to a
partner, until the step 4 drill has run it. A component built under this
section is done when it carries its port-table row and conformance module,
its Camel unit tests at the tag are ported or recorded as inapplicable
with citations, each refusal has an `adapter.*` code and a corpus case,
every read is bounded at the edge, diagnostics carry no values, its
feature is off by default with a test proving the facade cannot reach it,
and its row below passes.

| Component | Acceptance row |
|---|---|
| `http` under the job profile | A paged acquisition over a real HTTP source completes under the job profile with no facade-suite regression |
| `file` and the CSV, JSONL decoders | Quoted multiline fields, leading-zero identifiers, empty and null rules, oversized rows, and malformed items have deterministic outcomes; traversal and symlink escape are refused |
| `postgres` | Read-only authority, bounded queries, a defined snapshot or change order, and restart without duplicates, with a write proven refused |
| `sftp` | Incomplete uploads are not admitted; interrupted transfers and replaced same-name files do not corrupt or duplicate work |
| `kobotoolbox`, `odk-central` packs | Synthetic fixtures replay; every behavior that rests on documentation rather than a probe is listed as unproved |

| Scenario | Required result |
|---|---|
| Valid submission | One Proposal with the exact Action inputs, or one committed Action |
| Review and application | Separately observable; only application changes records |
| Duplicate read and restart | Unchanged items send nothing; a repeat recovers the same Proposal, receipt, or Run |
| Crash or lost response at any point | The next pass sends the same identity, and nothing is skipped or duplicated |
| Changed item after a first hand-off | Held, or sent as `revised` to Coordinator; never a second registration |
| Item changed before a lost response is recovered | `idempotency.key-reused`, and the item is held |
| Pending row past BReg's receipt horizon | Held for reconciliation, and status warned before it |
| Item-scoped refusal | Recorded with its code; the pass continues until the stop rule |
| Deployment-scoped answer | The pass stops with the position unchanged, and status names the code |
| Ambiguous or unresolved target | Never a direct create; a person decides |
| Refusal in one destination | No fallback to the other, or to another write mode |
| Product independence | A direct job runs with no Coordinator; a Coordinator job's tests pass against a fixture receiver; the dependency gate shows only `registry-breg-client`, behind its feature |
| Hooks | A forged, duplicate, or lost hook changes only when a pass runs |
| Queue | A message is acknowledged only after acceptance; a crash redelivers it with no duplicate effect; a refused message reaches the dead-letter path |
| Diagnostics and retention | No payload in the item table; no credentials or personal values in logs |
