# Adapter: Live Translation Facade

Status: concept, direction accepted 2026-10-30. No code exists yet; this
document is the plan of record for the product's shape, boundaries, and
verification. Decisions D1 to D6 are recorded in section 16.

## Executive summary

The Adapter exposes a standard registry API over systems that already hold
data (DHIS2, OpenCRVS, bespoke REST services) without changing their native
APIs. It translates requests and responses live, supporting reads and writes
where the underlying system allows them. It is a translator, not a registry:
it holds no records and decides nothing. Why a call is allowed is the
adapter's own access profile; what happens after a write is the source
system's native process.

The architecture follows the house rule the Base Registry Engine set: the
runtime has no built-in model of any source system; everything a source
system is arrives as configuration. Four authored artifacts (facade profile,
adapter pack, adapter project, runtime config) plus generated outputs compose
a deployment. A new source system is a new pack, written and validated
without touching Rust. New facade contracts (a GovStack profile later) are
new profile artifacts. The engine copies the parts of Apache Camel worth
copying, the exchange model and the enterprise integration pattern
vocabulary, and ports their documented semantics directly instead of
inventing parallel behavior; every divergence is written down in section 8.

## 1. Product thesis

Institutions do not lack registries; they lack one agreed way to read and
write the registries they already run. Replacing DHIS2 or OpenCRVS is not on
the table, and every bespoke integration so far has been a one-off. The
adapter makes the integration itself a reviewed, versioned artifact: a
pack that maps a declared model onto a source system's real API, executed by
one bounded engine that owns security, retries, audit, and contract
validation. The same engine serves every pack; the same pack serves every
deployment of that source system; a new deployment writes only a project
file.

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
  validated offline by `adapterctl check`.
- Response compatibility with Registry Record v1, so consumers of Base
  Registry Engine output can read adapter output.
- One native binary, PostgreSQL for the audit and idempotency journal,
  deployment story identical to the rest of the stack.

## 4. Non-goals (v1)

- The GovStack Registry Building Block profile (later artifact, plus a
  conformance mode; section 7).
- Message brokers, streaming, scheduled synchronization, batch ingestion.
- SOAP, XML, JDBC, and other envelopes beyond HTTP/JSON REST and HTTP/JSON
  GraphQL (they arrive as compiled-in envelope executors, section 8.5, only
  when a real adopter needs one).
- An identity correlation store (source-native identifiers pass through).
- Compensation, rollback, or sagas across upstream calls (section 9).
- Dynamic plugin loading; dlopen-style extension.
- BReg governance machinery: proposals, review lifecycle, evidence
  consumption, timers, MCP, statistics, spatial queries.
- `registry-breg-client` compatibility (Record v1 response shape
  compatibility is promised; BReg's opaque authorization handles are not
  replicated).
- Anonymous serving: the facade authenticates every caller.

## 5. Design principles

### 5.1 Translation, not custody

The adapter never stores a record. It holds configuration, journal entries
(metadata, digests, outcomes), and nothing else. The source system remains
the system of record and keeps its native administrative surface.

### 5.2 The declared model is the disclosure boundary

A deployment declares its record types and fields. The facade can only
return what the declaration names, in the shape the facade profile defines,
validated against a schema generated from the declaration. A pack cannot
widen disclosure; a script cannot smuggle a field past validation. This is
the property that makes a full-read-write proxy acceptable in a
minimum-disclosure stack: the standard API is the minimization contract.

### 5.3 System knowledge is configuration

Nothing about DHIS2 or OpenCRVS is compiled in. A pack is a reviewed,
versioned artifact: call templates, pagination plans, success and error
detection, code maps, and scripts at declared seams. Engine capabilities
grow only under the two-system rule: a capability is added when a second
real system needs it, otherwise it is pack logic. Executors compiled into
the engine are named for mechanisms (`soap-xml`, `jdbc`), never for
products.

### 5.4 Bounded scripts at declared seams

Scripts are Rhai, executed by `registry-platform-script` with budgets, no
I/O, and precompiled entrypoints, exactly as Evidence, Messaging,
Coordinator, and BReg already run theirs. Scripts fill declared placeholders
and transform values; they never see credentials and never construct URLs.
Conditionals live only in scripts; configuration stays declarative.

### 5.5 Port Camel's documented semantics; diverge deliberately and in writing

Where the engine implements a pattern Apache Camel documents, the Camel
documentation is the reference for its semantics (section 8.4 names each).
Divergences exist, they are intentional, boundedness and security force
them, and the port table records every one. We do not silently rename or
re-scope a documented pattern.

### 5.6 One contract artifact per deployment

The generated OpenAPI document is the exposed truth: it contains exactly the
operations the deployment binds, no more. Callers learn what exists today,
not what a profile family could someday offer.

## 6. Artifact model

| Artifact | Kind | Registered format | Contains |
|---|---|---|---|
| Facade profile | Authored, versioned, maintained by us | `AdapterProfile` | Operation set by id, methods and paths, envelopes, problem codes, parameterized parts. First: `breg-records` v1 |
| Adapter pack | Authored, versioned, reviewed | `AdapterPack` | Per source system: call templates, pagination plan, success and error detection, code maps, field maps, script references (own files, digest-pinned), required capabilities |
| Adapter project | Authored, top-level | `AdapterProject` | Declared record types and fields, profile and pack references pinned by version and digest, enabled operations |
| Runtime config | Operator | `AdapterRuntimeConfig` | Environment bindings: upstream URLs, secret references, listener, database, OIDC, from platform shared blocks |
| Fixture suite | Authored, per pack | `AdapterFixture` | Captured upstream exchanges with expected facade responses, each recording the upstream version it was captured from |
| Generated outputs | Build artifacts | read-back, drift-gated | Per-deployment facade OpenAPI and computed schemas, emitted by `adapterctl compile` into the built package |

Projects reference packs and profiles as plain identifiers (CFG-ID-3),
resolved and digest-checked by `adapterctl check` (CFG-ID-4). Packs declare
the engine capabilities they require; the ctl refuses a pack the binary
cannot run, and the runtime refuses at startup with a bounded problem.

## 7. Facade contract and dynamic payloads

The facade contract is an artifact, not engine code. A profile declares the
operation set (`records.search`, `records.get`, `records.create`,
`records.update`) with paths, methods, envelopes, and problem codes, and
declares which parts are parameterized by the deployment. The `breg-records`
v1 profile mirrors the Base Registry Engine's public read surface
(`/v1/records/{type}`, `/v1/records/{type}/{record_id}`) plus write
operations, with responses in Registry Record v1 shape through
`registry-record`. The adapter depends on `registry-record` and never on the
`registry-breg` runtime.

Payload content is dynamic: request and response schemas and search
parameters are computed per deployment from the declared model, the same way
BReg's compiler computes its per-package OpenAPI from a registry project.
Scripts receive and return values typed against the declared model; fixture
values are checked against declared field types at check time (CFG-VAL-9);
responses validate against the generated schema at runtime.

`adapterctl compile` emits the deployment's concrete OpenAPI document into
the built package, held byte-identical by a drift gate. It contains only the
operations the project binds (decision D6): the contract states what the
deployment actually serves. When the GovStack profile lands it may require
its full operation set, served by a conformance mode that fails a deployment
whose contract is incomplete; that mode arrives with the profile, not
before.

## 8. Engine model

### 8.1 Crates

- `registry-adapter-core`: source-neutral model, wire DTOs, problem codes,
  authoring checks. No I/O.
- `registry-adapter`: runtime. Serves the facade, executes call plans, owns
  security and the journal. Reuses `registry-platform-script`, `-oidc`,
  `-httputil`, `-httpsec`, `-ratelimit`, `-audit`, `-config`, `-yaml`.
- `registry-adapterctl`: authoring and operator tooling; the `adapterctl`
  binary. Check, compile, fixture replay, `verify --live`.

Platform reuse is load-bearing, not incidental: the adapter is the second
consumer the fixed-origin transport was waiting for. The upstream layer is
built on `registry-platform-httputil`'s `FixedDestinationPolicy` (opaque
templated requests, DNS pinning, mTLS and private CAs, the explicit
private-CIDR allowlist) and its destination script machinery, and the
facade's server side uses `registry-platform-httpsec`, as Evidence does.
Where the adapter needs more than the platform has (the read-class
redelivery executor, a circuit breaker), the addition lands in the platform
crate as mechanism under the two-system rule: additively, with Evidence's
frozen Version 1 served behavior preserved and its gates rerun. Product
logic (call plans, mapping, disclosure) never moves into a platform crate.
This program changes no Evidence crate; Evidence adopting the new shared
pieces (redelivery executor, breaker, plan-shaped destination use) is a
later decision on Evidence's own schedule, recorded as a follow-up
candidate, not adapter scope.

### 8.2 Lifecycle

One execution per facade call: validate against the declared model, resolve
the operation binding, build the upstream call plan, execute it (timeout,
retry, circuit breaker, throttle, size caps per endpoint declaration),
aggregate sequential and paginated calls, translate through the pack's
declared maps and script seams, validate the response against the generated
schema, answer. Every step journals metadata.

### 8.3 Call plans

One facade operation binds to one declared plan: an ordered list of steps
the engine interprets within the request. There are no user-composed
pipelines; the plan is part of the reviewed pack, and its shape is checkable
offline.

Step kinds (engine vocabulary; Camel names kept where a pattern is ported):

- `call`: one upstream request built from the pack's operation template.
- `map`: declarative field mapping plus an optional script seam; output is
  validated against the declared model before it can bind a name.
- `enrich`: a secondary `call` whose result merges into the working document
  by declared reference. Content-enricher semantics: enrichment failure is
  the operation's failure. There is no optional-skip enrichment in v1; a
  record served without its enrichment would mislead.
- `normalize`: merge differently shaped upstream branches into the one
  declared model. Totality is checked offline: every declared branch must
  produce the model.
- `paginate`: cursor walk over a declared page shape, bounded by
  `maximumPages` and `maximumItems`; duplicate or shifting pages are
  detected and fail the operation rather than silently merging (section
  13.4).
- `iterate`: bounded split of one declared array, with a per-item policy:
  `stopOnFirstFailure` (the default, and the only policy for writes) or
  `continueAndReport`, under which every item is accounted in the response
  as succeeded or failed with a bounded problem code. Per-item execution
  counts against the plan budget.

Bindings: each step names its output; later steps reference earlier outputs;
every reference resolves at check time (CFG-ID-4). Budgets are declared per
plan: `attemptTimeoutMilliseconds` per step, a plan deadline,
`maximumUpstreamCalls`, and `maximumResponseBytes`. The engine refuses at
budget with the bounded problem; the journal stays complete.

A read plan in pack form is three to five steps: `call` the search, `map`
page items, `paginate` while the cursor advances, `enrich` detail calls,
then a final `map` into Record v1. A write plan is a `call` sequence under
`stopOnFirstFailure` (section 9).

### 8.4 The Camel port table

| Pattern (Camel name kept) | Semantics ported from Camel | Our form | Divergence |
|---|---|---|---|
| Exchange, message exchange pattern | In/out messages, properties, InOut vs InOnly | Typed exchange; all v1 operations are InOut | InOnly deferred with async work |
| Message | Headers and body | Typed parameter set; body is a size-bounded JSON value | No mutable header bag; values are declared |
| Component, Endpoint | Connector implementation vs addressed endpoint | Envelope executors (`rest-json`, `graphql`) vs endpoint declarations in the pack | Components are not user-pluggable code; they are rungs on the ladder in 8.5 |
| Processor pipeline | Ordered processing steps | Fixed engine lifecycle; steps are engine-owned | Users do not compose pipelines |
| Content-Based Router | Route by predicate | Engine-internal: read path, write path, error path | Pack-level routing on request predicates is deferred |
| Message Filter | Drop content not matching | Declared field allowlist plus response schema validation | Filter is a security boundary, not a content step |
| Message Translator | Convert message to another form | Declared maps plus Rhai seams | Translator authoring is declarative-first |
| Normalizer | Different sources to one canonical model | The profile's Record v1 canonicalization | One canonical model per profile |
| Content Enricher | Call another source to complete a message | Secondary call in a sequential plan, joined by declared reference | Bounded to the plan's declared steps |
| Splitter | Divide one message into many | Pagination fan-out and multi-call plans | No user pipelines; one operation, one plan |
| Aggregator | Combine many into one, with completion conditions | Page assembly and multi-call assembly | No persistent aggregation repository; completion is bounded and immediate |
| Retry Template (redelivery policy) | Maximum attempts, delay, backoff, jitter; exhaustion routes to the error handler | `maximumAttempts`, `retryDelaySeconds`, backoff multiplier, bounded jitter (0.1 to 0.3), matching by upstream error class, per endpoint | Defaults differ by operation class (section 9): reads may retry, writes do not auto-retry |
| Circuit Breaker | CLOSED / OPEN / HALF_OPEN, failure-rate threshold over a window, open-state wait, limited half-open trials | Per upstream endpoint; a tower-style state machine (single-probe half-open admission) beside the retry modules in `registry-platform-httputil` | Journal, not an alternate route, receives the refused exchange |
| Throttler | Maximum exchanges per period | Token bucket per upstream endpoint (`registry-platform-ratelimit`) | None of substance |
| Dead Letter Channel | Terminal route for exhausted exchanges | Journal entry with bounded problem code; operator replay | No automatic redelivery to a secondary endpoint |
| Wire Tap | Fire-and-forget copy for inspection | Audit journal write before the response is sent | Synchronous, therefore stronger, not fire-and-forget |
| Type Converter | Registry of conversions with fallback | Code-system maps (option sets to enums), explicit, refusal on unmapped value | No implicit chains; an unmapped code is an error, never a guess |

Not ported, deliberately and completely: route DSLs (Java, XML, YAML), the
Simple language, beans and registry integration, dynamic router, service
discovery and load balancing, multicast and scatter-gather beyond bounded
split, streaming, sagas, transactions and UnitOfWork, broker components, the
roughly 300 component library, Camel K, Quarkus, and Spring runtimes.

Error handling adopts Camel's disposition vocabulary: a mapped upstream
error is handled (translated problem code, exchange ends); an unmapped one
propagates to the bounded engine problem. The third Camel disposition,
continued, has no v1 use: it resumes a user pipeline, and v1 has no
user-composed pipelines.

### 8.5 Executor escalation ladder

1. Declarative pack: templates, tables, code maps.
2. Pack plus Rhai seams for conditional logic.
3. WASM component (`registry-platform-script` wasm profile): ships as data,
   no engine rebuild, third parties can author them.
4. Compiled-in Rust executor, feature-gated, for new protocol envelopes
   only.

Rules: each rung is used only when the one below demonstrably fails;
security stays engine-side at every rung (credential custody, egress
allowlist, size caps, audit, response validation); no dynamic loading in v1;
components are named for mechanisms, never products.

## 9. Writes, idempotency, and failure semantics

The profile carries create, update, and partial-update operations; a project
binds them per record type, optionally. A write is expressed as a sequential
call plan: a DHIS2 create is one POST parsed through its import summary; an
OpenCRVS registration is the source's real process (draft, declare), several
calls in sequence. The engine journals every attempt: which step, which
endpoint, what status, what digest.

- Idempotency: the caller supplies a key; the journal replays the recorded
  outcome instead of re-executing. A retried write after a mid-sequence
  failure is safe and observable.
- Plan failure semantics: a write plan runs under `stopOnFirstFailure`;
  when step k fails, steps 1 to k-1 stand as journaled, the response is the
  mapped problem code naming the failed step's class, and replay with the
  same idempotency key resumes at the boundary. `continueAndReport` is not
  available for writes in v1.
- Batch acceptance (DHIS2 import summaries): success requires full
  acceptance; partial acceptance maps to a bounded 409 problem carrying the
  counts alone (imported, updated, ignored, rejected), never the raw
  upstream summary.
- Retry defaults differ by operation class: reads may auto-retry within the
  declared budget; writes are never auto-retried by the engine without the
  idempotency key (same-key resends use the platform's bounded
  keyed-mutation retry).
- Conflicts (DHIS2 import conflicts, GraphQL error arrays) map to bounded
  409 problem codes carrying translated detail, never the raw upstream body.
- No compensation and no rollback across upstream calls. Recovery is the
  source system's native process surface; the adapter reports exactly where
  a sequence stopped.
- Unknown upstream errors never leak: they surface as the bounded
  unmapped-upstream problem, and mapping totality is tested (section 13).

## 10. Authorization and secrets

Every facade call is authenticated (OIDC via the platform block) and
authorized by the adapter's own access profiles: named bindings of scopes to
facade operations and record types. The adapter inherits no authorization
from any product and grants none to any source. Upstream credentials live
only as `secret:` references in the runtime config, injected by the engine;
scripts, packs, diagnostics, and the audit journal never see them.

## 11. Audit and data minimization

The PostgreSQL journal records operation, caller identity, outcome, upstream
endpoints and paths, response sizes and digests, timings, and problem codes.
It records no bodies: no request payloads, no response payloads, no field
values. Retention follows the shared `audit.retentionDays` block.
Diagnostics are value-free (CFG-SEC-3); the conformance corpus marker test
proves it.

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

Two rules with consequences for packs:

- Code lives in its own file, referenced by relative path and pinned by
  digest (CFG-EMBED-1); no inline scripts.
- The universal 1 MiB document bound (CFG-YAML-6) applies, so the code-map
  member is designed so its content can move to a digest-pinned data file
  without a format change when a deployment's option sets outgrow it.

Increment 0 includes the platform change adding the `Adapter` prefix and
`adapter` product token to the conventions tables (CFG-ENV-2, CFG-ENV-3,
CFG-DIAG-3) and `products/platform/config-formats.yaml`.

## 13. Quality verification

### 13.1 Gates

- `products/adapter/scripts/check-contracts.sh`: `cargo fmt --check`,
  `cargo clippy` with `-D warnings` over the adapter crates, unit tests,
  schema regeneration drift, generated OpenAPI drift, CLI catalog
  regeneration when command trees change, fixture replay for every
  maintained pack, config-conventions lint and conformance corpus
  participation through the platform gate.
- `products/adapter/scripts/test-postgres.sh`: the journal suites (audit,
  idempotency, replay) on a disposable database with the `postgres-test`
  feature.
- Any change under `crates/registry-platform-*` also runs the platform
  gate and the gates of the products that consume the changed crate
  (Evidence at minimum); Evidence's Version 1 served behavior must not
  change.

### 13.2 Pack conformance: golden-fixture replay

Every maintained pack ships captured upstream exchanges (filled request
templates, upstream response bodies, statuses) with expected facade
responses. `adapterctl check` replays them offline: seam outputs validate
against the declared model, responses validate against the generated schema,
error fixtures must map to the expected problem codes. Each fixture records
the upstream version it was captured from; a pack declares its tested
versions; a fixture without provenance fails check.

### 13.3 Engine fault injection

An in-process upstream double (a scripted HTTP server) drives: timeouts,
connection resets, 5xx storms, malformed JSON, oversized bodies, slow
trickle, redirect attempts, and pagination sequences with duplicate or
shifting pages. These tests prove the ported semantics against their
declarations: retries honor `maximumAttempts` and the declared backoff; the
circuit breaker transitions CLOSED, OPEN, HALF_OPEN at the declared
thresholds; the throttler enforces the declared rate; exhausted exchanges
land in the journal with the terminal problem code.

### 13.4 Property tests

- Disclosure: no response escapes the declared model, across a generated
  corpus of packs and models.
- Idempotency: a replayed key produces the identical facade response and
  exactly one upstream effect, including under injected mid-sequence
  failure.
- Mapping totality: every declared upstream error class maps to a problem
  code; unknown upstream errors produce the bounded unmapped problem, never
  a leaked body.
- Pagination convergence: no duplicates or omissions across synthetic page
  sequences, including empty pages and page drift.
- Plan determinism: the same upstream transcript produces byte-identical
  facade responses.
- Budget exhaustion: exceeding calls, bytes, or the deadline yields the
  bounded problem with a complete journal and no partial response body.
- Step-failure replay: failure at step k journals steps 1 to k-1 as
  complete; same-key replay resumes at k with exactly one upstream effect
  per step.
- Iterate accounting: under `continueAndReport`, every item is accounted;
  under `stopOnFirstFailure`, the response names the failing item's bounded
  class without values.

### 13.5 Contract tests

The runtime serves exactly the generated OpenAPI: every documented route
answers, every undocumented route is refused. Record v1 responses match
`registry-record` serialization goldens and the shape of BReg's generated
per-package OpenAPI examples (`products/breg/generated/`).

### 13.6 Security tests

Egress allowlist: any call outside the declared base is refused and
journaled, including redirects. Private-address upstreams are expected, not
blocked: government DHIS2 and OpenCRVS instances sit on internal networks.
The platform's fixed-destination policy already decides this correctly;
private CIDRs are reachable only when the runtime config declares them
explicitly (`allowedPrivateCidrs`, bounded count), and plain HTTP stays
confined to those addresses. Secrets never appear in scripts,
diagnostics, or audit. Script budgets terminate runaway loops. Response size caps are
enforced. Diagnostics are value-free, asserted by the corpus marker.

### 13.7 Quality attributes

- Translation overhead: p99 at or under 20 ms excluding upstream time,
  measured in paired before/after local runs; local numbers are directional
  only and never cited as evidence.
- Memory bounded by `maximumResponseBytes` and aggregation caps.
- Observability: per-operation structured metrics (mapped and unmapped
  errors, retries, breaker state) and a queryable audit journal.

Definition of done for this section: every gate in 13.1 exists and is green;
the dhis2-tracker pack's fixture suite replays clean at check time; every
property test in 13.4 runs in the default test suite; the security tests in
13.6 are wired into `check-contracts.sh`.

## 14. Delivery increments

- Increment 0: platform token change; format registration and generated
  schemas; `registry-adapter-core` model; `adapterctl check` skeleton; corpus
  minimal examples; this product's row in the repository map and routing
  list.
- Increment 1: runtime serving `breg-records` v1 reads through the
  `dhis2-tracker` pack; generated OpenAPI; audit journal; fixture suite;
  gates from 13.1. A platform workstream lands the read-class redelivery
  executor and the circuit breaker in `registry-platform-httputil`
  additively, preserving Evidence's behavior and rerunning its gates.
- Increment 2: writes (create, update) with the idempotency journal and
  conflict mapping, against DHIS2.
- Increment 3: the `opencrvs` pack on the `graphql` envelope, reads first,
  then writes.
- Later: the GovStack profile and conformance mode; the WASM executor rung
  when a real pack needs it.

Global definition of done: an adopter with a DHIS2 instance and a project
file can serve Record v1 reads and writes through the adapter, with the
generated OpenAPI, a green `adapterctl check`, replayed fixtures, and the
journal answering every query section 11 promises.

## 15. Credit and licensing

The exchange model, pattern vocabulary, and error-handling semantics follow
Apache Camel (Apache License 2.0) and the Enterprise Integration Patterns
vocabulary of Hohpe and Woolf; the config-first facade over legacy health
systems follows the OpenHIE interoperability layer tradition; connector
manifest versioning follows the Airbyte and Singer practice. The Rust
precedent consulted is rust-camel (Apache 2.0, pre-release): its
Tower-native rendering of EIP patterns, its retry policy shape (backoff with
bounded jitter), and its error dispositions inform sections 8 and 9. It is
not a dependency: it is a general-purpose route framework with code-first
components, where this product is a bounded facade whose system knowledge is
configuration. No Camel code
is copied in v1 (it is Java); if documentation text or tables are ever
lifted, the Camel LICENSE and NOTICE ship beside it, and the product
documentation credits Camel and the EIP book regardless.

## 16. Recorded decisions

| ID | Decision | Date, status |
|---|---|---|
| D1 | Facade is the `breg-records` v1 profile artifact, parameterized by the declared model; GovStack later as a second profile | 2026-10-30, accepted |
| D2 | Packs and profiles are maintained artifacts under `products/adapter/` | 2026-10-30, accepted |
| D3 | v1 scope is reads plus DHIS2 writes; OpenCRVS writes follow as their own increment | 2026-10-30, accepted |
| D4 | Source-native identifiers pass through; no correlation store in v1 | 2026-10-30, accepted |
| D5 | Product name and token: `Adapter`, `adapter` (`AdapterPack`, `AdapterProject`, `AdapterRuntimeConfig`, `adapter.*` codes) | 2026-10-30, accepted |
| D6 | The generated OpenAPI contains only bound operations; a conformance mode arrives with the GovStack profile | 2026-10-30, accepted |
