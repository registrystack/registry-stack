# Adapter Delivery Plan

Status: active. Revised 2026-10-30 for the Camel port (`CONCEPT.md` D7 to
D15) and again that day for the exchange contract (`CONCEPT.md` 8.11, D20
to D28), which the first API transformation experiments showed the
Increment 1 runtime could not be designed without. Revised 2026-10-31 for
current engine semantics and lead-owned orchestration. Companion to
`CONCEPT.md`: the concept is the product contract; this
file decomposes its section 14 into parallel workstreams with definitions of
done and runnable acceptance commands. On any conflict, `CONCEPT.md` wins.

The scope is the full port table in `CONCEPT.md` section 8.10, every row,
whether or not a maintained pack uses it today (Jeremi's ruling: the engine
is a reusable integration piece). No stream shrinks a row to what a pack
needs; a row that cannot land says so in its report.

## Rules every agent works under

Every brief carries these rules by reference; they are not optional.

1. The current lead owns integration and may delegate bounded work to its
   own agents only. Each brief assigns disjoint paths; delegated agents do
   not spawn agents, and parallel agents never edit the same file.
2. Worktree: `/Users/jeremi/orca/workspaces/registry-stack/live-adapter`.
    Absolute paths only; never `cd`. First command: verify
    `git -C /Users/jeremi/orca/workspaces/registry-stack/live-adapter
    --no-optional-locks rev-parse HEAD` equals the SHA in your brief; if it
    differs, stop and report.
3. Never push, merge, rebase, tag, reset, stash, `checkout --`, or clean.
    Commit with plain `git commit -m ...`: this machine's commit-msg hook
    appends the DCO `Signed-off-by` trailer automatically. Never type that
    trailer yourself, never add agent attribution trailers, and never set
    author or committer to an agent. After your first commit, run
    `git --no-optional-locks log -1 --format=%B | rg 'Signed-off-by'` and
    confirm exactly one such line; if there is none, amend with
    `git commit --amend --no-edit -s`. Conventional subjects, imperative
    mood: `feat(adapter):`, `test(adapter):`, `chore(adapter):`, or the
    owning area's prefix (`feat(platform):` for `products/platform`).
4. Delete nothing outside `products/adapter/scratch/<your-stream>/`. Treat
    modified and untracked files you did not create as another session's
    work; never revert or reformat them.
5. Cargo always runs as:
   `CARGO_TARGET_DIR=<target-dir> PATH="$HOME/.cargo/bin:$PATH" cargo ...`
   Never clean a target directory another agent builds in. Concurrent
   cargo runs serialize on the target lock; wait, never kill.
6. Shared files (root `Cargo.toml`, `Cargo.lock` dependency additions,
   `deny.toml`, `rust-toolchain.toml`, root `AGENTS.md`, `.github/**`, and
   each crate's `lib.rs` module list) change only in a wave's scaffold step
   or by the integration stream at a wave boundary. If your stream needs a
   change there mid-wave, stop and report it instead of editing.
7. TDD: write the failing test first; write only enough code to pass;
   refactor while green. Test output must be clean; expected errors are
   captured and asserted on, never printed past.
8. Verification floor, reported verbatim with failures included:
   `cargo fmt --check`; `cargo clippy -p <owned crates> --all-targets --
   -D warnings`; `cargo test -p <owned crates> --locked`.
9. Report what landed and what did not. No stubs of promised behavior; if
   scope must shrink, the report says so, not the silence.
10. Never log secrets or environment dumps. All adapter diagnostics are
    value-free (`adapter.*` codes, CFG-SEC-3).
11. Port, do not invent. Before writing a port-table row, open its Camel
    page (and the resilience4j page for the breaker), and write the
    conformance cases from what the page says: option names, defaults,
    exchange properties, matching and ordering rules. Each case's doc
    comment cites the page URL. If the page contradicts `CONCEPT.md`, the
    report says so and the stream follows the page for semantics and
    `CONCEPT.md` for spelling and divergences; the integration stream
    corrects the concept. Never write a default from memory.
    The pinned reference (`CONCEPT.md` 5.4) is a read-only shallow clone of
    tag `camel-4.23.0` at
    `/Volumes/CodexWorktrees/agent-scratch/camel-src/camel-4.23.0`; never
    edit, build, or commit from it, and never copy it into the repository.
    Where the page is silent, ambiguous, or gone, read the implementing
    Java there and cite it (`camel-4.23.0:<path>`). Rows where this is
    mandatory, because the semantics live in code: error handler and
    redelivery (`RedeliveryErrorHandler`, `RedeliveryPolicy`), exception
    clauses (`DefaultExceptionPolicyStrategy`), try/catch/finally, circuit
    breaker, throttle, split, loop, enrich, aggregation strategies,
    `direct` (`DirectProducer`), `http` failure handling
    (`HttpOperationFailedException`), the header filter
    (`HttpHeaderFilterStrategy`), mock and intercept (`MockEndpoint`,
    `InterceptSendToEndpointDefinition`), and the idempotent consumer.
    For each such row, the stream lists the Camel unit tests under the
    clone that exercise it and ports each one as a conformance case, or
    records why it does not apply (outside the port's boundaries, or a
    recorded divergence). Read the Java for behavior and write idiomatic
    Rust; never translate it line by line.

## Wave model and review protocol

Waves run sequentially. The current lead may run a bounded set of streams in
parallel only on disjoint paths, and reviews every hand-back before
integration. Each increment opens with a serial scaffold step (module roots
and dependency additions), so parallel streams never touch a shared file.
The lead captures the HEAD SHA at wave launch, carries it in every brief,
closes the integration stream, runs the acceptance commands, records open
findings, and makes the go or stop decision for the next wave.

At every increment the lead assigns an independent staff-engineer review of
the integrated diff against `CONCEPT.md` to a fresh agent that owns no
concurrent edit path: is it still a faithful Camel port, is the architecture
holding up for the next increment, and what should change in the plan. The
lead resolves that feedback before the next increment and records the report
as `products/adapter/reviews/increment-<n>-staff.md`. Blockers and any
`CONCEPT.md` contradiction go directly to the lead as they happen; Jeremi's
fresh decisions remain authoritative.

## API transformation experiments (before Increment 1, after it, after 3)

The first run happened on the Increment 0 model, before any runtime: five
experiments (FHIR R4 search and conditional create, GraphQL cursor paging,
REST offset paging over mTLS with `private_key_jwt`, and a FHIR-shaped
second target profile) all passed `check` and still could not have run.
Their eight P0 gaps became `CONCEPT.md` 8.11; their check defects became
Increment 0's closing round; their P1 gaps are assigned to Increment 1
streams below. `products/adapter/experiments/FINDINGS.md` holds the record.
The experiments are rerun after Increment 1, migrated to 8.11, and after
Increment 3.

Owned by the lead, under `products/adapter/experiments/**`, no
`.rs` file. Each experiment is a pack, a profile, a project, and
`documented` fixtures served over the upstream double, chosen to stress the
engine on API shapes the two maintained packs do not cover:

- Sources: cursor pagination, offset and page-number pagination, a nested
  resource needing `enrich` per item, code lists needing conversion,
  partial failures inside a `split`, a source that returns 200 with an error
  body, a FHIR R4 source (Bundle paging over `link[relation=next]`,
  conditional create as `idempotentUpstream`), a GraphQL source (after
  Increment 3).
- Targets: `breg-records` v1, the 13.6 test profile, a POST-search profile
  with a query body, a FHIR R4 profile (searchset Bundle with links and
  totals, `OperationOutcome` problems).
- Upstream authentication: across the set, every kind of `CONCEPT.md` 10.2
  at least once (`static-api-key`, both OAuth2 kinds, mTLS with `none`),
  so the maintained packs and the experiments together cover all six.

Each experiment records what it needed: when one cannot be expressed
without Rust, or only awkwardly, the finding is a port-table gap or a
divergence to revisit, fed back into the plan. Results summarize in
`products/adapter/experiments/FINDINGS.md`. Candidate components beyond the
port table, ranked, are in `products/adapter/COMPONENT-CANDIDATES.md`; an
experiment that forces one of them records it there.

## Takeover

When Increment 3 closes (or the program stops earlier), the lead runs every
acceptance command and the final multi-expert review, fixes the remaining
findings directly, and writes the report to Jeremi.

## Increment 0: formats and the route model

### Wave 0, S0: scaffold (done)

Landed: the crate trio, workspace members, `products/adapter/AGENTS.md`,
`check-contracts.sh` v0, root `AGENTS.md` routing, CI shard. The revised
concept moves `test-postgres.sh` to Increment 1 and replaces the call-plan
vocabulary; the doc commit that carries this plan updates
`products/adapter/AGENTS.md` to match.

### Wave 1 (parallel)

**A1, core model**, owns `crates/registry-adapter-core/**`.
Reader types (serde, `deny_unknown_fields`, externally tagged step union
per CFG-ID-7) for: `AdapterProfile` (operations, request and response
envelope templates over the closed slot vocabulary of `CONCEPT.md` 7,
pagination parameters, problem envelope and codes); `AdapterPack` (endpoints with
component kind, the `authentication` kind of `CONCEPT.md` 10.2 (six kinds,
fields and spelling copied from Evidence's `SourceAuthentication`, read it,
do not depend on it), declared response headers, `idempotentUpstream`
per operation, tested versions; `routeTemplates` with typed parameters;
internal `routes`; code maps; script and query-file references with digest
pins; required capabilities); `AdapterProject` (record types and fields,
pinned pack and profile references, `templatedRoutes`, bindings, access
profiles); `AdapterRuntimeConfig` (per-endpoint base URL, credential
`secret:` references matching the endpoint's kind, token endpoint, optional
CA bundle and mTLS identity); `AdapterFixture` with provenance
(`kind: captured | documented`, `upstreamVersion`, `reference`). The step
union covers every port-table row in `CONCEPT.md` 8.10 for Increments 0 to
3, including `idempotentConsumer` and the `graphql` endpoint kind, so the
format does not change later. The error-class hierarchy and the
uncatchable set from `CONCEPT.md` 8.7; `adapter.*` problem codes.
Pure checks on parsed values (no I/O): reference resolution, template
instantiation with typed parameter checking and `{{name}}` / `{{?name}}`
resolution, acyclic `direct:` graph with bounded depth, mandatory
`maximumItems` and `maximumIterations`, static worst-case upstream call
count per bound operation against `maximumUpstreamCalls`, write-safety
(redelivery over a non-safe send without `idempotentUpstream`; non-safe
`to` inside `split` without `stopOnException: true`; write route without
`idempotentConsumer`; more than one non-safe send in a write route until
Increment 3), refusal of `onException`/`doCatch` naming an uncatchable
class, digest-pin shape, envelope-name validity, profile envelope checks
(unknown slot, missing result slot, problem envelope without its code
slot), authentication checks (runtime credentials match the endpoint kind,
`none` only on loopback or with an mTLS identity, reserved `headerName`
refused). No type or check names a `breg-records` path, operation, or field.

DoD: accept and reject unit tests for every check asserting `adapter.*`
codes, not prose; a round-trip test per step variant; verification floor
green; dependencies minimal.

**A2, platform registration**, owns `products/platform/**`.
`Adapter` envelope prefix and `adapter` product token in
CONFIG-CONVENTIONS.md (CFG-ENV-2, CFG-ENV-3, CFG-DIAG-3); the five format
kinds in `config-formats.yaml`; the CFG-EMBED-1 amendment admitting inline
RFC 9535 JSONPath selectors as queries, beside inline regular expressions,
with the reasoning in `CONCEPT.md` 8.5. Follow `products/platform/AGENTS.md`
for its checks.

DoD: the platform product's gates green; five kinds registered; tables and
the amendment present.

### Wave 2 (parallel; needs A1 and A2)

**B1, check tooling**, owns `crates/registry-adapterctl/**` and
`products/adapter/{schemas,scripts/check-port-table.py}`.
`adapterctl check` (envelope, file reads and digest verification,
template instantiation, A1's checks, Rhai entrypoints precompiled through
`registry-platform-script`, fixture provenance presence, fixture response
validation against the generated schema); generated schemas under
`products/adapter/schemas/` with a drift check; `check-port-table.py`
parsing `CONCEPT.md` 8.10 (fails when a delivered row's conformance module
is missing or empty, when a step or component key A1 accepts has no row,
or when a row's Camel reference is not a camel.apache.org path); clap tree
and `cargo run --locked -p registry-cli-docs -- --write`.

DoD: check accepts the good corpus and refuses every bad corpus member with
the exact code; schema drift gate green; CLI catalog snapshot green;
`check-port-table.py` runs and reports Increment 1 rows as pending, not
passing.

**B2, authored artifacts**, owns
`products/adapter/{profiles,packs,examples,fixtures}/**`.
`breg-records` v1 profile (operations, Record v1 envelope templates,
pagination parameters, problem envelope and codes); a second test profile
under the corpus with different paths, envelope, and pagination names
(`CONCEPT.md` 13.6); the
`dhis2-tracker` pack as route templates: search with pagination as `loop`
plus `enrich` with `json-array-append` and `uniqueBy`, get with `choice` and
a Rhai seam in its own digest-pinned file, code maps, `onException`
clauses mapping DHIS2 errors to profile problems; an example project
instantiating the templates; a bad corpus (one member per A1 check);
read fixtures with `kind: documented`, the DHIS2 version, and the
documentation URL (no fixture claims capture unless captured from a running
instance, which this stream may do with a local `dhis2/core` container if
it fits the time box; report which).

DoD: envelopes per A2; no inline scripts; every fixture has provenance;
the pack uses only port-table constructs.

### Wave 3, integration (single stream)

Owns cross-cutting wiring: `check-contracts.sh` gains schema drift,
`check-port-table.py`, fixture check, corpus participation; reconciles B1
and B2; corrects `CONCEPT.md` where rule 11 found a contradiction; writes
`products/adapter/reviews/increment-0.md` after the independent review.

DoD: `check-contracts.sh` green from a clean shell; report lists every gate
result verbatim.

### Closing rounds (staff review)

Increment 0 closes when the lead's staff-review rounds have
landed, recorded in `products/adapter/reviews/increment-0-staff.md`. The
last round carries the experiments' check defects (FINDINGS.md C1 to C23,
O8, O9), split by owner:

- A1 (core): header writes and reads bounded, credential and hop-by-hop
  headers refused on `setHeader` (C3, security); `tokenEndpoint` parsed as
  an https URL, loopback http only (C13, security); origin-relative static
  `path` (C1, C17); every `path` placeholder bound and every binding used
  (C12); `okStatusCodeRange` grammar (C2); apiKey `headerName` a token and
  not reserved (C10); no http parameters on `graphql:` (C11); GraphQL
  safety from the operation type (C19); envelope literals constrain the
  result schema (C16); envelope parse errors and the fixture body check
  (C15); one finding per defect and full pointers (C6, C7); the core halves
  of C8 and C9; problem codes inside the profile (C14).
- B1 (ctl): script parse errors and missing entrypoints in every slot (C8);
  query-file parse and `operationName` declared (C9); schema drift (C22).
- B2 (artifacts): the `dhis2-tracker` pack respelled to the kebab classes
  (C23); `shape-records.rhai` self-contained (O8); only a 404 maps to
  not-found on the read (O9); corpus members for C3 and C13.

C18 (a problem body built in a fallback passes as a success) and C20 (a
FHIR `POST _search` counts as a write) are resolved by 8.11.6 and the
`safeUpstream` claim, and land in Increment 1 stream X1.

## Increment 1: the read engine

### Wave 0, scaffold (serial)

Creates the runtime module roots named in `CONCEPT.md` 8.1 (`exchange`,
`route`, `processor/*` one file per EIP, `component/{direct,http,rest}`,
`language`, `errorhandler`, `notifier`, `idempotent`) with module docs and
no logic; adds dependencies (RFC 9535 JSONPath crate after `cargo deny
check`, PostgreSQL driver matching the workspace's, platform crates);
`products/adapter/scripts/test-postgres.sh` skeleton that starts and removes
its own loopback PostgreSQL 17 container when `ADAPTER_TEST_DATABASE_URL`
is absent; root `AGENTS.md` and `products/adapter/AGENTS.md` gate rows. The
AEAD for the continuation cursor (8.11.2) is one already in the workspace
(`aws-lc-rs` AES-256-GCM, or `chacha20poly1305` as BReg uses), chosen here
with the reason recorded.

### Wave 0b, the exchange contract in the format (serial: X1, then X2)

The runtime streams build against these types, so they land first.

**X1, contract model and checks**, owns `crates/registry-adapter-core/**`.
Reader types and pure checks for `CONCEPT.md` 8.11: the profile's
`problems` list (`code`, `status`, `title`, `classes`) replacing
`problemCodes`, with the totality check (every class resolves to exactly
one problem, by closest match, uncatchable and facade classes included);
the `outcome` and `facade` class branches; the `throwException` step
(`exceptionType` catchable, `message` constant and bounded); `httpUri` on
`http` sends (exactly one of `path` and `httpUri`, no `query` beside it);
the endpoint's `requestHeaders` allowlist and its never-allowlistable set;
the `safeUpstream` operation claim, `POST` only, feeding write safety (C20);
the read-only facade inputs of 8.11.1 (refusing writes to them except
`AdapterNextContinuation`) and the header-read bound of 8.11.4; the
singular-query predicate rule of 8.11.8; runtime config `cursorKeyRef`,
`previousCursorKeyRef`, `cursorTtlSeconds`; and the P1 format gaps:
`recordException` and `ignoreException` on `circuitBreaker`
(G-BREAKERCLASS, resilience4j names), per-endpoint `attemptTimeoutMilliseconds`
and `maximumResponseBytes` (G-TIMEOUT, CFG-NAME-5 spelling, Evidence bounds,
required, the runtime may only lower them), the Evidence-shaped trust
profile (`outboundTls.trustProfiles.<id>.caBundleFile`, endpoint
`tlsTrustProfile`) that the token request shares with its endpoint
(G-TOKENTLS, section 10.2), the facade classes
`facade.unsupported-media-type` and `facade.not-acceptable`, Evidence's
auth field bounds (section 10.2), the refusal of an `okStatusCodeRange`
covering 401 on an authenticated endpoint, `maximumIterations`
as a typed template parameter and `maximumTotal` checked against the loop
bound (G-BOUNDS). DoD as A1's, plus an accept and a reject unit test per
new check asserting its `adapter.*` code.

**X2, contract tooling and artifacts**, owns `crates/registry-adapterctl/**`
and `products/adapter/{schemas,profiles,packs,examples,fixtures}/**`.
The per-file script call check of 8.11.3; schema regeneration; both
profiles gain `problems`; the `dhis2-tracker` pack drops every
profile-shaped problem body and `CamelHttpResponseCode` write in favor of
`throwException` with `outcome.*` classes (C18), and its search route sets
`AdapterNextContinuation`; corpus members for every new check. DoD: the
pack names no profile problem code (acceptance 9 below); check accepts the
good corpus and refuses each new bad member with its code.

**From the Increment 0 staff review Part 2** (`reviews/increment-0-staff.md`),
closed inside Wave 0b rather than as a separate Increment 0 round:

- X1: the AggregationStrategy wire form and a test validating every
  maintained pack, example, and experiment against its schema (F1); no
  cascading finding after a primary fault (F4, corpus co-firing); a read
  operation reaches only safe sends (F5, CONCEPT 8.8); `retryWhile` moved
  to `onException` and the error handler, continuing while true (F7,
  CONCEPT 8.7); filter `statusPropertyName`; the `LoopStep` doc (F8);
  pointers keep the step-kind segment (F9); bracketed IPv6 loopback (F10);
  the remaining path and origin refusals (F11); credential headers refused
  in `setHeader` and `removeHeader` (F12); `okStatusCodeRange` `http` only,
  with Camel's grammar (F13); the corrected exception reasons (F1, F14); the
  G3 convert steps and code-map checks (CONCEPT 8.6).
- X2, after C9 lands: the plain `adapterctl check <project-dir>` form (F4
  item 2); corpus members for the four coverage gaps and every X1 check;
  the dhis2 scripts on the 8.11.3 ABI with 404 and 500 replay fixtures
  (F6); the code-map pack rewrite.
- **W0, contracts gate**, owns the adapter job in `.github/workflows/ci.yml`
  and `products/adapter/scripts/check-contracts.sh`: the CI job, and a
  `check-contracts.sh` that runs the conventions lint, the port-table check,
  the example check, fixture replay, and an exact-code corpus run (each bad
  member yields exactly its own code, members discovered, not listed) (F3,
  F4 item 3).
- Wave 1 streams whose files do not overlap `registry-adapter-core` (the
  language module, the journal) may start beside X1; they take the core
  types as they stand and adapt when X1 lands. Read-only Camel unit-test
  inventories for the source-bound rows may run at any time.

### Wave 1 (parallel, disjoint modules)

Order (D29, D31): the streams below pause once C4a and C4c land. `records-get`
is built end to end first, over the real exchange, route interpreter, egress,
and facade, so seams surface before the leaves multiply. The leaves then
resume over that route. C6's `circuitBreaker` and `throttle` are the last
slice of the increment, on the platform primitives of D13.

- **C1, exchange and core EIPs**, owns `src/{exchange,route,language}/**`,
  `src/processor/{to,set_body,transform,set_header,set_property,remove_header,remove_property,script,choice,filter,validate,stop,throw_exception}.rs`,
  and `tests/camel_{exchange,message,routes,languages,to,set_body,transform,headers_properties,script,choice,filter,validate,stop,throw_exception}.rs`:
  the script ABI of 8.11.3 (exchange view, JSON mapping, per-slot returns),
  the JSONPath result rule of 8.11.8, and the read-only facade inputs.
- **C2, splitting, aggregation, conversion**, owns
  `src/processor/{split,loop,enrich}.rs`, `src/processor/aggregation/**`,
  code-map conversion, and `tests/camel_{split,loop,enrich,aggregation,type_converter}.rs`:
  `enrich` on a copy with strategy-named `properties` (8.11.7), and `loop`'s
  `doWhile` timing and `copy` semantics from the Camel page (G-LOOPTIMING).
- **C3, error handling and resilience**, owns `src/errorhandler/**`,
  `src/processor/{do_try,circuit_breaker,throttle}.rs`, and
  `tests/camel_{error_handler,redelivery,exception_clause,try_catch_finally,circuit_breaker,throttle}.rs`:
  the clause semantics of 8.7 and 8.11.6 (a handled clause answers with a
  success body; `throwException` inside a clause ends the exchange; an
  uncatchable `RouteFailure` class fires no clause), `direct:` error propagation
  without redelivery (8.11.7), the class-to-problem resolution, and the
  breaker's `recordException` and `ignoreException`.
- **C4, components and facade**, owns `src/component/**`, `src/http/**`,
  `src/auth/**`, the upstream double under `tests/support/upstream/**`, and
  `tests/camel_{direct,http,rest_dsl,header_filter}.rs`: `direct`, `http` on
  `FixedDestinationPolicy`, the `rest` consumer on `registry-platform-httpsec`
  with OIDC and access profiles, filling the profile's envelope templates;
  `src/auth/**` carries all six upstream kinds of `CONCEPT.md` 10.2 with
  the token cache, the single refresh after a 401, `credential.rejected`,
  and mTLS identity, plus `tests/camel_http_authentication.rs` with one
  module per kind against a double token endpoint, and a marker secret
  asserted absent from journal, diagnostics, and replay output. The same
  stream owns the facade inputs of 8.11.1, the continuation codec of 8.11.2
  (`src/component/rest/continuation.rs`, `tests/adapter_continuation.rs`:
  tamper, expiry, other caller, other filters, key rotation), the header
  allowlists of 8.11.4, `httpUri` pinning of 8.11.5
  (`tests/camel_http_uri.rs`), the JSON media types, and the per-endpoint
  timeouts. Security-sensitive: the report carries review notes for the
  codec and the header filter.
- **C5, journal**, owns `src/notifier/**`, migrations, `tests/camel_event_notifier.rs`,
  and the PostgreSQL suite: event kinds from `CONCEPT.md` 11, value-free,
  written before the response; retention.
- **C6, compile and replay tooling**, owns `crates/registry-adapterctl/src/{compile,fixtures,verify}/**`,
  the `AdapterFixture` format change, and `tests/camel_testing.rs`: the
  fixture format carries what replay needs (G-FIXTURES: the facade request,
  several upstream exchanges per entry in order, request and response
  headers, JSON `null`, an expected problem by class and code); `adapterctl compile` (byte-stable OpenAPI
  into the built package, composed from the profile's envelopes and the
  declared model; the `breg-records` output checked against
  `registry-record` goldens (dev-dependency) and `products/breg/generated/`),
  `fixtures replay` (intercept and skip semantics), `verify --live` (tested
  against the double; a live DHIS2 run is Jeremi's optional step).

Each C stream ports its rows completely, every option and default the
Camel page documents within the port's boundaries, with conformance cases
per rule 11.

### Wave 2, integration

Wires C1 to C6 into one engine; dhis2-tracker search and get end to end
over the double and by replay, under both the `breg-records` profile and
the test profile, with an identical pack (errors included); fault injection
(13.4), read property tests (13.5), contract tests (13.6), security tests
(13.7) in the default suite; `check-port-table.py` now requires every
Increment 1 row; review report. Then the lead migrates the
experiments to 8.11 and reruns them, executed and not only checked: each
experiment's fixtures replay through the engine, and each read experiment
runs over HTTP against the upstream double through the compiled package.
A gap that still needs Rust, or an experiment that passes `check` but
fails to execute, is a finding against this increment, and Increment 1 is
not done while one is open.

Captured proof (D30): the increment's gate requires `kind: captured` DHIS2
fixtures for get, missing, and search page, taken from a real server by the
lead, scrubbed of hostnames, credentials, and personal data before they reach
a stream or the repository. `records-get` also runs once against that server,
from a local run that holds the credentials and commits nothing.

P1 gaps from the first experiments not owned above, with their
disposition: G-IDEMCLAIM (an `idempotentUpstream` or `safeUpstream` claim
needs a comment citing its source documentation, enforced by review, not
by `check`); G-COMPARE (no comparison language: Simple stays not ported,
a status or value comparison is a one-line `rhai` predicate; revisited if
the reruns show it in most packs); G-LOOPCLASS (resolved in 8.7);
G-CONTENTTYPE (resolved in 8.11.8, built by C4).

## Increment 2: writes

Scaffold: none needed beyond migrations, which D1 owns.

- **D1, idempotent consumer**, owns `src/idempotent/**`, its migrations,
  `src/processor/idempotent_consumer.rs`, `tests/camel_idempotent_consumer.rs`:
  Camel's options and defaults, our divergences (`CONCEPT.md` 9), the
  PostgreSQL store with retention sweep, replay, in-flight 409, digest
  mismatch 422; security review note on D12.
- **D2, DHIS2 writes**, owns pack, example, and fixture files for create and
  update: import summary via `choice` and `validate`, partial acceptance 409
  with counts only, conflict mapping via `onException`, `documented` write
  fixtures. No `.rs` change.
- Integration: write property tests (idempotency, mapping totality), write
  security tests, write-safety refusals live, review report.

The DHIS2 write route must carry the record: `to-bundle.rhai` sends
`attributes: []` today, and on 2.43.2.1 that keeps every existing attribute value,
so an import writes no attribute data. This increment maps attributes from the
record, and captures a create and an attribute change from the real server. The
deployment's account must reach a program of the entity's type: without that a
create answers 200, a repeat 409 E1323, and a read 404.

D16 is decided: an accepted but incomplete write answers a 202 with a status
link or a bounded wait, chosen by configuration. This increment implements
both, with their keys, the bound's expiry, and tests; until then such a route
is refused.

## Increment 3: the second system

Pre-launch check (lead, before any stream): confirm from current
OpenCRVS documentation which API the current release exposes for reads and
registration (GraphQL gateway or REST events API) and how an integration
client authenticates (which `CONCEPT.md` 10.2 kind; if its token endpoint
needs credentials in the query string, that is a finding, not an engine
change), and send the finding to
the lead before launching.

- **E1, graphql component** (if OpenCRVS is GraphQL), owns
  `src/component/graphql.rs`, `tests/camel_graphql.rs`; its own commit.
- **E2, write resume**, owns resume bindings in core and runtime and the
  resume property test; its own commit; port-table entry added as an
  addition.
- **E3, opencrvs pack**, owns `products/adapter/packs/opencrvs/**`, its
  example and fixtures: reads, then draft and declare writes. Its commits
  change no `.rs` file.
- **E4, facade contract as OpenAPI** (D35), starts only after the real proof
  of person-get, person-search, and person-create: a closed OpenAPI subset
  with `x-` extensions for slots and problems replaces `AdapterProfile`, tried
  first against a real ministry or GovStack specification. If that attempt
  needs heavy extensions, E4 stops and the result goes to Jeremi.
- Integration: both packs' example projects served by one binary; review
  report; final multi-expert review (security, Camel semantics, contracts,
  data minimization) recorded as `products/adapter/reviews/final.md`.

## Platform rules

- Generic mechanism with no product semantics goes into a platform crate from
  the start when that costs little (D13): the rolling-window limiter in
  `registry-platform-ratelimit`, the breaker state machine and redelivery delay
  computation in `registry-platform-resilience`. The processors and the
  redelivery loop stay in the adapter.
- Every other platform edit is A2's registration and amendment in
  `products/platform/**` or an additive constructor accepted in review. No
  Evidence crate changes.

## Brief template

```
Stream: <id>, Increment <n>, Wave <m>
Worktree: /Users/jeremi/orca/workspaces/registry-stack/live-adapter
Expected HEAD: <sha captured at launch>
You own these paths (create or edit only these): <paths>
Read first: products/adapter/CONCEPT.md sections <s> and the port-table
rows <rows>; this plan's rules and your stream DoD.
Task: <one-paragraph scope>
Rules: the eleven rules in products/adapter/DELIVERY-PLAN.md "Rules every
agent works under", all of them.
DoD: <stream DoD, copied>
Report: what landed, what did not, gate output verbatim, every Camel page
you cited and any contradiction with CONCEPT.md, any shared-file need you
stopped on.
```

## Increment acceptance (runnable, from the worktree root)

`CARGO` below abbreviates
`CARGO_TARGET_DIR=<target-dir> PATH="$HOME/.cargo/bin:$PATH" cargo`.

Increment 0:

1. `products/adapter/scripts/check-contracts.sh` exits 0.
2. `CARGO run --locked -p registry-adapterctl -- check products/adapter/examples/dhis2-tracker/project.yaml
   --profile products/adapter/profiles/breg-records/profile.yaml
   --pack products/adapter/packs/dhis2-tracker/pack.yaml`
   exits 0 with a value-free report (the integration report names the
   exact path if it differs).
3. Each bad corpus member fails `check` with exactly its expected code and
   no other (driven by `check-contracts.sh`, members discovered).
4. `python3 products/adapter/scripts/check-port-table.py` exits 0.
5. `git --no-optional-locks log --format='%H %s' origin/main..HEAD` shows
   conventional subjects; every commit body has exactly one DCO trailer and
   no agent attribution trailer.
6. `CARGO check --locked --workspace --all-targets`,
   `python3 .github/scripts/test_ci_changes.py`, and
   `products/platform/scripts/run-config-conformance.sh --strict` exit 0;
   any expected failure carries a written reason.
7. `CARGO run --locked -p registry-adapterctl -- schemas --check` exits 0.
8. Every closing-round item above is fixed or listed open in
   `products/adapter/reviews/increment-0-staff.md`.

Increment 1:

1. Increment 0's commands still pass.
2. `products/adapter/scripts/test-postgres.sh` exits 0 and reports a
   nonzero number of journal tests run.
3. `CARGO test --locked -p registry-adapter` includes every
   `camel_*` module for Increment 1 rows, the fault-injection suite, and
   the end-to-end reads over the double.
4. `CARGO run --locked -p registry-adapterctl -- compile <example project>`
   twice yields byte-identical `openapi.json`.
5. `CARGO run --locked -p registry-cli-docs -- --check` (or the snapshot
   test) passes; `CARGO clippy --workspace --all-targets -- -D warnings`
   exits 0.
6. `rg -n 'records\.(search|get|create|update|patch)|/v1/records' crates/registry-adapter*/src`
   prints nothing (the target API lives in profile files only), and
   `cargo tree -p registry-adapter -e normal | rg registry-record` prints
   nothing (dev-dependency only).
7. `CARGO test --locked -p registry-adapter --test camel_http_authentication`
   runs a nonzero number of tests covering each of the six kinds.
8. `CARGO test --locked -p registry-adapter --test adapter_continuation`
   and `--test camel_http_uri` run a nonzero number of tests.
9. `rg -n 'CamelHttpResponseCode|source\.(not-found|unavailable|upstream-error|write-rejected|write-partial)' products/adapter/packs`
   prints no `setHeader` of the response code and no profile problem code
   (packs raise classes; profiles own problems).
10. For every experiment under `products/adapter/experiments/`,
    `adapterctl check`, `adapterctl fixtures replay`, and
    `adapterctl verify --live` against the upstream double each exit 0, and
    `FINDINGS.md` carries the executed rerun with each command's output.
11. Every conformance module for a row listed in rule 11 as source-bound
    cites at least one `camel-4.23.0:` path:
    `rg --files-without-match 'camel-4\.23\.0:' crates/registry-adapter/tests/camel_{error_handler,redelivery,exception_clause,try_catch_finally,circuit_breaker,throttle,split,loop,enrich,aggregation,direct,http,header_filter,testing}.rs`
    prints nothing.
12. Every normal dependency of `registry-adapter` is referenced by its code
    (no dependency added ahead of use survives the increment).

Increment 2:

1. Increments 0 and 1 commands still pass.
2. `test-postgres.sh` includes the idempotency store, replay, and sweep
   suites.
3. Write fixtures replay in `check-contracts.sh`.
4. `git --no-optional-locks diff --name-only <first D2 commit>^ <last D2 commit> | rg '\.rs$'`
   prints nothing.

Increment 3:

1. All earlier commands still pass.
2. `check` and replay pass for the `opencrvs` example.
3. The no-Rust diff check passes for the E3 commits.
4. `products/adapter/reviews/final.md` exists, and each finding is fixed
   or listed open.

Global definition of done: `CONCEPT.md` section 14, items 1 to 9, each
verified by the commands above. The final report to Jeremi states the count
of `captured` and `documented` fixtures, every open finding, every
contradiction rule 11 surfaced, and the decisions still pending.

## Increment checklist

- [ ] Increment 0
- [ ] Increment 1
- [ ] Increment 2
- [ ] Increment 3
