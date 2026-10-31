# Increment 1 staff review

Date: 2026-10-31

Scope: independent staff-engineer review of the integrated post-checkpoint
Increment 1 candidate. This is not a repeat of the broad C6a branch review.
It concentrates on the current Camel corrections, the source-neutral problem
data boundary, the DHIS2 partial-result mapping, experiment execution, and the
remaining read-engine definition of done.

## Decision

- **Source review: PASS after closure.** F1 to F4 were open at the first
  review. Read-only re-review found the offline, serving, and execution paths
  on one effective exception-policy helper; direct conformance cases now
  cover the three missing resilience behaviors; the experiment execution
  record is current; and the stale attribution narrative is corrected.
- **Owning aggregate verification: PASS.** The complete Adapter contract and
  PostgreSQL gates, workspace check and Clippy, CLI catalog, CI classifier,
  port-table milestone, generated contracts, and exact-artifact source proof
  are green. The three retained property-test seeds were exercised by both
  owning gates. The lead has also verified the latest immutable-artifact MCP
  read pairing described below.
- **Increment 1 acceptance: PASS with explicit workspace exceptions.** Strict
  workspace configuration conformance still has two unchanged failures owned
  by Evidence and Coordinator. `cargo deny` still reports three unchanged
  Wasmtime advisories. Neither is an Adapter failure, and neither is described
  as green or fixed below.
- **Wider delivery: HOLD.** Later Adapter increments, real OpenCRVS proof,
  workspace conformance debt, merge, release, and deployment remain separate.

## Findings

### F1, P1, closed: offline and serving checks disagreed on output-bearing exception clauses

`CONCEPT.md` section 8.7 and the runtime now implement the pinned Camel rule:
an `onException` clause with output steps and no explicit redelivery policy
gets zero redeliveries, while an outputless clause inherits the route
handler's policy.

At first review, the serving check applied that distinction in
`crates/registry-adapter/src/route.rs`, and execution applied the same rule
when it selected the policy for a failed send. The pure authoring check in
`crates/registry-adapter-core/src/checks.rs`, however, validated `retryWhile`
with:

```text
clause.redelivery_policy.as_ref().or(handler_policy)
```

It did so regardless of whether the clause had output steps. Consequently,
`adapterctl check` could accept a route with all of these properties:

1. the route handler has `maximumRedeliveries > 0`;
2. an output-bearing `onException` clause has `retryWhile`;
3. that clause has no explicit redelivery policy.

The runtime serving check then refused the same route because the clause's
effective maximum was zero. This broke the required offline/runtime agreement
and made a checked project undeployable.

Closure readback: core, serving validation, and runtime execution now call the
same `effective_clause_redelivery_policy` helper. The core regression covers
the refused output-bearing form, admitted outputless inheritance, and an
explicit clause policy. The owner reported 308 unit tests, one documentation
test, formatting, and strict Clippy green.

### F2, P1, closed: the conformance inventory recorded applicable behavior without direct proof

At first review, the new boundary attribution was candid about three missing
cases:

- slow-call threshold and slow-call rate behavior at the Adapter boundary;
- the full default 100-call circuit-breaker window;
- a changing header expression in `concurrent-requests` throttle mode.

These were not excluded Camel facilities. They are supported options or
defaults in the bounded port. `CONCEPT.md` section 13.2 requires every ported
option's default and relevant edge to be restated as executable conformance
cases. Model round-trip tests and shared implementation code were useful, but
the attribution report correctly declined to treat either as direct runtime
conformance proof.

Closure readback: the Adapter tests now directly prove all three areas. One
case opens on a successful slow call at the authored duration and exact rate;
one separately proves the default 100-call minimum and rolling-window eviction
at call 101; one changes a concurrent-throttle header from one to two, admits
the second in-flight call, then refuses a third. The focused
`camel_resilience` target passed 19 of 19.

### F3, P1, closed: the experiment acceptance record described the pre-runtime state

At first review, `products/adapter/experiments/FINDINGS.md` contained only a
2026-10-30 run "before the Increment 1 runtime exists" and ended by saying
each experiment still waited for the runtime. The delivery plan's Increment 1
acceptance item 10 requires this file to carry the executed rerun and each
command's output.

The new native harness was materially stronger than that document. Its five
cases cover all five API transformation experiment projects. For each one,
the source invokes
`adapterctl check`, fixture replay, and `verify --live`, rejects a forged
facade token before source I/O, and then drives the documented facade request
through the native Adapter process to the upstream double. The mTLS cases use
the TLS double.

The record needed to remain precise: each experiment's `verify --live`
assertion expected `drove: 0` plus one or two `caller-sourced` waits. The
command itself documents that such a result is not live transport proof. The
subsequent served facade call is the separate transport and transformation
proof. The update therefore had to report both facts, not collapse them into a
claim that `verify --live` sent the request.

Closure readback: the dated Increment 1 section now records all five
experiments, the three command results, the exact `drove: 0` and
`caller-sourced` wait limitation, and the separate native facade transcripts.
The focused native experiment target passed 5 of 5 with strict Clippy green.

### F4, P2, closed: conformance comments called a resolved rule unresolved

At first review, the new regression
`an_output_bearing_clause_without_policy_disables_handler_redelivery` proved
the output-sensitive Camel rule. A later doc comment in the same
`camel_error_cluster.rs` file nevertheless said output-bearing clauses remained
an unresolved conformance difference.

The error attribution report had a similar time-boundary problem. It first
said the Adapter "currently" selected the old policy and that the contract
needed clarification, then later reported the runtime and contract fix as
integrated. As a durable review artifact, it needed to identify the first
passage as the defect found during inspection and the later passage as the
current state.

Closure readback: the test comment now names the focused regression rather
than an unresolved difference. The error attribution separates the initial
inspection from the integrated state and carries the current focused counts.
The boundary attribution labels its earlier Clippy and formatting results as
historical and leaves the final all-target gate to the integration record.

## Architecture and next-increment compatibility

Subject to the findings above, the current design choices fit the product
boundary and leave the next increment cleaner:

- Typed problem data remains profile-owned. A pack raises a neutral class;
  the profile declares the exact scalar fields a selected problem may expose.
  The route validates before handlers can catch the failure, and the facade
  validates again before release. The value is redacted from `Debug`, absent
  from the journal, and removed on disclosure failure. This is the right
  boundary for later pack-defined partial-write outcomes.
- The DHIS2 import-summary interpretation stays in the digest-pinned Rhai
  script rather than becoming a DHIS2 Rust type. The four released integers
  are declared in the profile, and the rejected count is described honestly
  as orthogonal to imported, updated, and ignored rather than being forced
  into an invalid total.
- Split and loop metadata now live only in exchange properties, matching the
  pinned Camel implementation. Static and dynamic guards protect the exact
  engine-owned names from authored writes. This avoids exposing engine
  bookkeeping as transport headers to future packs.
- Sparse HTTP success ranges are represented as a set of admitted statuses,
  with redirect refusal taking precedence. Automatic breaker transition is
  wired through the Adapter boundary while retaining the deliberately
  timerless platform model.
- The `doTry` structural guard now agrees across the contract, core check,
  serving check, and focused runtime test.

No additional product coupling or domain-specific runtime model was found in
these changes.

## Verification evidence and limits

### Independently inspected

- The runtime source was at the expected clean checkpoint. The later native
  PUT, DHIS2 attribute-update, and anonymous-HTTPS changes were inspected as
  current behavior rather than attributed to the earlier read checkpoint.
- The product guide, `CONCEPT.md`, `DELIVERY-PLAN.md`, platform configuration
  conventions, three Camel attribution reports, and integration review were
  read.
- Source paths for core checks, serving checks, route execution, problem-data
  validation and release, collection metadata, HTTP status handling,
  resilience wiring, the DHIS2 script, and the native experiment harness were
  inspected.
- The complete owning logs contain 960 contract tests and 645 PostgreSQL tests,
  with zero failures and zero ignored tests. The PostgreSQL gate includes a
  nonempty journal suite, both served profiles, persisted security negatives,
  problem data, idempotency, response-identity migration, six native PUT
  tests, four DHIS2 pack-write tests, and eight served response-custody tests.
- The CLI catalog correction has 24 unit and 3 snapshot tests green. Focused
  all-target Clippy is green after that test-only correction; the earlier
  workspace-wide check and all-target Clippy are also green.
- The CI change-classifier suite passed 183 tests. Final format and Adapter
  configuration-conventions checks are green: 114 recorded findings, zero
  unrecorded, stale, or erroneous findings.
- The port-table gate now reports 37 rows, 35 delivered with evidence and only
  the Increment 2 Idempotent Consumer and Increment 3 GraphQL rows pending.
  Its eight unit tests and the PostgreSQL wrapper self-test pass.
- The target-API source scan matched only inspected `#[cfg(test)]` modules.
  The pack scan found no response-status-header write and no profile problem
  code. Every required source-bound conformance module contains a pinned Camel
  source citation.
- Read-only `cargo tree` inspection found no normal `registry-record` reach.
  It confirmed that `jsonpath-rust` uses `pest 2.8.5` and that the direct
  declaration is the documented resolution-steering pin, not an unused future
  library. The Adapter normal tree contains no Wasmtime dependency.
- Local history inspection found conventional subjects, exactly one DCO
  sign-off per commit, and no agent-attribution trailer.
- The five API transformation projects and five native experiment cases match
  one for one. Their report distinguishes `verify --live` caller-sourced waits
  from the separate native facade transport proof.
- The native PUT source and tests enforce authentication, scope, contract pin,
  closed request identity, exact replay custody, mismatch without a source
  send, and fail-closed handling after an uncertain effect. The actual 202
  case stays spent and replays its bounded failure rather than claiming D16.
- The anonymous-HTTPS source and nine-test CLI TLS suite keep the named
  operator acknowledgement distinct from TLS trust and authentication. The
  accepted path sends no source credential or caller-token header, while an
  omitted acknowledgement or untrusted certificate remains closed.

This reviewer ran no build or test command and accessed no private credential
or harness. Read-only inspection included source, named gate logs, Git history,
and Cargo dependency metadata.

### Exact-artifact source and integration proof

The lead reports the following against one frozen feature-enabled Adapter
executable, its matching CLI and runtime library:

- the real DHIS2 read journey passed 264 of 264 checks;
- the synchronous DHIS2 create and attribute-update journey passed 25 of 25
  checks, including exact response bytes and the original response ID in
  header and body on replay, changed-body mismatch without a send, readback,
  and ownership-verified cleanup;
- real `verify --live` executed one request with zero waits and zero
  diagnostics;
- the HAPI journey passed 18 recorded checks for one synthetic Patient,
  including setup and authentication, conditional create 201, read and search
  200, exact replay, mismatch 422, one source POST, owned delete 200, and
  readback 410; and
- sensitive-output scans returned zero hits, both owned-record cleanups were
  confirmed, and the public summary records the artifact hash as unchanged.

Exact local artifact identities and the private execution details remain in
the lead's checkpoint. This report relies only on the supplied counts and
identity readback. It does not expose credentials or private harness content.
The latest immutable Adapter artifact passed six matching MCP/Adapter native
PostgreSQL cases, with zero failures or ignored cases. The lead verified the
log hash, all four retained artifact hashes, and the archive reproduced from
committed source. The first attempt failed at fixture digest-pin preparation
before any runtime journey; the successful rerun uses temporary projects with
exact supplied profile and pack pins. The gateway's subsequent two-file
inventory and regression-test follow-up changes no runtime. This is bounded
read-composition evidence with synthetic issuers and sources, not permission
to claim MCP writes or broader product authority.

Three generated property-test seeds, stored in two files, were present in both
owning runs and are retained unchanged in the final delivery set. Committing
those exact bytes makes the 960-test and 645-test results reproducible without
changing the test behavior the gates already exercised.

### Explicit workspace exceptions

Strict configuration conformance is **not green**. Of 5,553 cells, 4,133 pass,
2 fail, none are stale or blocked, and 1,418 are not applicable. The failures
are unchanged `evidence/bundle` and `coordinator/runtime` unique-list sweeps:
their owning readers wrap the expected duplicate-item diagnostic in a domain
diagnostic. Fresh prerequisite binaries were used, no Adapter cell failed, and
the owning reader and harness paths are unchanged by this increment. This is
the written exception allowed by inherited Increment 0 acceptance item 6, not
a workspace-wide pass or a fix to either product.

`cargo deny check` is also **not green**. It reports three unchanged Wasmtime
48.0.7 advisories: RUSTSEC-2026-0422, RUSTSEC-2026-0423, and
RUSTSEC-2026-0424. No manifest, package version, or checksum changed in this
checkpoint, no new ignore was added, the Adapter normal dependency tree does
not reach Wasmtime, and bans, licenses, and sources checks pass. These
advisories remain workspace dependency debt and are not claimed fixed.

### Wider delivery limits

- Passing Increment 1 marks the 30 read-engine port-table rows delivered. It
  does not deliver GraphQL, Idempotent Consumer, or the later increment
  checklist.
- Synchronous native POST create and PUT update are served, but D16's two
  asynchronous 202 modes, the nondefault Idempotent Consumer options, the full
  Increment 2 conformance record, and later write resume remain undelivered.
- Real OpenCRVS acceptance still needs the client supplied by Jeremi. The
  maintained OpenCRVS fixtures are documented evidence, not a live run.
- The lead-reported HAPI journey proves one live path with a synthetic Patient
  under the named anonymous-HTTPS acknowledgement. It does not establish a
  maintained FHIR pack or turn the documented experiment fixtures into
  captured evidence.
- The latest matching MCP/gateway native read run is green. Native writes
  remain outside the gateway contract; the proof uses synthetic issuers and
  sources rather than a real external deployment.
- Personal delegation, record and field disclosure authority, MCP writes, and
  typed non-record commands retain their own gates.
- No push, merge, tag, release, or production deployment is claimed.
