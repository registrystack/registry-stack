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
- **Aggregate verification: HOLD.** Focused and PostgreSQL results reported by
  the integration stream are strong supporting evidence, but the final
  contract, full-workspace, configuration-conformance, and dependency gates
  have not yet run on the final integrated tree.
- **Increment 1 acceptance: HOLD.** The source findings are closed, but do not
  describe this increment as delivered until the final gates pass on the same
  candidate.

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
cases cover all five experiment directories. For each one, the source invokes
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

- The candidate tree was based on the expected checkout state and was dirty
  with the integrated source and test changes. This review does not bind its
  verdict to a commit identifier.
- The product guide, `CONCEPT.md`, `DELIVERY-PLAN.md`, platform configuration
  conventions, and all three new Camel attribution reports were read.
- Source paths for core checks, serving checks, route execution, problem-data
  validation and release, collection metadata, HTTP status handling,
  resilience wiring, the DHIS2 script, and the native experiment harness were
  inspected.
- `git diff --check` was clean.
- The target-API source scan matched only test modules. The pack scan found no
  `CamelHttpResponseCode` write and no profile problem code. Every required
  source-bound conformance module contained a `camel-4.23.0:` citation.
- The five experiment directories and five native experiment test cases match
  one for one.

No Cargo command, build, private harness, credential, or private execution log
was accessed in this review.

### Reported by the integration stream, not independently rerun here

- Adapter core: 308 unit tests plus one documentation test, with focused
  Clippy green.
- Adapter runtime: 190 library tests, 9 problem-data tests, 15 error-cluster
  tests, and 7 lifecycle tests.
- Platform resilience: 22 tests and focused Clippy green.
- Camel attribution targets: 31 collection tests; the focused boundary
  targets reported 28 header-filter, 19 resilience, and 28 egress tests.
- Conformance corpus: 125 cases plus 17 harness self-tests.
- Eight project pins and OpenAPI outputs regenerated through the actual CLI,
  with the double-generation comparison byte-identical; six schemas reported
  fresh.
- An earlier post-checkpoint PostgreSQL gate was reported green and included
  five native experiment identity/authentication/TLS cases and four served
  security cases. Subsequent source fixes mean this is not the final-tree
  gate. This review did not inspect the private log or re-derive its totals.

These results support the candidate, but they do not substitute for final
acceptance gates.

### Evidence that must not be attributed to this candidate

- The earlier captured DHIS2 get, missing, search, and live records-get run was
  performed against an earlier checkpoint. It remains useful historical
  evidence, but it is not proof of the current post-checkpoint artifact.
- The earlier MCP Adapter/gateway run used a frozen Adapter binary from an
  earlier checkpoint. It must not be reported as a paired execution of the
  current candidate.

If either proof is needed as final-candidate evidence, rerun it against the
final artifact. Otherwise, describe it explicitly as earlier-checkpoint
evidence.

### Still required on the final integrated tree

At minimum:

1. run the Adapter contract gate;
2. run the full workspace check and all-target Clippy gate;
3. run strict configuration conformance and the CI change test;
4. run `cargo deny check`, because Cargo manifests and the lockfile changed;
5. run the final PostgreSQL gate after all source fixes;
6. preserve the generated OpenAPI and schema freshness proof on that same
   final tree.

Only then is there a revision-consistent basis for changing aggregate
verification and Increment 1 acceptance from HOLD to PASS.
