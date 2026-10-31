# Increment 1 integration review

Date: 2026-10-31

## Acceptance

The read engine has passed its owning contract and PostgreSQL gates, fresh
authenticated DHIS2 execution, the matching MCP read integration, workspace
check and strict Clippy, and the CLI catalog package. Increment 1 is accepted
with the explicit inherited workspace exceptions below. The port-table gate
now declares `INCREMENT_DELIVERED = 1`.

The port table has 37 rows: 5 belong to Increment 0 and another 30 to
Increment 1. The remaining GraphQL and Idempotent Consumer rows belong to
later increments. Passing the read increment does not accept those two rows
or complete the whole delivery program.

## Integrated behavior and review

The lead and bounded independent reviewers closed the component fix round.
Cancellation releases breaker trials and throttle slots; uncatchable failures
stay uncatchable through fallback, enrichment, handlers and redelivery;
deadline checks and cooperative yields bound CPU-only routes. Exchange and
aggregation size limits, GraphQL document/operation checks, malformed-response
refusals, reserved-name guards, conversion misses, direct-call error scope,
and value-free consumed-failure events have executable coverage.

The additional Camel source comparison corrected output-bearing exception
clauses, collection metadata as exchange properties, sparse HTTP success
ranges, automatic breaker transition, and `doTry` structure. The three
`camel-*-attribution.md` reviews record actual applicable upstream methods,
Rust assertions and bounded exclusions. The evidence checker accepts only
named test functions, including tests with intervening documentation.

Typed problem data is declared by a profile, evaluated and validated before
handlers can catch a failure, bounded to 16 scalar fields and 2048 serialized
bytes, and validated again before release. The generated schema correlates
problem code, title, allowed statuses and exact data fields. Runtime-fixed
facade statuses share a descriptor with schema generation. The actual served
422 regression validates against the protected contract, while arbitrary
418 and cross-code partial-result 422 fail validation. The source-specific
partial-result interpretation remains in the reviewed pack script.

Native write idempotency binds stable deployment and verified caller identity,
operation and key; the request digest also binds exact artifacts and request
content. Replays retain exact response bytes and the original response
request ID. Each physical attempt has a fresh journal ID. Migrations refuse
opaque legacy keys or cached responses without the required identity instead
of erasing them. Independent review closed both identity and response-custody
findings. This native write proof does not enable MCP writes.

## Verification

| Check | Result |
|---|---|
| Complete Adapter contract gate | 943 passed, 0 failed, 0 ignored, 35 nonempty test binaries |
| Complete Adapter PostgreSQL gate | 633 passed, 0 failed, 0 ignored, 42 nonempty test binaries; owned PostgreSQL 17 container removed |
| Workspace `check --locked --workspace --all-targets` | Pass |
| Workspace `clippy --locked --workspace --all-targets -- -D warnings` | Pass |
| CI change-classifier suite | 183 passed |
| CLI catalog package | 24 unit tests and 3 snapshot tests passed; the stale supported-binary expectation was corrected after its failing run |
| Generated contracts | Six schemas, eight example OpenAPI outputs and the actual CLI effective-contract example reproduced; repeated OpenAPI generation byte-identical |
| Refusal corpus | 125 members refuse with exactly their expected code; 17 harness self-tests pass |
| Native experiment journeys | 5 passed with actual Adapter/CLI, JWT verification, controlled sources and PostgreSQL, including source OAuth, API key and mTLS/private-key assertion paths |
| Served security negatives | 4 passed: invalid JWTs, actual redirect refusal, egress boundaries and filter-bound cursors; full journal/log canary scans |
| Fresh real DHIS2 read journey | 264 of 264 checks passed through the served Adapter |
| Fresh real DHIS2 tagged write journey | 16 of 16 checks passed: one create, exact response/request-ID replay without another send, changed-body 422 without a send, readback and ownership-verified cleanup |
| Fresh real `verify --live` | 1 request executed, 0 waits, 0 diagnostics |
| Matching MCP/gateway native read integration | 6 passed, 0 failed, 0 ignored; all four copied artifact hashes stable; owned PostgreSQL container removed |

The real-source runs used the same frozen feature-enabled Adapter executable
as the matching MCP read proof and its matching CLI/runtime library. Sensitive
output scans found zero hits. A new disposable local database preserved earlier
cached responses rather than bypassing the migration guard. The tagged source
record was confirmed deleted. Exact local artifact identities and private
harness evidence remain in the lead's checkpoint.

Three generated property-test seeds were present and executed in both owning
gates. Their exact files are retained for reproducibility, including cases
that first exposed mistakes in the generators or test expectations. Tracking
those unchanged bytes adds no runtime or test behavior beyond the recorded
gate runs.

The normal dependency audit removed four unused direct declarations. Every
remaining runtime library is referenced by code. `pest =2.8.5` is a documented
resolution-steering pin for the already-used `jsonpath-rust` parser, not an
ahead-of-use library. `cargo tree` verifies that relationship; the workspace
manifest states the upstream condition for revisiting the pin. The target-API
literal scan matches only inspected `#[cfg(test)]` modules. The production
runtime has no normal dependency on `registry-record`. Pack scans found no
profile problem codes or response-status-header writes.

## Explicit workspace exceptions

Strict configuration conformance is **not green**: 5552 cells comprise 4132
passes, 2 failures, 0 stale or blocked cells and 1418 not applicable cells.
The failures are the unchanged `evidence/bundle` and `coordinator/runtime`
`unique-list-sweep` cases: owning readers wrap duplicate-item diagnostics in
their domain diagnostics. Fresh prerequisite CLIs were built before the final
run; no Adapter cell failed. The owning reader and harness paths are unchanged
by this fix round. This is the written exception permitted by the inherited
Increment 0 acceptance item 6, not a workspace-wide pass or a fix to those
products.

`cargo deny check` also remains red on three unchanged Wasmtime 48.0.7
advisories: RUSTSEC-2026-0422, RUSTSEC-2026-0423 and RUSTSEC-2026-0424. No package
version or checksum changed in the lockfile cleanup. These advisories remain
workspace dependency debt; this review neither adds an ignore nor claims they
are fixed. Bans, licenses and sources checks passed.

## Wider delivery limits

Increment 2 remains incomplete. The current served write slice is synchronous
POST create. PUT update is deliberately unserved; an additional live update
attempt failed and its tagged test record was confirmed cleaned up. The
Idempotent Consumer still refuses nondefault `eager: false` and
`completionEager: true` options. D16's 202 status-link and bounded-wait modes,
their expiry behavior, update/recovery properties and the Increment 2
conformance record remain to be implemented and verified. These gaps do not
change the accepted read increment or enable MCP writes.

The five experiment fixtures remain documented synthetic evidence. Their
`verify --live` invocations report caller-sourced waits; the separate native
facade calls prove transport and transformation. The maintained fixture files
outside the refusal corpus total 7 captured and 22 documented: DHIS2 tracker
7 captured plus 3 documented, GovStack 4 documented, OpenCRVS 10 documented,
and experiments 5 documented. A captured upstream transcript does not imply
the reconstructed facade request was itself captured.

Real OpenCRVS acceptance still requires the client supplied by Jeremi. Public
FHIR has capability-discovery evidence only; an actual Adapter call remains
behind the pending anonymous-source authentication decision. Controlled FHIR
experiment success does not constitute a live HAPI run. Personal delegation,
record/field disclosure authority, MCP writes and typed non-record commands
retain their existing gates. No push, merge, tag, release or production deploy
was performed.
