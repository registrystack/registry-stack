# Increment 1 integration review

Date: 2026-10-31

## Acceptance

The Increment 1 read engine remains accepted. At the current checkpoint, the
Adapter has passed its complete owning contract and PostgreSQL gates, fresh
authenticated DHIS2 execution, workspace check and strict Clippy, and the CLI
catalog package. The latest live-source evidence also covers synchronous
native create and update, without accepting Increment 2 as a whole. Increment
1 retains the explicit inherited workspace exceptions below. The port-table
gate declares `INCREMENT_DELIVERED = 1`.

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

The native facade now serves synchronous POST create and PUT update. The PUT
boundary authenticates and authorizes before reading a body or reaching the
source, enforces the effective-contract pin, binds the path identity to the
closed request, and keeps an uncertain post-send effect spent. An actual
upstream 202 is retained as an exact failed response and is not resent. The
external gateway contract still excludes writes. An independent PUT and
security review reported PASS, with no weakening of TLS, authentication, or
header filtering.

Credential-free public HTTPS is now a closed, named operator decision. It
requires the matching `none` pair and `anonymousHttps: operator-approved` on a
fixed HTTPS binding. TLS verification and facade authentication remain
mandatory, no source credential or caller token is sent, and another
credential kind never falls back to anonymous access.

## Verification

| Check | Result |
|---|---|
| Complete Adapter contract gate | 960 passed, 0 failed, 0 ignored |
| Complete Adapter PostgreSQL gate | 645 passed, 0 failed, 0 ignored; owned PostgreSQL 17 container removed |
| Workspace `check --locked --workspace --all-targets` | Pass |
| Workspace `clippy --locked --workspace --all-targets -- -D warnings` | Pass |
| CI change-classifier suite | 183 passed |
| CLI catalog package | 24 unit tests and 3 snapshot tests passed |
| Generated contracts | Six schemas, eight example OpenAPI outputs and the actual CLI effective-contract example reproduced; repeated OpenAPI generation byte-identical |
| Refusal corpus | 127 members refuse with exactly their expected code; 17 harness self-tests pass |
| Native experiment journeys | 5 passed with actual Adapter/CLI, JWT verification, controlled sources and PostgreSQL, including source OAuth, API key and mTLS/private-key assertion paths |
| Served security negatives | 4 passed: invalid JWTs, actual redirect refusal, egress boundaries and filter-bound cursors; full journal/log canary scans |
| Focused current write and custody suites | 6 native PUT, 4 DHIS2 pack-write and 8 served response-custody tests passed; CLI TLS suite passed 9 tests |
| Fresh real DHIS2 read journey | 264 of 264 checks passed through the served Adapter |
| Fresh real DHIS2 create and attribute-update journey | 25 of 25 checks passed: create, update, exact body replay with the original response ID in header and body, changed-body mismatch without another send, readback and ownership-verified cleanup |
| Fresh real `verify --live` | 1 request executed, 0 waits, 0 diagnostics |
| Fresh HAPI journey | 18 recorded checks passed for one synthetic Patient: setup and authentication, conditional create 201, read and search 200, exact replay, mismatch 422, one source POST, owned delete 200 and readback 410 |

The lead reports that the DHIS2 and HAPI journeys used the same immutable
feature-enabled Adapter executable and matching CLI/runtime library. Its
public safe summary records an unchanged artifact hash. The lead separately
reports zero sensitive-output hits and confirmed cleanup of both owned records.
This review did not access the private harness, environment, logs, or recovery
material. Exact local artifact identities and private execution evidence remain
in the lead's checkpoint.

The earlier 6-of-6 matching MCP/gateway native read proof belongs to the
accepted read checkpoint and remains historical evidence only. A v3 Adapter
artifact has been handed off. The first six-case attempt failed during fixture
digest-pin preparation, with zero cases passed and no runtime journey reached.
Gateway fixture repair and a successful matching-artifact rerun remain
unverified. No current matching-artifact MCP claim is made here.

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

Strict configuration conformance is **not green**: 5553 cells comprise 4133
passes, 2 failures, 0 stale or blocked cells and 1418 not applicable cells.
The failures are the unchanged `evidence/bundle` and `coordinator/runtime`
`unique-list-sweep` cases: owning readers wrap duplicate-item diagnostics in
their domain diagnostics. Fresh prerequisite CLIs were built before the final
run; no Adapter cell failed. The owning reader and harness paths are unchanged
by this fix round. This is the written exception permitted by the inherited
Increment 0 acceptance item 6, not a workspace-wide pass or a fix to those
products.

`cargo deny check` also remains red on three unchanged Wasmtime 48.0.7
advisories: RUSTSEC-2026-0422, RUSTSEC-2026-0423 and RUSTSEC-2026-0424. No
manifest, package version, or checksum changed in this checkpoint, and no new
ignore was added. These advisories remain workspace dependency debt; this
review does not claim they are fixed. Bans, licenses and sources checks
passed.

## Wider delivery limits

Increment 2 remains incomplete even though synchronous native POST create and
PUT update are now served. The Idempotent Consumer still refuses nondefault
`eager: false` and `completionEager: true` options. D16's 202 status-link and
bounded-wait modes, their expiry behavior, the complete update and recovery
property set, and the Increment 2 conformance record remain to be implemented
and accepted. A synchronous PUT is not evidence for those asynchronous modes.
These gaps do not change the accepted read increment or enable MCP writes.

The five experiment fixtures remain documented synthetic evidence. Their
`verify --live` invocations report caller-sourced waits; the separate native
facade calls prove transport and transformation. The maintained fixture files
outside the refusal corpus total 7 captured and 23 documented: DHIS2 tracker
7 captured plus 4 documented, GovStack 4 documented, OpenCRVS 10 documented,
and experiments 5 documented. A captured upstream transcript does not imply
the reconstructed facade request was itself captured.

Real OpenCRVS acceptance still requires the unavailable client. Its 10
maintained fixtures are documented and offline only. The lead-reported HAPI
journey closes the earlier public-source and live-call gap for one synthetic
Patient, but it does not convert the documented FHIR experiment fixtures into
captured evidence or establish a maintained FHIR pack. Personal delegation,
record/field disclosure authority, MCP writes and typed non-record commands
retain their existing gates. No push, merge, tag, release or production deploy
was performed.
