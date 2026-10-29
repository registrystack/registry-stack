# Adapter Delivery Plan

Status: active, revised 2026-10-30 for the Camel port (`CONCEPT.md` D7 to
D15). Companion to `CONCEPT.md`: the concept is the product contract; this
file decomposes its section 14 into parallel workstreams with definitions of
done and runnable acceptance commands. On any conflict, `CONCEPT.md` wins.

The scope is the full port table in `CONCEPT.md` section 8.10, every row,
whether or not a maintained pack uses it today (Jeremi's ruling: the engine
is a reusable integration piece). No stream shrinks a row to what a pack
needs; a row that cannot land says so in its report.

## Rules every agent works under

Every brief carries these rules by reference; they are not optional.

1. Do NOT spawn subagents (do not use the Agent tool).
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
   `CARGO_TARGET_DIR=/Volumes/CodexWorktrees/target/live-adapter PATH="$HOME/.cargo/bin:$PATH" cargo ...`
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
    4.x page (and the resilience4j page for the breaker), and write the
    conformance cases from what the page says: option names, defaults,
    exchange properties, matching and ordering rules. Each case's doc
    comment cites the page URL. If the page contradicts `CONCEPT.md`, the
    report says so and the stream follows the page for semantics and
    `CONCEPT.md` for spelling and divergences; the integration stream
    corrects the concept. Never write a default from memory.

## Wave model and review protocol

Waves run sequentially; streams inside a wave run in parallel on disjoint
paths and commit their own work. Each increment opens with a scaffold step
(module roots and dependency additions, serial) so parallel streams never
touch a shared file. The integration stream closes each increment; an Opus
review agent then reviews it. HEAD SHAs are captured at wave launch and
carried in every brief.

After each increment's own Opus review, the orchestrator sends the lead
reviewer (the session in the Orca terminal "Live adapter CONCEPT and
DELIVERY-PLAN review") a message through orca with: the increment, the HEAD
SHA, the acceptance command results verbatim, the review report path, and
open findings. It then waits for the reviewer's go or feedback before
starting the next increment. Blockers and any `CONCEPT.md` contradiction
are sent the same way as they happen. The reviewer's feedback is binding
in the same way as Jeremi's for this program.

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
per CFG-ID-7) for: `AdapterProfile`; `AdapterPack` (endpoints with
component kind, auth kind, declared response headers, `idempotentUpstream`
per operation, tested versions; `routeTemplates` with typed parameters;
internal `routes`; code maps; script and query-file references with digest
pins; required capabilities); `AdapterProject` (record types and fields,
pinned pack and profile references, `templatedRoutes`, bindings, access
profiles); `AdapterRuntimeConfig`; `AdapterFixture` with provenance
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
class, digest-pin shape, envelope-name validity.

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
`breg-records` v1 profile (operations, problem schema and codes); the
`dhis2-tracker` pack as route templates: search with pagination as `loop`
plus `enrich` with `jsonArrayAppend` and `uniqueBy`, get with `choice` and
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
`products/adapter/reviews/increment-0.md` after the Opus review.

DoD: `check-contracts.sh` green from a clean shell; report lists every gate
result verbatim.

## Increment 1: the read engine

### Wave 0, scaffold (serial)

Creates the runtime module roots named in `CONCEPT.md` 8.1 (`exchange`,
`route`, `processor/*` one file per EIP, `component/{direct,http,rest}`,
`language`, `errorhandler`, `notifier`, `idempotent`) with module docs and
no logic; adds dependencies (RFC 9535 JSONPath crate after `cargo deny
check`, PostgreSQL driver matching the workspace's, platform crates);
`products/adapter/scripts/test-postgres.sh` skeleton that starts and removes
its own loopback PostgreSQL 17 container when `ADAPTER_TEST_DATABASE_URL`
is absent; root `AGENTS.md` and `products/adapter/AGENTS.md` gate rows.

### Wave 1 (parallel, disjoint modules)

- **C1, exchange and core EIPs**, owns `src/{exchange,route,language}/**`,
  `src/processor/{to,set_body,transform,set_header,set_property,remove_header,remove_property,script,choice,filter,validate,stop}.rs`,
  and `tests/camel_{exchange,message,routes,languages,to,set_body,transform,headers_properties,script,choice,filter,validate,stop}.rs`.
- **C2, splitting, aggregation, conversion**, owns
  `src/processor/{split,loop,enrich}.rs`, `src/processor/aggregation/**`,
  code-map conversion, and `tests/camel_{split,loop,enrich,aggregation,type_converter}.rs`.
- **C3, error handling and resilience**, owns `src/errorhandler/**`,
  `src/processor/{do_try,circuit_breaker,throttle}.rs`, and
  `tests/camel_{error_handler,redelivery,exception_clause,try_catch_finally,circuit_breaker,throttle}.rs`.
- **C4, components and facade**, owns `src/component/**`, `src/http/**`,
  `src/auth/**`, the upstream double under `tests/support/upstream/**`, and
  `tests/camel_{direct,http,rest_dsl,header_filter}.rs`: `direct`, `http` on
  `FixedDestinationPolicy`, the `rest` consumer on `registry-platform-httpsec`
  with OIDC and access profiles.
- **C5, journal**, owns `src/notifier/**`, migrations, `tests/camel_event_notifier.rs`,
  and the PostgreSQL suite: event kinds from `CONCEPT.md` 11, value-free,
  written before the response; retention.
- **C6, compile and replay tooling**, owns `crates/registry-adapterctl/src/{compile,fixtures,verify}/**`
  and `tests/camel_testing.rs`: `adapterctl compile` (byte-stable OpenAPI
  into the built package, Record v1 shape against `products/breg/generated/`),
  `fixtures replay` (intercept and skip semantics), `verify --live` (tested
  against the double; a live DHIS2 run is Jeremi's optional step).

Each C stream ports its rows completely, every option and default the
Camel page documents within the port's boundaries, with conformance cases
per rule 11.

### Wave 2, integration

Wires C1 to C6 into one engine; dhis2-tracker search and get end to end
over the double and by replay; fault injection (13.4), read property tests
(13.5), contract tests (13.6), security tests (13.7) in the default suite;
`check-port-table.py` now requires every Increment 1 row; review report.

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

Precondition: Jeremi decides D16 (accepted but not complete) before this
increment starts; until then such a route is refused and the increment
proceeds on synchronous outcomes only.

## Increment 3: the second system

Pre-launch check (orchestrator, before any stream): confirm from current
OpenCRVS documentation which API the current release exposes for reads and
registration (GraphQL gateway or REST events API), and send the finding to
the lead reviewer before launching.

- **E1, graphql component** (if OpenCRVS is GraphQL), owns
  `src/component/graphql.rs`, `tests/camel_graphql.rs`; its own commit.
- **E2, write resume**, owns resume bindings in core and runtime and the
  resume property test; its own commit; port-table entry added as an
  addition.
- **E3, opencrvs pack**, owns `products/adapter/packs/opencrvs/**`, its
  example and fixtures: reads, then draft and declare writes. Its commits
  change no `.rs` file.
- Integration: both packs' example projects served by one binary; review
  report; final multi-expert review (security, Camel semantics, contracts,
  data minimization) recorded as `products/adapter/reviews/final.md`.

## Platform rules

- Mechanism moves into platform crates only under the two-system rule; this
  program adds none. The redelivery, breaker, and throttle processors are
  adapter-local (D13).
- The only platform edits are A2's registration and amendment in
  `products/platform/**`. No Evidence crate changes.

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
`CARGO_TARGET_DIR=/Volumes/CodexWorktrees/target/live-adapter PATH="$HOME/.cargo/bin:$PATH" cargo`.

Increment 0:

1. `products/adapter/scripts/check-contracts.sh` exits 0.
2. `CARGO run --locked -p registry-adapterctl -- check products/adapter/examples/dhis2-tracker/project.yaml`
   exits 0 with a value-free report (the integration report names the
   exact path if it differs).
3. Each bad corpus member fails `check` with its expected code (driven by
   the gate).
4. `python3 products/adapter/scripts/check-port-table.py` exits 0.
5. `git --no-optional-locks log --format='%H %s' origin/main..HEAD` shows
   conventional subjects; every commit body has exactly one DCO trailer and
   no agent attribution trailer.
6. `CARGO check --locked --workspace --all-targets` and
   `python3 .github/scripts/test_ci_changes.py` exit 0.

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

Global definition of done: `CONCEPT.md` section 14, items 1 to 6, each
verified by the commands above. The final report to Jeremi states the count
of `captured` and `documented` fixtures, every open finding, every
contradiction rule 11 surfaced, and the decisions still pending (D7 to D16).

## Increment checklist

- [ ] Increment 0
- [ ] Increment 1
- [ ] Increment 2
- [ ] Increment 3
