# Increment 0 staff review

Independent staff review run by the lead reviewer's session on 2026-10-30,
in two parts: the core model crate first (while Wave 2 streams were still
active), then the tooling, authored artifacts, and integration at the
Increment 0 close. Findings are ranked P0 (blocks Increment 1), P1 (fix in
Increment 0), P2 (later). Probes were scratch Rust programs outside the repo
calling the public core checks; "passes" means `check` returned no finding.

## Part 1: `crates/registry-adapter-core`

Reviewed at the last core commit `0c4adaea5` (branch base `d1fd2781e`).

### Gates

| Gate | Result |
|---|---|
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets -- -D warnings` (default and `--features schema`) | pass |
| `cargo test` (default and `--features schema`) | pass, 124 tests each |
| `python3 products/platform/scripts/check-config-conventions.py` | FAIL, exit 1: five CFG-SCHEMA-1 errors, `products/adapter/schemas/{fixture,pack,profile,project,runtime}.v1alpha1.schema.json` "not registered, shared, or out of scope"; CI runs this lint |
| breg-records names in core `src` | none |
| Auth kinds against Evidence `SourceAuthentication` | match as ruled |
| Pin version and digest codes | distinct |
| Predicates (CFG-SCHEMA-8) | one flat closed struct, exactly one language key |

### P0

- **P0-1. Conventions lint fails on the five adapter schemas.** Register or
  classify them in `products/platform` in the same change; review which of the
  lint's recorded findings are the adapter's.
- **P0-2. The worst-case upstream bound undercounts.** CONCEPT section 13
  promises an Increment 1 property test that runtime sends never exceed it.
  - `checks.rs` ~1485: `total = total.max(fallback)` compares the fallback with
    the whole running total. `[GET, GET, circuitBreaker{GET} onFallback{GET}]`
    really sends 4 and passes a budget of 3.
  - `checks.rs` ~1521: `total = total.max(catch)`, same defect.
    `[GET, doTry{GET} doCatch{GET, GET}]` really sends 4 and passes a budget of 2.
  - `checks.rs` 26, ~684, ~1386: past `MAX_DIRECT_DEPTH = 16` the walk returns 0
    instead of refusing, and depth counts every composite step, while the reader
    allows depth 128. 17 nested filters around a `split` of 1000 pass a budget
    of 1.
  - Fix: add body plus the widest of (fallback, each catch) plus finally to the
    running total; past the depth limit emit a finding, never 0; one regression
    test per composite step as a table.
- **P0-3. `loop` matches neither CONCEPT nor Camel (`route.rs` 407-424).** No
  count form (CONCEPT 8.6 promises one), `doWhile` is the predicate where Camel
  has a boolean flag beside the expression, and reaching `maximumIterations`
  while the predicate still holds is undefined (silent partial pagination). The
  dhis2-tracker pack duplicates the bound in a `dhis2MaximumPages` property.

### P1

1. Nine step structs lack `deny_unknown_fields`, so the generated pack schema is
   open there (CFG-SCHEMA-4): `ValidateStep` 338, `SetHeaderStep` 353,
   `SetPropertyStep` 364, `SplitStep` 376, `LoopStep` 407,
   `CircuitBreakerStep` 450, `ThrottleStep` 538, `IdempotentConsumerStep` 566,
   `DoCatch` 709 (`route.rs`). The platform reader still refuses unknown keys,
   so `adapterctl` is safe; the published schema and plain serde accept typos.
2. Write-safety checks are blind to `direct:` and `split`:
   `collect_non_safe_sends` (`checks.rs` ~748) never expands `direct:`; a write
   route reaching two non-idempotent POSTs through `direct:` passes; a
   caller-level redelivery over a POST inside a `direct:` target passes; a write
   `split` of 100 POSTs passes the one-non-safe-send rule.
3. `send_claims_idempotent` (`checks.rs` 662-677): a send naming no operation is
   idempotent if any operation on the endpoint is; an undeclared operation id is
   accepted.
4. The expression and script walks miss slots (`checks.rs` 870-903, 967, 288):
   `to` path, `pathParameters`, query, `retryWhile`, `AggregationStrategy::Rhai`.
   Undeclared `{{placeholder}}` in a path is not flagged; scripts there get no
   unknown-script finding.
5. A project can bind a raw template never instantiated (`checks.rs` 105-125);
   the runtime would send `{{param}}` literally.
6. `direct:` resolves by route id, not by the `from` URI as in Camel
   (`checks.rs` ~609).
7. `errorHandler` can be empty or carry both handlers (`route.rs` 591).
8. Breaker, throttle, and `onException` values are unbounded (`route.rs`
   451-503, 539, 629): zero counts, slow-call rate 250, throttle 0 per 0 ms,
   empty exception list, `handled` and `continued` both true.
9. `split.errorThreshold` is a count where Camel's is a ratio 0.0 to 1.0
   (`route.rs` 393-398); `stopOnException` with `errorThreshold` or
   `maxFailedRecords` is not refused (Camel makes them exclusive).
10. No error-class match function in core (`model.rs` 171-262). CONCEPT 8.7
    needs Camel's closest match across the error and its cause chain, and
    `script.budgetExceeded` (uncatchable) sits under the catchable `script`, so
    a prefix match would let `onException: [script]` catch it.
11. CONCEPT 10.2 puts token requests outside `maximumUpstreamCalls`; the walk
    adds 2 per OAuth endpoint into it (`checks.rs` ~1311, ~1327), and the single
    resend after a refreshed 401 is counted nowhere.
12. Finding order depends on `HashMap` iteration (`checks.rs` ~108, `find_cycle`
    ~1011); snapshots and CI diffs will churn.
13. `enrich` has no method, query, or operation (`route.rs` ~432), so every HTTP
    enrich is treated as non-safe.

### P2

1. Finding pointers use route and instantiated ids, not the authored
   position; template findings repeat per instantiation.
2. Missing-endpoint finding points at `/endpoints` without naming it
   (`checks.rs` ~1610); too-broad `allowedPrivateCidrs` is reported as an
   insecure origin (~1619).
3. Loopback detection is numeric only (`localhost` refused); document it.
4. The fixture check (`checks.rs` ~1679-1740) does not confirm the route
   reaches `given.endpoint`.
5. GraphQL POST reads count as non-safe (query versus mutation not modelled).
6. `onException` inside `split` counts once; Camel handles errors per item.
7. `onException` and `errorHandler` nest anywhere; Camel scopes them to a
   route or globally.
8. `handled` and `continued` are booleans where Camel takes predicates;
   declare it in the mapping table.
9. Redelivery across `direct:` takes the widest of caller and target
   (`checks.rs` ~1402, ~1422); sound only with the runtime rule already ruled
   (redelivery never applies to a `to: direct:` send), which CONCEPT 8.7 must
   state.
10. `retry_while` field doc (`route.rs` ~696) reads inverted against Camel.
11. Breaker options sit directly on `circuitBreaker` (Camel nests them under
    `resilience4jConfiguration`); no `slidingWindowType`. Undeclared.

### Camel contradictions (camel.apache.org, fetched 2026-10-30)

| Topic | Camel | Adapter |
|---|---|---|
| Loop | expression (count, or predicate with `doWhile: true`); `doWhile` boolean, default false; no bound | no expression; `doWhile` is the predicate; `maximumIterations` required; shape change undeclared |
| Split | `errorThreshold` ratio; `stopOnException` exclusive with it and `maxFailedRecords`; per-item error handling | count; not exclusive; clause counted once |
| Throttle | option `expression`; `timePeriodMillis` default 1000 | `limit` (undeclared rename); `timePeriodMilliseconds` per CFG-QTY-1 |
| Resilience4j | options under `resilience4jConfiguration`; defaults 50/100/COUNT_BASED/100/100/60000/10 | flattened; no window type; zero values accepted |
| Exception clause | closest match across cause chain; route or global scope | no match function; nests anywhere |
| Direct | connected by URI name | resolved by route id (undeclared) |
| Enrich | dynamic URI expression | static URI only (declared) |

### Lead reviewer rulings on Part 1

- **Loop shape (P0-3).** Camel's shape with our bound: the count or predicate
  is the same flat single-language-key form as `filter` and `choice`
  (`loop: {constant: 3, steps: [...]}`), `doWhile: true` makes it a predicate
  loop (Camel's boolean), `maximumIterations` stays mandatory (declared
  divergence). A constant count above `maximumIterations` is refused at check;
  a dynamic count above it, or a `doWhile` predicate still true at the bound,
  raises the catchable error class `loop.maximumIterationsReached`, never a
  silent stop. Packs then drop duplicated bound properties.
- **Token requests (P1-11).** Keep CONCEPT 10.2: token requests sit outside
  `maximumUpstreamCalls`, capped separately at two per OAuth endpoint per
  exchange by the runtime. The single resend after a refreshed 401 is a data
  send, so the walk adds one per distinct OAuth endpoint. Remove the +2 tokens
  from the walk.
- **Direct resolution (P1-6).** Resolve by the `from` URI, as Camel does.
- **Error-class matching (P1-10).** A pure core function now: closest class
  over the error and its cause chain, uncatchable classes
  (`script.budgetExceeded`, `credential.rejected`, and the rest of CONCEPT 8.7)
  never matched by any clause, whatever prefix it names; C3 builds on it.
- **P2-6** folds into the P0-2 fix (multiply by `maximumItems`).
- Everything else as the reviewer suggests. All P0 and P1 close in Increment 0;
  P2 items go into the orchestrator's ledger with an owning increment.

## Part 2: tooling, authored artifacts, and integration

Reviewed at `efe56d4eb` by an independent Opus reviewer; probe scripts stayed
in the reviewer's scratch.

### Gates

| Gate | Result |
|---|---|
| `cargo fmt --check`, clippy (default and all features), `cargo deny check`, tests | pass |
| DCO over the branch | pass |
| Config conformance | 5463 cells: 4068 pass, 0 fail, 1395 n/a |
| `test_ci_changes.py` | pass, 183 tests |
| Part 1 P0-1 to P0-3, P1-1 to P1-9, P1-13 | fixed; P1-10 to P1-12 not probed |
| Adapter `check-contracts.sh` in CI | absent (F3) |

### P1

- **F1. The AggregationStrategy wire form is wrong in the pack schema.** The
  model reads it internally tagged (`model.rs` 230-274) and
  `apply_manual_wire_forms` (`schemas.rs` ~243) never rewrites it, so the
  maintained `dhis2-tracker` pack and the `fhir-r4-patient-source`
  experiment are invalid against their own schema. The only schema test
  covers the minimal fixture. Five CFG-NAME-1 exception reasons call
  `json-array-append` and `json-merge` Camel names; they are additions.
- **F2. C9 is open.** A non-GraphQL query file, an unknown `operationName`,
  and a `.rhai` `queryFile` all pass; the two GraphQL codes are never
  emitted.
- **F3. CI never runs the adapter `check-contracts.sh`**, the drift check
  every adapter format names in `config-formats.yaml`.
- **F4. Acceptance items 2, 3, and 8 fail** (see the closing round below).
- **F5. A read binding can send unguarded writes** (`cases-get` with two
  POSTs passes). Medium confidence on exploitability; the rule is cheap.
- **F6. The dhis2 scripts are not on the section 8.11.3 ABI**
  (`is-not-found.rhai` reads `body.httpStatusCode`; `shape_records` the
  same).

### P2

- **F7.** The `retryWhile` doc is inverted (`route.rs` 797).
- **F8.** The `LoopStep` doc contradicts `LoopProcessor` (`route.rs` 464).
- **F9.** Check pointers drop the step-kind segment.
- **F10.** `is_loopback_origin` receives `[::1]` with brackets.
- **F11.** Still accepted: `%2e%2e`, `?` or `#` inside a path, backslash,
  single-brace placeholders, query or fragment on `baseUrl` and
  `tokenEndpoint`.
- **F12.** `setHeader` of a credential header (`X-Api-Key`) is accepted.
- **F13.** `okStatusCodeRange` is accepted on `graphql:`, with a loose
  grammar.
- **F14.** The `slidingWindowCalls` exception reason misattributes the name;
  Camel's is `slidingWindowSize`.
- **F15.** The dependencies added for Wave 1 are not used yet; no gate
  checks unused dependencies.
- **F16.** `experiments/FINDINGS.md` statuses are stale.

### Camel contradictions (camel-4.23.0)

| Topic | Camel | Adapter |
|---|---|---|
| Filter | `statusPropertyName` sets the named property to the predicate result (`FilterProcessor`); nothing set by default | option missing |
| `retryWhile` | option of `onException` and of the default error handler, not of the redelivery policy; keeps redelivering while true | nested under the redelivery policy; doc says it stops while true |
| Breaker window | `slidingWindowSize` | `slidingWindowCalls` (CFG-NAME-4, declared) |

### Closing round (acceptance items)

| Item | Status at `efe56d4eb` | Closes with |
|---|---|---|
| 1 | pass | |
| 2 | FAIL: plain `adapterctl check <dir>` exits 3 reading `profile.yaml` | X2 |
| 3 | FAIL: no gate runs the corpus; 70 of 74 members give exactly their code, 4 co-fire, 4 coverage gaps | X1 (no cascade), X2 (members), W0 (gate) |
| 4 | pass | |
| 5 | pass | |
| 6 | pass | |
| 7 | pass | |
| 8 | FAIL: closing-round list not written | this table |

### Process finding for Jeremi

During Wave 2 a stream ran `git reset --soft HEAD~1` on the shared branch to
split its own mixed commit. Nothing was lost (the split commits match the
original), but the rule forbids it. Standing rules since: no stream runs
reset, rebase, amend, or stash; a stream that sees a wrong commit stops and
reports; one stream at a time holds staged files and commits by pathspec.

### Lead reviewer rulings on Part 2

- No P0. Increment 1 Wave 0b starts; F1 to F6 close inside it rather than as
  a separate Increment 0 round, because each has a single owning stream:
  F1, F4 co-firing, F5, F7 to F14 in X1; F2 in C9; F4 item 2, the corpus
  gaps, and F6 in X2; F3 and the exact-code corpus gate in a new stream W0.
- **F5.** Inside a read binding, an `http` send whose method is not safe is
  refused unless the endpoint operation declares `safeUpstream: true`; a
  GraphQL query is safe, a mutation is refused (CONCEPT 8.7).
- **Filter.** Port `statusPropertyName`; Camel sets no filter property by
  default, so no `CamelFilterMatched` property is added.
- **`retryWhile`.** Moves to `onException` and the error handler as in
  Camel; redelivery continues while it is true, capped by
  `maximumRedeliveries` (CONCEPT 8.7).
- **F12.** Routes may not set or remove `Authorization`,
  `Proxy-Authorization`, `Cookie`, or a header an authentication kind on the
  source uses.
- **F13.** `okStatusCodeRange` is `http` only, with Camel's grammar
  (`HttpUtil.isStatusCodeOk`): comma-separated `N` or `N-M`, each 100-599.
- **F15.** The Increment 1 exit checks that every runtime dependency is
  used.
