# Reusable payment contract tests

**Status: initial executable coverage, plus a broader future test catalogue.**
The suite verifies [G2P Profile 0.1](SPEC.md) and the separate
[P2G Collection Profile 0.1](P2G-SPEC.md) against an HTTP target. The same
assertions run against the Python simulator and a real implementation or its
adapter in an isolated sandbox.

The [initial definition of done](DEFINITION-OF-DONE.md) selects the required
subset for this mock. Callback delivery, receipt expiry, and exhaustive crash
injection below are future coverage; they are not claimed by the first build.

## Executable initial coverage

Run `uv run pytest tests/contract/test_g2p_profile.py -q` for the seven G2P live
HTTP tests. They cover
mapping round trips and atomic update, replay/conflict, successful and partial
batches, exact decimals, stable pagination, frozen destinations, basic scope
refusals, and acceptance-response loss followed by same-database restart and
replay. The local driver adds independent credit-ledger evidence. Tests under
`tests/test_service.py` cover strict decoding, input bounds, concurrent replay,
missing mappings, current authority and credential rotation, database version
refusal, and generated-contract parity.

Run `uv run pytest tests/contract/test_p2g_profile.py -q` for P2G live HTTP
tests covering paid, failed and expired outcomes; intermediate `COM/PENDING`;
exact amounts and original identities; create replay and identity conflicts;
current tenant/biller scope; and recovery after losing the acknowledgement
and restarting the process. The fixture independently counts one confirmed
payment receipt. `tests/test_p2g_service.py` additionally checks malformed
inputs, concurrent replay, configuration changes, revoked authority and the
additive database upgrade preserving G2P state.

P2G uses the same target URL/credential loader with `--target-biller` and
`collection-paid`, `collection-failed`, `collection-expired` capabilities.
The external driver can exercise declared paid destinations; controlled failed
and expired outcomes require a provider-specific fixture and otherwise skip.
Select the relevant profile's test file when a target implements only one.

The matrix below is a broader catalogue, not a claim that every row is fully
implemented or verified. See the README for external target options. External
fixtures without outcome, restart, or ledger controls report explicit skips.

## Keep assertions independent of the simulator

Use `pytest` and `httpx` with a live HTTP base URL. Contract tests must not
import `payment_simulator`, use FastAPI's in-process test client, inspect SQLite,
depend on generated identifier formats, or call mock-only HTTP routes.
Framework-level unit tests can do those things in a separate suite.

The harness supplies:

- A base URL, credential loader, authorized producer/tenant/institution,
  programme, payer account, source ID, and approved callback receivers.
- A unique fixture namespace, synthetic destinations, and currency/scale.
- An isolated unauthorized principal/scope for negative tests.
- Published target limits, enabled payment modes, recovery retention, polling
  interval, and deadline.
- A target fixture driver and an explicit capability list.

Credentials are loaded from protected files or a target's normal credential
provider, never committed or placed on a command line. The target must be an
explicitly selected sandbox that cannot move real funds. The driver owns and
cleans up only the namespace it created; the harness has no generic remote
reset command.

Fixture drivers perform setup and controlled faults. They may configure a
simulator process or a provider sandbox through its supported administration
surface. They must not normalize business HTTP requests or repair responses
inside the test harness. Provider translation belongs in the actual adapter
under test, where deployment will use it too.

The request builders use each profile's public operations. Tests parse
numeric values as exact decimals, validate response shapes and correlations,
and collect complete paginated results. They compare amount values, not JSON
number formatting, and do not assert informational descriptions verbatim.

## Fixture capabilities and evidence

| Capability | Required fixture behavior | Availability |
|---|---|---|
| `success` | Supply destinations that can finish successfully | Required to validate replacement |
| `partial-failure` | Arrange one successful and one rejected instruction | Required to validate replacement |
| `collection-paid` | Supply a synthetic payer that can complete a full collection | Required to validate P2G replacement |
| `collection-failed` | Arrange a rejected P2G request | Provider fixture required for this outcome |
| `collection-expired` | Arrange an unpaid P2G request expiring | Provider fixture required for this outcome |
| `lost-response` | Relay observes upstream acceptance (`202` G2P or `200` P2G), then drops downstream response | Required to validate replay recovery |
| `hold-processing` | Keep accepted rows nonterminal until explicitly released | Simulator required; provider-dependent |
| `restart` | Restart the target while preserving its durable state | Simulator required; provider-dependent |
| `effect-witness` | Independently count accepted work and credits or collection receipts by original identity | Simulator required; provider-dependent |
| `batch-callback` | Capture notifications, drop acknowledgements, and allow duplicates | Future extension; absent in the initial mock |
| `receipt-expiry` | Expire eligible receipt payloads without erasing spent identities | Only targets that support expiry |

Manual time control is a fixture convenience, not a provider requirement.
Targets with real clocks are polled within a bounded deadline and a published
observation interval. A test must not fail because a valid target progressed
too quickly to expose `PDNG` or `ACSP`.

`effect-witness` is deliberately separate from the public API assertions.
For the simulator, a read-only local fixture driver can inspect the simulated
credit ledger. For a real provider, use its sandbox ledger or other independent
accepted-payment evidence. A returned `ACCC` proves the target reported success;
it does not independently prove that money moved once.

An unavailable capability produces an explicit **not verified**, with its
reason and affected test IDs. It is not a passing test. Every simulator-required
capability in the initial definition of done must run locally; a missing driver
there is a failure. This iteration does not add CI machinery.
Do not silently use a weaker fault, fake a provider restart, or replace the
target with the mock to complete a report.

## G2P test matrix

Every row below maps to focused executable tests when implemented. API
assertions are reusable; tests needing a control or witness declare it.
Core tests use ordinary HTTP calls and isolated fixtures, without controlled
time, restart, or internal state access.

| ID | Assertion | Fixture requirement |
|---|---|---|
| MAP-01 | Register, lookup, update, and lookup preserve operation casing, scope, IDs, modality and exact address; committed writes are immediately visible | Core |
| MAP-02 | Exact register/update replay returns the original acknowledgement; changed command content returns `409`; replaying an old update after a newer one never restores old state | Core |
| MAP-03 | A malformed or duplicate item refuses the entire write; registration conflicts and update of a missing pair leave every existing mapping unchanged | Core |
| MAP-04 | Multiple modalities are distinct and sorted; lookup absence is `404`; unsupported `status`, callback-header aliases and unknown body fields are handled as specified | Core |
| PAY-01 | Scenario 1 produces one accepted batch and the exact original instruction set, all `ACCC`, totaling 250.00 USD | `success` |
| PAY-02 | Scenario 2 preserves the accepted batch and both instructions, one `ACCC`, one `RJCT` with a stable reason; no whole-batch resubmission | `partial-failure` |
| PAY-03 | Duplicate IDs, invalid body, unsupported/disabled modes (including `02` and `04`), currencies, mixed currency/payer, and excess limits cause no acceptance; correcting a definitely refused command under the same correlation ID can then succeed | Core |
| PAY-04 | Same command replays before and after completion; changed amount, payer, programme, institution, callback, or array content conflicts and preserves the original | Core |
| PAY-05 | Concurrent identical submissions converge on one `batchId`; a different batch command reusing an accepted instruction ID is refused atomically | Core; witness strengthens effect proof |
| PAY-06 | Detail always echoes original `requestId`; provider `transactionId`, batch, amount and currency remain stable; no terminal transition regresses | Core |
| PAY-07 | Missing mapping becomes `RJCT mapping-not-found`; another valid instruction can succeed; a mapping added later cannot rescue the accepted missing mapping | Core; `hold-processing` for the registration race |
| PAY-08 | Updating a mapping after acceptance changes lookup and a later new batch, but the original batch retains and uses its accepted financial address | `hold-processing`; `effect-witness` for routing effect |
| PAY-09 | Amounts such as 0.10 and 0.20 total exactly 0.30; equivalent decimal notation replays; excess scale, numeric strings, non-finite values and minor-unit overflow are refused | Core |
| PAGE-01 | With page size 1, pending and terminal observations yield each original row exactly once in stable order; past the end is `[]`; changing state never moves a row | Core; held transitions where available |
| PAGE-02 | Negative page numbers, invalid page sizes, unsupported `status`/`direction`, and mismatched correlation are refused as specified | Core |
| AUTH-01 | Missing/invalid credentials and unauthorized tenant, institution, source, programme or payer cannot read protected state or create effects | Separate principals/scopes |
| AUTH-02 | Repeated IDs across tenants/producers remain isolated; another producer cannot fetch a batch; credential rotation for the same producer preserves replay | Separate principals and credential rotation |
| AUTH-03 | After authority is revoked, replay of an accepted command and a conflicting variant both return an authorization refusal, never a stored response or existence-revealing conflict | Authority revocation |
| REC-01 | Scenario 3 loses the response after proven acceptance, then recovers the same batch by exact replay; the client cannot read the relay's hidden response | `lost-response` |
| REC-02 | Lost-response recovery, command conflicts, frozen destinations and terminal results survive restart using the same durable state | `restart`, `hold-processing` |
| REC-03 | Crash after acceptance but before processing, and crash around a terminal credit commit, resume with one simulated/provider credit per original instruction | `restart`, `effect-witness`, controlled crash points |
| REC-04 | Replay POST and detail GET return `410` after their acceptance/result evidence expires; retained identities still conflict and never enable fresh acceptance | `receipt-expiry` |
| CB-01 | Accepted and final notifications use distinct stable IDs, exact state counts/totals, JSON content type and persisted bodies; retry after an unacknowledged delivery reuses the same event | `batch-callback` |
| CB-02 | Duplicate, delayed, absent and out-of-order notifications do not change the final result or cause another submission | `batch-callback` |
| CB-03 | Notifications use only configured receiver credentials and scope headers, never the caller token; unapproved URLs are refused and receiver redirects are not followed | `batch-callback`, controlled receivers |

For MAP-04, lookup's obsolete `X-Callback_URL` is not a required field and has
no effect if an HTTP client sends it. Unknown JSON members are rejected;
ordinary irrelevant HTTP headers are ignored. Do not treat header-name case
as a different spelling. Update's undefined `status` is rejected.

There is no public endpoint listing all batches or all credits. Therefore an
HTTP-only test cannot prove hidden-effect absence after a refusal. Test the
observable refusal and subsequent behavior in the portable suite, and attach
the independent effect witness where that stronger claim is needed.

## Lost-response relay

The relay forwards the unchanged command to the configured target, reads a
complete successful acceptance (`202` for G2P, `200` for P2G), records its
batch or transfer-request ID privately for test comparison, and disconnects
the client before sending response headers. The
client's result is uncertain. It must recover through an unchanged POST to
the target, not a helper that reads the relay log.

The test compares the replay's returned ID with the relay's hidden one only
after the client has recovered it. Restart is injected between these steps
when available. Use separate tests for a response lost before any acceptance
and a response lost after a terminal state; they cover different boundaries.

## Consumer and Coordinator tests

Keep service compatibility tests separate from consumer interpretation tests.
A scripted HTTP peer supplies malformed or inconsistent responses to the
client/interpreter, including missing, duplicate and extra instruction IDs,
changed amounts or transaction IDs, incomplete pages, `ACSC`, unknown statuses,
and contradictory terminal outcomes. The consumer must hold instead of
reporting payment success or business rejection.

Also test the four valid aggregate cases directly: all `ACCC` is `completed`,
all `RJCT` is `failed`, a terminal mixture is `partial`, and any nonterminal
instruction leaves `pending`. The all-rejected interpreter case supplements
the three end-to-end traces without requiring a fourth named scenario.

Coordinator integration needs evidence that it:

1. Saves the command and payment IDs before any submission.
2. Interprets `202` as acceptance and derives completion only from complete,
   validated instruction results.
3. Uses the original command for uncertainty recovery, without extending the
   original authority, approval, or deadline.
4. Honors observation floors and budgets across restart and notification.
5. Handles partial outcomes through the same workflow branches for both targets.
6. Replaces only the connection/credential/adapter binding; the workflow
   definition and command/outcome schemas stay unchanged.

The [native Coordinator target](../../products/coordinator/README.md#verify-a-change)
runs the authored workflows through real HTTP and durable PostgreSQL state. It proves original
G2P replay after response loss, simulator process restart and Coordinator reconstruction, one
simulated credit, and refusal of incorrectly correlated P2G paid evidence. Authored scenarios
cover aggregate outcomes, uncertainty and bounded observation expiry. This native fixture advances
its own observation clock; real elapsed floors, Coordinator OS-process restart, notification
wake-ups and a second provider are not established by that target. The simulator adds no
Coordinator-specific behavior to make it pass.

## Compatibility report

Each run records the profile version, harness revision, target version or
immutable build identity, adapter version if any, fixture capabilities,
effective limits and retention, and per-test passed/failed/not-verified results.
Record synthetic request/response evidence with authorization headers removed;
never retain provider credentials or real beneficiary data.

Report separately:

- **Wire and behavioral compatibility:** the selected profile's APIs and reusable assertions.
- **Recovery evidence:** lost response, concurrency, restart, and retention.
- **Effect evidence:** whether independent ledger evidence ruled out duplicates
  and confirmed the destination used.
- **Coordinator integration:** whether an unchanged workflow was actually run.

A replacement is ready for the specified workflow only after applicable core
assertions and all three scenarios pass, modes/limits/retention cover that workflow,
and any missing durability or effect evidence is resolved through controlled
tests or explicitly reviewed provider guarantees. Never label a target fully
verified merely because unsupported tests were skipped. Passing this suite is
profile compatibility evidence, not full GovStack certification.
