# Registry Scheduling security review notes

Review notes for the security-sensitive Scheduling changes, held in tracked
material because commit messages do not survive a squash. Each section names
the change by its subject, the threat it answers, the defaults it ships, and
the tests that pin it. The security-invariant matrix in `contracts/` is the
row-per-invariant baseline; this file is the narrative behind the decisions
and the deferrals the matrix records.

## The task-grant bounds in the platform

The change `feat(auth): add scheduling bounds to task grants` carries its
review record in the `registry-platform-oidc` crate README (threat, wire
format, issuer and verifier compatibility, test evidence). It is not
restated here. In short: `GrantBounds::Scheduling` is a closed tagged union
with `deny_unknown_fields`, cardinality and length bounds (64 permissions,
32 actions each, 512-byte service and location values, unique
service-and-location pairs), and a `Debug` implementation that redacts
every value. A scheduling grant parsed by the BReg binding is refused, and
a test in `registry-breg` pins that refusal.

## The runtime edge: authentication, audit, listeners, and defaults

The change `feat(scheduling): serve the runtime edge with auth, workers,
and schema` introduced the HTTP edge, the authenticator, the audit
pipeline, the worker supervision, the listener policy, and the retention
defaults. AGENTS.md requires review notes for changes of this class; these
are they.

### Threat

A Scheduling deployment answers over HTTP to callers holding bearer
tokens, commits capacity inside PostgreSQL transactions, and writes an
audit journal. The threats this surface answers:

1. **A caller without a complete task grant books capacity.** The edge
   authenticates the bearer token against a pinned JWKS, requires the
   profile scope for every read and a separately configured explain scope
   for explanations, and requires a complete scheduling grant (service,
   location, actions) for every commitment. A partially formed grant set
   is refused as a credentials problem, never honoured partially.
2. **A token that was valid at the door commits after its grant lapsed.**
   The grant's expiry is re-checked inside the capacity transaction,
   immediately before the claim commits, against the same observed now the
   rest of the transaction decided under. The full bounds are matched once
   at the service before the transaction opens; re-reading them inside
   would only defend against narrowing at the issuer, which needs a
   revocation path this milestone does not have (matrix deferral
   SCHEDULING-DEF-01, recorded in the published reference).
3. **A deployment is reached over a public interface by accident.** The
   listener must bind a private address or an explicitly declared
   container network; anything else refuses to start.
4. **A commitment leaves no accountable trace.** Every ledger-decided
   commitment and refusal writes an audit row with a pseudonymized
   principal, and the audit rows chain by hash. A permission mismatch
   refused at the service, before the transaction opens, writes no audit
   row today (SCHEDULING-DEF-02): the compensating control is that the
   refusal answer is drawn from a closed vocabulary and says nothing about
   which bound failed, so probing the edge yields nothing beyond allowed
   or not allowed.
5. **A refusal discloses supply or another caller's booking.** Admission
   refusals project through a public code; the member-level cause stays
   behind the separately authorized explain path.

### Defaults

- The database connection requires TLS (`SslMode::Require`); the plaintext
  escape exists only behind the `postgres-test` feature for disposable
  test databases.
- The listener refuses public addresses absent an explicit container
  network declaration.
- Every answer carries `Cache-Control: no-store`, the security headers
  without HSTS (TLS termination is the deployer's), a 1 MiB body ceiling,
  and the caller's trace identifier when a trace is presented.
- Retention defaults (attempt receipt days, cursor minutes) are
  placeholders: a jurisdiction must approve real retention periods before
  production use. Retention sweeps idempotency attempt receipts and
  cursors only; appointments, history, outbox rows, and audit rows are
  never swept in this milestone (SCHEDULING-DEF-06, recorded in
  `RUNTIME-CONFIG.md`).
- Reminder intents with no configured destination stay local and readable
  in place; nothing is delivered by default.

### Test evidence

`crates/registry-scheduling/src/auth.rs` pins the partial-grant refusal,
the foreign-resource profile refusal, the unknown-key credential refusal,
and the explain scope separation. `crates/registry-scheduling/src/config.rs`
pins the listener policy, the static JWKS shape (unique named asymmetric
keys), the verified-package requirement in production, and that typed parse
paths never echo a rejected value. `crates/registry-scheduling/src/http.rs`
pins the problem rendering of the closed vocabulary, framework rejection
normalization, no-store and trace stamping, and the idempotency key bounds.
The PostgreSQL suite in `crates/registry-scheduling/tests/` pins the edge
refusing unauthenticated callers and unauthorized mutations end to end.

## The reschedule exclusion

The change `fix(scheduling): keep the reschedule exclusion inside the
runtime's transaction` removed the caller-settable `rescheduleOf` from the
wire admission request and made the exclusion an evaluator argument that
only the reschedule transaction supplies, from the appointment row it
locks. Before it, naming any live claim's identifier on a create path
excluded that claim from every capacity check; the review classed it a
merge blocker. The threat, the wire change, and the test evidence are
recorded in that change's own notes; the standing invariant is matrix row
SCHEDULING-SEC-17.

## Known deferrals

The matrix records five deferrals with their compensating controls. They
are restated here only as the index the matrix's `recordedIn` points at:

- **SCHEDULING-DEF-02, audit rows for pre-transaction permission
  refusals.** Grant-scope probing against the edge is invisible to the
  journal. Compensating control: closed-vocabulary refusals that name no
  failing bound.
- **SCHEDULING-DEF-03, caller string ceilings below the body limit.** The
  idempotency key and page limit are bounded; capabilities, prerequisites,
  channel, duplicate key, and reason are bounded only by the 1 MiB body
  ceiling and the database CHECK constraints, and an over-long reason
  surfaces as a service problem on that caller's own request. Tier 2 work
  bounds them at the edge with `request.invalid`.
- **SCHEDULING-DEF-04, the channel is not bound to the verified caller.**
  A caller entitled to book may choose which subquota it draws from. The
  policy declares a closed channel set and every subquota is a ceiling
  inside the published total, so a mis-chosen channel cannot oversell the
  window. Binding the channel to the verified client is a product
  decision for a later phase.
- **SCHEDULING-DEF-05, no database backstop under the duplicate-key
  guard.** The guard runs inside the same capacity transaction as the
  claim it protects, so a concurrent pair cannot straddle it; the
  supporting index is partial rather than unique.
- **SCHEDULING-DEF-06, retention scope.** Recorded in
  `RUNTIME-CONFIG.md`, which states plainly what the sweeps cover.

A change that closes one of these promotes the matrix entry in the same
commit and rewrites this section with it.
